use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use plume_utils::wireless::{PairingStore, ServiceKind, discover, pair};

use crate::get_data_path;

const DEFAULT_HOST: &str = "plume";

#[derive(Debug, Args)]
pub struct PairArgs {
    #[command(subcommand)]
    pub command: Option<PairCommands>,
    /// IP address of the device to pair with
    #[arg(long = "ip", value_name = "IP", requires = "port")]
    pub ip: Option<IpAddr>,
    /// Port the device advertises its pairing service on
    #[arg(long = "port", value_name = "PORT", requires = "ip")]
    pub port: Option<u16>,
    /// PIN shown on the device screen (read from stdin if not given)
    #[arg(long = "pin", value_name = "PIN")]
    pub pin: Option<String>,
    /// Name to present to the device
    #[arg(long = "host", value_name = "NAME", default_value = DEFAULT_HOST)]
    pub host: String,
}

#[derive(Debug, Subcommand)]
pub enum PairCommands {
    /// Browse the network for devices that can be paired with
    Discover(DiscoverArgs),
    /// List devices this host has already paired with
    List,
    /// Identify a paired device from its advertised mDNS identifier and auth tag
    Find(FindArgs),
    /// Delete a stored pairing
    Forget(ForgetArgs),
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    /// How long to browse for, in seconds
    #[arg(
        short = 't',
        long = "timeout",
        value_name = "SECONDS",
        default_value_t = 5
    )]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct FindArgs {
    /// `identifier` TXT record from the device's _remotepairing._tcp service
    #[arg(long = "identifier", value_name = "IDENTIFIER", required = true)]
    pub identifier: String,
    /// `authTag` TXT record from the device's _remotepairing._tcp service
    #[arg(long = "auth-tag", value_name = "AUTH_TAG", required = true)]
    pub auth_tag: String,
}

#[derive(Debug, Args)]
pub struct ForgetArgs {
    /// UDID of the device to forget
    #[arg(short = 'u', long = "udid", value_name = "UDID", required = true)]
    pub udid: String,
}

pub async fn execute(args: PairArgs) -> Result<()> {
    let store = PairingStore::new(get_data_path().join("remotepairing"));

    match args.command {
        Some(PairCommands::Discover(discover_args)) => run_discover(&store, discover_args).await,
        Some(PairCommands::List) => run_list(&store).await,
        Some(PairCommands::Find(find_args)) => run_find(&store, find_args).await,
        Some(PairCommands::Forget(forget_args)) => run_forget(&store, forget_args).await,
        None => run_pair(&store, args).await,
    }
}

async fn run_pair(store: &PairingStore, args: PairArgs) -> Result<()> {
    let (Some(ip), Some(port)) = (args.ip, args.port) else {
        bail!("--ip and --port are required to pair; run `plumesign pair discover` to find them");
    };
    let address = SocketAddr::new(ip, port);

    log::info!("Pairing with {address} as {:?}", args.host);

    let (pairing_file, device) = pair(address, &args.host, || {
        let pin = args.pin.clone();
        async move {
            match pin {
                Some(pin) => pin,
                None => read_pin(),
            }
        }
    })
    .await?;

    let path = store.save(&device, &pairing_file).await?;

    log::info!(
        "Paired with {} ({}), UDID {}",
        device.name,
        device.model,
        device.udid
    );
    println!("{}", path.display());

    Ok(())
}

async fn run_discover(store: &PairingStore, args: DiscoverArgs) -> Result<()> {
    let devices = discover(Duration::from_secs(args.timeout)).await?;

    if devices.is_empty() {
        log::warn!("No devices found. Check that the device is awake and on this network.");
        return Ok(());
    }

    for device in devices {
        let known = match (&device.identifier, &device.auth_tag) {
            (Some(identifier), Some(auth_tag)) => store.find(identifier, auth_tag).await?,
            _ => None,
        };

        match (device.kind, known) {
            (_, Some(record)) => println!("{device} paired as {}", record.udid),
            (ServiceKind::ManualPairing, None) => println!(
                "{device} run: {} pair --ip {} --port {}",
                invocation(),
                device.address.ip(),
                device.address.port()
            ),
            (ServiceKind::RemotePairing, None) => println!("{device} paired with another host"),
        }
    }

    Ok(())
}

async fn run_list(store: &PairingStore) -> Result<()> {
    let records = store.list().await?;

    if records.is_empty() {
        log::warn!("No paired devices in {}", store.directory().display());
        return Ok(());
    }

    for record in records {
        println!("{record}");
    }

    Ok(())
}

async fn run_find(store: &PairingStore, args: FindArgs) -> Result<()> {
    match store.find(&args.identifier, &args.auth_tag).await? {
        Some(record) => {
            println!("{record}");
            Ok(())
        }
        None => bail!("No stored pairing matches identifier {}", args.identifier),
    }
}

async fn run_forget(store: &PairingStore, args: ForgetArgs) -> Result<()> {
    if store.remove(&args.udid).await? {
        log::info!("Forgot pairing for {}", args.udid);
        Ok(())
    } else {
        bail!("No stored pairing for {}", args.udid)
    }
}

fn invocation() -> String {
    std::env::args()
        .next()
        .filter(|arg| !arg.is_empty())
        .unwrap_or_else(|| "plumesign".to_string())
}

/// Plain stdin read rather than a prompt widget: this is often driven by another
/// process writing the PIN to the child's stdin, where there is no terminal.
fn read_pin() -> String {
    print!("Enter the PIN shown on the device: ");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return String::new();
    }

    line.trim().to_string()
}
