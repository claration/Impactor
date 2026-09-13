use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use dialoguer::{Input, Select};
use plume_utils::discovery::{DeviceDiscovery, PlatformDiscovery};
use plume_utils::{Device, Package, get_device_for_id};

use crate::get_data_path;

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct DeviceArgs {
    #[arg(short = 'u', long = "udid", value_name = "UDID", conflicts_with = "mac")]
    pub udid: Option<String>,
    #[arg(short = 'i', long = "install", value_name = "PATH")]
    pub install: Option<PathBuf>,
    #[arg(
        short = 'p',
        long = "pairing",
        conflicts_with = "mac",
        requires = "pairing_path"
    )]
    pub pairing: bool,
    #[arg(long = "pairing-path", value_name = "PATH", requires = "pairing")]
    pub pairing_path: Option<PathBuf>,
    #[arg(long = "pairing-app-identifier", value_name = "IDENTIFIER")]
    pub pairing_app_identifier: Option<String>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[arg(short = 'm', long = "mac", conflicts_with = "udid")]
    pub mac: bool,
}

#[derive(Debug, Args)]
pub struct PairArgs {
    #[command(subcommand)]
    pub command: PairCommand,
}

#[derive(Debug, Subcommand)]
pub enum PairCommand {
    Scan {
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
    Connect(PairConnectArgs),
    Reconnect {
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
    Forget(PairForgetArgs),
}

#[derive(Debug, Args)]
pub struct PairConnectArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub ip: Option<IpAddr>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub pin: Option<String>,
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct PairForgetArgs {
    #[arg(long, conflicts_with = "identity")]
    pub name: Option<String>,
    #[arg(long)]
    pub identity: Option<String>,
}

pub async fn execute(args: DeviceArgs) -> Result<()> {
    let device = {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            if args.mac {
                Some(Device {
                    name: "My Mac".to_string(),
                    udid: String::new(),
                    product_type: None,
                    device_class: Some("Mac".to_string()),
                    os_version: None,
                    serial_number: None,
                    device_id: 0,
                    usbmuxd_device: None,
                    is_mac: true,
                    pairing_address: None,
                    reconnect_address: None,
                    pairing_identity: None,
                    pairing_cache_dir: None,
                    core_device_authenticated: false,
                })
            } else {
                Some(select_device(args.udid).await?)
            }
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            Some(select_device(args.udid).await?)
        }
    };

    let device = device.ok_or_else(|| anyhow!("No device selected"))?;

    if let Some(app_path) = args.install {
        let mut app_path = app_path;
        if !app_path.is_dir() {
            app_path = Package::new(app_path)?
                .get_package_bundle()?
                .bundle_dir()
                .clone();
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if args.mac {
            plume_utils::install_app_mac(&app_path).await?;
            return Ok(());
        }

        device
            .install_app(&app_path, |progress| async move {
                log::info!("Installation progress: {progress}%");
            })
            .await?;
    }

    if args.pairing {
        if let Some(pairing_path) = args.pairing_path {
            let app_identifier = match args.pairing_app_identifier {
                Some(identifier) => identifier,
                None => apps(&device).await?,
            };
            device
                .install_pairing_record(
                    &app_identifier,
                    pairing_path
                        .to_str()
                        .ok_or_else(|| anyhow!("Pairing path is not valid UTF-8"))?,
                )
                .await?;
        }
    }

    Ok(())
}

pub async fn execute_pair(args: PairArgs) -> Result<()> {
    match args.command {
        PairCommand::Scan { timeout } => {
            let devices = discover_network_devices(Duration::from_secs(timeout)).await?;
            if devices.is_empty() {
                println!("No Apple TVs found.");
            } else {
                for device in devices {
                    println!("{device}");
                }
            }
        }
        PairCommand::Connect(args) => pair_connect(args).await?,
        PairCommand::Reconnect { timeout } => {
            let devices = discover_network_devices(Duration::from_secs(timeout)).await?;
            let mut found = false;
            for device in devices {
                found = true;
                if plume_utils::is_valid_device_udid(&device.udid) {
                    println!("Reconnected {device}");
                } else {
                    println!("{} is paired but its authenticated UDID is unavailable", device.name);
                }
            }
            if !found {
                println!("No Apple TVs found.");
            }
        }
        PairCommand::Forget(args) => {
            let PairForgetArgs { name, identity } = args;
            let identity = identity
                .or_else(|| name.as_deref().map(|name| name.replace(' ', "-")))
                .ok_or_else(|| anyhow!("--name or --identity is required"))?;
            let name = name.unwrap_or_else(|| identity.replace('-', " "));
            let device = Device::new_tvos(
                name,
                identity,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                None,
                None,
                get_data_path(),
            );
            device.forget_tvos_pairing(get_data_path()).await?;
            println!("Forgot the saved Apple TV pairing record.");
        }
    }

    Ok(())
}

pub async fn select_device(device_udid: Option<String>) -> Result<Device> {
    let devices = discover_devices().await?;
    if let Some(udid) = device_udid {
        if let Some(device) = devices
            .iter()
            .find(|device| device.udid.eq_ignore_ascii_case(&udid))
        {
            return Ok(device.clone());
        }
        if let Ok(device) = get_device_for_id(&udid).await {
            return Ok(device);
        }
        return Err(anyhow!("No connected device has UDID {udid}"));
    }

    let names = devices.iter().map(ToString::to_string).collect::<Vec<_>>();
    let selection = Select::new()
        .with_prompt("Select a device to register and install to")
        .items(&names)
        .default(0)
        .interact()?;
    Ok(devices[selection].clone())
}

async fn discover_devices() -> Result<Vec<Device>> {
    let mut devices = Vec::new();
    if let Ok(mut muxer) = idevice::usbmuxd::UsbmuxdConnection::default().await {
        if let Ok(usb_devices) = muxer.get_devices().await {
            devices.extend(
                futures::future::join_all(usb_devices.into_iter().map(Device::new)).await,
            );
        }
    }
    devices.extend(discover_network_devices(Duration::from_secs(5)).await?);
    let devices = plume_utils::deduplicate_devices(devices);
    if devices.is_empty() {
        return Err(anyhow!(
            "No devices connected. Connect a device or pair an Apple TV with `plumesign pair connect`."
        ));
    }
    Ok(devices)
}

async fn discover_network_devices(timeout: Duration) -> Result<Vec<Device>> {
    let discovered = PlatformDiscovery::new().discover(timeout).await?;
    let cache_dir = get_data_path();
    let mut devices = plume_utils::discovery::group_network_devices(&discovered, &cache_dir);
    for device in &mut devices {
        if device.has_pairing_source(&cache_dir) {
            if let Ok(info) = device.fetch_tvos_info(cache_dir.clone()).await {
                device.apply_tvos_info(&info);
            }
        }
    }
    Ok(plume_utils::deduplicate_devices(devices))
}

async fn pair_connect(args: PairConnectArgs) -> Result<()> {
    let cache_dir = get_data_path();
    let mut device = if let Some(ip) = args.ip {
        let name = args.name.unwrap_or_else(|| "Apple TV".to_string());
        let port = args
            .port
            .ok_or_else(|| anyhow!("--port is required with --ip"))?;
        let identity = name.replace(' ', "-");
        Device::new_tvos(name, identity, ip, Some(port), None, cache_dir.clone())
    } else {
        let devices = discover_network_devices(Duration::from_secs(args.timeout)).await?;
        let tv_names = devices
            .iter()
            .map(|device| device.name.clone())
            .collect::<Vec<_>>();
        if tv_names.is_empty() {
            return Err(anyhow!("No Apple TVs found on the network"));
        }
        let index = if let Some(name) = args.name {
            devices
                .iter()
                .position(|device| device.name.eq_ignore_ascii_case(&name))
                .ok_or_else(|| anyhow!("Apple TV {name:?} was not found"))?
        } else {
            Select::new()
                .with_prompt("Select an Apple TV to pair")
                .items(&tv_names)
                .default(0)
                .interact()?
        };
        devices[index].clone()
    };

    let pin = args.pin;
    device
        .pair_tvos(
            move || {
                let pin = pin.clone();
                async move {
                    pin.unwrap_or_else(|| {
                        Input::<String>::new()
                            .with_prompt("Enter the PIN shown on the Apple TV")
                            .interact_text()
                            .unwrap_or_default()
                    })
                }
            },
            cache_dir.clone(),
        )
        .await?;

    let info = device.fetch_tvos_info(cache_dir).await?;
    device.apply_tvos_info(&info);
    if !plume_utils::is_valid_device_udid(&device.udid) {
        return Err(anyhow!(
            "Pairing succeeded but the authenticated Apple TV UDID was not returned"
        ));
    }
    println!(
        "Paired {} ({}, {}, UDID {})",
        device.name,
        device.product_type.as_deref().unwrap_or("Apple TV"),
        device.os_version.as_deref().unwrap_or("tvOS"),
        device.udid
    );
    Ok(())
}

async fn apps(device: &Device) -> Result<String> {
    let apps = device.installed_apps().await?;
    if apps.is_empty() {
        return Err(anyhow!("No supported installed apps found"));
    }
    let names = apps
        .iter()
        .map(|app| {
            format!(
                "{} ({})",
                app.app,
                app.bundle_id.as_deref().unwrap_or("unknown bundle")
            )
        })
        .collect::<Vec<_>>();
    let selection = Select::new()
        .with_prompt("Select an installed app")
        .items(&names)
        .default(0)
        .interact()?;
    apps[selection]
        .bundle_id
        .clone()
        .ok_or_else(|| anyhow!("Selected app has no bundle identifier"))
}
