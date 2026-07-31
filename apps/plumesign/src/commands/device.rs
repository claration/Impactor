use std::path::PathBuf;

use anyhow::{Error, Ok, Result};
use clap::Args;
use dialoguer::Select;
use idevice::{
    IdeviceService,
    installation_proxy::InstallationProxyClient,
    usbmuxd::{UsbmuxdAddr, UsbmuxdConnection},
};
use plume_utils::{Device, Package, get_device_for_id};


#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct DeviceArgs {
    /// Device UDID to target (optional, will prompt if not provided)
    #[arg(
        short = 'u',
        long = "udid",
        value_name = "UDID",
        conflicts_with = "mac"
    )]
    pub udid: Option<String>,
    /// Install app at specified path to device (.ipa, .app)
    #[arg(short = 'i', long = "install", value_name = "PATH")]
    pub install: Option<PathBuf>,
    /// Install pairing record from specified path to device
    #[arg(
        short = 'p',
        long = "pairing",
        value_name = "MAC",
        conflicts_with = "mac",
        requires = "pairing_path"
    )]
    pub pairing: bool,
    /// Path to pairing record to install (i.e. /Documents/pairingFile.plist)
    #[arg(long = "pairing-path", value_name = "PATH", requires = "pairing")]
    pub pairing_path: Option<PathBuf>,
    /// App identifier for the app to use for pairing record installation (optional, will prompt if not provided)
    #[arg(long = "pairing-app-identifier", value_name = "IDENTIFIER")]
    pub pairing_app_identifier: Option<String>,
    /// Install to connected Mac (arm64 only)
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[arg(short = 'm', long = "mac", value_name = "MAC", conflicts_with = "udid")]
    pub mac: bool,
}

pub async fn execute(args: DeviceArgs) -> Result<()> {
    let device = {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            if args.mac {
                Device {
                    name: "My Mac".to_string(),
                    udid: String::new(),
                    device_id: 0,
                    usbmuxd_device: None,
                    is_mac: true,
                    pairing_address: None,
                    reconnect_address: None,
                    pairing_identity: None,
                    pairing_cache_dir: None,
                }
            } else {
                select_device(args.udid).await?
            }
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            select_device(args.udid).await?
        }
    };

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
            log::info!("Installing app at {:?} to connected Mac", app_path);
            plume_utils::install_app_mac(&app_path).await?;
            return Ok(());
        }

        log::info!("Installing app at {:?} to device {}", app_path, device.name);
        device
            .install_app(&app_path, |progress| async move {
                log::info!("Installation progress: {}%", progress);
            })
            .await?;
    }

    if args.pairing {
        if let Some(pairing_path) = args.pairing_path {
            log::info!(
                "Installing pairing record from {:?} to device {}",
                pairing_path,
                device.name
            );
            let app_identifier = if let Some(identifier) = args.pairing_app_identifier {
                identifier
            } else {
                apps(&device).await?
            };
            device
                .install_pairing_record(&app_identifier, pairing_path.to_str().unwrap())
                .await?;
        }
    }

    Ok(())
}

pub async fn select_device(device_udid: Option<String>) -> Result<Device> {
    if let Some(udid) = device_udid {
        return Ok(get_device_for_id(&udid).await?);
    }

    let mut muxer = UsbmuxdConnection::default().await?;
    let devices = muxer.get_devices().await?;

    if devices.is_empty() {
        return Err(anyhow::anyhow!(
            "No devices connected. Please connect a device or specify a UDID with --device-udid"
        ));
    }

    let device_futures: Vec<_> = devices.into_iter().map(|d| Device::new(d)).collect();

    let devices = futures::future::join_all(device_futures).await;

    let device_names: Vec<String> = devices.iter().map(|d| d.to_string()).collect();

    let selection = Select::new()
        .with_prompt("Select a device to register and install to")
        .items(&device_names)
        .default(0)
        .interact()?;

    Ok(devices[selection].clone())
}

async fn apps(device: &Device) -> Result<String, Error> {
    const INSTALLATION_LABEL: &str = "App Installation";
    let p = device.usbmuxd_device.clone().unwrap().to_provider(
        UsbmuxdAddr::from_env_var().unwrap_or_default(),
        INSTALLATION_LABEL,
    );

    let mut lpc = InstallationProxyClient::connect(&p)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create installation proxy client: {}", e))?;

    let ia = lpc
        .get_apps(Some("User"), None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get installed apps: {}", e))?;

    let app_names: Vec<String> = ia.keys().cloned().collect();

    let selection = Select::new()
        .items(&app_names)
        .default(0)
        .with_prompt("Select an installed app")
        .interact()?;

    Ok(app_names[selection].clone())
}
