mod bundle;
mod cgbi;
mod device;
pub mod discovery;
mod options;
mod package;
pub mod pairing;
mod signer;
mod tweak;

use std::path::Path;
use idevice::usbmuxd::Connection;
pub use bundle::{Bundle, BundleType};
pub use device::{
    CoreDeviceTransport, Device, DeviceTransport, TvosDeviceInfo, get_device_for_id, install_app_mac,
    synthetic_device_id,
};
pub use options::{
    SignerApp, // Supported app types
    SignerAppReal,
    SignerEmbedding,   // Embedding options
    SignerFeatures,    // Feature support options
    SignerInstallMode, // Installation mode
    SignerMode,        // Signing mode
    SignerOptions,     // Main
};
pub use package::Package;
pub use pairing::{PairingBackend, PairingFailure, PairingStage, ensure_pairing};
pub use signer::Signer;
pub use tweak::Tweak;

pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Info.plist not found")]
    BundleInfoPlistMissing,
    // Device
    #[error("Bundle failed to rename, make sure its available: {0}")]
    BundleFailedToCopy(String),
    // Tweak
    #[error("Invalid tweak file path")]
    TweakInvalidPath,
    #[error("Tweak extraction failed: {0}")]
    TweakExtractionFailed(String),
    #[error("Unsupported file type: {0}")]
    UnsupportedFileType(String),

    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("Info.plist not found")]
    PackageInfoPlistMissing,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),
    #[error("Core error: {0}")]
    Core(#[from] plume_core::Error),
    #[error("Idevice error: {0}")]
    Idevice(#[from] idevice::IdeviceError),
    #[error("Codesign error: {0}")]
    Codesign(#[from] plume_core::AppleCodesignError),
    #[error("Other error: {0}")]
    Other(String),
    #[error("Image error: {0}")]
    Image(#[from] image::ImageError),
}

pub trait PlistInfoTrait {
    fn get_name(&self) -> Option<String>;
    fn get_executable(&self) -> Option<String>;
    fn get_bundle_identifier(&self) -> Option<String>;
    fn get_bundle_name(&self) -> Option<String>;
    fn get_version(&self) -> Option<String>;
    fn get_build_version(&self) -> Option<String>;
}

pub async fn copy_dir_recursively(src: &Path, dst: &Path) -> Result<()> {
    use tokio::fs;

    fs::create_dir_all(dst).await?;
    let mut entries = fs::read_dir(src).await?;

    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_symlink() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let target = fs::read_link(&src_path).await?;
                symlink(&target, &dst_path)?;
            }
        } else if file_type.is_dir() {
            Box::pin(copy_dir_recursively(&src_path, &dst_path)).await?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path).await?;
        }
    }

    Ok(())
}

pub use plume_core::is_valid_device_udid;

fn dedup_keys_for_device(device: &Device) -> Vec<String> {
    let mut keys = Vec::new();
    if is_valid_device_udid(&device.udid) {
        keys.push(format!("udid:{}", device.udid.to_ascii_lowercase()));
    }

    if let Some(identity) = device
        .pairing_identity
        .as_deref()
        .filter(|identity| !identity.is_empty())
    {
        keys.push(format!("pairing:{}", identity.to_ascii_lowercase()));
    }
    if let Some(usbmuxd) = &device.usbmuxd_device {
        keys.push(format!("mux:{}", usbmuxd.device_id));
        if let Connection::Network(ip) = &usbmuxd.connection_type {
            keys.push(format!("network-ip:{ip}"));
        }
    }
    for address in [device.pairing_address, device.reconnect_address]
        .into_iter()
        .flatten()
    {
        keys.push(format!("network-ip:{}", address.0));
    }

    keys
}

fn device_quality(device: &Device) -> usize {
    let mut score = 0;
    if is_valid_device_udid(&device.udid) {
        score += 100;
    }
    if device.pairing_identity.is_some() {
        score += 40;
    }
    if device.usbmuxd_device.is_some() {
        score += 20;
    }
    if device.core_device_authenticated {
        score += 25;
    }
    score += device.product_type.is_some() as usize * 10;
    score += device.device_class.is_some() as usize * 8;
    score += device.os_version.is_some() as usize * 4;
    score += device.serial_number.is_some() as usize * 4;
    score += device.reconnect_address.is_some() as usize * 3;
    score += device.pairing_address.is_some() as usize * 2;
    score
}

pub fn deduplicate_devices(devices: impl IntoIterator<Item = Device>) -> Vec<Device> {
    let mut groups: Vec<(Vec<String>, Device)> = Vec::new();

    for device in devices {
        let keys = dedup_keys_for_device(&device);
        let matching_indexes = groups
            .iter()
            .enumerate()
            .filter(|(_, (group_keys, _))| keys.iter().any(|key| group_keys.contains(key)))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        let Some(first_index) = matching_indexes.first().copied() else {
            groups.push((keys, device));
            continue;
        };

        merge_devices(&mut groups[first_index].1, device);
        groups[first_index].0 = dedup_keys_for_device(&groups[first_index].1);

        for index in matching_indexes.into_iter().skip(1).rev() {
            let (_, other) = groups.remove(index);
            merge_devices(&mut groups[first_index].1, other);
            groups[first_index].0 = dedup_keys_for_device(&groups[first_index].1);
        }
    }

    groups.into_iter().map(|(_, device)| device).collect()
}

fn merge_devices(existing: &mut Device, mut incoming: Device) {
    if device_quality(&incoming) > device_quality(existing) {
        std::mem::swap(existing, &mut incoming);
    }

    if existing.name.is_empty() {
        existing.name = incoming.name;
    }
    if !is_valid_device_udid(&existing.udid) && is_valid_device_udid(&incoming.udid) {
        existing.udid = incoming.udid;
    }
    if existing.product_type.is_none() {
        existing.product_type = incoming.product_type;
    }
    if existing.device_class.is_none() {
        existing.device_class = incoming.device_class;
    }
    if existing.os_version.is_none() {
        existing.os_version = incoming.os_version;
    }
    if existing.serial_number.is_none() {
        existing.serial_number = incoming.serial_number;
    }
    let is_remote_tvos = existing.pairing_identity.is_some()
        && (existing
            .product_type
            .as_deref()
            .is_some_and(|value| value.starts_with("AppleTV"))
            || existing
                .device_class
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("AppleTV")));
    if existing.usbmuxd_device.is_none() && !is_remote_tvos {
        existing.usbmuxd_device = incoming.usbmuxd_device;
    }
    if existing.pairing_address.is_none() {
        existing.pairing_address = incoming.pairing_address;
    }
    if existing.reconnect_address.is_none() {
        existing.reconnect_address = incoming.reconnect_address;
    }
    if existing.pairing_identity.is_none() {
        existing.pairing_identity = incoming.pairing_identity;
    }
    if existing.pairing_cache_dir.is_none() {
        existing.pairing_cache_dir = incoming.pairing_cache_dir;
    }
    if existing.device_id == 0 {
        existing.device_id = incoming.device_id;
    }
    existing.is_mac |= incoming.is_mac;
    existing.core_device_authenticated |= incoming.core_device_authenticated;
    if is_remote_tvos {
        existing.usbmuxd_device = None;
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000 * KB;
    const GB: u64 = 1_000 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        format!("{} B", bytes)
    }
}
