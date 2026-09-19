mod bundle;
mod cgbi;
mod device;
mod options;
mod package;
mod signer;
mod tweak;
pub mod wireless;

use std::path::Path;

pub use bundle::{Bundle, BundleType}; // Bundle helper
pub use device::{Device, get_device_for_id, install_app_mac}; // Device helper
pub use options::{
    SignerApp, // Supported app types
    SignerAppReal,
    SignerEmbedding,   // Embedding options
    SignerFeatures,    // Feature support options
    SignerInstallMode, // Installation mode
    SignerMode,        // Signing mode
    SignerOptions,     // Main
};
pub use package::Package; // Package helper
pub use signer::Signer; // Signer
pub use tweak::Tweak; // Tweak helper

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
    // Wireless pairing
    #[error("mDNS error: {0}")]
    Mdns(#[from] mdns_sd::Error),
    #[error("The device did not accept the pairing, it needs to be paired again")]
    PairingNotAccepted,
    #[error("No stored pairing for device: {0}")]
    PairingNotFound(String),
    #[error("Refusing to use an unsafe device identifier as a file name: {0}")]
    PairingInvalidUdid(String),

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

pub async fn copy_dir_recursively(src: &Path, dst: &Path) -> Result<(), Error> {
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
