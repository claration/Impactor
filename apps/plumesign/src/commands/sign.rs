use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use plume_core::{CertificateIdentity, MobileProvision};
use plume_utils::{Bundle, Package, Signer, SignerMode, SignerOptions};

use crate::{
    commands::{
        account::{get_authenticated_account, teams},
        device::select_device,
    },
    get_data_path,
};

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct SignArgs {
    /// Path to the app bundle or package to sign (.app or .ipa)
    #[arg(long, short, value_name = "PACKAGE")]
    pub package: PathBuf,
    /// PEM files for certificate and private key
    #[arg(long = "pem", value_name = "PEM", num_args = 1..)]
    pub pem_files: Option<Vec<PathBuf>>,
    /// Use Apple ID credentials for signing
    #[arg(long = "apple-id")]
    pub apple_id: bool,
    /// Provisioning profile files to embed
    #[arg(long = "provision", value_name = "PROVISION")]
    pub provisioning_files: Option<PathBuf>,
    /// Custom bundle identifier to set
    #[arg(long = "custom-identifier", value_name = "BUNDLE_ID")]
    pub bundle_identifier: Option<String>,
    /// Custom bundle name to set
    #[arg(long = "custom-name", value_name = "NAME")]
    pub name: Option<String>,
    /// Custom bundle version to set
    #[arg(long = "custom-version", value_name = "VERSION")]
    pub version: Option<String>,
    /// Perform ad-hoc signing (no certificate required)
    #[arg(long, short, num_args = 1..)]
    pub tweaks: Option<Vec<PathBuf>>,
    /// Register device and install after signing
    #[arg(long)]
    pub register_and_install: bool,
    /// Device UDID to register and install to (will prompt if not provided)
    #[arg(long, value_name = "UDID")]
    pub udid: Option<String>,
    /// Output path for signed .ipa (only for .ipa input)
    #[arg(long, short, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
    /// Install to connected Mac (arm64 only)
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[arg(short = 'm', long = "mac", value_name = "MAC", conflicts_with = "udid")]
    pub mac: bool,
}

pub async fn execute(args: SignArgs) -> Result<()> {
    if !args.package.is_dir() && !args.apple_id && args.output.is_none() {
        return Err(anyhow::anyhow!(
            "-o/--output is required when signing an .ipa without --apple-id (ad-hoc mode)."
        ));
    }

    let mut options = SignerOptions {
        custom_identifier: args.bundle_identifier,
        custom_name: args.name,
        custom_version: args.version,
        tweaks: args.tweaks,
        ..Default::default()
    };

    let (bundle, package) = if args.package.is_dir() {
        log::warn!("⚠️  Signing bundle in place: {}", args.package.display());
        if args.output.is_some() {
            log::warn!(
                "Note: -o/--output flag is ignored for .app bundles (in-place signing only)"
            );
        }
        (Bundle::new(&args.package)?, None)
    } else {
        let pkg = Package::new(args.package.clone())?;
        let bundle = pkg.get_package_bundle()?;
        (bundle, Some(pkg))
    };

    let (mut signer, team_id_opt) = if let Some(ref pem_files) = args.pem_files {
        let cert_identity = CertificateIdentity::new_with_paths(Some(pem_files.clone())).await?;

        options.mode = SignerMode::Pem;
        (Signer::new(Some(cert_identity), options), None)
    } else if args.apple_id {
        let session = get_authenticated_account().await?;
        let team_id = teams(&session).await?;
        let cert_identity = CertificateIdentity::new_with_session(
            &session,
            get_data_path(),
            None,
            &team_id,
            false,
            None,
        )
        .await?;

        options.mode = SignerMode::Pem;
        (
            Signer::new(Some(cert_identity), options),
            Some((session, team_id)),
        )
    } else {
        options.mode = SignerMode::Adhoc;
        (Signer::new(None, options), None)
    };

    if let Some(provision_path) = args.provisioning_files {
        let prov = MobileProvision::load_with_path(&provision_path)?;
        signer.provisioning_files.push(prov.clone());
    }

    let device = if args.register_and_install {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            if args.mac {
                use plume_utils::Device;

                Some(Device {
                    name: "My Mac".to_string(),
                    udid: String::new(),
                    device_id: 0,
                    usbmuxd_device: None,
                    is_mac: true,
                })
            } else {
                Some(select_device(args.udid).await?)
            }
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            Some(select_device(args.udid).await?)
        }
    } else {
        None
    };

    if let Some((session, team_id)) = team_id_opt {
        signer
            .modify_bundle(&bundle, &Some(team_id.clone()))
            .await?;

        if let Some(ref dev) = device {
            log::info!("Registering device: {} ({})", dev.name, dev.udid);
            session
                .qh_ensure_device(&team_id, &dev.name, &dev.udid)
                .await?;
        }

        signer
            .register_bundle(&bundle, &session, &team_id, false)
            .await?;
        signer.sign_bundle(&bundle).await?;

        if let Some(dev) = device {
            log::info!("Installing to device: {}", dev.name);
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if args.mac {
                plume_utils::install_app_mac(&bundle.bundle_dir()).await?;
            } else {
                dev.install_app(bundle.bundle_dir(), |progress| async move {
                    log::info!("Installation progress: {}%", progress);
                })
                .await?;
            }

            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            {
                dev.install_app(bundle.bundle_dir(), |progress| async move {
                    log::info!("Installation progress: {}%", progress);
                })
                .await?;
            }

            log::info!("Installation complete!");
        }
    } else {
        signer.modify_bundle(&bundle, &None).await?;
        signer.sign_bundle(&bundle).await?;

        if let Some(dev) = device {
            log::info!("Installing to device: {}", dev.name);
            dev.install_app(bundle.bundle_dir(), |progress| async move {
                log::info!("Installation progress: {}%", progress);
            })
            .await?;

            log::info!("Installation complete!");
        }
    }

    if let Some(pkg) = package {
        if let Some(output_path) = args.output {
            let archived_path = pkg.get_archive_based_on_path(&bundle.bundle_dir())?;
            tokio::fs::copy(&archived_path, &output_path).await?;
            log::info!("Saved signed package to: {}", output_path.display());
            if std::env::var("PLUME_DELETE_AFTER_FINISHED").is_err() {
                pkg.remove_package_stage();
            }
        } else {
            log::info!("Signed .ipa successfully (not archived, use -o to save)");
            if std::env::var("PLUME_DELETE_AFTER_FINISHED").is_err() {
                pkg.remove_package_stage();
            }
        }
    }

    Ok(())
}
