use std::{
    env,
    path::{Path, PathBuf},
};

use plume_core::MachO;
use uuid::Uuid;

use crate::{Bundle, Error, PlistInfoTrait, TweakInjection, TweakLoader, copy_dir_recursively};

const ELLEKIT_BYTES: &[u8] = include_bytes!("./ellekit.deb");

pub struct Tweak {
    path: PathBuf,
    app_bundle: PathBuf,
    stage_dir: PathBuf,
    loader: TweakLoader,
    injection: TweakInjection,
}

impl Tweak {
    pub async fn install_ellekit(app_bundle: &Bundle) -> Result<(), Error> {
        let stage_dir = env::temp_dir().join(format!("plume_ellekit_{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&stage_dir).await?;

        let deb_path = stage_dir.join("ellekit.deb");
        tokio::fs::write(&deb_path, ELLEKIT_BYTES).await?;

        let tweak = Tweak::new_with_options(
            &deb_path,
            app_bundle,
            TweakLoader::ElleKit,
            TweakInjection::Legacy,
        )
        .await?;
        tweak.install_deb().await?;

        tokio::fs::remove_dir_all(&stage_dir).await.ok();

        Ok(())
    }

    pub async fn new<P: AsRef<Path>>(tweak_path: P, app_bundle: &Bundle) -> Result<Self, Error> {
        Self::new_with_options(
            tweak_path,
            app_bundle,
            TweakLoader::ElleKit,
            TweakInjection::Legacy,
        )
        .await
    }

    pub async fn new_with_loader<P: AsRef<Path>>(
        tweak_path: P,
        app_bundle: &Bundle,
        loader: TweakLoader,
    ) -> Result<Self, Error> {
        Self::new_with_options(tweak_path, app_bundle, loader, TweakInjection::Legacy).await
    }

    pub async fn new_with_options<P: AsRef<Path>>(
        tweak_path: P,
        app_bundle: &Bundle,
        loader: TweakLoader,
        injection: TweakInjection,
    ) -> Result<Self, Error> {
        let path = tweak_path.as_ref();
        if !path.exists() {
            return Err(Error::TweakInvalidPath);
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::TweakInvalidPath)?;

        if !file_name.ends_with(".deb")
            && !file_name.ends_with(".dylib")
            && !file_name.ends_with(".framework")
            && !file_name.ends_with(".bundle")
            && !file_name.ends_with(".appex")
        {
            return Err(Error::UnsupportedFileType(file_name.to_string()));
        }

        let stage_dir = env::temp_dir().join(format!("plume_tweak_{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&stage_dir).await?;

        Ok(Self {
            path: path.to_path_buf(),
            app_bundle: app_bundle.bundle_dir().clone(),
            stage_dir,
            loader,
            injection,
        })
    }

    pub async fn apply(&self) -> Result<(), Error> {
        let file_name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::TweakInvalidPath)?;

        if file_name.ends_with(".deb") {
            self.install_deb().await?;
        } else if file_name.ends_with(".framework") {
            self.install_framework(&self.path).await?;
        } else if file_name.ends_with(".bundle") {
            self.install_bundle(&self.path).await?;
        } else if file_name.ends_with(".appex") {
            self.install_appex(&self.path).await?;
        } else if file_name.ends_with(".dylib") {
            self.install_dylib(&self.path).await?;
        }

        tokio::fs::remove_dir_all(&self.stage_dir).await.ok();

        Ok(())
    }

    async fn install_deb(&self) -> Result<(), Error> {
        use decompress::ExtractOpts;

        let extract_dir = self.stage_dir.join("deb_contents");
        tokio::fs::create_dir_all(&extract_dir).await?;

        let ar_extract_dir = self.stage_dir.join("ar_contents");
        tokio::fs::create_dir_all(&ar_extract_dir).await?;

        let ar_path_sync = self.path.clone();
        let ar_extract_dir_sync = ar_extract_dir.clone();

        tokio::task::spawn_blocking(move || {
            decompress::decompress(
                &ar_path_sync,
                &ar_extract_dir_sync,
                &ExtractOpts {
                    strip: 0,
                    detect_content: false,
                    filter: Box::new(|_: &std::path::Path| true),
                    map: Box::new(|p| std::borrow::Cow::Borrowed(p)),
                },
            )
        })
        .await
        .ok()
        .and_then(|r| r.ok())
        .ok_or_else(|| Error::TweakExtractionFailed("Failed to extract .ar archive".to_string()))?;

        for archive_name in [
            "data.tar.lzma",
            "data.tar.gz",
            "data.tar.xz",
            "data.tar.bz2",
            "data.tar",
        ] {
            let data_path = ar_extract_dir.join(archive_name);
            if data_path.exists() {
                let extract_dir_sync = extract_dir.clone();
                let data_path_sync = data_path.clone();

                tokio::task::spawn_blocking(move || {
                    decompress::decompress(
                        &data_path_sync,
                        &extract_dir_sync,
                        &ExtractOpts {
                            strip: 0,
                            detect_content: false,
                            filter: Box::new(|_: &std::path::Path| true),
                            map: Box::new(|p| std::borrow::Cow::Borrowed(p)),
                        },
                    )
                })
                .await
                .map_err(|e| {
                    Error::TweakExtractionFailed(format!("Failed to extract data.tar: {}", e))
                })?
                .map_err(|e| {
                    Error::TweakExtractionFailed(format!("Failed to extract data.tar: {}", e))
                })?;

                break;
            }
        }

        self.scan_and_install(&extract_dir).await
    }

    async fn scan_and_install(&self, root: &Path) -> Result<(), Error> {
        let search_paths = [
            "Library/MobileSubstrate/DynamicLibraries",
            "usr/lib",
            "Library/Frameworks",
            "Library/Application Support",
            "var/jb/Library/MobileSubstrate/DynamicLibraries",
            "var/jb/usr/lib",
            "var/jb/Library/Frameworks",
            "var/jb/Library/Application Support",
        ];

        for search_path in search_paths {
            let dir = root.join(search_path);
            if dir.exists() {
                self.scan_directory(&dir).await?;
            }
        }

        Ok(())
    }

    async fn scan_directory(&self, dir: &Path) -> Result<(), Error> {
        use futures::future::BoxFuture;

        fn scan_recursive<'a>(tweak: &'a Tweak, dir: &'a Path) -> BoxFuture<'a, Result<(), Error>> {
            Box::pin(async move {
                let mut entries = tokio::fs::read_dir(dir).await?;

                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    let metadata = tokio::fs::symlink_metadata(&path).await?;

                    if metadata.is_symlink() {
                        continue;
                    }

                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if path.is_file() && name.ends_with(".dylib") {
                            tweak.install_dylib(&path).await?;
                        } else if path.is_dir() {
                            if name.ends_with(".framework") {
                                tweak.install_framework(&path).await?;
                            } else if name.ends_with(".bundle") {
                                tweak.install_bundle(&path).await?;
                            } else if name.ends_with(".appex") {
                                tweak.install_appex(&path).await?;
                            } else {
                                // Recursively scan subdirectories
                                scan_recursive(tweak, &path).await?;
                            }
                        }
                    }
                }

                Ok(())
            })
        }

        scan_recursive(self, dir).await
    }

    async fn install_dylib(&self, dylib_path: &Path) -> Result<(), Error> {
        let install_dir = self.injection.destination_dir(&self.app_bundle);
        tokio::fs::create_dir_all(&install_dir).await?;

        let dylib_name = dylib_path.file_name().ok_or(Error::TweakInvalidPath)?;
        let dylib_name_str = dylib_name.to_str().ok_or(Error::TweakInvalidPath)?;
        let dest = install_dir.join(dylib_name);

        tokio::fs::copy(dylib_path, &dest).await?;

        if self.loader == TweakLoader::ElleKit {
            Self::patch_cydiasubstrate(&dest);
        }

        let load_path = self.injection.dylib_load_path(dylib_name_str);
        self.inject_load_path(&load_path).await
    }

    async fn install_framework(&self, framework_path: &Path) -> Result<(), Error> {
        let install_dir = self.injection.destination_dir(&self.app_bundle);
        tokio::fs::create_dir_all(&install_dir).await?;

        let framework_name = framework_path.file_name().ok_or(Error::TweakInvalidPath)?;
        let framework_name_str = framework_name.to_str().ok_or(Error::TweakInvalidPath)?;
        let dest = install_dir.join(framework_name);

        copy_dir_recursively(&framework_path, &dest).await?;

        if let Ok(bundle) = Bundle::new(&dest) {
            if let Some(exec_name) = bundle.get_executable() {
                let exec_path = dest.join(&exec_name);
                if exec_path.exists() {
                    if self.loader == TweakLoader::ElleKit {
                        Self::patch_cydiasubstrate(&exec_path);
                    }

                    let load_path = self
                        .injection
                        .framework_load_path(framework_name_str, &exec_name);
                    self.inject_load_path(&load_path).await?;
                }
            }
        }

        Ok(())
    }

    async fn install_bundle(&self, bundle_path: &Path) -> Result<(), Error> {
        let bundle_name = bundle_path.file_name().ok_or(Error::TweakInvalidPath)?;
        let dest = self.app_bundle.join(bundle_name);

        copy_dir_recursively(bundle_path, &dest).await
    }

    async fn install_appex(&self, appex_path: &Path) -> Result<(), Error> {
        let plugins_dir = self.app_bundle.join("PlugIns");
        tokio::fs::create_dir_all(&plugins_dir).await?;

        let appex_name = appex_path.file_name().ok_or(Error::TweakInvalidPath)?;
        let dest = plugins_dir.join(appex_name);

        copy_dir_recursively(appex_path, &dest).await
    }

    async fn inject_load_path(&self, load_path: &str) -> Result<(), Error> {
        let bundle = Bundle::new(&self.app_bundle)?;
        let executable_name = bundle
            .get_executable()
            .ok_or(Error::BundleInfoPlistMissing)?;

        let executable_path = self.app_bundle.join(&executable_name);
        if !executable_path.exists() {
            return Err(Error::BundleInfoPlistMissing);
        }

        if let Some(rpath) = self.injection.required_rpath() {
            let mut macho = MachO::new(&executable_path)?;
            macho.add_rpath(rpath)?;
        }

        // Re-parse after adding LC_RPATH so LC_LOAD_DYLIB insertion sees the updated header.
        let mut macho = MachO::new(&executable_path)?;
        macho.add_dylib(load_path)?;

        Ok(())
    }

    fn patch_cydiasubstrate(binary_path: &Path) {
        if let Ok(mut macho) = MachO::new(binary_path) {
            let _ = macho.replace_dylib(
                "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                "@rpath/CydiaSubstrate.framework/CydiaSubstrate",
            );
            let _ = macho.write_changes();
        }
    }
}
