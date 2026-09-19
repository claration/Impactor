// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Functionality for signing Apple bundles.

use {
    crate::{
        code_directory::CodeDirectoryBlob,
        code_requirement::{CodeRequirementExpression, RequirementType},
        code_resources::{normalized_resources_path, CodeResourcesBuilder, CodeResourcesRule},
        cryptography::DigestType,
        embedded_signature::{Blob, BlobData},
        error::AppleCodesignError,
        macho::MachFile,
        macho_signing::{write_macho_file, MachOSigner},
        signing::path_identifier,
        signing_settings::{SettingsScope, SigningSettings},
    },
    apple_bundles::{BundlePackageType, DirectoryBundle},
    log::{debug, info, warn},
    simple_file_manifest::create_symlink,
    std::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet},
        io::Write,
        path::{Path, PathBuf},
    },
};

/// Copy a bundle's contents to a destination directory.
///
/// This does not use the CodeResources rules for a bundle. Rather, it
/// blindly copies all files in the bundle. This means that excluded files
/// can be copied.
///
/// Returns the set of bundle-relative paths that are installed.
pub fn copy_bundle(
    bundle: &DirectoryBundle,
    dest_dir: &Path,
) -> Result<BTreeSet<PathBuf>, AppleCodesignError> {
    let settings = SigningSettings::default();

    let mut context = BundleSigningContext {
        dest_dir: dest_dir.to_path_buf(),
        settings: &settings,
        previously_installed_paths: Default::default(),
        installed_paths: Default::default(),
    };

    for file in bundle
        .files(false)
        .map_err(AppleCodesignError::DirectoryBundle)?
    {
        context.install_file(file.absolute_path(), file.relative_path())?;
    }

    Ok(context.installed_paths)
}

/// A primitive for signing an Apple bundle.
///
/// This type handles the high-level logic of signing an Apple bundle (e.g.
/// a `.app` or `.framework` directory with a well-defined structure).
///
/// This type handles the signing of nested bundles (if present) such that
/// they chain to the main bundle's signature.
pub struct BundleSigner {
    /// All the bundles being signed, indexed by relative path.
    bundles: BTreeMap<Option<String>, SingleBundleSigner>,
}

impl BundleSigner {
    /// Construct a new instance given the path to an on-disk bundle.
    ///
    /// The path should be the root directory of the bundle. e.g. `MyApp.app`.
    pub fn new_from_path(path: impl AsRef<Path>) -> Result<Self, AppleCodesignError> {
        let main_bundle = DirectoryBundle::new_from_path(path.as_ref())
            .map_err(AppleCodesignError::DirectoryBundle)?;
        let root_bundle_path = main_bundle.root_dir().to_path_buf();

        let mut bundles = BTreeMap::default();

        bundles.insert(None, SingleBundleSigner::new(root_bundle_path, main_bundle));

        Ok(Self { bundles })
    }

    /// Find bundles in subdirectories of the main bundle and mark them for signing.
    pub fn collect_nested_bundles(&mut self) -> Result<(), AppleCodesignError> {
        let (root_bundle_path, nested) = {
            let main = self.bundles.get(&None).expect("main bundle should exist");

            let nested = main
                .bundle
                .nested_bundles(true)
                .map_err(AppleCodesignError::DirectoryBundle)?;

            (main.root_bundle_path.clone(), nested)
        };

        self.bundles.extend(
        nested.into_iter()
            .filter(|(k, bundle)| {
                // Our bundle classifier is very aggressive about annotating directories
                // as bundles. Pretty much anything with an Info.plist can get through.
                // We apply additional filtering here so we only emit bundles that can
                // be signed.
                //
                // A better solution here is to use the CodeResources rule
                // based file walker to look for directories with the "nested" flag.
                // If a bundle-looking directory exists outside of a "nested" rule,
                // it probably shouldn't be signed.

                let (has_package_type, has_signable_package_type) = if let Ok(Some(pt)) = bundle.info_plist_key_string("CFBundlePackageType") {
                    (true, pt != "dSYM")
                } else {
                    (false, false)
                };

                let has_bundle_identifier = matches!(bundle.info_plist_key_string("CFBundleIdentifier"), Ok(Some(_)));

                match (has_package_type, has_signable_package_type, has_bundle_identifier)  {
                    (true, false, _) =>{
                        debug!("{k} discarded because its CFBundlePackageType is not signable");
                        false
                    }
                    (true, _, true) => {
                        // It quacks like a bundle.
                        true
                    }
                    (false, _, false) => {
                        // This looks like a naked Info.plist.
                        debug!("{k} discarded as a signable bundle because its Info.plist lacks CFBundlePackageType and CFBundleIdentifier");
                        false
                    }
                    (true, _, false) => {
                        info!("{k} has an Info.plist with a CFBundlePackageType but not a CFBundleIdentifier; we'll try to sign it but we recommend adding a CFBundleIdentifier");
                        true
                    }
                    (false, _, true) => {
                        info!("{k} has an Info.plist with a CFBundleIdentifier but without a CFBundlePackageType; we'll try to sign it but we recommend adding a CFBundlePackageType");
                        true
                    }
                }
            })
            .map(|(k, bundle)| {
                (
                    Some(k),
                    SingleBundleSigner::new(root_bundle_path.clone(), bundle),
                )
            })
        );

        Ok(())
    }

    /// Write a signed bundle to the given destination directory.
    ///
    /// The destination directory can be the same as the source directory. However,
    /// if this is done and an error occurs in the middle of signing, the bundle
    /// may be left in an inconsistent or corrupted state and may not be usable.
    pub fn write_signed_bundle(
        &self,
        dest_dir: impl AsRef<Path>,
        settings: &SigningSettings,
    ) -> Result<DirectoryBundle, AppleCodesignError> {
        let dest_dir = dest_dir.as_ref();

        // We need to sign the leaf-most bundles first since a parent bundle may need
        // to record information about the child in its signature.
        let mut bundles = self
            .bundles
            .iter()
            .filter_map(|(rel, bundle)| rel.as_ref().map(|rel| (rel, bundle)))
            .collect::<Vec<_>>();

        // This won't preserve alphabetical order. But since the input was stable, output
        // should be deterministic.
        bundles.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));

        if !bundles.is_empty() {
            if settings.shallow() {
                warn!("{} nested bundles will be copied instead of signed because shallow signing enabled:", bundles.len());
            } else {
                warn!(
                    "signing {} nested bundles in the following order:",
                    bundles.len()
                );
            }
            for bundle in &bundles {
                warn!("{}", bundle.0);
            }
        }

        // We keep track of root relative input paths that have been installed so we can
        // skip installing in case we encounter the path again when signing a parent
        // bundle.
        //
        // If we fail to do this, during non-shallow signing operations we may descend
        // into a child bundle that is outside a directory with the "nested" flag set.
        // Files in non-"nested" directories need to be sealed in CodeResources files
        // as regular files, not bundles. So we need to walk into the child bundle in
        // this scenario. But during the walk we want to prevent already installed files
        // from being processed again.
        //
        // In the case of Mach-O binaries in the above non-"nested" directory scenario,
        // excluding already signed files prevents the Mach-O from being signed again.
        // Signing the Mach-O twice could invalidate the bundle's signature and/or result
        // in incorrect signing settings since a bundle's main binary wouldn't be
        // recognized as such since we're outside the context of that bundle.
        //
        // In all cases, we prevent redundant work installing files if a file is seen
        // twice.
        let mut installed_rel_paths = BTreeSet::<PathBuf>::new();

        for (rel, nested) in bundles {
            let rel_path = PathBuf::from(rel);

            let nested_dest_dir = dest_dir.join(rel);
            warn!("entering nested bundle {}", rel,);

            let bundle_installed_rel_paths = if settings.shallow() {
                warn!("shallow signing enabled; bundle will be copied instead of signed");
                copy_bundle(&nested.bundle, &nested_dest_dir)?
            } else if settings.path_exclusion_pattern_matches(rel) {
                // If we excluded this bundle from signing, just copy all the files.
                warn!("bundle is in exclusion list; it will be copied instead of signed");
                copy_bundle(&nested.bundle, &nested_dest_dir)?
            } else {
                let bundle_installed = installed_rel_paths
                    .iter()
                    .filter_map(|p| {
                        if let Ok(p) = p.strip_prefix(&rel_path) {
                            Some(p.to_path_buf())
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeSet<_>>();

                let info = nested.write_signed_bundle(
                    nested_dest_dir,
                    &settings.as_nested_bundle_settings(rel),
                    bundle_installed,
                )?;

                info.installed_rel_paths
            };

            for p in bundle_installed_rel_paths {
                installed_rel_paths.insert(rel_path.join(p).to_path_buf());
            }

            warn!("leaving nested bundle {}", rel);
        }

        let main = self
            .bundles
            .get(&None)
            .expect("main bundle should have a key");

        Ok(main
            .write_signed_bundle(dest_dir, settings, installed_rel_paths)?
            .bundle)
    }
}

/// Metadata about a signed Mach-O file or bundle.
///
/// If referring to a bundle, the metadata refers to the 1st Mach-O in the
/// bundle's main executable.
///
/// This contains enough metadata to construct references to the file/bundle
/// in [crate::code_resources::CodeResources] files.
pub struct SignedMachOInfo {
    /// Raw data constituting the code directory blob.
    ///
    /// Is typically digested to construct a <cdhash>.
    pub code_directory_blob: Vec<u8>,

    /// Designated code requirements string.
    ///
    /// Typically occupies a `<key>requirement</key>` in a
    /// [crate::code_resources::CodeResources] file.
    pub designated_code_requirement: Option<String>,
}

impl SignedMachOInfo {
    /// Parse Mach-O data to obtain an instance.
    pub fn parse_data(data: &[u8]) -> Result<Self, AppleCodesignError> {
        // Initial Mach-O's signature data is used.
        let mach = MachFile::parse(data)?;
        let macho = mach.nth_macho(0)?;

        let signature = macho
            .code_signature()?
            .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

        let code_directory_blob = signature.preferred_code_directory()?.to_blob_bytes()?;

        let designated_code_requirement = if let Some(requirements) =
            signature.code_requirements()?
        {
            if let Some(designated) = requirements.requirements.get(&RequirementType::Designated) {
                let req = designated.parse_expressions()?;

                Some(format!("{}", req[0]))
            } else {
                // In case no explicit requirements has been set, we use current file cdhashes.
                let mut requirement_expr = None;

                // We record the 20 byte digests of every code directory in every
                // Mach-O.
                // Note: Apple's tooling appears to always record the x86-64 Mach-O
                // first, even if it isn't first in the universal binary. Since we're
                // dealing with a bunch of OR'd code requirements expressions, we don't
                // believe this difference is worth caring about.
                for macho in mach.iter_macho() {
                    for (_, cd) in macho
                        .code_signature()?
                        .ok_or(AppleCodesignError::BinaryNoCodeSignature)?
                        .all_code_directories()?
                    {
                        let digest_type = if cd.digest_type == DigestType::Sha256 {
                            DigestType::Sha256Truncated
                        } else {
                            cd.digest_type
                        };

                        let digest = digest_type.digest_data(&cd.to_blob_bytes()?)?;
                        let expression = Box::new(CodeRequirementExpression::CodeDirectoryHash(
                            Cow::from(digest),
                        ));

                        if let Some(left_part) = requirement_expr {
                            requirement_expr = Some(Box::new(CodeRequirementExpression::Or(
                                left_part, expression,
                            )))
                        } else {
                            requirement_expr = Some(expression);
                        }
                    }
                }

                Some(format!(
                    "{}",
                    requirement_expr.expect("a Mach-O should have been present")
                ))
            }
        } else {
            None
        };

        Ok(SignedMachOInfo {
            code_directory_blob,
            designated_code_requirement,
        })
    }

    /// Resolve the parsed code directory from stored data.
    pub fn code_directory(&self) -> Result<Box<CodeDirectoryBlob<'_>>, AppleCodesignError> {
        let blob = BlobData::from_blob_bytes(&self.code_directory_blob)?;

        if let BlobData::CodeDirectory(cd) = blob {
            Ok(cd)
        } else {
            Err(AppleCodesignError::BinaryNoCodeSignature)
        }
    }

    /// Resolve the notarization ticket record name for this Mach-O file.
    pub fn notarization_ticket_record_name(&self) -> Result<String, AppleCodesignError> {
        let cd = self.code_directory()?;

        let digest_type: u8 = cd.digest_type.into();

        let mut digest = cd.digest_with(cd.digest_type)?;

        // Digests appear to be truncated at 20 bytes / 40 characters.
        digest.truncate(20);

        let digest = hex::encode(digest);

        // Unsure what the leading `2/` means.
        Ok(format!("2/{digest_type}/{digest}"))
    }
}

/// Holds state and helper methods to facilitate signing a bundle.
pub struct BundleSigningContext<'a, 'key> {
    /// Settings for this bundle.
    pub settings: &'a SigningSettings<'key>,
    /// Where the bundle is getting installed to.
    pub dest_dir: PathBuf,
    /// Bundle relative paths of files that have already been installed.
    ///
    /// The already-present destination file content should be used for sealing.
    pub previously_installed_paths: BTreeSet<PathBuf>,
    /// Bundle relative paths of files that are installed by this signing operation.
    pub installed_paths: BTreeSet<PathBuf>,
}

impl<'a, 'key> BundleSigningContext<'a, 'key> {
    /// Install a file (regular or symlink) in the destination directory.
    pub fn install_file(
        &mut self,
        source_path: &Path,
        bundle_rel_path: &Path,
    ) -> Result<PathBuf, AppleCodesignError> {
        let dest_path = self.dest_dir.join(bundle_rel_path);

        if source_path != dest_path {
            // Remove an existing file before installing the replacement. In
            // the case of symlinks this is required due to how symlink creation
            // works.
            if dest_path.symlink_metadata().is_ok() {
                std::fs::remove_file(&dest_path)?;
            }

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let metadata = source_path.symlink_metadata()?;
            let mtime = filetime::FileTime::from_last_modification_time(&metadata);

            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(source_path)?;
                info!(
                    "replicating symlink {} -> {}",
                    dest_path.display(),
                    target.display()
                );
                create_symlink(&dest_path, target)?;
                filetime::set_symlink_file_times(
                    &dest_path,
                    filetime::FileTime::from_last_access_time(&metadata),
                    mtime,
                )?;
            } else {
                info!(
                    "copying file {} -> {}",
                    source_path.display(),
                    dest_path.display()
                );
                // TODO consider stripping XATTR_RESOURCEFORK_NAME and XATTR_FINDERINFO_NAME.
                std::fs::copy(source_path, &dest_path)?;
                filetime::set_file_mtime(&dest_path, mtime)?;
            }
        }

        // Always record the installation even if we no-op. The intent of the
        // annotation is to mark files that are already present in the destination
        // bundle.
        self.installed_paths.insert(bundle_rel_path.to_path_buf());

        Ok(dest_path)
    }

    /// Sign a Mach-O file and ensure its new content is installed.
    ///
    /// Returns Mach-O metadata which can be recorded in a CodeResources file.

    pub fn sign_and_install_macho(
        &mut self,
        source_path: &Path,
        bundle_rel_path: &Path,
    ) -> Result<(PathBuf, SignedMachOInfo), AppleCodesignError> {
        warn!("signing Mach-O file {}", bundle_rel_path.display());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(source_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(source_path, perms)?;
        }

        let macho_data = std::fs::read(source_path)?;
        let signer = MachOSigner::new(&macho_data)?;

        let mut settings = self
            .settings
            .as_bundle_macho_settings(bundle_rel_path.to_string_lossy().as_ref());

        // When signing a Mach-O in the context of a bundle, always define the
        // binary identifier from the filename so everything is consistent.
        // Unless an existing setting overrides it, of course.
        if settings.binary_identifier(SettingsScope::Main).is_none() {
            let identifier = path_identifier(bundle_rel_path)?;
            info!("setting binary identifier based on path: {}", identifier);

            settings.set_binary_identifier(SettingsScope::Main, &identifier);
        }

        settings.import_settings_from_macho(&macho_data)?;

        let mut new_data = Vec::<u8>::with_capacity(macho_data.len() + 2_usize.pow(17));
        signer.write_signed_binary(&settings, &mut new_data)?;

        let dest_path = self.dest_dir.join(bundle_rel_path);

        info!("writing Mach-O to {}", dest_path.display());
        write_macho_file(source_path, &dest_path, &new_data)?;

        let info = SignedMachOInfo::parse_data(&new_data)?;

        self.installed_paths.insert(bundle_rel_path.to_path_buf());

        Ok((dest_path, info))
    }
}

/// Holds metadata describing the result of a bundle signing operation.
pub struct BundleSigningInfo {
    /// The signed bundle.
    pub bundle: DirectoryBundle,

    /// Bundle relative paths of files that are installed by this signing operation.
    pub installed_rel_paths: BTreeSet<PathBuf>,
}

/// A primitive for signing a single Apple bundle.
///
/// Unlike [BundleSigner], this type only signs a single bundle and is ignorant
/// about nested bundles. You probably want to use [BundleSigner] as the interface
/// for signing bundles, as failure to account for nested bundles can result in
/// signature verification errors.
pub struct SingleBundleSigner {
    /// Path of the root bundle being signed.
    root_bundle_path: PathBuf,

    /// The bundle being signed.
    bundle: DirectoryBundle,
}

impl SingleBundleSigner {
    /// Construct a new instance.
    pub fn new(root_bundle_path: PathBuf, bundle: DirectoryBundle) -> Self {
        Self {
            root_bundle_path,
            bundle,
        }
    }

    /// Write a signed bundle to the given directory.
    pub fn write_signed_bundle(
        &self,
        dest_dir: impl AsRef<Path>,
        settings: &SigningSettings,
        previously_installed_paths: BTreeSet<PathBuf>,
    ) -> Result<BundleSigningInfo, AppleCodesignError> {
        let dest_dir = dest_dir.as_ref();

        warn!(
            "signing bundle at {} into {}",
            self.bundle.root_dir().display(),
            dest_dir.display()
        );

        // Frameworks are a bit special.
        //
        // Modern frameworks typically have a `Versions/` directory containing directories
        // with the actual frameworks. These are the actual directories that are signed - not
        // the top-most directory. In fact, the top-most `.framework` directory doesn't have any
        // code signature elements at all and can effectively be ignored as far as signing
        // is concerned.
        //
        // But even if there is a `Versions/` directory with nested bundles to sign, the top-level
        // directory may have some symlinks. And those need to be preserved. In addition, there
        // may be symlinks in `Versions/`. `Versions/Current` is common.
        //
        // Of course, if there is no `Versions/` directory, the top-level directory could be
        // a valid framework warranting signing.
        if self.bundle.package_type() == BundlePackageType::Framework {
            if self.bundle.root_dir().join("Versions").is_dir() {
                info!("found a versioned framework; each version will be signed as its own bundle");

                // But we still need to preserve files (hopefully just symlinks) outside the
                // nested bundles under `Versions/`. Since we don't nest into child bundles
                // here, it should be safe to handle each encountered file.
                let mut context = BundleSigningContext {
                    dest_dir: dest_dir.to_path_buf(),
                    settings,
                    previously_installed_paths,
                    installed_paths: Default::default(),
                };

                for file in self
                    .bundle
                    .files(false)
                    .map_err(AppleCodesignError::DirectoryBundle)?
                {
                    context.install_file(file.absolute_path(), file.relative_path())?;
                }

                let bundle = DirectoryBundle::new_from_path(dest_dir)
                    .map_err(AppleCodesignError::DirectoryBundle)?;

                return Ok(BundleSigningInfo {
                    bundle,
                    installed_rel_paths: context.installed_paths,
                });
            } else {
                info!("found an unversioned framework; signing like normal");
            }
        }

        let dest_dir_root = dest_dir.to_path_buf();

        let dest_dir = if self.bundle.shallow() {
            dest_dir_root.clone()
        } else {
            dest_dir.join("Contents")
        };

        let mut resources_digests = settings.all_digests(SettingsScope::Main);

        // State in the main executable can influence signing settings of the bundle. So examine
        // it first.

        let main_exe = self
            .bundle
            .files(false)
            .map_err(AppleCodesignError::DirectoryBundle)?
            .into_iter()
            .find(|f| matches!(f.is_main_executable(), Ok(true)));

        if let Some(exe) = &main_exe {
            let macho_data = std::fs::read(exe.absolute_path())?;
            let mach = MachFile::parse(&macho_data)?;

            for macho in mach.iter_macho() {
                let need_sha1_sha256 = if let Some(targeting) = macho.find_targeting()? {
                    let sha256_version = targeting.platform.sha256_digest_support()?;

                    !sha256_version.matches(&targeting.minimum_os_version)
                } else {
                    true
                };

                if need_sha1_sha256
                    && resources_digests != vec![DigestType::Sha1, DigestType::Sha256]
                {
                    info!(
                        "activating SHA-1 + SHA-256 signing due to requirements of main executable"
                    );
                    resources_digests = vec![DigestType::Sha1, DigestType::Sha256];
                    break;
                }
            }
        }

        info!("collecting code resources files");

        // The set of rules to use is determined by whether the bundle *can* have a
        // `Resources/`, not whether it necessarily does. The exact rules for this are not
        // known. Essentially we want to test for the result of CFBundleCopyResourcesDirectoryURL().
        // We assume that we can use the resources rules when there is a `Resources` directory
        // (this seems obvious!) or when the bundle isn't shallow, as a non-shallow bundle should
        // be an app bundle and app bundles can always have resources (we think).
        let mut resources_builder =
            if self.bundle.resolve_path("Resources").is_dir() || !self.bundle.shallow() {
                CodeResourcesBuilder::default_resources_rules()?
            } else {
                CodeResourcesBuilder::default_no_resources_rules()?
            };

        // Ensure emitted digests match what we're configured to emit.
        resources_builder.set_digests(resources_digests.into_iter());

        // Exclude code signature files we'll write.
        resources_builder.add_exclusion_rule(CodeResourcesRule::new("^_CodeSignature/")?.exclude());
        // Ignore notarization ticket.
        resources_builder.add_exclusion_rule(CodeResourcesRule::new("^CodeResources$")?.exclude());
        // Ignore store manifest directory.
        resources_builder.add_exclusion_rule(CodeResourcesRule::new("^_MASReceipt$")?.exclude());

        // The bundle's main executable file's code directory needs to hold a
        // digest of the CodeResources file for the bundle. Therefore it needs to
        // be handled last. We add an exclusion rule to prevent the directory walker
        // from touching this file.
        if let Some(main_exe) = &main_exe {
            // Also seal the resources normalized path, just in case it is different.
            resources_builder.add_exclusion_rule(
                CodeResourcesRule::new(format!(
                    "^{}$",
                    regex::escape(&normalized_resources_path(main_exe.relative_path()))
                ))?
                .exclude(),
            );
        }

        let mut context = BundleSigningContext {
            dest_dir: dest_dir_root.clone(),
            settings,
            previously_installed_paths,
            installed_paths: Default::default(),
        };

        resources_builder.walk_and_seal_directory(
            &self.root_bundle_path,
            self.bundle.root_dir(),
            &mut context,
        )?;

        let info_plist_data = std::fs::read(self.bundle.info_plist_path())?;

        // The resources are now sealed. Write out that XML file.
        let code_resources_path = dest_dir.join("_CodeSignature").join("CodeResources");
        info!(
            "writing sealed resources to {}",
            code_resources_path.display()
        );
        std::fs::create_dir_all(code_resources_path.parent().unwrap())?;
        let mut resources_data = Vec::<u8>::new();
        resources_builder.write_code_resources(&mut resources_data)?;

        {
            let mut fh = std::fs::File::create(&code_resources_path)?;
            fh.write_all(&resources_data)?;
        }

        // Seal the main executable.
        if let Some(exe) = main_exe {
            warn!("signing main executable {}", exe.relative_path().display());

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(exe.absolute_path())?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(exe.absolute_path(), perms)?;
            }

            let macho_data = std::fs::read(exe.absolute_path())?;
            let signer = MachOSigner::new(&macho_data)?;

            let mut settings = settings
                .as_bundle_main_executable_settings(exe.relative_path().to_string_lossy().as_ref());

            // The identifier for the main executable is defined in the bundle's Info.plist.
            if let Some(ident) = self
                .bundle
                .identifier()
                .map_err(AppleCodesignError::DirectoryBundle)?
            {
                info!("setting main executable binary identifier to {} (derived from CFBundleIdentifier in Info.plist)", ident);
                settings.set_binary_identifier(SettingsScope::Main, ident);
            } else {
                info!("unable to determine binary identifier from bundle's Info.plist (CFBundleIdentifier not set?)");
            }

            settings.set_code_resources_data(SettingsScope::Main, resources_data);
            settings.set_info_plist_data(SettingsScope::Main, info_plist_data);

            // Important: manually override all settings before calling this so that
            // explicitly set settings are always used and we don't get misleading logs.
            // If we set settings after the fact, we may fail to define settings on a
            // sub-scope, leading the overwrite to not being used.
            settings.import_settings_from_macho(&macho_data)?;

            let mut new_data = Vec::<u8>::with_capacity(macho_data.len() + 2_usize.pow(17));
            signer.write_signed_binary(&settings, &mut new_data)?;

            let dest_path = dest_dir_root.join(exe.relative_path());
            info!("writing signed main executable to {}", dest_path.display());
            write_macho_file(exe.absolute_path(), &dest_path, &new_data)?;

            context
                .installed_paths
                .insert(exe.relative_path().to_path_buf());
        } else {
            warn!("bundle has no main executable to sign specially");
        }

        let bundle = DirectoryBundle::new_from_path(&dest_dir_root)
            .map_err(AppleCodesignError::DirectoryBundle)?;

        Ok(BundleSigningInfo {
            bundle,
            installed_rel_paths: context.installed_paths,
        })
    }
}
