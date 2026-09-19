// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! High level signing primitives.

use {
    crate::{
        bundle_signing::BundleSigner,
        dmg::DmgSigner,
        error::AppleCodesignError,
        macho_signing::{write_macho_file, MachOSigner},
        reader::PathType,
        signing_settings::{SettingsScope, SigningSettings},
    },
    apple_xar::{reader::XarReader, signing::XarSigner},
    log::{info, warn},
    std::{fs::File, path::Path},
};

/// An entity for performing signing that is able to handle all supported target types.
pub struct UnifiedSigner<'key> {
    settings: SigningSettings<'key>,
}

impl<'key> UnifiedSigner<'key> {
    /// Construct a new instance bound to a [SigningSettings].
    pub fn new(settings: SigningSettings<'key>) -> Self {
        Self { settings }
    }

    /// Signs `input_path` and writes the signed output to `output_path`.
    pub fn sign_path(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<(), AppleCodesignError> {
        let input_path = input_path.as_ref();

        match PathType::from_path(input_path)? {
            PathType::Bundle => self.sign_bundle(input_path, output_path),
            PathType::Dmg => self.sign_dmg(input_path, output_path),
            PathType::MachO => self.sign_macho(input_path, output_path),
            PathType::Xar => self.sign_xar(input_path, output_path),
            PathType::Zip | PathType::Other => Err(AppleCodesignError::UnrecognizedPathType),
        }
    }

    /// Sign a filesystem path in place.
    ///
    /// This is just a convenience wrapper for [Self::sign_path()] with the same path passed
    /// to both the input and output path.
    pub fn sign_path_in_place(&self, path: impl AsRef<Path>) -> Result<(), AppleCodesignError> {
        let path = path.as_ref();

        self.sign_path(path, path)
    }

    /// Sign a Mach-O binary.
    pub fn sign_macho(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<(), AppleCodesignError> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        warn!("signing {} as a Mach-O binary", input_path.display());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(input_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(input_path, perms)?;
        }

        let macho_data = std::fs::read(input_path)?;

        let mut settings = self.settings.clone();

        settings.import_settings_from_macho(&macho_data)?;

        if settings.binary_identifier(SettingsScope::Main).is_none() {
            let identifier = path_identifier(input_path)?;

            warn!("setting binary identifier to {}", identifier);
            settings.set_binary_identifier(SettingsScope::Main, identifier);
        }

        warn!("parsing Mach-O");
        let signer = MachOSigner::new(&macho_data)?;

        let mut macho_data = vec![];
        signer.write_signed_binary(&settings, &mut macho_data)?;
        warn!("writing Mach-O to {}", output_path.display());
        write_macho_file(input_path, output_path, &macho_data)?;

        Ok(())
    }

    /// Sign a `.dmg` file.
    pub fn sign_dmg(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<(), AppleCodesignError> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        warn!("signing {} as a DMG", input_path.display());

        // There must be a binary identifier on the DMG. So try to derive one
        // from the filename if one isn't present in the settings.
        let mut settings = self.settings.clone();

        if settings.binary_identifier(SettingsScope::Main).is_none() {
            let file_name = input_path
                .file_stem()
                .ok_or_else(|| {
                    AppleCodesignError::CliGeneralError("unable to resolve file name of DMG".into())
                })?
                .to_string_lossy();

            warn!(
                "setting binary identifier to {} (derived from file name)",
                file_name
            );
            settings.set_binary_identifier(SettingsScope::Main, file_name);
        }

        // The DMG signer signs in place because it needs a `File` handle. So if
        // the output path is different, copy the DMG first.

        // This is not robust same file detection.
        if input_path != output_path {
            info!(
                "copying {} to {} in preparation for signing",
                input_path.display(),
                output_path.display()
            );
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::copy(input_path, output_path)?;
        }

        let signer = DmgSigner::default();
        let mut fh = std::fs::File::options()
            .read(true)
            .write(true)
            .open(output_path)?;
        signer.sign_file(&settings, &mut fh)?;

        Ok(())
    }

    /// Sign a bundle.
    pub fn sign_bundle(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<(), AppleCodesignError> {
        let input_path = input_path.as_ref();
        warn!("signing bundle at {}", input_path.display());

        let mut signer = BundleSigner::new_from_path(input_path)?;
        signer.collect_nested_bundles()?;
        signer.write_signed_bundle(output_path, &self.settings)?;

        Ok(())
    }

    pub fn sign_xar(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<(), AppleCodesignError> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        // The XAR can get corrupted if we sign into place. So we always go through a temporary
        // file. We could potentially avoid the overhead if we're not signing in place...

        let output_path_temp =
            output_path.with_file_name(if let Some(file_name) = output_path.file_name() {
                file_name.to_string_lossy().to_string() + ".tmp"
            } else {
                "xar.tmp".to_string()
            });

        warn!(
            "signing XAR pkg installer at {} to {}",
            input_path.display(),
            output_path_temp.display()
        );

        let (signing_key, signing_cert) = self
            .settings
            .signing_key()
            .ok_or(AppleCodesignError::XarNoAdhoc)?;

        {
            let reader = XarReader::new(File::open(input_path)?)?;
            let mut signer = XarSigner::new(reader);

            let mut fh = File::create(&output_path_temp)?;
            signer.sign(
                &mut fh,
                signing_key,
                signing_cert,
                self.settings.time_stamp_url(),
                self.settings.certificate_chain().iter().cloned(),
            )?;
        }

        if output_path.exists() {
            warn!("removing existing {}", output_path.display());
            std::fs::remove_file(output_path)?;
        }

        warn!(
            "renaming {} -> {}",
            output_path_temp.display(),
            output_path.display()
        );
        std::fs::rename(&output_path_temp, output_path)?;

        Ok(())
    }
}

pub fn path_identifier(path: impl AsRef<Path>) -> Result<String, AppleCodesignError> {
    let path = path.as_ref();

    // We only care about the file name.
    let file_name = path
        .file_name()
        .ok_or_else(|| {
            AppleCodesignError::PathIdentifier(format!("path {} lacks a file name", path.display()))
        })?
        .to_string_lossy()
        .to_string();

    // Remove the final file extension unless it is numeric.
    let id = if let Some((prefix, extension)) = file_name.rsplit_once('.') {
        if extension.chars().all(|c| c.is_ascii_digit()) {
            file_name.as_str()
        } else {
            prefix
        }
    } else {
        file_name.as_str()
    };

    let is_digit_or_dot = |c: char| c == '.' || c.is_ascii_digit();

    // If begins with digit or dot, use as is, handling empty string special
    // case.
    let id = match id.chars().next() {
        Some(first) => {
            if is_digit_or_dot(first) {
                return Ok(id.to_string());
            } else {
                id
            }
        }
        None => {
            return Ok(id.to_string());
        }
    };

    // Strip all components having numeric *suffixes* except the first
    // one. This doesn't strip extension components but *suffixes*. So
    // e.g. libFoo1.2.3 -> libFoo1. Logically, we strip trailing digits
    // + dot after the first dot preceded by digits.

    let prefix = id.trim_end_matches(is_digit_or_dot);
    let stripped = &id[prefix.len()..];

    if stripped.is_empty() {
        Ok(id.to_string())
    } else {
        // If the next character is a dot, add it back in.
        let (prefix, stripped) = if matches!(stripped.chars().next(), Some('.')) {
            (&id[0..prefix.len() + 1], &stripped[1..])
        } else {
            (prefix, stripped)
        };

        // Add back in any leading digits.

        let id = prefix
            .chars()
            .chain(stripped.chars().take_while(|c| c.is_ascii_digit()))
            .collect::<String>();

        Ok(id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn path_identifier_normalization() {
        assert_eq!(path_identifier("foo").unwrap(), "foo");
        assert_eq!(path_identifier("foo.dylib").unwrap(), "foo");
        assert_eq!(path_identifier("/etc/foo.dylib").unwrap(), "foo");
        assert_eq!(path_identifier("/etc/foo").unwrap(), "foo");

        // Starts with digit or dot is preserved module final extension.
        assert_eq!(path_identifier(".foo").unwrap(), "");
        assert_eq!(path_identifier("123").unwrap(), "123");
        assert_eq!(path_identifier(".foo.dylib").unwrap(), ".foo");
        assert_eq!(path_identifier("123.dylib").unwrap(), "123");
        assert_eq!(path_identifier("123.42").unwrap(), "123.42");

        // Digit final extension preserved.

        assert_eq!(path_identifier("foo1").unwrap(), "foo1");
        assert_eq!(path_identifier("foo1.dylib").unwrap(), "foo1");
        assert_eq!(path_identifier("foo1.2.dylib").unwrap(), "foo1");
        assert_eq!(path_identifier("foo1.2").unwrap(), "foo1");
        assert_eq!(path_identifier("foo1.2.3.4.dylib").unwrap(), "foo1");
        assert_eq!(path_identifier("foo.1").unwrap(), "foo.1");
        assert_eq!(path_identifier("foo.1.2.3").unwrap(), "foo.1");
        assert_eq!(path_identifier("foo.1.2.dylib").unwrap(), "foo.1");
        assert_eq!(path_identifier("foo.1.dylib").unwrap(), "foo.1");
    }
}
