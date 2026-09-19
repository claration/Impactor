// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        cli::{CliCommand, Context},
        code_requirement::CodeRequirements,
        cryptography::DigestType,
        error::{AppleCodesignError, Result},
    },
    clap::{Parser, ValueEnum},
    log::warn,
    std::{ops::Deref, path::PathBuf},
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum MachOArch {
    Aarch64,
    X86_64,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum MachOFileType {
    Executable,
    Dylib,
}

impl MachOFileType {
    fn to_header_filetype(&self) -> u32 {
        match self {
            Self::Executable => object::macho::MH_EXECUTE,
            Self::Dylib => object::macho::MH_DYLIB,
        }
    }
}

#[derive(Parser)]
pub struct DebugCreateCodeRequirements {
    /// Code requirement expression to emit.
    #[arg(long, value_enum)]
    code_requirement: crate::policy::ExecutionPolicy,

    /// Path to write binary requirements to.
    path: PathBuf,
}

impl CliCommand for DebugCreateCodeRequirements {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let expression = self.code_requirement.deref();

        let mut reqs = CodeRequirements::default();
        reqs.push(expression.clone());

        let data = reqs.to_blob_data()?;

        println!("writing code requirements to {}", self.path.display());

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.path, data)?;

        Ok(())
    }
}

#[derive(Parser)]
pub struct DebugCreateConstraints {
    /// Team identifier constraint.
    #[arg(long)]
    team_id: Option<String>,

    /// Path to write plist XML to.
    path: PathBuf,
}

impl CliCommand for DebugCreateConstraints {
    fn run(&self, _context: &Context) -> Result<()> {
        let mut v = plist::Dictionary::default();

        if let Some(id) = &self.team_id {
            v.insert("team-identifier".into(), id.to_string().into());
        }

        let mut reqs = plist::Dictionary::default();

        reqs.insert("$or".into(), v.into());

        let v = plist::Value::Dictionary(reqs);

        println!("writing constraints plist to {}", self.path.display());
        v.to_file_xml(&self.path)?;

        Ok(())
    }
}

#[derive(Parser)]
pub struct DebugCreateEntitlements {
    /// Add the `get-task-allow` entitlement.
    #[arg(long)]
    get_task_allow: bool,

    /// Add the `run-unsigned-code` entitlement.
    #[arg(long)]
    run_unsigned_code: bool,

    /// Add the `com.apple.private.cs.debugger` entitlement.
    #[arg(long)]
    debugger: bool,

    /// Add the `dynamic-codesigning` entitlement.
    #[arg(long)]
    dynamic_code_signing: bool,

    /// Add the `com.apple.private.skip-library-validation` entitlement.
    #[arg(long)]
    skip_library_validation: bool,

    /// Add the `com.apple.private.amfi.can-load-cdhash` entitlement.
    #[arg(long)]
    can_load_cd_hash: bool,

    /// Add the `com.apple.private.amfi.can-execute-cdhash` entitlement.
    #[arg(long)]
    can_execute_cd_hash: bool,

    /// Path to write entitlements to.
    output_path: PathBuf,
}

impl CliCommand for DebugCreateEntitlements {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let mut d = plist::Dictionary::default();

        if self.get_task_allow {
            d.insert("get-task-allow".into(), true.into());
        }
        if self.run_unsigned_code {
            d.insert("run-unsigned-code".into(), true.into());
        }
        if self.debugger {
            d.insert("com.apple.private.cs.debugger".into(), true.into());
        }
        if self.dynamic_code_signing {
            d.insert("dynamic-codesigning".into(), true.into());
        }
        if self.skip_library_validation {
            d.insert(
                "com.apple.private.skip-library-validation".into(),
                true.into(),
            );
        }
        if self.can_load_cd_hash {
            d.insert("com.apple.private.amfi.can-load-cdhash".into(), true.into());
        }
        if self.can_execute_cd_hash {
            d.insert(
                "com.apple.private.amfi.can-execute-cdhash".into(),
                true.into(),
            );
        }

        let value = plist::Value::from(d);
        let mut xml = vec![];
        value.to_writer_xml(&mut xml)?;

        warn!("writing {}", self.output_path.display());
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.output_path, &xml)?;

        Ok(())
    }
}

#[derive(Parser)]
pub struct DebugCreateInfoPlist {
    /// Name of the bundle.
    #[arg(long)]
    bundle_name: String,

    /// Bundle package type.
    #[arg(long, default_value = "APPL")]
    package_type: String,

    /// CFBundleExecutable value.
    #[arg(long)]
    bundle_executable: Option<String>,

    /// Bundle identifier.
    #[arg(long, default_value = "com.example.mybundle")]
    bundle_identifier: String,

    /// Bundle version.
    #[arg(long, default_value = "1.0.0")]
    bundle_version: String,

    /// Path to write Info.plist to.
    output_path: PathBuf,

    /// Write an empty Info.plist file. Other arguments ignored.
    #[arg(long)]
    empty: bool,
}

impl CliCommand for DebugCreateInfoPlist {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let mut d = plist::Dictionary::default();

        if !self.empty {
            d.insert("CFBundleName".into(), self.bundle_name.clone().into());
            d.insert(
                "CFBundlePackageType".into(),
                self.package_type.clone().into(),
            );
            d.insert(
                "CFBundleDisplayName".into(),
                self.bundle_name.clone().into(),
            );
            if let Some(exe) = &self.bundle_executable {
                d.insert("CFBundleExecutable".into(), exe.clone().into());
            }
            d.insert(
                "CFBundleIdentifier".into(),
                self.bundle_identifier.clone().into(),
            );
            d.insert("CFBundleVersion".into(), self.bundle_version.clone().into());
            d.insert("CFBundleSignature".into(), "sig".into());
            d.insert("CFBundleExecutable".into(), self.bundle_name.clone().into());
        }

        let value = plist::Value::from(d);

        let mut xml = vec![];
        value.to_writer_xml(&mut xml)?;

        println!("writing {}", self.output_path.display());
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.output_path, &xml)?;

        Ok(())
    }
}

#[derive(Parser)]
pub struct DebugCreateMachO {
    /// Architecture of Mach-O binary.
    #[arg(long, value_enum, default_value_t = MachOArch::Aarch64)]
    architecture: MachOArch,

    /// The Mach-O file type.
    #[arg(long, value_enum, default_value_t = MachOFileType::Executable)]
    file_type: MachOFileType,

    /// Do not write platform targeting to Mach-O binary.
    #[arg(long)]
    no_targeting: bool,

    /// The minimum operating system version the binary will run on.
    #[arg(long)]
    minimum_os_version: Option<semver::Version>,

    /// The platform SDK version used to build the binary.
    #[arg(long)]
    sdk_version: Option<semver::Version>,

    /// Set the file start offset of the __TEXT segment.
    #[arg(long)]
    text_segment_start_offset: Option<usize>,

    /// Filename of Mach-O binary to write.
    output_path: PathBuf,
}

impl CliCommand for DebugCreateMachO {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let mut builder = match self.architecture {
            MachOArch::Aarch64 => {
                crate::macho_builder::MachOBuilder::new_aarch64(self.file_type.to_header_filetype())
            }
            MachOArch::X86_64 => {
                crate::macho_builder::MachOBuilder::new_x86_64(self.file_type.to_header_filetype())
            }
        };

        let target = match (
            self.no_targeting,
            &self.minimum_os_version,
            &self.sdk_version,
        ) {
            (true, _, _) => None,
            (false, None, None) => {
                warn!("assuming default minimum version 11.0.0");

                Some(crate::macho::MachoTarget {
                    platform: crate::Platform::MacOs,
                    minimum_os_version: semver::Version::new(11, 0, 0),
                    sdk_version: semver::Version::new(11, 0, 0),
                })
            }
            (false, _, _) => {
                let minimum_os_version = self
                    .minimum_os_version
                    .clone()
                    .unwrap_or_else(|| self.sdk_version.clone().unwrap());
                let sdk_version = self
                    .sdk_version
                    .clone()
                    .unwrap_or_else(|| self.minimum_os_version.clone().unwrap());

                Some(crate::macho::MachoTarget {
                    platform: crate::Platform::MacOs,
                    minimum_os_version,
                    sdk_version,
                })
            }
        };

        if let Some(target) = target {
            builder = builder.macho_target(target);
        }

        if let Some(offset) = self.text_segment_start_offset {
            builder = builder.text_segment_start_offset(offset);
        }

        let data = builder.write_macho()?;

        warn!("writing Mach-O to {}", self.output_path.display());
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.output_path, data)?;

        Ok(())
    }
}

#[derive(Parser)]
pub struct DebugFileTree {
    /// Directory to walk.
    path: PathBuf,
}

impl CliCommand for DebugFileTree {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let root = self
            .path
            .components()
            .last()
            .expect("should have final component")
            .as_os_str()
            .to_string_lossy()
            .to_string();

        for entry in walkdir::WalkDir::new(&self.path).sort_by_file_name() {
            let entry = entry?;

            let path = entry.path();

            let rel_path = if let Ok(p) = path.strip_prefix(&self.path) {
                format!("{}/{}", root, p.to_string_lossy().replace('\\', "/"))
            } else {
                root.clone()
            };

            let metadata = entry.metadata()?;

            let entry_type = if metadata.is_symlink() {
                'l'
            } else if metadata.is_dir() {
                'd'
            } else if metadata.is_file() {
                'f'
            } else {
                'u'
            };

            let sha256 = if entry_type == 'f' {
                let data = std::fs::read(path)?;
                hex::encode(DigestType::Sha256.digest_data(&data)?)[0..20].to_string()
            } else {
                " ".repeat(20)
            };

            let link_target = if entry_type == 'l' {
                format!(" -> {}", std::fs::read_link(path)?.to_string_lossy())
            } else {
                "".to_string()
            };

            println!("{} {} {}{}", entry_type, sha256, rel_path, link_target);
        }

        Ok(())
    }
}
