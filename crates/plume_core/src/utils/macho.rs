use std::fs;
use std::path::Path;

use apple_codesign::{MachFile, MachOBinary, UniversalBinaryBuilder};
use goblin::mach::{
    MachO as GoblinMachO,
    cputype::CPU_TYPE_ARM64,
    load_command::{
        CommandVariant, LC_LAZY_LOAD_DYLIB, LC_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB,
        LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
    },
};
use plist::{Dictionary, Value};

use crate::Error;

/// Represents a Mach-O file and its entitlements.
pub struct MachO {
    data: Vec<u8>,
    path: std::path::PathBuf,
    entitlements: Option<Dictionary>,
}

impl MachO {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let data = fs::read(&path)?;
        let macho_file = MachFile::parse(&data)?;
        let entitlements = Self::extract_entitlements(&macho_file)?;

        Ok(MachO {
            data,
            path: path.as_ref().to_path_buf(),
            entitlements,
        })
    }

    pub fn macho_file(&self) -> MachFile<'_> {
        MachFile::parse(&self.data).expect("MachO struct should contain valid data")
    }

    pub fn entitlements(&self) -> &Option<Dictionary> {
        &self.entitlements
    }

    fn extract_entitlements(macho_file: &MachFile<'_>) -> Result<Option<Dictionary>, Error> {
        macho_file.nth_macho(0)?.embedded_entitlements()
    }

    pub fn app_groups_for_entitlements(&self) -> Option<Vec<String>> {
        self.entitlements
            .as_ref()
            .and_then(|e| e.get("com.apple.security.application-groups")?.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_string().map(|s| s.to_string()))
                    .collect()
            })
    }

    fn modify_binaries<F>(&mut self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&MachOBinary<'_>) -> Result<Vec<u8>, Error>,
    {
        let macho_file = self.macho_file();
        let mut builder = UniversalBinaryBuilder::default();
        for binary in macho_file.iter_macho() {
            builder.add_binary(&f(binary)?)?;
        }
        self.data.clear();
        builder.write(&mut self.data)?;
        fs::write(&self.path, &self.data)?;
        Ok(())
    }

    pub fn add_dylib(&mut self, path: &str) -> Result<(), Error> {
        self.modify_binaries(|macho| macho.add_dylib_load_path(path))
    }

    pub fn replace_dylib(&mut self, old_path: &str, new_path: &str) -> Result<(), Error> {
        self.modify_binaries(|macho| macho.replace_dylib_load_path(old_path, new_path))
    }

    pub fn remove_dylib(&mut self, path: &str) -> Result<(), Error> {
        self.modify_binaries(|macho| macho.remove_dylib_load_path(path))
    }

    pub fn replace_sdk_version(&mut self, new_version: &str) -> Result<(), Error> {
        self.modify_binaries(|macho| macho.replace_sdk_version(new_version))
    }
}

#[allow(dead_code)]
pub trait MachOExt {
    fn embedded_entitlements(&self) -> Result<Option<Dictionary>, Error>;
    fn dylib_load_paths(&self) -> Result<Vec<String>, Error>;
    fn add_dylib_load_path(&self, path: &str) -> Result<Vec<u8>, Error>;
    fn remove_dylib_load_path(&self, path: &str) -> Result<Vec<u8>, Error>;
    fn replace_dylib_load_path(&self, old_path: &str, new_path: &str) -> Result<Vec<u8>, Error>;
    fn replace_sdk_version(&self, new_version: &str) -> Result<Vec<u8>, Error>;
}

// theres multiple binaries in MachFile, being Vec<MachOBinary>
impl<'a> MachOExt for MachOBinary<'a> {
    fn embedded_entitlements(&self) -> Result<Option<Dictionary>, Error> {
        if let Some(embedded_sig) = self.code_signature()? {
            if let Ok(Some(slot)) = embedded_sig.entitlements() {
                let value = Value::from_reader_xml(slot.to_string().as_bytes())?;
                if let Value::Dictionary(dict) = value {
                    return Ok(Some(dict));
                }
            }
        }

        Ok(None)
    }

    fn dylib_load_paths(&self) -> Result<Vec<String>, Error> {
        const DYLIB_COMMANDS: &[u32] = &[
            LC_LOAD_DYLIB,
            LC_LOAD_WEAK_DYLIB,
            LC_REEXPORT_DYLIB,
            LC_LAZY_LOAD_DYLIB,
            LC_LOAD_UPWARD_DYLIB,
        ];

        let mut paths = Vec::new();

        for load_cmd in &self.macho.load_commands {
            if DYLIB_COMMANDS.contains(&load_cmd.command.cmd()) {
                let path = match &load_cmd.command {
                    CommandVariant::LoadDylib(dylib) => {
                        extract_dylib_path(self.data, load_cmd.offset, dylib.dylib.name)
                    }
                    _ => manually_parse_dylib(self.data, load_cmd.offset),
                };
                if let Some(p) = path {
                    paths.push(p);
                }
            }
        }

        Ok(paths)
    }

    // these require rewriting the Mach-O
    fn add_dylib_load_path(&self, path: &str) -> Result<Vec<u8>, Error> {
        let macho = &self.macho;

        let read_u32_le = |data: &[u8], offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };

        let dylib_exists_in_macho = |macho: &GoblinMachO, base_offset: usize| -> bool {
            macho.load_commands.iter().any(|load_cmd| {
                if let CommandVariant::LoadDylib(dylib) = &load_cmd.command {
                    extract_dylib_path(&self.data, base_offset + load_cmd.offset, dylib.dylib.name)
                        .map_or(false, |name| name == path)
                } else {
                    manually_parse_dylib(&self.data, base_offset + load_cmd.offset)
                        .map_or(false, |name| name == path)
                }
            })
        };

        let is_64 = matches!(macho.header.cputype, CPU_TYPE_ARM64);
        let dylib_exists = dylib_exists_in_macho(macho, 0);
        let current_sizeofcmds = read_u32_le(&self.data, 20);
        let current_ncmds = read_u32_le(&self.data, 16);

        // Create a mutable Vec<u8> so we can modify the Mach-O data in place
        let mut data = self.data.to_vec();

        // with macho.data we can clone, modify, then set the data
        // for our modified binary, then using MachO struct we can make our universal bin

        if dylib_exists {
            log::warn!("Dylib already exists in binary: {}", path);
            return Ok(data);
        }

        let header_size = if is_64 { 32 } else { 28 };

        // Calculate new load command size (must be 8-byte aligned)
        let dylib_path_len = path.len();
        let padding = (8 - ((dylib_path_len + 1) % 8)) % 8; // +1 for null terminator
        let dylib_command_size = 24 + dylib_path_len + 1 + padding; // sizeof(dylib_command) = 24

        // Find the position to insert the new load command
        let header_offset = 0;
        let load_commands_offset = header_offset + header_size;
        let sizeofcmds_offset = header_offset + 20;
        let ncmds_offset = header_offset + 16;

        // Find the minimum non-zero file offset from segments
        let min_fileoff = macho
            .load_commands
            .iter()
            .filter_map(|load_cmd| match &load_cmd.command {
                CommandVariant::Segment64(seg) if seg.filesize > 0 && seg.fileoff > 0 => {
                    Some(seg.fileoff)
                }
                CommandVariant::Segment32(seg) if seg.filesize > 0 && seg.fileoff > 0 => {
                    Some(seg.fileoff as u64)
                }
                _ => None,
            })
            .min()
            .unwrap_or(u64::MAX);

        // Calculate available space
        let load_commands_end = load_commands_offset + current_sizeofcmds as usize;
        let data_start = if min_fileoff < u64::MAX {
            min_fileoff as usize
        } else {
            data.len()
        };

        let available_space = data_start.saturating_sub(load_commands_end);

        if dylib_command_size > available_space {
            return Err(Error::Parse);
        }

        // Write the new load command into the available space (no splice needed!)
        let insert_offset = load_commands_end;
        let mut new_command = Vec::new();
        new_command.extend_from_slice(&(LC_LOAD_WEAK_DYLIB as u32).to_le_bytes()); // cmd
        new_command.extend_from_slice(&(dylib_command_size as u32).to_le_bytes()); // cmdsize

        // dylib_command structure:
        // struct dylib {
        //     uint32_t name;          // offset from start of load command to start of name string
        //     uint32_t timestamp;     // date/time stamp
        //     uint32_t current_version;
        //     uint32_t compatibility_version;
        // };
        new_command.extend_from_slice(&24u32.to_le_bytes()); // name.offset (sizeof dylib_command header = 8 + 16 = 24)
        new_command.extend_from_slice(&2u32.to_le_bytes()); // timestamp
        new_command.extend_from_slice(&0x00010000u32.to_le_bytes()); // current_version (1.0.0)
        new_command.extend_from_slice(&0x00010000u32.to_le_bytes()); // compatibility_version (1.0.0)
        new_command.extend_from_slice(path.as_bytes());
        new_command.push(0); // null terminator
        new_command.extend(vec![0u8; padding]); // padding

        // Write directly into the existing padding space
        data[insert_offset..insert_offset + dylib_command_size].copy_from_slice(&new_command);

        // Update header fields
        let new_sizeofcmds = current_sizeofcmds + dylib_command_size as u32;
        let new_ncmds = current_ncmds + 1;

        data[sizeofcmds_offset..sizeofcmds_offset + 4]
            .copy_from_slice(&new_sizeofcmds.to_le_bytes());
        data[ncmds_offset..ncmds_offset + 4].copy_from_slice(&new_ncmds.to_le_bytes());

        Ok(data)
    }

    fn remove_dylib_load_path(&self, path: &str) -> Result<Vec<u8>, Error> {
        let macho = &self.macho;
        let mut data = self.data.to_vec();

        let read_u32_le = |data: &[u8], offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };

        let replacements: Vec<(usize, usize, usize)> = macho
            .load_commands
            .iter()
            .filter_map(|load_cmd| {
                match &load_cmd.command {
                    CommandVariant::LoadDylib(dylib) => {
                        extract_dylib_path(self.data, load_cmd.offset, dylib.dylib.name)
                    }
                    _ => manually_parse_dylib(self.data, load_cmd.offset),
                }
                .and_then(|name| {
                    if name == path {
                        let cmdsize = read_u32_le(&self.data, load_cmd.offset + 4) as usize;
                        Some((0, load_cmd.offset, cmdsize))
                    } else {
                        None
                    }
                })
            })
            .collect();

        if replacements.is_empty() {
            log::warn!("No matching dylib load commands found for path: {}", path);
            return Ok(data);
        }

        let current_sizeofcmds = read_u32_le(&self.data, 20);
        let current_ncmds = read_u32_le(&self.data, 16);
        let mut total_removed_size = 0;
        for (arch_offset, cmd_offset, cmdsize) in &replacements {
            let absolute_cmd_offset = arch_offset + cmd_offset - total_removed_size;
            // Shift subsequent data to overwrite the removed command
            data.copy_within(absolute_cmd_offset + cmdsize.., absolute_cmd_offset);
            total_removed_size += cmdsize;
        }
        // Update header fields
        let new_sizeofcmds = current_sizeofcmds - total_removed_size as u32;
        let new_ncmds = current_ncmds - replacements.len() as u32;
        data[20..24].copy_from_slice(&new_sizeofcmds.to_le_bytes());
        data[16..20].copy_from_slice(&new_ncmds.to_le_bytes());
        data.truncate(20 + new_sizeofcmds as usize);

        Ok(data)
    }

    fn replace_dylib_load_path(&self, old_path: &str, new_path: &str) -> Result<Vec<u8>, Error> {
        let macho = &self.macho;
        let mut data = self.data.to_vec();

        const DYLIB_COMMANDS: &[u32] = &[
            LC_LOAD_DYLIB,
            LC_LOAD_WEAK_DYLIB,
            LC_REEXPORT_DYLIB,
            LC_LAZY_LOAD_DYLIB,
            LC_LOAD_UPWARD_DYLIB,
        ];

        let read_u32_le = |data: &[u8], offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };

        let find_dylib_matches = |macho: &GoblinMachO, base_offset: usize| -> Vec<(usize, usize)> {
            macho
                .load_commands
                .iter()
                .filter(|load_cmd| DYLIB_COMMANDS.contains(&load_cmd.command.cmd()))
                .filter_map(|load_cmd| {
                    // Try to extract the path, first from LoadDylib variant, then manually
                    let path = match &load_cmd.command {
                        goblin::mach::load_command::CommandVariant::LoadDylib(dylib) => {
                            extract_dylib_path(
                                &self.data,
                                base_offset + load_cmd.offset,
                                dylib.dylib.name,
                            )
                        }
                        _ => manually_parse_dylib(&self.data, base_offset + load_cmd.offset),
                    }?;

                    if path == old_path {
                        let cmdsize =
                            read_u32_le(&self.data, base_offset + load_cmd.offset + 4) as usize;
                        return Some((load_cmd.offset, cmdsize));
                    }
                    None
                })
                .collect()
        };

        let replacements: Vec<(usize, usize, usize)> = find_dylib_matches(macho, 0)
            .into_iter()
            .map(|(offset, size)| (0, offset, size))
            .collect();

        if replacements.is_empty() {
            log::warn!(
                "No matching dylib load commands found for path: {}",
                old_path
            );
            return Ok(data);
        }

        for (arch_offset, cmd_offset, cmdsize) in &replacements {
            let absolute_cmd_offset = arch_offset + cmd_offset;
            let dylib_name_offset = absolute_cmd_offset + 24; // sizeof(dylib_command)
            let available_space = cmdsize - 24;

            let new_path_len = new_path.len();
            let old_path_len = old_path.len();
            let new_padding = (8 - ((new_path_len + 1) % 8)) % 8;
            let required_space = new_path_len + 1 + new_padding;

            if required_space > available_space {
                return Err(Error::Parse);
            }

            // Only zero out the space we're actually using (old path + its null terminator + old padding)
            let old_padding = (8 - ((old_path_len + 1) % 8)) % 8;
            let old_total_size = old_path_len + 1 + old_padding;
            for i in 0..old_total_size.min(available_space) {
                data[dylib_name_offset + i] = 0;
            }

            // Write new path and null terminator
            data[dylib_name_offset..dylib_name_offset + new_path_len]
                .copy_from_slice(new_path.as_bytes());
            // Null terminator is already written by the zeroing above, padding bytes are also zeros
        }

        Ok(data)
    }

    fn replace_sdk_version(&self, new_version: &str) -> Result<Vec<u8>, Error> {
        let macho = &self.macho;
        let mut data = self.data.to_vec();

        let version_parts: Vec<&str> = new_version.split('.').collect();
        if version_parts.len() != 3 {
            return Err(Error::Parse);
        }
        let major: u32 = version_parts[0].parse().map_err(|_| Error::Parse)?;
        let minor: u32 = version_parts[1].parse().map_err(|_| Error::Parse)?;
        let patch: u32 = version_parts[2].parse().map_err(|_| Error::Parse)?;
        let new_version_encoded = (major << 16) | (minor << 8) | patch;

        for load_cmd in &macho.load_commands {
            if load_cmd.command.cmd() == goblin::mach::load_command::LC_BUILD_VERSION {
                let sdk_offset = load_cmd.offset + 16;

                if sdk_offset + 4 > data.len() {
                    return Err(Error::Parse);
                }

                data[sdk_offset..sdk_offset + 4]
                    .copy_from_slice(&new_version_encoded.to_le_bytes());
            }
        }

        Ok(data)
    }
}

fn extract_dylib_path(
    file_data: &[u8],
    load_cmd_offset: usize,
    name_offset_rel: u32,
) -> Option<String> {
    let name_offset = load_cmd_offset + name_offset_rel as usize;
    if name_offset >= file_data.len() {
        return None;
    }

    let mut end = name_offset;
    while end < file_data.len() && file_data[end] != 0 {
        end += 1;
    }

    std::str::from_utf8(&file_data[name_offset..end])
        .ok()
        .map(|s| s.to_string())
}

// TODO: our custom ones need manual parsing?
fn manually_parse_dylib(file_data: &[u8], load_cmd_offset: usize) -> Option<String> {
    if load_cmd_offset + 12 > file_data.len() {
        return None;
    }

    let name_offset_field = u32::from_le_bytes([
        file_data[load_cmd_offset + 8],
        file_data[load_cmd_offset + 9],
        file_data[load_cmd_offset + 10],
        file_data[load_cmd_offset + 11],
    ]);

    extract_dylib_path(file_data, load_cmd_offset, name_offset_field)
}
