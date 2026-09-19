// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Mach-O writing.
//!
//! Initially authored to facilitate testing.

use {
    crate::{macho::MachoTarget, AppleCodesignError},
    object::{
        endian::{BigEndian, U32, U64},
        macho::*,
        pod::bytes_of,
        AddressSize, Architecture, Endian, Endianness,
    },
};

/// A Mach-O segment.
#[derive(Debug)]
pub struct Segment {
    /// Name of the segment. Max of 16 bytes.
    name: String,
    /// Segment flags.
    flags: u32,
}

impl Segment {
    /// Obtain the segment name as bytes.
    fn name_bytes(&self) -> Result<[u8; 16], AppleCodesignError> {
        let mut v = [0; 16];

        v.get_mut(..self.name.len())
            .ok_or_else(|| {
                AppleCodesignError::MachOWrite(format!("segment name too long: {}", self.name))
            })?
            .copy_from_slice(self.name.as_bytes());

        Ok(v)
    }

    /// Obtain the bytes for the load command data.
    ///
    /// Just the segment load command. Does not include section header data.
    #[allow(clippy::too_many_arguments)]
    pub fn to_load_command_data(
        &self,
        address_size: AddressSize,
        endian: Endianness,
        section_count: usize,
        vm_start: u64,
        vm_length: u64,
        file_offset: usize,
        file_length: usize,
    ) -> Result<Vec<u8>, AppleCodesignError> {
        if address_size == AddressSize::U64 {
            let segment = SegmentCommand64 {
                cmd: U32::new(endian, LC_SEGMENT_64),
                cmdsize: U32::new(
                    endian,
                    (std::mem::size_of::<SegmentCommand64<Endianness>>()
                        + section_count * std::mem::size_of::<Section64<Endianness>>())
                        as u32,
                ),
                segname: self.name_bytes()?,
                vmaddr: U64::new(endian, vm_start),
                vmsize: U64::new(endian, vm_length as _),
                fileoff: U64::new(endian, file_offset as _),
                filesize: U64::new(endian, file_length as _),
                maxprot: U32::new(endian, 0),
                initprot: U32::new(endian, 0),
                nsects: U32::new(endian, section_count as _),
                flags: U32::new(endian, self.flags),
            };

            Ok(bytes_of(&segment).to_vec())
        } else {
            let segment = SegmentCommand32 {
                cmd: U32::new(endian, LC_SEGMENT),
                cmdsize: U32::new(
                    endian,
                    (std::mem::size_of::<SegmentCommand32<Endianness>>()
                        + section_count * std::mem::size_of::<Section32<Endianness>>())
                        as u32,
                ),
                segname: self.name_bytes()?,
                vmaddr: U32::new(endian, vm_start as _),
                vmsize: U32::new(endian, vm_length as _),
                fileoff: U32::new(endian, file_offset as _),
                filesize: U32::new(endian, file_length as _),
                maxprot: U32::new(endian, 0),
                initprot: U32::new(endian, 0),
                nsects: U32::new(endian, section_count as _),
                flags: U32::new(endian, self.flags),
            };

            Ok(bytes_of(&segment).to_vec())
        }
    }
}

#[derive(Debug)]
pub struct Section {
    segment: String,
    name: String,
    align: usize,
    data: Vec<u8>,
    flags: u32,
}

impl Section {
    /// Obtain the segment name as bytes.
    pub fn segment_name_bytes(&self) -> Result<[u8; 16], AppleCodesignError> {
        let mut v = [0; 16];

        v.get_mut(..self.segment.len())
            .ok_or_else(|| {
                AppleCodesignError::MachOWrite(format!("segment name too long: {}", self.segment))
            })?
            .copy_from_slice(self.segment.as_bytes());

        Ok(v)
    }

    /// Obtain the section name as bytes.
    pub fn section_name_bytes(&self) -> Result<[u8; 16], AppleCodesignError> {
        let mut v = [0; 16];

        v.get_mut(..self.name.len())
            .ok_or_else(|| {
                AppleCodesignError::MachOWrite(format!("section name too long: {}", self.name))
            })?
            .copy_from_slice(self.name.as_bytes());

        Ok(v)
    }

    pub fn to_section_header_data(
        &self,
        address_size: AddressSize,
        endian: Endianness,
        address: u64,
        size: usize,
        offset: usize,
        alignment: usize,
    ) -> Result<Vec<u8>, AppleCodesignError> {
        if address_size == AddressSize::U64 {
            let header = Section64 {
                sectname: self.section_name_bytes()?,
                segname: self.segment_name_bytes()?,
                addr: U64::new(endian, address),
                size: U64::new(endian, size as _),
                offset: U32::new(endian, offset as _),
                align: U32::new(endian, alignment as _),
                reloff: U32::new(endian, 0),
                nreloc: U32::new(endian, 0),
                flags: U32::new(endian, self.flags),
                reserved1: U32::new(endian, 0),
                reserved2: U32::new(endian, 0),
                reserved3: U32::new(endian, 0),
            };

            Ok(bytes_of(&header).to_vec())
        } else {
            let header = Section32 {
                sectname: self.section_name_bytes()?,
                segname: self.segment_name_bytes()?,
                addr: U32::new(endian, address as _),
                size: U32::new(endian, size as _),
                offset: U32::new(endian, offset as _),
                align: U32::new(endian, alignment as _),
                reloff: U32::new(endian, 0),
                nreloc: U32::new(endian, 0),
                flags: U32::new(endian, self.flags),
                reserved1: U32::new(endian, 0),
                reserved2: U32::new(endian, 0),
            };

            Ok(bytes_of(&header).to_vec())
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SegmentMetadata {
    file_offset: usize,
    file_size: usize,
    vm_address: u64,
    vm_size: u64,
}

/// Describes a Mach-O section in the context of a larger file.
#[derive(Clone, Copy, Debug, Default)]
struct SectionMetadata {
    /// File offset of start of section.
    offset: usize,
    /// Start address of section.
    address: u64,
}

fn align_u64(offset: u64, size: u64) -> u64 {
    (offset + (size - 1)) & !(size - 1)
}

fn align_usize(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

/// Constructor of Mach-O binaries.
///
/// Originally written to facilitate testing so we can generate Mach-O binaries
/// for tests. Not intended to be a fully-functional linker! Use at your own
/// risk.
pub struct MachOBuilder {
    architecture: Architecture,
    endian: Endianness,
    address_size: AddressSize,
    page_size: usize,
    file_type: u32,
    macho_flags: u32,
    /// Start offset for __TEXT segment.
    text_segment_start_offset: usize,
    segments: Vec<Segment>,
    /// Sections within the Mach-O.
    ///
    /// Sections are grouped by segment and each group is ordered by segment file order.
    sections: Vec<Section>,

    // Optional load commands.
    /// Mach-O targeting.
    ///
    /// Turned into an LC_BUILD_VERSION load command.
    macho_target: Option<MachoTarget>,
}

impl MachOBuilder {
    /// Create a new instance having the specified architecture and endianness.
    pub fn new(architecture: Architecture, endianness: Endianness, file_type: u32) -> Self {
        let page_size = match architecture {
            Architecture::Aarch64 => 16384,
            Architecture::X86_64 => 4096,
            _ => 4096,
        };

        let segments = vec![
            Segment {
                name: "__PAGEZERO".to_string(),
                flags: 0,
            },
            Segment {
                name: "__TEXT".to_string(),
                flags: 0,
            },
            Segment {
                name: "__DATA_CONST".to_string(),
                flags: 0,
            },
            Segment {
                name: "__DATA".to_string(),
                flags: 0,
            },
            Segment {
                name: "__LINKEDIT".to_string(),
                flags: 0,
            },
        ];

        let sections = vec![
            Section {
                segment: "__TEXT".to_string(),
                name: "__text".to_string(),
                align: page_size,
                data: vec![],
                flags: 0,
            },
            Section {
                segment: "__TEXT".to_string(),
                name: "__const".to_string(),
                align: page_size,
                data: vec![],
                flags: 0,
            },
            Section {
                segment: "__DATA_CONST".to_string(),
                name: "__const".to_string(),
                align: page_size,
                data: vec![],
                flags: 0,
            },
            Section {
                segment: "__DATA".to_string(),
                name: "__data".to_string(),
                align: page_size,
                data: vec![],
                flags: 0,
            },
        ];

        Self {
            architecture,
            endian: endianness,
            address_size: architecture
                .address_size()
                .expect("address size should be known"),
            file_type,
            page_size,
            macho_flags: 0,
            text_segment_start_offset: 0,
            segments,
            sections,
            macho_target: None,
        }
    }

    /// Create a new instance for x86-64.
    pub fn new_x86_64(file_type: u32) -> Self {
        Self::new(Architecture::X86_64, Endianness::Little, file_type)
    }

    /// Create a new instance for aarch64.
    pub fn new_aarch64(file_type: u32) -> Self {
        Self::new(Architecture::Aarch64, Endianness::Little, file_type)
    }

    /// Set the Mach-O targeting info for the binary.
    ///
    /// Will result in a LC_BUILD_VERSION load command being emitted.
    pub fn macho_target(mut self, target: MachoTarget) -> Self {
        self.macho_target = Some(target);
        self
    }

    /// Set the start offset for the __TEXT segment.
    ///
    /// Normally the __TEXT segment starts at 0x0.
    ///
    /// Very little validation is performed on the value. It may be possible
    /// to write corrupted Mach-O by feeding this a sufficiently large number.
    pub fn text_segment_start_offset(mut self, offset: usize) -> Self {
        self.text_segment_start_offset = offset;
        self
    }

    fn mach_header(
        &self,
        number_commands: u32,
        size_of_commands: u32,
    ) -> Result<Vec<u8>, AppleCodesignError> {
        let endian = self.endian;

        let (cpu_type, cpu_sub_type) = match self.architecture {
            Architecture::Arm => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_ALL),
            Architecture::Aarch64 => (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
            Architecture::Aarch64_Ilp32 => (CPU_TYPE_ARM64_32, CPU_SUBTYPE_ARM64_32_V8),
            Architecture::I386 => (CPU_TYPE_X86, CPU_SUBTYPE_I386_ALL),
            Architecture::X86_64 => (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
            Architecture::PowerPc => (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_ALL),
            Architecture::PowerPc64 => (CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_ALL),
            _ => {
                return Err(AppleCodesignError::MachOWrite(format!(
                    "unhandled architecture: {:?}",
                    self.architecture
                )));
            }
        };

        if self.address_size == AddressSize::U64 {
            let magic = if endian.is_big_endian() {
                MH_MAGIC_64
            } else {
                MH_CIGAM_64
            };
            let header = MachHeader64 {
                magic: U32::new(BigEndian, magic),
                cputype: U32::new(endian, cpu_type),
                cpusubtype: U32::new(endian, cpu_sub_type),
                filetype: U32::new(endian, self.file_type),
                ncmds: U32::new(endian, number_commands),
                sizeofcmds: U32::new(endian, size_of_commands),
                flags: U32::new(endian, self.macho_flags),
                reserved: U32::default(),
            };

            Ok(bytes_of(&header).to_vec())
        } else {
            let magic = if endian.is_big_endian() {
                MH_MAGIC
            } else {
                MH_CIGAM
            };
            let header = MachHeader32 {
                magic: U32::new(BigEndian, magic),
                cputype: U32::new(endian, cpu_type),
                cpusubtype: U32::new(endian, cpu_sub_type),
                filetype: U32::new(endian, self.file_type),
                ncmds: U32::new(endian, number_commands),
                sizeofcmds: U32::new(endian, size_of_commands),
                flags: U32::new(endian, self.macho_flags),
            };

            Ok(bytes_of(&header).to_vec())
        }
    }

    /// Length of segment load command header.
    fn segment_header_size(&self) -> usize {
        if self.address_size == AddressSize::U64 {
            std::mem::size_of::<SegmentCommand64<Endianness>>()
        } else {
            std::mem::size_of::<SegmentCommand32<Endianness>>()
        }
    }

    /// Length of section header.
    fn section_header_size(&self) -> usize {
        if self.address_size == AddressSize::U64 {
            std::mem::size_of::<Section64<Endianness>>()
        } else {
            std::mem::size_of::<Section32<Endianness>>()
        }
    }

    /// Get the sections in a named segment.
    fn sections_in_segment<'a>(
        &'a self,
        segment_name: &'a str,
    ) -> impl Iterator<Item = &'a Section> + 'a {
        self.sections
            .iter()
            .filter(move |x| x.segment.as_str() == segment_name)
    }

    /// Write Mach-O data to a memory buffer.
    pub fn write_macho(&self) -> Result<Vec<u8>, AppleCodesignError> {
        let endian = self.endian;

        // Before writing anything we do a pass to resolve metadata (lengths, file-level
        // offsets, etc) for segments, sections, and other important data structures, as
        // these all need to be expressed in the file header and load commands.

        let mut current_file_offset = 0;
        let mut number_commands = 0;

        // Header is constant sized. So generate one with placeholder data.
        current_file_offset += self.mach_header(0, 0)?.len();

        let load_commands_offset = current_file_offset;

        // The segment load commands come first. Each has a fixed size header followed by
        // section headers describing the sections within the segment.
        for segment in &self.segments {
            number_commands += 1;
            current_file_offset += self.segment_header_size()
                + self.sections_in_segment(&segment.name).count() * self.section_header_size();
        }

        // The next set of load commands describe data in the __LINKEDIT segment.

        // Symbol table.
        number_commands += 1;
        current_file_offset += std::mem::size_of::<SymtabCommand<Endianness>>();

        // Now extra load commands.
        if let Some(target) = &self.macho_target {
            number_commands += 1;
            current_file_offset += target.to_build_version_command_vec(endian).len();
        }

        // TODO support additional load commands. Build version, source version, minimum
        // version, Uuid. Main, CodeSignature, etc.

        let load_command_size = current_file_offset - load_commands_offset;

        // After the load commands is the segment / section data.

        let start_address = if self.address_size == AddressSize::U64 {
            0x1_0000_0000
        } else {
            0x4000_0000
        };

        let mut current_address = start_address;

        // Iterate through all the sections and collect metadata for them.
        let mut section_metadata = vec![SectionMetadata::default(); self.sections.len()];

        for (index, section) in self.sections.iter().enumerate() {
            current_file_offset = align_usize(current_file_offset, section.align);
            current_address = align_u64(current_address, section.align as _);

            section_metadata[index].offset = current_file_offset;
            section_metadata[index].address = current_address;

            current_file_offset += section.data.len();
            current_address += section.data.len() as u64;
        }

        // After the section data is the __LINKEDIT segment and all its special data.
        current_file_offset = align_usize(current_file_offset, self.page_size);
        current_address = align_u64(current_address, self.page_size as _);

        let linkedit_start_file_offset = current_file_offset;
        let linkedit_start_address = current_address;

        let symbol_table_offset = current_file_offset;
        let symbol_table_data = vec![0];
        current_file_offset += symbol_table_data.len();

        let string_table_offset = current_file_offset;
        // Need to write a null name for Mach-O.
        let string_table_data = vec![0];
        current_file_offset += string_table_data.len();

        // We're at the end of the file!

        // Derive segment metadata from section metadata and special rules.
        let mut segment_metadata = vec![SegmentMetadata::default(); self.segments.len()];

        for (segment_index, segment) in self.segments.iter().enumerate() {
            let metadata = &mut segment_metadata[segment_index];

            match segment.name.as_str() {
                "__PAGEZERO" => {
                    // __PAGEZERO is empty in the file but is mapped to an empty virtual address
                    // outside the used memory address range in order to trigger a fault.
                    metadata.file_offset = 0;
                    metadata.file_size = 0;
                    metadata.vm_address = 0;
                    // A constant value is obviously incorrect for binaries larger than 4 GB.
                    metadata.vm_size = start_address;
                }
                "__LINKEDIT" => {
                    metadata.file_offset = linkedit_start_file_offset;
                    metadata.file_size = current_file_offset - linkedit_start_file_offset;
                    metadata.vm_address = linkedit_start_address;
                    metadata.vm_size = (current_file_offset - linkedit_start_file_offset) as _;
                }
                segment_name => {
                    // All the other segments are derived from section metadata.
                    let first_section_index = self
                        .sections
                        .iter()
                        .enumerate()
                        .find_map(|(index, section)| {
                            if section.segment == segment_name {
                                Some(index)
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| {
                            AppleCodesignError::MachOWrite(format!(
                                "unable to find section in segment {}",
                                segment.name
                            ))
                        })?;
                    let last_section_index = self
                        .sections
                        .iter()
                        .enumerate()
                        .rfind(|(_, section)| section.segment == segment_name)
                        .map(|(index, _)| index)
                        .ok_or_else(|| {
                            AppleCodesignError::MachOWrite(format!(
                                "unable to find section in segment {}",
                                segment.name
                            ))
                        })?;

                    let start_file_offset = section_metadata[first_section_index].offset;
                    let start_address = section_metadata[first_section_index].address;
                    let end_address = section_metadata[last_section_index].address
                        + self.sections[last_section_index].data.len() as u64;

                    metadata.file_offset = start_file_offset;
                    metadata.vm_address = start_address;
                    metadata.vm_size = (end_address - start_address) as _;

                    // End offset is next section start or start of __LINKEDIT.
                    metadata.file_size =
                        if let Some(next_section) = section_metadata.get(last_section_index + 1) {
                            next_section.offset - start_file_offset
                        } else {
                            linkedit_start_file_offset - start_file_offset
                        };

                    // But there's a special case for __TEXT, which starts at the beginning of the
                    // file and encompasses the header and load commands.
                    if segment_name == "__TEXT" {
                        metadata.file_offset = self.text_segment_start_offset;

                        metadata.file_size = if let Some(next_section) =
                            section_metadata.get(last_section_index + 1)
                        {
                            next_section.offset
                        } else {
                            current_file_offset
                        } - self.text_segment_start_offset;
                    }
                }
            }
        }

        // Now proceed with writing data.

        let mut buffer = Vec::with_capacity(current_file_offset);

        buffer.extend_from_slice(
            self.mach_header(number_commands, load_command_size as _)?
                .as_slice(),
        );

        for (index, segment) in self.segments.iter().enumerate() {
            let metadata = &segment_metadata[index];

            let segment_command_data = segment.to_load_command_data(
                self.address_size,
                endian,
                self.sections_in_segment(&segment.name).count(),
                metadata.vm_address,
                metadata.vm_size,
                metadata.file_offset,
                metadata.file_size,
            )?;

            buffer.extend_from_slice(segment_command_data.as_slice());

            for (index, section) in self
                .sections
                .iter()
                .enumerate()
                .filter(|(_, x)| x.segment == segment.name)
            {
                let metadata = &section_metadata[index];

                let section_header_data = section.to_section_header_data(
                    self.address_size,
                    endian,
                    metadata.address,
                    section.data.len(),
                    metadata.offset,
                    section.align,
                )?;

                buffer.extend_from_slice(section_header_data.as_slice());
            }
        }

        let symtab_command = SymtabCommand {
            cmd: U32::new(endian, LC_SYMTAB),
            cmdsize: U32::new(
                endian,
                std::mem::size_of::<SymtabCommand<Endianness>>() as u32,
            ),
            symoff: U32::new(endian, symbol_table_offset as _),
            nsyms: U32::new(endian, 0),
            stroff: U32::new(endian, string_table_offset as _),
            strsize: U32::new(endian, string_table_data.len() as _),
        };
        buffer.extend_from_slice(bytes_of(&symtab_command));

        if let Some(target) = &self.macho_target {
            buffer.extend_from_slice(&target.to_build_version_command_vec(endian));
        }

        // Done with load commands. Start writing section data.

        for (index, section) in self.sections.iter().enumerate() {
            let metadata = &section_metadata[index];

            // Pad zeroes until section start.
            if metadata.offset > buffer.len() {
                buffer.resize(metadata.offset, 0);
            }

            if !section.data.is_empty() {
                buffer.extend_from_slice(&section.data);
            }
        }

        buffer.resize(linkedit_start_file_offset, 0);

        buffer.extend_from_slice(&symbol_table_data);
        buffer.extend_from_slice(&string_table_data);

        Ok(buffer)
    }
}
