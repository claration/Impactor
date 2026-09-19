// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        cli::{CliCommand, Context},
        code_directory::CodeDirectoryBlob,
        cryptography::DigestType,
        embedded_signature::{Blob, CodeSigningSlot, RequirementSetBlob},
        error::AppleCodesignError,
        macho::MachFile,
    },
    base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine},
    clap::{Parser, Subcommand},
    cryptographic_message_syntax::SignedData,
    std::{io::Write, path::PathBuf},
};

fn print_signed_data(
    prefix: &str,
    signed_data: &SignedData,
    external_content: Option<Vec<u8>>,
) -> Result<(), AppleCodesignError> {
    println!(
        "{}signed content (embedded): {:?}",
        prefix,
        signed_data.signed_content().map(hex::encode)
    );
    println!(
        "{}signed content (external): {:?}... ({} bytes)",
        prefix,
        external_content.as_ref().map(|x| hex::encode(&x[0..40])),
        external_content.as_ref().map(|x| x.len()).unwrap_or(0),
    );

    let content = if let Some(v) = signed_data.signed_content() {
        Some(v)
    } else {
        external_content.as_ref().map(|v| v.as_ref())
    };

    if let Some(content) = content {
        println!(
            "{}signed content SHA-1:   {}",
            prefix,
            hex::encode(DigestType::Sha1.digest_data(content)?)
        );
        println!(
            "{}signed content SHA-256: {}",
            prefix,
            hex::encode(DigestType::Sha256.digest_data(content)?)
        );
        println!(
            "{}signed content SHA-384: {}",
            prefix,
            hex::encode(DigestType::Sha384.digest_data(content)?)
        );
        println!(
            "{}signed content SHA-512: {}",
            prefix,
            hex::encode(DigestType::Sha512.digest_data(content)?)
        );
    }
    println!(
        "{}certificate count: {}",
        prefix,
        signed_data.certificates().count()
    );
    for (i, cert) in signed_data.certificates().enumerate() {
        println!(
            "{}certificate #{}: subject CN={}; self signed={}",
            prefix,
            i,
            cert.subject_common_name()
                .unwrap_or_else(|| "<unknown>".to_string()),
            cert.subject_is_issuer()
        );
    }
    println!("{}signer count: {}", prefix, signed_data.signers().count());
    for (i, signer) in signed_data.signers().enumerate() {
        println!(
            "{}signer #{}: digest algorithm: {:?}",
            prefix,
            i,
            signer.digest_algorithm()
        );
        println!(
            "{}signer #{}: signature algorithm: {:?}",
            prefix,
            i,
            signer.signature_algorithm()
        );

        if let Some(sa) = signer.signed_attributes() {
            println!(
                "{}signer #{}: content type: {}",
                prefix,
                i,
                sa.content_type()
            );
            println!(
                "{}signer #{}: message digest: {}",
                prefix,
                i,
                hex::encode(sa.message_digest())
            );
            println!(
                "{}signer #{}: signing time: {:?}",
                prefix,
                i,
                sa.signing_time()
            );
        }

        let digested_data = signer.signed_content_with_signed_data(signed_data);

        println!(
            "{}signer #{}: signature content SHA-1:   {}",
            prefix,
            i,
            hex::encode(DigestType::Sha1.digest_data(&digested_data)?)
        );
        println!(
            "{}signer #{}: signature content SHA-256: {}",
            prefix,
            i,
            hex::encode(DigestType::Sha256.digest_data(&digested_data)?)
        );
        println!(
            "{}signer #{}: signature content SHA-384: {}",
            prefix,
            i,
            hex::encode(DigestType::Sha384.digest_data(&digested_data)?)
        );
        println!(
            "{}signer #{}: signature content SHA-512: {}",
            prefix,
            i,
            hex::encode(DigestType::Sha512.digest_data(&digested_data)?)
        );

        if signed_data.signed_content().is_some() {
            println!(
                "{}signer #{}: digest valid: {}",
                prefix,
                i,
                signer
                    .verify_message_digest_with_signed_data(signed_data)
                    .is_ok()
            );
        }
        println!(
            "{}signer #{}: signature valid: {}",
            prefix,
            i,
            signer
                .verify_signature_with_signed_data(signed_data)
                .is_ok()
        );

        println!(
            "{}signer #{}: time-stamp token present: {}",
            prefix,
            i,
            signer.time_stamp_token_signed_data()?.is_some()
        );

        if let Some(tsp_signed_data) = signer.time_stamp_token_signed_data()? {
            let prefix = format!("{prefix}signer #{i}: time-stamp token: ");

            print_signed_data(&prefix, &tsp_signed_data, None)?;
        }
    }

    Ok(())
}

#[derive(Clone, Parser)]
struct ExtractCommon {
    /// Path to Mach-O binary to examine
    path: PathBuf,
}

#[derive(Clone, Subcommand)]
enum ExtractData {
    /// Code directory blobs.
    Blobs(ExtractCommon),
    /// Information about cryptographic message syntax signature.
    CmsInfo(ExtractCommon),
    /// PEM encoded cryptographic message syntax signature.
    CmsPem(ExtractCommon),
    /// Binary cryptographic message syntax signature. Should be BER encoded ASN.1 data.
    CmsRaw(ExtractCommon),
    /// ASN.1 decoded cryptographic message syntax data.
    Cms(ExtractCommon),
    /// Information from the main code directory data structure.
    CodeDirectory(ExtractCommon),
    /// Raw binary data composing the code directory data structure.
    CodeDirectoryRaw(ExtractCommon),
    /// Reserialize the parsed code directory, parse it again, and then print it like `code-directory` would.
    CodeDirectorySerialized(ExtractCommon),
    /// Reserialize the parsed code directory and emit its binary.
    ///
    /// Useful for comparing round-tripping of code directory data.
    CodeDirectorySerializedRaw(ExtractCommon),
    /// Information about the __LINKEDIT Mach-O segment.
    LinkeditInfo(ExtractCommon),
    /// Complete content of the __LINKEDIT Mach-O segment.
    LinkeditSegmentRaw(ExtractCommon),
    /// Mach-O file header data.
    MachoHeader(ExtractCommon),
    /// High-level information about Mach-O load commands.
    MachoLoadCommands(ExtractCommon),
    /// Debug formatted Mach-O load command data structures.
    MachoLoadCommandsRaw(ExtractCommon),
    /// Information about Mach-O segments.
    MachoSegments(ExtractCommon),
    /// Mach-O targeting info.
    MachoTarget(ExtractCommon),
    /// Parsed code requirement statement/expression.
    Requirements(ExtractCommon),
    /// Raw binary data composing the requirements blob/slot.
    RequirementsRaw(ExtractCommon),
    /// Dump the internal Rust data structures representing the requirements expressions.
    RequirementsRust(ExtractCommon),
    /// Reserialize the code requirements blob, parse it again, and then print it like `requirements` would.
    RequirementsSerialized(ExtractCommon),
    /// Like `requirements-serialized` except emit the binary data representation.
    RequirementsSerializedRaw(ExtractCommon),
    /// Raw binary data constituting the signature data embedded in the binary.
    SignatureRaw(ExtractCommon),
    /// Show information about the SuperBlob record and high-level details of embedded Blob records.
    Superblob(ExtractCommon),
}

impl ExtractData {
    fn common_args(&self) -> &ExtractCommon {
        match self {
            ExtractData::Blobs(x) => x,
            ExtractData::CmsInfo(x) => x,
            ExtractData::CmsPem(x) => x,
            ExtractData::CmsRaw(x) => x,
            ExtractData::Cms(x) => x,
            ExtractData::CodeDirectoryRaw(x) => x,
            ExtractData::CodeDirectorySerializedRaw(x) => x,
            ExtractData::CodeDirectorySerialized(x) => x,
            ExtractData::CodeDirectory(x) => x,
            ExtractData::LinkeditInfo(x) => x,
            ExtractData::LinkeditSegmentRaw(x) => x,
            ExtractData::MachoHeader(x) => x,
            ExtractData::MachoLoadCommands(x) => x,
            ExtractData::MachoLoadCommandsRaw(x) => x,
            ExtractData::MachoSegments(x) => x,
            ExtractData::MachoTarget(x) => x,
            ExtractData::RequirementsRaw(x) => x,
            ExtractData::RequirementsRust(x) => x,
            ExtractData::RequirementsSerializedRaw(x) => x,
            ExtractData::RequirementsSerialized(x) => x,
            ExtractData::Requirements(x) => x,
            ExtractData::SignatureRaw(x) => x,
            ExtractData::Superblob(x) => x,
        }
    }
}

#[derive(Parser)]
pub struct Extract {
    /// Index of Mach-O binary to operate on within a universal/fat binary
    #[arg(long, global = true, default_value = "0")]
    universal_index: usize,

    /// Which data to extract and how to format it
    #[command(subcommand)]
    data: ExtractData,
}

impl CliCommand for Extract {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let common = self.data.common_args();

        let data = std::fs::read(&common.path)?;
        let mach = MachFile::parse(&data)?;
        let macho = mach.nth_macho(self.universal_index)?;

        match self.data {
            ExtractData::Blobs(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                for blob in embedded.blobs {
                    let parsed = blob.into_parsed_blob()?;
                    println!("{parsed:#?}");
                }
            }
            ExtractData::CmsInfo(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(cms) = embedded.signature_data()? {
                    let signed_data = SignedData::parse_ber(cms)?;

                    let cd_data = if let Ok(Some(blob)) = embedded.code_directory() {
                        Some(blob.to_blob_bytes()?)
                    } else {
                        None
                    };

                    print_signed_data("", &signed_data, cd_data)?;
                } else {
                    eprintln!("no CMS data");
                }
            }
            ExtractData::CmsPem(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(cms) = embedded.signature_data()? {
                    print!("{}", pem::encode(&pem::Pem::new("PKCS7", cms.to_vec())));
                } else {
                    eprintln!("no CMS data");
                }
            }
            ExtractData::CmsRaw(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(cms) = embedded.signature_data()? {
                    std::io::stdout().write_all(cms)?;
                } else {
                    eprintln!("no CMS data");
                }
            }
            ExtractData::Cms(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(signed_data) = embedded.signed_data()? {
                    println!("{signed_data:#?}");
                } else {
                    eprintln!("no CMS data");
                }
            }
            ExtractData::CodeDirectoryRaw(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(blob) = embedded.find_slot(CodeSigningSlot::CodeDirectory) {
                    std::io::stdout().write_all(blob.data)?;
                } else {
                    eprintln!("no code directory");
                }
            }
            ExtractData::CodeDirectorySerializedRaw(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Ok(Some(cd)) = embedded.code_directory() {
                    std::io::stdout().write_all(&cd.to_blob_bytes()?)?;
                } else {
                    eprintln!("no code directory");
                }
            }
            ExtractData::CodeDirectorySerialized(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Ok(Some(cd)) = embedded.code_directory() {
                    let serialized = cd.to_blob_bytes()?;
                    println!("{:#?}", CodeDirectoryBlob::from_blob_bytes(&serialized)?);
                }
            }
            ExtractData::CodeDirectory(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(cd) = embedded.code_directory()? {
                    println!("{cd:#?}");
                } else {
                    eprintln!("no code directory");
                }
            }
            ExtractData::LinkeditInfo(_) => {
                let sig = macho
                    .find_signature_data()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
                println!("__LINKEDIT segment index: {}", sig.linkedit_segment_index);
                println!(
                    "__LINKEDIT segment start offset: {}",
                    sig.linkedit_segment_start_offset
                );
                println!(
                    "__LINKEDIT segment end offset: {}",
                    sig.linkedit_segment_end_offset
                );
                println!(
                    "__LINKEDIT segment size: {}",
                    sig.linkedit_segment_data.len()
                );
                println!(
                    "__LINKEDIT signature global start offset: {}",
                    sig.signature_file_start_offset
                );
                println!(
                    "__LINKEDIT signature global end offset: {}",
                    sig.signature_file_end_offset
                );
                println!(
                    "__LINKEDIT signature local segment start offset: {}",
                    sig.signature_segment_start_offset
                );
                println!(
                    "__LINKEDIT signature local segment end offset: {}",
                    sig.signature_segment_end_offset
                );
                println!("__LINKEDIT signature size: {}", sig.signature_data.len());
            }
            ExtractData::LinkeditSegmentRaw(_) => {
                let sig = macho
                    .find_signature_data()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
                std::io::stdout().write_all(sig.linkedit_segment_data)?;
            }
            ExtractData::MachoHeader(_) => {
                println!("{:#?}", macho.macho.header);
            }
            ExtractData::MachoLoadCommands(_) => {
                println!("load command count: {}", macho.macho.load_commands.len());

                for command in &macho.macho.load_commands {
                    println!(
                        "{}; offsets=0x{:x}-0x{:x} ({}-{}); size={}",
                        goblin::mach::load_command::cmd_to_str(command.command.cmd()),
                        command.offset,
                        command.offset + command.command.cmdsize(),
                        command.offset,
                        command.offset + command.command.cmdsize(),
                        command.command.cmdsize(),
                    );
                }
            }
            ExtractData::MachoLoadCommandsRaw(_) => {
                for command in &macho.macho.load_commands {
                    println!("{:?}", command);
                }
            }
            ExtractData::MachoSegments(_) => {
                println!("segments count: {}", macho.macho.segments.len());
                for (segment_index, segment) in macho.macho.segments.iter().enumerate() {
                    let sections = segment.sections()?;

                    println!(
                        "segment #{}; {}; offsets=0x{:x}-0x{:x} ({}-{}); addresses=0x{:x}-0x{:x}; vm/file size {}/{}; section count {}",
                        segment_index,
                        segment.name()?,
                        segment.fileoff,
                        segment.fileoff as usize + segment.data.len(),
                        segment.fileoff,
                        segment.fileoff as usize + segment.data.len(),
                        segment.vmaddr,
                        segment.vmaddr + segment.vmsize,
                        segment.vmsize,
                        segment.filesize,
                        sections.len()
                    );
                    for (section_index, (section, _)) in sections.into_iter().enumerate() {
                        println!(
                            "segment #{}; section #{}: {}; offsets=0x{:x}-0x{:x} ({}-{}); addresses=0x{:x}-0x{:x}; size {}; align={}; flags={}",
                            segment_index,
                            section_index,
                            section.name()?,
                            section.offset,
                            section.offset as u64 + section.size,
                            section.offset,
                            section.offset as u64 + section.size,
                            section.addr,
                            section.addr + section.size,
                            section.size,
                            section.align,
                            section.flags,
                        );
                    }
                }
            }
            ExtractData::MachoTarget(_) => {
                if let Some(target) = macho.find_targeting()? {
                    println!("Platform: {}", target.platform);
                    println!("Minimum OS: {}", target.minimum_os_version);
                    println!("SDK: {}", target.sdk_version);
                } else {
                    println!("Unable to resolve Mach-O targeting from load commands");
                }
            }
            ExtractData::RequirementsRaw(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(blob) = embedded.find_slot(CodeSigningSlot::RequirementSet) {
                    std::io::stdout().write_all(blob.data)?;
                } else {
                    eprintln!("no requirements");
                }
            }
            ExtractData::RequirementsRust(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(reqs) = embedded.code_requirements()? {
                    for (typ, req) in &reqs.requirements {
                        for expr in req.parse_expressions()?.iter() {
                            println!("{typ} => {expr:#?}");
                        }
                    }
                } else {
                    eprintln!("no requirements");
                }
            }
            ExtractData::RequirementsSerializedRaw(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(reqs) = embedded.code_requirements()? {
                    std::io::stdout().write_all(&reqs.to_blob_bytes()?)?;
                } else {
                    eprintln!("no requirements");
                }
            }
            ExtractData::RequirementsSerialized(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(reqs) = embedded.code_requirements()? {
                    let serialized = reqs.to_blob_bytes()?;
                    println!("{:#?}", RequirementSetBlob::from_blob_bytes(&serialized)?);
                } else {
                    eprintln!("no requirements");
                }
            }
            ExtractData::Requirements(_) => {
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                if let Some(reqs) = embedded.code_requirements()? {
                    for (typ, req) in &reqs.requirements {
                        for expr in req.parse_expressions()?.iter() {
                            println!("{typ} => {expr}");
                        }
                    }
                } else {
                    eprintln!("no requirements");
                }
            }
            ExtractData::SignatureRaw(_) => {
                let sig = macho
                    .find_signature_data()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
                std::io::stdout().write_all(sig.signature_data)?;
            }
            ExtractData::Superblob(_) => {
                let sig = macho
                    .find_signature_data()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
                let embedded = macho
                    .code_signature()?
                    .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

                println!("file start offset: {}", sig.signature_file_start_offset);
                println!("file end offset: {}", sig.signature_file_end_offset);
                println!(
                    "__LINKEDIT start offset: {}",
                    sig.signature_segment_start_offset
                );
                println!(
                    "__LINKEDIT end offset: {}",
                    sig.signature_segment_end_offset
                );
                println!("length: {}", embedded.length);
                println!("blob count: {}", embedded.count);
                println!("blobs:");
                for blob in embedded.blobs {
                    println!("- index: {}", blob.index);
                    println!(
                        "  offsets: 0x{:x}-0x{:x} ({}-{})",
                        blob.offset,
                        blob.offset + blob.length - 1,
                        blob.offset,
                        blob.offset + blob.length - 1
                    );
                    println!("  length: {}", blob.length);
                    println!("  slot: {:?}", blob.slot);
                    println!("  magic: {:?} (0x{:x})", blob.magic, u32::from(blob.magic));
                    println!(
                        "  sha1: {}",
                        hex::encode(blob.digest_with(DigestType::Sha1)?)
                    );
                    println!(
                        "  sha256: {}",
                        hex::encode(blob.digest_with(DigestType::Sha256)?)
                    );
                    println!(
                        "  sha256-truncated: {}",
                        hex::encode(blob.digest_with(DigestType::Sha256Truncated)?)
                    );
                    println!(
                        "  sha384: {}",
                        hex::encode(blob.digest_with(DigestType::Sha384)?),
                    );
                    println!(
                        "  sha512: {}",
                        hex::encode(blob.digest_with(DigestType::Sha512)?),
                    );
                    println!(
                        "  sha1-base64: {}",
                        STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha1)?)
                    );
                    println!(
                        "  sha256-base64: {}",
                        STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha256)?)
                    );
                    println!(
                        "  sha256-truncated-base64: {}",
                        STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha256Truncated)?)
                    );
                    println!(
                        "  sha384-base64: {}",
                        STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha384)?)
                    );
                    println!(
                        "  sha512-base64: {}",
                        STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha512)?)
                    );
                }
            }
        }

        Ok(())
    }
}
