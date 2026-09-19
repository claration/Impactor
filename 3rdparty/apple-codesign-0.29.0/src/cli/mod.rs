// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod certificate_source;
pub mod config;
pub mod debug_commands;
pub mod extract_commands;

use {
    crate::{
        certificate::{
            create_self_signed_code_signing_certificate, AppleCertificate, CertificateProfile,
        },
        cli::{
            certificate_source::CertificateSource,
            config::{Config, ConfigBuilder},
        },
        code_directory::CodeSignatureFlags,
        code_requirement::CodeRequirements,
        cryptography::DigestType,
        environment_constraints::EncodedEnvironmentConstraints,
        error::AppleCodesignError,
        macho::MachFile,
        reader::SignatureReader,
        remote_signing::{
            session_negotiation::{create_session_joiner, SessionJoinState},
            RemoteSignError, UnjoinedSigningClient,
        },
        signing::UnifiedSigner,
        signing_settings::{SettingsScope, SigningSettings},
    },
    base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine},
    clap::{ArgAction, Args, Parser, Subcommand},
    difference::{Changeset, Difference},
    log::{error, warn, LevelFilter},
    serde::{Deserialize, Serialize},
    spki::EncodePublicKey,
    std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        str::FromStr,
    },
    x509_certificate::{CapturedX509Certificate, EcdsaCurve, KeyAlgorithm, X509CertificateBuilder},
};

#[cfg(feature = "notarize")]
use crate::notarization::Notarizer;

#[cfg(feature = "yubikey")]
use {
    crate::yubikey::YubiKey,
    yubikey::{PinPolicy, TouchPolicy},
};

#[cfg(target_os = "macos")]
use crate::macos::{
    keychain_find_code_signing_certificates, macos_keychain_find_certificate_chain, KeychainDomain,
};

#[cfg(target_os = "windows")]
use crate::windows::{
    windows_store_find_certificate_chain, windows_store_find_code_signing_certificates, StoreName,
};

pub const KEYCHAIN_DOMAINS: [&str; 4] = ["user", "system", "common", "dynamic"];
pub const WINDOWS_STORE_NAMES: [&str; 3] = ["user", "machine", "service"];

const APPLE_TIMESTAMP_URL: &str = "http://timestamp.apple.com/ts01";

/// Holds state to pass to CLI commands.
pub struct Context {
    pub config: Config,
}

pub trait CliCommand {
    /// Obtain the current command arguments normalized to a [Config] instance.
    fn as_config(&self) -> Result<Option<Config>, AppleCodesignError> {
        Ok(None)
    }

    /// Runs the command.
    fn run(&self, context: &Context) -> Result<(), AppleCodesignError>;
}

#[allow(unused)]
pub fn prompt_smartcard_pin() -> Result<Vec<u8>, AppleCodesignError> {
    let pin = dialoguer::Password::new()
        .with_prompt("Please enter device PIN")
        .interact()?;

    Ok(pin.as_bytes().to_vec())
}

pub fn get_pkcs12_password(
    password: Option<impl ToString>,
    password_file: Option<impl AsRef<Path>>,
) -> Result<String, AppleCodesignError> {
    if let Some(password) = password {
        Ok(password.to_string())
    } else if let Some(path) = password_file {
        Ok(std::fs::read_to_string(path.as_ref())?
            .lines()
            .next()
            .ok_or_else(|| {
                AppleCodesignError::CliGeneralError("password file appears to be empty".into())
            })?
            .to_string())
    } else {
        Ok(dialoguer::Password::new()
            .with_prompt("Please enter password for p12 file")
            .interact()?)
    }
}

#[cfg(feature = "notarize")]
#[derive(Args)]
struct NotaryApi {
    /// Path to a JSON file containing the API Key
    #[arg(
        long = "api-key-file",
        alias = "api-key-path",
        group = "source",
        value_name = "PATH"
    )]
    api_key_path: Option<PathBuf>,

    /// App Store Connect Issuer ID (likely a UUID)
    #[arg(long, requires = "api_key")]
    api_issuer: Option<String>,

    #[arg(long, requires = "api_issuer")]
    /// App Store Connect API Key ID
    api_key: Option<String>,
}

#[cfg(feature = "notarize")]
impl NotaryApi {
    /// Resolve a notarizer from arguments.
    fn notarizer(&self) -> Result<Notarizer, AppleCodesignError> {
        if let Some(api_key_path) = &self.api_key_path {
            Notarizer::from_api_key(api_key_path)
        } else if let (Some(issuer), Some(key)) = (&self.api_issuer, &self.api_key) {
            Notarizer::from_api_key_id(issuer, key)
        } else {
            Err(AppleCodesignError::NotarizeNoAuthCredentials)
        }
    }
}

#[derive(Args)]
struct YubikeyPolicy {
    /// Smartcard touch policy to protect key access
    #[arg(long, value_parser = ["default", "always", "never", "cached"], default_value = "default")]
    touch_policy: String,

    /// Smartcard pin prompt policy to protect key access
    #[arg(long, value_parser = ["default", "never", "once", "always"], default_value = "default")]
    pin_policy: String,
}

#[cfg(feature = "yubikey")]
fn str_to_touch_policy(s: &str) -> Result<TouchPolicy, AppleCodesignError> {
    match s {
        "default" => Ok(TouchPolicy::Default),
        "never" => Ok(TouchPolicy::Never),
        "always" => Ok(TouchPolicy::Always),
        "cached" => Ok(TouchPolicy::Cached),
        _ => Err(AppleCodesignError::CliBadArgument),
    }
}

#[cfg(feature = "yubikey")]
fn str_to_pin_policy(s: &str) -> Result<PinPolicy, AppleCodesignError> {
    match s {
        "default" => Ok(PinPolicy::Default),
        "never" => Ok(PinPolicy::Never),
        "once" => Ok(PinPolicy::Once),
        "always" => Ok(PinPolicy::Always),
        _ => Err(AppleCodesignError::CliBadArgument),
    }
}

fn print_certificate_info(cert: &CapturedX509Certificate) -> Result<(), AppleCodesignError> {
    println!(
        "Subject CN:                  {}",
        cert.subject_common_name()
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!(
        "Issuer CN:                   {}",
        cert.issuer_common_name()
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!("Subject is Issuer?:          {}", cert.subject_is_issuer());
    println!(
        "Team ID:                     {}",
        cert.apple_team_id()
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!(
        "SHA-1 fingerprint:           {}",
        hex::encode(cert.sha1_fingerprint()?)
    );
    println!(
        "SHA-256 fingerprint:         {}",
        hex::encode(cert.sha256_fingerprint()?)
    );
    println!(
        "Not Valid Before:            {}",
        cert.validity_not_before().to_rfc3339()
    );
    println!(
        "Not Valid After:             {}",
        cert.validity_not_after().to_rfc3339()
    );
    if let Some(alg) = cert.key_algorithm() {
        println!("Key Algorithm:               {alg}");
    }
    if let Some(alg) = cert.signature_algorithm() {
        println!("Signature Algorithm:         {alg}");
    }
    println!(
        "Public Key Data:             {}",
        STANDARD_ENGINE.encode(
            cert.to_public_key_der()
                .map_err(|e| AppleCodesignError::X509Parse(format!(
                    "error constructing SPKI: {e}"
                )))?
        )
    );
    println!(
        "Signed by Apple?:            {}",
        cert.chains_to_apple_root_ca()
    );
    if cert.chains_to_apple_root_ca() {
        println!("Apple Issuing Chain:");
        for signer in cert.apple_issuing_chain() {
            println!(
                "  - {}",
                signer
                    .subject_common_name()
                    .unwrap_or_else(|| "<unknown>".to_string())
            );
        }
    }

    println!(
        "Guessed Certificate Profile: {}",
        if let Some(profile) = cert.apple_guess_profile() {
            format!("{profile:?}")
        } else {
            "none".to_string()
        }
    );
    println!("Is Apple Root CA?:           {}", cert.is_apple_root_ca());
    println!(
        "Is Apple Intermediate CA?:   {}",
        cert.is_apple_intermediate_ca()
    );

    if !cert.apple_ca_extensions().is_empty() {
        println!("Apple CA Extensions:");
        for ext in cert.apple_ca_extensions() {
            println!("  - {} ({:?})", ext.as_oid(), ext);
        }
    }

    println!("Apple Extended Key Usage Purpose Extensions:");
    for purpose in cert.apple_extended_key_usage_purposes() {
        println!("  - {} ({:?})", purpose.as_oid(), purpose);
    }
    println!("Apple Code Signing Extensions:");
    for ext in cert.apple_code_signing_extensions() {
        println!("  - {} ({:?})", ext.as_oid(), ext);
    }
    print!(
        "\n{}",
        cert.to_public_key_pem(Default::default())
            .map_err(|e| AppleCodesignError::X509Parse(format!("error constructing SPKI: {e}")))?
    );
    print!("\n{}", cert.encode_pem());

    Ok(())
}

pub fn print_session_join(sjs_base64: &str, sjs_pem: &str) -> Result<(), RemoteSignError> {
    error!("");
    error!("Run the following command to join this signing session:");
    error!("");
    error!("    rcodesign remote-sign {}", sjs_base64);
    error!("");
    error!("Or if this output is too long, paste the following output:");
    error!("");
    for line in sjs_pem.lines() {
        error!("{}", line);
    }
    error!("");
    error!("Into an interactive editor using:");
    error!("");
    error!("    rcodesign remote-sign --editor");
    error!("");
    error!("Or into a new file whose path you define with:");
    error!("");
    error!("    rcodesign remote-sign --sjs-path /path/to/file/you/just/saved");
    error!("");
    error!("(waiting for remote signer to join)");

    Ok(())
}

#[derive(Parser)]
struct AnalyzeCertificate {
    #[command(flatten)]
    certificate: CertificateSource,
}

impl CliCommand for AnalyzeCertificate {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let certs = self.certificate.resolve_certificates(true)?.certs;

        for (i, cert) in certs.into_iter().enumerate() {
            println!("# Certificate {i}");
            println!();
            print_certificate_info(&cert)?;
            println!();
        }

        Ok(())
    }
}

#[derive(Parser)]
struct ComputeCodeHashes {
    /// Path to Mach-O binary to examine.
    path: PathBuf,

    /// Hashing algorithm to use.
    #[arg(long, default_value_t = DigestType::Sha256)]
    hash: DigestType,

    /// Chunk size to digest over.
    #[arg(long, default_value = "4096")]
    page_size: usize,

    /// Index of Mach-O binary to operate on within a universal/fat binary
    #[arg(long, default_value = "0")]
    universal_index: usize,
}

impl CliCommand for ComputeCodeHashes {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let data = std::fs::read(&self.path)?;
        let mach = MachFile::parse(&data)?;
        let macho = mach.nth_macho(self.universal_index)?;

        let hashes = macho.code_digests(self.hash, self.page_size)?;

        for hash in hashes {
            println!("{}", hex::encode(hash));
        }

        Ok(())
    }
}

#[derive(Parser)]
struct DiffSignatures {
    /// The first path to compare
    path0: PathBuf,

    /// The second path to compare
    path1: PathBuf,
}

impl CliCommand for DiffSignatures {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let reader = SignatureReader::from_path(&self.path0)?;

        let a_entities = reader.entities()?;

        let reader = SignatureReader::from_path(&self.path1)?;
        let b_entities = reader.entities()?;

        let a = serde_yaml::to_string(&a_entities)?;
        let b = serde_yaml::to_string(&b_entities)?;

        let Changeset { diffs, .. } = Changeset::new(&a, &b, "\n");

        for item in diffs {
            match item {
                Difference::Same(ref x) => {
                    for line in x.lines() {
                        println!(" {line}");
                    }
                }
                Difference::Add(ref x) => {
                    for line in x.lines() {
                        println!("+{line}");
                    }
                }
                Difference::Rem(ref x) => {
                    for line in x.lines() {
                        println!("-{line}");
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct EncodeAppStoreConnectApiKey {
    /// Path to a JSON file to create the output to
    #[arg(short = 'o', long)]
    output_path: Option<PathBuf>,

    /// The issuer of the API Token. Likely a UUID
    issuer_id: String,

    /// The Key ID. A short alphanumeric string like DEADBEEF42
    key_id: String,

    /// Path to a file containing the private key downloaded from Apple
    private_key_path: PathBuf,
}

#[cfg(feature = "notarize")]
impl CliCommand for EncodeAppStoreConnectApiKey {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let unified = app_store_connect::UnifiedApiKey::from_ecdsa_pem_path(
            &self.issuer_id,
            &self.key_id,
            &self.private_key_path,
        )?;

        if let Some(output_path) = &self.output_path {
            eprintln!("writing unified key JSON to {}", output_path.display());
            unified.write_json_file(output_path)?;
            eprintln!(
                "consider auditing the file's access permissions to ensure its content remains secure"
            );
        } else {
            println!("{}", unified.to_json_string()?);
        }

        Ok(())
    }
}

#[derive(Parser)]
struct GenerateCertificateSigningRequest {
    /// Path to file to write PEM encoded CSR to
    #[arg(long = "csr-pem-file", alias = "csr-pem-path")]
    csr_pem_path: Option<PathBuf>,

    #[command(flatten)]
    certificate: CertificateSource,
}

impl CliCommand for GenerateCertificateSigningRequest {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let signing_certs = self.certificate.resolve_certificates(true)?;

        let private_key = signing_certs.private_key()?;

        let mut builder = X509CertificateBuilder::default();
        builder
            .subject()
            .append_common_name_utf8_string("Apple Code Signing CSR")
            .map_err(|e| AppleCodesignError::CertificateBuildError(format!("{e:?}")))?;

        warn!("generating CSR; you may be prompted to enter credentials to unlock the signing key");
        let pem = builder
            .create_certificate_signing_request(private_key.as_key_info_signer())?
            .encode_pem()?;

        if let Some(dest_path) = &self.csr_pem_path {
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            warn!("writing PEM encoded CSR to {}", dest_path.display());
            std::fs::write(dest_path, pem.as_bytes())?;
        }

        print!("{pem}");

        Ok(())
    }
}

#[derive(Parser)]
struct GenerateSelfSignedCertificate {
    /// Which key type to use
    #[arg(long, value_parser = ["ecdsa", "ed25519", "rsa"], default_value = "rsa")]
    algorithm: String,

    #[arg(long, value_parser = CertificateProfile::str_names(), default_value = "apple-development")]
    profile: String,

    /// Team ID (this is a short string attached to your Apple Developer account)
    #[arg(long, default_value = "unset")]
    team_id: String,

    /// The name of the person this certificate is for
    #[arg(long)]
    person_name: String,

    /// Country Name (C) value for certificate identifier
    #[arg(long, default_value = "XX")]
    country_name: String,

    /// How many days the certificate should be valid for
    #[arg(long, default_value = "365")]
    validity_days: i64,

    /// Base name of files to write PEM encoded certificate to
    #[arg(long)]
    pem_filename: Option<String>,

    /// Filename to write PEM encoded private key and public certificate to.
    #[arg(
        long = "pem-unified-file",
        alias = "pem-unified-filename",
        value_name = "PATH"
    )]
    pem_unified_path: Option<PathBuf>,

    /// Filename to write a PKCS#12 / p12 / PFX encoded certificate to.
    #[arg(long = "p12-file", alias = "pfx-file", value_name = "PATH")]
    p12_path: Option<PathBuf>,

    /// Password to use to encrypt --p12-path.
    ///
    /// If not provided you will be prompted for a password.
    #[arg(long)]
    p12_password: Option<String>,
}

impl CliCommand for GenerateSelfSignedCertificate {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let algorithm = match self.algorithm.as_str() {
            "ecdsa" => KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1),
            "ed25519" => KeyAlgorithm::Ed25519,
            "rsa" => KeyAlgorithm::Rsa,
            value => panic!("algorithm values should have been validated by arg parser: {value}"),
        };

        let profile = CertificateProfile::from_str(self.profile.as_str())?;

        let validity_duration = chrono::Duration::days(self.validity_days);

        let (cert, key_pair) = create_self_signed_code_signing_certificate(
            algorithm,
            profile,
            &self.team_id,
            &self.person_name,
            &self.country_name,
            validity_duration,
        )?;

        let cert_pem = cert.encode_pem();
        let key_pem = pem::encode(&pem::Pem::new(
            "PRIVATE KEY",
            key_pair.to_pkcs8_one_asymmetric_key_der().to_vec(),
        ));

        let mut wrote_file = false;

        if let Some(pem_filename) = &self.pem_filename {
            let cert_path = PathBuf::from(format!("{pem_filename}.crt"));
            let key_path = PathBuf::from(format!("{pem_filename}.key"));

            if let Some(parent) = cert_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            println!("writing public certificate to {}", cert_path.display());
            std::fs::write(&cert_path, cert_pem.as_bytes())?;
            println!("writing private signing key to {}", key_path.display());
            std::fs::write(&key_path, key_pem.as_bytes())?;

            wrote_file = true;
        }

        if let Some(path) = &self.pem_unified_path {
            let content = format!("{}{}", key_pem, cert_pem);

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            println!("writing unified PEM to {}", path.display());
            std::fs::write(path, content.as_bytes())?;

            wrote_file = true;
        }

        if let Some(path) = &self.p12_path {
            let password = get_pkcs12_password(self.p12_password.clone(), None::<PathBuf>)?;

            let pfx = p12::PFX::new(
                &cert.encode_der()?,
                &key_pair.to_pkcs8_one_asymmetric_key_der(),
                None,
                &password,
                "code-signing",
            )
            .ok_or_else(|| {
                AppleCodesignError::CliGeneralError("failed to create PFX structure".into())
            })?;

            println!("writing PKCS#12 certificate to {}", path.display());

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, pfx.to_der())?;

            wrote_file = true;
        }

        if !wrote_file {
            print!("{cert_pem}");
            print!("{key_pem}");
        }

        Ok(())
    }
}

#[derive(Parser)]
struct KeychainExportCertificateChain {
    /// Keychain domain to operate on
    #[arg(long, value_parser = KEYCHAIN_DOMAINS, default_value = "user")]
    domain: String,

    /// Password to unlock the Keychain
    #[arg(long, group = "unlock-password")]
    password: Option<String>,

    /// File containing password to use to unlock the Keychain
    #[arg(long = "password-file", group = "unlock-password")]
    password_path: Option<PathBuf>,

    /// Print only the issuing certificate chain, not the subject certificate
    #[arg(long)]
    no_print_self: bool,

    /// User ID value of code signing certificate to find and whose CA chain to export
    #[arg(long)]
    user_id: String,
}

impl CliCommand for KeychainExportCertificateChain {
    #[cfg(target_os = "macos")]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let domain = KeychainDomain::try_from(self.domain.as_str())
            .expect("clap should have validated domain values");

        let password = if let Some(path) = &self.password_path {
            let data = std::fs::read_to_string(path)?;

            Some(
                data.lines()
                    .next()
                    .expect("should get a single line")
                    .to_string(),
            )
        } else {
            self.password.as_ref().map(|password| password.to_string())
        };

        let certs =
            macos_keychain_find_certificate_chain(domain, password.as_deref(), &self.user_id)?;

        for (i, cert) in certs.iter().enumerate() {
            if self.no_print_self && i == 0 {
                continue;
            }

            print!("{}", cert.encode_pem());
        }

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        Err(AppleCodesignError::CliGeneralError(
            "macOS Keychain export only supported on macOS".to_string(),
        ))
    }
}

#[derive(Parser)]
struct KeychainPrintCertificates {
    /// Keychain domain to operate on
    #[arg(long, value_parser = KEYCHAIN_DOMAINS, default_value = "user")]
    domain: String,
}

impl CliCommand for KeychainPrintCertificates {
    #[cfg(target_os = "macos")]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let domain = KeychainDomain::try_from(self.domain.as_str())
            .expect("clap should have validated domain values");

        let certs = keychain_find_code_signing_certificates(domain, None)?;

        for (i, cert) in certs.into_iter().enumerate() {
            println!("# Certificate {}", i);
            println!();
            print_certificate_info(&cert)?;
            println!();
        }

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        Err(AppleCodesignError::CliGeneralError(
            "macOS Keychain integration supported on macOS".to_string(),
        ))
    }
}

#[derive(Parser)]
struct MachoUniversalCreate {
    /// Input Mach-O binaries to combine.
    input: Vec<PathBuf>,

    /// Output file to write.
    #[arg(short = 'o', long)]
    output: PathBuf,
}

impl CliCommand for MachoUniversalCreate {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let mut builder = crate::macho_universal::UniversalBinaryBuilder::default();

        for path in &self.input {
            eprintln!("adding {}", path.display());
            let data = std::fs::read(path)?;
            builder.add_binary(data)?;
        }

        eprintln!("writing {}", self.output.display());

        if let Some(parent) = self.output.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut fh = std::fs::File::create(&self.output)?;
        simple_file_manifest::set_executable(&mut fh)?;
        builder.write(&mut fh)?;

        Ok(())
    }
}

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct NotaryList {
    #[command(flatten)]
    api: NotaryApi,
}

#[cfg(feature = "notarize")]
impl CliCommand for NotaryList {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let notarizer = self.api.notarizer()?;

        let submissions = notarizer.list_submissions()?;

        for entry in &submissions.data {
            println!(
                "{} {} {} {} {}",
                entry.id,
                entry.attributes.created_date,
                entry.attributes.name,
                entry.r#type,
                entry.attributes.status
            );
        }

        Ok(())
    }
}

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct NotaryLog {
    /// The ID of the previous submission to wait on
    submission_id: String,

    #[command(flatten)]
    api: NotaryApi,
}

#[cfg(feature = "notarize")]
impl CliCommand for NotaryLog {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let notarizer = self.api.notarizer()?;

        let log = notarizer.fetch_notarization_log(&self.submission_id)?;

        for line in serde_json::to_string_pretty(&log)?.lines() {
            println!("{line}");
        }

        Ok(())
    }
}

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct NotarySubmit {
    /// Whether to wait for upload processing to complete
    #[arg(long)]
    wait: bool,

    /// Maximum time in seconds to wait for the upload result
    #[arg(long, default_value = "600")]
    max_wait_seconds: u64,

    /// Staple the notarization ticket after successful upload (implies --wait)
    #[arg(long)]
    staple: bool,

    /// Path to asset to upload
    path: PathBuf,

    #[command(flatten)]
    api: NotaryApi,
}

#[cfg(feature = "notarize")]
impl CliCommand for NotarySubmit {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let wait = self.wait || self.staple;

        let wait_limit = if wait {
            Some(std::time::Duration::from_secs(self.max_wait_seconds))
        } else {
            None
        };
        let notarizer = self.api.notarizer()?;

        let upload = notarizer.notarize_path(&self.path, wait_limit)?;

        if self.staple {
            match upload {
                crate::notarization::NotarizationUpload::UploadId(_) => {
                    panic!(
                        "NotarizationUpload::UploadId should not be returned if we waited successfully"
                    );
                }
                crate::notarization::NotarizationUpload::NotaryResponse(_) => {
                    let stapler = crate::stapling::Stapler::new()?;
                    stapler.staple_path(&self.path)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct NotaryWait {
    /// Maximum time in seconds to wait for the upload result
    #[arg(long, default_value = "600")]
    max_wait_seconds: u64,

    /// The ID of the previous submission to wait on
    submission_id: String,

    #[command(flatten)]
    api: NotaryApi,
}

#[cfg(feature = "notarize")]
impl CliCommand for NotaryWait {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let wait_duration = std::time::Duration::from_secs(self.max_wait_seconds);
        let notarizer = self.api.notarizer()?;

        notarizer.wait_on_notarization_and_fetch_log(&self.submission_id, wait_duration)?;

        Ok(())
    }
}

#[derive(Parser)]
struct ParseCodeSigningRequirement {
    /// Output format
    #[arg(long, value_parser = ["csrl", "expression-tree"], default_value = "csrl")]
    format: String,

    /// Path to file to parse
    input_path: PathBuf,
}

impl CliCommand for ParseCodeSigningRequirement {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let data = std::fs::read(&self.input_path)?;

        let requirements = CodeRequirements::parse_blob(&data)?.0;

        for requirement in requirements.iter() {
            match self.format.as_str() {
                "csrl" => {
                    println!("{requirement}");
                }
                "expression-tree" => {
                    println!("{requirement:#?}");
                }
                format => panic!("unhandled format: {format}"),
            }
        }

        Ok(())
    }
}

#[derive(Parser)]
struct PrintSignatureInfo {
    /// Filesystem path to entity whose info to print
    path: PathBuf,
}

impl CliCommand for PrintSignatureInfo {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let reader = SignatureReader::from_path(&self.path)?;

        let entities = reader.entities()?;
        serde_yaml::to_writer(std::io::stdout(), &entities)?;

        Ok(())
    }
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct SessionJoinString {
    /// Open an editor to input the session join string
    #[arg(long = "editor")]
    session_join_string_editor: bool,

    /// Path to file containing session join string
    #[arg(long = "sjs-file", alias = "sjs-path")]
    session_join_string_path: Option<PathBuf>,

    /// Session join string (provided by the signing initiator)
    session_join_string: Option<String>,
}

#[derive(Parser)]
struct RemoteSign {
    #[command(flatten)]
    session_join_string: SessionJoinString,

    #[command(flatten)]
    certificate: CertificateSource,
}

impl CliCommand for RemoteSign {
    fn as_config(&self) -> Result<Option<Config>, AppleCodesignError> {
        Ok(Some(Config {
            remote_sign: config::RemoteSignConfig {
                signer: self.certificate.clone(),
            },
            ..Default::default()
        }))
    }

    fn run(&self, context: &Context) -> Result<(), AppleCodesignError> {
        let c = &context.config.remote_sign;

        let session_join_string = if self.session_join_string.session_join_string_editor {
            let mut value = None;

            for _ in 0..3 {
                if let Some(content) = dialoguer::Editor::new()
                    .require_save(true)
                    .edit("# Please enter the -----BEGIN SESSION JOIN STRING---- content below.\n# Remember to save the file!")?
                {
                    value = Some(content);
                    break;
                }
            }

            value.ok_or_else(|| {
                AppleCodesignError::CliGeneralError(
                    "session join string not entered in editor".into(),
                )
            })?
        } else if let Some(path) = &self.session_join_string.session_join_string_path {
            std::fs::read_to_string(path)?
        } else if let Some(value) = &self.session_join_string.session_join_string {
            value.to_string()
        } else {
            return Err(AppleCodesignError::CliGeneralError(
                "session join string argument parsing failure".into(),
            ));
        };

        let mut joiner = create_session_joiner(session_join_string)?;

        let url = if let Some(key) = &c.signer.remote_signing_key {
            if let Some(env) = &key.shared_secret_env {
                let secret = std::env::var(env).map_err(|_| AppleCodesignError::CliBadArgument)?;
                joiner
                    .register_state(SessionJoinState::SharedSecret(secret.as_bytes().to_vec()))?;
            } else if let Some(secret) = &key.shared_secret {
                joiner
                    .register_state(SessionJoinState::SharedSecret(secret.as_bytes().to_vec()))?;
            }

            key.url()
        } else {
            crate::remote_signing::DEFAULT_SERVER_URL.to_string()
        };

        let signing_certs = c.signer.resolve_certificates(true)?;

        let private = signing_certs.private_key()?;

        let mut public_certificates = signing_certs.certs.clone();
        let cert = public_certificates.remove(0);

        let certificates = if let Some(chain) = cert.apple_root_certificate_chain() {
            // The chain starts with self.
            chain.into_iter().skip(1).collect::<Vec<_>>()
        } else {
            public_certificates
        };

        joiner.register_state(SessionJoinState::PublicKeyDecrypt(
            private.to_public_key_peer_decrypt()?,
        ))?;

        let client = UnjoinedSigningClient::new_signer(
            joiner,
            private.as_key_info_signer(),
            cert,
            certificates,
            url,
        )?;
        client.run()?;

        Ok(())
    }
}

/// Signing arguments that can be scoped.
#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct ScopedSigningArgs {
    /// Identifier string for binary. The value normally used by CFBundleIdentifier
    #[arg(long = "binary-identifier", value_name = "IDENTIFIER")]
    binary_identifiers: Vec<String>,

    /// Path to a file containing binary code requirements data to be used as designated requirements
    #[arg(
        long = "code-requirements-file",
        alias = "code-requirements-path",
        value_name = "PATH"
    )]
    code_requirements_paths: Vec<String>,

    /// Path to an XML plist file containing code resources
    #[arg(
        long = "code-resources-file",
        alias = "code-resources",
        value_name = "PATH"
    )]
    code_resources_paths: Vec<String>,

    /// Code signature flags to set.
    ///
    /// Valid values: host, hard, kill, expires, library, runtime, linker-signed
    #[arg(long)]
    code_signature_flags: Vec<String>,

    /// Digest algorithms to use.
    ///
    /// This typically doesn't need to be set since the OS targeting information
    /// from signed binaries implicitly derives appropriate digests to sign with.
    ///
    /// However, there are special cases where you may want to force use of
    /// specific digests.
    ///
    /// The first provided value will become the "primary" digest. Subsequent
    /// values will become alternative digests. The "primary" digest should be
    /// "older" to ensure compatibility with older clients.
    ///
    /// When targeting older Apple OS versions, SHA-1 should be the primary digest
    /// and SHA-256 should also be present for compatibility with newer OS versions.
    ///
    /// When targeting new OS versions, it is sufficient to only provide SHA-256
    /// digests.
    ///
    /// The following values are accepted: none, sha1, sha256, sha384, sha512.
    ///
    /// Important: only "sha1" and "sha256" are widely used and use of other
    /// algorithms may cause problems.
    #[arg(long = "digest", value_name = "DIGEST")]
    digests: Vec<String>,

    /// Path to a plist file containing entitlements
    #[arg(
        short = 'e',
        long = "entitlements-xml-file",
        alias = "entitlements-xml-path",
        value_name = "PATH"
    )]
    entitlements_xml_paths: Vec<String>,

    /// Launch constraints on the current executable.
    ///
    /// Specify the path to a plist XML file defining launch constraints.
    #[arg(long = "launch-constraints-self-file", value_name = "PATH")]
    launch_constraints_self_paths: Vec<String>,

    /// Launch constraints on the parent process.
    ///
    /// Specify the path to a plist XML file defining launch constraints.
    #[arg(long = "launch-constraints-parent-file", value_name = "PATH")]
    launch_constraints_parent_paths: Vec<String>,

    /// Launch constraints on the responsible process.
    ///
    /// Specify the path to a plist XML file defining launch constraints.
    #[arg(long = "launch-constraints-responsible-file", value_name = "PATH")]
    launch_constraints_responsible_paths: Vec<String>,

    /// Constraints on loaded libraries.
    ///
    /// Specify the path to a plist XML file defining launch constraints.
    #[arg(long = "library-constraints-file", value_name = "PATH")]
    library_constraints_paths: Vec<String>,

    /// Hardened runtime version to use (defaults to SDK version used to build binary)
    #[arg(long = "runtime-version", value_name = "VERSION")]
    runtime_versions: Vec<String>,

    /// Path to an Info.plist file whose digest to include in Mach-O signature
    #[arg(
        long = "info-plist-file",
        alias = "info-plist-path",
        value_name = "PATH"
    )]
    info_plist_paths: Vec<String>,
}

/// Represents the set of scopable signing settings for a given scope.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSigningSettingsValues {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_requirements_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_resources_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_signature_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlements_xml_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_constraints_self_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_constraints_parent_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_constraints_responsible_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_constraints_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info_plist_file: Option<PathBuf>,
}

pub fn split_scoped_value(s: &str) -> (String, &str) {
    let parts = s.splitn(2, ':').collect::<Vec<_>>();

    match parts.len() {
        1 => ("@main".into(), s),
        2 => (parts[0].to_string(), parts[1]),
        _ => {
            panic!("error splitting scoped value; this should not occur");
        }
    }
}

/// A mapping of scopes to collections of signing settings.
///
/// This abstraction exists to make it easier to load config files.
pub struct ScopedSigningSettings(pub BTreeMap<String, ScopedSigningSettingsValues>);

impl TryFrom<&ScopedSigningArgs> for ScopedSigningSettings {
    type Error = AppleCodesignError;

    fn try_from(args: &ScopedSigningArgs) -> Result<Self, Self::Error> {
        let mut res = BTreeMap::<String, ScopedSigningSettingsValues>::default();

        for value in &args.binary_identifiers {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().binary_identifier = Some(value.into());
        }

        for value in &args.code_requirements_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().code_requirements_file = Some(value.into());
        }

        for value in &args.code_resources_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().code_resources_file = Some(value.into());
        }

        for value in &args.code_signature_flags {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope)
                .or_default()
                .code_signature_flags
                .push(value.into());
        }

        for value in &args.digests {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().digests.push(value.into());
        }

        for value in &args.entitlements_xml_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().entitlements_xml_file = Some(value.into());
        }

        for value in &args.launch_constraints_self_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().launch_constraints_self_file = Some(value.into());
        }

        for value in &args.launch_constraints_parent_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().launch_constraints_parent_file = Some(value.into());
        }

        for value in &args.launch_constraints_responsible_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope)
                .or_default()
                .launch_constraints_responsible_file = Some(value.into());
        }

        for value in &args.library_constraints_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().library_constraints_file = Some(value.into());
        }

        for value in &args.runtime_versions {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().runtime_version = Some(value.into());
        }

        for value in &args.info_plist_paths {
            let (scope, value) = split_scoped_value(value);
            res.entry(scope).or_default().info_plist_file = Some(value.into());
        }

        Ok(Self(res))
    }
}

impl ScopedSigningSettings {
    pub fn load_into_settings(
        self,
        settings: &mut SigningSettings,
    ) -> Result<(), AppleCodesignError> {
        for (scope, values) in self.0 {
            let scope = SettingsScope::try_from(scope.as_str())?;

            if let Some(v) = values.binary_identifier {
                settings.set_binary_identifier(scope.clone(), v);
            }

            if let Some(v) = values.code_requirements_file {
                let code_requirements_data = std::fs::read(v)?;
                let reqs = CodeRequirements::parse_blob(&code_requirements_data)?.0;
                for expr in reqs.iter() {
                    warn!(
                        "setting designated code requirements for {}: {}",
                        scope, expr
                    );

                    settings.set_designated_requirement_expression(scope.clone(), expr)?;
                }
            }

            if let Some(path) = values.code_resources_file {
                warn!(
                    "setting code resources data for {} from path {}",
                    scope,
                    path.display()
                );
                let code_resources_data = std::fs::read(path)?;
                settings.set_code_resources_data(scope.clone(), code_resources_data);
            }

            // If code signature flags are specified, they overwrite defaults. So reset
            // current values on the scope before setting anything.
            if !values.code_signature_flags.is_empty() {
                if let Some(existing) = settings.code_signature_flags(&scope) {
                    if existing != CodeSignatureFlags::empty() {
                        warn!(
                            "removing code signature flags {:?} from {}",
                            existing, scope
                        );
                    }
                }

                settings.set_code_signature_flags(scope.clone(), CodeSignatureFlags::empty());
            }

            for value in values.code_signature_flags {
                let flags = CodeSignatureFlags::from_str(&value)?;
                warn!("adding code signature flag {:?} to {}", flags, scope);
                settings.add_code_signature_flags(scope.clone(), flags);
            }

            for (i, value) in values.digests.into_iter().enumerate() {
                let digest_type = DigestType::try_from(value.as_str())?;

                if i == 0 {
                    settings.set_digest_type(scope.clone(), digest_type);
                } else {
                    settings.add_extra_digest(scope.clone(), digest_type);
                }
            }

            if let Some(path) = values.entitlements_xml_file {
                warn!(
                    "setting entitlements XML for {} from path {}",
                    scope,
                    path.display()
                );
                let entitlements_data = std::fs::read_to_string(path)?;
                settings.set_entitlements_xml(scope.clone(), entitlements_data)?;
            }

            if let Some(path) = values.launch_constraints_self_file {
                warn!(
                    "setting self launch constraints for {} from path {}",
                    scope,
                    path.display()
                );
                settings.set_launch_constraints_self(
                    scope.clone(),
                    EncodedEnvironmentConstraints::from_requirements_plist_file(path)?,
                );
            }

            if let Some(path) = values.launch_constraints_parent_file {
                warn!(
                    "setting parent process launch constraints for {} from path {}",
                    scope,
                    path.display()
                );
                settings.set_launch_constraints_parent(
                    scope.clone(),
                    EncodedEnvironmentConstraints::from_requirements_plist_file(path)?,
                );
            }

            if let Some(path) = values.launch_constraints_responsible_file {
                warn!(
                    "setting responsible process launch constraints for {} from path {}",
                    scope,
                    path.display()
                );
                settings.set_launch_constraints_responsible(
                    scope.clone(),
                    EncodedEnvironmentConstraints::from_requirements_plist_file(path)?,
                );
            }

            if let Some(path) = values.library_constraints_file {
                warn!(
                    "setting loaded library constraints for {} from path {}",
                    scope,
                    path.display()
                );
                settings.set_library_constraints(
                    scope.clone(),
                    EncodedEnvironmentConstraints::from_requirements_plist_file(path)?,
                );
            }

            if let Some(value) = values.runtime_version {
                let version = semver::Version::parse(&value)?;
                settings.set_runtime_version(scope.clone(), version);
            }

            if let Some(path) = values.info_plist_file {
                let data = std::fs::read(path)?;
                settings.set_info_plist_data(scope, data);
            }
        }

        Ok(())
    }
}

#[derive(Parser)]
struct Sign {
    #[command(flatten)]
    scoped: ScopedSigningArgs,

    /// Team name/identifier to include in code signature
    #[arg(long, value_name = "NAME")]
    team_name: Option<String>,

    /// An RFC 3339 date and time string to be used in signatures.
    ///
    /// e.g. 2023-11-05T10:42:00Z.
    ///
    /// If not specified, the current time will be used.
    ///
    /// Setting is only used when signing with a signing certificate.
    ///
    /// This setting is typically not necessary. It was added to facilitate
    /// deterministic signing behavior.
    #[arg(long)]
    signing_time: Option<String>,

    /// URL of time-stamp server to use to obtain a token of the CMS signature
    ///
    /// Can be set to the special value `none` to disable the generation of time-stamp
    /// tokens and use of a time-stamp server.
    #[arg(long, default_value = APPLE_TIMESTAMP_URL)]
    timestamp_url: String,

    /// Glob expression of paths to exclude from signing
    #[arg(long)]
    exclude: Vec<String>,

    /// Do not traverse into nested entities when signing.
    ///
    /// Some signable entities (like directory bundles) have child/nested entities
    /// that can be signed. By default, signing traversed into these entities and
    /// signs all entities recursively.
    ///
    /// Activating shallow signing mode using this flag overrides the default behavior.
    ///
    /// The behavior of this flag is subject to change. As currently implemented it
    /// will:
    ///
    /// * Prevent signing nested bundles when signing a bundle. e.g. if an app
    ///   bundle contains a framework, only the app bundle will be signed. Additional
    ///   Mach-O binaries within a bundle may still be signed with this flag set.
    ///
    /// Activating shallow signing mode can result in signing failures if the skipped
    /// nested entities aren't signed. For example, when signing an application bundle
    /// containing an unsigned nested bundle/framework, signing will fail with an
    /// error about a missing code signature. Always be sure to sign nested entities
    /// before their parents when this mode is activated.
    #[arg(long)]
    shallow: bool,

    /// Indicate that the entity being signed will later be notarized.
    ///
    /// Notarized software is subject to specific requirements, such as enabling the
    /// hardened runtime.
    ///
    /// The presence of this flag influences signing settings and engages additional
    /// checks to help ensure that signed software can be successfully notarized.
    ///
    /// This flag is best effort. Notarization failures of software signed with
    /// this flag may be indicative of bugs in this software.
    ///
    /// The behavior of this flag is subject to change. As currently implemented,
    /// it will:
    ///
    /// * Require the use of a "Developer ID" signing certificate issued by Apple.
    /// * Require the use of a time-stamp server.
    /// * Enable the hardened runtime code signature flag on all Mach-O binaries
    ///   (equivalent to `--code-signature-flags runtime` for all signed paths).
    #[arg(long)]
    for_notarization: bool,

    /// Path to Mach-O binary to sign
    input_path: PathBuf,

    /// Path to signed Mach-O binary to write
    output_path: Option<PathBuf>,

    #[command(flatten)]
    certificate: CertificateSource,
}

impl CliCommand for Sign {
    fn as_config(&self) -> Result<Option<Config>, AppleCodesignError> {
        let paths = ScopedSigningSettings::try_from(&self.scoped)?;

        Ok(Some(Config {
            sign: config::SignConfig {
                signer: self.certificate.clone(),
                paths: paths.0,
            },
            ..Default::default()
        }))
    }

    fn run(&self, context: &Context) -> Result<(), AppleCodesignError> {
        let c = &context.config.sign;

        let mut settings = SigningSettings::default();

        let certs = c.signer.resolve_certificates(true)?;
        certs.load_into_signing_settings(&mut settings)?;

        // Doesn't make sense to set a time-stamp server URL unless we're generating
        // CMS signatures.
        if settings.signing_key().is_some() && self.timestamp_url != "none" {
            warn!("using time-stamp protocol server {}", self.timestamp_url);
            settings.set_time_stamp_url(&self.timestamp_url)?;
        }

        if let Some(time) = &self.signing_time {
            let time = chrono::DateTime::parse_from_rfc3339(time).map_err(|e| {
                AppleCodesignError::CliGeneralError(format!("invalid signing time format: {}", e))
            })?;
            let time = time.with_timezone(&chrono::Utc);
            settings.set_signing_time(time);
        }

        if let Some(team_id) = settings.set_team_id_from_signing_certificate() {
            warn!(
                "automatically setting team ID from signing certificate: {}",
                team_id
            );
        }

        if let Some(team_name) = &self.team_name {
            settings.set_team_id(team_name);
        }

        settings.set_shallow(self.shallow);
        settings.set_for_notarization(self.for_notarization);

        for pattern in &self.exclude {
            settings.add_path_exclusion(pattern)?;
        }

        ScopedSigningSettings(c.paths.clone()).load_into_settings(&mut settings)?;

        settings.ensure_for_notarization_settings()?;

        // Settings are locked in. Proceed to sign.

        let signer = UnifiedSigner::new(settings);

        if let Some(output_path) = &self.output_path {
            warn!(
                "signing {} to {}",
                self.input_path.display(),
                output_path.display()
            );

            signer.sign_path(&self.input_path, output_path)?;
        } else {
            warn!("signing {} in place", self.input_path.display());
            signer.sign_path_in_place(&self.input_path)?;
        }

        if let Some(private) = certs.private_key_optional()? {
            private.finish()?;
        }

        Ok(())
    }
}

#[derive(Parser)]
struct SmartcardScan {}

impl CliCommand for SmartcardScan {
    #[cfg(feature = "yubikey")]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let mut ctx = ::yubikey::reader::Context::open()?;
        for (index, reader) in ctx.iter()?.enumerate() {
            println!("Device {}: {}", index, reader.name());

            if let Ok(yk) = reader.open() {
                let mut yk = crate::yubikey::YubiKey::from(yk);
                println!("Device {}: Serial: {}", index, yk.inner()?.serial());
                println!("Device {}: Version: {}", index, yk.inner()?.version());

                for (slot, cert) in yk.find_certificates()? {
                    println!(
                        "Device {}: Certificate in slot {:?} / {}",
                        index,
                        slot,
                        hex::encode([u8::from(slot)])
                    );
                    print_certificate_info(&cert)?;
                    println!();
                }
            }
        }

        Ok(())
    }

    #[cfg(not(feature = "yubikey"))]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        eprintln!("smartcard reading requires the `yubikey` crate feature, which isn't enabled.");
        eprintln!("recompile the crate with `cargo build --features yubikey` to enable support");
        std::process::exit(1);
    }
}

#[derive(Parser)]
struct SmartcardGenerateKey {
    /// Smartcard slot number to store key in (9c is common)
    #[arg(long)]
    smartcard_slot: String,

    #[command(flatten)]
    policy: YubikeyPolicy,
}

impl CliCommand for SmartcardGenerateKey {
    #[cfg(feature = "yubikey")]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let slot_id = ::yubikey::piv::SlotId::from_str(&self.smartcard_slot)?;

        let touch_policy = str_to_touch_policy(self.policy.touch_policy.as_str())?;
        let pin_policy = str_to_pin_policy(self.policy.pin_policy.as_str())?;

        let mut yk = YubiKey::new()?;
        yk.set_pin_callback(prompt_smartcard_pin);

        yk.generate_key(slot_id, touch_policy, pin_policy)?;

        Ok(())
    }

    #[cfg(not(feature = "yubikey"))]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        eprintln!(
            "smartcard integration requires the `yubikey` crate feature, which isn't enabled."
        );
        eprintln!("recompile the crate with `cargo build --features yubikey` to enable support");
        std::process::exit(1);
    }
}

#[derive(Parser)]
struct SmartcardImport {
    /// Re-use the existing private key in the smartcard slot
    #[arg(long)]
    existing_key: bool,

    /// Don't actually perform the import
    #[arg(long)]
    dry_run: bool,

    #[command(flatten)]
    certificate: CertificateSource,

    #[command(flatten)]
    policy: YubikeyPolicy,
}

impl CliCommand for SmartcardImport {
    #[cfg(feature = "yubikey")]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let signing_certs = self.certificate.resolve_certificates(false)?;

        let slot_id = ::yubikey::piv::SlotId::from_str(
            self.certificate
                .smartcard_key
                .as_ref()
                .unwrap()
                .slot
                .as_ref()
                .ok_or_else(|| {
                    error!("--smartcard-slot is required");
                    AppleCodesignError::CliBadArgument
                })?,
        )?;
        let touch_policy = str_to_touch_policy(self.policy.touch_policy.as_str())?;
        let pin_policy = str_to_pin_policy(self.policy.pin_policy.as_str())?;

        println!(
            "found {} private keys and {} public certificates",
            signing_certs.keys.len(),
            signing_certs.certs.len()
        );

        let key = if self.existing_key {
            println!("using existing private key in smartcard");

            if !signing_certs.keys.is_empty() {
                println!(
                    "ignoring {} private keys specified via arguments",
                    signing_certs.keys.len()
                );
            }

            None
        } else {
            Some(signing_certs.private_key()?)
        };

        let cert = signing_certs
            .certs
            .clone()
            .into_iter()
            .next()
            .ok_or_else(|| {
                println!("no public certificates found");
                AppleCodesignError::CliBadArgument
            })?;

        println!(
            "Will import the following certificate into slot {}",
            hex::encode([u8::from(slot_id)])
        );
        print_certificate_info(&cert)?;

        let mut yk = YubiKey::new()?;
        yk.set_pin_callback(prompt_smartcard_pin);

        if self.dry_run {
            println!("dry run mode enabled; stopping");
            return Ok(());
        }

        if let Some(key) = key {
            yk.import_key(
                slot_id,
                key.as_key_info_signer(),
                &cert,
                touch_policy,
                pin_policy,
            )?;
        } else {
            yk.import_certificate(slot_id, &cert)?;
        }

        Ok(())
    }

    #[cfg(not(feature = "yubikey"))]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        eprintln!("smartcard import requires `yubikey` crate feature, which isn't enabled.");
        eprintln!("recompile the crate with `cargo build --features yubikey` to enable support");
        std::process::exit(1);
    }
}

#[derive(Parser)]
struct Staple {
    /// Path to entity to attempt to staple
    path: PathBuf,
}

impl CliCommand for Staple {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let stapler = crate::stapling::Stapler::new()?;
        stapler.staple_path(&self.path)?;

        Ok(())
    }
}

#[derive(Parser)]
struct Verify {
    /// Path of Mach-O binary to examine
    path: PathBuf,
}

impl CliCommand for Verify {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let path_type = crate::PathType::from_path(&self.path)?;

        if path_type != crate::PathType::MachO {
            return Err(AppleCodesignError::CliGeneralError(format!(
                "verify command only works on Mach-O binaries; provided path is a {:?}",
                path_type
            )));
        }

        warn!("(the verify command is known to be buggy and gives misleading results; we highly recommend using Apple's tooling until this message is removed)");
        let data = std::fs::read(&self.path)?;

        let problems = crate::verify::verify_macho_data(data);

        for problem in &problems {
            println!("{problem}");
        }

        if problems.is_empty() {
            eprintln!("no problems detected!");
            eprintln!("(we do not verify everything so please do not assume that the signature meets Apple standards)");
            Ok(())
        } else {
            Err(AppleCodesignError::VerificationProblems)
        }
    }
}

#[derive(Parser)]
struct WindowsStoreExportCertificateChain {
    /// Windows Store to operate on
    #[arg(long, value_parser = WINDOWS_STORE_NAMES, default_value = "user", value_name = "STORE")]
    windows_store_name: String,

    /// Print only the issuing certificate chain, not the subject certificate
    #[arg(long)]
    no_print_self: bool,

    /// SHA-1 thumbprint of code signing certificate to find and whose CA chain to export
    #[arg(long)]
    thumbprint: String,
}

impl CliCommand for WindowsStoreExportCertificateChain {
    #[cfg(target_os = "windows")]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let store_name = StoreName::try_from(self.windows_store_name.as_str())
            .expect("clap should have validated store name values");

        let certs = windows_store_find_certificate_chain(store_name, &self.thumbprint)?;

        for (i, cert) in certs.iter().enumerate() {
            if self.no_print_self && i == 0 {
                continue;
            }

            print!("{}", cert.encode_pem());
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        Err(AppleCodesignError::CliGeneralError(
            "Windows Store export only supported on Windows".to_string(),
        ))
    }
}

#[derive(Parser)]
struct WindowsStorePrintCertificates {
    /// Windows Store name to operate on
    #[arg(long, value_parser = WINDOWS_STORE_NAMES, default_value = "user", value_name = "STORE")]
    windows_store_name: String,
}

impl CliCommand for WindowsStorePrintCertificates {
    #[cfg(target_os = "windows")]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        let store_name = StoreName::try_from(self.windows_store_name.as_str())
            .expect("clap should have validated store name values");

        let certs = windows_store_find_code_signing_certificates(store_name)?;

        for (i, cert) in certs.into_iter().enumerate() {
            println!("# Certificate {}", i);
            println!();
            print_certificate_info(&cert)?;
            println!();
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        Err(AppleCodesignError::CliGeneralError(
            "Windows Store integration only supported on Windows".to_string(),
        ))
    }
}

#[derive(Parser)]
struct X509Oids {}

impl CliCommand for X509Oids {
    fn run(&self, _context: &Context) -> Result<(), AppleCodesignError> {
        println!("# Extended Key Usage (EKU) Extension OIDs");
        println!();
        for ekup in crate::certificate::ExtendedKeyUsagePurpose::all() {
            println!("{}\t{:?}", ekup.as_oid(), ekup);
        }
        println!();
        println!("# Code Signing Certificate Extension OIDs");
        println!();
        for ext in crate::certificate::CodeSigningCertificateExtension::all() {
            println!("{}\t{:?}", ext.as_oid(), ext);
        }
        println!();
        println!("# Certificate Authority Certificate Extension OIDs");
        println!();
        for ext in crate::certificate::CertificateAuthorityExtension::all() {
            println!("{}\t{:?}", ext.as_oid(), ext);
        }

        Ok(())
    }
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Subcommands {
    /// Analyze an X.509 certificate for Apple code signing properties.
    ///
    /// Given the path to a PEM encoded X.509 certificate, this command will read
    /// the certificate and print information about it relevant to Apple code
    /// signing.
    ///
    /// The output of the command can be useful to learn about X.509 certificate
    /// extensions used by code signing certificates and to debug low-level
    /// properties related to certificates.
    AnalyzeCertificate(AnalyzeCertificate),

    /// Compute code hashes for a binary
    ComputeCodeHashes(ComputeCodeHashes),

    /// Create a binary code requirements file.
    #[command(hide = true)]
    DebugCreateCodeRequirements(debug_commands::DebugCreateCodeRequirements),

    /// Create a (launch or library) constraints file.
    #[command(hide = true)]
    DebugCreateConstraints(debug_commands::DebugCreateConstraints),

    /// Create an entitlements file.
    #[command(hide = true)]
    DebugCreateEntitlements(debug_commands::DebugCreateEntitlements),

    /// Create an Info.plist file.
    #[command(hide = true)]
    DebugCreateInfoPlist(debug_commands::DebugCreateInfoPlist),

    /// Create a Mach-O binary from parameters.
    #[command(hide = true)]
    DebugCreateMacho(debug_commands::DebugCreateMachO),

    /// Print a filesystem tree with basic metadata.
    #[command(hide = true)]
    DebugFileTree(debug_commands::DebugFileTree),

    /// Print a diff between the signature content of two paths
    DiffSignatures(DiffSignatures),

    /// Encode App Store Connect API Key metadata to JSON
    ///
    /// App Store Connect API Keys
    /// (https://developer.apple.com/documentation/appstoreconnectapi/creating_api_keys_for_app_store_connect_api)
    /// are defined by 3 components:
    ///
    /// * The Issuer ID (likely a UUID)
    /// * A Key ID (an alphanumeric value like `DEADBEEF42`)
    /// * A PEM encoded ECDSA private key (typically a file beginning with
    ///   `-----BEGIN PRIVATE KEY-----`).
    ///
    /// This command is used to encode all API Key components into a single JSON
    /// object so you only have to refer to a single entity when performing
    /// operations (like notarization) using these API Keys.
    ///
    /// The API Key components are specified as positional arguments.
    ///
    /// By default, the JSON encoded unified representation is printed to stdout.
    /// You can write to a file instead by passing `--output-path <path>`.
    ///
    /// # Security Considerations
    ///
    /// The App Store Connect API Key contains a private key and its value should be
    /// treated as sensitive: if an unwanted party obtains your private key, they
    /// effectively have access to your App Store Connect account.
    ///
    /// When this command writes JSON files, an attempt is made to limit access
    /// to the file. However, file access restrictions may not be as secure as you
    /// want. Security conscious individuals should audit the permissions of the
    /// file and adjust accordingly.
    #[cfg(feature = "notarize")]
    #[command(verbatim_doc_comment)]
    EncodeAppStoreConnectApiKey(EncodeAppStoreConnectApiKey),

    /// Print/extract various information from a Mach-O binary.
    ///
    /// Given the path to a Mach-O binary (including fat/universal binaries), this
    /// command will attempt to locate and format the requested data.
    #[command(override_usage = "rcodesign extract [OPTIONS] <COMMAND> <INPUT_PATH>")]
    Extract(extract_commands::Extract),

    /// Generates a certificate signing request that can be sent to Apple and exchanged for a signing certificate
    GenerateCertificateSigningRequest(GenerateCertificateSigningRequest),

    /// Generate a self-signed certificate for code signing
    ///
    /// This command will generate a new key pair using the algorithm of choice
    /// then create an X.509 certificate wrapper for it that is signed with the
    /// just-generated private key. The created X.509 certificate has extensions
    /// that mark it as appropriate for code signing.
    ///
    /// Certificates generated with this command can be useful for local testing.
    /// However, because it is a self-signed certificate and isn't signed by a
    /// trusted certificate authority, Apple operating systems may refuse to
    /// load binaries signed with it.
    ///
    /// By default the command prints 2 PEM encoded blocks. One block is for the
    /// X.509 public certificate. The other is for the PKCS#8 private key (which
    /// can include the public key).
    ///
    /// The `--pem-filename` argument can be specified to write the generated
    /// certificate pair to a pair of files. The destination files will have
    /// `.crt` and `.key` appended to the value provided.
    ///
    /// When the certificate is written to a file, it isn't printed to stdout.
    GenerateSelfSignedCertificate(GenerateSelfSignedCertificate),

    /// Export Apple CA certificates from the macOS Keychain
    KeychainExportCertificateChain(KeychainExportCertificateChain),

    /// Print information about certificates in the macOS keychain
    KeychainPrintCertificates(KeychainPrintCertificates),

    /// Create a universal ("fat") Mach-O binary.
    ///
    /// This is similar to the `lipo -create` command. Use it to stitch
    /// multiple single architecture Mach-O binaries into a single multi-arch
    /// binary.
    MachoUniversalCreate(MachoUniversalCreate),

    #[cfg(feature = "notarize")]
    /// List notarization submissions
    NotaryList(NotaryList),

    #[cfg(feature = "notarize")]
    /// Fetch the notarization log for a previous submission
    NotaryLog(NotaryLog),

    /// Upload an asset to Apple for notarization and possibly staple it
    ///
    /// This command is used to submit an asset to Apple for notarization. Given
    /// a path to an asset with a code signature, this command will connect to Apple's
    /// Notary API and upload the asset. It will then optionally wait on the submission
    /// to finish processing (which typically takes a few dozen seconds). If the
    /// asset validates Apple's requirements, Apple will issue a *notarization ticket*
    /// as proof that they approved of it. This ticket is then added to the asset in a
    /// process called *stapling*, which this command can do automatically if the
    /// `--staple` argument is passed.
    ///
    /// # App Store Connect API Key
    ///
    /// In order to communicate with Apple's servers, you need an App Store Connect
    /// API Key. This requires an Apple Developer account. You can generate an
    /// API Key at https://appstoreconnect.apple.com/access/api.
    ///
    /// The recommended mechanism to define the API Key is via `--api-key-path`,
    /// which takes the path to a file containing JSON produced by the
    /// `encode-app-store-connect-api-key` command. See that command's help for
    /// more details.
    ///
    /// If you don't wish to use `--api-key-path`, you can define the key components
    /// via the `--api-issuer` and `--api-key` arguments. You will need a file named
    /// `AuthKey_<ID>.p8` in one of the following locations: `$(pwd)/private_keys/`,
    /// `~/private_keys/`, '~/.private_keys/`, and `~/.appstoreconnect/private_keys/`
    /// (searched in that order). The name of the file is derived from the value of
    /// `--api-key`.
    ///
    /// In all cases, App Store Connect API Keys can be managed at
    /// https://appstoreconnect.apple.com/access/api.
    ///
    /// # Modes of Operation
    ///
    /// By default, the `notarize` command will initiate an upload to Apple and exit
    /// once the upload is complete.
    ///
    /// Once an upload is performed, Apple will asynchronously process the uploaded
    /// content. This can take seconds to minutes.
    ///
    /// To poll Apple's servers and wait on the server-side processing to finish,
    /// specify `--wait`. This will query the state of the processing every few seconds
    /// until it is finished, the max wait time is reached, or an error occurs.
    ///
    /// To automatically staple an asset after server-side processing has finished,
    /// specify `--staple`. This implies `--wait`.
    #[cfg(feature = "notarize")]
    #[command(alias = "notarize")]
    NotarySubmit(NotarySubmit),

    /// Wait for completion of a previous submission
    #[cfg(feature = "notarize")]
    NotaryWait(NotaryWait),

    /// Parse binary Code Signing Requirement data into a human readable string
    ///
    /// This command can be used to parse binary code signing requirement data and
    /// print it in various formats.
    ///
    /// The source input format is the binary code requirement serialization. This
    /// is the format generated by Apple's `csreq` tool via `csreq -b`. The binary
    /// data begins with header magic `0xfade0c00`.
    ///
    /// The default output format is the Code Signing Requirement Language. But the
    /// output format can be changed via the --format argument.
    ///
    /// Our Code Signing Requirement Language output may differ from Apple's. For
    /// example, `and` and `or` expressions always have their sub-expressions surrounded
    /// by parentheses (e.g. `(a) and (b)` instead of `a and b`) and strings are always
    /// quoted. The differences, however, should not matter to the parser or result
    /// in a different binary serialization.
    ParseCodeSigningRequirement(ParseCodeSigningRequirement),

    /// Print signature information for a filesystem path
    PrintSignatureInfo(PrintSignatureInfo),

    /// Create signatures initiated from a remote signing operation
    RemoteSign(RemoteSign),

    /// Adds code signatures to a signable entity.
    ///
    /// This command can sign the following entities:
    ///
    /// * A single Mach-O binary (specified by its file path)
    /// * A bundle (specified by its directory path)
    /// * A DMG disk image (specified by its path)
    /// * A XAR archive (commonly a .pkg installer file)
    ///
    /// If the input is Mach-O binary, it can be a single or multiple/fat/universal
    /// Mach-O binary. If a fat binary is given, each Mach-O within that binary will
    /// be signed.
    ///
    /// If the input is a bundle, the bundle will be recursively signed. If the
    /// bundle contains nested bundles or Mach-O binaries, those will be signed
    /// automatically.
    ///
    /// # Settings Scope
    ///
    /// The following signing settings are global and apply to all signed entities:
    ///
    /// * --pem-source
    /// * --team-name
    /// * --timestamp-url
    ///
    /// The following signing settings can be scoped so they only apply to certain
    /// entities:
    ///
    /// * --digest
    /// * --binary-identifier
    /// * --code-requirements-files
    /// * --code-resources-file
    /// * --code-signature-flags
    /// * --entitlements-xml-file
    /// * --info-plist-file
    ///
    /// Scoped settings take the form <value> or <scope>:<value>. If the 2nd form
    /// is used, the string before the first colon is parsed as a \"scoping string\".
    /// It can have the following values:
    ///
    /// * `main` - Applies to the main entity being signed and all nested entities.
    /// * `@<integer>` - e.g. `@0`. Applies to a Mach-O within a fat binary at the
    ///   specified index. 0 means the first Mach-O in a fat binary.
    /// * `@[cpu_type=<int>` - e.g. `@[cpu_type=7]`. Applies to a Mach-O within a fat
    ///   binary targeting a numbered CPU architecture (using numeric constants
    ///   as defined by Mach-O).
    /// * `@[cpu_type=<string>` - e.g. `@[cpu_type=x86_64]`. Applies to a Mach-O within
    ///   a fat binary targeting a CPU architecture identified by a string. See below
    ///   for the list of recognized values.
    /// * `<string>` - e.g. `path/to/file`. Applies to content at a given path. This
    ///   should be the bundle-relative path to a Mach-O binary, a nested bundle, or
    ///   a Mach-O binary within a nested bundle. If a nested bundle is referenced,
    ///   settings apply to everything within that bundle.
    /// * `<string>@<int>` - e.g. `path/to/file@0`. Applies to a Mach-O within a
    ///   fat binary at the given path. If the path is to a bundle, the setting applies
    ///   to all Mach-O binaries in that bundle.
    /// * `<string>@[cpu_type=<int|string>]` e.g. `Contents/MacOS/binary@[cpu_type=7]`
    ///   or `Contents/MacOS/binary@[cpu_type=arm64]`. Applies to a Mach-O within a
    ///   fat binary targeting a CPU architecture identified by its integer constant
    ///   or string name. If the path is to a bundle, the setting applies to all
    ///   Mach-O binaries in that bundle.
    ///
    /// The following named CPU architectures are recognized:
    ///
    /// * arm
    /// * arm64
    /// * arm64_32
    /// * x86_64
    ///
    /// Signing will traverse into nested entities:
    ///
    /// * A fat Mach-O binary will traverse into the multiple Mach-O binaries within.
    /// * A bundle will traverse into nested bundles.
    /// * A bundle will traverse non-code "resource" files and sign their digests.
    /// * A bundle will traverse non-main Mach-O binaries and sign them, adding their
    ///   metadata to the signed resources file.
    ///
    /// When signing nested entities, only some signing settings will be copied
    /// automatically:
    ///
    /// * All settings related to the signing certificate/key.
    /// * --timestamp-url
    /// * --signing-time
    /// * --exclude
    /// * --digest
    /// * --runtime-version
    ///
    /// All other settings only apply to the main entity being signed or the
    /// scoped path being annotated.
    ///
    /// # Bundle Signing Overrides Settings
    ///
    /// When signing bundles, some settings specified on the command line will be
    /// ignored. This is to ensure that the produced signing data is correct. The
    /// settings ignored include (but may not be limited to):
    ///
    /// * --binary-identifier for the main executable. The `CFBundleIdentifier` value
    ///   from the bundle's `Info.plist` will be used instead.
    /// * --code-resources-path. The code resources data will be computed automatically
    ///   as part of signing the bundle.
    /// * --info-plist-path. The `Info.plist` from the bundle will be used instead.
    /// * --digest
    ///
    /// # Designated Code Requirements
    ///
    /// When using Apple issued code signing certificates, we will attempt to apply
    /// an appropriate designated requirement automatically during signing which
    /// matches the behavior of what `codesign` would do. We do not yet support all
    /// signing certificates and signing targets for this, however. So you may
    /// need to provide your own requirements.
    ///
    /// Designated code requirements can be specified via --code-requirements-path.
    ///
    /// This file MUST contain a binary/compiled code requirements expression. We do
    /// not (yet) support parsing the human-friendly code requirements DSL. A
    /// binary/compiled file can be produced via Apple's `csreq` tool. e.g.
    /// `csreq -r '=<expression>' -b /output/path`. If code requirements data is
    /// specified, it will be parsed and displayed as part of signing to ensure it
    /// is well-formed.
    ///
    /// # Code Signing Key Pair
    ///
    /// By default, the embedded code signature will only contain digests of the
    /// binary and other important entities (such as entitlements and resources).
    /// This is often referred to as \"ad-hoc\" signing.
    ///
    /// To use a code signing key/certificate to derive a cryptographic signature,
    /// you must specify a source certificate to use. This can be done in the following
    /// ways:
    ///
    /// * The --p12-file denotes the location to a PFX formatted file. These are
    ///   often .pfx or .p12 files. A password is required to open these files.
    ///   Specify one via --p12-password or --p12-password-file or enter a password
    ///   when prompted.
    /// * The --pem-file argument defines paths to files containing PEM encoded
    ///   certificate/key data. (e.g. files with \"===== BEGIN CERTIFICATE =====\").
    /// * The --certificate-der-file argument defines paths to files containing DER
    ///   encoded certificate/key data.
    /// * The --keychain-domain and --keychain-fingerprint arguments can be used to
    ///   load code signing certificates from macOS keychains. These arguments are
    ///   ignored on non-macOS platforms.
    /// * The --windows-store-name and --windows-store-cert-fingerprint arguments can be used to
    ///   load code signing certificates from the Windows store. These arguments are
    ///   ignored on non-Windows platforms.
    /// * The --smartcard-slot argument defines the name of a slot in a connected
    ///   smartcard device to read from. `9c` is common.
    /// * Arguments beginning with --remote activate *remote signing mode* and can
    ///   be used to delegate cryptographic signing operations to a separate machine.
    ///   It is strongly advised to read the user documentation on remote signing
    ///   mode at https://gregoryszorc.com/docs/apple-codesign/main/.
    ///
    /// If you export a code signing certificate from the macOS keychain via the
    /// `Keychain Access` application as a .p12 file, we should be able to read these
    /// files via --p12-file.
    ///
    /// When using --pem-file, certificates and public keys are parsed from
    /// `BEGIN CERTIFICATE` and `BEGIN PRIVATE KEY` sections in the files.
    ///
    /// The way certificate discovery works is that --p12-file is read followed by
    /// all values to --pem-file. The seen signing keys and certificates are
    /// collected. After collection, there must be 0 or 1 signing keys present, or
    /// an error occurs. The first encountered public certificate is assigned
    /// to be paired with the signing key. All remaining certificates are assumed
    /// to constitute the CA issuing chain and will be added to the signature
    /// data to facilitate validation.
    ///
    /// If you are using an Apple-issued code signing certificate, we detect this
    /// and automatically register the Apple CA certificate chain so it is included
    /// in the digital signature. This matches the behavior of the `codesign` tool.
    ///
    /// For best results, put your private key and its corresponding X.509 certificate
    /// in a single file, either a PFX or PEM formatted file. Then add any additional
    /// certificates constituting the signing chain in a separate PEM file.
    ///
    /// When using a code signing key/certificate, a Time-Stamp Protocol server URL
    /// can be specified via --timestamp-url. By default, Apple's server is used. The
    /// special value \"none\" can disable using a timestamp server.
    ///
    /// # Selecting What to Sign
    ///
    /// By default, this command attempts to recursively sign everything in the source
    /// path. This applies to:
    ///
    /// * Bundles. If the specified bundle has nested bundles, those nested bundles
    ///   will be signed automatically.
    ///
    /// It is possible to exclude nested items from signing using --exclude. This
    /// argument takes a glob expression that matches *relative paths* from the
    /// source path. Glob expressions can be literal string compares. Or the
    /// following special syntax is recognized:
    ///
    /// * `?` matches any single character.
    /// * `*` matches any (possibly empty) sequence of characters.
    /// * `**` matches the current directory and arbitrary subdirectories. This sequence
    ///   must form a single path component, so both **a and b** are invalid and will
    ///   result in an error. A sequence of more than two consecutive * characters is
    ///   also invalid.
    /// * `[...]` matches any character inside the brackets. Character sequences can also
    ///   specify ranges of characters, as ordered by Unicode, so e.g. [0-9] specifies any
    ///   character between 0 and 9 inclusive. An unclosed bracket is invalid.
    /// * `[!...]` is the negation of `[...]`, i.e. it matches any characters not in the
    ///   brackets.
    /// * The metacharacters `?`, `*`, `[`, `]` can be matched by using brackets (e.g.
    ///   `[?]`). When a `]` occurs immediately following `[` or `[!` then it is
    ///   interpreted as being part of, rather then ending, the character set, so `]` and
    ///   `NOT ]` can be matched by `[]]` and `[!]]` respectively. The `-` character can
    ///   be specified inside a character sequence pattern by placing it at the start or
    ///   the end, e.g. `[abc-]`.
    ///
    /// Currently, --exclude only applies to the relative path of nested bundles within
    /// the main bundle to sign. e.g. if you sign `MyApp.app` and it has a
    /// `Contents/Frameworks/MyFramework.framework` that you wish to exclude, you would
    /// `--exclude Contents/Frameworks/MyFramework.framework` or even
    /// `--exclude Contents/Frameworks/**` to exclude the entire directory tree.
    ///
    /// Exclusions will still be copied and parents that need to reference exclude
    /// entities will continue to do so. If you wish to make a file or directory
    /// disappear, create a new directory without the file(s) and sign that.
    ///
    /// To exclude all nested bundles from being signed and only sign the main bundle
    /// (the default behavior of ``codesign`` without ``--deep``), use `--exclude '**'`.
    #[command(verbatim_doc_comment)]
    Sign(Sign),

    /// Generate a new private key on a smartcard
    SmartcardGenerateKey(SmartcardGenerateKey),

    /// Import a code signing certificate and key into a smartcard
    SmartcardImport(SmartcardImport),

    /// Show information about available smartcard (SC) devices
    SmartcardScan(SmartcardScan),

    /// Staples a notarization ticket to an entity
    Staple(Staple),

    /// Verifies code signature data
    Verify(Verify),

    /// Export CA certificates from the Windows Store
    WindowsStoreExportCertificateChain(WindowsStoreExportCertificateChain),

    /// Print information about certificates in the Windows Store
    WindowsStorePrintCertificates(WindowsStorePrintCertificates),

    /// Print information about X.509 OIDs related to Apple code signing
    X509Oids(X509Oids),
}

impl Subcommands {
    fn as_cli_command(&self) -> &dyn CliCommand {
        match self {
            Subcommands::AnalyzeCertificate(c) => c,
            Subcommands::ComputeCodeHashes(c) => c,
            Subcommands::DebugCreateCodeRequirements(c) => c,
            Subcommands::DebugCreateConstraints(c) => c,
            Subcommands::DebugCreateEntitlements(c) => c,
            Subcommands::DebugCreateInfoPlist(c) => c,
            Subcommands::DebugCreateMacho(c) => c,
            Subcommands::DebugFileTree(c) => c,
            Subcommands::DiffSignatures(c) => c,
            #[cfg(feature = "notarize")]
            Subcommands::EncodeAppStoreConnectApiKey(c) => c,
            Subcommands::Extract(c) => c,
            Subcommands::GenerateCertificateSigningRequest(c) => c,
            Subcommands::GenerateSelfSignedCertificate(c) => c,
            Subcommands::KeychainExportCertificateChain(c) => c,
            Subcommands::KeychainPrintCertificates(c) => c,
            Subcommands::MachoUniversalCreate(c) => c,
            #[cfg(feature = "notarize")]
            Subcommands::NotaryLog(c) => c,
            #[cfg(feature = "notarize")]
            Subcommands::NotaryList(c) => c,
            #[cfg(feature = "notarize")]
            Subcommands::NotarySubmit(c) => c,
            #[cfg(feature = "notarize")]
            Subcommands::NotaryWait(c) => c,
            Subcommands::ParseCodeSigningRequirement(c) => c,
            Subcommands::PrintSignatureInfo(c) => c,
            Subcommands::RemoteSign(c) => c,
            Subcommands::Sign(c) => c,
            Subcommands::SmartcardGenerateKey(c) => c,
            Subcommands::SmartcardImport(c) => c,
            Subcommands::SmartcardScan(c) => c,
            Subcommands::Staple(c) => c,
            Subcommands::Verify(c) => c,
            Subcommands::WindowsStoreExportCertificateChain(c) => c,
            Subcommands::WindowsStorePrintCertificates(c) => c,
            Subcommands::X509Oids(c) => c,
        }
    }
}

/// Sign and notarize Apple programs. See https://gregoryszorc.com/docs/apple-codesign/main/ for more docs
#[derive(Parser)]
#[command(author, version, arg_required_else_help = true)]
struct Cli {
    /// Explicit configuration file to load.
    ///
    /// If provided, the default configuration files are not loaded, even
    /// if they exist.
    ///
    /// Can be specified multiple times. Files are loaded/merged in the order
    /// given.
    ///
    /// The special value `/dev/null` can be used to specify an empty/null
    /// config file. It can be used to short-circuit loading of default config
    /// files.
    #[arg(short = 'C', long = "config-file", global = true)]
    config_path: Vec<PathBuf>,

    /// Configuration profile to load.
    ///
    /// If not specified, the implicit "default" profile is loaded.
    #[arg(short = 'P', long, global = true)]
    profile: Option<String>,

    /// Increase logging verbosity. Can be specified multiple times
    #[arg(short = 'v', long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Subcommands,
}

impl Cli {
    pub fn config_builder(&self) -> ConfigBuilder {
        let mut config = ConfigBuilder::default();

        config = if self.config_path.is_empty() {
            config.with_user_config_file().with_cwd_config_file()
        } else {
            for path in &self.config_path {
                if path.display().to_string() == "/dev/null" {
                    break;
                }

                config = config.toml_file(path);
            }

            config
        };

        if let Some(profile) = &self.profile {
            config = config.profile(profile.to_string());
        }

        // Environment variables override everything.
        config = config.with_env_prefix();

        config
    }
}

pub fn main_impl() -> Result<(), AppleCodesignError> {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let mut builder = env_logger::Builder::new();

    builder
        .filter_level(log_level)
        .parse_default_env();

    // Disable log context except at higher log levels.
    if log_level <= LevelFilter::Info {
        builder
            .format_timestamp(None)
            .format_level(false)
            .format_target(false);
    }

    // This spews unwanted output at default level. Nerf it by default.
    if log_level == LevelFilter::Info {
        builder.filter_module("rustls", LevelFilter::Error);
    }

    builder.init();

    let mut config_builder = cli.config_builder();

    let command = cli.command.as_cli_command();

    if let Some(config) = command.as_config()? {
        config_builder = config_builder.with_config_struct(config);
    }

    let config = config_builder.config()?;

    let context = Context { config };

    command.run(&context)
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
