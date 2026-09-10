//! A library to generate "anisette" data. Docs are coming soon.
//!
//! If you want an async API, enable the `async` feature.
//!
//! If you want remote anisette, make sure the `remote-anisette` feature is enabled. (it's currently on by default)

use crate::adi_proxy::{ADIProxyAnisetteProvider, ConfigurableADIProxy};
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use adi_proxy::ADIError;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

pub mod adi_proxy;
pub mod anisette_headers_provider;
pub mod store_services_core;

#[cfg(feature = "remote-anisette-v3")]
pub mod remote_anisette_v3;

#[allow(dead_code)]
pub struct AnisetteHeaders;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AnisetteError {
    #[allow(dead_code)]
    #[error("Unsupported device")]
    UnsupportedDevice,
    #[error("Invalid argument {0}")]
    InvalidArgument(String),
    #[error("Anisette not provisioned!")]
    AnisetteNotProvisioned,
    #[error("Plist serialization error {0}")]
    PlistError(#[from] plist::Error),
    #[error("Request Error {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("Provisioning socket error {0}")]
    WsError(#[from] tokio_tungstenite::tungstenite::error::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("JSON error {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("IO error {0}")]
    IOError(#[from] io::Error),
    #[error("ADI error {0}")]
    ADIError(#[from] ADIError),
    #[error("Invalid library format")]
    InvalidLibraryFormat,
    #[error("Misc")]
    Misc,
    #[error("Missing Libraries")]
    MissingLibraries,
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}

pub const DEFAULT_ANISETTE_URL: &str = "https://ani.f1sh.me/";

pub const DEFAULT_ANISETTE_URL_V3: &str = "https://ani.sidestore.app";

/// Client identifier Apple currently accepts in the `X-MMe-Client-Info` header
/// of GrandSlam (`gsa.apple.com`) requests.
///
/// Since early September 2026 Apple's authentication edge answers HTTP 503
/// (a short HTML page, not a GSA plist) to any request whose client token is
/// `com.apple.dt.Xcode/...`, before any credential is checked. Reporting the
/// client as `akd` — the daemon that performs this request on macOS — restores
/// authentication. Same approach as AltStore PR #1790.
///
/// NOTE: this is unrelated to the `com.apple.gs.xcode.auth` *app* identifier
/// (used for `X-Apple-App-Info` / apptoken requests) — that one must stay as is.
pub const AUTHKIT_CLIENT_INFO: &str = "com.apple.AuthKit/1 (com.apple.akd/1.0)";

/// Blocked client-token prefix inside `X-MMe-Client-Info`.
const BLOCKED_GSA_CLIENT_TOKEN_PREFIX: &str = "com.apple.dt.Xcode";

/// Accepted replacement client token inside `X-MMe-Client-Info`.
pub const GSA_CLIENT_TOKEN: &str = "com.apple.akd/1.0";

/// Replace any blocked `com.apple.dt.Xcode/<version>` client token in an
/// `X-MMe-Client-Info` value with the accepted `com.apple.akd/1.0` token.
///
/// Third-party anisette servers commonly still serve the stale Xcode string,
/// so values received from them are passed through here before being sent to
/// Apple. Anything that does not contain the blocked token is returned
/// unchanged.
pub fn sanitize_gsa_client_info(info: &str) -> String {
    let mut out = String::with_capacity(info.len());
    let mut rest = info;
    while let Some(pos) = rest.find(BLOCKED_GSA_CLIENT_TOKEN_PREFIX) {
        out.push_str(&rest[..pos]);
        let mut end = pos + BLOCKED_GSA_CLIENT_TOKEN_PREFIX.len();
        // Skip the trailing `/version` (e.g. `/3594.4.19`), if present.
        let bytes = rest.as_bytes();
        if bytes.get(end) == Some(&b'/') {
            end += 1;
            while let Some(&b) = bytes.get(end) {
                if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
                    end += 1;
                } else {
                    break;
                }
            }
        }
        out.push_str(GSA_CLIENT_TOKEN);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[derive(Clone, Debug)]
pub struct AnisetteConfiguration {
    anisette_url: String,
    anisette_url_v3: String,
    configuration_path: PathBuf,
    macos_serial: String,
}

impl Default for AnisetteConfiguration {
    fn default() -> Self {
        AnisetteConfiguration::new()
    }
}

impl AnisetteConfiguration {
    pub fn new() -> AnisetteConfiguration {
        AnisetteConfiguration {
            anisette_url: DEFAULT_ANISETTE_URL.to_string(),
            anisette_url_v3: DEFAULT_ANISETTE_URL_V3.to_string(),
            configuration_path: PathBuf::new(),
            macos_serial: "0".to_string(),
        }
    }

    pub fn anisette_url(&self) -> &String {
        &self.anisette_url
    }

    pub fn configuration_path(&self) -> &PathBuf {
        &self.configuration_path
    }

    pub fn set_anisette_url(mut self, anisette_url: String) -> AnisetteConfiguration {
        self.anisette_url = anisette_url;
        self
    }

    pub fn set_macos_serial(mut self, macos_serial: String) -> AnisetteConfiguration {
        self.macos_serial = macos_serial;
        self
    }

    pub fn set_configuration_path(mut self, configuration_path: PathBuf) -> AnisetteConfiguration {
        self.configuration_path = configuration_path;
        self
    }
}

pub enum AnisetteHeadersProviderType {
    Local,
    Remote,
}

pub struct AnisetteHeadersProviderRes {
    pub provider: Box<dyn AnisetteHeadersProvider>,
    pub provider_type: AnisetteHeadersProviderType,
}

impl AnisetteHeadersProviderRes {
    pub fn local(provider: Box<dyn AnisetteHeadersProvider>) -> AnisetteHeadersProviderRes {
        AnisetteHeadersProviderRes {
            provider,
            provider_type: AnisetteHeadersProviderType::Local,
        }
    }

    pub fn remote(provider: Box<dyn AnisetteHeadersProvider>) -> AnisetteHeadersProviderRes {
        AnisetteHeadersProviderRes {
            provider,
            provider_type: AnisetteHeadersProviderType::Remote,
        }
    }
}

impl AnisetteHeaders {
    pub fn get_anisette_headers_provider(
        configuration: AnisetteConfiguration,
    ) -> Result<AnisetteHeadersProviderRes, AnisetteError> {
        // TODO: handle Err because it will just go to remote anisette and not tell the user anything
        if let Ok(ssc_anisette_headers_provider) =
            AnisetteHeaders::get_ssc_anisette_headers_provider(configuration.clone())
        {
            return Ok(ssc_anisette_headers_provider);
        }

        #[cfg(feature = "remote-anisette-v3")]
        return Ok(AnisetteHeadersProviderRes::remote(Box::new(
            remote_anisette_v3::RemoteAnisetteProviderV3::new(
                configuration.anisette_url_v3,
                configuration.configuration_path.clone(),
                configuration.macos_serial.clone(),
            ),
        )));
    }

    pub fn get_ssc_anisette_headers_provider(
        configuration: AnisetteConfiguration,
    ) -> Result<AnisetteHeadersProviderRes, AnisetteError> {
        let mut ssc_adi_proxy = store_services_core::StoreServicesCoreADIProxy::new(
            configuration.configuration_path(),
        )?;
        let config_path = configuration.configuration_path();
        ssc_adi_proxy.set_provisioning_path(config_path.to_str().ok_or(
            AnisetteError::InvalidArgument("configuration.configuration_path".to_string()),
        )?)?;
        Ok(AnisetteHeadersProviderRes::local(Box::new(
            ADIProxyAnisetteProvider::new(ssc_adi_proxy, config_path.to_path_buf())?,
        )))
    }
}

#[cfg(test)]
mod tests {
    use log::LevelFilter;
    use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};

    pub fn init_logger() {
        if TermLogger::init(
            LevelFilter::Trace,
            ConfigBuilder::new()
                .set_target_level(LevelFilter::Error)
                .add_filter_allow_str("omnisette")
                .build(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .is_ok()
        {}
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn fetch_anisette_auto() -> Result<()> {
        use crate::{AnisetteConfiguration, AnisetteHeaders};
        use log::info;
        use std::path::PathBuf;

        crate::tests::init_logger();

        let mut provider = AnisetteHeaders::get_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test")),
        )?;
        info!(
            "Headers: {:?}",
            provider.provider.get_authentication_headers()?
        );
        Ok(())
    }

    #[test]
    fn gsa_client_info_avoids_blocked_xcode_token() {
        assert!(
            crate::AUTHKIT_CLIENT_INFO.contains(crate::GSA_CLIENT_TOKEN),
            "unexpected AUTHKIT_CLIENT_INFO: {}",
            crate::AUTHKIT_CLIENT_INFO
        );
        assert!(
            !crate::AUTHKIT_CLIENT_INFO.contains("com.apple.dt.Xcode"),
            "blocked Xcode token in AUTHKIT_CLIENT_INFO: {}",
            crate::AUTHKIT_CLIENT_INFO
        );
        assert!(
            crate::adi_proxy::CLIENT_INFO_HEADER.contains(crate::AUTHKIT_CLIENT_INFO),
            "CLIENT_INFO_HEADER diverged: {}",
            crate::adi_proxy::CLIENT_INFO_HEADER
        );
        assert!(
            !crate::adi_proxy::CLIENT_INFO_HEADER.contains("com.apple.dt.Xcode"),
            "blocked Xcode token still in CLIENT_INFO_HEADER: {}",
            crate::adi_proxy::CLIENT_INFO_HEADER
        );
    }

    #[test]
    fn sanitize_gsa_client_info_replaces_blocked_token() {
        // The block is on `com.apple.dt.Xcode` regardless of version.
        for version in ["3594.4.19", "9999.9.99", "1.0"] {
            let input = format!(
                "<Mac14,2> <macOS;15.7.5;24G624> <com.apple.AuthKit/1 (com.apple.dt.Xcode/{version})>"
            );
            let out = crate::sanitize_gsa_client_info(&input);
            assert!(
                out.contains("com.apple.akd/1.0"),
                "expected accepted akd token for version {version}, got: {out}"
            );
            assert!(
                !out.contains("com.apple.dt.Xcode"),
                "blocked Xcode token still present: {out}"
            );
        }
        // Already-accepted values pass through unchanged.
        let good = "<Mac14,2> <macOS;15.7.5;24G624> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
        assert_eq!(crate::sanitize_gsa_client_info(good), good);
    }
}
