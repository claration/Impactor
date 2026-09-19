// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        cli::{certificate_source::CertificateSource, ScopedSigningSettingsValues},
        error::AppleCodesignError,
    },
    figment::{
        providers::{Env, Format, Serialized, Toml},
        Figment,
    },
    log::debug,
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
        ops::{Deref, DerefMut},
        path::Path,
    },
};

/// Configuration file profile definition.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// Configuration for the sign command.
    #[serde(default)]
    pub sign: SignConfig,

    #[serde(default)]
    pub remote_sign: RemoteSignConfig,
}

/// Configuration for the sign command.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignConfig {
    /// Defines a source for the cryptographic signing key.
    #[serde(default)]
    pub signer: CertificateSource,

    /// Keys are scope paths. Values are per-path configs.
    #[serde(default, rename = "path", skip_serializing_if = "BTreeMap::is_empty")]
    pub paths: BTreeMap<String, ScopedSigningSettingsValues>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSignConfig {
    /// Defines a source for the cryptographic signing key.
    #[serde(default)]
    pub signer: CertificateSource,
}

/// Used to instantiate [Config] instances.
#[derive(Clone)]
pub struct ConfigBuilder {
    loader: Figment,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            loader: Figment::new(),
        }
    }
}

impl Deref for ConfigBuilder {
    type Target = Figment;

    fn deref(&self) -> &Self::Target {
        &self.loader
    }
}

impl DerefMut for ConfigBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.loader
    }
}

impl ConfigBuilder {
    /// Add the $XDG_CONFIG/rcodesign/rcodesign.toml user config file if it exists.
    pub fn with_user_config_file(mut self) -> Self {
        if let Some(base) = dirs::config_dir() {
            let p = base.join("rcodesign").join("rcodesign.toml");
            debug!("registering user config file: {}", p.display());

            self.loader = self.loader.merge(Toml::file(p).nested());
        }

        self
    }

    /// Merge a config file from `pwd`/rcodesign.toml.
    pub fn with_cwd_config_file(mut self) -> Self {
        if let Ok(cwd) = std::env::current_dir() {
            let p = cwd.join("rcodesign.toml");
            debug!("registering cwd config file: {}", p.display());

            self.loader = self.loader.merge(Toml::file(p).nested());
        }

        self
    }

    /// Merge with environment variables.
    ///
    /// Must be called after [profile()] to ensure environment variables are
    /// mapped to the current profile.
    pub fn with_env_prefix(mut self) -> Self {
        debug!("registering RCODESIGN_ environment variable config source");
        let env = Env::prefixed("RCODESIGN_")
            .split("_")
            .profile(self.loader.profile().to_string());

        self.loader = self.loader.merge(env);
        self
    }

    /// Add a TOML config file to this instance.
    pub fn toml_file(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        debug!("registering custom config file: {}", path.display());
        self.loader = self.loader.merge(Toml::file(path).nested());
        self
    }

    /// Add a TOML string config to this instance.
    pub fn toml_string(mut self, data: &str) -> Self {
        debug!("registering TOML string config data");
        self.loader = self.loader.merge(Toml::string(data).nested());
        self
    }

    /// Merge a [Config] struct into this builder
    pub fn with_config_struct(mut self, config: Config) -> Self {
        debug!("registering config struct");
        let serialized = Serialized::defaults(config).profile(self.loader.profile().to_string());

        self.loader = self.loader.merge(serialized);
        self
    }

    /// Load the named profile instead of the `[default]` profile.
    pub fn profile(mut self, profile: String) -> Self {
        self.loader = self.loader.select(profile);
        self
    }

    /// Obtain a config profile.
    pub fn config(self) -> Result<Config, AppleCodesignError> {
        Ok(self.loader.extract()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use {
        crate::cli::certificate_source::{
            MacosKeychainSigningKey, P12SigningKey, PemSigningKey, RemoteSigningKey,
            SmartcardSigningKey, WindowsStoreSigningKey,
        },
        std::path::PathBuf,
    };

    #[test]
    fn default_config() {
        let c = ConfigBuilder::default().config().unwrap();

        assert_eq!(c, Config::default());
    }

    #[test]
    fn smartcard_signer() {
        let c = ConfigBuilder::default()
            .toml_string(
                r#"
                [default.sign]
                signer.smartcard = { slot = "9c" }
                "#,
            )
            .config()
            .unwrap();

        assert_eq!(
            c.sign.signer,
            CertificateSource {
                smartcard_key: Some(SmartcardSigningKey {
                    slot: Some("9c".into()),
                    pin: None,
                    pin_env: None,
                }),
                ..Default::default()
            }
        );

        let c = ConfigBuilder::default()
            .toml_string(
                r#"
                [default.sign]
                signer.smartcard = { slot = "9c", pin = "1234" }
                "#,
            )
            .config()
            .unwrap();
        assert_eq!(
            c.sign.signer,
            CertificateSource {
                smartcard_key: Some(SmartcardSigningKey {
                    slot: Some("9c".into()),
                    pin: Some("1234".into()),
                    pin_env: None,
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn macos_keychain_signer() {
        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                    [default.sign]
                    signer.macos_keychain = { sha256_fingerprint = "deadbeef" }
                    "#,
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                macos_keychain_key: Some(MacosKeychainSigningKey {
                    domains: vec![],
                    sha256_fingerprint: Some("deadbeef".into()),
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn pem_signer() {
        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                [default.sign]
                signer.pem.files = ["key.pem", "cert.pem"]
                "#
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                pem_path_key: Some(PemSigningKey {
                    paths: vec![PathBuf::from("key.pem"), PathBuf::from("cert.pem")]
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn p12_signer() {
        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                [default.sign]
                signer.p12 = { path = "key.p12", password = "password" }
                "#
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                p12_key: Some(P12SigningKey {
                    path: Some(PathBuf::from("key.p12")),
                    password: Some("password".into()),
                    password_path: None
                }),
                ..Default::default()
            }
        );
        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                [default.sign]
                signer.p12 = { path = "key.p12", password_path = "path/to/file" }
                "#
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                p12_key: Some(P12SigningKey {
                    path: Some(PathBuf::from("key.p12")),
                    password: None,
                    password_path: Some("path/to/file".into()),
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn remote_signer() {
        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                [default.sign]
                signer.remote.public_key = "DEADBEEF"
                "#
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                remote_signing_key: Some(RemoteSigningKey {
                    public_key: Some("DEADBEEF".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }
        );

        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                [default.sign]
                signer.remote.public_key_pem_path = "path/to/cert.pem"
                "#
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                remote_signing_key: Some(RemoteSigningKey {
                    public_key_pem_path: Some("path/to/cert.pem".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }
        );

        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                [default.sign]
                signer.remote.shared_secret = "SECRET"
                "#
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                remote_signing_key: Some(RemoteSigningKey {
                    shared_secret: Some("SECRET".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn windows_store() {
        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
                [default.sign]
                signer.windows_store = { stores = ["user"], sha1_fingerprint = "DEADBEEF" }
                "#
                )
                .config()
                .unwrap()
                .sign
                .signer,
            CertificateSource {
                windows_store_key: Some(WindowsStoreSigningKey {
                    stores: vec!["user".into()],
                    sha1_fingerprint: Some("DEADBEEF".into()),
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn paths_toml() {
        assert_eq!(
            ConfigBuilder::default()
                .toml_string(
                    r#"
            [default.sign.path."Contents/MacOS/extra-bin"]
            binary_identifier = "ident"
            code_requirements_file = "reqs"
            code_resources_file = "code-resources"
            code_signature_flags = ["runtime"]
            digests = ["sha1", "sha256"]
            entitlements_xml_file = "entitlements.plist"
            launch_constraints_self_file = "lc-self"
            launch_constraints_parent_file = "lc-parent"
            launch_constraints_responsible_file = "lc-responsible"
            library_constraints_file = "lc-library"
            runtime_version = "11.0.0"
            info_plist_file = "Info.plist"
            "#
                )
                .config()
                .unwrap()
                .sign
                .paths,
            BTreeMap::from_iter([(
                "Contents/MacOS/extra-bin".into(),
                ScopedSigningSettingsValues {
                    binary_identifier: Some("ident".into()),
                    code_requirements_file: Some("reqs".into()),
                    code_resources_file: Some("code-resources".into()),
                    code_signature_flags: vec!["runtime".into()],
                    digests: vec!["sha1".into(), "sha256".into()],
                    entitlements_xml_file: Some("entitlements.plist".into()),
                    launch_constraints_self_file: Some("lc-self".into()),
                    launch_constraints_parent_file: Some("lc-parent".into()),
                    launch_constraints_responsible_file: Some("lc-responsible".into()),
                    library_constraints_file: Some("lc-library".into()),
                    runtime_version: Some("11.0.0".into()),
                    info_plist_file: Some("Info.plist".into()),
                }
            )])
        );
    }
}
