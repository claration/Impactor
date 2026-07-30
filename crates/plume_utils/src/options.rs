use std::{path::PathBuf, str::FromStr};

/// Settings for the signer process.
#[derive(Clone, Debug)]
pub struct SignerOptions {
    /// Custom app name override.
    pub custom_name: Option<String>,
    /// Custom bundle identifier override.
    pub custom_identifier: Option<String>,
    /// Custom version override.
    pub custom_version: Option<String>,
    pub custom_icon: Option<PathBuf>,
    /// Custom entitlements plist to embed (only used when single_profile is set).
    pub custom_entitlements: Option<PathBuf>,
    /// Feature support options.
    pub features: SignerFeatures,
    /// Embedding options.
    pub embedding: SignerEmbedding,
    /// Mode.
    pub mode: SignerMode,
    /// Installation mode.
    pub install_mode: SignerInstallMode,
    /// Tweaks to apply before signing.
    pub tweaks: Option<Vec<PathBuf>>,
    /// Loader/runtime to bundle when applying tweaks.
    pub tweak_loader: TweakLoader,
    /// User tweak load-path behavior.
    pub tweak_injection: TweakInjection,
    /// App type.
    pub app: SignerApp,
    /// Apply autorefresh
    pub refresh: bool,
}

impl Default for SignerOptions {
    fn default() -> Self {
        SignerOptions {
            custom_name: None,
            custom_identifier: None,
            custom_version: None,
            custom_icon: None,
            custom_entitlements: None,
            features: SignerFeatures::default(),
            embedding: SignerEmbedding::default(),
            mode: SignerMode::default(),
            install_mode: SignerInstallMode::default(),
            tweaks: None,
            tweak_loader: TweakLoader::default(),
            tweak_injection: TweakInjection::default(),
            app: SignerApp::Default,
            refresh: false,
        }
    }
}

impl SignerOptions {
    pub fn new_for_app(app: SignerApp) -> Self {
        let mut settings = Self {
            app,
            ..Self::default()
        };

        match app {
            SignerApp::LiveContainer | SignerApp::LiveContainerAndSideStore => {
                settings.embedding.single_profile = true;
            }
            _ => {}
        }

        settings
    }
}

#[derive(Clone, Debug, Default)]
pub struct SignerFeatures {
    pub support_minimum_os_version: bool,
    pub support_file_sharing: bool,
    pub support_ipad_fullscreen: bool,
    pub support_game_mode: bool,
    pub support_pro_motion: bool,
    pub support_liquid_glass: bool,
    pub support_ellekit: bool,
    pub remove_url_schemes: bool,
}

/// Embedding options.
#[derive(Clone, Debug, Default)]
pub struct SignerEmbedding {
    pub single_profile: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TweakLoader {
    /// Bundle and inject the bundled ElleKit/CydiaSubstrate compatibility framework.
    ElleKit,
    /// Do not bundle a tweak loader. User tweak dylibs/frameworks are still copied and injected.
    None,
}

impl Default for TweakLoader {
    fn default() -> Self {
        TweakLoader::ElleKit
    }
}

impl std::fmt::Display for TweakLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TweakLoader::ElleKit => write!(f, "ellekit"),
            TweakLoader::None => write!(f, "none"),
        }
    }
}

impl FromStr for TweakLoader {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ellekit" => Ok(TweakLoader::ElleKit),
            "none" | "nothing" | "direct" => Ok(TweakLoader::None),
            other => Err(format!(
                "unsupported tweak loader '{other}', expected one of: ellekit, none"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TweakInjectPath {
    ExecutablePath,
    RPath,
}

impl Default for TweakInjectPath {
    fn default() -> Self {
        TweakInjectPath::RPath
    }
}

impl TweakInjectPath {
    pub fn token(self) -> &'static str {
        match self {
            TweakInjectPath::ExecutablePath => "@executable_path",
            TweakInjectPath::RPath => "@rpath",
        }
    }
}

impl std::fmt::Display for TweakInjectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token())
    }
}

impl FromStr for TweakInjectPath {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "@rpath" | "rpath" => Ok(TweakInjectPath::RPath),
            "@executable_path" | "executable" | "executable_path" | "executable-path" | "exec" => {
                Ok(TweakInjectPath::ExecutablePath)
            }
            other => Err(format!(
                "unsupported tweak inject path '{other}', expected @rpath or @executable_path"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TweakInjectFolder {
    Root,
    Frameworks,
}

impl Default for TweakInjectFolder {
    fn default() -> Self {
        TweakInjectFolder::Root
    }
}

impl TweakInjectFolder {
    pub fn load_path_component(self) -> &'static str {
        match self {
            TweakInjectFolder::Root => "",
            TweakInjectFolder::Frameworks => "Frameworks/",
        }
    }
}

impl std::fmt::Display for TweakInjectFolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TweakInjectFolder::Root => write!(f, "/"),
            TweakInjectFolder::Frameworks => write!(f, "Frameworks/"),
        }
    }
}

impl FromStr for TweakInjectFolder {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "/" | "." | "root" => Ok(TweakInjectFolder::Root),
            "framework" | "frameworks" | "frameworks/" | "/frameworks" | "/frameworks/" => {
                Ok(TweakInjectFolder::Frameworks)
            }
            other => Err(format!(
                "unsupported tweak inject folder '{other}', expected / or Frameworks/"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TweakInjection {
    /// Existing behavior: copy dylibs/frameworks into Frameworks and inject @rpath/<leaf>.
    Legacy,
    /// Explicit UI-compatible path/folder mode.
    Custom {
        path: TweakInjectPath,
        folder: TweakInjectFolder,
    },
}

impl Default for TweakInjection {
    fn default() -> Self {
        TweakInjection::Legacy
    }
}

impl TweakInjection {
    pub fn custom(path: TweakInjectPath, folder: TweakInjectFolder) -> Self {
        TweakInjection::Custom { path, folder }
    }

    pub fn destination_dir(self, app_bundle: &std::path::Path) -> PathBuf {
        match self {
            TweakInjection::Legacy => app_bundle.join("Frameworks"),
            TweakInjection::Custom { folder, .. } => match folder {
                TweakInjectFolder::Root => app_bundle.to_path_buf(),
                TweakInjectFolder::Frameworks => app_bundle.join("Frameworks"),
            },
        }
    }

    pub fn dylib_load_path(self, file_name: &str) -> String {
        match self {
            TweakInjection::Legacy => format!("@rpath/{file_name}"),
            TweakInjection::Custom { path, folder } => format!(
                "{}/{folder}{file_name}",
                path.token(),
                folder = folder.load_path_component()
            ),
        }
    }

    pub fn framework_load_path(self, framework_name: &str, executable_name: &str) -> String {
        match self {
            TweakInjection::Legacy => format!("@rpath/{framework_name}/{executable_name}"),
            TweakInjection::Custom { path, folder } => format!(
                "{}/{folder}{framework_name}/{executable_name}",
                path.token(),
                folder = folder.load_path_component()
            ),
        }
    }

    pub fn required_rpath(self) -> Option<&'static str> {
        match self {
            TweakInjection::Custom {
                path: TweakInjectPath::RPath,
                ..
            } => Some("@executable_path"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerInstallMode {
    Install,
    Export,
}

impl Default for SignerInstallMode {
    fn default() -> Self {
        SignerInstallMode::Install
    }
}

impl std::fmt::Display for SignerInstallMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerInstallMode::Install => write!(f, "Install"),
            SignerInstallMode::Export => write!(f, "Export"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerMode {
    Pem,
    Adhoc,
    None,
}

impl Default for SignerMode {
    fn default() -> Self {
        SignerMode::Pem
    }
}

impl std::fmt::Display for SignerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerMode::Pem => write!(f, "Apple ID"),
            SignerMode::Adhoc => write!(f, "Adhoc"),
            SignerMode::None => write!(f, "No Modify"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerAppReal {
    pub app: SignerApp,
    pub bundle_id: Option<String>,
}

impl SignerAppReal {
    pub fn from_bundle_identifier(identifier: Option<&str>) -> Self {
        let app = SignerApp::from_bundle_identifier(identifier);
        Self {
            app,
            bundle_id: identifier.map(|s| s.to_string()),
        }
    }

    pub fn from_bundle_identifier_and_name(identifier: Option<&str>, name: Option<&str>) -> Self {
        let app = SignerApp::from_bundle_identifier_or_name(identifier, name);
        Self {
            app,
            bundle_id: identifier.map(|s| s.to_string()),
        }
    }
}

/// Supported app types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerApp {
    Default,
    Antrag,
    Feather,
    Protokolle,
    AltStore,
    SideStore,
    LiveContainer,
    LiveContainerAndSideStore,
    StikDebug,
    SparseBox,
    EnsWilde,
    ByeTunes,
    StikStore,
    Reynard,
    Ksign,
    AutoCapture,
}

impl std::fmt::Display for SignerApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SignerApp::*;
        let name = match self {
            Default => "Default",
            Antrag => "Antrag",
            Feather => "Feather",
            Protokolle => "Protokolle",
            AltStore => "AltStore",
            SideStore => "SideStore",
            LiveContainer | LiveContainerAndSideStore => "LiveContainer",
            StikDebug => "StikDebug",
            SparseBox => "SparseBox",
            EnsWilde => "EnsWilde",
            ByeTunes => "ByeTunes",
            StikStore => "StikStore",
            Reynard => "Reynard",
            Ksign => "Ksign",
            AutoCapture => "Dev Auto Capture",
        };
        write!(f, "{}", name)
    }
}

impl SignerApp {
    pub fn from_bundle_identifier(identifier: Option<impl AsRef<str>>) -> Self {
        let id = match identifier {
            Some(id) => id.as_ref().to_owned(),
            None => return SignerApp::Default,
        };

        const KNOWN_APPS: &[(&str, SignerApp)] = &[
            ("com.kdt.livecontainer", SignerApp::LiveContainer),
            ("thewonderofyou.syslog", SignerApp::Protokolle),
            ("thewonderofyou.antrag2", SignerApp::Antrag),
            ("thewonderofyou.Feather", SignerApp::Feather),
            ("com.SideStore.SideStore", SignerApp::SideStore),
            ("com.rileytestut.AltStore", SignerApp::AltStore),
            ("com.stik.sj", SignerApp::StikDebug),
            ("com.kdt.SparseBox", SignerApp::SparseBox),
            ("com.yangjiii.EnsWilde", SignerApp::EnsWilde),
            ("com.EduAlexxis.MusicManager", SignerApp::ByeTunes),
            ("me.stik.store", SignerApp::StikStore),
            ("app.stik.store", SignerApp::StikStore),
            ("com.minh-ton.Reynard", SignerApp::Reynard),
            ("nya.asami.ksign", SignerApp::Ksign),
            ("com.halfeatentoast.devcapture", SignerApp::AutoCapture),
        ];

        for &(known_id, app) in KNOWN_APPS {
            if id.contains(known_id) {
                return app;
            }
        }

        SignerApp::Default
    }

    pub fn from_bundle_identifier_or_name(
        identifier: Option<impl AsRef<str>>,
        name: Option<impl AsRef<str>>,
    ) -> Self {
        let app = Self::from_bundle_identifier(identifier);
        if app != SignerApp::Default {
            return app;
        }

        let name = match name {
            Some(name) => name.as_ref().to_owned(),
            None => return SignerApp::Default,
        };

        let normalized = name
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>();

        const KNOWN_APP_NAMES: &[(&str, SignerApp)] = &[
            ("livecontainer", SignerApp::LiveContainer),
            ("sidestore", SignerApp::SideStore),
            ("altstore", SignerApp::AltStore),
            ("feather", SignerApp::Feather),
            ("antrag", SignerApp::Antrag),
            ("protokolle", SignerApp::Protokolle),
            ("stikdebug", SignerApp::StikDebug),
            ("sparsebox", SignerApp::SparseBox),
            ("enswilde", SignerApp::EnsWilde),
            ("byetunes", SignerApp::ByeTunes),
            ("stikstore", SignerApp::StikStore),
            ("reynard", SignerApp::Reynard),
            ("ksign", SignerApp::Ksign),
            ("dev auto capture", SignerApp::AutoCapture),
        ];

        for &(needle, app) in KNOWN_APP_NAMES {
            if normalized.contains(needle) {
                return app;
            }
        }

        SignerApp::Default
    }

    pub fn supports_pairing_file(&self) -> bool {
        use SignerApp::*;
        !matches!(self, Default | LiveContainer | AltStore)
    }

    pub fn supports_pairing_file_alt(&self) -> bool {
        use SignerApp::*;
        !matches!(self, Default | AltStore)
    }

    pub fn pairing_file_path(&self) -> Option<&'static str> {
        use SignerApp::*;
        match self {
            Antrag | Feather | Protokolle | StikDebug | SparseBox | EnsWilde | StikStore
            | Reynard | Ksign => Some("/Documents/pairingFile.plist"),
            SideStore => Some("/Documents/ALTPairingFile.mobiledevicepairing"),
            LiveContainerAndSideStore | LiveContainer => {
                Some("/Documents/SideStore/Documents/ALTPairingFile.mobiledevicepairing")
            }
            ByeTunes => Some("/Documents/pairing file/pairingFile.plist"),
            AutoCapture => Some("/Documents/rpPairingFile.plist"),
            _ => None,
        }
    }
}
