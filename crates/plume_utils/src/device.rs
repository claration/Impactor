use std::fmt;
use std::path::{Component, Path, PathBuf};

use idevice::core_device_proxy::CoreDeviceProxy;
use idevice::installation_proxy::InstallationProxyClient;
use idevice::lockdown::LockdownClient;
use idevice::misagent::MisagentClient;
use idevice::provider::UsbmuxdProvider;
use idevice::remote_pairing::{
    RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
};
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
use idevice::usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdDevice};
use idevice::utils::installation;
use idevice::{IdeviceService, RemoteXpcClient};
use plume_core::MobileProvision;

use crate::Error;
use crate::options::SignerAppReal;
use idevice::afc::opcode::AfcFopenMode;
use idevice::house_arrest::HouseArrestClient;
use idevice::usbmuxd::UsbmuxdConnection;
use plist::Value;

pub const CONNECTION_LABEL: &str = "plume_info";
pub const INSTALLATION_LABEL: &str = "plume_install";
pub const HOUSE_ARREST_LABEL: &str = "plume_house_arrest";

macro_rules! get_dict_string {
    ($dict:expr, $key:expr) => {
        $dict
            .as_dictionary()
            .and_then(|dict| dict.get($key))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "".to_string())
    };
}

#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    pub udid: String,
    pub device_id: u32,
    pub usbmuxd_device: Option<UsbmuxdDevice>,
    // On x86_64 macs, `is_mac` variable should never be true
    // since its only true if the device is added manually.
    pub is_mac: bool,
    /// Address of the `_remotepairing-manual-pairing._tcp.local.` service, advertised only
    /// while the Apple TV is actively showing a pairing PIN. Required for first-time pairing;
    /// not valid once the pairing UI is dismissed.
    pub pairing_address: Option<(std::net::IpAddr, u16)>,
    /// Address of the `_remotepairing._tcp.local.` service, advertised whenever the Apple TV
    /// has an established pairing. Used to reconnect (pair-verify) after the initial pairing.
    pub reconnect_address: Option<(std::net::IpAddr, u16)>,
    /// Stable key for this device's cached pairing file, for devices paired over the network.
    /// `None` for USB devices, which are keyed by `udid`. Deliberately not the mDNS-advertised
    /// identifier, which changes between advertisements of the same device.
    pub pairing_identity: Option<String>,
    /// Directory holding this device's cached pairing file. Set for network devices, whose
    /// install path must re-establish a tunnel; `None` for USB devices, which need no pairing file.
    pub pairing_cache_dir: Option<PathBuf>,
}

/// A network Apple TV's real identity, as reported by the device itself over an RSD handshake
/// rather than derived from mDNS advertisements.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TvosDeviceInfo {
    pub udid: Option<String>,
    pub product_type: Option<String>,
    pub device_class: Option<String>,
    pub os_version: Option<String>,
    pub serial_number: Option<String>,
}

impl TvosDeviceInfo {
    /// Extracts the fields the signing pipeline and device list need from an RSD handshake's
    /// `properties` map. Pure and I/O-free: every field is read as a plist string, and a key
    /// that is missing or holds a non-string value yields `None` rather than a stringified
    /// fallback or a panic. `OSVersion` is preferred over `HumanReadableProductVersionString`
    /// for `os_version`, falling back to the latter when the former is absent.
    pub fn from_rsd_properties(props: &std::collections::HashMap<String, plist::Value>) -> Self {
        let as_string = |key: &str| -> Option<String> {
            props
                .get(key)
                .and_then(|v| v.as_string())
                .map(str::to_string)
        };

        TvosDeviceInfo {
            udid: as_string("UniqueDeviceID"),
            product_type: as_string("ProductType"),
            device_class: as_string("DeviceClass"),
            os_version: as_string("OSVersion")
                .or_else(|| as_string("HumanReadableProductVersionString")),
            serial_number: as_string("SerialNumber"),
        }
    }
}

/// Stable, collision-avoiding device id for a device discovered over the network.
///
/// `Device::new_tvos` leaves `device_id` at 0 (the same default a real usbmuxd device would
/// never have), and `u32::MAX` is reserved in `screen/mod.rs` as the sentinel for the "This Mac"
/// gestalt device; a caller building a `Device` for a network Apple TV must replace `device_id`
/// with this function's result to avoid colliding with either. FNV-1a is used rather than
/// `std::collections::hash_map::DefaultHasher` because the latter's output is not guaranteed
/// stable across Rust versions, and this id must stay the same across app restarts (it is how
/// the device list dedupes and how disconnect events are matched to the device that connected).
pub fn synthetic_device_id(pairing_identity: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in pairing_identity.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    // Setting the top bit both keeps the result out of usbmuxd's small sequential id space and
    // guarantees it is never 0, since the FNV-1a output above is then unconditionally nonzero
    // in its high half.
    hash |= 0x8000_0000;

    // The only value the top-bit setting above cannot rule out is u32::MAX itself, which is a
    // reserved sentinel (see the doc comment); remapped to a different fixed value that is
    // still nonzero and still has the top bit set.
    if hash == u32::MAX {
        hash = 0x8000_0000;
    }

    hash
}

impl Device {
    pub async fn new(usbmuxd_device: UsbmuxdDevice) -> Self {
        let name = Self::get_name_from_usbmuxd_device(&usbmuxd_device)
            .await
            .unwrap_or_default();

        Device {
            name,
            udid: usbmuxd_device.udid.clone(),
            device_id: usbmuxd_device.device_id.clone(),
            usbmuxd_device: Some(usbmuxd_device),
            is_mac: false,
            pairing_address: None,
            reconnect_address: None,
            pairing_identity: None,
            pairing_cache_dir: None,
        }
    }

    /// Create a Device representing a network Apple TV (no USB connection).
    /// `pairing_identity` is used as the stable key for this device's cached pairing file
    /// (e.g. derived from its advertised name). It is not the device's real UDID: that value is
    /// not available over mDNS at all, so `udid` is left empty here. A network device's real
    /// UDID, once known (see `fetch_tvos_info`/`apply_tvos_info`), must never be fabricated from
    /// mDNS data, because `udid` is what gets registered with Apple's developer portal and doing
    /// so would consume a real device slot on a value that does not correspond to a real device.
    ///
    /// `pairing_address` should come from `_remotepairing-manual-pairing._tcp.local.` and is
    /// required for `pair_tvos()`. `reconnect_address` should come from
    /// `_remotepairing._tcp.local.` and is preferred by `establish_tvos_tunnel()` once a device
    /// is already paired; when absent, `pairing_address` is used as a fallback.
    ///
    /// `cache_dir` is the directory this device's pairing file lives (or will be cached) under;
    /// it is stored on the device so `install_app()` can re-establish a tunnel without the
    /// transport-agnostic caller having to know a cache directory even exists.
    pub fn new_tvos(
        name: String,
        pairing_identity: String,
        ip: std::net::IpAddr,
        pairing_port: Option<u16>,
        reconnect_port: Option<u16>,
        cache_dir: PathBuf,
    ) -> Self {
        Device {
            name,
            udid: String::new(),
            device_id: 0,
            usbmuxd_device: None,
            is_mac: false,
            pairing_address: pairing_port.map(|port| (ip, port)),
            reconnect_address: reconnect_port.map(|port| (ip, port)),
            pairing_identity: Some(pairing_identity),
            pairing_cache_dir: Some(cache_dir),
        }
    }

    /// Path of this device's cached pairing file under `cache_dir`.
    /// Network devices are keyed by `pairing_identity` (a stable name-derived key); USB devices,
    /// which have no `pairing_identity`, fall back to `udid`.
    ///
    /// The key can originate from mDNS-advertised data on the local network, so it is validated
    /// rather than trusted: an empty key would collapse every un-enriched network device onto
    /// the same cache file, and a key containing a path separator or drive letter could write
    /// outside `cache_dir` entirely. Both are rejected outright rather than sanitized, since a
    /// rewritten key could just as easily collide two distinct devices onto one cache file.
    pub(crate) fn pairing_cache_path(&self, cache_dir: &Path) -> Result<PathBuf, Error> {
        let key = self.pairing_identity.as_deref().unwrap_or(&self.udid);

        if key.is_empty() {
            return Err(Error::Other(
                "Device has neither a pairing identity nor a UDID; cannot locate its pairing \
                 file cache"
                    .to_string(),
            ));
        }
        if key.contains('/')
            || key.contains('\\')
            || key.contains(':')
            || key.chars().all(|c| c == '.')
        {
            return Err(Error::Other(format!(
                "Pairing identity {key:?} is not a valid cache key"
            )));
        }

        Ok(cache_dir.join(format!("plume_{key}.plist")))
    }

    /// True when this device is an Apple TV, which the developer portal must be told about
    /// explicitly because its requests default to iOS.
    ///
    /// A network-paired device (one with a `pairing_identity`) is the only case this recognizes;
    /// a USB-attached Apple TV is not currently distinguished from a USB-attached iOS device and
    /// is treated as iOS. That gap is out of scope here: USB Apple TV support does not exist yet
    /// in this codebase, so there is no USB device to misclassify in practice.
    pub fn is_tvos(&self) -> bool {
        self.pairing_identity.is_some()
    }

    /// Whether `install_app` will reach this device over a network tunnel rather than usbmuxd.
    ///
    /// Mirrors the transport selection in `install_app` itself, so a caller that needs to know
    /// which transport an install will take cannot disagree with the one it actually picks. The
    /// distinction matters because a round trip over the tunnel costs orders of magnitude more
    /// than one over usbmuxd.
    pub fn is_network(&self) -> bool {
        self.usbmuxd_device.is_none()
            && (self.pairing_address.is_some() || self.reconnect_address.is_some())
    }

    async fn get_name_from_usbmuxd_device(device: &UsbmuxdDevice) -> Result<String, Error> {
        let mut lockdown =
            LockdownClient::connect(&device.to_provider(UsbmuxdAddr::default(), CONNECTION_LABEL))
                .await?;
        let values = lockdown.get_value(None, None).await?;
        Ok(get_dict_string!(values, "DeviceName"))
    }

    pub async fn installed_apps(&self) -> Result<Vec<SignerAppReal>, Error> {
        let device = match &self.usbmuxd_device {
            Some(dev) => dev,
            None => return Err(Error::Other("Device is not connected via USB".to_string())),
        };

        let provider = device.to_provider(
            UsbmuxdAddr::from_env_var().unwrap_or_default(),
            INSTALLATION_LABEL,
        );

        let mut ic = InstallationProxyClient::connect(&provider).await?;
        let apps = ic.get_apps(Some("User"), None).await?;

        let mut found_apps = Vec::new();

        for (bundle_id, info) in apps {
            let app_name = get_app_name_from_info(&info);
            let signer_app = SignerAppReal::from_bundle_identifier_and_name(
                Some(bundle_id.as_str()),
                app_name.as_deref(),
            );

            if signer_app.app.supports_pairing_file_alt()
                && !found_apps
                    .iter()
                    .any(|a: &SignerAppReal| a.bundle_id == signer_app.bundle_id)
            {
                found_apps.push(signer_app);
            }
        }

        Ok(found_apps)
    }

    pub async fn is_app_installed(&self, bundle_id: &str) -> Result<bool, Error> {
        let device = match &self.usbmuxd_device {
            Some(dev) => dev,
            None => return Err(Error::Other("Device is not connected via USB".to_string())),
        };

        let provider = device.to_provider(
            UsbmuxdAddr::from_env_var().unwrap_or_default(),
            INSTALLATION_LABEL,
        );

        let mut ic = InstallationProxyClient::connect(&provider).await?;
        let apps = ic.get_apps(Some("User"), None).await?;

        Ok(apps.contains_key(bundle_id))
    }

    pub async fn install_profile(&self, profile: &MobileProvision) -> Result<(), Error> {
        if self.usbmuxd_device.is_none() {
            return Err(Error::Other("Device is not connected via USB".to_string()));
        }

        let provider = self.usbmuxd_device.clone().unwrap().to_provider(
            UsbmuxdAddr::from_env_var().unwrap_or_default(),
            INSTALLATION_LABEL,
        );

        let mut mc = MisagentClient::connect(&provider).await?;
        mc.install(profile.data.clone()).await?;

        Ok(())
    }

    pub async fn pair(&self) -> Result<(), Error> {
        if self.usbmuxd_device.is_none() {
            return Err(Error::Other("Device is not connected via USB".to_string()));
        }

        let mut usbmuxd = UsbmuxdConnection::default().await?;

        let provider = self.usbmuxd_device.clone().unwrap().to_provider(
            UsbmuxdAddr::from_env_var().unwrap_or_default(),
            INSTALLATION_LABEL,
        );

        let mut lc = LockdownClient::connect(&provider).await?;
        let id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let buid = usbmuxd.get_buid().await?;
        let mut pairing_file = lc.pair(id, buid, None).await?;
        pairing_file.udid = Some(self.udid.clone());
        let pairing_file = pairing_file.serialize()?;

        usbmuxd.save_pair_record(&self.udid, pairing_file).await?;

        Ok(())
    }

    pub async fn install_pairing_record(
        &self,
        identifier: &String,
        path: &str,
    ) -> Result<(), Error> {
        if self.usbmuxd_device.is_none() {
            return Err(Error::Other("Device is not connected via USB".to_string()));
        }

        let mut usbmuxd = UsbmuxdConnection::default().await?;
        let provider = self
            .usbmuxd_device
            .clone()
            .unwrap()
            .to_provider(UsbmuxdAddr::default(), HOUSE_ARREST_LABEL);
        let mut pairing_file = usbmuxd.get_pair_record(&self.udid).await?;

        // saving pairing record requires enabling wifi debugging
        // since operations are done over wifi
        let mut lc = LockdownClient::connect(&provider).await?;
        lc.start_session(&pairing_file).await.ok();
        lc.set_value(
            "EnableWifiDebugging",
            true.into(),
            Some("com.apple.mobile.wireless_lockdown"),
        )
        .await
        .ok();

        pairing_file.udid = Some(self.udid.clone());

        let hc = HouseArrestClient::connect(&provider).await?;
        let mut ac = hc.vend_documents(identifier.clone()).await?;
        if let Some(parent) = Path::new(path).parent() {
            let mut current = String::new();
            let has_root = parent.has_root();

            for component in parent.components() {
                if let Component::Normal(dir) = component {
                    if has_root && current.is_empty() {
                        current.push('/');
                    } else if !current.is_empty() && !current.ends_with('/') {
                        current.push('/');
                    }

                    current.push_str(&dir.to_string_lossy());
                    ac.mk_dir(&current).await?;
                }
            }
        }

        let mut f = ac.open(path, AfcFopenMode::Wr).await?;
        f.write_entire(&pairing_file.serialize().unwrap()).await?;

        Ok(())
    }

    pub async fn install_remote_pairing_record(
        &self,
        identifier: &String,
        path: &str,
        path_to_store: PathBuf,
    ) -> Result<(), Error> {
        if self.usbmuxd_device.is_none() {
            return Err(Error::Other("Device is not connected via USB".to_string()));
        }

        let provider = self
            .usbmuxd_device
            .clone()
            .unwrap()
            .to_provider(UsbmuxdAddr::default(), HOUSE_ARREST_LABEL);

        let pairing_file = self.get_rsd_pairing_file(&provider, path_to_store).await?;

        let hc = HouseArrestClient::connect(&provider).await?;
        let mut ac = hc.vend_documents(identifier.clone()).await?;
        if let Some(parent) = Path::new(path).parent() {
            let mut current = String::new();
            let has_root = parent.has_root();

            for component in parent.components() {
                if let Component::Normal(dir) = component {
                    if has_root && current.is_empty() {
                        current.push('/');
                    } else if !current.is_empty() && !current.ends_with('/') {
                        current.push('/');
                    }

                    current.push_str(&dir.to_string_lossy());
                    ac.mk_dir(&current).await?;
                }
            }
        }

        let mut f = ac.open(path, AfcFopenMode::Wr).await?;
        f.write_entire(&pairing_file.to_bytes()).await?;

        Ok(())
    }

    async fn get_rsd_pairing_file(
        &self,
        provider: &UsbmuxdProvider,
        path: PathBuf,
    ) -> Result<RpPairingFile, Error> {
        let pairing_file_path = path.join(format!("plume_{}.plist", self.udid));

        if pairing_file_path.exists() {
            return Ok(RpPairingFile::read_from_file(pairing_file_path).await?);
        } else {
            let cdp = CoreDeviceProxy::connect(provider).await?;
            let cdp_port = cdp.tunnel_info().server_rsd_port;
            let cdp_adapter = cdp.create_software_tunnel()?;
            let mut cdp_adapter = cdp_adapter.to_async_handle();

            let cdp_stream = cdp_adapter.connect(cdp_port).await?;
            let cdp_handshake = RsdHandshake::new(cdp_stream).await?;

            let tunnel_service = cdp_handshake
                .services
                .get("com.apple.internal.dt.coredevice.untrusted.tunnelservice")
                .ok_or_else(|| Error::Other("Tunnel service not found".to_string()))?;

            let tunnel_service_stream = cdp_adapter.connect(tunnel_service.port).await?;
            let mut remote_xpc = RemoteXpcClient::new(tunnel_service_stream).await?;
            remote_xpc.do_handshake().await?;
            let _ = remote_xpc.recv_root().await;

            let suffix: String = uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(6)
                .collect();

            let hostname = format!("plume-{}", suffix);

            let mut pairing_file = RpPairingFile::generate(&hostname);
            let mut pairing_client =
                RemotePairingClient::new(remote_xpc, &hostname, &mut pairing_file);
            pairing_client
                .connect(async |_| "000000".to_string(), ())
                .await?;

            let tunnel_service_stream = cdp_adapter.connect(tunnel_service.port).await?;
            let mut remote_xpc = RemoteXpcClient::new(tunnel_service_stream).await?;
            remote_xpc.do_handshake().await?;
            let _ = remote_xpc.recv_root().await;
            let mut pairing_client =
                RemotePairingClient::new(remote_xpc, &hostname, &mut pairing_file);
            pairing_client
                .connect(async |_| "000000".to_string(), ())
                .await?;

            let pairing_file_bytes = pairing_file.to_bytes();

            tokio::fs::write(&pairing_file_path, &pairing_file_bytes).await?;

            Ok(pairing_file)
        }
    }

    /// Pair with a network Apple TV (tvOS 17.4+) using the RPPairing binary protocol.
    /// Connects to the mDNS `_remotepairing-manual-pairing._tcp.local.` service - the only
    /// service that accepts a first-time SRP pair-setup - which is advertised only while the
    /// Apple TV is actively showing a pairing PIN (Settings > Remotes and Devices > Remote App
    /// and Devices). `pin` is the 6-digit code shown on the Apple TV screen.
    /// The resulting pairing file is cached at `cache_dir/plume_<hostname>.plist`.
    ///
    /// Always contacts the device, even when a cached pairing file already exists: a cached
    /// file that still verifies produces a silent pair-verify with `pin_provider` never called,
    /// while a stale one (device reset, "Forget This Device", tvOS update) is transparently
    /// replaced by a real pair-setup. This is why calling this again is the correct way to
    /// recover from a pairing that `establish_tvos_tunnel` found to be stale.
    ///
    /// `pin_provider` is invoked only once the device has accepted the pair-setup request, which
    /// is the moment its PIN appears on screen. Taking a provider rather than a string is what
    /// lets a caller prompt for the code at that point: the code does not exist before then, and
    /// the device stops displaying it as soon as the session closes.
    pub async fn pair_tvos<F, Fut>(
        &self,
        pin_provider: F,
        cache_dir: PathBuf,
    ) -> Result<RpPairingFile, Error>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = String>,
    {
        let (ip, port) = self.pairing_address.ok_or_else(|| {
            Error::Other(
                "Device is not advertising the pairing service. On the Apple TV, open Settings \
                 > Remotes and Devices > Remote App and Devices and wait for \"Waiting to \
                 Pair...\", then scan again."
                    .to_string(),
            )
        })?;

        let cache_path = self.pairing_cache_path(&cache_dir)?;

        let addr = std::net::SocketAddr::new(ip, port);
        log::info!("tvOS pairing: connecting to {addr}");
        let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
            Error::Other(format!(
                "Failed to connect to Apple TV at {addr}: {e}. The manual-pairing port changes \
                 each time the Apple TV re-advertises, so a stale scan result will not connect - \
                 scan again immediately before pairing."
            ))
        })?;
        log::info!("tvOS pairing: TCP connected to {addr}, starting RPPairing handshake");

        let conn = RpPairingSocket::new(stream);

        // A cached pairing file is loaded (rather than always generating fresh) so that
        // `connect()` below can pair-verify against it: an already-valid pairing succeeds at
        // verification and never invokes the PIN provider at all, while a stale one (device
        // reset, "Forget This Device", tvOS update) falls through to a real pair-setup that
        // does invoke it. This is what makes pressing Pair on a healthy pairing silent.
        // `sending_host` is only a label: it travels as the `sendingHost`/`name` field and is what
        // the Apple TV lists this host as, while the pairing identity is the file's `identifier`
        // and its Ed25519 keys. A fresh pairing therefore uses a readable name, and
        // `RpPairingFile::generate` derives the identifier from it.
        let (mut pairing_file, sending_host) = if cache_path.exists() {
            let file = RpPairingFile::read_from_file(&cache_path).await?;
            let host = file.identifier.clone();
            (file, host)
        } else {
            let suffix: String = uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(6)
                .collect();
            let host = format!("plume-{suffix}");
            (RpPairingFile::generate(&host), host)
        };

        let mut pairing_client = RemotePairingClient::new(conn, &sending_host, &mut pairing_file);
        pairing_client
            .connect(
                move |_: u8| {
                    log::info!("tvOS pairing: device requested the PIN");
                    pin_provider()
                },
                0u8,
            )
            .await
            .map_err(|e| Error::Other(format!("RPPairing handshake failed: {e}")))?;
        log::info!("tvOS pairing: handshake succeeded, caching pairing file");

        tokio::fs::create_dir_all(&cache_dir).await?;
        pairing_file.write_to_file(&cache_path).await?;

        Ok(pairing_file)
    }

    /// Establish a TLS-PSK tunnel to an already-paired Apple TV and discover RSD services.
    /// This is the post-pairing step that gives access to InstallationProxy, AFC, etc.
    ///
    /// Verify-only: this pair-verifies against the cached pairing file and never performs a
    /// fresh SRP pair-setup, so it can never make the Apple TV display a pairing code - unlike
    /// `pair_tvos()`, which is the only place that may do that. If the cached pairing file is
    /// no longer valid (device factory reset, "Forget This Device", or a tvOS update that broke
    /// the pairing - the last of which the Apple TV routinely does after a system update), this
    /// call fails and deletes the stale cache file so the next `pair_tvos()` call re-pairs
    /// instead of hitting the same failure again.
    ///
    /// Prefers `reconnect_address` (`_remotepairing._tcp.local.`), which is what a paired
    /// device keeps advertising. Falls back to `pairing_address` if no reconnect address is
    /// known (e.g. installing immediately after pairing, in the same scan, before a reconnect
    /// address has been observed).
    pub async fn establish_tvos_tunnel(
        &self,
        cache_dir: PathBuf,
    ) -> Result<(AdapterHandle, RsdHandshake), Error> {
        let (ip, port) = self
            .reconnect_address
            .or(self.pairing_address)
            .ok_or_else(|| Error::Other("Device has no network address".to_string()))?;

        let connect_addr = std::net::SocketAddr::new(ip, port);

        // Load or generate pairing file
        let cache_path = self.pairing_cache_path(&cache_dir)?;
        let mut pairing_file = if cache_path.exists() {
            RpPairingFile::read_from_file(&cache_path).await?
        } else {
            let suffix: String = uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(6)
                .collect();
            RpPairingFile::generate(&format!("plume-{suffix}"))
        };

        // Connect via RPPairing binary protocol
        let stream = tokio::net::TcpStream::connect(connect_addr)
            .await
            .map_err(|e| {
                Error::Other(format!(
                    "Could not connect to Apple TV at {connect_addr}: {e}"
                ))
            })?;
        let conn = RpPairingSocket::new(stream);

        let hostname = pairing_file.identifier.clone();
        let tunnel = {
            let mut rpc = RemotePairingClient::new(conn, &hostname, &mut pairing_file);

            rpc.attempt_pair_verify()
                .await
                .map_err(|e| Error::Other(format!("Pair-verify failed: {e}")))?;

            if let Err(e) = rpc.validate_pairing().await {
                if cache_path.exists() {
                    log::warn!(
                        "tvOS tunnel: cached pairing file at {} no longer verifies ({e}); \
                         removing it",
                        cache_path.display()
                    );
                    let _ = tokio::fs::remove_file(&cache_path).await;
                }
                return Err(Error::Other(format!(
                    "This Apple TV no longer recognizes this pairing (it may have been reset, \
                     forgotten, or lost pairing after a system update); pair with it again: {e}"
                )));
            }

            let tunnel_port = rpc
                .create_tcp_listener()
                .await
                .map_err(|e| Error::Other(format!("Failed to create tunnel listener: {e}")))?;

            let tunnel_addr = std::net::SocketAddr::new(connect_addr.ip(), tunnel_port);
            let tunnel_stream = tokio::net::TcpStream::connect(tunnel_addr)
                .await
                .map_err(|e| Error::Other(format!("TLS tunnel connect failed: {e}")))?;

            connect_tls_psk_tunnel_native(Box::new(tunnel_stream), rpc.encryption_key())
                .await
                .map_err(|e| Error::Other(format!("TLS-PSK tunnel handshake failed: {e}")))?
        };

        // Cache pairing file now that rpc is dropped
        if !cache_path.exists() {
            tokio::fs::create_dir_all(&cache_dir).await?;
            pairing_file.write_to_file(&cache_path).await?;
        }

        let client_ip: std::net::IpAddr = tunnel
            .info
            .client_address
            .parse()
            .map_err(|e| Error::Other(format!("Invalid tunnel client address: {e}")))?;
        let server_ip: std::net::IpAddr = tunnel
            .info
            .server_address
            .parse()
            .map_err(|e| Error::Other(format!("Invalid tunnel server address: {e}")))?;
        let rsd_port = tunnel.info.server_rsd_port;
        let mtu = tunnel.info.mtu as usize;
        let mss = mtu.saturating_sub(60);
        log::info!("tvOS tunnel: negotiated MTU {mtu}, using MSS {mss}");

        let raw = tunnel.into_inner();
        let mut adapter = Adapter::new(Box::new(raw), client_ip, server_ip);
        // The tunnel's own handshake settles the MTU, and the software TCP stack sends one
        // segment per round trip, so the segment size sets the transfer rate outright. Left
        // unset it falls back to a 1280-byte-MTU default an order of magnitude below what the
        // tunnel carries.
        adapter.set_mss(mss);
        let mut adapter_handle = adapter.to_async_handle();

        let rsd_stream = adapter_handle
            .connect(rsd_port)
            .await
            .map_err(|e| Error::Other(format!("RSD connection failed: {e}")))?;
        let handshake = RsdHandshake::new(rsd_stream)
            .await
            .map_err(|e| Error::Other(format!("RSD handshake failed: {e}")))?;

        Ok((adapter_handle, handshake))
    }

    /// Whether a pairing file is already cached for this device under `cache_dir`. Lets a
    /// caller decide whether attempting `fetch_tvos_info` is worthwhile before doing so: a
    /// device that has never been paired has no pairing file to verify against, so a tunnel
    /// attempt would only fail, and callers that poll periodically (e.g. network device
    /// discovery) should treat that as "nothing to enrich yet" rather than a failure worth
    /// logging on every poll.
    pub fn has_cached_pairing_file(&self, cache_dir: &Path) -> bool {
        self.pairing_cache_path(cache_dir)
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    /// Read a network Apple TV's real identity (UDID, product type, OS version, etc.) over its
    /// tunnel's RSD handshake. mDNS never advertises these values, so this is the only way to
    /// learn a network device's actual UDID before registering it with Apple.
    /// The tunnel is torn down before returning; this call exists purely to enrich a `Device`,
    /// not to keep a connection open.
    ///
    /// Requires an existing cached pairing file and fails before touching the network if there
    /// is none. `establish_tvos_tunnel` is verify-only and would fail on a missing file anyway,
    /// but checking here first gives a specific, actionable error instead of a generic
    /// verification failure for what is meant to be a read-only identity probe.
    pub async fn fetch_tvos_info(&self, cache_dir: PathBuf) -> Result<TvosDeviceInfo, Error> {
        let cache_path = self.pairing_cache_path(&cache_dir)?;
        if !cache_path.exists() {
            return Err(Error::Other(
                "Device has no cached pairing file; fetch_tvos_info only reads an already \
                 paired device and will not initiate a new pairing"
                    .to_string(),
            ));
        }

        let (_adapter, handshake) = self.establish_tvos_tunnel(cache_dir).await?;
        Ok(TvosDeviceInfo::from_rsd_properties(&handshake.properties))
    }

    /// Copy the real UDID from a previously fetched `TvosDeviceInfo` into this device.
    /// A no-op unless `self.pairing_identity` is set, i.e. unless this is a network device:
    /// applying tvOS-sourced info to a USB device would silently overwrite its real usbmuxd
    /// UDID with an unrelated one. Leaves `self.udid` untouched when `info.udid` is `None` or
    /// empty, which keeps a device that has not yet been enriched (or whose RSD properties did
    /// not carry a UDID) from ever acquiring a fabricated identity. Does not touch
    /// `pairing_identity`, which stays keyed to the pairing file regardless of what the device
    /// turns out to be.
    pub fn apply_tvos_info(&mut self, info: &TvosDeviceInfo) {
        if self.pairing_identity.is_none() {
            return;
        }
        if let Some(udid) = info.udid.as_deref() {
            if !udid.is_empty() {
                self.udid = udid.to_string();
            }
        }
    }

    /// Install an app on this device, whether it is reachable over USB or over a network
    /// TLS-PSK tunnel. `app_path` may be a single file (e.g. a signed `.ipa`) or a directory
    /// (e.g. `package_file.bundle_dir()` from the standard signing pipeline) - both transports
    /// upload it via `idevice`'s installation helpers, which branch on `app_path` being a
    /// directory the same way for USB and network devices.
    pub async fn install_app<F, Fut>(
        &self,
        app_path: &PathBuf,
        progress_callback: F,
    ) -> Result<(), Error>
    where
        F: FnMut(i32) -> Fut + Send + Clone + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let callback = move |(progress, _): (u64, ())| {
            let mut cb = progress_callback.clone();
            async move {
                cb(progress as i32).await;
            }
        };
        let state = ();

        if self.usbmuxd_device.is_some() {
            let provider = self.usbmuxd_device.clone().unwrap().to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );

            installation::install_package_with_callback(&provider, app_path, None, callback, state)
                .await?;
        } else if self.pairing_address.is_some() || self.reconnect_address.is_some() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other(
                    "Network Apple TV has no pairing_cache_dir configured on this Device; \
                     install_app has nowhere to look for its pairing file"
                        .to_string(),
                )
            })?;

            // Checked up front rather than left to establish_tvos_tunnel: that call is
            // verify-only and would fail on a missing file regardless, but checking here first
            // gives a specific "pair before installing" error instead of a generic verification
            // failure surfacing from deep inside the tunnel handshake.
            let cache_path = self.pairing_cache_path(&cache_dir)?;
            if !cache_path.exists() {
                return Err(Error::Other(
                    "No pairing file is cached yet for this Apple TV; pair with it before \
                     installing"
                        .to_string(),
                ));
            }

            let (mut adapter, mut handshake) = self.establish_tvos_tunnel(cache_dir).await?;

            installation::install_package_with_callback_rsd(
                &mut adapter,
                &mut handshake,
                app_path,
                None,
                callback,
                state,
            )
            .await?;
        } else {
            return Err(Error::Other(
                "Device has no USB connection and no network address; cannot install".to_string(),
            ));
        }

        Ok(())
    }
}

fn get_app_name_from_info(info: &Value) -> Option<String> {
    let dict = info.as_dictionary()?;
    dict.get("CFBundleDisplayName")
        .and_then(|value| value.as_string())
        .or_else(|| dict.get("CFBundleName").and_then(|value| value.as_string()))
        .or_else(|| {
            dict.get("CFBundleExecutable")
                .and_then(|value| value.as_string())
        })
        .map(|value| value.to_string())
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let conn = if self.pairing_address.is_some() || self.reconnect_address.is_some() {
            "WiFi (tvOS)"
        } else {
            match &self.usbmuxd_device {
                Some(device) => match &device.connection_type {
                    Connection::Usb => "USB",
                    Connection::Network(_) => "WiFi",
                    Connection::Unknown(_) => "Unknown",
                },
                None => "LOCAL",
            }
        };
        write!(f, "[{conn}] {}", self.name)
    }
}

pub async fn get_device_for_id(device_id: &str) -> Result<Device, Error> {
    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let usbmuxd_device = usbmuxd
        .get_devices()
        .await?
        .into_iter()
        .find(|d| d.device_id.to_string() == device_id)
        .ok_or_else(|| Error::Other(format!("Device ID {device_id} not found")))?;

    Ok(Device::new(usbmuxd_device).await)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub async fn install_app_mac(app_path: &PathBuf) -> Result<(), Error> {
    use crate::copy_dir_recursively;
    use std::env;
    use tokio::fs;
    use uuid::Uuid;

    let stage_dir = env::temp_dir().join(format!(
        "plume_mac_stage_{}",
        Uuid::new_v4().to_string().to_uppercase()
    ));
    let app_name = app_path
        .file_name()
        .ok_or(Error::Other("Invalid app path".to_string()))?;

    // iOS Apps on macOS need to be wrapped in a special structure, more specifically
    // ```
    // LiveContainer.app
    // ├── WrappedBundle -> Wrapper/LiveContainer.app
    // └── Wrapper
    //     └── LiveContainer.app
    // ```
    // Then install to /Applications/...

    let outer_app_dir = stage_dir.join(app_name);
    let wrapper_dir = outer_app_dir.join("Wrapper");

    fs::create_dir_all(&wrapper_dir).await?;

    copy_dir_recursively(app_path, &wrapper_dir.join(app_name)).await?;

    let wrapped_bundle_path = outer_app_dir.join("WrappedBundle");
    fs::symlink(
        PathBuf::from("Wrapper").join(app_name),
        &wrapped_bundle_path,
    )
    .await?;

    let applications_dir = PathBuf::from("/Applications/iOS");
    fs::create_dir_all(&applications_dir).await?;

    let applications_dir = applications_dir.join(app_name);

    fs::remove_dir_all(&applications_dir).await.ok();

    fs::rename(&outer_app_dir, &applications_dir)
        .await
        .map_err(|_| Error::BundleFailedToCopy(applications_dir.to_string_lossy().into_owned()))?;

    Ok(())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub async fn install_app_mac(_app_path: &PathBuf) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Property map captured from a live Apple TV 4K (AppleTV14,1) RSD handshake, trimmed to
    /// the keys `TvosDeviceInfo` reads. The handshake carries 46 keys in total; only the ones
    /// relevant here are reproduced.
    fn real_rsd_properties() -> HashMap<String, plist::Value> {
        let mut props = HashMap::new();
        props.insert(
            "UniqueDeviceID".to_string(),
            plist::Value::String("00008110-001E60481AD9401E".to_string()),
        );
        props.insert(
            "ProductType".to_string(),
            plist::Value::String("AppleTV14,1".to_string()),
        );
        props.insert(
            "DeviceClass".to_string(),
            plist::Value::String("AppleTV".to_string()),
        );
        props.insert(
            "OSVersion".to_string(),
            plist::Value::String("26.5".to_string()),
        );
        props.insert(
            "HumanReadableProductVersionString".to_string(),
            plist::Value::String("26.5".to_string()),
        );
        props.insert(
            "SerialNumber".to_string(),
            plist::Value::String("C6FCY44V73".to_string()),
        );
        props.insert(
            "HWModel".to_string(),
            plist::Value::String("J255AP".to_string()),
        );
        props.insert(
            "ProductName".to_string(),
            plist::Value::String("Apple TVOS".to_string()),
        );
        props.insert(
            "BuildVersion".to_string(),
            plist::Value::String("23L471".to_string()),
        );
        props
    }

    #[test]
    fn from_rsd_properties_reads_real_device_fields() {
        let info = TvosDeviceInfo::from_rsd_properties(&real_rsd_properties());
        assert_eq!(info.udid.as_deref(), Some("00008110-001E60481AD9401E"));
        assert_eq!(info.product_type.as_deref(), Some("AppleTV14,1"));
        assert_eq!(info.device_class.as_deref(), Some("AppleTV"));
        assert_eq!(info.os_version.as_deref(), Some("26.5"));
        assert_eq!(info.serial_number.as_deref(), Some("C6FCY44V73"));
    }

    #[test]
    fn from_rsd_properties_empty_map_yields_default() {
        let info = TvosDeviceInfo::from_rsd_properties(&HashMap::new());
        assert_eq!(info, TvosDeviceInfo::default());
    }

    #[test]
    fn from_rsd_properties_non_string_value_yields_none() {
        let mut props = HashMap::new();
        props.insert(
            "UniqueDeviceID".to_string(),
            plist::Value::Integer(12345.into()),
        );

        let info = TvosDeviceInfo::from_rsd_properties(&props);
        assert_eq!(info.udid, None);
    }

    #[test]
    fn from_rsd_properties_falls_back_to_human_readable_version() {
        let mut props = HashMap::new();
        props.insert(
            "HumanReadableProductVersionString".to_string(),
            plist::Value::String("17.1".to_string()),
        );

        let info = TvosDeviceInfo::from_rsd_properties(&props);
        assert_eq!(info.os_version.as_deref(), Some("17.1"));
    }

    #[test]
    fn from_rsd_properties_prefers_os_version_over_human_readable_when_both_present() {
        let mut props = HashMap::new();
        props.insert(
            "OSVersion".to_string(),
            plist::Value::String("26.5".to_string()),
        );
        props.insert(
            "HumanReadableProductVersionString".to_string(),
            plist::Value::String("26.5 (23L471)".to_string()),
        );

        let info = TvosDeviceInfo::from_rsd_properties(&props);
        assert_eq!(info.os_version.as_deref(), Some("26.5"));
    }

    #[test]
    fn new_tvos_leaves_udid_empty_and_sets_pairing_identity() {
        let d = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            None,
            std::env::temp_dir(),
        );
        assert!(d.udid.is_empty());
        assert_eq!(d.pairing_identity.as_deref(), Some("Apple-TV"));
    }

    #[test]
    fn new_tvos_stores_pairing_cache_dir() {
        let cache_dir = std::env::temp_dir().join("plume_test_new_tvos_cache_dir");
        let d = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            None,
            cache_dir.clone(),
        );
        assert_eq!(d.pairing_cache_dir, Some(cache_dir));
    }

    /// Represents a USB device: keyed by `udid`, with no `pairing_identity`.
    fn stub_device() -> Device {
        Device {
            name: "Test Device".to_string(),
            udid: "EXISTING-UDID".to_string(),
            device_id: 0,
            usbmuxd_device: None,
            is_mac: false,
            pairing_address: None,
            reconnect_address: None,
            pairing_identity: None,
            pairing_cache_dir: None,
        }
    }

    /// Represents a network (tvOS) device: keyed by `pairing_identity`, same as what
    /// `Device::new_tvos` produces once an install has left a UDID on it via `apply_tvos_info`.
    fn stub_tvos_device() -> Device {
        let mut d = stub_device();
        d.pairing_identity = Some("stable-key".to_string());
        d
    }

    #[test]
    fn apply_tvos_info_none_udid_leaves_existing_udid_unchanged() {
        let mut device = stub_tvos_device();
        let info = TvosDeviceInfo {
            udid: None,
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "EXISTING-UDID");
    }

    #[test]
    fn apply_tvos_info_some_udid_overwrites_existing_udid() {
        let mut device = stub_tvos_device();
        let info = TvosDeviceInfo {
            udid: Some("REAL".to_string()),
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "REAL");
    }

    #[test]
    fn apply_tvos_info_empty_udid_leaves_existing_udid_unchanged() {
        let mut device = stub_tvos_device();
        let info = TvosDeviceInfo {
            udid: Some(String::new()),
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "EXISTING-UDID");
    }

    #[test]
    fn apply_tvos_info_no_op_when_device_has_no_pairing_identity() {
        let mut device = stub_device();
        let info = TvosDeviceInfo {
            udid: Some("SHOULD-NOT-APPLY".to_string()),
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "EXISTING-UDID");
    }

    #[test]
    fn is_tvos_true_for_network_paired_device() {
        let device = stub_tvos_device();
        assert!(device.is_tvos());
    }

    #[test]
    fn is_tvos_false_for_usb_device() {
        let device = stub_device();
        assert!(!device.is_tvos());
    }

    #[test]
    fn new_tvos_device_reports_is_tvos() {
        let d = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            None,
            std::env::temp_dir(),
        );
        assert!(d.is_tvos());
    }

    #[test]
    fn pairing_cache_path_prefers_pairing_identity_over_udid() {
        let device = stub_tvos_device();
        let cache_dir = Path::new("/cache");
        assert_eq!(
            device.pairing_cache_path(cache_dir).unwrap(),
            cache_dir.join("plume_stable-key.plist")
        );
    }

    #[test]
    fn pairing_cache_path_falls_back_to_udid_when_no_pairing_identity() {
        let device = stub_device();
        let cache_dir = Path::new("/cache");
        assert_eq!(
            device.pairing_cache_path(cache_dir).unwrap(),
            cache_dir.join("plume_EXISTING-UDID.plist")
        );
    }

    #[test]
    fn pairing_cache_path_rejects_empty_key() {
        let mut device = stub_device();
        device.udid = String::new();
        let cache_dir = Path::new("/cache");
        assert!(device.pairing_cache_path(cache_dir).is_err());
    }

    #[test]
    fn pairing_cache_path_rejects_dots_only_key() {
        let mut device = stub_device();
        device.pairing_identity = Some("..".to_string());
        let cache_dir = Path::new("/cache");
        assert!(device.pairing_cache_path(cache_dir).is_err());
    }

    #[test]
    fn pairing_cache_path_rejects_key_with_path_separator() {
        let mut device = stub_device();
        device.pairing_identity = Some("../evil".to_string());
        let cache_dir = Path::new("/cache");
        assert!(device.pairing_cache_path(cache_dir).is_err());
    }

    /// Unique scratch directory under the system temp dir, not created on disk by this helper.
    fn unique_temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "plume_test_{tag}_{}",
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn has_cached_pairing_file_reports_presence_and_absence() {
        let cache_dir = unique_temp_dir("has_cached_pairing_file");
        std::fs::create_dir_all(&cache_dir).expect("create scratch cache dir");

        let mut device = stub_tvos_device();
        device.pairing_identity = Some("has-cache-test".to_string());

        assert!(!device.has_cached_pairing_file(&cache_dir));

        let cache_path = device.pairing_cache_path(&cache_dir).unwrap();
        std::fs::write(&cache_path, b"stub").unwrap();

        assert!(device.has_cached_pairing_file(&cache_dir));

        std::fs::remove_dir_all(&cache_dir).ok();
    }

    /// `is_network` decides whether an install pays to be archived first, so it has to agree with
    /// the transport `install_app` actually selects rather than merely with "is this an Apple TV".
    #[test]
    fn is_network_follows_the_transport_install_app_picks() {
        let mut device = stub_device();
        assert!(
            !device.is_network(),
            "a device with no transport at all is not a network device"
        );

        device.reconnect_address =
            Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49151));
        assert!(device.is_network(), "a reconnect address makes it network");

        device.reconnect_address = None;
        device.pairing_address = Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49152));
        assert!(device.is_network(), "a pairing address makes it network");

        let mut mac = stub_device();
        mac.is_mac = true;
        assert!(
            !mac.is_network(),
            "the local Mac is not reached over a tunnel"
        );
    }

    async fn noop_callback(_progress: i32) {}

    #[tokio::test]
    async fn install_app_with_no_transport_names_the_missing_transport() {
        // No usbmuxd device, no pairing_address, no reconnect_address.
        let device = stub_device();

        let err = device
            .install_app(&PathBuf::from("nonexistent.ipa"), noop_callback)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("no USB connection") && msg.contains("no network address"),
            "expected a message naming both missing transports, got: {msg}"
        );
    }

    #[tokio::test]
    async fn install_app_network_device_without_cache_dir_returns_distinct_error() {
        let mut device = stub_device();
        device.reconnect_address =
            Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49151));
        assert!(device.pairing_cache_dir.is_none());

        let err = device
            .install_app(&PathBuf::from("nonexistent.ipa"), noop_callback)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("pairing_cache_dir"),
            "expected the missing-cache-dir error, got: {msg}"
        );
        // Distinct from both the no-transport error and the no-pairing-file error below.
        assert!(!msg.contains("no USB connection"));
        assert!(!msg.contains("No pairing file is cached"));
    }

    #[tokio::test]
    async fn install_app_network_device_with_no_pairing_file_errors_before_tunnel() {
        let cache_dir = unique_temp_dir("no_pairing_file");
        std::fs::create_dir_all(&cache_dir).expect("create scratch cache dir");

        let mut device = stub_device();
        device.reconnect_address =
            Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49151));
        device.pairing_cache_dir = Some(cache_dir.clone());
        // stub_device()'s udid is non-empty, so pairing_cache_path resolves under cache_dir,
        // which is empty here - no pairing file exists there.

        let err = device
            .install_app(&PathBuf::from("nonexistent.ipa"), noop_callback)
            .await
            .unwrap_err();

        let msg = err.to_string();
        // This is what actually catches the guard being deleted: install_app's own
        // "no cached pairing file" check must fire before establish_tvos_tunnel runs at all.
        assert!(
            msg.contains("No pairing file is cached"),
            "expected the missing-pairing-file error, got: {msg}"
        );
        assert!(!msg.contains("pairing_cache_dir"));

        std::fs::remove_dir_all(&cache_dir).ok();
    }

    /// A large, cheap-to-generate corpus of distinct identities, so the invariants below are
    /// checked across a broad slice of the hash's output space rather than a handful of
    /// hand-picked strings.
    fn generated_identities(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("dev-{i}")).collect()
    }

    #[test]
    fn synthetic_device_id_is_deterministic() {
        for name in generated_identities(100_000) {
            assert_eq!(synthetic_device_id(&name), synthetic_device_id(&name));
        }
    }

    #[test]
    fn synthetic_device_id_never_zero_or_u32_max() {
        for name in generated_identities(100_000) {
            let id = synthetic_device_id(&name);
            assert_ne!(id, 0, "input {name:?} produced 0");
            assert_ne!(id, u32::MAX, "input {name:?} produced u32::MAX");
        }

        // Edge cases the generated sweep above does not naturally produce.
        for input in ["", &"x".repeat(500)] {
            let id = synthetic_device_id(input);
            assert_ne!(id, 0, "input {input:?} produced 0");
            assert_ne!(id, u32::MAX, "input {input:?} produced u32::MAX");
        }
    }

    #[test]
    fn synthetic_device_id_top_bit_always_set() {
        let inputs = [
            "",
            "a",
            "Living-Room",
            "Bedroom",
            "Apple-TV",
            "Office",
            &"z".repeat(200),
        ];
        for input in inputs {
            let id = synthetic_device_id(input);
            assert_eq!(
                id & 0x8000_0000,
                0x8000_0000,
                "input {input:?} did not have the top bit set"
            );
        }
    }

    #[test]
    fn synthetic_device_id_distinct_for_realistic_names() {
        let names = ["Living-Room", "Bedroom", "Apple-TV", "Office"];
        let ids: Vec<u32> = names.iter().map(|n| synthetic_device_id(n)).collect();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(
                    ids[i], ids[j],
                    "{:?} and {:?} produced the same id",
                    names[i], names[j]
                );
            }
        }
    }

    #[test]
    fn synthetic_device_id_known_value_regression() {
        assert_eq!(synthetic_device_id("Living-Room"), 0xe3eb1b88);
    }

    #[tokio::test]
    async fn establish_tvos_tunnel_takes_no_pin_argument() {
        // Compile-level check that the tunnel path is verify-only and takes no PIN: a device
        // with neither pairing_address nor reconnect_address fails on the address lookup before
        // any I/O, which both proves the one-argument signature and keeps this test hardware-free.
        let device = stub_device();
        let err = device
            .establish_tvos_tunnel(std::env::temp_dir())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no network address"));
    }
}
