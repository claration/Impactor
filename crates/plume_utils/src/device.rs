use std::fmt;
use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use idevice::core_device_proxy::CoreDeviceProxy;
use idevice::installation_proxy::InstallationProxyClient;
use idevice::lockdown::LockdownClient;
use idevice::misagent::MisagentClient;
use idevice::provider::UsbmuxdProvider;
use idevice::remote_pairing::{
    connect_tls_psk_tunnel_native, RemotePairingClient, RpPairingFile, RpPairingSocket,
    RpPairingSocketProvider,
};
use idevice::remote_pairing::errors::RemotePairingError;
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
use idevice::usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdDevice};
use idevice::utils::installation;
use idevice::{IdeviceService, RemoteXpcClient, RsdService};
use plume_core::{MobileProvision, developer::DeveloperPlatform};

use crate::Error;
use crate::discovery::{DeviceDiscovery, DeviceType, PlatformDiscovery, REMOTEPAIRING_SERVICE};
use crate::options::SignerAppReal;
use crate::pairing::{PairingBackend, PairingFailure, PairingStage, ensure_pairing};
use idevice::afc::opcode::AfcFopenMode;
use idevice::house_arrest::HouseArrestClient;
use idevice::usbmuxd::UsbmuxdConnection;
use plist::Value;
use serde::Serialize;

pub const CONNECTION_LABEL: &str = "plume_info";
pub const INSTALLATION_LABEL: &str = "plume_install";
pub const HOUSE_ARREST_LABEL: &str = "plume_house_arrest";

impl<'a, R: idevice::remote_pairing::RpPairingSocketProvider> PairingBackend
    for RemotePairingClient<'a, R>
{
    async fn verify(&mut self) -> Result<(), PairingFailure> {
        self.attempt_pair_verify()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))?;
        self.validate_pairing()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))
    }

    async fn pair(&mut self, pin: &str) -> Result<(), PairingFailure> {
        let pin = pin.to_string();
        RemotePairingClient::connect(
            self,
            |_| {
                let pin = pin.clone();
                async move { pin }
            },
            (),
        )
        .await
        .map_err(|error| match error {
            idevice::IdeviceError::RemotePairing(RemotePairingError::SrpAuthFailed) => {
                PairingFailure::WrongPin
            }
            error => PairingFailure::Protocol(error.to_string()),
        })
    }
}

#[derive(Debug)]
struct SequencedTvosPairingSocket {
    inner: RpPairingSocket<tokio::net::TcpStream>,
    sequence_offset: usize,
}

impl SequencedTvosPairingSocket {
    fn new(inner: RpPairingSocket<tokio::net::TcpStream>, sequence_offset: usize) -> Self {
        Self {
            inner,
            sequence_offset,
        }
    }
}

impl RpPairingSocketProvider for SequencedTvosPairingSocket {
    fn send_plain(
        &mut self,
        value: impl Serialize,
        seq: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), idevice::IdeviceError>> + Send + '_>> {
        self.inner.send_plain(value, seq + self.sequence_offset)
    }

    fn send_encrypted(
        &mut self,
        ciphertext: Vec<u8>,
        seq: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), idevice::IdeviceError>> + Send + '_>> {
        self.inner
            .send_encrypted(ciphertext, seq + self.sequence_offset)
    }

    fn recv_plain<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<plist::Value, idevice::IdeviceError>> + Send + 'a>> {
        self.inner.recv_plain()
    }

    fn serialize_bytes(b: &[u8]) -> plist::Value {
        RpPairingSocket::<tokio::net::TcpStream>::serialize_bytes(b)
    }

    fn deserialize_bytes(v: plist::Value) -> Option<Vec<u8>> {
        RpPairingSocket::<tokio::net::TcpStream>::deserialize_bytes(v)
    }
}

struct TvosPairingBackend<'a> {
    client: RemotePairingClient<'a, SequencedTvosPairingSocket>,
}

impl<'a> PairingBackend for TvosPairingBackend<'a> {
    async fn verify(&mut self) -> Result<(), PairingFailure> {
        self.client
            .attempt_pair_verify()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))?;
        self.client
            .validate_pairing()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))
    }

    async fn pair(&mut self, pin: &str) -> Result<(), PairingFailure> {
        let pin = pin.to_string();
        RemotePairingClient::pair(
            &mut self.client,
            |_| {
                let pin = pin.clone();
                async move { pin }
            },
            (),
        )
        .await
        .map_err(|error| match error {
            idevice::IdeviceError::RemotePairing(RemotePairingError::SrpAuthFailed) => {
                PairingFailure::WrongPin
            }
            error => PairingFailure::Protocol(error.to_string()),
        })
    }
}

const TVOS_RP_PAIRING_WIRE_PROTOCOL_VERSION: i64 = 26;

async fn begin_tvos_pairing(
    stream: tokio::net::TcpStream,
) -> Result<SequencedTvosPairingSocket, Error> {
    let correlation_identifier: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(6)
        .collect();
    let mut socket = RpPairingSocket::new(stream);
    socket
        .send_plain(tvos_pairing_handshake_request(&correlation_identifier), 0)
        .await?;
    let response = socket.recv_plain().await?;
    if !tvos_pairing_handshake_allows_pair_setup(&response) {
        return Err(Error::Other(
            "Apple TV did not advertise support for manual pairing".to_string(),
        ));
    }
    Ok(SequencedTvosPairingSocket::new(socket, 1))
}

fn tvos_pairing_handshake_request(correlation_identifier: &str) -> Value {
    let mut host_options = plist::Dictionary::new();
    host_options.insert("attemptPairVerify".to_string(), Value::Boolean(false));

    let mut correlation = plist::Dictionary::new();
    correlation.insert(
        "value".to_string(),
        Value::String(correlation_identifier.to_string()),
    );

    let mut handshake = plist::Dictionary::new();
    handshake.insert("hostOptions".to_string(), Value::Dictionary(host_options));
    handshake.insert(
        "correlationIdentifier".to_string(),
        Value::Dictionary(correlation),
    );
    handshake.insert(
        "wireProtocolVersion".to_string(),
        Value::Integer(TVOS_RP_PAIRING_WIRE_PROTOCOL_VERSION.into()),
    );

    let mut handshake_container = plist::Dictionary::new();
    handshake_container.insert("_0".to_string(), Value::Dictionary(handshake));

    let mut request = plist::Dictionary::new();
    request.insert(
        "handshake".to_string(),
        Value::Dictionary(handshake_container),
    );

    let mut request_container = plist::Dictionary::new();
    request_container.insert("_0".to_string(), Value::Dictionary(request));

    let mut root = plist::Dictionary::new();
    root.insert("request".to_string(), Value::Dictionary(request_container));
    Value::Dictionary(root)
}

fn tvos_pairing_handshake_allows_pair_setup(response: &Value) -> bool {
    response
        .as_dictionary()
        .and_then(|value| value.get("response"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("_1"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("handshake"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("_0"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("deviceOptions"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("allowsPairSetup"))
        .and_then(Value::as_boolean)
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTransport {
    Usbmuxd,
    RemotePairing,
    CoreDevice,
    LocalMac,
    Unavailable,
}

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
    pub product_type: Option<String>,
    pub device_class: Option<String>,
    pub os_version: Option<String>,
    pub serial_number: Option<String>,
    pub device_id: u32,
    pub usbmuxd_device: Option<UsbmuxdDevice>,
    // On x86_64 macs, `is_mac` variable should never be true
    // since its only true if the device is added manually.
    pub is_mac: bool,
    pub pairing_address: Option<(std::net::IpAddr, u16)>,
    pub reconnect_address: Option<(std::net::IpAddr, u16)>,
    pub pairing_identity: Option<String>,
    pub pairing_cache_dir: Option<PathBuf>,
    pub core_device_authenticated: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TvosDeviceInfo {
    pub name: Option<String>,
    pub udid: Option<String>,
    pub product_type: Option<String>,
    pub device_class: Option<String>,
    pub os_version: Option<String>,
    pub serial_number: Option<String>,
}

impl TvosDeviceInfo {
    pub fn from_rsd_properties(props: &std::collections::HashMap<String, plist::Value>) -> Self {
        let as_string = |key: &str| -> Option<String> {
            props
                .get(key)
                .and_then(|v| v.as_string())
                .map(str::to_string)
        };

        TvosDeviceInfo {
            name: as_string("DeviceName").or_else(|| as_string("Name")),
            udid: as_string("UniqueDeviceID"),
            product_type: as_string("ProductType"),
            device_class: as_string("DeviceClass"),
            os_version: as_string("OSVersion")
                .or_else(|| as_string("HumanReadableProductVersionString")),
            serial_number: as_string("SerialNumber"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreDeviceTransport {
    pairing_address: Option<(std::net::IpAddr, u16)>,
    reconnect_address: Option<(std::net::IpAddr, u16)>,
    pairing_identity: Option<String>,
    udid: String,
    cache_dir: PathBuf,
    authenticated: bool,
}

impl CoreDeviceTransport {
    fn new(device: &Device, cache_dir: PathBuf) -> Result<Self, Error> {
        if device.usbmuxd_device.is_some() {
            return Err(Error::Other(
                "CoreDevice transport cannot wrap a usbmuxd device".to_string(),
            ));
        }
        Ok(Self {
            pairing_address: device.pairing_address,
            reconnect_address: device.reconnect_address,
            pairing_identity: device.pairing_identity.clone(),
            udid: device.udid.clone(),
            cache_dir,
            authenticated: device.core_device_authenticated,
        })
    }

    pub fn kind(&self) -> DeviceTransport {
        if self.authenticated {
            DeviceTransport::CoreDevice
        } else if self.pairing_address.is_some() || self.reconnect_address.is_some() {
            DeviceTransport::RemotePairing
        } else {
            DeviceTransport::Unavailable
        }
    }

    pub async fn connect(&self) -> Result<(AdapterHandle, RsdHandshake), Error> {
        establish_core_device_tunnel(
            self.pairing_address,
            self.reconnect_address,
            self.pairing_identity.as_deref(),
            &self.udid,
            &self.cache_dir,
        )
        .await
    }
}

pub fn synthetic_device_id(pairing_identity: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in pairing_identity.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash |= 0x8000_0000;

    if hash == u32::MAX {
        hash = 0x8000_0000;
    }

    hash
}

impl Device {
    pub async fn new(usbmuxd_device: UsbmuxdDevice) -> Self {
        let values = Self::get_values_from_usbmuxd_device(&usbmuxd_device)
            .await
            .ok();
        let name = values
            .as_ref()
            .map(|values| get_dict_string!(values, "DeviceName"))
            .unwrap_or_default();
        let product_type = values
            .as_ref()
            .map(|values| get_dict_string!(values, "ProductType"))
            .filter(|value| !value.is_empty());
        let device_class = values
            .as_ref()
            .map(|values| get_dict_string!(values, "DeviceClass"))
            .filter(|value| !value.is_empty());
        let os_version = values
            .as_ref()
            .map(|values| get_dict_string!(values, "ProductVersion"))
            .filter(|value| !value.is_empty());
        let serial_number = values
            .as_ref()
            .map(|values| get_dict_string!(values, "SerialNumber"))
            .filter(|value| !value.is_empty());

        Device {
            name,
            udid: usbmuxd_device.udid.clone(),
            product_type,
            device_class,
            os_version,
            serial_number,
            device_id: usbmuxd_device.device_id.clone(),
            usbmuxd_device: Some(usbmuxd_device),
            is_mac: false,
            pairing_address: None,
            reconnect_address: None,
            pairing_identity: None,
            pairing_cache_dir: None,
            core_device_authenticated: false,
        }
    }

    async fn get_values_from_usbmuxd_device(
        device: &UsbmuxdDevice,
    ) -> Result<Value, Error> {
        let mut lockdown =
            LockdownClient::connect(&device.to_provider(UsbmuxdAddr::default(), CONNECTION_LABEL))
                .await?;
        Ok(lockdown.get_value(None, None).await?)
    }

    pub fn new_tvos(
        name: String,
        pairing_identity: String,
        ip: std::net::IpAddr,
        pairing_port: Option<u16>,
        reconnect_port: Option<u16>,
        cache_dir: PathBuf,
    ) -> Self {
        Self::new_tvos_with_addresses(
            name,
            pairing_identity,
            pairing_port.map(|port| (ip, port)),
            reconnect_port.map(|port| (ip, port)),
            cache_dir,
        )
    }

    pub fn new_tvos_with_addresses(
        name: String,
        pairing_identity: String,
        pairing_address: Option<(std::net::IpAddr, u16)>,
        reconnect_address: Option<(std::net::IpAddr, u16)>,
        cache_dir: PathBuf,
    ) -> Self {
        Device {
            name,
            udid: String::new(),
            product_type: None,
            device_class: Some("AppleTV".to_string()),
            os_version: None,
            serial_number: None,
            device_id: 0,
            usbmuxd_device: None,
            is_mac: false,
            pairing_address,
            reconnect_address,
            pairing_identity: Some(pairing_identity),
            pairing_cache_dir: Some(cache_dir),
            core_device_authenticated: false,
        }
    }

    pub(crate) fn pairing_cache_path(&self, cache_dir: &Path) -> Result<PathBuf, Error> {
        pairing_cache_path_for(self.pairing_identity.as_deref(), &self.udid, cache_dir)
    }

    pub fn is_tvos(&self) -> bool {
        self.developer_platform() == DeveloperPlatform::Tvos
    }

    pub fn developer_platform(&self) -> DeveloperPlatform {
        DeveloperPlatform::from_device_metadata(
            self.product_type.as_deref(),
            self.device_class.as_deref(),
            self.is_network() || self.pairing_identity.is_some(),
        )
    }

    pub fn is_network(&self) -> bool {
        matches!(
            self.transport(),
            DeviceTransport::RemotePairing | DeviceTransport::CoreDevice
        )
    }

    pub fn transport(&self) -> DeviceTransport {
        if self.usbmuxd_device.is_some() {
            DeviceTransport::Usbmuxd
        } else if self.core_device_authenticated {
            DeviceTransport::CoreDevice
        } else if self.pairing_address.is_some() || self.reconnect_address.is_some() {
            DeviceTransport::RemotePairing
        } else if self.is_mac {
            DeviceTransport::LocalMac
        } else {
            DeviceTransport::Unavailable
        }
    }

    pub fn core_device_transport(
        &self,
        cache_dir: PathBuf,
    ) -> Result<CoreDeviceTransport, Error> {
        CoreDeviceTransport::new(self, cache_dir)
    }

    pub async fn installed_apps(&self) -> Result<Vec<SignerAppReal>, Error> {
        let apps = if let Some(device) = &self.usbmuxd_device {
            let provider = device.to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );
            let mut ic = InstallationProxyClient::connect(&provider).await?;
            ic.get_apps(Some("User"), None).await?
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other("Network Apple TV has no pairing cache directory".to_string())
            })?;
            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;
            let mut ic = InstallationProxyClient::connect_rsd(&mut adapter, &mut handshake).await?;
            ic.get_apps(Some("User"), None).await?
        } else {
            return Err(Error::Other("Device has no installation transport".to_string()));
        };

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
        let apps = if let Some(device) = &self.usbmuxd_device {
            let provider = device.to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );
            let mut ic = InstallationProxyClient::connect(&provider).await?;
            ic.get_apps(Some("User"), None).await?
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other("Network Apple TV has no pairing cache directory".to_string())
            })?;
            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;
            let mut ic = InstallationProxyClient::connect_rsd(&mut adapter, &mut handshake).await?;
            ic.get_apps(Some("User"), None).await?
        } else {
            return Err(Error::Other("Device has no installation transport".to_string()));
        };

        Ok(apps.contains_key(bundle_id))
    }

    pub async fn install_profile(&self, profile: &MobileProvision) -> Result<(), Error> {
        if let Some(device) = &self.usbmuxd_device {
            let provider = device.to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );
            let mut mc = MisagentClient::connect(&provider).await?;
            mc.install(profile.data.clone()).await?;
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other("Network Apple TV has no pairing cache directory".to_string())
            })?;
            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;
            let mut mc = MisagentClient::connect_rsd(&mut adapter, &mut handshake).await?;
            mc.install(profile.data.clone()).await?;
        } else {
            return Err(Error::Other("Device has no installation transport".to_string()));
        }

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

            write_pairing_file(&pairing_file, &path, &pairing_file_path).await?;

            Ok(pairing_file)
        }
    }

    async fn try_import_external_pairing(
        &self,
        cache_dir: &Path,
        cache_path: &Path,
    ) -> Result<Option<RpPairingFile>, Error> {
        try_import_external_pairing_at(
            self.reconnect_address.or(self.pairing_address),
            cache_dir,
            cache_path,
        )
        .await
    }

    pub async fn pair_tvos<F, Fut>(
        &mut self,
        pin_provider: F,
        cache_dir: PathBuf,
    ) -> Result<RpPairingFile, Error>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = String>,
    {
        let cache_path = self.pairing_cache_path(&cache_dir)?;

        let cached_pairing_file = if cache_path.exists() {
            match RpPairingFile::read_from_file(&cache_path).await {
                Ok(pairing_file) => Some(pairing_file),
                Err(error) => {
                    log::warn!(
                        "Removing unreadable Apple TV pairing record at {}: {error}",
                        cache_path.display()
                    );
                    let _ = tokio::fs::remove_file(&cache_path).await;
                    None
                }
            }
        } else {
            None
        };

        if cached_pairing_file.is_none() {
            if let Some(pairing_file) =
                self.try_import_external_pairing(&cache_dir, &cache_path).await?
            {
                return self.finish_tvos_pairing(pairing_file).await;
            }
        }

        let action = pairing_action(
            cached_pairing_file.is_some(),
            self.pairing_address.is_some(),
            self.reconnect_address.is_some(),
        )
        .map_err(Error::Other)?;

        if action == PairingAction::Reconnect {
            let (ip, port) = self
                .reconnect_address
                .or(self.pairing_address)
                .expect("pairing_action guarantees an address");
            let addr = std::net::SocketAddr::new(ip, port);
            log::info!("tvOS pairing: reconnecting to {addr}");
            let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
                Error::Other(format!(
                    "Failed to reconnect to Apple TV at {addr}: {e}; scan again if the device changed its advertised address"
                ))
            })?;
            let mut pairing_file = cached_pairing_file
                .expect("pairing_action selected reconnect with a cached pairing file");
            let sending_host = pairing_file.identifier.clone();
            let mut pairing_client =
                RemotePairingClient::new(RpPairingSocket::new(stream), &sending_host, &mut pairing_file);

            let reconnect_result = match pairing_client.attempt_pair_verify().await {
                Ok(_) => pairing_client.validate_pairing().await,
                Err(error) => Err(error),
            };
            drop(pairing_client);

            if reconnect_result.is_ok() {
                write_pairing_file(&pairing_file, &cache_dir, &cache_path).await?;
                log::info!("tvOS pairing: cached record reconnected without a PIN");
                return self.finish_tvos_pairing(pairing_file).await;
            }

            if cache_path.exists() {
                log::warn!(
                    "Cached Apple TV pairing record at {} is stale; removing it",
                    cache_path.display()
                );
                let _ = tokio::fs::remove_file(&cache_path).await;
            }
            if let Some(pairing_file) =
                self.try_import_external_pairing(&cache_dir, &cache_path).await?
            {
                log::info!("tvOS pairing: recovered an existing native pairing record");
                return self.finish_tvos_pairing(pairing_file).await;
            }
        }

        {
            let (ip, port) = self.pairing_address.ok_or_else(|| {
                Error::Other(
                    "Apple TV pairing requires its manual-pairing service. On the Apple TV, open Settings \
                     > Remotes and Devices > Remote App and Devices and wait for \"Waiting to Pair...\", \
                     then scan again."
                        .to_string(),
                )
            })?;

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

            let local_hostname = local_remote_pairing_hostname().ok_or_else(|| {
                Error::Other("Could not determine the host name for Apple TV pairing".to_string())
            })?;
            let mut pairing_file = RpPairingFile::generate(&local_hostname);
            let conn = begin_tvos_pairing(stream).await?;
            let pairing_client =
                RemotePairingClient::new(conn, &local_hostname, &mut pairing_file);
            let mut pairing_backend = TvosPairingBackend {
                client: pairing_client,
            };
            let stage = ensure_pairing(
                &mut pairing_backend,
                false,
                true,
                false,
                pin_provider,
            )
            .await
            .map_err(pairing_failure_to_error)?;
            if stage != PairingStage::Paired {
                return Err(Error::Other(
                    "Apple TV pairing did not complete a new pairing".to_string(),
                ));
            }
            log::info!("tvOS pairing: handshake succeeded, caching pairing file");

            write_pairing_file(&pairing_file, &cache_dir, &cache_path).await?;

            self.finish_tvos_pairing(pairing_file).await
        }
    }

    async fn finish_tvos_pairing(
        &mut self,
        pairing_file: RpPairingFile,
    ) -> Result<RpPairingFile, Error> {
        self.refresh_tvos_reconnect_address(Duration::from_secs(5))
            .await?;
        Ok(pairing_file)
    }

    pub async fn refresh_tvos_reconnect_address(
        &mut self,
        timeout: Duration,
    ) -> Result<(), Error> {
        let pairing_identity = self
            .pairing_identity
            .as_deref()
            .filter(|identity| !identity.is_empty())
            .map(str::to_ascii_lowercase);
        let known_ip = self
            .pairing_address
            .or(self.reconnect_address)
            .map(|(ip, _)| ip);

        let discovered = PlatformDiscovery::new().discover(timeout).await?;
        let candidate = discovered
            .into_iter()
            .filter(|device| {
                device.device_type == DeviceType::AppleTV
                    && device.service_type == REMOTEPAIRING_SERVICE
            })
            .filter_map(|device| {
                let ip = device.ip_address.as_deref()?.parse().ok()?;
                let port = device.port?;
                let same_ip = known_ip == Some(ip);
                let same_identity = pairing_identity.as_deref().is_some_and(|identity| {
                    device.hostname.eq_ignore_ascii_case(identity)
                        || device.name.eq_ignore_ascii_case(identity)
                });
                let same_name = !self.name.is_empty()
                    && device.name.eq_ignore_ascii_case(&self.name);
                if !(same_ip || same_identity || same_name) {
                    return None;
                }
                Some(((same_ip, same_identity, same_name), (ip, port)))
            })
            .max_by_key(|(matches, _)| *matches)
            .map(|(_, address)| address);

        if let Some(address) = candidate {
            self.reconnect_address = Some(address);
            log::info!(
                "tvOS pairing: using verified reconnect service at {}:{}",
                address.0,
                address.1
            );
            return Ok(());
        }

        Err(Error::Other(
            "Apple TV pairing succeeded, but its verified _remotepairing._tcp service was not found; scan again and retry"
                .to_string(),
        ))
    }

    pub async fn establish_tvos_tunnel(
        &self,
        cache_dir: PathBuf,
    ) -> Result<(AdapterHandle, RsdHandshake), Error> {
        self.core_device_transport(cache_dir)?.connect().await
    }

    pub fn has_cached_pairing_file(&self, cache_dir: &Path) -> bool {
        self.pairing_cache_path(cache_dir)
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    pub fn has_pairing_source(&self, cache_dir: &Path) -> bool {
        if self.has_cached_pairing_file(cache_dir) {
            return true;
        }

        #[cfg(target_os = "macos")]
        {
            return self.has_native_tvos_pairing();
        }

        #[cfg(not(target_os = "macos"))]
        false
    }

    pub async fn forget_tvos_pairing(&self, cache_dir: PathBuf) -> Result<(), Error> {
        let path = self.pairing_cache_path(&cache_dir)?;

        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn fetch_tvos_info(&self, cache_dir: PathBuf) -> Result<TvosDeviceInfo, Error> {
        let (_adapter, handshake) = self.establish_tvos_tunnel(cache_dir).await?;
        Ok(TvosDeviceInfo::from_rsd_properties(&handshake.properties))
    }

    #[cfg(target_os = "macos")]
    fn has_native_tvos_pairing(&self) -> bool {
        let expected_name = self.name.to_ascii_lowercase();
        let expected_product_type = self
            .product_type
            .as_deref()
            .map(str::to_ascii_lowercase);

        for host_path in external_pairing_paths() {
            let Some(peers_path) = host_path.parent().map(|path| path.join("peers")) else {
                continue;
            };
            let Ok(entries) = std::fs::read_dir(peers_path) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("plist") {
                    continue;
                }
                let Ok(bytes) = std::fs::read(path) else {
                    continue;
                };
                let Ok(peer) = plist::from_bytes::<plist::Dictionary>(&bytes) else {
                    continue;
                };
                let model = peer
                    .get("model")
                    .and_then(Value::as_string)
                    .map(str::to_ascii_lowercase);
                let name = peer
                    .get("name")
                    .and_then(Value::as_string)
                    .map(str::to_ascii_lowercase);
                let model_matches = model.as_deref().is_some_and(|model| {
                    model.starts_with("appletv")
                        && expected_product_type
                            .as_deref()
                            .is_none_or(|expected| expected == model)
                });
                let name_matches = name.as_deref() == Some(expected_name.as_str());
                if model_matches && name_matches {
                    return true;
                }
            }
        }

        false
    }

    pub fn apply_tvos_info(&mut self, info: &TvosDeviceInfo) {
        if self.pairing_identity.is_none() {
            return;
        }
        if let Some(name) = info.name.as_deref().filter(|value| !value.is_empty()) {
            self.name = name.to_string();
        }
        if let Some(udid) = info.udid.as_deref() {
            if crate::is_valid_device_udid(udid) {
                self.udid = udid.to_string();
            }
        }
        if info.product_type.is_some() {
            self.product_type = info.product_type.clone();
        }
        if info.device_class.is_some() {
            self.device_class = info.device_class.clone();
        }
        if info.os_version.is_some() {
            self.os_version = info.os_version.clone();
        }
        if info.serial_number.is_some() {
            self.serial_number = info.serial_number.clone();
        }
        if info.udid.as_deref().is_some_and(crate::is_valid_device_udid) {
            self.core_device_authenticated = true;
        }
    }

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
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other(
                    "Network Apple TV has no pairing_cache_dir configured on this Device; \
                     install_app has nowhere to look for its pairing file"
                        .to_string(),
                )
            })?;

            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;

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

fn pairing_cache_path_for(
    pairing_identity: Option<&str>,
    udid: &str,
    cache_dir: &Path,
) -> Result<PathBuf, Error> {
    let key = pairing_identity.unwrap_or(udid);

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

async fn try_import_external_pairing_at(
    address: Option<(std::net::IpAddr, u16)>,
    cache_dir: &Path,
    cache_path: &Path,
) -> Result<Option<RpPairingFile>, Error> {
    let Some((ip, port)) = address else {
        return Ok(None);
    };
    let address = std::net::SocketAddr::new(ip, port);

    for (source, mut pairing_file) in external_pairing_candidates() {
        let stream = match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => stream,
            Err(error) => {
                log::debug!(
                    "Could not connect to Apple TV while trying external pairing record {}: {error}",
                    source
                );
                continue;
            }
        };
        let sending_host = pairing_file.identifier.clone();
        let mut client = RemotePairingClient::new(
            RpPairingSocket::new(stream),
            &sending_host,
            &mut pairing_file,
        );
        let valid = client.attempt_pair_verify().await.is_ok()
            && client.validate_pairing().await.is_ok();
        drop(client);

        if valid {
            write_pairing_file(&pairing_file, cache_dir, cache_path).await?;
            log::info!(
                "Imported an existing Apple TV pairing record from {}",
                source
            );
            return Ok(Some(pairing_file));
        }
    }

    Ok(None)
}

enum CoreDeviceTunnelAttemptError {
    Pairing(Error),
    Tunnel(Error),
}

fn tvos_create_listener_request(encryption_key: &[u8]) -> Value {
    let mut listener = plist::Dictionary::new();
    listener.insert(
        "key".to_string(),
        Value::String(STANDARD.encode(encryption_key)),
    );

    let mut peer_connection = plist::Dictionary::new();
    peer_connection.insert(
        "owningPID".to_string(),
        Value::Integer((std::process::id() as i64).into()),
    );
    peer_connection.insert(
        "owningProcessName".to_string(),
        Value::String("CoreDeviceService".to_string()),
    );
    listener.insert(
        "peerConnectionsInfo".to_string(),
        Value::Array(vec![Value::Dictionary(peer_connection)]),
    );
    listener.insert(
        "transportProtocolType".to_string(),
        Value::String("tcp".to_string()),
    );

    let mut operation = plist::Dictionary::new();
    operation.insert("createListener".to_string(), Value::Dictionary(listener));

    let mut request_body = plist::Dictionary::new();
    request_body.insert("_0".to_string(), Value::Dictionary(operation));

    let mut request = plist::Dictionary::new();
    request.insert("request".to_string(), Value::Dictionary(request_body));
    Value::Dictionary(request)
}

async fn create_tvos_tcp_listener<R: RpPairingSocketProvider>(
    rpc: &mut RemotePairingClient<'_, R>,
) -> Result<u16, Error> {
    let request = tvos_create_listener_request(rpc.encryption_key());
    let response = rpc.send_receive_encrypted_request(request).await?;
    log::debug!("tvOS createListener response: {response:#?}");

    let port = response
        .as_dictionary()
        .and_then(|value| value.get("createListener"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("port"))
        .and_then(Value::as_unsigned_integer)
        .filter(|port| *port <= u16::MAX as u64)
        .ok_or_else(|| Error::Other("missing port in createListener response".to_string()))?;

    Ok(port as u16)
}

async fn establish_core_device_tunnel(
    pairing_address: Option<(std::net::IpAddr, u16)>,
    reconnect_address: Option<(std::net::IpAddr, u16)>,
    pairing_identity: Option<&str>,
    udid: &str,
    cache_dir: &Path,
) -> Result<(AdapterHandle, RsdHandshake), Error> {
    let (ip, port) = reconnect_address.ok_or_else(|| {
        if pairing_address.is_some() {
            Error::Other(
                "Apple TV has only its manual-pairing service; discover its verified _remotepairing._tcp service before opening a tunnel"
                    .to_string(),
            )
        } else {
            Error::Other("Device has no network address".to_string())
        }
    })?;

    let connect_addr = std::net::SocketAddr::new(ip, port);
    let cache_path = pairing_cache_path_for(pairing_identity, udid, cache_dir)?;
    let (mut pairing_file, mut can_try_external) = if cache_path.exists() {
        (RpPairingFile::read_from_file(&cache_path).await?, true)
    } else {
        (
            try_import_external_pairing_at(Some((ip, port)), cache_dir, &cache_path)
                .await?
                .ok_or_else(|| {
                    Error::Other(
                        "No pairing record is cached for this Apple TV; pair before reconnecting"
                            .to_string(),
                    )
                })?,
            false,
        )
    };

    let tunnel = loop {
        let stream = tokio::net::TcpStream::connect(connect_addr).await.map_err(|e| {
            Error::Other(format!("Could not connect to Apple TV at {connect_addr}: {e}"))
        })?;
        let conn = RpPairingSocket::new(stream);
        let hostname = pairing_file.identifier.clone();

        let attempt: Result<_, CoreDeviceTunnelAttemptError> = async {
            let mut rpc = RemotePairingClient::new(conn, &hostname, &mut pairing_file);

            if let Err(e) = rpc.attempt_pair_verify().await {
                return Err(CoreDeviceTunnelAttemptError::Pairing(Error::Other(
                    format!("Pair-verify failed: {e}"),
                )));
            }

            if let Err(e) = rpc.validate_pairing().await {
                return Err(CoreDeviceTunnelAttemptError::Pairing(Error::Other(
                    format!(
                        "This Apple TV no longer recognizes this pairing (it may have been reset, \
                         forgotten, or lost pairing after a system update); pair with it again: {e}"
                    ),
                )));
            }

            let tunnel_port = create_tvos_tcp_listener(&mut rpc).await.map_err(|e| {
                CoreDeviceTunnelAttemptError::Tunnel(Error::Other(format!(
                    "Failed to create tunnel listener: {e}"
                )))
            })?;

            let tunnel_addr = std::net::SocketAddr::new(connect_addr.ip(), tunnel_port);
            let tunnel_stream = tokio::net::TcpStream::connect(tunnel_addr)
                .await
                .map_err(|e| {
                    CoreDeviceTunnelAttemptError::Tunnel(Error::Other(format!(
                        "TLS tunnel connect failed: {e}"
                    )))
                })?;

            connect_tls_psk_tunnel_native(Box::new(tunnel_stream), rpc.encryption_key())
                .await
                .map_err(|e| {
                    CoreDeviceTunnelAttemptError::Tunnel(Error::Other(format!(
                        "TLS-PSK tunnel handshake failed: {e}"
                    )))
                })
        }
        .await;

        match attempt {
            Ok(tunnel) => break tunnel,
            Err(CoreDeviceTunnelAttemptError::Pairing(error)) if can_try_external => {
                can_try_external = false;
                log::warn!(
                    "tvOS tunnel: cached pairing file at {} is stale ({error}); removing it",
                    cache_path.display()
                );
                let _ = tokio::fs::remove_file(&cache_path).await;

                if let Some(imported) =
                    try_import_external_pairing_at(Some((ip, port)), cache_dir, &cache_path)
                        .await?
                {
                    pairing_file = imported;
                    continue;
                }

                return Err(error);
            }
            Err(CoreDeviceTunnelAttemptError::Pairing(error))
            | Err(CoreDeviceTunnelAttemptError::Tunnel(error)) => return Err(error),
        }
    };

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

async fn write_pairing_file(
    pairing_file: &RpPairingFile,
    cache_dir: &Path,
    cache_path: &Path,
) -> Result<(), Error> {
    tokio::fs::create_dir_all(cache_dir).await?;

    #[cfg(unix)]
    tokio::fs::set_permissions(
        cache_dir,
        std::fs::Permissions::from_mode(0o700),
    )
    .await?;

    let temporary_path = cache_path.with_extension("plist.tmp");
    tokio::fs::write(&temporary_path, pairing_file.to_bytes()).await?;

    #[cfg(unix)]
    tokio::fs::set_permissions(
        &temporary_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .await?;

    tokio::fs::rename(&temporary_path, cache_path).await?;

    #[cfg(unix)]
    tokio::fs::set_permissions(cache_path, std::fs::Permissions::from_mode(0o600)).await?;

    Ok(())
}

fn external_pairing_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut paths = Vec::new();

        let native_dir = Path::new("/var/db/lockdown/RemotePairing");
        if let Ok(entries) = std::fs::read_dir(native_dir) {
            for entry in entries.flatten() {
                let path = entry.path().join("selfIdentity.plist");
                if path.is_file() {
                    paths.push(path);
                }
            }
        }

        paths.sort();
        paths.dedup();
        paths
    }

    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

fn external_pairing_candidates() -> Vec<(String, RpPairingFile)> {
    let mut candidates = Vec::new();

    for path in external_pairing_paths() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };

        let peer_paths = path
            .parent()
            .map(|parent| parent.join("peers"))
            .and_then(|directory| std::fs::read_dir(directory).ok())
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("plist"))
            .collect::<Vec<_>>();
        let peer_bytes = peer_paths
            .iter()
            .filter_map(|peer_path| std::fs::read(peer_path).ok())
            .collect::<Vec<_>>();
        let peer_refs = peer_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();

        if let Ok(native_candidates) = native_pairing_candidates_from_bytes(&bytes, &peer_refs) {
            for (index, candidate) in native_candidates.into_iter().enumerate() {
                let source = if index == 0 {
                    path.display().to_string()
                } else {
                    peer_paths
                        .get(index - 1)
                        .map(|peer_path| peer_path.display().to_string())
                        .unwrap_or_else(|| path.display().to_string())
                };
                candidates.push((source, candidate));
            }
        }
    }

    candidates
}

fn native_pairing_candidates_from_bytes(
    host_bytes: &[u8],
    peer_bytes: &[&[u8]],
) -> Result<Vec<RpPairingFile>, Error> {
    let mut host = external_pairing_file_from_bytes(host_bytes)?;
    host.alt_irk = None;

    let mut candidates = vec![host.clone()];
    for bytes in peer_bytes {
        let Ok(peer) = plist::from_bytes::<plist::Dictionary>(bytes) else {
            continue;
        };
        let Some(irk) = ["irk", "altIRK", "alt_irk"].iter().find_map(|key| {
            peer.get(*key)
                .and_then(plist::Value::as_data)
                .filter(|data| data.len() == 16)
                .map(|data| data.to_vec())
        }) else {
            continue;
        };

        let mut candidate = host.clone();
        candidate.alt_irk = Some(irk);
        candidates.push(candidate);
    }

    Ok(candidates)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairingAction {
    FirstPairing,
    Reconnect,
}

fn pairing_action(
    has_cached_pairing: bool,
    has_pairing_service: bool,
    has_reconnect_service: bool,
) -> Result<PairingAction, String> {
    if has_cached_pairing && (has_reconnect_service || has_pairing_service) {
        Ok(PairingAction::Reconnect)
    } else if !has_cached_pairing && has_pairing_service {
        Ok(PairingAction::FirstPairing)
    } else if has_cached_pairing {
        Err("Apple TV pairing record is stale and no pairing service is currently advertised".to_string())
    } else {
        Err(
            "Apple TV is not advertising its manual-pairing service; open Settings > Remotes and Devices > Remote App and Devices and wait for \"Waiting to Pair...\", then scan again".to_string(),
        )
    }
}

fn pairing_failure_to_error(failure: PairingFailure) -> Error {
    match failure {
        PairingFailure::Cancelled => Error::Other("Apple TV pairing was cancelled".to_string()),
        PairingFailure::InvalidPin => {
            Error::Other("Apple TV pairing PIN must contain exactly six digits".to_string())
        }
        PairingFailure::WrongPin => Error::Other("Apple TV rejected the pairing PIN".to_string()),
        PairingFailure::StaleRecord => Error::Other(
            "This Apple TV pairing record is stale; open the Apple TV pairing screen and try again"
                .to_string(),
        ),
        PairingFailure::ServiceDisappeared => Error::Other(
            "Apple TV pairing service disappeared; scan again while the pairing screen is open"
                .to_string(),
        ),
        PairingFailure::Protocol(message) => {
            Error::Other(format!("RPPairing handshake failed: {message}"))
        }
    }
}

fn local_remote_pairing_hostname() -> Option<String> {
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .filter(|hostname| !hostname.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|hostname| hostname.trim().to_string())
                .filter(|hostname| !hostname.is_empty())
        })?;

    Some(hostname)
}

fn local_remote_pairing_identifier() -> Option<String> {
    let hostname = local_remote_pairing_hostname()?;
    Some(
        uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_DNS, hostname.as_bytes())
            .to_string()
            .to_uppercase(),
    )
}

fn external_pairing_file_from_bytes(bytes: &[u8]) -> Result<RpPairingFile, Error> {
    let source: plist::Dictionary = plist::from_bytes(bytes)?;
    let data_field = |names: &[&str]| {
        names.iter().find_map(|name| {
            source
                .get(*name)
                .and_then(plist::Value::as_data)
                .map(|data| data.to_vec())
        })
    };
    let string_field = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| source.get(*name).and_then(plist::Value::as_string))
            .map(str::to_string)
    };

    let public_key = data_field(&["public_key", "publicKey"])
        .filter(|key| key.len() == 32)
        .ok_or_else(|| Error::Other("External pairing record has no valid public key".to_string()))?;
    let private_key = data_field(&["private_key", "privateKey"])
        .filter(|key| key.len() == 32)
        .ok_or_else(|| Error::Other("External pairing record has no valid private key".to_string()))?;
    let identifier = string_field(&["identifier", "host_identifier"])
        .or_else(local_remote_pairing_identifier)
        .ok_or_else(|| Error::Other("External pairing record has no host identifier".to_string()))?;

    let mut normalized = plist::Dictionary::new();
    normalized.insert("public_key".to_string(), plist::Value::Data(public_key));
    normalized.insert("private_key".to_string(), plist::Value::Data(private_key));
    normalized.insert(
        "identifier".to_string(),
        plist::Value::String(identifier),
    );
    if let Some(irk) = data_field(&["alt_irk", "irk", "host_alt_irk"]) {
        if irk.len() == 16 {
            normalized.insert("alt_irk".to_string(), plist::Value::Data(irk));
        }
    }

    let mut normalized_bytes = Vec::new();
    plist::to_writer_xml(&mut normalized_bytes, &normalized)?;
    Ok(RpPairingFile::from_bytes(&normalized_bytes)?)
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
            "WiFi"
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
        let identity = if crate::is_valid_device_udid(&self.udid) {
            format!(" [{}…{}]", &self.udid[..8], &self.udid[self.udid.len() - 4..])
        } else if self.is_network() {
            " [unpaired]".to_string()
        } else {
            String::new()
        };
        let platform = if self.is_tvos() { " (tvOS)" } else { "" };
        write!(f, "[{conn}] {}{platform}{identity}", self.name)
    }
}

pub async fn get_device_for_id(device_id: &str) -> Result<Device, Error> {
    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let usbmuxd_device = usbmuxd
        .get_devices()
        .await?
        .into_iter()
        .find(|d| {
            d.device_id.to_string() == device_id || d.udid.eq_ignore_ascii_case(device_id)
        })
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
