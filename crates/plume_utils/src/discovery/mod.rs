pub mod mdns;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use crate::{Device, synthetic_device_id};

pub const REMOTEPAIRING_MANUAL_PAIRING_SERVICE: &str = "_remotepairing-manual-pairing._tcp.local.";
pub const REMOTEPAIRING_SERVICE: &str = "_remotepairing._tcp.local.";
pub const APPLE_MOBDEV2_SERVICE: &str = "_apple-mobdev2._tcp.local.";
pub const APPLE_PAIRABLE_SERVICE: &str = "_apple-pairable._tcp.local.";
pub const COMPANION_LINK_SERVICE: &str = "_companion-link._tcp.local.";

pub const SERVICE_TYPES: [&str; 4] = [
    APPLE_MOBDEV2_SERVICE,
    APPLE_PAIRABLE_SERVICE,
    REMOTEPAIRING_SERVICE,
    REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
];

pub const METADATA_SERVICE_TYPES: [&str; 1] = [COMPANION_LINK_SERVICE];

pub const ALL_SCANNED_SERVICE_TYPES: [&str; 5] = [
    APPLE_MOBDEV2_SERVICE,
    APPLE_PAIRABLE_SERVICE,
    REMOTEPAIRING_SERVICE,
    REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
    COMPANION_LINK_SERVICE,
];

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceType {
    IPhone,
    IPad,
    AppleTV,
    AppleMac,
    Unknown,
}

impl DeviceType {
    pub fn from_device_class(device_class: &str) -> Self {
        match device_class {
            "iPhone" => DeviceType::IPhone,
            "iPad" => DeviceType::IPad,
            "AppleTV" => DeviceType::AppleTV,
            "Mac" => DeviceType::AppleMac,
            _ => DeviceType::Unknown,
        }
    }

    pub fn from_product_type(product_type: &str) -> Self {
        if product_type.starts_with("iPhone") {
            DeviceType::IPhone
        } else if product_type.starts_with("iPad") {
            DeviceType::IPad
        } else if product_type.starts_with("AppleTV") {
            DeviceType::AppleTV
        } else if product_type.starts_with("Mac") {
            DeviceType::AppleMac
        } else {
            DeviceType::Unknown
        }
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::IPhone => write!(f, "iPhone"),
            DeviceType::IPad => write!(f, "iPad"),
            DeviceType::AppleTV => write!(f, "Apple TV"),
            DeviceType::AppleMac => write!(f, "Mac"),
            DeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionType {
    USB,
    WiFi,
}

impl std::fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionType::USB => write!(f, "USB"),
            ConnectionType::WiFi => write!(f, "WiFi"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub name: String,
    pub hostname: String,
    pub udid: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub device_type: DeviceType,
    pub connection_type: ConnectionType,
    pub is_paired: bool,
    pub product_type: Option<String>,
    pub os_version: Option<String>,
    pub service_type: String,
}


pub(crate) fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    let (haystack, needle) = (s.as_bytes(), suffix.as_bytes());
    needle.len() <= haystack.len()
        && haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

pub(crate) fn parse_instance_name(full_name: &str, service_type: &str) -> String {
    let full = full_name.trim_end_matches('.');
    let service = service_type.trim_end_matches('.');

    if !service.is_empty() {
        let suffix_len = service.len() + 1;
        if full.len() > suffix_len && ends_with_ignore_case(full, service) {
            let cut = full.len() - suffix_len;
            if full.as_bytes()[cut] == b'.' {
                return full[..cut].to_string();
            }
        }
    }
    full.to_string()
}

pub(crate) fn short_hostname(hostname: &str) -> &str {
    let hostname = hostname.trim_end_matches('.');
    if ends_with_ignore_case(hostname, ".local") {
        &hostname[..hostname.len() - ".local".len()]
    } else {
        hostname
    }
}

pub(crate) fn dedup_key(
    hostname: &str,
    instance_name: &str,
    service_type: &str,
) -> (String, String) {
    let host = short_hostname(hostname);
    let base = if host.is_empty() { instance_name } else { host };
    (base.to_ascii_lowercase(), service_type.to_string())
}

pub(crate) fn first_non_empty<'a>(
    props: &'a HashMap<String, String>,
    candidates: &[&str],
) -> Option<&'a str> {
    candidates
        .iter()
        .filter_map(|k| props.get(*k))
        .map(|v| v.as_str())
        .find(|v| !v.is_empty())
}

pub(crate) fn build_device(
    instance_name: &str,
    hostname: &str,
    service_type: &str,
    port: Option<u16>,
    addresses: &[IpAddr],
    props: &HashMap<String, String>,
) -> DiscoveredDevice {
    let device_type = if let Some(class) = first_non_empty(props, &["DeviceClass", "deviceClass"]) {
        DeviceType::from_device_class(class)
    } else if let Some(model) = first_non_empty(props, &["ProductType", "model", "rpMd"]) {
        DeviceType::from_product_type(model)
    } else {
        DeviceType::Unknown
    };

    let product_type =
        first_non_empty(props, &["ProductType", "model", "rpMd"]).map(str::to_string);
    let os_version = first_non_empty(props, &["OSVersion", "osVersion"]).map(str::to_string);
    let udid = None;

    let name = {
        let from_host = short_hostname(hostname).replace('-', " ");
        if !from_host.is_empty() {
            from_host
        } else {
            first_non_empty(props, &["name", "Name"])
                .map(str::to_string)
                .unwrap_or_else(|| instance_name.to_string())
        }
    };

    DiscoveredDevice {
        name,
        hostname: short_hostname(hostname).to_string(),
        udid,
        ip_address: preferred_ip_address(addresses),
        port,
        device_type,
        connection_type: ConnectionType::WiFi,
        is_paired: service_type.contains("mobdev2"),
        product_type,
        os_version,
        service_type: service_type.to_string(),
    }
}

fn preferred_ip_address(addresses: &[IpAddr]) -> Option<String> {
    addresses
        .iter()
        .filter(|address| address.is_ipv4())
        .min_by_key(|address| address.to_string())
        .or_else(|| addresses.iter().min_by_key(|address| address.to_string()))
        .map(ToString::to_string)
}

pub(crate) fn is_metadata_service(service_type: &str) -> bool {
    METADATA_SERVICE_TYPES.contains(&service_type)
}

fn device_correlation_key(device: &DiscoveredDevice) -> String {
    if device.hostname.is_empty() {
        device.name.to_ascii_lowercase()
    } else {
        device.hostname.to_ascii_lowercase()
    }
}

pub(crate) fn enrich_and_filter(devices: Vec<DiscoveredDevice>) -> Vec<DiscoveredDevice> {
    let mut metadata: HashMap<String, DiscoveredDevice> = HashMap::new();
    for d in &devices {
        if !is_metadata_service(&d.service_type) {
            continue;
        }
        let key = device_correlation_key(d);
        let should_replace = match metadata.get(&key) {
            Some(existing) => existing.device_type == DeviceType::Unknown,
            None => true,
        };
        if should_replace {
            metadata.insert(key, d.clone());
        }
    }

    devices
        .into_iter()
        .filter(|d| !is_metadata_service(&d.service_type))
        .map(|mut d| {
            if let Some(meta) = metadata.get(&device_correlation_key(&d)) {
                let agrees = d.device_type == DeviceType::Unknown
                    || meta.device_type == DeviceType::Unknown
                    || d.device_type == meta.device_type;
                if agrees {
                    if d.device_type == DeviceType::Unknown {
                        d.device_type = meta.device_type.clone();
                    }
                    if d.product_type.is_none() {
                        d.product_type = meta.product_type.clone();
                    }
                    if d.os_version.is_none() {
                        d.os_version = meta.os_version.clone();
                    }
                }
            }
            d
        })
        .collect()
}

struct NetworkDeviceGroup {
    name: String,
    hostname: String,
    pairing_address: Option<(IpAddr, u16)>,
    reconnect_address: Option<(IpAddr, u16)>,
    legacy_core_device: bool,
}

pub fn group_network_devices(discovered: &[DiscoveredDevice], cache_dir: &Path) -> Vec<Device> {
    let mut groups: HashMap<String, NetworkDeviceGroup> = HashMap::new();

    for d in discovered {
        if d.device_type != DeviceType::AppleTV {
            continue;
        }
        let is_remote_pairing = d.service_type == REMOTEPAIRING_SERVICE
            || d.service_type == REMOTEPAIRING_MANUAL_PAIRING_SERVICE;
        let is_core_device = d.service_type == APPLE_MOBDEV2_SERVICE;
        if !is_remote_pairing && !is_core_device {
            continue;
        }
        if d.name.is_empty() {
            continue;
        }

        let key = if d.hostname.is_empty() {
            d.name.to_ascii_lowercase()
        } else {
            d.hostname.to_ascii_lowercase()
        };
        let entry = groups.entry(key).or_insert_with(|| NetworkDeviceGroup {
            name: d.name.clone(),
            hostname: d.hostname.clone(),
            pairing_address: None,
            reconnect_address: None,
            legacy_core_device: false,
        });
        entry.legacy_core_device |= is_core_device;

        let address = d
            .ip_address
            .as_deref()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .zip(d.port);
        if d.service_type == REMOTEPAIRING_MANUAL_PAIRING_SERVICE {
            if entry.pairing_address.is_none() {
                entry.pairing_address = address;
            }
        } else if d.service_type == REMOTEPAIRING_SERVICE {
            if entry.reconnect_address.is_none() {
                entry.reconnect_address = address;
            }
        }
    }

    let mut devices = Vec::with_capacity(groups.len());
    for group in groups.into_values() {
        if group.pairing_address.is_none()
            && group.reconnect_address.is_none()
            && !group.legacy_core_device
        {
            continue;
        }
        let pairing_identity = if group.hostname.is_empty() {
            group.name.replace(' ', "-")
        } else {
            group.hostname
        };
        let id = synthetic_device_id(&pairing_identity);

        let mut device = Device::new_tvos_with_addresses(
            group.name,
            pairing_identity,
            group.pairing_address,
            group.reconnect_address,
            cache_dir.to_path_buf(),
        );
        device.device_id = id;

        devices.push(device);
    }

    devices
}

pub fn disconnected_after_missed_scans(
    present_ids: &mut HashSet<u32>,
    current_ids: &HashSet<u32>,
    miss_counts: &mut HashMap<u32, u32>,
    required_misses: u32,
) -> Vec<u32> {
    for id in current_ids {
        miss_counts.remove(id);
    }

    let missing = present_ids
        .iter()
        .copied()
        .filter(|id| !current_ids.contains(id))
        .collect::<Vec<_>>();
    let threshold = required_misses.max(1);
    let mut disconnected = Vec::new();

    for id in missing {
        let misses = miss_counts.entry(id).or_insert(0);
        *misses += 1;
        if *misses >= threshold {
            present_ids.remove(&id);
            miss_counts.remove(&id);
            disconnected.push(id);
        }
    }

    disconnected
}

#[allow(async_fn_in_trait)]
pub trait DeviceDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformDiscovery;

impl PlatformDiscovery {
    pub fn new() -> Self {
        Self
    }
}

impl DeviceDiscovery for PlatformDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>> {
        mdns::MdnsDiscovery::new().discover(timeout).await
    }
}
