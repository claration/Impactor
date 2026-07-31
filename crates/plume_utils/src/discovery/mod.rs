pub mod mdns;
#[cfg(windows)]
pub mod windows_dnssd;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use crate::{Device, synthetic_device_id};

/// Service for devices with no existing pairing, actively showing a pairing PIN on screen.
/// This is the only service that supports first-time SRP pair-setup.
pub const REMOTEPAIRING_MANUAL_PAIRING_SERVICE: &str = "_remotepairing-manual-pairing._tcp.local.";
/// Service for devices with an existing pairing. Reconnect (pair-verify) only - does not
/// support first-time pairing.
pub const REMOTEPAIRING_SERVICE: &str = "_remotepairing._tcp.local.";
/// Legacy lockdown-over-network service, advertised by devices already paired with this host.
pub const APPLE_MOBDEV2_SERVICE: &str = "_apple-mobdev2._tcp.local.";
/// Legacy service advertised by devices willing to accept a new lockdown pairing.
pub const APPLE_PAIRABLE_SERVICE: &str = "_apple-pairable._tcp.local.";
/// Advertised persistently by Macs, iPhones and Apple TVs alike, so unlike the four services
/// above this is not a service anything here connects to. It exists only so entries built from
/// it can supply the model of a same-host entry whose own advertisement carries none - a paired
/// Apple TV that is not on its pairing screen advertises only `_remotepairing._tcp.local.`,
/// whose TXT record has no model at all. See `enrich_and_filter`.
pub const COMPANION_LINK_SERVICE: &str = "_companion-link._tcp.local.";

/// The service types scanned by every discovery backend, in a fixed order. Every entry built
/// from one of these is returned to callers as a device in its own right.
pub const SERVICE_TYPES: [&str; 4] = [
    APPLE_MOBDEV2_SERVICE,
    APPLE_PAIRABLE_SERVICE,
    REMOTEPAIRING_SERVICE,
    REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
];

/// Service types browsed only to enrich `SERVICE_TYPES` entries that lack a model. Entries built
/// from these are never themselves returned as devices - see `enrich_and_filter`.
pub const METADATA_SERVICE_TYPES: [&str; 1] = [COMPANION_LINK_SERVICE];

/// Every service type a discovery backend browses in one scan: the four device-producing
/// services followed by the metadata-only companion-link service.
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
    pub udid: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub device_type: DeviceType,
    pub connection_type: ConnectionType,
    pub is_paired: bool,
    pub product_type: Option<String>,
    pub os_version: Option<String>,
    /// The mDNS service type this entry was resolved from (e.g.
    /// `_remotepairing-manual-pairing._tcp.local.`). Devices advertise different RPPairing
    /// services depending on whether they're actively showing a pairing PIN or already paired,
    /// and those services listen on different ports - callers must not treat entries from
    /// different service types as interchangeable.
    pub service_type: String,
}

// ---------------------------------------------------------------------------------------------
// Shared advertisement mapping
//
// Every backend funnels its raw advertisement facts through these helpers, so the two backends
// produce identical `DiscoveredDevice` values and remain interchangeable.
// ---------------------------------------------------------------------------------------------

/// Case-insensitive check that `s` ends with `suffix`.
///
/// Compares bytes rather than slicing the `&str`: instance names carry literal non-ASCII (a real
/// device on this network is named `Frankie<U+2019>s MacBook Pro`), and slicing at
/// `len - suffix.len()` panics whenever that offset lands inside a multi-byte character.
pub(crate) fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    let (haystack, needle) = (s.as_bytes(), suffix.as_bytes());
    needle.len() <= haystack.len()
        && haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

/// Extracts the instance label from a full DNS-SD instance name.
///
/// Instance names arrive with literal spaces and literal non-ASCII - there is no `\032` escaping
/// and no punycode - so the label is recovered by stripping the known `.<service type>` suffix,
/// never by splitting on `.`.
pub(crate) fn parse_instance_name(full_name: &str, service_type: &str) -> String {
    let full = full_name.trim_end_matches('.');
    let service = service_type.trim_end_matches('.');

    if !service.is_empty() {
        let suffix_len = service.len() + 1;
        if full.len() > suffix_len && ends_with_ignore_case(full, service) {
            let cut = full.len() - suffix_len;
            // A `.` at `cut` proves `cut` is a character boundary, so the slice below is safe.
            if full.as_bytes()[cut] == b'.' {
                return full[..cut].to_string();
            }
        }
    }
    full.to_string()
}

/// Strips the trailing dot and the `.local` label from a host name.
pub(crate) fn short_hostname(hostname: &str) -> &str {
    hostname.trim_end_matches('.').trim_end_matches(".local")
}

/// Key under which a discovered entry is stored.
///
/// The same physical device legitimately advertises several service types at once on *different*
/// ports (manual pairing versus an established pairing), so the service type is part of the key
/// and those entries must not collapse into one. The host part is lower-cased because DNS names
/// are case-insensitive and the same device may be advertised with differing case.
pub(crate) fn dedup_key(
    hostname: &str,
    instance_name: &str,
    service_type: &str,
) -> (String, String) {
    let host = short_hostname(hostname);
    let base = if host.is_empty() { instance_name } else { host };
    (base.to_ascii_lowercase(), service_type.to_string())
}

/// Looks up the first present key from `candidates`, ignoring empty values.
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

/// Builds a [`DiscoveredDevice`] from the facts one backend gathered about a single service
/// instance. Free of any backend-specific or FFI type, so both backends share it verbatim.
pub(crate) fn build_device(
    instance_name: &str,
    hostname: &str,
    service_type: &str,
    port: Option<u16>,
    addresses: &[IpAddr],
    props: &HashMap<String, String>,
) -> DiscoveredDevice {
    // Real Apple TV advertisements carry no `DeviceClass` and no `ProductType`: manual pairing
    // reports `model=AppleTV14,1` and companion-link reports `rpMd=AppleTV14,1`. Both must map to
    // `AppleTV`, because the pairing UI hard-filters on that.
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
    let udid =
        first_non_empty(props, &["UniqueDeviceID", "udid", "identifier"]).map(str::to_string);

    // Derived from the hostname first. The name is what the UI uses to correlate a device's
    // several service-type entries with each other, so it must be identical across them: one
    // device advertises manual pairing under a friendly instance name ("Living Room") but an
    // established pairing under a bare UUID, and only the shared hostname yields the same value
    // for both. TXT and instance name are fallbacks for advertisements carrying no hostname.
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
        udid,
        ip_address: addresses.first().map(|a| a.to_string()),
        port,
        device_type,
        connection_type: ConnectionType::WiFi,
        is_paired: service_type.contains("mobdev2"),
        product_type,
        os_version,
        service_type: service_type.to_string(),
    }
}

/// True when `service_type` is browsed only to enrich other entries and must never itself be
/// surfaced as a device.
pub(crate) fn is_metadata_service(service_type: &str) -> bool {
    METADATA_SERVICE_TYPES.contains(&service_type)
}

/// Fills in missing model information on entries whose own advertisement carries none, using
/// metadata-only advertisements from the same host, then drops those metadata entries.
///
/// Correlation is by lower-cased `name`: both device-producing and metadata-only entries derive
/// `name` from the advertised host name (see `build_device`), so entries for one physical device
/// share it regardless of which service they came from.
pub(crate) fn enrich_and_filter(devices: Vec<DiscoveredDevice>) -> Vec<DiscoveredDevice> {
    let mut metadata: HashMap<String, DiscoveredDevice> = HashMap::new();
    for d in &devices {
        if !is_metadata_service(&d.service_type) {
            continue;
        }
        let key = d.name.to_ascii_lowercase();
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
            if let Some(meta) = metadata.get(&d.name.to_ascii_lowercase()) {
                // Values are adopted only from a metadata advertisement that agrees about what
                // the device is. Filling individual fields from one that disagrees would produce
                // an incoherent entry, such as an Apple TV carrying an iPhone model.
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

/// One physical network Apple TV's manual-pairing and reconnect advertisements, correlated by
/// name (see `screen/tvos_pairing.rs`'s `manual_pairing_entry`/`reconnect_entry`, which this
/// mirrors), merged into the single address and port pair `Device::new_tvos` needs.
struct NetworkDeviceGroup {
    name: String,
    ip: Option<IpAddr>,
    pairing_port: Option<u16>,
    reconnect_port: Option<u16>,
}

/// Turns a raw scan result into the `Device` values a global device picker can list and select,
/// one per physical Apple TV. Pure and I/O-free: callers that need a device's real UDID still
/// have to enrich it themselves (see `Device::fetch_tvos_info`), since that requires a network
/// round trip this function deliberately does not perform.
///
/// Only entries typed `AppleTV` and advertising `REMOTEPAIRING_SERVICE` or
/// `REMOTEPAIRING_MANUAL_PAIRING_SERVICE` are considered; everything else (other device types,
/// the legacy lockdown services, the metadata-only companion-link service) is ignored. Entries
/// are grouped by case-insensitive name, exactly as `screen/tvos_pairing.rs` correlates them, so
/// a device advertising both services yields one `Device` carrying both ports rather than two.
///
/// A group with no resolved IP address, or an empty name, is dropped rather than turned into a
/// `Device`: an empty name would produce a `pairing_identity` of `""`, which
/// `Device::pairing_cache_path` rejects outright, and would collide every such device onto the
/// same synthetic id.
pub fn group_network_devices(discovered: &[DiscoveredDevice], cache_dir: &Path) -> Vec<Device> {
    let mut groups: HashMap<String, NetworkDeviceGroup> = HashMap::new();

    for d in discovered {
        if d.device_type != DeviceType::AppleTV {
            continue;
        }
        if d.service_type != REMOTEPAIRING_SERVICE
            && d.service_type != REMOTEPAIRING_MANUAL_PAIRING_SERVICE
        {
            continue;
        }
        if d.name.is_empty() {
            continue;
        }

        let key = d.name.to_ascii_lowercase();
        let entry = groups.entry(key).or_insert_with(|| NetworkDeviceGroup {
            name: d.name.clone(),
            ip: None,
            pairing_port: None,
            reconnect_port: None,
        });

        // The first entry to resolve an address for this device wins; a later entry for the
        // same physical device never overrides it. Scan order between the manual-pairing and
        // reconnect entries is not guaranteed stable across scans (the Windows backend walks a
        // HashMap internally), so preferring "first seen" over "last seen" keeps the chosen
        // address from flapping between otherwise-identical scans.
        if entry.ip.is_none() {
            if let Some(ip_str) = &d.ip_address {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    entry.ip = Some(ip);
                }
            }
        }

        if d.service_type == REMOTEPAIRING_MANUAL_PAIRING_SERVICE {
            entry.pairing_port = d.port;
        } else if d.service_type == REMOTEPAIRING_SERVICE {
            entry.reconnect_port = d.port;
        }
    }

    let mut devices = Vec::with_capacity(groups.len());
    for group in groups.into_values() {
        // No resolved address means no connection info exists for this Apple TV in this scan;
        // it cannot be turned into a usable Device, so it is treated as absent.
        let Some(ip) = group.ip else {
            continue;
        };

        let pairing_identity = group.name.replace(' ', "-");
        let id = synthetic_device_id(&pairing_identity);

        let mut device = Device::new_tvos(
            group.name,
            pairing_identity,
            ip,
            group.pairing_port,
            group.reconnect_port,
            cache_dir.to_path_buf(),
        );
        // Every network device would otherwise share new_tvos()'s default device_id of 0 and
        // collide with each other under the app's id-based device-list dedupe, leaving only one
        // Apple TV ever listed no matter how many are actually on the network.
        device.device_id = id;

        devices.push(device);
    }

    devices
}

#[allow(async_fn_in_trait)]
pub trait DeviceDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>>;
}

/// Discovery backend appropriate for the host platform.
///
/// On Windows the native DNS-SD resolver (`dnsapi.dll`) is tried first, because the
/// raw-multicast-socket backend does not reliably receive responses there; if it errors or
/// finds nothing, the `mdns-sd` backend runs as a fallback. Every other platform uses
/// `mdns-sd` directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformDiscovery;

impl PlatformDiscovery {
    pub fn new() -> Self {
        Self
    }
}

impl DeviceDiscovery for PlatformDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>> {
        // The fallback runs inside the caller's budget, not in addition to it: the two backends
        // together never exceed `timeout`. A native scan that finds nothing returns after its
        // browse budget, which is what leaves the fallback a usable slice.
        #[cfg(windows)]
        let timeout = {
            let started = std::time::Instant::now();

            match windows_dnssd::WindowsDnsSdDiscovery::new()
                .discover(timeout)
                .await
            {
                Ok(devices) if !devices.is_empty() => return Ok(devices),
                Ok(_) => log::warn!(
                    "Windows DNS-SD discovery returned no devices, falling back to mdns-sd"
                ),
                Err(e) => {
                    log::warn!("Windows DNS-SD discovery failed ({e}), falling back to mdns-sd")
                }
            }

            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                log::warn!("No time left for the mdns-sd fallback within the requested timeout");
                return Ok(Vec::new());
            }
            remaining
        };

        mdns::MdnsDiscovery::new().discover(timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn instance_name_strips_service_suffix() {
        assert_eq!(
            parse_instance_name(
                "Living Room._remotepairing-manual-pairing._tcp.local",
                REMOTEPAIRING_MANUAL_PAIRING_SERVICE
            ),
            "Living Room"
        );
    }

    #[test]
    fn instance_name_handles_trailing_dot_on_both_sides() {
        assert_eq!(
            parse_instance_name("Apple TV._remotepairing._tcp.local.", REMOTEPAIRING_SERVICE),
            "Apple TV"
        );
        assert_eq!(
            parse_instance_name(
                "Apple TV._remotepairing._tcp.local",
                "_remotepairing._tcp.local"
            ),
            "Apple TV"
        );
    }

    #[test]
    fn instance_name_keeps_literal_non_ascii() {
        let full = "Frankie\u{2019}s MacBook Pro._companion-link._tcp.local";
        assert_eq!(
            parse_instance_name(full, "_companion-link._tcp.local."),
            "Frankie\u{2019}s MacBook Pro"
        );
    }

    #[test]
    fn instance_name_left_alone_when_suffix_absent() {
        assert_eq!(
            parse_instance_name("Living Room._other._tcp.local", REMOTEPAIRING_SERVICE),
            "Living Room._other._tcp.local"
        );
    }

    #[test]
    fn instance_name_does_not_split_a_multibyte_character() {
        // The suffix comparison must not slice the string at `len - suffix.len()`: here that
        // offset lands inside the leading U+2019, which panics on a `&str` slice.
        let name = "\u{2019}".to_string() + &"X".repeat(24);
        assert_eq!(parse_instance_name(&name, REMOTEPAIRING_SERVICE), name);

        // Same hazard with the multi-byte character straddling the boundary from the other side.
        for pad in 0..8 {
            let name = "A".repeat(pad) + "\u{2019}\u{2019}\u{2019}";
            assert_eq!(parse_instance_name(&name, "_x._tcp.local"), name);
        }
    }

    #[test]
    fn suffix_match_is_case_insensitive() {
        assert!(ends_with_ignore_case(
            "Living Room._TCP.LOCAL",
            "_tcp.local"
        ));
        assert!(ends_with_ignore_case("abc", "ABC"));
        assert!(!ends_with_ignore_case("abc", "abd"));
        assert!(!ends_with_ignore_case("ab", "abc"));
        // DNS names are case-insensitive, so a differently-cased service label still strips.
        assert_eq!(
            parse_instance_name(
                "Living Room._RemotePairing._TCP.local",
                REMOTEPAIRING_SERVICE
            ),
            "Living Room"
        );
    }

    #[test]
    fn first_non_empty_skips_present_but_empty_values() {
        let p = props(&[("ProductType", ""), ("model", "AppleTV14,1")]);
        assert_eq!(
            first_non_empty(&p, &["ProductType", "model"]),
            Some("AppleTV14,1")
        );
        assert_eq!(first_non_empty(&p, &["ProductType"]), None);
        assert_eq!(first_non_empty(&p, &["absent"]), None);
    }

    #[test]
    fn real_apple_tv_txt_maps_to_apple_tv() {
        // Manual pairing: no DeviceClass, no ProductType, model only. The pairing UI filters on
        // `device_type == AppleTV`, so anything else drops the device before the user sees it.
        let manual = props(&[("model", "AppleTV14,1")]);
        let d = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
            Some(49153),
            &[],
            &manual,
        );
        assert_eq!(d.device_type, DeviceType::AppleTV);
        assert_eq!(d.product_type.as_deref(), Some("AppleTV14,1"));

        // Companion-link style: rpMd only.
        let companion = props(&[("rpMd", "AppleTV14,1"), ("udid", "deadbeef")]);
        let d = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(49152),
            &[],
            &companion,
        );
        assert_eq!(d.device_type, DeviceType::AppleTV);
        assert_eq!(d.product_type.as_deref(), Some("AppleTV14,1"));
        assert_eq!(d.udid.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn mapping_prefers_device_class() {
        let p = props(&[
            ("DeviceClass", "AppleTV"),
            ("ProductType", "AppleTV11,1"),
            ("UniqueDeviceID", "abc123"),
            ("OSVersion", "17.4"),
            ("name", "Ignored"),
        ]);
        let d = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(49152),
            &["10.0.0.5".parse::<IpAddr>().unwrap()],
            &p,
        );
        assert_eq!(d.device_type, DeviceType::AppleTV);
        assert_eq!(d.product_type.as_deref(), Some("AppleTV11,1"));
        assert_eq!(d.os_version.as_deref(), Some("17.4"));
        assert_eq!(d.udid.as_deref(), Some("abc123"));
        assert_eq!(d.ip_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(d.port, Some(49152));
        assert_eq!(d.connection_type, ConnectionType::WiFi);
        assert!(!d.is_paired);
        assert_eq!(d.service_type, REMOTEPAIRING_SERVICE);
    }

    #[test]
    fn mapping_name_prefers_hostname_over_txt_and_instance() {
        // Instance label and TXT name both differ from the host name; the host name still wins.
        let d = build_device(
            "A827F07B-2D1D-4D09-8E1E-5E37EE47A96C",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(1),
            &[],
            &props(&[("name", "Some Other Name")]),
        );
        assert_eq!(d.name, "Living Room");
    }

    #[test]
    fn mapping_name_falls_back_when_hostname_missing() {
        // No host name: the TXT name is next.
        let d = build_device(
            "instance-label",
            "",
            REMOTEPAIRING_SERVICE,
            Some(1),
            &[],
            &props(&[("name", "Txt Name")]),
        );
        assert_eq!(d.name, "Txt Name");

        // Neither host name nor TXT name: the parsed instance label is last.
        let d = build_device(
            "instance-label",
            "",
            REMOTEPAIRING_SERVICE,
            Some(1),
            &[],
            &props(&[]),
        );
        assert_eq!(d.name, "instance-label");
    }

    #[test]
    fn same_device_yields_identical_name_across_service_types() {
        // An Apple TV advertises manual pairing under a friendly instance name carrying a TXT
        // `name`, and an established pairing under a bare UUID with no TXT `name` at all (both
        // shapes taken from a packet capture of a real pairing session). The UI correlates a
        // device's service-type entries by name, so both must resolve to the same name while
        // remaining separate entries with their own ports.
        let manual = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
            Some(62782),
            &[],
            &props(&[("name", "Living Room"), ("model", "AppleTV14,1")]),
        );
        let reconnect = build_device(
            "A827F07B-2D1D-4D09-8E1E-5E37EE47A96C",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(49152),
            &[],
            &props(&[("identifier", "73B8BE56-3881-4145-BF61-EFB7BBAEC98F")]),
        );

        assert_eq!(manual.name, "Living Room");
        assert_eq!(manual.name, reconnect.name);
        assert_ne!(manual.service_type, reconnect.service_type);
        assert_eq!(manual.port, Some(62782));
        assert_eq!(reconnect.port, Some(49152));
    }

    #[test]
    fn mapping_marks_mobdev2_as_paired() {
        let d = build_device(
            "x",
            "",
            APPLE_MOBDEV2_SERVICE,
            Some(62078),
            &[],
            &props(&[]),
        );
        assert!(d.is_paired);
        assert_eq!(d.device_type, DeviceType::Unknown);
        assert_eq!(d.product_type, None);
    }

    #[test]
    fn mapping_udid_precedence() {
        let p = props(&[("udid", "second"), ("identifier", "third")]);
        assert_eq!(
            build_device("x", "", REMOTEPAIRING_SERVICE, Some(1), &[], &p)
                .udid
                .as_deref(),
            Some("second")
        );
        let p = props(&[("identifier", "third")]);
        assert_eq!(
            build_device("x", "", REMOTEPAIRING_SERVICE, Some(1), &[], &p)
                .udid
                .as_deref(),
            Some("third")
        );
    }

    #[test]
    fn dedup_key_normalizes_case_and_falls_back_to_instance() {
        assert_eq!(
            dedup_key("Living-Room.local.", "Living Room", REMOTEPAIRING_SERVICE),
            dedup_key("living-room.local", "Living Room", REMOTEPAIRING_SERVICE)
        );
        assert_eq!(
            dedup_key("", "Living Room", REMOTEPAIRING_SERVICE),
            ("living room".to_string(), REMOTEPAIRING_SERVICE.to_string())
        );
    }

    #[test]
    fn same_device_under_two_service_types_is_not_collapsed() {
        let p = props(&[("model", "AppleTV14,1")]);
        let mut devices: HashMap<(String, String), DiscoveredDevice> = HashMap::new();

        for (service, port) in [
            (REMOTEPAIRING_SERVICE, 49152u16),
            (REMOTEPAIRING_MANUAL_PAIRING_SERVICE, 49153u16),
        ] {
            let device = build_device(
                "Living Room",
                "Living-Room.local.",
                service,
                Some(port),
                &[],
                &p,
            );
            devices.insert(
                dedup_key("Living-Room.local.", "Living Room", service),
                device,
            );
        }

        assert_eq!(devices.len(), 2);
        let mut ports: Vec<u16> = devices.values().filter_map(|d| d.port).collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![49152, 49153]);
        assert!(devices.values().all(|d| d.name == "Living Room"));
    }

    fn unknown_device(name: &str, service_type: &str, port: u16) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.to_string(),
            udid: None,
            ip_address: None,
            port: Some(port),
            device_type: DeviceType::Unknown,
            connection_type: ConnectionType::WiFi,
            is_paired: false,
            product_type: None,
            os_version: None,
            service_type: service_type.to_string(),
        }
    }

    fn companion_link_device(name: &str, product_type: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.to_string(),
            udid: None,
            ip_address: None,
            port: Some(49155),
            device_type: DeviceType::from_product_type(product_type),
            connection_type: ConnectionType::WiFi,
            is_paired: false,
            product_type: Some(product_type.to_string()),
            os_version: None,
            service_type: COMPANION_LINK_SERVICE.to_string(),
        }
    }

    #[test]
    fn enrich_and_filter_fills_model_from_companion_link() {
        let remotepairing = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
        let companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![remotepairing, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service_type, REMOTEPAIRING_SERVICE);
        assert_eq!(result[0].port, Some(49152));
        assert_eq!(result[0].device_type, DeviceType::AppleTV);
        assert_eq!(result[0].product_type.as_deref(), Some("AppleTV14,1"));
    }

    #[test]
    fn enrich_and_filter_name_correlation_is_case_insensitive() {
        let remotepairing = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
        let companion = companion_link_device("living room", "AppleTV14,1");

        let result = enrich_and_filter(vec![remotepairing, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].device_type, DeviceType::AppleTV);
        assert_eq!(result[0].product_type.as_deref(), Some("AppleTV14,1"));
    }

    #[test]
    fn enrich_and_filter_does_not_overwrite_known_device_type() {
        let mut manual = unknown_device("Living Room", REMOTEPAIRING_MANUAL_PAIRING_SERVICE, 49153);
        manual.device_type = DeviceType::AppleTV;
        // A companion-link entry disagreeing with an already-known type must not win.
        let mut companion = companion_link_device("Living Room", "iPhone15,2");
        companion.device_type = DeviceType::IPhone;

        let result = enrich_and_filter(vec![manual, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].device_type, DeviceType::AppleTV);
        // Nor may its other fields be filled from that disagreeing entry: an Apple TV carrying
        // an iPhone model is worse than an Apple TV carrying no model at all.
        assert_eq!(result[0].product_type, None);
    }

    #[test]
    fn enrich_and_filter_prefers_a_typed_metadata_entry_regardless_of_order() {
        // Several metadata entries can share a name; the one that actually identifies the
        // device must win whichever order they arrive in.
        for reversed in [false, true] {
            let target = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
            let untyped = companion_link_device("Living Room", "");
            let mut untyped = untyped;
            untyped.device_type = DeviceType::Unknown;
            untyped.product_type = None;
            let typed = companion_link_device("Living Room", "AppleTV14,1");

            let input = if reversed {
                vec![target, typed, untyped]
            } else {
                vec![target, untyped, typed]
            };
            let result = enrich_and_filter(input);

            assert_eq!(result.len(), 1);
            assert_eq!(
                result[0].device_type,
                DeviceType::AppleTV,
                "reversed={reversed}"
            );
            assert_eq!(
                result[0].product_type.as_deref(),
                Some("AppleTV14,1"),
                "reversed={reversed}"
            );
        }
    }

    #[test]
    fn enrich_and_filter_does_not_overwrite_known_product_type() {
        let mut remotepairing = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
        remotepairing.product_type = Some("x".to_string());
        let companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![remotepairing, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].product_type.as_deref(), Some("x"));
    }

    #[test]
    fn enrich_and_filter_drops_unmatched_metadata_entries() {
        let companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![companion]);

        assert!(result.is_empty());
    }

    #[test]
    fn enrich_and_filter_does_not_cross_contaminate_hosts() {
        let bedroom = unknown_device("Bedroom", REMOTEPAIRING_SERVICE, 49152);
        let living_room_companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![bedroom, living_room_companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "Bedroom");
        assert_eq!(result[0].device_type, DeviceType::Unknown);
        assert_eq!(result[0].product_type, None);
    }

    #[test]
    fn enrich_and_filter_preserves_order_of_non_metadata_entries() {
        let bedroom = unknown_device("Bedroom", REMOTEPAIRING_SERVICE, 1);
        let companion = companion_link_device("Living Room", "AppleTV14,1");
        let living_room = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 2);
        let kitchen = unknown_device("Kitchen", REMOTEPAIRING_SERVICE, 3);

        let result = enrich_and_filter(vec![bedroom, companion, living_room, kitchen]);

        assert_eq!(
            result.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["Bedroom", "Living Room", "Kitchen"]
        );
    }

    fn network_apple_tv(name: &str, service_type: &str, port: u16, ip: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.to_string(),
            udid: None,
            ip_address: Some(ip.to_string()),
            port: Some(port),
            device_type: DeviceType::AppleTV,
            connection_type: ConnectionType::WiFi,
            is_paired: false,
            product_type: Some("AppleTV14,1".to_string()),
            os_version: None,
            service_type: service_type.to_string(),
        }
    }

    #[test]
    fn group_network_devices_only_manual_sets_pairing_port_only() {
        let discovered = [network_apple_tv(
            "Living Room",
            REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
            49153,
            "10.0.0.5",
        )];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].pairing_address,
            Some(("10.0.0.5".parse().unwrap(), 49153))
        );
        assert_eq!(devices[0].reconnect_address, None);
    }

    #[test]
    fn group_network_devices_only_reconnect_sets_reconnect_port_only() {
        let discovered = [network_apple_tv(
            "Living Room",
            REMOTEPAIRING_SERVICE,
            49152,
            "10.0.0.5",
        )];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].reconnect_address,
            Some(("10.0.0.5".parse().unwrap(), 49152))
        );
        assert_eq!(devices[0].pairing_address, None);
    }

    #[test]
    fn group_network_devices_merges_both_service_types_into_one_device() {
        let discovered = [
            network_apple_tv(
                "Living Room",
                REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
                49153,
                "10.0.0.5",
            ),
            network_apple_tv("living room", REMOTEPAIRING_SERVICE, 49152, "10.0.0.5"),
        ];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pairing_address.map(|(_, p)| p), Some(49153));
        assert_eq!(devices[0].reconnect_address.map(|(_, p)| p), Some(49152));
    }

    #[test]
    fn group_network_devices_excludes_non_appletv() {
        let mut d = network_apple_tv("Some iPhone", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");
        d.device_type = DeviceType::IPhone;

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_excludes_non_rppairing_service() {
        let d = network_apple_tv("Living Room", APPLE_MOBDEV2_SERVICE, 62078, "10.0.0.5");

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_keeps_two_different_apple_tvs_separate() {
        let discovered = [
            network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 1, "10.0.0.5"),
            network_apple_tv("Bedroom", REMOTEPAIRING_SERVICE, 2, "10.0.0.6"),
        ];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 2);
        let mut names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["Bedroom", "Living Room"]);
    }

    #[test]
    fn group_network_devices_skips_empty_name() {
        let d = network_apple_tv("", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_skips_unresolved_ip() {
        let mut d = network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");
        d.ip_address = None;

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_sets_synthetic_device_id_and_pairing_identity() {
        let d = network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pairing_identity.as_deref(), Some("Living-Room"));
        assert_eq!(devices[0].device_id, synthetic_device_id("Living-Room"));
        assert_ne!(devices[0].device_id, 0);
    }

    #[test]
    fn group_network_devices_keeps_first_resolved_address_when_entries_share_a_name() {
        let discovered = [
            network_apple_tv(
                "Living Room",
                REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
                49153,
                "10.0.0.5",
            ),
            network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 49152, "10.0.0.9"),
        ];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        // The first entry encountered (the manual-pairing one, listed first above) sets the
        // address; the later reconnect entry for the same device does not override it.
        assert_eq!(
            devices[0].pairing_address.unwrap().0.to_string(),
            "10.0.0.5"
        );
        assert_eq!(
            devices[0].reconnect_address.unwrap().0.to_string(),
            "10.0.0.5"
        );
    }
}
