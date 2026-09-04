use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent};

use crate::Error;

pub const MANUAL_PAIRING_SERVICE: &str = "_remotepairing-manual-pairing._tcp.local.";
pub const REMOTE_PAIRING_SERVICE: &str = "_remotepairing._tcp.local.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// Offering to pair, and will show a PIN when connected to.
    ManualPairing,
    /// Already paired, though not necessarily with this host.
    RemotePairing,
}

impl ServiceKind {
    fn service_type(self) -> &'static str {
        match self {
            Self::ManualPairing => MANUAL_PAIRING_SERVICE,
            Self::RemotePairing => REMOTE_PAIRING_SERVICE,
        }
    }
}

impl std::fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManualPairing => write!(f, "pairable"),
            Self::RemotePairing => write!(f, "paired"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub kind: ServiceKind,
    pub service_name: String,
    pub hostname: String,
    pub name: Option<String>,
    pub identifier: Option<String>,
    pub auth_tag: Option<String>,
    pub address: SocketAddr,
}

impl DiscoveredDevice {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.hostname)
    }

    fn from_resolved(kind: ServiceKind, service: &ResolvedService) -> Option<Self> {
        if !service.is_valid() {
            return None;
        }

        Some(Self {
            kind,
            service_name: service.get_fullname().to_string(),
            hostname: trim_local(service.get_hostname()),
            name: txt(service, "name"),
            identifier: txt(service, "identifier"),
            auth_tag: txt(service, "authTag"),
            address: best_address(service)?,
        })
    }
}

impl std::fmt::Display for DiscoveredDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} ({})",
            self.kind,
            self.display_name(),
            self.address
        )
    }
}

/// Browses both RemotePairing services for `timeout` and returns everything seen.
pub async fn discover(timeout: Duration) -> Result<Vec<DiscoveredDevice>, Error> {
    let daemon = ServiceDaemon::new()?;

    let browses = [
        (
            ServiceKind::ManualPairing,
            daemon.browse(ServiceKind::ManualPairing.service_type())?,
        ),
        (
            ServiceKind::RemotePairing,
            daemon.browse(ServiceKind::RemotePairing.service_type())?,
        ),
    ];

    // Keyed by service name so devices re-announcing every few seconds collapse
    // into one entry.
    let mut found: HashMap<String, DiscoveredDevice> = HashMap::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let (kind, event) = tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            event = browses[0].1.recv_async() => (browses[0].0, event),
            event = browses[1].1.recv_async() => (browses[1].0, event),
        };

        // Both receivers share a daemon, so a closed channel means neither will
        // produce anything further.
        let Ok(event) = event else { break };

        match event {
            ServiceEvent::ServiceResolved(service) => {
                if let Some(device) = DiscoveredDevice::from_resolved(kind, &service) {
                    found.insert(device.service_name.clone(), device);
                }
            }
            ServiceEvent::ServiceRemoved(_, service_name) => {
                found.remove(&service_name);
            }
            _ => {}
        }
    }

    if let Err(e) = daemon.shutdown() {
        log::debug!("failed to shut down mDNS daemon: {e}");
    }

    let mut devices: Vec<_> = found.into_values().collect();
    devices.sort_by(|a, b| {
        a.display_name()
            .cmp(b.display_name())
            .then_with(|| a.service_name.cmp(&b.service_name))
    });

    Ok(devices)
}

fn txt(service: &ResolvedService, key: &str) -> Option<String> {
    service
        .get_property_val_str(key)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn trim_local(hostname: &str) -> String {
    hostname
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

fn best_address(service: &ResolvedService) -> Option<SocketAddr> {
    let port = service.get_port();

    // Addresses arrive in a HashSet, so take the lowest rather than the first
    // iterated to keep repeated scans stable.
    let mut v4: Vec<Ipv4Addr> = service
        .get_addresses()
        .iter()
        .filter_map(|ip| match ip {
            ScopedIp::V4(v4) => Some(*v4.addr()),
            _ => None,
        })
        .filter(|addr| !addr.is_loopback() && !addr.is_unspecified())
        .collect();
    v4.sort();

    if let Some(addr) = v4.first() {
        return Some(SocketAddr::new(IpAddr::V4(*addr), port));
    }

    // Link-local v6 is only routable with the scope id of the interface it was
    // discovered on.
    let mut v6: Vec<SocketAddrV6> = service
        .get_addresses()
        .iter()
        .filter_map(|ip| match ip {
            ScopedIp::V6(v6) => Some(v6),
            _ => None,
        })
        .filter(|v6| !v6.addr().is_loopback() && !v6.addr().is_unspecified())
        .map(|v6| SocketAddrV6::new(*v6.addr(), port, 0, v6.scope_id().index))
        .collect();
    v6.sort();

    v6.into_iter().next().map(SocketAddr::V6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_local_strips_mdns_suffix() {
        assert_eq!(trim_local("Living-Room.local."), "Living-Room");
        assert_eq!(trim_local("Living-Room.local"), "Living-Room");
        assert_eq!(trim_local("Living-Room"), "Living-Room");
    }

    #[test]
    fn service_kinds_map_to_distinct_types() {
        assert_ne!(
            ServiceKind::ManualPairing.service_type(),
            ServiceKind::RemotePairing.service_type()
        );
    }
}
