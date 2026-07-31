use super::{
    ALL_SCANNED_SERVICE_TYPES, DeviceDiscovery, DiscoveredDevice, build_device, enrich_and_filter,
    parse_instance_name, short_hostname,
};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::time::Duration;

/// The service-type constants live in the parent module so every backend shares them; they are
/// re-exported here because callers import them from this path.
pub use super::{
    APPLE_MOBDEV2_SERVICE, APPLE_PAIRABLE_SERVICE, REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
    REMOTEPAIRING_SERVICE,
};

pub struct MdnsDiscovery {
    service_types: Vec<String>,
}

impl MdnsDiscovery {
    pub fn new() -> Self {
        Self {
            service_types: ALL_SCANNED_SERVICE_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl Default for MdnsDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceDiscovery for MdnsDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>> {
        let mdns = ServiceDaemon::new()
            .map_err(|e| crate::Error::Other(format!("Failed to create mDNS daemon: {e}")))?;

        // Browse all service types simultaneously
        let mut receivers = Vec::new();
        for service_type in &self.service_types {
            match mdns.browse(service_type) {
                Ok(receiver) => receivers.push((service_type.clone(), receiver)),
                Err(e) => {
                    log::warn!("Failed to browse {service_type}: {e}");
                }
            }
        }

        let service_types = self.service_types.clone();
        let discovered = tokio::task::spawn_blocking(move || {
            // Keyed by (hostname, service_type): the same physical device can advertise
            // multiple RPPairing service types at once with different ports (e.g. manual
            // pairing vs. an already-established pairing), and those are not interchangeable.
            let mut discovered_devices: HashMap<(String, String), DiscoveredDevice> =
                HashMap::new();
            let deadline = std::time::Instant::now() + timeout;

            // Poll all receivers until timeout
            while std::time::Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                // Short poll interval so we check all receivers fairly
                let poll_time = remaining.min(Duration::from_millis(200));
                let mut got_event = false;

                for (service_type, receiver) in &receivers {
                    match receiver.recv_timeout(poll_time) {
                        Ok(ServiceEvent::ServiceResolved(info)) => {
                            got_event = true;
                            let properties: HashMap<String, String> = info
                                .get_properties()
                                .iter()
                                .map(|p| (p.key().to_string(), p.val_str().to_string()))
                                .collect();

                            let hostname = info.get_hostname();
                            let instance_name =
                                parse_instance_name(info.get_fullname(), service_type);
                            let addresses: Vec<std::net::IpAddr> =
                                info.get_addresses().iter().copied().collect();
                            let port = Some(info.get_port());

                            // Shared with the native Windows backend so both produce identical
                            // `DiscoveredDevice` values.
                            let device = build_device(
                                &instance_name,
                                hostname,
                                service_type,
                                port,
                                &addresses,
                                &properties,
                            );

                            log::debug!(
                                "mDNS resolved: hostname={} service={} ip={:?} port={:?}",
                                hostname,
                                service_type,
                                device.ip_address,
                                port
                            );

                            let key = (
                                short_hostname(hostname).to_ascii_lowercase(),
                                service_type.clone(),
                            );

                            discovered_devices.insert(key, device);
                        }
                        Ok(_) => {
                            got_event = true;
                        }
                        Err(_) => {} // timeout on this receiver, try next
                    }
                }

                if !got_event && poll_time == remaining {
                    break; // final poll expired with no events
                }
            }

            // Stop all browses before dropping to avoid "closed channel" errors
            for stype in &service_types {
                let _ = mdns.stop_browse(stype);
            }
            let _ = mdns.shutdown();

            discovered_devices
        })
        .await
        .map_err(|e| crate::Error::Other(format!("mDNS scan task failed: {e}")))?;

        Ok(enrich_and_filter(discovered.into_values().collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DeviceType;

    #[test]
    fn test_device_type_from_class() {
        assert_eq!(
            DeviceType::from_device_class("AppleTV"),
            DeviceType::AppleTV
        );
        assert_eq!(DeviceType::from_device_class("iPhone"), DeviceType::IPhone);
    }

    #[test]
    fn test_device_type_from_product() {
        assert_eq!(
            DeviceType::from_product_type("AppleTV11,1"),
            DeviceType::AppleTV
        );
        assert_eq!(
            DeviceType::from_product_type("iPhone15,2"),
            DeviceType::IPhone
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_mdns_discovery() {
        let discovery = MdnsDiscovery::new();
        let devices = discovery.discover(Duration::from_secs(5)).await.unwrap();
        println!("Discovered {} devices:", devices.len());
        for device in &devices {
            println!("  - {} ({:?})", device.name, device.device_type);
        }
    }
}
