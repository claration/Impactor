use iced::futures::StreamExt;
use iced::widget::{button, column, container, pick_list, row, rule, scrollable, text, text_input};
use iced::{Center, Color, Element, Fill, Task};
use plume_utils::Device;
use plume_utils::discovery::{
    DeviceDiscovery, DeviceType, DiscoveredDevice, PlatformDiscovery,
    REMOTEPAIRING_MANUAL_PAIRING_SERVICE, REMOTEPAIRING_SERVICE,
};
use std::time::Duration;

use crate::appearance;
use crate::defaults::get_data_path;

#[derive(Debug, Clone)]
struct StatusMessage {
    content: String,
    is_error: bool,
}

impl StatusMessage {
    fn success(s: impl Into<String>) -> Self {
        Self {
            content: s.into(),
            is_error: false,
        }
    }
    fn error(s: impl Into<String>) -> Self {
        Self {
            content: s.into(),
            is_error: true,
        }
    }
    fn info(s: impl Into<String>) -> Self {
        Self {
            content: s.into(),
            is_error: false,
        }
    }
    fn color(&self) -> Color {
        if self.is_error {
            Color::from_rgb(0.9, 0.2, 0.2)
        } else {
            Color::from_rgb(0.2, 0.8, 0.4)
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Scan,
    ScanComplete(Result<Vec<DiscoveredDevice>, String>),
    SelectDevice(String),
    PinChanged(String),
    Pair,
    Reconnect,
    PinRequested(bool),
    SubmitPin,
    CancelPin,
    PairComplete(Result<Device, String>),
    ReconnectComplete(Result<Device, String>),
    Forget,
    ForgetComplete(Result<Device, String>),
    StartOver,
}

#[derive(Debug, Clone)]
pub struct TvOsPairingScreen {
    discovered: Vec<DiscoveredDevice>,
    selected_label: Option<String>,
    pin: String,
    scanning: bool,
    pairing: bool,
    reconnecting: bool,
    awaiting_pin: bool,
    pin_sender: Option<std::sync::mpsc::SyncSender<String>>,
    status: Option<StatusMessage>,
    paired_device: Option<Device>,
}

impl TvOsPairingScreen {
    pub fn new() -> Self {
        Self {
            discovered: Vec::new(),
            selected_label: None,
            pin: String::new(),
            scanning: false,
            pairing: false,
            reconnecting: false,
            awaiting_pin: false,
            pin_sender: None,
            status: None,
            paired_device: None,
        }
    }

    fn device_label(device: &DiscoveredDevice) -> String {
        let host = if device.hostname.is_empty() {
            device.name.replace(' ', "-")
        } else {
            device.hostname.clone()
        };
        format!("[WiFi] {} (tvOS) ({host})", device.name)
    }

    fn selected_label(&self) -> Option<&str> {
        self.selected_label.as_deref()
    }

    fn selected_device(&self) -> Option<&DiscoveredDevice> {
        let label = self.selected_label()?;
        self.discovered
            .iter()
            .find(|device| Self::device_label(device) == label)
    }

    fn manual_pairing_entry(&self) -> Option<&DiscoveredDevice> {
        let label = self.selected_label()?;
        self.discovered.iter().find(|d| {
            Self::device_label(d) == label
                && d.service_type == REMOTEPAIRING_MANUAL_PAIRING_SERVICE
        })
    }

    fn pairing_identity(device: &DiscoveredDevice) -> String {
        if device.hostname.is_empty() {
            device.name.replace(' ', "-")
        } else {
            device.hostname.clone()
        }
    }

    fn reconnect_entry(&self) -> Option<&DiscoveredDevice> {
        let label = self.selected_label()?;
        self.discovered
            .iter()
            .find(|d| Self::device_label(d) == label && d.service_type == REMOTEPAIRING_SERVICE)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Scan => {
                self.scanning = true;
                self.status = Some(StatusMessage::info("Scanning for Apple TVs..."));
                self.discovered.clear();
                self.selected_label = None;
                self.pin.clear();

                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let result: Result<Vec<DiscoveredDevice>, String> = rt.block_on(async {
                        PlatformDiscovery::new()
                            .discover(Duration::from_secs(5))
                            .await
                            .map_err(|e| format!("Scan failed: {e}"))
                    });
                    let _ = tx.send(result);
                });

                Task::perform(
                    async move {
                        std::thread::spawn(move || {
                            rx.recv().unwrap_or_else(|_| Err("Scan error".to_string()))
                        })
                        .join()
                        .unwrap()
                    },
                    Message::ScanComplete,
                )
            }

            Message::ScanComplete(result) => {
                self.scanning = false;
                match result {
                    Ok(devices) => {
                        self.discovered = devices
                            .into_iter()
                            .filter(|d| d.device_type == DeviceType::AppleTV)
                            .collect();
                        let tv_count = self
                            .discovered
                            .iter()
                            .map(Self::device_label)
                            .collect::<std::collections::HashSet<_>>()
                            .len();
                        if tv_count == 0 {
                            self.status =
                                Some(StatusMessage::info("No Apple TVs found on this network."));
                        } else {
                            self.status = Some(StatusMessage::info(format!(
                                "Found {} Apple TV(s). Select one to pair.",
                                tv_count
                            )));
                        }
                    }
                    Err(e) => {
                        self.status = Some(StatusMessage::error(e));
                    }
                }
                Task::none()
            }

            Message::SelectDevice(label) => {
                self.selected_label = Some(label);
                self.pin.clear();
                self.status = None;
                Task::none()
            }

            Message::PinChanged(s) => {
                self.pin = s.chars().filter(|c| c.is_ascii_digit()).take(6).collect();
                Task::none()
            }

            Message::Pair => {
                let Some(dev) = self.manual_pairing_entry() else {
                    self.status = Some(StatusMessage::error(
                        "This Apple TV isn't showing a pairing PIN. On the Apple TV, open \
                         Settings > Remotes and Devices > Remote App and Devices, wait for \
                         \"Waiting to Pair...\", then Scan again.",
                    ));
                    return Task::none();
                };

                let ip_str = match &dev.ip_address {
                    Some(s) => s.clone(),
                    None => {
                        self.status =
                            Some(StatusMessage::error("Selected device has no IP address."));
                        return Task::none();
                    }
                };
                let pairing_port = match dev.port {
                    Some(p) => p,
                    None => {
                        self.status = Some(StatusMessage::error("Selected device has no port."));
                        return Task::none();
                    }
                };
                let reconnect_address = self.reconnect_entry().and_then(|device| {
                    let ip = device.ip_address.as_deref()?.parse().ok()?;
                    Some((ip, device.port?))
                });

                let name = dev.name.clone();
                let hostname = Self::pairing_identity(dev);
                let cache_dir = get_data_path();

                self.pin.clear();
                self.awaiting_pin = false;
                self.pairing = true;
                self.status = Some(StatusMessage::info("Connecting to Apple TV..."));

                let (pin_req_tx, mut pin_req_rx) = iced::futures::channel::mpsc::unbounded::<()>();
                let (result_tx, mut result_rx) =
                    iced::futures::channel::mpsc::unbounded::<Result<Device, String>>();
                let (pin_resp_tx, pin_resp_rx) = std::sync::mpsc::sync_channel::<String>(1);
                self.pin_sender = Some(pin_resp_tx);
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let pin_resp_rx = std::sync::Arc::new(std::sync::Mutex::new(pin_resp_rx));
                    let result = rt.block_on(async move {
                        let ip: std::net::IpAddr =
                            ip_str.parse().map_err(|e| format!("Invalid IP: {e}"))?;
                        let mut device = Device::new_tvos_with_addresses(
                            name,
                            hostname,
                            Some((ip, pairing_port)),
                            reconnect_address,
                            cache_dir.clone(),
                        );
                        device
                            .pair_tvos(
                                move || {
                                    let pin_req_tx = pin_req_tx.clone();
                                    let pin_resp_rx = pin_resp_rx.clone();
                                    async move {
                                        let _ = pin_req_tx.unbounded_send(());
                                        let Ok(rx) = pin_resp_rx.lock() else {
                                            return String::new();
                                        };
                                        rx.recv_timeout(Duration::from_secs(180))
                                            .unwrap_or_default()
                                    }
                                },
                                cache_dir.clone(),
                            )
                            .await
                            .map_err(|e| format!("{e}"))?;
                        let info = device
                            .fetch_tvos_info(cache_dir)
                            .await
                            .map_err(|e| format!("{e}"))?;
                        device.apply_tvos_info(&info);
                        if !plume_utils::is_valid_device_udid(&device.udid) {
                            return Err(
                                "Apple TV pairing succeeded but its authenticated UDID was not returned"
                                    .to_string(),
                            );
                        }
                        Ok(device)
                    });
                    let _ = result_tx.unbounded_send(result);
                });

                Task::batch([
                    Task::perform(
                        async move {
                            result_rx
                                .next()
                                .await
                                .unwrap_or_else(|| Err("Pairing thread error".to_string()))
                        },
                        Message::PairComplete,
                    ),
                    Task::perform(
                        async move { pin_req_rx.next().await.is_some() },
                        Message::PinRequested,
                    ),
                ])
            }

            Message::Reconnect => {
                let Some(dev) = self.reconnect_entry() else {
                    self.status = Some(StatusMessage::error(
                        "This Apple TV is not advertising its reconnect service.",
                    ));
                    return Task::none();
                };
                let Some(ip_str) = dev.ip_address.clone() else {
                    self.status = Some(StatusMessage::error(
                        "Selected device has no IP address.",
                    ));
                    return Task::none();
                };
                let Some(reconnect_port) = dev.port else {
                    self.status = Some(StatusMessage::error("Selected device has no port."));
                    return Task::none();
                };
                let name = dev.name.clone();
                let identity = Self::pairing_identity(dev);
                let cache_dir = get_data_path();
                self.reconnecting = true;
                self.status = Some(StatusMessage::info("Reconnecting to Apple TV..."));

                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                std::thread::spawn(move || {
                    let result = tokio::runtime::Runtime::new()
                        .unwrap()
                        .block_on(async move {
                            let ip = ip_str
                                .parse()
                                .map_err(|error| format!("Invalid IP address: {error}"))?;
                            let mut device = Device::new_tvos(
                                name,
                                identity,
                                ip,
                                None,
                                Some(reconnect_port),
                                cache_dir.clone(),
                            );
                            if !device.has_pairing_source(&cache_dir) {
                                return Err(
                                    "No saved pairing record exists for this Apple TV. Pair it first."
                                        .to_string(),
                                );
                            }
                            let info = device
                                .fetch_tvos_info(cache_dir)
                                .await
                                .map_err(|error| format!("{error}"))?;
                            device.apply_tvos_info(&info);
                            if !plume_utils::is_valid_device_udid(&device.udid) {
                                return Err(
                                    "Apple TV reconnected but its authenticated UDID was not returned"
                                        .to_string(),
                                );
                            }
                            Ok(device)
                        });
                    let _ = tx.send(result);
                });

                Task::perform(
                    async move {
                        std::thread::spawn(move || {
                            rx.recv()
                                .unwrap_or_else(|_| Err("Reconnect thread error".to_string()))
                        })
                        .join()
                        .unwrap()
                    },
                    Message::ReconnectComplete,
                )
            }

            Message::PinRequested(requested) => {
                if requested {
                    self.awaiting_pin = true;
                    self.status =
                        Some(StatusMessage::info("Enter the code shown on your Apple TV"));
                }
                Task::none()
            }

            Message::SubmitPin => {
                if self.pin.len() != 6 {
                    return Task::none();
                }
                if let Some(tx) = self.pin_sender.as_ref() {
                    let _ = tx.try_send(self.pin.clone());
                }
                self.awaiting_pin = false;
                self.status = Some(StatusMessage::info("Verifying..."));
                Task::none()
            }

            Message::CancelPin => {
                if let Some(tx) = self.pin_sender.as_ref() {
                    let _ = tx.try_send(String::new());
                }
                self.awaiting_pin = false;
                self.status = Some(StatusMessage::info("Cancelling pairing..."));
                Task::none()
            }

            Message::PairComplete(result) => {
                self.pairing = false;
                self.awaiting_pin = false;
                self.pin_sender = None;
                match result {
                    Ok(device) => {
                        self.paired_device = Some(device);
                        self.status = Some(StatusMessage::success("Paired successfully."));
                        self.pin.clear();
                    }
                    Err(e) => {
                        self.status = Some(StatusMessage::error(e));
                    }
                }
                Task::none()
            }

            Message::ReconnectComplete(result) => {
                self.reconnecting = false;
                match result {
                    Ok(device) => {
                        self.paired_device = Some(device);
                        self.status = Some(StatusMessage::success("Reconnected successfully."));
                    }
                    Err(error) => self.status = Some(StatusMessage::error(error)),
                }
                Task::none()
            }

            Message::Forget => {
                let cache_dir = get_data_path();
                let device = if let Some(device) = self.paired_device.clone() {
                    device
                } else {
                    let Some(discovered) = self.selected_device().cloned() else {
                        self.status = Some(StatusMessage::error("Select an Apple TV first."));
                        return Task::none();
                    };
                    let identity = Self::pairing_identity(&discovered);
                    Device::new_tvos(
                        discovered.name,
                        identity,
                        "0.0.0.0".parse().unwrap(),
                        None,
                        None,
                        cache_dir.clone(),
                    )
                };
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                std::thread::spawn(move || {
                    let result = tokio::runtime::Runtime::new()
                        .unwrap()
                        .block_on(device.forget_tvos_pairing(cache_dir))
                        .map(|_| device)
                        .map_err(|e| format!("{e}"));
                    let _ = tx.send(result);
                });
                self.status = Some(StatusMessage::info("Removing Apple TV pairing..."));
                Task::perform(
                    async move {
                        std::thread::spawn(move || {
                            rx.recv()
                                .unwrap_or_else(|_| Err("Forget thread error".to_string()))
                        })
                        .join()
                        .unwrap()
                    },
                    Message::ForgetComplete,
                )
            }

            Message::ForgetComplete(result) => {
                match result {
                    Ok(_) => {
                        self.paired_device = None;
                        self.status = Some(StatusMessage::success(
                            "Host pairing removed. The Apple TV may reconnect without a PIN until its remote devices are forgotten.",
                        ));
                    }
                    Err(error) => self.status = Some(StatusMessage::error(error)),
                }
                Task::none()
            }

            Message::StartOver => {
                self.paired_device = None;
                self.discovered.clear();
                self.selected_label = None;
                self.pin.clear();
                self.awaiting_pin = false;
                self.pin_sender = None;
                self.reconnecting = false;
                self.status = None;
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let content = match &self.paired_device {
            Some(device) => self.view_paired(device),
            None => self.view_pairing(),
        };

        container(scrollable(content.spacing(appearance::THEME_PADDING))).into()
    }

    fn view_pairing(&self) -> iced::widget::Column<'_, Message> {
        let mut content = column![];

        let scan_label = if self.scanning {
            "Scanning..."
        } else {
            "Scan for Apple TVs"
        };
        content = content.push(
            button(text(scan_label).align_x(Center))
                .on_press_maybe(if self.scanning {
                    None
                } else {
                    Some(Message::Scan)
                })
                .style(appearance::s_button)
                .width(Fill),
        );

        if let Some(ref s) = self.status {
            content = content.push(text(&s.content).size(13).color(s.color()));
        }

        if !self.discovered.is_empty() {
            content = content
                .push(container(rule::horizontal(1)).padding([appearance::THEME_PADDING, 0.0]));

            let mut device_labels: Vec<String> = self
                .discovered
                .iter()
                .filter(|d| d.device_type == DeviceType::AppleTV)
                .map(Self::device_label)
                .collect();
            device_labels.sort();
            device_labels.dedup();

            content = content.push(
                pick_list(
                    device_labels,
                    self.selected_label.clone(),
                    Message::SelectDevice,
                )
                .placeholder("Select an Apple TV")
                .width(Fill),
            );
        }

        if self.selected_label.is_some() && !self.awaiting_pin {
            let pair_label = if self.pairing { "Pairing..." } else { "Pair" };
            if self.manual_pairing_entry().is_some() {
                content = content.push(
                    button(text(pair_label).align_x(Center))
                        .on_press_maybe(if self.pairing || self.reconnecting {
                            None
                        } else {
                            Some(Message::Pair)
                        })
                        .style(appearance::p_button)
                        .width(Fill),
                );
            }
            if self.reconnect_entry().is_some() {
                let reconnect_label = if self.reconnecting {
                    "Reconnecting..."
                } else {
                    "Reconnect"
                };
                content = content.push(
                    button(text(reconnect_label).align_x(Center))
                        .on_press_maybe(if self.pairing || self.reconnecting {
                            None
                        } else {
                            Some(Message::Reconnect)
                        })
                        .style(appearance::s_button)
                        .width(Fill),
                );
            }
        }

        if self.awaiting_pin {
            content = content
                .push(container(rule::horizontal(1)).padding([appearance::THEME_PADDING, 0.0]));
            content = content.push(text("Enter the 6-digit code shown on your Apple TV:").size(13));
            content = content.push(
                row![
                    text_input("123456", &self.pin)
                        .on_input(Message::PinChanged)
                        .on_submit_maybe(if self.pin.len() == 6 {
                            Some(Message::SubmitPin)
                        } else {
                            None
                        })
                        .width(iced::Length::Fixed(120.0)),
                    button(text("Submit").align_x(Center))
                        .on_press_maybe(if self.pin.len() == 6 {
                            Some(Message::SubmitPin)
                        } else {
                            None
                        })
                        .style(appearance::p_button)
                ]
                .spacing(appearance::THEME_PADDING)
                .align_y(Center),
            );
            content = content.push(
                button(text("Cancel").align_x(Center))
                    .on_press(Message::CancelPin)
                    .style(appearance::s_button)
                    .width(Fill),
            );
        }

        content
    }

    fn view_paired(&self, device: &Device) -> iced::widget::Column<'_, Message> {
        let mut content = column![];

        content = content
            .push(text(format!("Paired with {}", device.name)).size(appearance::THEME_FONT_SIZE + 2.0));

        content = content.push(
            text(format!(
                "{} · {} · UDID {}",
                device.product_type.as_deref().unwrap_or("Apple TV"),
                device.os_version.as_deref().unwrap_or("tvOS"),
                device.udid
            ))
            .size(13),
        );

        content = content.push(
            text(
                "This Apple TV is now selectable in the device list at the top of the window. \
                 To install to it, import an IPA from the main screen the same way you would \
                 for any other device. Forgetting here removes Impactor's local pairing record; \
                 use the Apple TV's Forget All Remote Devices option to require a new PIN.",
            )
            .size(13),
        );

        if let Some(ref s) = self.status {
            content = content.push(text(&s.content).size(13).color(s.color()));
        }

        content =
            content.push(container(rule::horizontal(1)).padding([appearance::THEME_PADDING, 0.0]));
        content = content.push(
            button(text("Pair a Different Apple TV").align_x(Center))
                .on_press(Message::StartOver)
                .style(appearance::s_button)
                .width(Fill),
        );
        content = content.push(
            button(text("Forget Host Pairing").align_x(Center))
                .on_press(Message::Forget)
                .style(appearance::s_button)
                .width(Fill),
        );

        content
    }
}
