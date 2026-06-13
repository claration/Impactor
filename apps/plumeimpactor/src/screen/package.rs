use iced::widget::{
    button, checkbox, column, container, image, pick_list, row, scrollable, stack, text, text_input,
};
use iced::{Alignment, Center, Element, Fill, Task};
use plume_utils::{Package, PlistInfoTrait, SignerInstallMode, SignerMode, SignerOptions};
use rust_i18n::t;
use std::path::PathBuf;
use tiny_skia::{FillRule, Mask, Path, PathBuilder, Transform};

use crate::appearance;

#[derive(Debug, Clone)]
pub enum Message {
    UpdateCustomName(String),
    UpdateCustomIdentifier(String),
    UpdateCustomVersion(String),
    ToggleMinimumOsVersion(bool),
    ToggleFileSharing(bool),
    ToggleIpadFullscreen(bool),
    ToggleGameMode(bool),
    ToggleProMotion(bool),
    ToggleSingleProfile(bool),
    ToggleLiquidGlass(bool),
    ToggleRefresh(bool),
    ToggleElleKit(bool),
    UpdateSignerMode(SignerMode),
    UpdateInstallMode(SignerInstallMode),
    AddTweak,
    AddBundle,
    RemoveTweak(usize),
    SetCustomIcon,
    ClearCustomIcon,
    SetCustomEntitlements,
    ClearCustomEntitlements,
    Back,
    RequestInstallation,
}

#[derive(Debug, Clone)]
pub struct PackageScreen {
    pub selected_package: Option<Package>,
    pub options: SignerOptions,
    package_icon_handle: Option<image::Handle>,
    custom_icon_path: Option<PathBuf>,
    custom_icon_handle: Option<image::Handle>,
}

impl PackageScreen {
    pub fn new(package: Option<Package>, options: SignerOptions) -> Self {
        let package_icon_handle = package
            .as_ref()
            .and_then(|p| p.app_icon_data.as_ref())
            .and_then(|data| icon_handle_from_bytes(data));

        let custom_icon_path = options.custom_icon.clone();
        let custom_icon_handle = custom_icon_path.as_ref().and_then(icon_handle_from_path);

        Self {
            selected_package: package,
            options,
            package_icon_handle,
            custom_icon_path,
            custom_icon_handle,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::UpdateCustomName(name) => {
                let pkg_name = self
                    .selected_package
                    .as_ref()
                    .and_then(|p| p.get_name())
                    .unwrap_or_default();

                if name != pkg_name {
                    self.options.custom_name = Some(name);
                } else {
                    self.options.custom_name = None;
                }
                Task::none()
            }
            Message::UpdateCustomIdentifier(id) => {
                let pkg_id = self
                    .selected_package
                    .as_ref()
                    .and_then(|p| p.get_bundle_identifier())
                    .unwrap_or_default();

                if id != pkg_id {
                    self.options.custom_identifier = Some(id);
                } else {
                    self.options.custom_identifier = None;
                }
                Task::none()
            }
            Message::UpdateCustomVersion(ver) => {
                let pkg_ver = self
                    .selected_package
                    .as_ref()
                    .and_then(|p| p.get_version())
                    .unwrap_or_default();

                if ver != pkg_ver {
                    self.options.custom_version = Some(ver);
                } else {
                    self.options.custom_version = None;
                }
                Task::none()
            }
            Message::ToggleMinimumOsVersion(value) => {
                self.options.features.support_minimum_os_version = value;
                Task::none()
            }
            Message::ToggleFileSharing(value) => {
                self.options.features.support_file_sharing = value;
                Task::none()
            }
            Message::ToggleIpadFullscreen(value) => {
                self.options.features.support_ipad_fullscreen = value;
                Task::none()
            }
            Message::ToggleGameMode(value) => {
                self.options.features.support_game_mode = value;
                Task::none()
            }
            Message::ToggleProMotion(value) => {
                self.options.features.support_pro_motion = value;
                Task::none()
            }
            Message::ToggleSingleProfile(value) => {
                self.options.embedding.single_profile = value;
                Task::none()
            }
            Message::ToggleLiquidGlass(value) => {
                self.options.features.support_liquid_glass = value;
                Task::none()
            }
            Message::ToggleRefresh(value) => {
                self.options.refresh = value;
                Task::none()
            }
            Message::ToggleElleKit(value) => {
                self.options.features.support_ellekit = value;
                Task::none()
            }
            Message::UpdateSignerMode(mode) => {
                self.options.mode = mode;
                Task::none()
            }
            Message::UpdateInstallMode(mode) => {
                self.options.install_mode = mode;
                Task::none()
            }
            Message::AddTweak => {
                let path = rfd::FileDialog::new()
                    .add_filter("Tweak files", &["deb", "dylib"])
                    .set_title("Select Tweak File")
                    .pick_file();

                if let Some(path) = path {
                    match &mut self.options.tweaks {
                        Some(vec) => vec.push(path),
                        None => self.options.tweaks = Some(vec![path]),
                    }
                }

                Task::none()
            }
            Message::AddBundle => {
                let path = rfd::FileDialog::new()
                    .set_title("Select Bundle Folder")
                    .pick_folder();

                if let Some(path) = path {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ["framework", "bundle", "appex"].contains(&ext) {
                            match &mut self.options.tweaks {
                                Some(vec) => vec.push(path),
                                None => self.options.tweaks = Some(vec![path]),
                            }
                        }
                    }
                }

                Task::none()
            }
            Message::RemoveTweak(index) => {
                if let Some(tweaks) = &mut self.options.tweaks {
                    if index < tweaks.len() {
                        tweaks.remove(index);
                    }
                }
                Task::none()
            }
            Message::SetCustomIcon => {
                let path = rfd::FileDialog::new()
                    .add_filter("Image files", &["png", "jpg", "jpeg"])
                    .set_title("Select App Icon")
                    .pick_file();

                if let Some(path) = path {
                    self.options.custom_icon = Some(path.clone());
                    self.custom_icon_path = Some(path.clone());
                    self.custom_icon_handle = icon_handle_from_path(&path);
                }

                Task::none()
            }
            Message::ClearCustomIcon => {
                self.options.custom_icon = None;
                self.custom_icon_path = None;
                self.custom_icon_handle = None;
                Task::none()
            }
            Message::SetCustomEntitlements => {
                let path = rfd::FileDialog::new()
                    .add_filter("Entitlements plist", &["plist", "xml"])
                    .set_title("Select Entitlements File")
                    .pick_file();

                if let Some(path) = path {
                    self.options.custom_entitlements = Some(path);
                }

                Task::none()
            }
            Message::ClearCustomEntitlements => {
                self.options.custom_entitlements = None;
                Task::none()
            }
            _ => Task::none(),
        }
    }

    pub fn view(&self, has_device: bool) -> Element<'_, Message> {
        let Some(pkg) = &self.selected_package else {
            return self.view_no_package();
        };

        let content = scrollable(
            row![
                self.view_package_info_column(pkg),
                self.view_options_column()
            ]
            .spacing(appearance::THEME_PADDING),
        );

        column![
            container(content).width(Fill).height(Fill),
            self.view_buttons(has_device)
        ]
        .spacing(appearance::THEME_PADDING)
        .into()
    }

    fn view_no_package(&self) -> Element<'_, Message> {
        column![
            text(t!("options_no_package")).size(32),
            text(t!("options_go_back_and_get_package")).size(16),
        ]
        .spacing(appearance::THEME_PADDING)
        .align_x(Center)
        .into()
    }

    fn view_package_info_column(&self, pkg: &Package) -> Element<'_, Message> {
        let pkg_name = pkg.get_name().unwrap_or_default();
        let pkg_id = pkg.get_bundle_identifier().unwrap_or_default();
        let pkg_ver = pkg.get_version().unwrap_or_default();

        column![
            row![
                self.view_custom_icon(),
                column![
                    text(t!("options_name")).size(12),
                    text_input(
                        "example",
                        self.options.custom_name.as_ref().unwrap_or(&pkg_name)
                    )
                    .on_input(Message::UpdateCustomName)
                    .padding(8),
                ]
                .spacing(8),
            ]
            .spacing(8),
            text(t!("options_identifier")).size(12),
            text_input(
                "com.example.app",
                self.options.custom_identifier.as_ref().unwrap_or(&pkg_id)
            )
            .on_input(Message::UpdateCustomIdentifier)
            .padding(8),
            text(t!("options_version")).size(12),
            text_input(
                "1.0.0",
                self.options.custom_version.as_ref().unwrap_or(&pkg_ver)
            )
            .on_input(Message::UpdateCustomVersion)
            .padding(8),
            text(t!("options_entitlements")).size(12),
            self.view_custom_entitlements(),
            text(t!("options_entitlements_warn")).size(11),
            text(t!("options_tweaks")).size(12),
            self.view_tweaks(),
            row![
                button(appearance::icon_text(
                    appearance::PLUS,
                    t!("options_add_tweak"),
                    None
                ))
                .on_press(Message::AddTweak)
                .style(appearance::s_button),
                button(appearance::icon_text(
                    appearance::PLUS,
                    t!("options_add_bundle"),
                    None
                ))
                .on_press(Message::AddBundle)
                .style(appearance::s_button),
            ]
            .spacing(8),
        ]
        .spacing(8)
        .width(Fill)
        .into()
    }

    fn view_options_column(&self) -> Element<'_, Message> {
        column![
            text(t!("options_general")).size(12),
            checkbox(self.options.features.support_minimum_os_version)
                .label(t!("options_support_versions"))
                .on_toggle(Message::ToggleMinimumOsVersion),
            checkbox(self.options.features.support_file_sharing)
                .label(t!("options_file_sharing"))
                .on_toggle(Message::ToggleFileSharing),
            checkbox(self.options.features.support_ipad_fullscreen)
                .label(t!("options_ipad_fullscreen"))
                .on_toggle(Message::ToggleIpadFullscreen),
            checkbox(self.options.features.support_game_mode)
                .label(t!("options_game_mode"))
                .on_toggle(Message::ToggleGameMode),
            checkbox(self.options.features.support_pro_motion)
                .label(t!("options_pro_motion"))
                .on_toggle(Message::ToggleProMotion),
            text(t!("options_advanced")).size(12),
            checkbox(self.options.embedding.single_profile)
                .label(t!("options_register_main_bundle"))
                .on_toggle(Message::ToggleSingleProfile),
            checkbox(self.options.features.support_liquid_glass)
                .label(t!("options_liquid_glass"))
                .on_toggle(Message::ToggleLiquidGlass),
            checkbox(self.options.features.support_ellekit)
                .label(t!("options_ellekit"))
                .on_toggle(Message::ToggleElleKit),
            checkbox(self.options.refresh)
                .label(t!("options_auto_refresh"))
                .on_toggle(Message::ToggleRefresh),
            text(t!("options_mode")).size(12),
            pick_list(
                &[SignerInstallMode::Install, SignerInstallMode::Export][..],
                Some(self.options.install_mode),
                Message::UpdateInstallMode
            )
            .style(appearance::s_pick_list)
            .placeholder(t!("options_mode_desc")),
            text(t!("options_signing")).size(12),
            pick_list(
                &[SignerMode::Pem, SignerMode::Adhoc, SignerMode::None][..],
                Some(self.options.mode),
                Message::UpdateSignerMode
            )
            .style(appearance::s_pick_list)
            .placeholder(t!("options_signing_desc")),
        ]
        .spacing(8)
        .width(Fill)
        .into()
    }

    fn view_buttons(&self, has_device: bool) -> Element<'_, Message> {
        let (button_enabled, button_label) = match self.options.install_mode {
            SignerInstallMode::Install => (has_device, t!("install")),
            SignerInstallMode::Export => (true, t!("export")),
        };

        container(
            row![
                button(appearance::icon_text(
                    appearance::CHEVRON_BACK,
                    t!("back"),
                    None
                ))
                .on_press(Message::Back)
                .style(appearance::s_button)
                .width(Fill),
                button(appearance::icon_text(
                    appearance::DOWNLOAD,
                    button_label,
                    None
                ))
                .on_press_maybe(button_enabled.then_some(Message::RequestInstallation))
                .style(appearance::p_button)
                .width(Fill),
            ]
            .spacing(appearance::THEME_PADDING),
        )
        .width(Fill)
        .into()
    }

    fn view_custom_entitlements(&self) -> Element<'_, Message> {
        let enabled = self.options.embedding.single_profile;

        let ent_name = self
            .options
            .custom_entitlements
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("No entitlements file");

        let label_color = if enabled {
            iced::Color::WHITE
        } else {
            iced::Color::from_rgb(0.5, 0.5, 0.5)
        };

        row![
            text(ent_name).size(12).width(Fill).color(label_color),
            button(appearance::icon(appearance::PLUS))
                .on_press_maybe(enabled.then_some(Message::SetCustomEntitlements))
                .style(appearance::s_button),
            button(appearance::icon(appearance::MINUS))
                .on_press_maybe(
                    (enabled && self.options.custom_entitlements.is_some())
                        .then_some(Message::ClearCustomEntitlements)
                )
                .style(appearance::s_button)
                .padding(6),
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
    }

    fn view_custom_icon(&self) -> Element<'_, Message> {
        let has_custom = self.custom_icon_path.is_some();

        const ICON_SIZE: f32 = 56.0;

        let loading_indicator = container(text("⏳"))
            .width(ICON_SIZE)
            .height(ICON_SIZE)
            .align_x(Center)
            .align_y(Center);

        let preview: Element<'_, Message> = if let Some(handle) = &self.custom_icon_handle {
            container(stack![
                loading_indicator,
                image(handle.clone()).width(ICON_SIZE).height(ICON_SIZE)
            ])
            .width(ICON_SIZE)
            .height(ICON_SIZE)
            .align_x(Center)
            .align_y(Center)
            .into()
        } else if let Some(handle) = &self.package_icon_handle {
            container(stack![
                loading_indicator,
                image(handle.clone()).width(ICON_SIZE).height(ICON_SIZE)
            ])
            .width(ICON_SIZE)
            .height(ICON_SIZE)
            .align_x(Center)
            .align_y(Center)
            .into()
        } else {
            container(text("No icon").size(11))
                .width(ICON_SIZE)
                .height(ICON_SIZE)
                .align_x(Center)
                .align_y(Center)
                .into()
        };

        let on_press = if has_custom {
            Message::ClearCustomIcon
        } else {
            Message::SetCustomIcon
        };

        button(preview)
            .on_press(on_press)
            .style(appearance::s_button)
            .padding(0)
            .into()
    }

    fn view_tweaks(&self) -> Element<'_, Message> {
        let tweaks = self.options.tweaks.as_ref();

        if let Some(tweaks) = tweaks {
            if tweaks.is_empty() {
                return text("No tweaks added").size(12).into();
            }

            let mut tweak_list = column![].spacing(4);

            for (i, tweak) in tweaks.iter().enumerate() {
                let tweak_row = row![
                    text(tweak.file_name().and_then(|n| n.to_str()).unwrap_or("???"))
                        .size(12)
                        .width(Fill)
                        .wrapping(text::Wrapping::WordOrGlyph),
                    button(appearance::icon(appearance::MINUS))
                        .on_press(Message::RemoveTweak(i))
                        .style(appearance::s_button)
                        .padding(6)
                ]
                .spacing(8)
                .align_y(Alignment::Start);

                tweak_list = tweak_list.push(tweak_row);
            }

            scrollable(tweak_list).into()
        } else {
            text("No tweaks added").size(12).into()
        }
    }
}

const IOS_ICON_CORNER_RADIUS_FACTOR: f32 = 0.225;
const IOS_ICON_EDGE: f32 = 1.528_665;
const IOS_ICON_SHOULDER: f32 = 0.631_493_8;
const IOS_ICON_KNEE: f32 = 0.074_911_39;
const IOS_ICON_CTRL_EDGE: f32 = 1.088_493;
const IOS_ICON_CTRL_SHOULDER: f32 = 0.868_406_95;
const IOS_ICON_CTRL_CURVE_OUTER: f32 = 0.372_823_83;
const IOS_ICON_CTRL_CURVE_INNER: f32 = 0.169_059_56;

fn icon_handle_from_bytes(data: &[u8]) -> Option<image::Handle> {
    icon_handle_from_image(::image::load_from_memory(data).ok()?)
}

fn icon_handle_from_path(path: &PathBuf) -> Option<image::Handle> {
    icon_handle_from_image(::image::open(path).ok()?)
}

fn icon_handle_from_image(image: ::image::DynamicImage) -> Option<image::Handle> {
    let mut pixels = image.to_rgba8();
    let (width, height) = pixels.dimensions();
    let mut mask = Mask::new(width, height)?;
    mask.fill_path(
        &ios_icon_mask(width as f32, height as f32)?,
        FillRule::Winding,
        true,
        Transform::identity(),
    );

    for (pixel, coverage) in pixels.chunks_exact_mut(4).zip(mask.data()) {
        pixel[3] = ((u16::from(pixel[3]) * u16::from(*coverage) + 127) / 255) as u8;
    }

    Some(image::Handle::from_rgba(width, height, pixels.into_raw()))
}

fn ios_icon_mask(width: f32, height: f32) -> Option<Path> {
    let radius = width.min(height) * IOS_ICON_CORNER_RADIUS_FACTOR;
    let mut path = PathBuilder::new();
    let tl = |x: f32, y: f32| (x * radius, y * radius);
    let tr = |x: f32, y: f32| (width - x * radius, y * radius);
    let br = |x: f32, y: f32| (width - x * radius, height - y * radius);
    let bl = |x: f32, y: f32| (x * radius, height - y * radius);

    let (x, y) = tl(IOS_ICON_EDGE, 0.0);
    path.move_to(x, y);

    let (x, y) = tr(IOS_ICON_EDGE, 0.0);
    path.line_to(x, y);
    let (x1, y1) = tr(IOS_ICON_CTRL_EDGE, 0.0);
    let (x2, y2) = tr(IOS_ICON_CTRL_SHOULDER, 0.0);
    let (x, y) = tr(IOS_ICON_SHOULDER, IOS_ICON_KNEE);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = tr(IOS_ICON_CTRL_CURVE_OUTER, IOS_ICON_CTRL_CURVE_INNER);
    let (x2, y2) = tr(IOS_ICON_CTRL_CURVE_INNER, IOS_ICON_CTRL_CURVE_OUTER);
    let (x, y) = tr(IOS_ICON_KNEE, IOS_ICON_SHOULDER);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = tr(0.0, IOS_ICON_CTRL_SHOULDER);
    let (x2, y2) = tr(0.0, IOS_ICON_CTRL_EDGE);
    let (x, y) = tr(0.0, IOS_ICON_EDGE);
    path.cubic_to(x1, y1, x2, y2, x, y);

    let (x, y) = br(0.0, IOS_ICON_EDGE);
    path.line_to(x, y);
    let (x1, y1) = br(0.0, IOS_ICON_CTRL_EDGE);
    let (x2, y2) = br(0.0, IOS_ICON_CTRL_SHOULDER);
    let (x, y) = br(IOS_ICON_KNEE, IOS_ICON_SHOULDER);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = br(IOS_ICON_CTRL_CURVE_INNER, IOS_ICON_CTRL_CURVE_OUTER);
    let (x2, y2) = br(IOS_ICON_CTRL_CURVE_OUTER, IOS_ICON_CTRL_CURVE_INNER);
    let (x, y) = br(IOS_ICON_SHOULDER, IOS_ICON_KNEE);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = br(IOS_ICON_CTRL_SHOULDER, 0.0);
    let (x2, y2) = br(IOS_ICON_CTRL_EDGE, 0.0);
    let (x, y) = br(IOS_ICON_EDGE, 0.0);
    path.cubic_to(x1, y1, x2, y2, x, y);

    let (x, y) = bl(IOS_ICON_EDGE, 0.0);
    path.line_to(x, y);
    let (x1, y1) = bl(IOS_ICON_CTRL_EDGE, 0.0);
    let (x2, y2) = bl(IOS_ICON_CTRL_SHOULDER, 0.0);
    let (x, y) = bl(IOS_ICON_SHOULDER, IOS_ICON_KNEE);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = bl(IOS_ICON_CTRL_CURVE_OUTER, IOS_ICON_CTRL_CURVE_INNER);
    let (x2, y2) = bl(IOS_ICON_CTRL_CURVE_INNER, IOS_ICON_CTRL_CURVE_OUTER);
    let (x, y) = bl(IOS_ICON_KNEE, IOS_ICON_SHOULDER);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = bl(0.0, IOS_ICON_CTRL_SHOULDER);
    let (x2, y2) = bl(0.0, IOS_ICON_CTRL_EDGE);
    let (x, y) = bl(0.0, IOS_ICON_EDGE);
    path.cubic_to(x1, y1, x2, y2, x, y);

    let (x, y) = tl(0.0, IOS_ICON_EDGE);
    path.line_to(x, y);
    let (x1, y1) = tl(0.0, IOS_ICON_CTRL_EDGE);
    let (x2, y2) = tl(0.0, IOS_ICON_CTRL_SHOULDER);
    let (x, y) = tl(IOS_ICON_KNEE, IOS_ICON_SHOULDER);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = tl(IOS_ICON_CTRL_CURVE_INNER, IOS_ICON_CTRL_CURVE_OUTER);
    let (x2, y2) = tl(IOS_ICON_CTRL_CURVE_OUTER, IOS_ICON_CTRL_CURVE_INNER);
    let (x, y) = tl(IOS_ICON_SHOULDER, IOS_ICON_KNEE);
    path.cubic_to(x1, y1, x2, y2, x, y);
    let (x1, y1) = tl(IOS_ICON_CTRL_SHOULDER, 0.0);
    let (x2, y2) = tl(IOS_ICON_CTRL_EDGE, 0.0);
    let (x, y) = tl(IOS_ICON_EDGE, 0.0);
    path.cubic_to(x1, y1, x2, y2, x, y);

    path.close();
    path.finish()
}
