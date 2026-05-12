use std::collections::HashMap;
use image::{Rgba, RgbaImage};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuId, MenuItem, PredefinedMenuItem, Submenu},
};

pub(crate) fn build_tray_icon(menu: &Menu) -> TrayIcon {
    let icon = load_icon();
    TrayIconBuilder::new()
        .with_menu(Box::new(menu.clone()))
        .with_tooltip(crate::APP_NAME)
        .with_icon(icon)
        .with_icon_as_template(true)
        .build()
        .expect("Failed to build tray icon")
}

fn base_icon_image() -> RgbaImage {
    #[cfg(target_os = "windows")]
    let bytes: &[u8] = include_bytes!("./tray_colored.png");
    #[cfg(all(not(target_os = "windows")))]
    let bytes: &[u8] = include_bytes!("./tray.png");
    image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .expect("Failed to load icon bytes")
        .to_rgba8()
}

fn load_icon() -> Icon {
    let image = base_icon_image();
    let (width, height) = image.dimensions();
    Icon::from_rgba(image.into_raw(), width, height).unwrap()
}

#[derive(Debug, Clone)]
pub enum TrayAction {
    Show,
    Quit,
    RefreshApp { udid: String, app_path: String },
    ForgetApp { udid: String, app_path: String },
}

pub(crate) struct ImpactorTray {
    icon: Option<TrayIcon>,
    menu: Menu,
    show_item_id: MenuId,
    quit_item_id: MenuId,
    action_map: HashMap<MenuId, TrayAction>,
}

impl ImpactorTray {
    pub(crate) fn new() -> Self {
        let tray_menu = Menu::new();
        let show_item = MenuItem::new("Open", true, None);
        let quit_item = MenuItem::new(format!("Quit {}", crate::APP_NAME), true, None);

        let show_item_id = show_item.id().clone();
        let quit_item_id = quit_item.id().clone();

        let mut action_map = HashMap::new();
        action_map.insert(show_item_id.clone(), TrayAction::Show);
        action_map.insert(quit_item_id.clone(), TrayAction::Quit);

        let _ = tray_menu.append_items(&[&show_item, &PredefinedMenuItem::separator(), &quit_item]);

        Self {
            icon: Some(build_tray_icon(&tray_menu)),
            menu: tray_menu,
            show_item_id,
            quit_item_id,
            action_map,
        }
    }

    pub(crate) fn update_refresh_apps(&mut self, store: &plume_store::AccountStore) {
        let new_menu = Menu::new();
        let show_item = MenuItem::new("Open", true, None);

        let mut action_map = HashMap::new();
        action_map.insert(show_item.id().clone(), TrayAction::Show);

        let _ = new_menu.append(&show_item);
        let _ = new_menu.append(&PredefinedMenuItem::separator());

        let has_apps = store.refreshes().values().any(|d| !d.apps.is_empty());

        if has_apps {
            let refresh_submenu = Submenu::new("Auto-Refresh Apps", true);

            for (udid, refresh_device) in store.refreshes() {
                if refresh_device.apps.is_empty() {
                    continue;
                }

                let device_label = MenuItem::with_id(
                    MenuId::new(format!("header-{}", udid)),
                    &refresh_device.name,
                    false,
                    None,
                );
                let _ = refresh_submenu.append(&device_label);

                for app in &refresh_device.apps {
                    let scheduled = app.scheduled_refresh.format("%H:%M %b %d").to_string();

                    let app_submenu = Submenu::new(
                        &format!(
                            "{} (Next: {})",
                            app.name.clone().unwrap_or("???".to_string()),
                            scheduled
                        ),
                        true,
                    );

                    let refresh_item = MenuItem::new("Refresh Now", true, None);
                    let forget_item = MenuItem::new("Forget App", true, None);

                    action_map.insert(
                        refresh_item.id().clone(),
                        TrayAction::RefreshApp {
                            udid: udid.clone(),
                            app_path: app.path.to_string_lossy().to_string(),
                        },
                    );
                    action_map.insert(
                        forget_item.id().clone(),
                        TrayAction::ForgetApp {
                            udid: udid.clone(),
                            app_path: app.path.to_string_lossy().to_string(),
                        },
                    );

                    let _ = app_submenu.append(&refresh_item);
                    let _ = app_submenu.append(&forget_item);

                    let _ = refresh_submenu.append(&app_submenu);
                }

                let _ = refresh_submenu.append(&PredefinedMenuItem::separator());
            }

            let _ = new_menu.append(&refresh_submenu);
            let _ = new_menu.append(&PredefinedMenuItem::separator());
        }

        let quit_item = MenuItem::new(format!("Quit {}", crate::APP_NAME), true, None);
        action_map.insert(quit_item.id().clone(), TrayAction::Quit);
        let _ = new_menu.append(&quit_item);

        self.show_item_id = show_item.id().clone();
        self.quit_item_id = quit_item.id().clone();

        self.menu = new_menu;
        self.action_map = action_map;

        if let Some(tray_icon) = &mut self.icon {
            let _ = tray_icon.set_menu(Some(Box::new(self.menu.clone())));
        }
    }

    pub(crate) fn get_action(&self, id: &MenuId) -> Option<&TrayAction> {
        self.action_map.get(id)
    }

    pub(crate) fn set_signing_progress(&mut self, progress: i32) {
        let Some(tray_icon) = &self.icon else { return };
        let clamped = progress.clamp(0, 100);
        if let Some(icon) = render_progress_icon(clamped) {
            let _ = tray_icon.set_icon(Some(icon));
        }
        let _ = tray_icon.set_title(Some(&format!(" {clamped}%")));
    }

    pub(crate) fn clear_signing_progress(&mut self) {
        let Some(tray_icon) = &self.icon else { return };
        let _ = tray_icon.set_icon(Some(load_icon()));
        let _ = tray_icon.set_title(None::<&str>);
    }
}

// Pill bar geometry, in pixels of the base 64-tall icon. The base tray.png is
// 64×64; we render a wider canvas next to it so macOS shows a track + fill
// alongside the glyph. Template mode means only alpha drives the rendered color.
const BAR_GAP: u32 = 14;
const BAR_WIDTH: u32 = 132;
const BAR_HEIGHT: u32 = 12;
const BAR_TRACK_ALPHA: u8 = 70;
const BAR_FILL_ALPHA: u8 = 255;

fn render_progress_icon(percent: i32) -> Option<Icon> {
    let base = base_icon_image();
    let (bw, bh) = base.dimensions();

    let total_w = bw + BAR_GAP + BAR_WIDTH;
    let mut canvas = RgbaImage::new(total_w, bh);

    for (x, y, p) in base.enumerate_pixels() {
        canvas.put_pixel(x, y, *p);
    }

    let bar_x0 = bw + BAR_GAP;
    let bar_y0 = (bh - BAR_HEIGHT) / 2;
    draw_rounded_pill(&mut canvas, bar_x0, bar_y0, BAR_WIDTH, BAR_HEIGHT, BAR_TRACK_ALPHA);

    let fill_w = (percent.clamp(0, 100) as u32 * BAR_WIDTH) / 100;
    if fill_w > 0 {
        draw_rounded_pill(&mut canvas, bar_x0, bar_y0, fill_w.max(BAR_HEIGHT), BAR_HEIGHT, BAR_FILL_ALPHA);
    }

    Icon::from_rgba(canvas.into_raw(), total_w, bh).ok()
}

fn draw_rounded_pill(canvas: &mut RgbaImage, x0: u32, y0: u32, w: u32, h: u32, alpha: u8) {
    if w == 0 || h == 0 {
        return;
    }
    let radius = (h as f32) / 2.0;
    let cw = canvas.width();
    let ch = canvas.height();
    for y in 0..h {
        for x in 0..w {
            let px = x0 + x;
            let py = y0 + y;
            if px >= cw || py >= ch {
                continue;
            }
            let inside = if x < (radius as u32) {
                let cx = radius;
                let cy = radius;
                let dx = (x as f32) - cx + 0.5;
                let dy = (y as f32) - cy + 0.5;
                dx * dx + dy * dy <= radius * radius
            } else if x >= w - (radius as u32) {
                let cx = (w as f32) - radius;
                let cy = radius;
                let dx = (x as f32) - cx + 0.5;
                let dy = (y as f32) - cy + 0.5;
                dx * dx + dy * dy <= radius * radius
            } else {
                true
            };
            if inside {
                canvas.put_pixel(px, py, Rgba([255, 255, 255, alpha]));
            }
        }
    }
}
