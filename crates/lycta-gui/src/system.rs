use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Prefs {
    pub lock_minutes: u32,
    pub lock_on_minimize: bool,
    pub notifications: bool,

    pub hide_from_capture: bool,

    pub close_to_tray: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            lock_minutes: 10,
            lock_on_minimize: false,
            notifications: true,
            hide_from_capture: true,
            close_to_tray: true,
        }
    }
}

impl Prefs {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("interface.json")
    }

    pub fn load(data_dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(data_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data_dir: &Path) {
        let _ = std::fs::create_dir_all(data_dir);
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(Self::path(data_dir), s);
        }
    }
}

pub fn set_capture_protection(frame: &eframe::Frame, on: bool) -> bool {
    #[cfg(windows)]
    {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
        };
        if let Ok(handle) = frame.window_handle() {
            if let RawWindowHandle::Win32(h) = handle.as_raw() {
                let hwnd = h.hwnd.get() as windows_sys::Win32::Foundation::HWND;
                let affinity = if on { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };

                #[allow(unsafe_code)]
                let ok = unsafe { SetWindowDisplayAffinity(hwnd, affinity) };
                return ok != 0;
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        let _ = (frame, on);
        false
    }
}

pub fn notify_new_message() {
    let _ = notify_rust::Notification::new()
        .summary("LyctaCrypt")
        .body("New message")
        .show();
}

#[derive(Default)]
pub struct TrayFlags {
    pub lock: AtomicBool,
    pub quit: AtomicBool,
}

pub struct Tray {
    _icon: tray_icon::TrayIcon,
    pub flags: Arc<TrayFlags>,
}

pub fn create_tray(ctx: &egui::Context, rgba: Vec<u8>, w: u32, h: u32) -> Option<Tray> {
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{MouseButton, TrayIconBuilder, TrayIconEvent};

    let menu = Menu::new();
    let open = MenuItem::new("Open LyctaCrypt", true, None);
    let lock = MenuItem::new("Lock", true, None);
    let quit = MenuItem::new("Quit", true, None);
    menu.append_items(&[&open, &lock, &PredefinedMenuItem::separator(), &quit])
        .ok()?;
    let icon = tray_icon::Icon::from_rgba(rgba, w, h).ok()?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("LyctaCrypt")
        .with_icon(icon)
        .with_menu_on_left_click(false)
        .build()
        .ok()?;

    let flags = Arc::new(TrayFlags::default());
    let show = {
        let ctx = ctx.clone();
        move || {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.request_repaint();
        }
    };

    {
        let show = show.clone();
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                ..
            } = e
            {
                show();
            }
        }));
    }
    {
        let ctx = ctx.clone();
        let flags = Arc::clone(&flags);
        let (open_id, lock_id, quit_id) = (open.id().clone(), lock.id().clone(), quit.id().clone());
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            if e.id == open_id {
                show();
            } else if e.id == lock_id {
                flags.lock.store(true, Ordering::SeqCst);
                ctx.request_repaint();
            } else if e.id == quit_id {
                flags.quit.store(true, Ordering::SeqCst);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                ctx.request_repaint();
            }
        }));
    }
    Some(Tray { _icon: tray, flags })
}
