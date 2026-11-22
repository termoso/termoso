//! WebKitGTK workarounds on Linux:
//!
//! 1. On Wayland, WebKitGTK's DMA-BUF presentation path can stall xterm.js's
//!    WebGL renderer on non-NVIDIA GPUs (e.g. Intel Iris Xe / Mesa), freezing
//!    individual terminal panes while the rest of the UI keeps responding.
//!    Disabling DMA-BUF (`WEBKIT_DISABLE_DMABUF_RENDERER=1`) avoids the freeze
//!    but forces slow software frame readbacks. Preferring XWayland
//!    (`GDK_BACKEND=x11`) when an X11 `DISPLAY` is available keeps GPU
//!    acceleration active without the Wayland stall, unless the user already
//!    set `GDK_BACKEND`.
//! 2. WebKitGTK's DMA-BUF renderer asks the GPU driver for buffer formats the
//!    proprietary NVIDIA driver does not provide; the webview then paints
//!    nothing (a blank / see-through window), flickers or dies on resize
//!    (tauri-apps/tauri#9394, WebKit bug 261874). Disabling that renderer
//!    keeps the app usable at the cost of the faster presentation path, so it
//!    is done only when the NVIDIA kernel module is loaded and the user has not
//!    decided for themselves via `WEBKIT_DISABLE_DMABUF_RENDERER` (`=0` keeps
//!    the renderer on).

use std::path::Path;

const DMABUF_VAR: &str = "WEBKIT_DISABLE_DMABUF_RENDERER";
const GDK_BACKEND_VAR: &str = "GDK_BACKEND";
const DISPLAY_VAR: &str = "DISPLAY";

fn nvidia_loaded() -> bool {
    Path::new("/proc/driver/nvidia/version").exists() || Path::new("/sys/module/nvidia").exists()
}

fn is_wayland_session() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("XDG_SESSION_TYPE").is_some_and(|v| v == "wayland")
}

/// Must run before GTK / WebKit initialise and before any other thread starts.
pub fn apply_workarounds() {
    if std::env::var_os(GDK_BACKEND_VAR).is_none()
        && is_wayland_session()
        && std::env::var_os(DISPLAY_VAR).is_some_and(|v| !v.is_empty())
    {
        // SAFETY: called from `run()` on the main thread before any thread is
        // spawned, so nothing can read the environment concurrently.
        unsafe { std::env::set_var(GDK_BACKEND_VAR, "x11") };
        tracing::info!("Wayland session with XWayland detected: preferring GDK_BACKEND=x11");
    }

    if std::env::var_os(DMABUF_VAR).is_some() || !nvidia_loaded() {
        return;
    }
    // SAFETY: called from `run()` on the main thread before any thread is
    // spawned, so nothing can read the environment concurrently.
    unsafe { std::env::set_var(DMABUF_VAR, "1") };
    tracing::info!("NVIDIA driver detected: WebKitGTK DMA-BUF renderer disabled");
}
