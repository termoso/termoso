//! Mobile settings, stored as JSON in the encrypted store's metadata so they
//! travel with the vault backup and never sit in plain `SharedPreferences`.

use serde::{Deserialize, Serialize};
use termoso_core::store::Store;
use termoso_core::terminal::clamp_scrollback;

use crate::error::Result;

const SETTINGS_META: &str = "mobile.settings";

fn default_true() -> bool {
    true
}
fn default_font_size() -> u32 {
    14
}
fn default_scrollback() -> u32 {
    5000
}
fn default_keepalive() -> u32 {
    30
}
fn default_term() -> String {
    "xterm-256color".into()
}
fn default_theme() -> String {
    crate::themes::TERMOSO_DARK.into()
}
fn default_cursor() -> String {
    "block".into()
}
fn default_view() -> String {
    "list".into()
}
fn default_app_theme() -> String {
    "system".into()
}
fn default_cursor_speed() -> String {
    "normal".into()
}

fn default_hotkeys() -> String {
    "ctrl_shift".into()
}

/// One button of a custom key-panel group. `action` is a small grammar the
/// Android side parses: optional `ctrl+`/`alt+`/`shift+` prefixes, then
/// `key:<SPECIAL>` (`key:ESCAPE`, `key:F5`), `text:<literal>` or
/// `mod:ctrl|alt|shift` for a sticky modifier. Unknown actions are dropped
/// at render time rather than failing the whole layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct PanelKeyDef {
    pub label: String,
    pub action: String,
}

/// A row of the expandable key panel. Groups are shown in list order; a
/// disabled group stays in the editor but is not rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
#[serde(default, rename_all = "camelCase")]
pub struct KeyGroup {
    pub id: String,
    pub name: String,
    pub keys: Vec<PanelKeyDef>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for KeyGroup {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            keys: Vec::new(),
            enabled: true,
        }
    }
}

/// Upper bounds so a corrupt or malicious sync payload cannot blow up the panel.
pub const MAX_KEY_GROUPS: usize = 24;
pub const MAX_KEYS_PER_GROUP: usize = 16;
const MAX_KEY_TEXT: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
#[serde(default, rename_all = "camelCase")]
pub struct MobileSettings {
    /// `system` | `dark` | `light`.
    #[serde(default = "default_app_theme")]
    pub app_theme: String,
    /// Derive the app palette from the device wallpaper colours (Material
    /// You, Android 12+). The terminal keeps its own theme either way.
    #[serde(default = "default_true")]
    pub dynamic_color: bool,
    /// `list` | `grid`.
    #[serde(default = "default_view")]
    pub hosts_view: String,
    #[serde(default = "default_theme")]
    pub terminal_theme: String,
    #[serde(default = "default_font_size")]
    pub terminal_font_size: u32,
    pub terminal_font_family: String,
    /// `block` | `underline` | `beam`.
    #[serde(default = "default_cursor")]
    pub cursor_style: String,
    #[serde(default = "default_true")]
    pub cursor_blink: bool,
    #[serde(default = "default_scrollback")]
    pub scrollback_lines: u32,
    #[serde(default = "default_term")]
    pub term_type: String,
    #[serde(default = "default_true")]
    pub terminal_bell: bool,
    /// Reconnect dropped SSH sessions by itself when the network comes back or changes.
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    #[serde(default = "default_true")]
    pub haptic_feedback: bool,
    /// Keep the screen on while a terminal is in front.
    #[serde(default = "default_true")]
    pub keep_screen_on: bool,
    /// Seconds between SSH keepalives; 0 disables.
    #[serde(default = "default_keepalive")]
    pub keep_alive_seconds: u32,
    #[serde(default = "default_true")]
    pub post_quantum_kex: bool,
    #[serde(default = "default_true")]
    pub detect_os: bool,
    /// Read the remote shell's history files after connecting (opt-in; nothing is stored).
    #[serde(default)]
    pub import_shell_history: bool,
    /// Ask for the device credential (biometric / PIN) when the app returns
    /// to the foreground.
    pub lock_on_background: bool,
    /// Seconds in background before the lock kicks in.
    pub lock_after_seconds: u32,
    /// Sync identities, keys and certificates of the Personal vault. Off
    /// keeps them on this phone (hosts etc. still sync); they are removed
    /// together with the account on sign-out.
    #[serde(default = "default_true")]
    pub sync_credentials: bool,
    /// Keep key passphrases typed at connect time (without "remember") in
    /// process memory until the vault is locked or the app exits, so the
    /// next connection with that key does not ask again. Nothing is written
    /// to the vault or synced.
    #[serde(default)]
    pub cache_passphrases: bool,
    /// Record terminal output of every session into the encrypted log
    /// store (team vaults with session logging on record regardless).
    #[serde(default)]
    pub record_sessions: bool,
    /// What the hardware volume keys do while a terminal is in front; empty
    /// or `disabled` leaves them to the system. Values are either a UI action
    /// (`font_up`, `font_down`, `scroll_up`, `scroll_down`, `next_session`,
    /// `prev_session`, `toggle_keyboard`, `close_session`) or a key action in
    /// the [`PanelKeyDef::action`] grammar.
    #[serde(default)]
    pub volume_up_action: String,
    #[serde(default)]
    pub volume_down_action: String,
    /// What shaking the device does while a terminal is in front (same grammar; empty = off).
    #[serde(default)]
    pub shake_action: String,
    /// Physical-keyboard app shortcuts (session switching, close, new, zoom):
    /// `disabled` | `ctrl` | `ctrl_shift`. Ctrl+Shift by default so Ctrl+W,
    /// Ctrl+T and friends keep reaching the shell.
    #[serde(default = "default_hotkeys")]
    pub hardware_hotkeys: String,
    /// Collapse the on-screen key panel to its toggle while a physical
    /// keyboard is attached.
    #[serde(default)]
    pub hide_panel_with_keyboard: bool,
    /// Suggestions strip above the key panel while typing at a prompt
    /// (commands, options, history, snippets, paths).
    #[serde(default = "default_true")]
    pub autocomplete: bool,
    /// Two-finger pinch changes the terminal text size.
    #[serde(default = "default_true")]
    pub pinch_zoom: bool,
    /// Horizontal one-finger swipe sends ←/→ per cell travelled.
    #[serde(default = "default_true")]
    pub swipe_arrows: bool,
    /// Two-finger horizontal swipe switches between open sessions.
    #[serde(default = "default_true")]
    pub swipe_sessions: bool,
    /// Long-press, then drag in any direction to send arrow keys (held still
    /// at the edge keeps repeating; farther = faster).
    #[serde(default = "default_true")]
    pub long_press_arrows: bool,
    /// Double-tap on the terminal sends Tab instead of selecting a word.
    #[serde(default = "default_true")]
    pub double_tap_tab: bool,
    /// How far the finger travels per arrow key in gesture mode:
    /// `slow` | `normal` | `fast`.
    #[serde(default = "default_cursor_speed")]
    pub cursor_speed: String,
    /// Custom rows of the expandable key panel; empty means the built-in layout.
    #[serde(default)]
    pub key_groups: Vec<KeyGroup>,
    /// Onboarding shown.
    pub welcome_seen: bool,
    /// Vault shown in the Vaults tab when the app was last used.
    #[serde(default)]
    pub selected_vault_id: Option<String>,
}

impl Default for MobileSettings {
    fn default() -> Self {
        Self {
            app_theme: default_app_theme(),
            dynamic_color: true,
            hosts_view: default_view(),
            terminal_theme: default_theme(),
            terminal_font_size: default_font_size(),
            terminal_font_family: String::new(),
            cursor_style: default_cursor(),
            cursor_blink: true,
            scrollback_lines: default_scrollback(),
            term_type: default_term(),
            terminal_bell: true,
            auto_reconnect: true,
            haptic_feedback: true,
            keep_screen_on: true,
            keep_alive_seconds: default_keepalive(),
            post_quantum_kex: true,
            detect_os: true,
            import_shell_history: false,
            lock_on_background: false,
            lock_after_seconds: 0,
            sync_credentials: true,
            cache_passphrases: false,
            record_sessions: false,
            volume_up_action: String::new(),
            volume_down_action: String::new(),
            shake_action: String::new(),
            hardware_hotkeys: default_hotkeys(),
            hide_panel_with_keyboard: false,
            autocomplete: true,
            pinch_zoom: true,
            swipe_arrows: true,
            swipe_sessions: true,
            long_press_arrows: true,
            double_tap_tab: true,
            cursor_speed: default_cursor_speed(),
            key_groups: Vec::new(),
            welcome_seen: false,
            selected_vault_id: None,
        }
    }
}

impl MobileSettings {
    pub(crate) fn load(store: &Store) -> Result<Self> {
        Ok(match store.meta(SETTINGS_META)? {
            Some(json) => serde_json::from_str(&json).unwrap_or_default(),
            None => Self::default(),
        })
    }

    pub(crate) fn save(&self, store: &Store) -> Result<()> {
        let mut s = self.clone();
        s.scrollback_lines = clamp_scrollback(s.scrollback_lines);
        s.terminal_font_size = s.terminal_font_size.clamp(6, 40);
        if s.term_type.trim().is_empty() {
            s.term_type = default_term();
        }
        if !matches!(
            s.hardware_hotkeys.as_str(),
            "disabled" | "ctrl" | "ctrl_shift"
        ) {
            s.hardware_hotkeys = default_hotkeys();
        }
        s.key_groups = sanitize_groups(std::mem::take(&mut s.key_groups));
        store.set_meta(SETTINGS_META, &serde_json::to_string(&s)?)?;
        Ok(())
    }
}

/// Drop empty/oversized groups and keys, trim labels, and make ids unique so
/// the Android editor can key its list on them.
fn sanitize_groups(groups: Vec<KeyGroup>) -> Vec<KeyGroup> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (i, mut g) in groups.into_iter().enumerate() {
        if out.len() >= MAX_KEY_GROUPS {
            break;
        }
        g.keys.retain(|k| !k.action.trim().is_empty());
        g.keys.truncate(MAX_KEYS_PER_GROUP);
        if g.keys.is_empty() {
            continue;
        }
        for k in &mut g.keys {
            k.label = k.label.trim().chars().take(12).collect();
            k.action = k.action.chars().take(MAX_KEY_TEXT).collect();
        }
        g.name = g.name.trim().chars().take(32).collect();
        if g.id.trim().is_empty() || !seen.insert(g.id.clone()) {
            g.id = format!("g{}", i + 1);
            while !seen.insert(g.id.clone()) {
                g.id.push('x');
            }
        }
        out.push(g);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(action: &str) -> PanelKeyDef {
        PanelKeyDef {
            label: format!("  {action}  "),
            action: action.into(),
        }
    }

    #[test]
    fn defaults_are_conservative() {
        let s = MobileSettings::default();
        assert!(s.volume_up_action.is_empty() && s.volume_down_action.is_empty());
        assert_eq!(s.hardware_hotkeys, "ctrl_shift");
        assert!(s.pinch_zoom && s.swipe_arrows && s.swipe_sessions);
        assert!(s.long_press_arrows && s.double_tap_tab);
        assert_eq!(s.cursor_speed, "normal");
        assert!(!s.hide_panel_with_keyboard);
        assert!(s.key_groups.is_empty());
    }

    #[test]
    fn old_settings_json_still_loads() {
        let s: MobileSettings =
            serde_json::from_str(r#"{"appTheme":"dark","recordSessions":true}"#).unwrap();
        assert_eq!(s.app_theme, "dark");
        assert!(s.record_sessions);
        assert_eq!(s.hardware_hotkeys, "ctrl_shift");
        assert!(s.key_groups.is_empty());
    }

    #[test]
    fn group_without_enabled_defaults_to_enabled() {
        let g: KeyGroup = serde_json::from_str(
            r#"{"id":"a","name":"Nav","keys":[{"label":"←","action":"key:LEFT"}]}"#,
        )
        .unwrap();
        assert!(g.enabled);
    }

    #[test]
    fn sanitize_drops_empty_and_dedups_ids() {
        let groups = vec![
            KeyGroup {
                id: "a".into(),
                name: " Nav ".into(),
                keys: vec![key("key:LEFT"), key("   ")],
                enabled: true,
            },
            KeyGroup {
                id: "a".into(),
                name: "Dup".into(),
                keys: vec![key("text:|")],
                enabled: false,
            },
            KeyGroup {
                id: "".into(),
                name: "Empty".into(),
                keys: vec![],
                enabled: true,
            },
        ];
        let out = sanitize_groups(groups);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "Nav");
        assert_eq!(out[0].keys.len(), 1);
        assert_eq!(out[0].keys[0].label, "key:LEFT");
        assert_eq!(out[1].id, "g2");
        assert!(!out[1].enabled);
    }

    #[test]
    fn sanitize_caps_sizes() {
        let big = KeyGroup {
            id: "x".into(),
            name: "x".into(),
            keys: (0..40).map(|_| key("text:a")).collect(),
            enabled: true,
        };
        let groups: Vec<KeyGroup> = (0..40).map(|_| big.clone()).collect();
        let out = sanitize_groups(groups);
        assert_eq!(out.len(), MAX_KEY_GROUPS);
        assert!(out.iter().all(|g| g.keys.len() == MAX_KEYS_PER_GROUP));
    }
}
