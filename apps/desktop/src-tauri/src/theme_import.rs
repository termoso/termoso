//! Import terminal colour schemes from other terminals' files. Every parser
//! yields the same [`ColorScheme`] payload (16 ANSI colours in xterm order,
//! `#rrggbb`), so the result can be saved to the vault as-is.
//!
//! Supported: iTerm2 `.itermcolors` (plist), Windows Terminal (a scheme
//! object or a whole `settings.json`), Alacritty (`.toml` and the older
//! `.yml`), Kitty `.conf`, Ghostty config, Gogh `.yml`.

use std::path::Path;

use serde::Serialize;
use termoso_core::model::ColorScheme;

use crate::error::{DesktopError, Result};

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThemeImport {
    pub schemes: Vec<ColorScheme>,
    pub warnings: Vec<String>,
}

const ANSI_NAMES: [&str; 16] = [
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "white",
    "brightBlack",
    "brightRed",
    "brightGreen",
    "brightYellow",
    "brightBlue",
    "brightMagenta",
    "brightCyan",
    "brightWhite",
];

/// Parse `text` taken from `path` (the extension and the file stem are hints).
pub fn parse(path: &str, text: &str) -> Result<ThemeImport> {
    let p = Path::new(path);
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "Imported".into());
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let t = text.trim_start_matches('\u{feff}');
    let head = t.trim_start();
    let out = if ext == "itermcolors" || head.starts_with("<?xml") || head.starts_with("<plist") {
        itermcolors(&stem, t)
    } else if head.starts_with('{') || head.starts_with('[') && ext == "json" {
        windows_terminal(&stem, t)
    } else if ext == "toml" || t.contains("[colors") {
        alacritty_toml(&stem, t)
    } else if t.contains("color_01") {
        gogh(&stem, t)
    } else if t.contains("colors:") {
        alacritty_yaml(&stem, t)
    } else if t.lines().any(|l| l.trim_start().starts_with("palette")) {
        ghostty(&stem, t)
    } else if t.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("color0 ") || l.starts_with("color0\t")
    }) {
        kitty(&stem, t)
    } else {
        return Err(DesktopError::invalid(
            "Not a recognised colour scheme file (iTerm2, Windows Terminal, Alacritty, Kitty, Ghostty or Gogh)",
        ));
    }?;
    if out.schemes.is_empty() {
        return Err(DesktopError::invalid("No colour scheme found in the file"));
    }
    Ok(out)
}

/// Read and parse a file.
pub fn import_file(path: &str) -> Result<ThemeImport> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| DesktopError::new("io", format!("{path}: {e}")))?;
    parse(path, &text)
}

// ───────────────────────────── colours ─────

/// Normalise `#rgb`, `#rrggbb`, `#rrggbbaa`, `0xrrggbb`, `rrggbb` to `#rrggbb`.
pub fn hex(s: &str) -> Option<String> {
    let s = s.trim().trim_matches(|c| c == '"' || c == '\'');
    let s = s
        .strip_prefix('#')
        .or_else(|| s.strip_prefix("0x"))
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match s.len() {
        3 => {
            let c: Vec<char> = s.chars().collect();
            Some(format!("#{}{}{}{}{}{}", c[0], c[0], c[1], c[1], c[2], c[2]).to_lowercase())
        }
        6 | 8 => Some(format!("#{}", &s[..6]).to_lowercase()),
        _ => None,
    }
}

fn component(v: f64) -> u8 {
    (v.clamp(0.0, 1.0) * 255.0).round() as u8
}

struct Builder {
    name: String,
    background: Option<String>,
    foreground: Option<String>,
    cursor: Option<String>,
    selection: Option<String>,
    ansi: [Option<String>; 16],
}

impl Builder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            background: None,
            foreground: None,
            cursor: None,
            selection: None,
            ansi: Default::default(),
        }
    }

    fn set_ansi(&mut self, i: usize, v: Option<String>) {
        if i < 16 && v.is_some() {
            self.ansi[i] = v;
        }
    }

    fn finish(self, warnings: &mut Vec<String>) -> Option<ColorScheme> {
        let missing: Vec<usize> = (0..16).filter(|i| self.ansi[*i].is_none()).collect();
        let (Some(background), Some(foreground)) =
            (self.background.clone(), self.foreground.clone())
        else {
            warnings.push(format!("{}: no background/foreground colour", self.name));
            return None;
        };
        if missing.len() > 8 {
            warnings.push(format!(
                "{}: only {} of 16 ANSI colours found",
                self.name,
                16 - missing.len()
            ));
            return None;
        }
        if !missing.is_empty() {
            warnings.push(format!(
                "{}: {} ANSI colour(s) missing, filled from the foreground",
                self.name,
                missing.len()
            ));
        }
        let ansi = self
            .ansi
            .iter()
            .map(|c| c.clone().unwrap_or_else(|| foreground.clone()))
            .collect();
        Some(ColorScheme {
            name: self.name,
            cursor: self.cursor.unwrap_or_else(|| foreground.clone()),
            selection: self.selection,
            background,
            foreground,
            ansi,
        })
    }
}

fn single(b: Builder) -> Result<ThemeImport> {
    let mut warnings = Vec::new();
    let schemes = b.finish(&mut warnings).into_iter().collect();
    Ok(ThemeImport { schemes, warnings })
}

// ───────────────────────────── iTerm2 ─────

fn itermcolors(name: &str, text: &str) -> Result<ThemeImport> {
    let v: plist::Value = plist::from_bytes(text.as_bytes())
        .map_err(|e| DesktopError::invalid(format!("not an iTerm2 colour file: {e}")))?;
    let Some(dict) = v.as_dictionary() else {
        return Err(DesktopError::invalid("iTerm2 file has no colour table"));
    };
    let color = |key: &str| -> Option<String> {
        let d = dict.get(key)?.as_dictionary()?;
        let ch = |k: &str| {
            d.get(k)
                .and_then(|x| x.as_real().or(x.as_signed_integer().map(|i| i as f64)))
        };
        let (r, g, b) = (
            ch("Red Component")?,
            ch("Green Component")?,
            ch("Blue Component")?,
        );
        Some(format!(
            "#{:02x}{:02x}{:02x}",
            component(r),
            component(g),
            component(b)
        ))
    };
    let mut b = Builder::new(name);
    b.background = color("Background Color");
    b.foreground = color("Foreground Color");
    b.cursor = color("Cursor Color");
    b.selection = color("Selection Color");
    for i in 0..16 {
        b.set_ansi(i, color(&format!("Ansi {i} Color")));
    }
    single(b)
}

// ───────────────────────────── Windows Terminal ─────

fn windows_terminal(name: &str, text: &str) -> Result<ThemeImport> {
    // settings.json allows comments and trailing commas; strip the former.
    let cleaned: String = text
        .lines()
        .map(|l| {
            let mut out = String::new();
            let mut in_str = false;
            let mut prev = '\0';
            let mut chars = l.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '"' && prev != '\\' {
                    in_str = !in_str;
                }
                if !in_str && c == '/' && chars.peek() == Some(&'/') {
                    break;
                }
                out.push(c);
                prev = c;
            }
            out
        })
        .collect::<Vec<_>>()
        .join("\n");
    let cleaned = regex_lite_trailing_commas(&cleaned);
    let v: serde_json::Value = serde_json::from_str(&cleaned)
        .map_err(|e| DesktopError::invalid(format!("not a Windows Terminal scheme: {e}")))?;
    let objects: Vec<&serde_json::Value> = match v.get("schemes").and_then(|s| s.as_array()) {
        Some(list) => list.iter().collect(),
        None => match v.as_array() {
            Some(list) => list.iter().collect(),
            None => vec![&v],
        },
    };
    let mut warnings = Vec::new();
    let mut schemes = Vec::new();
    for o in objects {
        let get = |k: &str| o.get(k).and_then(|x| x.as_str()).and_then(hex);
        let label = o
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or(name)
            .to_string();
        let mut b = Builder::new(&label);
        b.background = get("background");
        b.foreground = get("foreground");
        b.cursor = get("cursorColor");
        b.selection = get("selectionBackground");
        for (i, k) in ANSI_NAMES.iter().enumerate() {
            b.set_ansi(i, get(k));
        }
        if let Some(s) = b.finish(&mut warnings) {
            schemes.push(s);
        }
    }
    Ok(ThemeImport { schemes, warnings })
}

/// Remove `,` directly before `}` or `]` (JSONC leniency) without a regex crate.
fn regex_lite_trailing_commas(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ',' {
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && (chars[j] == '}' || chars[j] == ']') {
                i += 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

// ───────────────────────────── Alacritty ─────

const ALACRITTY_NORMAL: [&str; 8] = [
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
];

fn alacritty_toml(name: &str, text: &str) -> Result<ThemeImport> {
    // toml 1.x parses a bare `Value` as a single value; a document is a `Table`.
    let v: toml::Value = text
        .parse::<toml::Table>()
        .map(toml::Value::Table)
        .map_err(|e| DesktopError::invalid(format!("not an Alacritty TOML file: {e}")))?;
    let colors = v.get("colors").unwrap_or(&v);
    let get = |table: &str, key: &str| -> Option<String> {
        colors.get(table)?.get(key)?.as_str().and_then(hex)
    };
    let mut b = Builder::new(name);
    b.background = get("primary", "background");
    b.foreground = get("primary", "foreground");
    b.cursor = get("cursor", "cursor").or_else(|| get("cursor", "text"));
    b.selection = get("selection", "background");
    for (i, k) in ALACRITTY_NORMAL.iter().enumerate() {
        b.set_ansi(i, get("normal", k));
        b.set_ansi(i + 8, get("bright", k));
    }
    single(b)
}

/// Flat `key: value` reader for the two-level YAML Alacritty and Gogh use.
/// Returns `(section, key, value)` triples; nested sections join with `.`.
fn yaml_lite(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    for raw in text.lines() {
        // Only whole-line comments: `#` also starts every colour value.
        let line = raw.trim_end();
        if line.trim().is_empty()
            || line.trim_start().starts_with('#')
            || line.trim_start().starts_with("- ")
        {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let Some((k, v)) = line.trim().split_once(':') else {
            continue;
        };
        while stack.last().is_some_and(|(i, _)| *i >= indent) {
            stack.pop();
        }
        let key = k.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
        let value = v.trim();
        if value.is_empty() {
            stack.push((indent, key));
        } else {
            let section = stack
                .iter()
                .map(|(_, s)| s.as_str())
                .collect::<Vec<_>>()
                .join(".");
            out.push((section, key, value.to_string()));
        }
    }
    out
}

fn alacritty_yaml(name: &str, text: &str) -> Result<ThemeImport> {
    let entries = yaml_lite(text);
    let get = |section: &str, key: &str| -> Option<String> {
        entries
            .iter()
            .find(|(s, k, _)| (s == section || s.ends_with(&format!(".{section}"))) && k == key)
            .and_then(|(_, _, v)| hex(v))
    };
    let mut b = Builder::new(name);
    b.background = get("colors.primary", "background").or_else(|| get("primary", "background"));
    b.foreground = get("colors.primary", "foreground").or_else(|| get("primary", "foreground"));
    b.cursor = get("colors.cursor", "cursor").or_else(|| get("cursor", "cursor"));
    b.selection = get("colors.selection", "background").or_else(|| get("selection", "background"));
    for (i, k) in ALACRITTY_NORMAL.iter().enumerate() {
        b.set_ansi(i, get("colors.normal", k).or_else(|| get("normal", k)));
        b.set_ansi(i + 8, get("colors.bright", k).or_else(|| get("bright", k)));
    }
    single(b)
}

// ───────────────────────────── Gogh ─────

fn gogh(name: &str, text: &str) -> Result<ThemeImport> {
    let entries = yaml_lite(text);
    let get = |key: &str| -> Option<&str> {
        entries
            .iter()
            .find(|(_, k, _)| k == key)
            .map(|(_, _, v)| v.as_str())
    };
    let label = get("name")
        .map(|n| n.trim_matches(|c| c == '"' || c == '\'').to_string())
        .unwrap_or_else(|| name.to_string());
    let mut b = Builder::new(&label);
    b.background = get("background").and_then(hex);
    b.foreground = get("foreground").and_then(hex);
    b.cursor = get("cursor").and_then(hex);
    for i in 0..16 {
        b.set_ansi(i, get(&format!("color_{:02}", i + 1)).and_then(hex));
    }
    single(b)
}

// ───────────────────────────── Kitty / Ghostty ─────

/// `key value` or `key = value` lines; comments start with `#`.
fn kv_lines(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = match l.split_once('=') {
                Some((k, v)) if !k.trim().contains(char::is_whitespace) => (k, v),
                _ => l.split_once(char::is_whitespace)?,
            };
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

fn kitty(name: &str, text: &str) -> Result<ThemeImport> {
    let kv = kv_lines(text);
    let get = |key: &str| kv.iter().find(|(k, _)| k == key).and_then(|(_, v)| hex(v));
    let mut b = Builder::new(name);
    b.background = get("background");
    b.foreground = get("foreground");
    b.cursor = get("cursor");
    b.selection = get("selection_background");
    for i in 0..16 {
        b.set_ansi(i, get(&format!("color{i}")));
    }
    single(b)
}

fn ghostty(name: &str, text: &str) -> Result<ThemeImport> {
    let kv = kv_lines(text);
    let get = |key: &str| kv.iter().find(|(k, _)| k == key).and_then(|(_, v)| hex(v));
    let mut b = Builder::new(name);
    b.background = get("background");
    b.foreground = get("foreground");
    b.cursor = get("cursor-color");
    b.selection = get("selection-background");
    for (k, v) in &kv {
        if k == "palette"
            && let Some((i, c)) = v.split_once('=')
            && let Ok(i) = i.trim().parse::<usize>()
        {
            b.set_ansi(i, hex(c));
        }
    }
    single(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSI: [&str; 16] = [
        "#000000", "#ff0000", "#00ff00", "#ffff00", "#0000ff", "#ff00ff", "#00ffff", "#ffffff",
        "#555555", "#ff5555", "#55ff55", "#ffff55", "#5555ff", "#ff55ff", "#55ffff", "#eeeeee",
    ];

    fn check(out: ThemeImport, name: &str) {
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        assert_eq!(out.schemes.len(), 1);
        let s = &out.schemes[0];
        assert_eq!(s.name, name);
        assert_eq!(s.background, "#101010");
        assert_eq!(s.foreground, "#d0d0d0");
        assert_eq!(s.cursor, "#ffcc00");
        assert_eq!(s.ansi, ANSI);
    }

    #[test]
    fn windows_terminal_scheme_and_settings() {
        let mut o = String::from(
            r##"{ "name": "WT Test", "background": "#101010", "foreground": "#D0D0D0", "cursorColor": "#FFCC00", "selectionBackground": "#FFFFFF","##,
        );
        for (i, k) in ANSI_NAMES.iter().enumerate() {
            o.push_str(&format!(r#""{k}": "{}","#, ANSI[i]));
        }
        o.push('}');
        let out = parse("wt.json", &o).unwrap();
        check(out, "WT Test");
        assert_eq!(out_sel(&o), Some("#ffffff".into()));
        let settings = format!("{{\n  // comment\n  \"schemes\": [ {o} ],\n}}");
        let out = parse("settings.json", &settings).unwrap();
        check(out, "WT Test");
    }

    fn out_sel(o: &str) -> Option<String> {
        parse("x.json", o).unwrap().schemes[0].selection.clone()
    }

    #[test]
    fn alacritty_toml_and_yaml() {
        let names = ALACRITTY_NORMAL;
        let mut t = String::from(
            "[colors.primary]\nbackground = '#101010'\nforeground = '#d0d0d0'\n[colors.cursor]\ncursor = '#ffcc00'\n[colors.normal]\n",
        );
        for (i, n) in names.iter().enumerate() {
            t.push_str(&format!("{n} = '{}'\n", ANSI[i]));
        }
        t.push_str("[colors.bright]\n");
        for (i, n) in names.iter().enumerate() {
            t.push_str(&format!("{n} = '{}'\n", ANSI[i + 8]));
        }
        check(parse("dark.toml", &t).unwrap(), "dark");

        let mut y = String::from(
            "colors:\n  primary:\n    background: '0x101010'\n    foreground: '0xd0d0d0'\n  cursor:\n    cursor: '0xffcc00'\n  normal:\n",
        );
        for (i, n) in names.iter().enumerate() {
            y.push_str(&format!("    {n}: '0x{}'\n", &ANSI[i][1..]));
        }
        y.push_str("  bright:\n");
        for (i, n) in names.iter().enumerate() {
            y.push_str(&format!("    {n}: '0x{}'\n", &ANSI[i + 8][1..]));
        }
        check(parse("dark.yml", &y).unwrap(), "dark");
    }

    #[test]
    fn gogh_kitty_ghostty() {
        let mut g = String::from(
            "name: \"Gogh Test\"\nbackground: \"#101010\"\nforeground: \"#d0d0d0\"\ncursor: \"#ffcc00\"\n",
        );
        for (i, c) in ANSI.iter().enumerate() {
            g.push_str(&format!("color_{:02}: \"{c}\"\n", i + 1));
        }
        check(parse("gogh.yml", &g).unwrap(), "Gogh Test");

        let mut k = String::from(
            "# kitty\nbackground #101010\nforeground #d0d0d0\ncursor #ffcc00\nselection_background #444444\n",
        );
        for (i, c) in ANSI.iter().enumerate() {
            k.push_str(&format!("color{i} {c}\n"));
        }
        check(parse("my.conf", &k).unwrap(), "my");

        let mut gh =
            String::from("background = 101010\nforeground = d0d0d0\ncursor-color = ffcc00\n");
        for (i, c) in ANSI.iter().enumerate() {
            gh.push_str(&format!("palette = {i}={c}\n"));
        }
        check(parse("ghostty", &gh).unwrap(), "ghostty");
    }

    #[test]
    fn itermcolors_plist() {
        fn color(key: &str, hex: &str) -> String {
            let r = u8::from_str_radix(&hex[1..3], 16).unwrap() as f64 / 255.0;
            let g = u8::from_str_radix(&hex[3..5], 16).unwrap() as f64 / 255.0;
            let b = u8::from_str_radix(&hex[5..7], 16).unwrap() as f64 / 255.0;
            format!(
                "<key>{key}</key><dict><key>Blue Component</key><real>{b}</real><key>Green Component</key><real>{g}</real><key>Red Component</key><real>{r}</real></dict>"
            )
        }
        let mut p = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>"#,
        );
        for (i, c) in ANSI.iter().enumerate() {
            p.push_str(&color(&format!("Ansi {i} Color"), c));
        }
        p.push_str(&color("Background Color", "#101010"));
        p.push_str(&color("Foreground Color", "#d0d0d0"));
        p.push_str(&color("Cursor Color", "#ffcc00"));
        p.push_str("</dict></plist>");
        check(parse("Solarized.itermcolors", &p).unwrap(), "Solarized");
    }

    #[test]
    fn rejects_garbage_and_fills_gaps() {
        assert!(parse("x.txt", "hello").is_err());
        let partial = "background #101010\nforeground #d0d0d0\ncolor0 #000000\ncolor1 #ff0000\ncolor2 #00ff00\ncolor3 #ffff00\ncolor4 #0000ff\ncolor5 #ff00ff\ncolor6 #00ffff\ncolor7 #ffffff\n";
        let out = parse("p.conf", partial).unwrap();
        assert_eq!(out.schemes.len(), 1);
        assert_eq!(out.warnings.len(), 1);
        assert_eq!(out.schemes[0].ansi[15], "#d0d0d0");
        assert_eq!(hex("#abc"), Some("#aabbcc".into()));
        assert_eq!(hex("0xABCDEF12"), Some("#abcdef".into()));
        assert_eq!(hex("red"), None);
    }
}
