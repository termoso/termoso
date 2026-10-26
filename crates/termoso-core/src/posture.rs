//! Device posture: what this installation can tell the server about the
//! security state of the device it runs on (see `Posture` in the proto).
//!
//! Desktop builds probe the OS with short-lived commands ([`collect`]);
//! mobile builds get the facts from the platform shell ([`set_reported`]).
//! The latest value is kept in memory and attached to every `DeviceInfo`
//! the client sends ([`reported`]). Nothing here is authoritative on its own —
//! the server simply refuses sign-in to teams whose policies require a fact
//! this device cannot prove.

use std::sync::Mutex;
use std::time::Duration;

pub use termoso_proto::auth::Posture;

static REPORTED: Mutex<Option<Posture>> = Mutex::new(None);

/// How long a single probe command may run.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Remember the posture that goes out with the next `DeviceInfo`.
pub fn set_reported(p: Posture) {
    *REPORTED.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
}

/// The posture last stored with [`set_reported`], if any.
pub fn reported() -> Option<Posture> {
    REPORTED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Probe the desktop OS. `secure_key_storage` is decided by the caller, who
/// knows whether the device key ended up in a TPM / Secure Enclave.
pub async fn collect(secure_key_storage: Option<bool>) -> Posture {
    let (os_version, disk_encryption, screen_lock) =
        tokio::join!(os_version(), disk_encryption(), screen_lock());
    Posture {
        os_version,
        disk_encryption,
        screen_lock,
        secure_key_storage,
    }
}

async fn run(program: &str, args: &[&str]) -> Option<String> {
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let out = tokio::time::timeout(PROBE_TIMEOUT, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

async fn os_version() -> String {
    if cfg!(target_os = "linux") {
        if let Ok(f) = tokio::fs::read_to_string("/etc/os-release").await
            && let Some(l) = f.lines().find(|l| l.starts_with("PRETTY_NAME="))
        {
            return l["PRETTY_NAME=".len()..].trim_matches('"').to_string();
        }
        run("uname", &["-sr"])
            .await
            .unwrap_or_default()
            .trim()
            .to_string()
    } else if cfg!(target_os = "macos") {
        let v = run("sw_vers", &["-productVersion"])
            .await
            .unwrap_or_default();
        format!("macOS {}", v.trim())
    } else if cfg!(target_os = "windows") {
        let v = run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Environment]::OSVersion.Version.ToString()",
            ],
        )
        .await
        .unwrap_or_default();
        format!("Windows {}", v.trim())
    } else {
        String::new()
    }
}

/// Whole-disk encryption of the system volume: LUKS/dm-crypt, FileVault, BitLocker.
async fn disk_encryption() -> Option<bool> {
    if cfg!(target_os = "linux") {
        // Any dm-crypt mapping in the block tree counts; LUKS root is the usual case.
        if let Ok(mut rd) = tokio::fs::read_dir("/sys/class/block").await {
            let mut seen = false;
            while let Ok(Some(e)) = rd.next_entry().await {
                seen = true;
                if let Ok(uuid) = tokio::fs::read_to_string(e.path().join("dm/uuid")).await
                    && uuid.starts_with("CRYPT-")
                {
                    return Some(true);
                }
            }
            if seen {
                return Some(false);
            }
        }
        None
    } else if cfg!(target_os = "macos") {
        let out = run("fdesetup", &["status"]).await?;
        Some(out.contains("FileVault is On"))
    } else if cfg!(target_os = "windows") {
        let out = run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus",
            ],
        )
        .await?;
        let s = out.trim();
        match s {
            "On" | "1" => Some(true),
            "Off" | "0" => Some(false),
            _ => None,
        }
    } else {
        None
    }
}

/// A lock that engages on idle / sleep and asks for the user's credentials.
async fn screen_lock() -> Option<bool> {
    if cfg!(target_os = "linux") {
        if let Some(out) = run(
            "gsettings",
            &["get", "org.gnome.desktop.screensaver", "lock-enabled"],
        )
        .await
            && out.contains("true") | out.contains("false")
        {
            return Some(out.contains("true"));
        }
        for tool in ["kreadconfig6", "kreadconfig5"] {
            if let Some(out) = run(
                tool,
                &[
                    "--file",
                    "kscreenlockerrc",
                    "--group",
                    "Daemon",
                    "--key",
                    "Autolock",
                ],
            )
            .await
            {
                let v = out.trim();
                if v.is_empty() || v == "true" {
                    return Some(true);
                }
                if v == "false" {
                    return Some(false);
                }
            }
        }
        None
    } else if cfg!(target_os = "macos") {
        let out = run("sysadminctl", &["-screenLock", "status"]).await?;
        if out.contains("screenLock is off") {
            Some(false)
        } else if out.contains("screenLock") {
            Some(true)
        } else {
            None
        }
    } else if cfg!(target_os = "windows") {
        let out = run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$d='HKCU:\\Control Panel\\Desktop'; $p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; \
                 $a=(Get-ItemProperty $d -ErrorAction SilentlyContinue).ScreenSaveActive; \
                 $s=(Get-ItemProperty $d -ErrorAction SilentlyContinue).ScreenSaverIsSecure; \
                 $t=(Get-ItemProperty $p -ErrorAction SilentlyContinue).InactivityTimeoutSecs; \
                 if (($a -eq '1' -and $s -eq '1') -or ($t -gt 0)) { 'on' } else { 'off' }",
            ],
        )
        .await?;
        match out.trim() {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_round_trip() {
        assert!(reported().is_none() || reported().is_some());
        set_reported(Posture {
            os_version: "test".into(),
            disk_encryption: Some(true),
            ..Default::default()
        });
        let p = reported().unwrap();
        assert_eq!(p.os_version, "test");
        assert_eq!(p.disk_encryption, Some(true));
    }

    #[tokio::test]
    async fn collect_fills_os_version_on_desktop() {
        let p = collect(Some(false)).await;
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            assert!(!p.os_version.is_empty());
        }
        assert_eq!(p.secure_key_storage, Some(false));
    }
}
