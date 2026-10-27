---
title: Import existing hosts
description: Bring hosts in from OpenSSH, PuTTY, Termius, MobaXterm, SecureCRT, ZOC, cloud providers, a text snippet or a QR code instead of typing them again.
---

## Desktop

Open **Hosts → New host ▾ → Import…** and pick a source:

![Import sources](/docs/img/desktop-import.png)

| Source           | What is imported                                                                                                                                                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| OpenSSH `~/.ssh` | `Host` blocks from `config` (address, user, port, `IdentityFile`, `ProxyJump`, `ForwardAgent`, proxies), the keys they reference and `known_hosts`. Wildcard blocks (`Host *`) are applied as defaults, not imported as hosts. |
| PuTTY            | Saved sessions, read from the registry on Windows or from a `.reg` export elsewhere, including the key file and proxy settings.                                                                                                |
| Termius          | The Termius CSV export: hosts, groups and tags. Termius does not export passwords or keys — see [Coming from Termius](/docs/getting-started/migrating-from-termius).                                                           |
| MobaXterm        | A `.mxtsessions` export or `MobaXterm.ini`: SSH and Telnet sessions with their folders, gateway (jump) chains, SOCKS/HTTP proxies, key paths, X11 and agent forwarding. Passwords are stored encrypted inside MobaXterm and are not part of the file. |
| SecureCRT        | The `Config/Sessions` directory (sub-folders become groups), a single session `.ini`, or the XML from *File → Export Settings*: SSH and Telnet sessions, key files, `Session:` firewalls as jump hosts, descriptions as notes. Saved passwords are encrypted with the config passphrase and are skipped. |
| ZOC Terminal     | `HostDirectory.zhd` (in *ZOC Files → Options*): SSH hosts with folders, usernames, key files and memos. Serial entries are listed as skipped. |

Parsing only produces a **preview**: hosts, keys and settings are listed with what will be created, and nothing is written until you pick what to import and a target vault.

![Import preview](/docs/img/desktop-import-preview.png)

- A `ProxyJump` becomes a **jump host** reference to the imported bastion, so chains keep working.
- Hosts that are already in the vault (same address, port and user) are recognised, so importing the same file twice does not duplicate them. What the existing host is missing — group, tags, notes, password, key, proxy, jump hosts — is filled in from the import; anything already set is kept. That lets you combine sources in either order, for example the Termius CSV for groups and passwords and `~/.ssh` for keys.
- Private keys are read from disk only when you confirm, and go into the Keychain encrypted. A key with a passphrase is asked for it on first use, not during import.
- Passwords found in the source never reach the interface; PuTTY and Termius do not export them anyway, MobaXterm and SecureCRT keep theirs encrypted and the import says so per session.

### Cloud providers

**New host ▾ → AWS / DigitalOcean / Azure Integration** lists machines from AWS EC2, DigitalOcean or Azure and turns them into a host group that mirrors the account — one subgroup per region or project, instance names as host names, public or private address as you choose. **Sync now** (or the background refresh) adds new machines, updates addresses that changed and, if you ask, removes hosts the provider no longer lists — anything you set on a host yourself (credentials, tags, notes) stays.

The provider credentials are kept only in this device's encrypted local storage: they are never part of a vault, so they never sync or reach the server. The hosts the integration created do sync like any other.

### Export

**New host ▾ → Export CSV** writes the hosts of the current vault (or the selection) in the same CSV layout Termius uses, so a Termoso export imports into either client. Passwords and keys are not exported.

## Android

**+ → Import hosts** on the Hosts screen takes pasted text, a QR code or a file from the system picker and runs the same parsers as the desktop: OpenSSH `ssh_config`, a PuTTY registry export (`.reg`), MobaXterm bookmarks (`.mxtsessions`), SecureCRT settings (`.ini` / `.xml`), the ZOC host directory and CSV (the desktop's template or any sheet with host/address columns). The format is detected from the file name and contents; loose `user@host:port` lines work too. Tick the hosts you want — label, address, port, user and a password from the source are imported; key files, jump hosts, proxies and port-forwarding rules are not on the phone, so they are listed as warnings instead. Copy the export to the phone (or open it from a cloud drive) and pick it.

![Quick Import on Android](/docs/img/android-quick-import.png)

QR decoding runs on the device and the camera is only requested when you open the scanner. A handy trick for a new phone: `cat ~/.ssh/config | qrencode -t ansiutf8` on the desktop, then scan.

## Discover on local network

**Discover on local network** (in the **+** menu on Android, and under **New host ▾** on the desktop) lists SSH and SFTP servers that advertise themselves over mDNS/DNS-SD on your network — Linux machines with Avahi, macOS with Remote Login on, NAS boxes, Raspberry Pis. Tap one to connect or save it.

## Import from Tailscale, NetBird or ZeroTier

On the desktop, **New host ▾ → Import from Tailscale / NetBird…** lists the machines your overlay-network client knows about. Termoso only asks the client that is already installed and signed in on this computer (`tailscale status --json`, `netbird status --json`, `zerotier-cli -j listnetworks`); nothing is sent anywhere and nothing is stored until you click **Add**.

- Pick the devices to import, choose whether hosts connect by **DNS name** (MagicDNS / NetBird FQDN — survives address changes) or by **IP address**, and set an optional username, group and vault.
- Devices already present in the vault (same name or address) are shown but skipped, so re-importing never creates duplicates. Offline peers are listed greyed out and can still be imported.
- Tailscale tags (`tag:server` → `server`) and NetBird groups become host tags.
- ZeroTier's CLI only reports this computer's own addresses per network, not other peers, so for ZeroTier the list is informational; add peers by their managed IP from the ZeroTier Central page.

If no client is found, the dialog says so — install Tailscale, NetBird or ZeroTier, sign in, then **Refresh**.

## Shell history

**Settings → Terminal → Import shell history** reads the history file of the remote shell when you connect, so autocomplete can suggest commands you already ran there. It is off by default, and the imported history is kept in memory only for that session.
