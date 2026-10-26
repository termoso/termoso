---
title: Connecting to a server
description: Saved hosts, quick connect, authentication prompts, host keys, jump hosts and proxies, and every option a host can carry.
---

## Quick connect

Type into the search field on the Hosts screen and press <kbd>Enter</kbd>:

```
deploy@10.0.1.12
deploy@10.0.1.12:2222
ssh://deploy@edge.example.io
telnet://switch.lab:23
```

The session opens in a new tab. If a saved host matches the address and user, its settings (key, jump host, terminal preferences) are used; otherwise the connection is ad hoc and shows up in the connection history under **Logs**, from where it can be saved as a host.

The same field filters the host list as you type, and <kbd>Ctrl</kbd>+<kbd>J</kbd> opens a jump list across hosts and open tabs.

![The Hosts screen](/docs/img/desktop-hosts.png)

## Command line

The desktop binary doubles as a launcher, so a host can be opened from a shell, a script or another tool:

```
termoso ssh deploy@10.0.1.12          # ad hoc, or the saved host with that address and user
termoso ssh -l root -p 2200 edge      # OpenSSH-style flags
termoso ssh "prod web"                # a saved host by label
termoso telnet switch.lab:23
termoso sftp prod-web                 # SFTP browser on a saved host
termoso open termoso://host/<id>      # a host link copied from the app
termoso local                         # local terminal
termoso new                           # new host dialog
termoso --version
```

Labels are matched case-insensitively, then addresses; with no match the connection is ad hoc, like quick connect. If Termoso is already running, the command goes to that window instead of starting a second one; otherwise the app starts and opens it. Files on the command line (keys, colour schemes, `ssh_config`) and `ssh://` / `telnet://` / `termoso://` links keep working as before.

Where the binary is: `termoso` on the `PATH` from the deb/rpm packages; `/Applications/Termoso.app/Contents/MacOS/Termoso` on macOS (add an alias); `%LOCALAPPDATA%\Programs\Termoso\Termoso.exe` from the Windows installer (add that folder to `PATH` to type `termoso` in a shell; `--help` and `--version` print to the console you ran it from).

## Saved hosts

**New host** (or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>N</kbd>) opens the details panel. The address is all that is required; everything else has a sensible default and is saved as you type.

![Host details on the desktop](/docs/img/desktop-host-details.png)

| Field                     | Notes                                                                                                                                                      |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Name                      | Shown on the card and the tab. Defaults to the address.                                                                                                    |
| Address, port, IP version | Hostname or IP; `Auto`, `IPv4` or `IPv6`. Use `IPv4` when a host advertises AAAA records but IPv6 is not routed.                                           |
| Protocol                  | SSH (default), Mosh, Telnet, local shell. Add **Telnet** or **WebDAV** to the same host with the buttons at the bottom.                                    |
| Credentials               | Username plus a password, a key or identity from the Keychain, an SSH certificate, a FIDO2 security key or an SSH ID handle.                               |
| Group, tags, notes        | Groups pass their settings to hosts without their own; tags filter; notes are free text, shown on the card.                                                |
| Jump host                 | Another saved host to hop through (`ProxyJump`). Chains of several hops work.                                                                              |
| Proxy                     | HTTP, SOCKS4 or SOCKS5, with optional credentials.                                                                                                         |
| Terminal                  | Color scheme, character set, backspace key, terminal type, startup snippet, environment variables.                                                         |
| AI coding agent (Android) | Start Claude Code, Gemini CLI, Codex, OpenCode or Aider after connecting — see [Compose and AI](/docs/terminal/compose-and-ai#ai-coding-agent-on-connect). |
| Agent forwarding, X11     | Off by default; X11 needs an X server on the local machine.                                                                                                |

The **New host ▾** menu next to the button also holds **New group**, **Import…**, cloud integrations, **Discover on local network**, **Serial** and **Export CSV**.

![New host menu](/docs/img/desktop-new-host-menu.png)

### Which credentials win

Settings are resolved from the most specific to the least: the host's own value, then the identity it references, then the group chain from the innermost group outwards. A host with an empty username inside a `production` group whose username is `deploy` connects as `deploy`; set anything on the host and it overrides the group.

## Authentication prompts

Whatever the server asks for — password, key passphrase, keyboard-interactive questions, a FIDO2 touch, a PIN — appears **inside the connection card**, in the same place, while the progress line shows which step you are on (_Connecting_, _Verifying host key_, _Authenticating (publickey)_…). On Android the same card is a bottom sheet above the keyboard.

![Password prompt inside the connection card](/docs/img/desktop-auth-prompt.png)

- **Save to this host** stores the answer in the vault, encrypted, so the next connection does not ask.
- A wrong password shows _Authentication failed_ and asks again; the server decides how many attempts you get.
- An empty keyboard-interactive round (some servers send one after a password) is answered automatically instead of showing an empty dialog.
- Methods are tried in the order the server advertises them: certificate, key or security key first, then password or keyboard-interactive. A key the server rejects falls through to the next method silently.

## Host keys

The first connection shows the server's key fingerprint (SHA-256, the same format `ssh` prints). Confirming it stores the key in **Known Hosts** for that vault; from then on a different key for the same address stops the connection and shows the new fingerprint **before anything is sent**. Known hosts sync with the vault, so a key you confirmed on the desktop is trusted on your phone.

![Known hosts](/docs/img/desktop-known-hosts.png)

A server that was legitimately reinstalled is handled by removing its old entry in **Known Hosts** and connecting again. Imported `~/.ssh/known_hosts` entries are merged into the same list.

## Jump hosts and proxies

A **jump host** is any other saved host; Termoso opens an SSH connection to it and tunnels the real connection through, exactly like `ssh -J`. The jump host's own credentials and known-host entry are used, and a jump host can itself have a jump host — three hops through two bastions is a normal setup. Agent forwarding to the jump host is not required.

A **proxy** (HTTP `CONNECT`, SOCKS4, SOCKS5) sits in front of the TCP connection instead, for networks where only a proxy is allowed out. Jump host and proxy can be combined: the proxy carries the connection to the bastion.

## Post-quantum key exchange

When the server supports it, the SSH key exchange uses the ML-KEM hybrid (`mlkem768x25519-sha256`, as in OpenSSH 10) and the tab shows a small **PQ** badge. Nothing to configure; legacy servers keep working with the classic curves.

## Reconnecting

A dropped SSH session shows **Reconnect** in the terminal; the scrollback stays, the new shell starts below it. Mosh sessions survive network changes and sleep on their own — switch from Wi-Fi to mobile data and the prompt is simply there when you come back. Port-forwarding rules reconnect by themselves with increasing back-off.

## Local terminal

**New local terminal** (<kbd>Ctrl</kbd>+<kbd>L</kbd>) opens a shell on this machine — your login shell on Linux and macOS, PowerShell or cmd on Windows. On Android the local terminal runs the [Linux environment](/docs/terminal/linux-on-android) once it is installed, or the Android shell.

## Android

The host list, the details editor and quick connect are the same on the phone, as a full-screen list with search and the **+** menu (**New host**, **Quick Import**, **Discover on local network**).

![Hosts on Android](/docs/img/android-hosts.png)

## Wake-on-LAN

A host that sleeps can carry its MAC address (`aa:bb:cc:dd:ee:ff`). **Wake** sends the magic packet (6 × `FF` + 16 × MAC, UDP ports 9 and 7) to the broadcast address — optionally a specific one, for a router that forwards directed broadcasts — from the machine running Termoso. Like every Wake-on-LAN, it works on the same network segment: wake first, connect a few seconds later.

## Export to `ssh_config` and Ansible

Besides CSV and the encrypted backup, hosts can be exported as an OpenSSH `ssh_config` fragment (one `Host` block per SSH host with `HostName`, `Port`, `User` and `ProxyJump` through the stored jump chain) or as an Ansible INI inventory (a group per folder and per tag, `ansible_host` / `ansible_port` / `ansible_user`). Neither contains secrets — keys and passwords stay in the vault — and both honour the team's **deny local export** policy.
