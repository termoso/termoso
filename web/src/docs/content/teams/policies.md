---
title: Team policies
description: Rules an owner sets once for the whole team — what the server enforces and what the apps enforce on members' devices.
---

Owners (and holders of `policies.manage`) set team policies in **Team → Policies** on the desktop; Android shows them read-only. When a member belongs to several teams the strictest value applies to them.

## Enforced by the server

| Policy | Effect |
|---|---|
| MFA | `any` or `passkey` — members without it cannot sign in. |
| Session lifetime | Hours before members must sign in again (1–2160). |
| SSO-only + approved domains | Members sign in only through the team's identity provider; invitations are limited to the listed e-mail domains. Owners are exempt so they can never be locked out. |
| Device approval / admin approval for new devices | New devices wait for the member — or an admin — before they can sign in. |
| IP allow-list | Members may sign in only from the listed networks (CIDR). |
| Audit retention, recording retention | How long audit events and session recordings are kept. |
| Session recording | `required` switches recording on in every team vault. |
| Key / password rotation age | Hosts whose secrets are older than the limit are flagged for rotation. |
| Device posture: disk encryption, screen lock, hardware-backed key | At sign-in every app reports what it can prove about its device — OS version, encrypted system disk (LUKS / FileVault / BitLocker / Android FBE), screen lock, device key in TPM / Secure Enclave / StrongBox. A team may require any of the three; a device that cannot prove a required fact (including old clients that report nothing) is refused with `device_posture` and the attempt is audited (`login.posture_denied`). Owners are exempt so the team can never lock itself out. The last report is shown in **Account → Devices**. |

## Enforced by the apps

These rules concern data the server never sees (keys, host credentials, connections), so the desktop and Android apps apply them to every host, key and rule that lives in a **team vault**. The apps keep an encrypted copy of the policies and refresh it with every sync, so the rules hold offline too.

| Policy | Effect |
|---|---|
| Deny device-local identities | Keys must live in team vaults or SSH ID. |
| Key-based authentication only (`auth = keys_only`) | Connections to team hosts never offer a password or answer keyboard-interactive prompts; keys, certificates, the team CA, SSH ID and agents still work. A host with no key-based method is refused. |
| Jump host required | A team host is opened only through a jump host on its chain; a direct connection is refused with an explanation. |
| No local export (`export = deny`) | Encrypted backups and CSV export skip team vaults (and refuse when one is asked for by name); private keys of team vaults cannot be exported. |
| Forwarded ports | Allow-list of remote ports (`22`, `8000-8999`) members may forward from team hosts. Empty allows any; a non-empty list also disables dynamic (SOCKS) forwarding, which could reach any port. |

Personal vaults are never affected. Changes are audited (`policies.update`) and reach members' devices on their next sync.

## API

`GET /api/v1/teams/{id}/policies` returns the policies and, under `effective_for_me`, what applies to the caller across all their teams; `PUT` with any subset of fields updates them (`policies.manage`).
