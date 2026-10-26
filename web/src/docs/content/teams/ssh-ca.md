---
title: Team SSH certificate authority
description: Short-lived SSH certificates for every member's device, trusted by hosts through one TrustedUserCAKeys line.
---

A team can run its own SSH certificate authority on the Termoso server. Instead of putting every member's public key into `authorized_keys` on every host, hosts trust one CA key, and the server hands each member's device a short-lived user certificate (8 hours by default). Removing a member or a device stops new certificates; nothing on the hosts has to change.

## How it works

1. An admin creates the CA in the team page (**SSH CA** tab). The server generates an Ed25519 key and keeps the private half sealed with its master key.
2. The admin lists the **principals** — login names certificates may carry (`ubuntu`, `deploy`, …) — and optionally the lifetime (1–168 hours) and the certificate extensions (`permit-pty`, `permit-port-forwarding`, `permit-user-rc` by default).
3. Every host of the team gets one line in `sshd_config`:

   ```sh
   curl -fsS https://app.example.com/ca/<team-id> | sudo tee /etc/ssh/termoso_ca.pub >/dev/null
   echo 'TrustedUserCAKeys /etc/ssh/termoso_ca.pub' | sudo tee -a /etc/ssh/sshd_config >/dev/null
   sudo systemctl reload ssh
   ```

   The team page shows the exact command. The URL is public — a CA public key is not a secret, and the team id is not guessable.
4. Each device generates its own key for the CA (separate from your SSH keys and SSH ID) and asks the server for a certificate during the regular account sync. Certificates are cached in the encrypted local store and renewed when a quarter of their lifetime is left.
5. When you connect to a host that lives in a team vault, the client offers the certificate first. If the host does not trust the CA, authentication continues with the identity's own key or password as before.

Hosts match the certificate's principals against the login name, so a member logging in as `deploy` needs `deploy` among the team's principals.

## Permissions

| Permission | Who has it by default | Allows |
|---|---|---|
| `ca.manage` | Owner, Admin | create, configure, rotate, pause and delete the CA; revoke anyone's certificate; see every issued certificate |
| `ca.issue` | Owner, Admin, Member, Viewer | receive certificates for the current device; see and revoke one's own |

Teams that require admin approval of devices only issue certificates to approved devices.

## Rotation and revocation

- **Rotate** generates a new CA key. The previous key stays in the public trusted-keys text for a grace period (24 hours by default) so hosts that re-fetch it keep accepting unexpired certificates. Hosts that fetched the file once need to fetch it again — a cron entry that re-runs the `curl` line keeps them current.
- **Revoke** marks a certificate as revoked and it is no longer renewed. Because sshd does not consult the server, a revoked but unexpired certificate still works on hosts that do not enforce a key revocation list. Keep lifetimes short, or export `GET /api/v1/teams/{id}/ca/revoked` (a KRL specification) and turn it into a KRL with `ssh-keygen -k -f /etc/ssh/revoked.krl -s termoso_ca.pub spec.txt`, referenced from `sshd_config` as `RevokedKeys`.
- Revoking a device or removing a member revokes their live certificates immediately.

## Audit

`ca.created`, `ca.updated`, `ca.disabled`, `ca.rotated`, `ca.deleted`, `ca.issued` (serial, key fingerprint, principals, expiry) and `ca.revoked` appear in the team audit log and go out through webhooks like any other event.

## API

| Method | Path | Permission |
|---|---|---|
| `GET` / `PUT` / `DELETE` | `/api/v1/teams/{id}/ca` | `team.view` / `ca.manage` / `ca.manage` |
| `POST` | `/api/v1/teams/{id}/ca/rotate` | `ca.manage` |
| `POST` | `/api/v1/teams/{id}/ca/issue` | `ca.issue` |
| `GET` | `/api/v1/teams/{id}/ca/certificates` | `team.view` (own) / `ca.manage` (all) |
| `POST` | `/api/v1/teams/{id}/ca/certificates/{cid}/revoke` | own / `ca.manage` |
| `GET` | `/api/v1/teams/{id}/ca/revoked` | `team.view` |
| `GET` | `/ca/{team_id}` | public, `text/plain` |
