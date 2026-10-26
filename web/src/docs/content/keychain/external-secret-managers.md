---
title: External secret managers
description: Keep host passwords and key passphrases in 1Password, Bitwarden or pass and let Termoso fetch them at connect time.
---

A password or key passphrase field can hold a **reference** instead of the secret. Termoso resolves it on the machine that opens the connection, right before authenticating, and never writes the value back to the vault or syncs it. The reference itself is an ordinary (encrypted) vault field, so it is shared with the team like any other credential — each member's machine resolves it against *their* manager.

| Reference | Resolved with |
|---|---|
| `op://Vault/Item/field` | 1Password CLI — `op read` |
| `bw://<item id or name>` or `bw://<item>/<field>` | Bitwarden CLI — `bw get password|username|totp|notes <item>`; any other name is looked up among the item's custom fields |
| `pass://path/to/entry` | passwordstore — first line of `pass show` |
| `env://NAME` | environment variable `NAME` |

Type the reference into the **Password** field of an identity or host, or the **Passphrase** field of a key. The helper text confirms it is treated as a reference.

## Requirements

- The CLI must be on `PATH` of the Termoso process and already signed in: `op signin` (or `OP_SERVICE_ACCOUNT_TOKEN`), `bw unlock` with `BW_SESSION` exported, a running gpg-agent for `pass`. Termoso only runs the CLI; it never sees the manager's credentials.
- A reference that cannot be resolved fails the connection with the CLI's message (not installed, locked, item not found) instead of falling back to another method.
- Resolved values are cached in memory for 5 minutes, so opening several tabs or running a snippet on many hosts asks the manager once.
- The CLI may take up to 60 seconds (biometric prompts); after that the connection fails.

## Where references work

- **Desktop** — all protocols that use the identity password or key passphrase.
- **API bridge** — headless runs (MCP tools, automations) resolve references the same way, so a bridge in CI can use `env://` or a 1Password service account.
- **Android / iOS** — only `env://` can be resolved on the device; other schemes fail with a clear message. Keep a plain secret or use the desktop for those hosts.

Backups export the reference, not the resolved secret.
