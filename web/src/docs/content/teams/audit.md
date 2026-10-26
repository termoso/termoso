---
title: Activity log and tamper evidence
description: Every team-scoped change is logged, hash-chained and signed by the server; verify the chain from the console or with ssh-keygen.
---

Every team-scoped change — members, roles, invites, vaults and their access, entities, policies, devices, sign-ins refused by a policy, automations, SSH CA — lands in the team's activity log (`GET /api/v1/teams/{id}/audit`, **Team → Activity** in the apps). The server never sees vault payloads, so an entry names the kind and id of what changed and the client resolves it to a label where it holds the vault key. Members see the log too: the software reports *to* the team, not on it.

## What makes it tamper-evident

An audit log is only evidence if nobody — including whoever runs the database — can quietly rewrite it. Termoso chains and signs the log:

- **Hash chain.** Every entry stores `hash = SHA-256(canonical fields ‖ prev_hash)`, where `prev_hash` is the hash of the team's previous entry. The database computes it in a trigger that serialises inserts per team, so the chain never forks, and no code path can write an unchained row. Editing an entry changes its hash; deleting one leaves a gap the next entry's `prev_hash` exposes. Both hashes are returned with every entry and in CSV / JSONL exports.
- **Signed checkpoints.** Once an hour (and on demand via `POST /api/v1/teams/{id}/audit/checkpoint`, permission `audit.export`) the server signs the head of each chain — `termoso-audit-checkpoint-v1|<team_id>|<last_id>|<hex hash>` — with an Ed25519 key that is generated on first use and sealed with the server master key. The signature is an OpenSSH *sshsig* (namespace `termoso-audit`), so `ssh-keygen -Y verify` can check it without Termoso. The public key is at `GET /audit/key`.
- **Retention anchors.** When retention removes old entries it first records the hash of the newest one it deletes, so the first surviving entry still has a known predecessor and the remaining chain verifies.

## Verifying

`GET /api/v1/teams/{id}/audit/verify` (permission `audit.view`) walks the whole chain in one pass and returns:

| Field | Meaning |
|---|---|
| `ok` | Every entry re-hashes, links to its predecessor, the first surviving entry is genesis or a retention anchor, and the latest signed checkpoint matches a stored entry and verifies. |
| `events`, `first_id`, `last_id`, `head_hash` | What was checked. |
| `broken_at`, `reason` | First failing entry: `hash` (contents changed), `link` (an entry before it is missing or reordered), `anchor` (the oldest entry's predecessor is unknown), `unhashed` (written before the chain existed). |
| `checkpoint`, `checkpoint_ok` | Latest signed checkpoint and whether its entry and signature check out. |

To verify a checkpoint independently, save the public key from `/audit/key` to `allowed_signers` as `termoso <key>`, the signature to `cp.sig`, and run:

```sh
printf 'termoso-audit-checkpoint-v1|%s|%s|%s' "$TEAM_ID" "$LAST_ID" "$HASH" \
  | ssh-keygen -Y verify -f allowed_signers -I termoso -n termoso-audit -s cp.sig
```

Keep an exported copy of the log (or just the checkpoints) off the server: a signed head you hold is what proves later that nothing before it was rewritten.
