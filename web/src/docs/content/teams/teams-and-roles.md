---
title: Teams and roles
description: Create a team, invite people and decide who manages it — free for any number of members.
---

A team groups people who share infrastructure. Teams and memberships are managed in the web cabinet or in the apps; the shared hosts live in [team vaults](/docs/teams/team-vaults).

## Creating a team

Sign in to the cabinet, open **Teams** and press **New team**. You become its **Owner**. On self-hosted servers the administrator can restrict team creation to admins.

## Roles

| Team role  | Can do                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------- |
| **Owner**  | Everything an admin can, plus delete the team and transfer ownership. Exactly one per team. |
| **Admin**  | Manage members, invitations and vaults.                                                     |
| **Member** | Use the vaults they were given access to.                                                   |

Team roles decide who manages the team. Access to the data is granted separately, per vault — see [Team vaults](/docs/teams/team-vaults#vault-roles).

## Inviting people

**Invite** sends an e-mail with a link (or gives you the link to pass on). The invitee signs up or signs in, and an admin then grants vault access. Because vault keys are sealed to each member's public key, granting access happens on an admin's device: the server cannot hand out keys on its own.

## Removing members

Removing a member revokes their sessions for the team at once. Rotate the vault keys afterwards (the cabinet offers it) so that anything they might have kept a copy of becomes useless for new data.

## Activity

The team page shows an activity log of membership changes, vault access and shared sessions. Admins can opt in to a daily or weekly e-mail digest.

## Access reviews

Access tends to accumulate: people change roles, contractors finish, a vault shared "for a week" stays shared for a year. An access review is the periodic question "does everyone here still need this?", asked of the people who can answer it, with the answer recorded.

- **Opening.** `POST /api/v1/teams/{id}/access-reviews` (permission `members.remove`) snapshots every non-owner membership and every access to a team vault, with each person's role and when they were last seen. Or set **Access review cadence** in the team policies and the server opens one every N days (7–365) and e-mails owners and admins; one open review per team at a time.
- **Deciding.** Each line gets `keep` or `remove` (and an optional note) via `POST …/access-reviews/{rid}/items/{iid}`. Nobody can remove themselves this way.
- **Completing.** `POST …/access-reviews/{rid}/complete` applies the removals through the normal paths — members leave the team (`member.removed`), vault accesses are revoked (`vault.access_revoked`) — each audit entry tagged with the review id, and then records `access_review.completed` with the counts. By default it refuses while lines are undecided; send `{"undecided": "keep"}` to confirm the rest. `…/cancel` closes a review without changes.
- **Reminders.** A review is due 14 days after it opens; owners and admins get one reminder once it is overdue.

The list of past reviews (`GET /api/v1/teams/{id}/access-reviews`) and their lines is the evidence an auditor asks for: who confirmed whose access, when, and what was removed.

## Break-glass

A team has exactly one owner. If that person is unreachable — on a plane, locked out, gone — nobody can change roles, revoke a leaked vault access or remove a departed member. Break-glass is the sealed envelope for that day.

- **Set-up** (owner, fresh step-up): `PUT /api/v1/teams/{id}/break-glass` with the designated member and a duration (1–72 h) returns a one-time secret, shown once. Store it offline — a safe, a password manager the designated person does *not* control alone. `GET` shows who is designated and the status; `DELETE` removes it.
- **Use** (the designated member only): `POST …/break-glass/use` with the secret and a reason. The member becomes a team **admin** immediately for the configured duration; every owner and admin is e-mailed, `break_glass.used` is audited (and so delivered to webhooks / SIEM) with the reason, and the previous role is remembered. Five wrong secrets lock the endpoint for 15 minutes and are audited as `break_glass.denied`.
- **End**: the role reverts when the time is up (`break_glass.expired`) or earlier via `POST …/break-glass/end` by the owner or the member (`break_glass.ended`). A redeemed secret is spent: the owner issues a new one when they are back.

Admin, not owner: the emergency role can do everything day-to-day (members, roles, vaults, policies, reviews) but cannot delete the team or transfer ownership, so a stolen envelope cannot take the team away.
