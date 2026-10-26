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
