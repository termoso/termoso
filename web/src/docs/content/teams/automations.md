---
title: Team automations
description: Run a snippet on a set of hosts on a schedule, keep the results per host and get alerted when something fails.
---

An automation runs one of the team's snippets on a set of hosts on a cron-like schedule. The server keeps the schedule and the run history; the snippet text and the host credentials never leave the vault — a member's device or the API bridge resolves them locally, runs the commands over SSH and reports back exit codes and output.

## Creating one

In the team page open **Automations → New automation** (requires the `automations.manage` permission — owners and admins by default):

- **Vault** and **Snippet** — the snippet to run. Variables are not prompted for on a schedule, so use fixed values.
- **Hosts** and/or a **host group** — a group includes every host in it and in its subgroups at run time, so hosts added later are picked up automatically. Up to 200 explicit hosts.
- **Schedule** — a preset or a five-field cron expression (`minute hour day month weekday`; lists `1,15`, ranges `1-5`, steps `*/10`, `@hourly`, `@daily`, `@weekly`, `@monthly`). Day-of-month and day-of-week combine like Vixie cron (either matches when both are restricted).
- **Time zone** — `UTC` or a fixed offset such as `+03:00`.
- **Timeout** per host (10 s – 1 h).
- **E-mail alert** — never, on failure, or after every run; extra recipients plus, optionally, the team owners and admins.

Pause/resume, **Run now** and editing are in the same table; **History** shows every run with per-host status, exit code, duration and the captured output (capped at 8 KiB per stream).

## Who executes runs

The server never holds the vault key, so it cannot run anything itself. At the scheduled time it creates a *pending* run; the first executor that holds the vault claims it:

- the **API bridge** mirroring the team vault — recommended for anything that must run while laptops are closed;
- a member's **desktop** with *Settings → Run team automations on this computer* enabled and the vault unlocked.

Only one executor gets a given run. A run nobody claims within 15 minutes is marked **missed** and alerted like a failure. Hosts run up to four at a time; a host that exceeds the timeout is reported as failed with the output captured so far.

## Alerts and audit

Every finished or missed run is written to the team audit log (`automation.run.ok`, `automation.run.failed`, `automation.run.missed`) and therefore reaches configured webhooks. E-mails are sent according to the automation's alert policy.

## What the server stores

Automation name, schedule, time zone, timeout, alert settings, the UUIDs of the vault, snippet, hosts and group, and run results as reported by the executor (host label, target, exit code, truncated stdout/stderr, error, duration). It stores no snippet text, host addresses, usernames or credentials beyond what the executor includes in the result's `label`/`target` fields — these are the host label and `user@host:port` for readability. If that is more than your policy allows, keep automations to hosts whose addresses are not sensitive.

## API

- `GET/POST /api/v1/teams/{id}/automations`
- `GET/PUT/DELETE /api/v1/teams/{id}/automations/{aid}`
- `POST /api/v1/teams/{id}/automations/{aid}/run` — run now
- `GET /api/v1/teams/{id}/automations/{aid}/runs`
- `POST /api/v1/teams/{id}/automations/runs/claim`, `PATCH …/runs/{rid}` — executor protocol
