---
title: Session logs
description: Record terminal sessions, encrypted on the device, search them, pin the ones that matter, and keep them locally or on the server you chose.
---

## Recording

Turn on **Settings → Session logs → Record terminal sessions** and every terminal session from then on is written to a log as it happens. **Keep recordings for** sets how many days they are kept (0 keeps them forever); **Pinned** recordings are exempt from the limit.

![Recording settings](/docs/img/desktop-recording-settings.png)

Typed passwords are masked by the terminal's no-echo mode, so they do not end up in recordings; anything the server printed does, so treat recordings as sensitive as the sessions themselves.

## Browsing recordings

Recordings and the connection history are listed under **Logs** in the sidebar: host, user, when, how long, and the device that recorded it. Recording starts and stops with the session; a session that is still open shows a red dot on its tab.

![Logs](/docs/img/desktop-logs.png)

Open a recording to read it in a terminal view with the original colours. **Search** finds text in the output, **bookmark** a line to come back to it, and **Copy** takes a selection or the whole log as plain text. A recording can be exported as a text file, and deleted individually.

### Pinning

**Pin** marks a recording as one to keep: it is excluded from the retention limit and listed first. Pin the session where something went wrong before the next deployment; the rest can expire.

## Connection history

Below the recordings, the history lists every connection — saved hosts and quick connects alike — with the time and the result. A quick connect can be saved as a host from here, and the history feeds autocomplete's knowledge of which commands ran where.

## Where logs are stored

Recordings are encrypted with your master key and stay on the device that made them; nothing is uploaded by default.

On servers with object storage configured (`TERMOSO_S3__*`, see [Self-hosting](/docs/self-hosting/configuration)) the apps can keep session logs on the server too — encrypted on the device before upload, so the server only stores an opaque file and the metadata needed to list it. Team vault recordings uploaded this way are readable by the vault's members, which turns them into a shared audit trail of who did what on shared hosts.

## Android

**Recordings** in the vault menu lists the phone's recordings with the same search and pin. Recording is switched on under **Settings → Session logs** like on the desktop; the setting is per device.

## Comments

Every recording has a thread: the **Comments** button in its row (vault page or **Team → Recordings**) opens it. Editors and the recording's author post, optionally with the moment of the session the note refers to (`mm:ss`); viewers read. A comment is removed by its author or by a vault manager, and both actions land in the team audit trail as `log.commented` / `log.comment_deleted`. The thread is plain text on the server, like the shared note; the recording itself stays encrypted.
