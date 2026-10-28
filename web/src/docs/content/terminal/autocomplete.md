---
title: Autocomplete and shell integration
description: Suggestions from your own history and snippets, saved passwords offered at password prompts, prompt markers and keyword highlighting — computed on the device, never in a cloud.
---

## Shell integration

Termoso understands the OSC 133 prompt markers that modern shells can emit (and injects a small script for `bash`, `zsh` and `fish` to emit them when a host allows it). With them it knows where each prompt, command and output starts, which powers autocomplete, the per-session command history in the side panel and the "which command printed this" context for Ask AI. Nothing has to be installed on the server for basic suggestions; the markers make them precise.

The script is typed only once a real shell prompt is on screen, never into a program that opened instead of one (a REPL, a TUI, `ssh host -t cmd`). Turn it off globally with **Settings → Terminal → Shell integration**, or for one host under **Advanced → Shell integration** in the host form: useful for routers, jump hosts and hosts whose session is a program rather than a shell.

## Autocomplete

As you type at a prompt, a popup suggests completions from:

- commands you ran before on this host (local history, kept in the vault's connection history);
- your snippets, matched by label or by the command text;
- the remote shell history, if **Import shell history** is on.

![Autocomplete popup](/docs/img/desktop-autocomplete.png)

Use <kbd>↑</kbd>/<kbd>↓</kbd> to choose and <kbd>Tab</kbd> or <kbd>Enter</kbd> to accept; <kbd>Esc</kbd> hides the popup for the current line. Suggestions rank by how often and how recently you used them on this host, then on any host. Turn it off with **Settings → Terminal → Command autocomplete**.

### Saved passwords at prompts

When a program on the host asks for a password — `sudo`, `su`, `ssh` to another machine, `mysql -p` — and the host has a saved password, the popup offers it as **Password · ‹host or identity›**; <kbd>Tab</kbd> types it, masked. The password is handed to the terminal from the encrypted vault and never shown.

## Keyword highlighting

**Keyword highlighting** colours words like `error`, `warning`, `failed`, `denied` or `ok` in the output so they stand out in long logs. It works on the stream, so it does not change what the server sends, and recordings keep the original output.

## Privacy

Every suggestion is computed on the device from data in your vault. Nothing you type is sent anywhere except to the server you are connected to. The optional [Ask AI](/docs/terminal/compose-and-ai#ask-ai) is a separate, opt-in feature that only runs when you ask for it.
