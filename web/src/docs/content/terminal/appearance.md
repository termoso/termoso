---
title: Themes, fonts and links
description: Colour schemes, bundled monospace fonts with Nerd Font glyphs, clickable OSC 8 hyperlinks and keyword highlighting — per host or for the whole app.
---

## Colour schemes

**Settings → Terminal** lists more than sixty schemes — the classics (Solarized, Dracula, Nord, Gruvbox, One Dark, Tokyo Night, Catppuccin in all four flavours) and newer ones such as Kanagawa, Flexoki and Rosé Pine — each shown as a live preview with the real font. Pick one as the default, then override it per host in **Host details → Terminal → Color scheme** when a server deserves its own colours (a red scheme for production is an old habit for a reason).

![Terminal appearance settings](/docs/img/desktop-terminal-themes.png)

The same scheme list ships on Android under **Settings → Appearance**; schemes are a per-device preference, so they are not part of a vault and do not sync.

## Fonts

Monospace fonts are bundled so the terminal looks the same on every machine. The desktop ships **JetBrains Mono** (default), **Fira Code**, **Fira Mono**, **Cascadia Code**, **Source Code Pro**, **IBM Plex Mono** and **Roboto Mono**. Choose the font, size and line height in **Settings → Terminal**; <kbd>Ctrl</kbd>+<kbd>=</kbd> / <kbd>-</kbd> / <kbd>0</kbd> zoom a single session without changing the default.

Android bundles **JetBrains Mono**, **Fira Code**, **Source Code Pro** and **Ubuntu Mono**. The size is a pinch away and can be bound to the volume buttons.

### Nerd Font glyphs

Prompts such as Starship, Powerlevel10k and Oh My Posh, and tools like `eza`, `lsd`, `lazygit` or Neovim status lines draw icons from the Nerd Fonts private-use ranges. Termoso appends **Symbols Nerd Font Mono** as a fallback behind whichever font you chose, on the desktop and on Android. Icons render in any of the bundled fonts without installing a patched font on the device; if a glyph still shows as a box the program is using a code point outside the Nerd Fonts ranges, and switching the prompt to the "Nerd Font" preset usually fixes it.

## Hyperlinks

Two kinds of links are clickable:

- **Plain URLs** in the output (`https://…`, `http://…`) are detected as you scroll.
- **OSC 8 hyperlinks** — links that programs attach to arbitrary text: `ls --hyperlink=auto`, `gcc`/`rustc` diagnostics, `cargo`, `delta`, `systemd` journal output, GitHub CLI and many more. The visible text stays as the program printed it; the target is in the escape sequence.

On the desktop hover to see the target, then <kbd>Ctrl</kbd>+click (<kbd>⌘</kbd>+click on macOS) to open it in the browser; a plain click still positions the cursor or selects text, so links never get in the way. On Android a tap on a link shows the target and offers to open it, so a mistap cannot launch anything.

## Keyword highlighting

**Settings → Terminal → Keyword highlighting** colours words such as `error`, `warning`, `failed`, `denied`, `fatal` and `ok` in the stream so they stand out in a long build log. It is purely a display rule on your side: the bytes sent to or from the server are not changed, and a recording of the session contains the original output.

## Cursor, bell and scrollback

| Setting              | What it does                                                                          |
| -------------------- | ------------------------------------------------------------------------------------- |
| **Scrollback lines** | How much output is kept per session, up to 100 000 lines on every platform; **Clear buffer** wipes it for one session |
| **Audible bell**     | Play a sound on `BEL`; off by default                                                 |
| **Copy on select**   | Copy a selection to the clipboard as soon as it is made; otherwise right-click copies |
| **Line height**      | Spacing between rows, for dense logs or for readability                               |

> [!TIP]
> Appearance settings live on the device, not in a vault, so a work laptop and a phone can look different while sharing the same hosts. Per-host overrides (colour scheme, character set, backspace key, terminal type) do live in the vault and follow the host everywhere.
