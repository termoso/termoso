// Shell integration: the shell tells the terminal where prompts, commands
// and output begin (FinalTerm / OSC 133 marks, OSC 7 for the working
// directory and a VS Code-style `633;E` carrying the command text).
// Everything here is one line typed into the shell after connecting; the
// user's dotfiles are never touched and unsupported shells are left alone.

export type IntegratedShell = "bash" | "zsh" | "fish";

export function integratedShell(shell: string | null | undefined): IntegratedShell | null {
  switch (shell) {
    case "bash":
    case "zsh":
    case "fish":
      return shell;
    default:
      return null;
  }
}

// Rows the echoed injection occupies once the shell has printed it: the tail
// of the script moves up that far and wipes it, and the shell then redraws
// its prompt in the same spot as if nothing had been typed.
const D = "${";
const eraseTail = (rows: number) => String.raw`printf '\033[${rows}A\r\033[J'`;

// `history 1` may not hold the line when HISTCONTROL / HISTIGNORE dropped it;
// the terminal then falls back to what is on screen between the B and C
// marks. An existing DEBUG trap (bash-preexec, another terminal's hooks)
// keeps running first and ours is appended; should that fail, the prompt
// hook reports the command late, right before the `D` mark, whenever a new
// history entry appeared.
const bashScript = (rows: number) =>
  [
    String.raw`__tmo_emit(){ local c=$1; c="${D}c#*[0-9]  }"; c="${D}c//\\/\\\\}"; c="${D}c//$'\n'/\\x0a}"; c="${D}c//;/\\x3b}"; printf '\033]633;E;%s\007\033]133;C\007' "$c"; __tmo_in=1; }`,
    String.raw`__tmo_pre(){ [ -n "$COMP_LINE" ] && return; [ "$__tmo_in" = 1 ] && return; case ";$PROMPT_COMMAND;" in *";$BASH_COMMAND;"*) return;; esac; __tmo_emit "$(HISTTIMEFORMAT= builtin history 1)"; }`,
    String.raw`__tmo_prompt(){ local s=$? h n; h=$(HISTTIMEFORMAT= builtin history 1); n="${D}h%%[^0-9 ]*}"; n="${D}n// /}"; if [ "$__tmo_in" != 1 ] && [ -n "$__tmo_hn" ] && [ "$n" != "$__tmo_hn" ]; then __tmo_emit "$h"; fi; __tmo_hn=$n; [ "$__tmo_in" = 1 ] && printf '\033]133;D;%s\007' "$s"; __tmo_in=0; printf '\033]7;file://%s%s\007\033]133;A\007' "${D}HOSTNAME:-localhost}" "$PWD"; case "$PS1" in *'\[\033]133;B'*) ;; *) PS1="$PS1"'\[\033]133;B\007\]';; esac; }`,
    String.raw`__tmo_in=1`,
    String.raw`case ";$PROMPT_COMMAND;" in *";__tmo_prompt;"*) ;; *) PROMPT_COMMAND="__tmo_prompt${D}PROMPT_COMMAND:+;$PROMPT_COMMAND}";; esac`,
    String.raw`__tmo_trap(){ __tmo_t=$3; }`,
    String.raw`__tmo_t=; eval "__tmo_trap $(trap -p DEBUG)"`,
    String.raw`case "$__tmo_t" in *__tmo_pre*) ;; '') trap __tmo_pre DEBUG;; *) trap "$__tmo_t; __tmo_pre" DEBUG;; esac`,
    String.raw`case "$(HISTTIMEFORMAT= builtin history 1)" in *__tmo_pre*) builtin history -d -1 2>/dev/null;; esac`,
    eraseTail(rows),
  ].join("; ");

const zshScript = (rows: number) =>
  [
    String.raw`__tmo_pre(){ local c=$1; c=${D}c//\\/\\\\}; c=${D}c//$'\n'/\\x0a}; c=${D}c//;/\\x3b}; printf '\033]633;E;%s\007\033]133;C\007' "$c"; __tmo_in=1; }`,
    String.raw`__tmo_precmd(){ local s=$?; [[ $__tmo_in == 1 ]] && printf '\033]133;D;%s\007' "$s"; __tmo_in=0; printf '\033]7;file://%s%s\007\033]133;A\007' "${D}HOST:-localhost}" "$PWD"; [[ $PS1 != *$'\033]133;B'* ]] && PS1="$PS1"$'%{\033]133;B\007%}'; }`,
    String.raw`__tmo_in=0`,
    String.raw`autoload -Uz add-zsh-hook`,
    String.raw`add-zsh-hook preexec __tmo_pre`,
    String.raw`add-zsh-hook precmd __tmo_precmd`,
    eraseTail(rows),
  ].join("; ");

const fishScript = (rows: number) =>
  [
    String.raw`function __tmo_pre --on-event fish_preexec; set -l c (string replace -a '\\' '\\\\' -- $argv[1] | string replace -a ';' '\\x3b' | string join '\\x0a'); printf '\033]633;E;%s\007\033]133;C\007' "$c"; set -g __tmo_in 1; end`,
    String.raw`function __tmo_post --on-event fish_postexec; printf '\033]133;D;%s\007' $status; set -g __tmo_in 0; end`,
    String.raw`function __tmo_prompt --on-event fish_prompt; printf '\033]7;file://%s%s\007\033]133;A\007' (hostname 2>/dev/null; or echo localhost) $PWD; end`,
    String.raw`if not functions -q __tmo_orig_prompt; functions -q fish_prompt; and functions -c fish_prompt __tmo_orig_prompt; function fish_prompt; __tmo_orig_prompt; printf '\033]133;B\007'; end; end`,
    String.raw`set -g __tmo_in 0`,
    eraseTail(rows),
  ].join("; ");

/**
 * The line typed into the shell to install the hooks. `cursorX` / `cols`
 * are where the shell's cursor sits, so the script can erase its own echo
 * afterwards. The leading space keeps it out of history in shells that
 * ignore space-prefixed lines.
 */
/**
 * Prompt tails of the shells we integrate: `$ # %` and the common zsh/fish
 * theme glyphs. `>` is deliberately absent: it is what Python (`>>>`),
 * mysql, RouterOS and most chat-style CLIs draw, and typing the hooks into
 * those is exactly the failure this guards against.
 */
const PROMPT_TAIL = /[$#%❯➜›λ]\s?$/;

export interface PromptProbe {
  /** The cursor row's text, trailing blanks trimmed. */
  line: string;
  cursorX: number;
  /** A full-screen program owns the terminal (vim, htop, a TUI). */
  alternateScreen: boolean;
  /** The foreground program asked for bracketed paste: an editor line, not a bare shell. */
  bracketedPaste: boolean;
}

/**
 * Whether what is on the cursor row plausibly is a shell prompt waiting for
 * input, as opposed to a banner still printing, a TUI, or a REPL / CLI in
 * front of the shell. Deciding this from the configured login shell alone
 * is not enough: `ssh host -t app` never reaches it.
 */
export function looksLikeShellPrompt(p: PromptProbe): boolean {
  if (p.alternateScreen || p.bracketedPaste) return false;
  return p.line.length > 0 && p.line.length <= p.cursorX && PROMPT_TAIL.test(p.line);
}

export function integrationCommand(shell: IntegratedShell, cursorX: number, cols: number): string {
  const build = shell === "bash" ? bashScript : shell === "zsh" ? zshScript : fishScript;
  // Row count depends on the length, which depends on the row count; a couple of passes settle it.
  let rows = 1;
  for (let i = 0; i < 4; i++) {
    const next = Math.floor((cursorX + 1 + build(rows).length) / Math.max(1, cols)) + 1;
    if (next === rows) break;
    rows = next;
  }
  return ` ${build(rows)}\r`;
}

/**
 * Undo `633;E` escaping: `\\` → `\`, `\x0a` → newline, `\x3b` → `;`.
 * A bare `;` separates the command from an optional nonce (VS Code's
 * flavour of the sequence), so everything after it is dropped.
 */
export function decodeCommandText(raw: string): string {
  const sep = raw.indexOf(";");
  return (sep === -1 ? raw : raw.slice(0, sep)).replace(/\\(\\|x0a|x3b)/g, (_, k: string) =>
    k === "\\" ? "\\" : k === "x0a" ? "\n" : ";",
  );
}

/** `file://host/path` from OSC 7 → `/path` (percent-decoded), or null. */
export function decodeCwd(raw: string): string | null {
  if (!raw.startsWith("file://")) return null;
  const slash = raw.indexOf("/", "file://".length);
  if (slash === -1) return null;
  try {
    return decodeURIComponent(raw.slice(slash));
  } catch {
    return raw.slice(slash);
  }
}

export interface Mark {
  /** Absolute buffer line. */
  y: number;
  x: number;
}

/** What the parser derives from one shell's marks. */
export interface ShellTracker {
  /** Saw at least one prompt mark — the integration is live. */
  active: boolean;
  /** Between `B` (prompt printed) and `C` (command started). */
  atPrompt: boolean;
  /** Where the input area starts, set by `B`. */
  inputStart: Mark | null;
  /**
   * A `B` mark was seen since the last `D`. A `C` without one is a stale
   * report of an already finished command (two integrations in one shell)
   * and is ignored; a second `C` before `D` simply refines the command text.
   */
  sawInput: boolean;
  /** Command text the shell reported via `633;E` for the next `C`. */
  reportedCommand: string | null;
  cwd: string | null;
  lastExit: number | null;
}

export function newTracker(): ShellTracker {
  return {
    active: false,
    atPrompt: false,
    inputStart: null,
    sawInput: false,
    reportedCommand: null,
    cwd: null,
    lastExit: null,
  };
}

export type MarkEvent =
  | { kind: "prompt" }
  | { kind: "input"; at: Mark }
  | { kind: "command"; reported: string | null; inputStart: Mark | null }
  | { kind: "finished"; exit: number | null }
  | { kind: "cwd"; cwd: string };

/**
 * Feed one OSC 133 / 633 payload (`A`, `B`, `C`, `D;<n>`, `E;<text>`).
 * Returns what changed, or null for payloads we do not use.
 *
 * Only OSC 133 prompt marks count as "integration live": a shell that only
 * speaks the 633 dialect (another editor's hooks) still gets ours installed,
 * because its `E` text is derived from `BASH_COMMAND` and is truncated at
 * the first pipe or `;`.
 */
export function feedMark(
  t: ShellTracker,
  payload: string,
  cursor: Mark,
  family: 133 | 633 = 133,
): MarkEvent | null {
  const code = payload[0];
  const rest = payload.length > 2 && payload[1] === ";" ? payload.slice(2) : "";
  switch (code) {
    case "A":
      if (family === 133) t.active = true;
      t.atPrompt = false;
      t.inputStart = null;
      t.reportedCommand = null;
      return { kind: "prompt" };
    case "B":
      if (family === 133) t.active = true;
      t.atPrompt = true;
      t.inputStart = cursor;
      t.sawInput = true;
      return { kind: "input", at: cursor };
    case "C": {
      t.atPrompt = false;
      if (!t.sawInput) {
        t.reportedCommand = null;
        t.inputStart = null;
        return null;
      }
      const ev: MarkEvent = {
        kind: "command",
        reported: t.reportedCommand,
        inputStart: t.inputStart,
      };
      t.reportedCommand = null;
      t.inputStart = null;
      return ev;
    }
    case "D": {
      const n = rest === "" ? null : Number.parseInt(rest, 10);
      t.lastExit = n === null || Number.isNaN(n) ? null : n;
      t.atPrompt = false;
      t.sawInput = false;
      return { kind: "finished", exit: t.lastExit };
    }
    case "E":
      t.reportedCommand = decodeCommandText(rest);
      return null;
    default:
      return null;
  }
}

export function feedCwd(t: ShellTracker, payload: string): MarkEvent | null {
  const cwd = decodeCwd(payload);
  if (!cwd) return null;
  t.cwd = cwd;
  return { kind: "cwd", cwd };
}

/**
 * Lines that likely carry a secret stay out of history. A heuristic on
 * purpose — the user can still save such a line as a snippet by hand.
 */
export function looksLikeSecret(command: string): boolean {
  const c = command.trim();
  return (
    /\b(passw(or)?d|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\w*\s*[=:]\s*\S/i.test(
      c,
    ) ||
    /(^|\s)export\s+\w*(KEY|TOKEN|SECRET|PASS)\w*=/.test(c) ||
    /(^|\s)(mysql|mysqladmin|mysqldump|mariadb)\b.*\s-p\S+/.test(c) ||
    /(^|\s)sshpass\s+-p\s+\S+/.test(c) ||
    /(^|\s)(curl|wget|http)\b.*\s(-u|--user)\s+\S+:\S+/.test(c) ||
    /authorization:\s*(bearer|basic)\s+\S+/i.test(c) ||
    /(^|\s)(echo|printf)\s+\S+\s*\|\s*(sudo\s+)?(passwd|chpasswd|su\b)/.test(c)
  );
}

/** The last line of output asks for a password / passphrase. */
export function looksLikePasswordPrompt(line: string): boolean {
  return /(password|passphrase|passcode)\s*(for\s+[^:]+)?\s*:\s*$/i.test(line.trim());
}
