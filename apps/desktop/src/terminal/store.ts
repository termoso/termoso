// Terminal tabs and panes. React renders this state; xterm instances live in
// `runtimes` so they survive tab switches. Every session decision (connect,
// auth, prompts, history) is made in Rust — this file only moves bytes
// between the IPC channel and xterm.js.

import { copyToClipboard } from "@/lib/clipboard";
import { Terminal, type IBuffer, type IDisposable } from "@xterm/xterm";
import type { QueryClient } from "@tanstack/react-query";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { ImageAddon } from "@xterm/addon-image";
import * as triggers from "./triggers";
import { WebglAddon } from "@xterm/addon-webgl";
import { openUrl } from "@tauri-apps/plugin-opener";
import { readText as readNativeClipboard } from "@tauri-apps/plugin-clipboard-manager";
import * as ipc from "@/ipc/commands";
import type {
  ConnectPhase,
  DirEntry,
  LayoutTemplate,
  OpenTarget,
  SessionEvent,
  SessionInfo,
  Settings,
  SshAlgorithms,
  TabViewMode,
  Uuid,
} from "@/ipc/types";
import { errorMessage } from "@/ipc/types";
import type { ZmodemKind } from "@/ipc/types";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { downloadDir } from "@tauri-apps/api/path";
import { keys } from "@/ipc/hooks";
import { createStore, omit, useStore } from "@/lib/store";
import { dismissControlHint, viewerJoined } from "./multiplayer";
import { commandForEvent, tabDigit } from "@/app/shortcuts";
import { primaryKey } from "@/app/keymap";
import { terminalFontStack } from "./fonts";
import {
  complete,
  mergePaths,
  suffixFor,
  type PathQuery,
  type SnippetSource,
  type Suggestion,
} from "./autocomplete";
import {
  feedCwd,
  feedMark,
  integratedShell,
  looksLikeShellPrompt,
  integrationCommand,
  looksLikePasswordPrompt,
  looksLikeSecret,
  newTracker,
  type Mark,
  type ShellTracker,
} from "./shellIntegration";
import {
  MAX_PANES,
  leaf,
  leaves,
  neighbor,
  removeLeaf,
  setRatio,
  splitLeaf,
  type Rect,
  type Side,
  type SplitDirection,
  type SplitNode,
} from "./layout";
import { resolveTerminalTheme, toXtermTheme, type TerminalTheme } from "./themes";
import { KeywordHighlighter } from "./highlight";
import { leafState, type LeafState, restoreKeystrokes, withLeafState } from "./restore";
import {
  RECONNECT_ATTEMPTS,
  dequeueReconnect as dequeueReconnectQueue,
  enqueueReconnect,
  type ReconnectQueue,
} from "./reconnect";
import { tr, trn } from "@/i18n";
import { requireAnywhere, requirePerm } from "@/team/perms";

export type { SplitDirection, SplitNode } from "./layout";

export type PaneStatus = "connecting" | "connected" | "exited" | "error" | "closed";

export interface Pane {
  id: Uuid;
  target: OpenTarget;
  title: string;
  subtitle: string;
  protocol: SessionInfo["protocol"] | null;
  hostId: Uuid | null;
  algorithms: SshAlgorithms | null;
  /** Jump hosts the connection went through, outermost first. */
  via: string[];
  /** Colour scheme configured on the host; `null` follows the app setting. */
  hostTheme: string | null;
  startedAt: string | null;
  status: PaneStatus;
  message: string | null;
  /** Latest stage of the SSH connection attempt while `status` is `connecting`. */
  progress: ConnectProgress | null;
  /** Human-readable trail of the connection attempt, oldest first. */
  log: ConnectLogLine[];
  /** Base name of the shell (`bash`, `zsh`, …) once the session reports it. */
  shell: string | null;
  /** The shell is emitting prompt marks (OSC 133) — history and suggestions work. */
  integration: boolean;
  /** Working directory reported by the shell (OSC 7). */
  cwd: string | null;
  /** Command running right now (between the OSC 133 `C` and `D` marks). */
  command: string | null;
  lastExit: number | null;
  /** Per-session suggestions switch (the global one lives in settings). */
  autocomplete: boolean;
  /**
   * The pane is re-establishing (or failed to re-establish) a dropped session
   * in place: the old buffer stays on screen instead of the connection view.
   */
  reconnecting: boolean;
  /** ZMODEM transfer (`rz` / `sz` on the remote) in progress on this pane. */
  zmodem: ZmodemState | null;
}

export interface ZmodemState {
  kind: ZmodemKind;
  /** Current file; empty while the folder / files are still being picked. */
  name: string;
  done: number;
  total: number | null;
  files: number;
}

/** Hovered link with the modifier hint, at viewport coordinates. */
export interface LinkHover {
  paneId: Uuid;
  uri: string;
  left: number;
  top: number;
}

export interface ConnectProgress {
  /** Jump host this stage belongs to; `null` for the final target. */
  hop: string | null;
  phase: ConnectPhase;
}

export interface ConnectLogLine {
  at: number;
  text: string;
  level: "info" | "error";
}

function phaseLine(p: ConnectProgress): string {
  const where = p.hop ? ` (${tr("jump host {hop}", { hop: p.hop })})` : "";
  switch (p.phase.kind) {
    case "resolving":
      return tr("Resolving address{where}", { where });
    case "connecting":
      return tr("Connecting via {via}{where}", { via: p.phase.via, where });
    case "handshake":
      return tr("Negotiating keys{where}", { where });
    case "host_key":
      return tr("Verifying host key{where}", { where });
    case "auth":
      return tr("Authenticating with {method}{where}", { method: p.phase.method, where });
    case "security_key_touch":
      return tr("Waiting for a touch on the security key ({key}){where}", {
        key: p.phase.key,
        where,
      });
    case "authenticated":
      return tr("Authenticated, opening shell{where}", { where });
    case "mosh_server":
      return tr("Starting mosh-server over SSH, then switching to UDP");
  }
}

function appendLog(paneId: Uuid, text: string, level: ConnectLogLine["level"] = "info") {
  terminalStore.set((s) => {
    const pane = s.panes[paneId];
    if (!pane) return s;
    const line = { at: Date.now(), text, level };
    return { ...s, panes: { ...s.panes, [paneId]: { ...pane, log: [...pane.log, line] } } };
  });
}

/** Popup with completions for the line being typed. */
export interface SuggestState {
  paneId: Uuid;
  items: Suggestion[];
  selected: number;
  /** Cursor cell, in pixels relative to the pane. */
  left: number;
  top: number;
  cellHeight: number;
  /** Open upwards — the cursor is near the bottom of the pane. */
  above: boolean;
  paneWidth: number;
}

export interface TerminalTab {
  id: string;
  /** Workspace name; `null` for a plain session tab titled after its active pane. */
  name: string | null;
  /** `split` shows the whole tree; `list` shows one pane next to a list of all of them. */
  viewMode: TabViewMode;
  /** Saved workspace this tab was opened from, if any. */
  templateId: Uuid | null;
  layout: SplitNode;
  /** Leaves of `layout` in reading order (kept in sync by the store). */
  paneIds: Uuid[];
  activePaneId: Uuid;
  /** Focus mode: the active pane fills the tab, the rest of the split stays intact. */
  focused: boolean;
  broadcast: boolean;
  /** Font scale, 1 = the settings font size. */
  zoom: number;
  /** Colour scheme picked from the side panel for this tab; `null` = host / app default. */
  themeOverride: string | null;
}

export const isWorkspaceTab = (tab: TerminalTab) => tab.name !== null;

/** Title shown on the tab strip: the workspace name or the active pane's title. */
export function tabTitle(tab: TerminalTab, s: TerminalState = terminalStore.get()): string {
  if (tab.name !== null) return tab.name;
  const pane = s.panes[tab.activePaneId];
  const title = pane?.title ?? tr("Terminal");
  return tab.paneIds.length > 1 ? `${title} (+${tab.paneIds.length - 1})` : title;
}

export type SidePanelTab =
  "search" | "forwarding" | "snippets" | "history" | "themes" | "ask" | "info";

export const HOME_TAB = "home";

export interface TerminalState {
  tabs: TerminalTab[];
  panes: Record<Uuid, Pane>;
  activeTabId: string;
  /** Multi-line paste waiting for the user's confirmation. */
  pendingPaste: { paneId: Uuid; text: string } | null;
  /** Panes awaiting the "close connected session?" confirmation. */
  pendingClose: Uuid[] | null;
  /** Right-click menu for a pane, at viewport coordinates. */
  contextMenu: { paneId: Uuid; left: number; top: number } | null;
  /** Open section of the terminal side panel (shared by all tabs). */
  sidePanel: SidePanelTab | null;
  suggest: SuggestState | null;
  /** Suggestions paused everywhere until this time (ms since epoch). */
  suggestPausedUntil: number | null;
  reconnect: ReconnectQueue | null;
  linkHover: LinkHover | null;
}

const PAUSE_KEY = "termoso.suggestPausedUntil";

function loadPause(): number | null {
  try {
    const v = Number(localStorage.getItem(PAUSE_KEY));
    return v > Date.now() ? v : null;
  } catch {
    return null;
  }
}

export const terminalStore = createStore<TerminalState>({
  tabs: [],
  panes: {},
  activeTabId: HOME_TAB,
  pendingPaste: null,
  pendingClose: null,
  contextMenu: null,
  sidePanel: null,
  suggest: null,
  suggestPausedUntil: loadPause(),
  reconnect: null,
  linkHover: null,
});

export const useTerminal = <S>(selector: (s: TerminalState) => S) =>
  useStore(terminalStore, selector);

interface Runtime {
  term: Terminal;
  fit: FitAddon;
  search: SearchAddon;
  container: HTMLDivElement;
  webgl: WebglAddon | null;
  opened: boolean;
  disposables: IDisposable[];
  shell: ShellTracker;
  /** Integration script: not yet decided / typed into the shell / not applicable. */
  integration: "pending" | "sent" | "none";
  injectTimer: ReturnType<typeof setTimeout> | null;
  lastOutputAt: number;
  /** Command text captured at the `C` mark, recorded once `D` reports completion. */
  pendingCommand: string | null;
  /** The next finished command is ours (a restored `cd`), not the user's: keep it out of history. */
  skipRecord: boolean;
  /** Shell state saved with the workspace, applied once the shell shows its first prompt. */
  restore: LeafState | null;
  suggestTimer: ReturnType<typeof setTimeout> | null;
  /** Line the user dismissed suggestions for; they come back once it changes. */
  mutedLine: string | null;
  /** Sequence number of the latest directory listing request. */
  pathSeq: number;
  /** Label of the saved identity with a stored password, offered on password prompts. */
  identityLabel: string | null;
  /** Multiplayer viewer: the grid follows the host's size instead of the container. */
  fixedSize: { cols: number; rows: number } | null;
  /**
   * Shells without OSC 133 (ash, dash, tcsh, PowerShell…): the cursor position
   * where the user started typing after the last unsolicited output. Cleared
   * on Enter / control keys and whenever output arrives that typing did not
   * cause, so a redrawn prompt or command output never counts as input.
   */
  typedStart: Mark | null;
  lastInputAt: number;
  /** Keyword colouring of the output stream (`null` when the setting is off). */
  highlighter: KeywordHighlighter | null;
}

const runtimes = new Map<Uuid, Runtime>();
export const getRuntime = (paneId: Uuid) => runtimes.get(paneId);

let queryClient: QueryClient | null = null;
let currentSettings: Settings | null = null;
let currentScheme: "dark" | "light" = "dark";

const uuid = () => crypto.randomUUID();

function update(fn: (s: TerminalState) => TerminalState) {
  terminalStore.set(fn);
}

function patchPane(id: Uuid, patch: Partial<Pane>) {
  update((s) => {
    const pane = s.panes[id];
    if (!pane) return s;
    return { ...s, panes: { ...s.panes, [id]: { ...pane, ...patch } } };
  });
}

function patchTab(id: string, patch: Partial<TerminalTab>) {
  update((s) => ({
    ...s,
    tabs: s.tabs.map((t) => (t.id === id ? { ...t, ...patch } : t)),
  }));
}

function tabOf(s: TerminalState, paneId: Uuid) {
  return s.tabs.find((t) => t.paneIds.includes(paneId));
}

export function activeTab(s: TerminalState = terminalStore.get()): TerminalTab | undefined {
  return s.tabs.find((t) => t.id === s.activeTabId);
}

function withLayout(tab: TerminalTab, layout: SplitNode): TerminalTab {
  return { ...tab, layout, paneIds: leaves(layout) };
}

function newTab(layout: SplitNode, extra: Partial<TerminalTab> = {}): TerminalTab {
  const paneIds = leaves(layout);
  return {
    id: uuid(),
    name: null,
    viewMode: "split",
    focused: false,
    templateId: null,
    layout,
    paneIds,
    activePaneId: paneIds[0] ?? "",
    broadcast: false,
    zoom: 1,
    themeOverride: null,
    ...extra,
  };
}

// ───────────────────────────── settings / theme ─────────────────────────────

const fontFamily = (settings: Settings | null) => terminalFontStack(settings?.terminalFontFamily);

export const ZOOM_STEPS = [0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3];

const fontSize = (zoom: number) =>
  Math.max(6, Math.round((currentSettings?.terminalFontSize ?? 14) * zoom));

/** Scheme id a pane renders with: tab override → host scheme → app setting. */
export function paneThemeId(pane: Pane | undefined, tab: TerminalTab | undefined): string {
  return tab?.themeOverride ?? pane?.hostTheme ?? currentSettings?.terminalTheme ?? "auto";
}

export function paneTheme(paneId: Uuid, s: TerminalState = terminalStore.get()): TerminalTheme {
  return resolveTerminalTheme(paneThemeId(s.panes[paneId], tabOf(s, paneId)), currentScheme);
}

function applyPaneLook(paneId: Uuid, s: TerminalState = terminalStore.get()) {
  const rt = runtimes.get(paneId);
  if (!rt) return;
  const tab = tabOf(s, paneId);
  rt.term.options.theme = toXtermTheme(paneTheme(paneId, s));
  const size = fontSize(tab?.zoom ?? 1);
  if (rt.term.options.fontSize !== size) {
    rt.term.options.fontSize = size;
    if (rt.opened) fitPane(paneId);
  }
  if (rt.opened) rt.term.refresh(0, rt.term.rows - 1);
}

function applyTabLook(tabId: string) {
  const s = terminalStore.get();
  const tab = s.tabs.find((t) => t.id === tabId);
  for (const id of tab?.paneIds ?? []) applyPaneLook(id, s);
}

export function applyTerminalSettings(settings: Settings) {
  currentSettings = settings;
  const s = terminalStore.get();
  for (const [id, rt] of runtimes) {
    rt.term.options.fontFamily = fontFamily(settings);
    rt.term.options.lineHeight = settings.terminalLineHeight;
    rt.term.options.cursorBlink = settings.cursorBlink;
    rt.term.options.cursorStyle = settings.cursorStyle;
    rt.term.options.scrollback = settings.scrollback;
    rt.term.options.drawBoldTextInBrightColors = settings.brightBold;
    rt.term.options.theme = toXtermTheme(paneTheme(id, s));
    rt.term.options.fontSize = fontSize(tabOf(s, id)?.zoom ?? 1);
    if (settings.keywordHighlight) rt.highlighter ??= new KeywordHighlighter();
    else rt.highlighter = null;
    if (rt.opened) rt.fit.fit();
  }
}

export function applyTerminalScheme(scheme: "dark" | "light") {
  currentScheme = scheme;
  const s = terminalStore.get();
  for (const [id, rt] of runtimes) rt.term.options.theme = toXtermTheme(paneTheme(id, s));
}

/** Pick a colour scheme for every pane of the tab; `null` returns to the host / app default. */
export function setTabTheme(tabId: string, themeId: string | null) {
  patchTab(tabId, { themeOverride: themeId });
  applyTabLook(tabId);
}

export function zoomTab(tabId: string, step: 1 | -1) {
  const tab = terminalStore.get().tabs.find((t) => t.id === tabId);
  if (!tab) return;
  const i = ZOOM_STEPS.findIndex((z) => Math.abs(z - tab.zoom) < 1e-6);
  const next = ZOOM_STEPS[(i === -1 ? ZOOM_STEPS.indexOf(1) : i) + step];
  if (next === undefined) return;
  patchTab(tabId, { zoom: next });
  applyTabLook(tabId);
}

export function resetZoom(tabId: string) {
  patchTab(tabId, { zoom: 1 });
  applyTabLook(tabId);
}

/** Wipe scrollback and the screen; the shell prompt is redrawn on the next output. */
export function clearBuffer(paneId: Uuid) {
  runtimes.get(paneId)?.term.clear();
}

export function selectAll(paneId: Uuid) {
  runtimes.get(paneId)?.term.selectAll();
}

// ───────────────────────────── clipboard ─────────────────────────────

// Native clipboard first: WebKitGTK only allows `navigator.clipboard.readText()` inside a paste event.
export async function copyText(text: string) {
  try {
    await copyToClipboard(text);
  } catch {
    // clipboard unavailable; selection stays in xterm
  }
}

async function readClipboard(): Promise<string> {
  try {
    return await readNativeClipboard();
  } catch {
    try {
      return await navigator.clipboard.readText();
    } catch {
      return "";
    }
  }
}

export function copySelection(paneId: Uuid) {
  const term = runtimes.get(paneId)?.term;
  if (term?.hasSelection()) {
    void copyText(term.getSelection());
    term.clearSelection();
  }
}

export function pasteClipboard(paneId: Uuid) {
  void readClipboard().then((t) => pasteInto(paneId, t));
}

/** Types `text` at the prompt the way a paste does (bracketed paste, multi-line confirm); never appends Enter. */
export function pasteText(paneId: Uuid, text: string) {
  pasteInto(paneId, text);
}

function pasteInto(paneId: Uuid, text: string, force = false) {
  if (!text) return;
  if (!force && currentSettings?.confirmPasteMultiline && /\r|\n/.test(text.trimEnd())) {
    update((s) => ({ ...s, pendingPaste: { paneId, text } }));
    return;
  }
  const rt = runtimes.get(paneId);
  rt?.term.paste(text);
}

export function confirmPendingPaste(accept: boolean) {
  const pending = terminalStore.get().pendingPaste;
  update((s) => ({ ...s, pendingPaste: null }));
  if (pending && accept) pasteInto(pending.paneId, pending.text, true);
}

/**
 * OSC 52 — programs on the remote side (tmux, vim, `osc52.sh`) put text on
 * the local clipboard. Writes only: a query (`?`) is swallowed rather than
 * answered, so no remote program can read the clipboard.
 */
function handleOsc52(data: string): boolean {
  const sep = data.indexOf(";");
  const payload = sep === -1 ? data : data.slice(sep + 1);
  if (payload === "?" || payload === "") return true;
  try {
    const bin = atob(payload.replace(/\s+/g, ""));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const text = new TextDecoder().decode(bytes);
    if (text) void copyText(text);
  } catch {
    // malformed base64 — ignore
  }
  return true;
}

// ───────────────────────────── bell ─────────────────────────────

let audio: AudioContext | null = null;

function beep() {
  try {
    audio ??= new AudioContext();
    const osc = audio.createOscillator();
    const gain = audio.createGain();
    osc.type = "sine";
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.08, audio.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, audio.currentTime + 0.12);
    osc.connect(gain).connect(audio.destination);
    osc.start();
    osc.stop(audio.currentTime + 0.12);
  } catch {
    // no audio output available
  }
}

// ───────────────────────────── xterm runtime ─────────────────────────────

/** Keys bound to app commands (see app/commands.ts) that xterm must not turn into input. */
function isAppShortcut(ev: KeyboardEvent): boolean {
  return tabDigit(ev) !== null || commandForEvent(ev) !== null;
}

function createRuntime(paneId: Uuid): Runtime {
  const term = new Terminal({
    allowProposedApi: true,
    cursorBlink: currentSettings?.cursorBlink ?? true,
    cursorStyle: currentSettings?.cursorStyle ?? "bar",
    fontSize: fontSize(1),
    fontFamily: fontFamily(currentSettings),
    fontWeight: "400",
    fontWeightBold: "600",
    lineHeight: currentSettings?.terminalLineHeight ?? 1,
    letterSpacing: 0,
    scrollback: currentSettings?.scrollback ?? 10_000,
    theme: toXtermTheme(resolveTerminalTheme(currentSettings?.terminalTheme, currentScheme)),
    drawBoldTextInBrightColors: currentSettings?.brightBold ?? false,
    macOptionIsMeta: true,
    minimumContrastRatio: 1,
    scrollOnUserInput: true,
    smoothScrollDuration: 0,
    // OSC 8 hyperlinks (ls --hyperlink, gcc, cargo, …): same Ctrl / Cmd + click rule as plain URLs.
    linkHandler: {
      activate: (ev, uri) => {
        if ((ev.ctrlKey || ev.metaKey) && safeLinkTarget(uri)) void openUrl(uri);
      },
      hover: (ev, uri) => {
        update((s) => ({
          ...s,
          linkHover: { paneId, uri, left: ev.clientX, top: ev.clientY },
        }));
      },
      leave: () => clearLinkHover(paneId),
      allowNonHttpProtocols: false,
    },
  });
  const fit = new FitAddon();
  const search = new SearchAddon();
  term.loadAddon(fit);
  term.loadAddon(search);
  term.loadAddon(new Unicode11Addon());
  term.unicode.activeVersion = "11";
  // Links open with Ctrl / Cmd + click only; a plain click just moves on.
  term.loadAddon(
    new WebLinksAddon(
      (ev, uri) => {
        if (ev.ctrlKey || ev.metaKey) void openUrl(uri);
      },
      {
        hover: (ev, uri) => {
          update((s) => ({
            ...s,
            linkHover: { paneId, uri, left: ev.clientX, top: ev.clientY },
          }));
        },
        leave: () => clearLinkHover(paneId),
      },
    ),
  );

  const container = document.createElement("div");
  container.className = "termoso-xterm";

  const disposables: IDisposable[] = [];
  disposables.push(
    term.onData((data) => {
      dismissControlHint();
      void sendInput(paneId, data);
    }),
    term.onBinary((data) => {
      void sendInput(paneId, data);
    }),
    term.onResize(({ cols, rows }) => {
      const pane = terminalStore.get().panes[paneId];
      if (pane?.status === "connected") {
        ipc.terminalResize(paneId, cols, rows).catch(() => undefined);
      }
    }),
    term.onTitleChange((title) => {
      const pane = terminalStore.get().panes[paneId];
      if (pane && title.trim()) patchPane(paneId, { title: title.trim() });
    }),
    term.onSelectionChange(() => {
      if (currentSettings?.copyOnSelect && term.hasSelection()) {
        void copyText(term.getSelection());
      }
    }),
    term.onBell(() => {
      if (currentSettings?.terminalBell) beep();
    }),
    term.parser.registerOscHandler(52, handleOsc52),
    term.parser.registerOscHandler(133, (data) => handleMark(paneId, data, 133)),
    term.parser.registerOscHandler(633, (data) => handleMark(paneId, data, 633)),
    term.parser.registerOscHandler(7, (data) => handleCwd(paneId, data)),
  );

  term.attachCustomKeyEventHandler((ev) => {
    if (ev.type !== "keydown") return true;
    if (handleSuggestKey(paneId, ev)) {
      ev.preventDefault();
      ev.stopPropagation();
      return false;
    }
    // Ctrl (⌘ on macOS, where Ctrl+C must stay SIGINT) + C copies a selection.
    const ctrl = primaryKey(ev);
    if (ctrl && ev.code === "KeyC" && !ev.shiftKey && !ev.altKey && term.hasSelection()) {
      void copyText(term.getSelection());
      term.clearSelection();
      return false;
    }
    if (ev.shiftKey && !ctrl && ev.code === "Insert") {
      void readClipboard().then((t) => pasteInto(paneId, t));
      return false;
    }
    if (ctrl && ev.code === "Insert") {
      if (term.hasSelection()) void copyText(term.getSelection());
      return false;
    }
    return !isAppShortcut(ev);
  });

  container.addEventListener("contextmenu", (ev) => {
    ev.preventDefault();
    if (!currentSettings?.pasteOnRightClick) {
      update((s) => ({ ...s, contextMenu: { paneId, left: ev.clientX, top: ev.clientY } }));
      return;
    }
    if (term.hasSelection()) {
      void copyText(term.getSelection());
      term.clearSelection();
    } else {
      void readClipboard().then((t) => pasteInto(paneId, t));
    }
  });
  container.addEventListener("mousedown", () => {
    setActivePane(paneId);
    hideSuggest(paneId);
  });
  container.addEventListener("focusout", (ev) => {
    if (ev.relatedTarget instanceof Node && container.contains(ev.relatedTarget)) return;
    hideSuggest(paneId);
  });

  return {
    term,
    fit,
    search,
    container,
    webgl: null,
    opened: false,
    disposables,
    shell: newTracker(),
    integration: "pending",
    injectTimer: null,
    lastOutputAt: 0,
    pendingCommand: null,
    skipRecord: false,
    restore: null,
    suggestTimer: null,
    mutedLine: null,
    pathSeq: 0,
    identityLabel: null,
    fixedSize: null,
    typedStart: null,
    lastInputAt: 0,
    highlighter: currentSettings?.keywordHighlight === false ? null : new KeywordHighlighter(),
  };
}

function clearLinkHover(paneId: Uuid) {
  update((s) => (s.linkHover?.paneId === paneId ? { ...s, linkHover: null } : s));
}

export function closeContextMenu() {
  update((s) => (s.contextMenu ? { ...s, contextMenu: null } : s));
}

/** Attach the pane's DOM to `host` (first mount also opens xterm). */
export function mountPane(paneId: Uuid, host: HTMLElement) {
  const rt = runtimes.get(paneId);
  if (!rt) return () => undefined;
  host.appendChild(rt.container);
  if (!rt.opened) {
    rt.term.open(rt.container);
    rt.opened = true;
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => {
        webgl.dispose();
        rt.webgl = null;
      });
      rt.term.loadAddon(webgl);
      rt.webgl = webgl;
    } catch {
      rt.webgl = null;
    }
    // Inline images: sixel (DCS q) and iTerm2 OSC 1337 — after the renderer so
    // the overlay canvas sits above it. Kitty graphics are not supported by
    // xterm.js and are left alone.
    try {
      rt.term.loadAddon(
        new ImageAddon({
          sixelSupport: true,
          iipSupport: true,
          sixelScrolling: true,
          storageLimit: 64,
          showPlaceholder: true,
        }),
      );
    } catch {
      // No canvas: fall back to text only.
    }
  }
  const ro = new ResizeObserver(() => fitPane(paneId));
  ro.observe(host);
  requestAnimationFrame(() => fitPane(paneId));
  return () => {
    ro.disconnect();
    if (rt.container.parentElement === host) host.removeChild(rt.container);
  };
}

export function fitPane(paneId: Uuid) {
  const rt = runtimes.get(paneId);
  if (!rt?.opened || !rt.container.isConnected) return;
  const { width, height } = rt.container.getBoundingClientRect();
  if (width < 20 || height < 20) return;
  try {
    const el = rt.term.element;
    if (rt.fixedSize) {
      rt.term.resize(rt.fixedSize.cols, rt.fixedSize.rows);
      // A pinned grid (multiplayer: somebody else's size) is scaled to fit
      // instead of being clipped.
      if (el) {
        const natural = el.querySelector<HTMLElement>(".xterm-screen") ?? el;
        const scale = Math.min(1, width / natural.offsetWidth, height / natural.offsetHeight);
        el.style.transformOrigin = "0 0";
        el.style.transform = scale < 0.999 ? `scale(${scale})` : "";
      }
    } else {
      if (el) el.style.transform = "";
      rt.fit.fit();
    }
    requestAnimationFrame(() => rt.term.refresh(0, rt.term.rows - 1));
  } catch {
    // container not laid out yet
  }
}

/** Pin (or release, with `null`) the grid size of a pane — used by multiplayer viewers. */
export function setPaneFixedSize(paneId: Uuid, size: { cols: number; rows: number } | null) {
  const rt = runtimes.get(paneId);
  if (!rt) return;
  rt.fixedSize = size;
  fitPane(paneId);
}

export function focusPane(paneId: Uuid) {
  runtimes.get(paneId)?.term.focus();
}

/** Rows × cols of the live grid. */
export function paneSize(paneId: Uuid): { cols: number; rows: number } | null {
  const t = runtimes.get(paneId)?.term;
  return t ? { cols: t.cols, rows: t.rows } : null;
}

export function paneHasSelection(paneId: Uuid): boolean {
  return runtimes.get(paneId)?.term.hasSelection() ?? false;
}

function disposeRuntime(paneId: Uuid) {
  const rt = runtimes.get(paneId);
  if (!rt) return;
  runtimes.delete(paneId);
  if (rt.injectTimer) clearTimeout(rt.injectTimer);
  if (rt.suggestTimer) clearTimeout(rt.suggestTimer);
  hideSuggest(paneId);
  clearLinkHover(paneId);
  for (const d of rt.disposables) d.dispose();
  rt.webgl?.dispose();
  rt.term.dispose();
  rt.container.remove();
}

export function writeSystemLine(paneId: Uuid, text: string, color = "90") {
  const rt = runtimes.get(paneId);
  rt?.term.write(`\r\n\x1b[${color}m${text}\x1b[0m\r\n`);
}

// ───────────────────────────── shell integration ─────────────────────────────

const INJECT_IDLE_MS = 250;
const INJECT_MAX_WAIT_MS = 8000;

// The shell is ready for typed input when the cursor sits right after a
// prompt-looking line on the normal screen; a login banner still scrolling
// by, a TUI, or a REPL in front of the shell does not qualify.
function atPromptLine(term: Terminal): boolean {
  const buf = term.buffer.active;
  const line = buf.getLine(buf.baseY + buf.cursorY);
  if (!line) return false;
  return looksLikeShellPrompt({
    line: line.translateToString(true),
    cursorX: buf.cursorX,
    alternateScreen: buf.type === "alternate",
  });
}

function cursorMark(term: Terminal): Mark {
  const b = term.buffer.active;
  return { y: b.baseY + b.cursorY, x: b.cursorX };
}

/** Text on screen between two marks, joining wrapped rows; `null` when the rows are gone. */
function readBetween(buffer: IBuffer, from: Mark, to: Mark): string | null {
  if (to.y < from.y || from.y < 0) return null;
  let out = "";
  for (let y = from.y; y <= to.y; y++) {
    const line = buffer.getLine(y);
    if (!line) return null;
    const last = y === to.y;
    const startX = y === from.y ? from.x : 0;
    const text = last
      ? line.translateToString(false, startX, to.x)
      : line.translateToString(true, startX);
    out += text;
    if (!last) {
      const next = buffer.getLine(y + 1);
      if (next && !next.isWrapped) out += "\n";
    }
  }
  return out;
}

/** What the user has typed at the prompt so far (up to the cursor). */
function currentInput(rt: Runtime): string | null {
  const t = rt.shell;
  const start = t.active ? (t.atPrompt ? t.inputStart : null) : rt.typedStart;
  if (!start || rt.term.buffer.active.type !== "normal") return null;
  const cur = cursorMark(rt.term);
  if (cur.y < start.y || (cur.y === start.y && cur.x < start.x)) return null;
  return readBetween(rt.term.buffer.active, start, cur);
}

/** Track typed input for shells that do not report prompt marks. */
function noteTyped(paneId: Uuid, rt: Runtime, data: string) {
  if (rt.shell.active) return;
  rt.lastInputAt = Date.now();
  if (data === "\r" && rt.typedStart) {
    // No exit marks here, so the line is recorded as typed. Unechoed input
    // (password prompts) leaves the cursor in place and yields nothing.
    const text = currentInput(rt)?.trim() ?? "";
    if (text.length > 0) recordCommand(paneId, text);
  }
  let printable = true;
  for (let i = 0; i < data.length; i++) {
    const c = data.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) printable = false;
  }
  if (printable) {
    rt.typedStart ??= cursorMark(rt.term);
    return;
  }
  if (data === "\x7f" || data === "\b") return;
  rt.typedStart = null;
}

const TYPING_ECHO_MS = 400;

export type CommandEvent = { kind: "started" } | { kind: "finished"; exit: number | null };
type CommandListener = (paneId: Uuid, ev: CommandEvent) => void;
const commandListeners = new Set<CommandListener>();

/** Shell-integration command lifecycle across all panes. */
export function onCommandEvent(listener: CommandListener): () => void {
  commandListeners.add(listener);
  return () => {
    commandListeners.delete(listener);
  };
}

type DropListener = (paneId: Uuid) => void;
const dropListeners = new Set<DropListener>();

/** A connected session ended without the user asking for it (network / server side). */
export function onSessionDropped(listener: DropListener): () => void {
  dropListeners.add(listener);
  return () => {
    dropListeners.delete(listener);
  };
}

function reportDrop(paneId: Uuid) {
  for (const l of dropListeners) l(paneId);
}

function handleMark(paneId: Uuid, data: string, family: 133 | 633): boolean {
  const rt = runtimes.get(paneId);
  if (!rt) return true;
  // Once our 133 hooks are live, a coexisting 633 integration only contributes
  // command text; its prompt/exit marks would double-report every command.
  if (family === 633 && rt.shell.active && !data.startsWith("E")) return true;
  const ev = feedMark(rt.shell, data, cursorMark(rt.term), family);
  if (!ev) return true;
  switch (ev.kind) {
    case "prompt":
      if (rt.shell.active && !terminalStore.get().panes[paneId]?.integration) {
        patchPane(paneId, { integration: true });
      }
      if (rt.shell.active) applyRestore(paneId);
      break;
    case "input":
      rt.mutedLine = null;
      hideSuggest(paneId);
      break;
    case "command": {
      const typed =
        ev.reported ??
        (ev.inputStart
          ? readBetween(rt.term.buffer.active, ev.inputStart, cursorMark(rt.term))
          : null);
      const text = typed?.trim() ?? "";
      rt.pendingCommand = text.length > 0 ? text : null;
      patchPane(paneId, { command: rt.skipRecord ? null : rt.pendingCommand });
      hideSuggest(paneId);
      for (const l of commandListeners) l(paneId, { kind: "started" });
      break;
    }
    case "finished":
      if (rt.pendingCommand && !rt.skipRecord) recordCommand(paneId, rt.pendingCommand);
      rt.skipRecord = false;
      rt.pendingCommand = null;
      patchPane(paneId, { lastExit: ev.exit, command: null });
      for (const l of commandListeners) l(paneId, { kind: "finished", exit: ev.exit });
      break;
    case "cwd":
      break;
  }
  return true;
}

function handleCwd(paneId: Uuid, data: string): boolean {
  const rt = runtimes.get(paneId);
  if (!rt) return true;
  const ev = feedCwd(rt.shell, data);
  if (ev?.kind === "cwd" && terminalStore.get().panes[paneId]?.cwd !== ev.cwd) {
    patchPane(paneId, { cwd: ev.cwd });
  }
  return true;
}

/** Runs after each chunk of output has been parsed into the buffer. */
function onOutput(paneId: Uuid) {
  const rt = runtimes.get(paneId);
  if (!rt) return;
  rt.lastOutputAt = Date.now();
  if (!rt.shell.active && rt.typedStart && rt.lastOutputAt - rt.lastInputAt > TYPING_ECHO_MS) {
    rt.typedStart = null;
    hideSuggest(paneId);
  }
  if (!autocompleteOn(paneId)) return;
  if (rt.shell.active ? rt.shell.atPrompt : rt.typedStart !== null) {
    scheduleSuggest(paneId);
  } else if (rt.identityLabel) {
    offerIdentity(paneId, rt);
  }
}

/**
 * Put the pane back where its workspace left it: `cd` to the saved directory
 * (kept out of history) and, per the setting, type or run the command that
 * was going at the time. One shot, the first time the shell is ready.
 */
function applyRestore(paneId: Uuid) {
  const rt = runtimes.get(paneId);
  if (!rt?.restore) return;
  const state = rt.restore;
  rt.restore = null;
  rt.skipRecord = state.cwd !== null;
  const text = restoreKeystrokes(state, currentSettings?.restoreCommands ?? "type");
  if (text) void writeOrdered(paneId, text);
}

/**
 * Run `ready` once the shell's first prompt has settled: output has been
 * idle for a moment and the cursor sits after a prompt-looking line. When
 * the wait runs out without one, `ready` still runs with `settled = false`
 * so the caller can decide what is safe to type. Gives up when the pane
 * stops being connected.
 */
function whenPromptReady(paneId: Uuid, ready: (rt: Runtime, settled: boolean) => void) {
  const startedAt = Date.now();
  const tick = () => {
    const r = runtimes.get(paneId);
    if (!r) return;
    r.injectTimer = null;
    const pane = terminalStore.get().panes[paneId];
    if (pane?.status !== "connected") {
      if (pane?.status === "connecting") r.injectTimer = setTimeout(tick, INJECT_IDLE_MS);
      return;
    }
    const idle = Date.now() - r.lastOutputAt;
    const waited = Date.now() - startedAt;
    const settled = r.lastOutputAt > 0 && idle >= INJECT_IDLE_MS && atPromptLine(r.term);
    if (!settled && waited < INJECT_MAX_WAIT_MS) {
      r.injectTimer = setTimeout(tick, INJECT_IDLE_MS - Math.min(idle, INJECT_IDLE_MS) + 10);
      return;
    }
    ready(r, settled);
  };
  const r = runtimes.get(paneId);
  if (r) r.injectTimer = setTimeout(tick, INJECT_IDLE_MS);
}

// After the hooks are typed in, the shell answers with its first marks within
// a round trip; a shell that stays silent this long did not take them.
const MARKS_WAIT_MS = 3000;

/**
 * Type the OSC 133 hooks into the shell once its first prompt has settled.
 * Only for shells we have a script for, only when the setting allows it,
 * only into this pane (never broadcast), and never on a timeout alone: a
 * session that lands in a REPL, a TUI or `ssh host -t cmd` shows no shell
 * prompt, and the script must not arrive there as input. Shells that get
 * no hooks (or ignore them) still receive the workspace's saved directory /
 * command.
 */
function scheduleIntegration(paneId: Uuid, shell: string) {
  const rt = runtimes.get(paneId);
  if (rt?.integration !== "pending") return;
  const kind = integratedShell(shell);
  if (!kind || currentSettings?.shellIntegration === false) {
    rt.integration = "none";
    if (rt.restore) whenPromptReady(paneId, () => applyRestore(paneId));
    return;
  }
  whenPromptReady(paneId, (r, settled) => {
    if (r.integration !== "pending") return;
    if (!settled) {
      r.integration = "none";
      if (r.restore) applyRestore(paneId);
      return;
    }
    r.integration = "sent";
    if (r.shell.active) return;
    const script = integrationCommand(kind, r.term.buffer.active.cursorX, r.term.cols);
    void writeOrdered(paneId, script);
    if (r.restore) {
      setTimeout(() => {
        const cur = runtimes.get(paneId);
        if (cur?.restore && !cur.shell.active) {
          whenPromptReady(paneId, () => applyRestore(paneId));
        }
      }, MARKS_WAIT_MS);
    }
  });
}

// ───────────────────────────── command history ─────────────────────────────

let historyCache: string[] | null = null;
let historyLoading: Promise<void> | null = null;

function loadHistory(): Promise<void> {
  historyLoading ??= ipc
    .historyCommands(1000)
    .then((items) => {
      const seen = new Set<string>();
      historyCache = [];
      for (const it of items) {
        if (seen.has(it.data.command)) continue;
        seen.add(it.data.command);
        historyCache.push(it.data.command);
      }
    })
    .catch(() => {
      historyCache = [];
    })
    .finally(() => {
      historyLoading = null;
    });
  return historyLoading;
}

/** Forget the cached history (after deleting / clearing from the panel). */
export function dropHistoryCache() {
  historyCache = null;
}

function recordCommand(paneId: Uuid, command: string) {
  const s = terminalStore.get();
  const pane = s.panes[paneId];
  if (!pane || command.startsWith("__tmo_") || looksLikeSecret(command)) return;
  const tab = tabOf(s, paneId);
  if (tab?.broadcast && tab.paneIds.length > 1 && tab.activePaneId !== paneId) return;
  ipc
    .historyRecordCommand(pane.hostId, command)
    .then((id) => {
      if (id === null) return;
      if (historyCache) {
        historyCache = [command, ...historyCache.filter((c) => c !== command)];
      }
      void queryClient?.invalidateQueries({ queryKey: keys.commandHistory });
    })
    .catch(() => undefined);
}

let snippetCache: SnippetSource[] = [];
let snippetsLoadedAt = 0;

function loadSnippets() {
  if (Date.now() - snippetsLoadedAt < 30_000) return;
  snippetsLoadedAt = Date.now();
  ipc
    .snippetsList(null)
    .then((list) => {
      snippetCache = list.map((s) => ({ label: s.label, script: s.script }));
    })
    .catch(() => undefined);
}

// ───────────────────────────── suggestions ─────────────────────────────

const SUGGEST_DEBOUNCE_MS = 40;
const POPUP_HEIGHT = 240;

export function autocompleteOn(paneId: Uuid, s: TerminalState = terminalStore.get()): boolean {
  if (currentSettings?.autocomplete === false) return false;
  if (s.suggestPausedUntil !== null && s.suggestPausedUntil > Date.now()) return false;
  return s.panes[paneId]?.autocomplete ?? false;
}

export function setPaneAutocomplete(paneId: Uuid, on: boolean) {
  patchPane(paneId, { autocomplete: on });
  if (!on) hideSuggest(paneId);
}

/** Pause suggestions in every terminal until the end of the day (or resume with `null`). */
export function pauseSuggestions(until: number | null) {
  try {
    if (until === null) localStorage.removeItem(PAUSE_KEY);
    else localStorage.setItem(PAUSE_KEY, String(until));
  } catch {
    // storage unavailable — pause for this run only
  }
  update((s) => ({ ...s, suggestPausedUntil: until, suggest: until === null ? s.suggest : null }));
}

export function endOfToday(): number {
  const d = new Date();
  d.setHours(24, 0, 0, 0);
  return d.getTime();
}

export function hideSuggest(paneId: Uuid) {
  update((s) => (s.suggest?.paneId === paneId ? { ...s, suggest: null } : s));
}

function scheduleSuggest(paneId: Uuid) {
  const rt = runtimes.get(paneId);
  if (!rt) return;
  if (rt.suggestTimer) clearTimeout(rt.suggestTimer);
  rt.suggestTimer = setTimeout(() => {
    rt.suggestTimer = null;
    computeSuggest(paneId);
  }, SUGGEST_DEBOUNCE_MS);
}

/** Pixel position of the cursor cell inside the pane, or null before layout. */
export function cursorPixels(
  rt: Runtime,
): { left: number; top: number; cellHeight: number } | null {
  const screen = rt.container.querySelector<HTMLElement>(".xterm-screen");
  if (!screen || rt.term.cols === 0 || rt.term.rows === 0) return null;
  const cellW = screen.clientWidth / rt.term.cols;
  const cellH = screen.clientHeight / rt.term.rows;
  const b = rt.term.buffer.active;
  const offsetTop = screen.getBoundingClientRect().top - rt.container.getBoundingClientRect().top;
  const offsetLeft =
    screen.getBoundingClientRect().left - rt.container.getBoundingClientRect().left;
  return {
    left: offsetLeft + b.cursorX * cellW,
    top: offsetTop + b.cursorY * cellH,
    cellHeight: cellH,
  };
}

function showSuggest(paneId: Uuid, items: Suggestion[]) {
  const rt = runtimes.get(paneId);
  if (!rt || items.length === 0) {
    hideSuggest(paneId);
    return;
  }
  const pos = cursorPixels(rt);
  if (!pos) return;
  const above = pos.top + pos.cellHeight + POPUP_HEIGHT > rt.container.clientHeight;
  update((s) => {
    const prev = s.suggest;
    const selected =
      prev?.paneId === paneId && prev.items[prev.selected]?.label === items[prev.selected]?.label
        ? prev.selected
        : 0;
    return {
      ...s,
      suggest: { paneId, items, selected, ...pos, above, paneWidth: rt.container.clientWidth },
    };
  });
}

function computeSuggest(paneId: Uuid) {
  const rt = runtimes.get(paneId);
  if (!rt || !autocompleteOn(paneId)) return;
  const line = currentInput(rt);
  if (!line?.trim()) {
    hideSuggest(paneId);
    return;
  }
  if (rt.mutedLine !== null) {
    if (rt.mutedLine === line) return;
    rt.mutedLine = null;
  }
  if (historyCache === null) {
    void loadHistory().then(() => {
      if (runtimes.get(paneId) && currentInput(rt) === line) computeSuggest(paneId);
    });
    return;
  }
  loadSnippets();
  const { items, path } = complete({ line, history: historyCache, snippets: snippetCache });
  showSuggest(paneId, items);
  if (path) void listPath(paneId, rt, line, items, path);
}

const dirCache = new Map<string, { at: number; entries: DirEntry[] }>();
const DIR_CACHE_MS = 5000;

async function listPath(
  paneId: Uuid,
  rt: Runtime,
  line: string,
  items: Suggestion[],
  q: PathQuery,
) {
  const seq = ++rt.pathSeq;
  const dir = q.dir === "" ? "." : q.dir;
  const key = `${paneId}\0${rt.shell.cwd ?? ""}\0${dir}`;
  let cached = dirCache.get(key);
  if (!cached || Date.now() - cached.at > DIR_CACHE_MS) {
    try {
      const entries = await ipc.terminalListDir(paneId, rt.shell.cwd, dir);
      cached = { at: Date.now(), entries };
      dirCache.set(key, cached);
    } catch {
      return;
    }
  }
  if (rt.pathSeq !== seq || !runtimes.has(paneId)) return;
  if (currentInput(rt) !== line) return;
  showSuggest(paneId, mergePaths(items, q, cached.entries));
}

/** Offer the saved password when the last output line asks for one (explicit Tab to insert). */
function offerIdentity(paneId: Uuid, rt: Runtime) {
  const b = rt.term.buffer.active;
  const line = b.getLine(b.baseY + b.cursorY)?.translateToString(true, 0, b.cursorX) ?? "";
  const current = terminalStore.get().suggest;
  if (!looksLikePasswordPrompt(line)) {
    if (current?.paneId === paneId && current.items[0]?.kind === "identity") hideSuggest(paneId);
    return;
  }
  if (current?.paneId === paneId && current.items[0]?.kind === "identity") return;
  showSuggest(paneId, [
    {
      kind: "identity",
      label: `Password · ${rt.identityLabel ?? ""}`,
      desc: tr("from Keychain — Tab to insert"),
      insert: "",
    },
  ]);
}

export function moveSuggest(step: 1 | -1) {
  update((s) => {
    if (!s.suggest) return s;
    const n = s.suggest.items.length;
    return { ...s, suggest: { ...s.suggest, selected: (s.suggest.selected + step + n) % n } };
  });
}

export function selectSuggest(index: number) {
  update((s) =>
    s.suggest?.items[index] && s.suggest.selected !== index
      ? { ...s, suggest: { ...s.suggest, selected: index } }
      : s,
  );
}

export function acceptSuggest(index?: number) {
  const s = terminalStore.get();
  const sg = s.suggest;
  if (!sg) return;
  const item = sg.items[index ?? sg.selected];
  hideSuggest(sg.paneId);
  if (!item) return;
  if (item.kind === "identity") {
    ipc.terminalInsertPassword(sg.paneId, null).catch((e: unknown) => {
      writeSystemLine(sg.paneId, errorMessage(e), "31");
    });
    return;
  }
  const rt = runtimes.get(sg.paneId);
  if (rt) rt.mutedLine = null;
  void sendInput(sg.paneId, item.insert + (item.kind === "path" ? "" : suffixFor(item.kind)));
}

export function dismissSuggest(paneId: Uuid) {
  const rt = runtimes.get(paneId);
  if (rt) rt.mutedLine = currentInput(rt);
  hideSuggest(paneId);
}

/** Keys the popup consumes while it is open; returns true when handled. */
function handleSuggestKey(paneId: Uuid, ev: KeyboardEvent): boolean {
  const sg = terminalStore.get().suggest;
  if (sg?.paneId !== paneId) return false;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return false;
  switch (ev.code) {
    case "ArrowDown":
      moveSuggest(1);
      return true;
    case "ArrowUp":
      moveSuggest(-1);
      return true;
    case "Tab":
      acceptSuggest();
      return true;
    case "Escape":
      dismissSuggest(paneId);
      return true;
    case "Enter":
    case "NumpadEnter":
      hideSuggest(paneId);
      return false;
    default:
      return false;
  }
}

// ───────────────────────────── input ─────────────────────────────

/** Type `command` and run it in the pane (honours broadcast). */
export function runCommand(paneId: Uuid, command: string) {
  if (terminalStore.get().panes[paneId]?.status !== "connected") return;
  focusPane(paneId);
  void sendInput(paneId, `${command.replace(/\r?\n/g, "\r")}\r`);
}

/**
 * Per-pane outbox: every Tauri command runs as its own task, so two
 * back-to-back `terminal_write`s may reach the PTY out of order. Only one
 * write is in flight per pane; input arriving meanwhile is appended and goes
 * out as the next chunk.
 */
const outbox = new Map<Uuid, { buf: string; busy: boolean }>();

/**
 * Input produced while the pane is still connecting, sent as soon as it is.
 * xterm.js answers terminal queries on its own (ConPTY opens with `ESC[6n`,
 * a cursor-position request, and renders nothing until it gets the reply),
 * and the first output often lands before the open call has resolved —
 * dropping that reply left Windows local terminals blank forever.
 */
const pendingInput = new Map<Uuid, string>();
const PENDING_INPUT_MAX = 64 * 1024;

function queuePendingInput(paneId: Uuid, data: string) {
  const buf = (pendingInput.get(paneId) ?? "") + data;
  pendingInput.set(paneId, buf.length > PENDING_INPUT_MAX ? buf.slice(-PENDING_INPUT_MAX) : buf);
}

function flushPendingInput(paneId: Uuid) {
  const queued = pendingInput.get(paneId);
  pendingInput.delete(paneId);
  if (queued) void writeOrdered(paneId, queued);
}

function writeOrdered(paneId: Uuid, data: string): Promise<void> {
  let box = outbox.get(paneId);
  if (!box) {
    box = { buf: "", busy: false };
    outbox.set(paneId, box);
  }
  box.buf += data;
  if (box.busy) return Promise.resolve();
  return drainOutbox(paneId, box);
}

async function drainOutbox(paneId: Uuid, box: { buf: string; busy: boolean }) {
  box.busy = true;
  try {
    while (box.buf) {
      const chunk = box.buf;
      box.buf = "";
      await ipc.terminalWrite(paneId, chunk).catch(() => undefined);
    }
  } finally {
    box.busy = false;
    if (!runtimes.has(paneId)) outbox.delete(paneId);
  }
}

async function sendInput(paneId: Uuid, data: string) {
  const s = terminalStore.get();
  // Enter in a dropped pane is the snackbar's "Reconnect ⏎".
  if (data === "\r" && s.reconnect?.paneIds.includes(paneId)) {
    reconnectNow();
    return;
  }
  if (s.suggest?.paneId === paneId && s.suggest.items[0]?.kind === "identity") hideSuggest(paneId);
  if (s.panes[paneId]?.status === "connecting") {
    queuePendingInput(paneId, data);
    return;
  }
  const rt = runtimes.get(paneId);
  if (rt) noteTyped(paneId, rt, data);
  const tab = tabOf(s, paneId);
  const targets =
    tab?.broadcast && tab.paneIds.length > 1
      ? tab.paneIds.filter((id) => s.panes[id]?.status === "connected")
      : [paneId];
  await Promise.all(
    targets.map((id) =>
      s.panes[id]?.status === "connected" ? writeOrdered(id, data) : Promise.resolve(),
    ),
  );
}

// ───────────────────────────── lifecycle ─────────────────────────────

function describe(target: OpenTarget): { title: string; subtitle: string } {
  switch (target.kind) {
    case "local":
      return { title: tr("Local"), subtitle: tr("local shell") };
    case "quick":
      return { title: target.address, subtitle: target.address };
    case "serial":
      return { title: target.path.replace(/^\/dev\//, ""), subtitle: target.path };
    case "host":
      return { title: tr("Connecting…"), subtitle: "" };
    case "live":
      return { title: tr("Multiplayer"), subtitle: tr("joining…") };
  }
}

const utf8 = new TextDecoder();

/** Called whenever Settings change: the trigger list the panes watch. */
export const applyTriggers = triggers.setTriggers;

function startSession(paneId: Uuid, target: OpenTarget) {
  pendingInput.delete(paneId);
  const rt = runtimes.get(paneId);
  const cols = rt?.term.cols ?? 80;
  const rows = rt?.term.rows ?? 24;
  ipc
    .terminalOpen(paneId, target, cols, rows, (bytes) => {
      const r = runtimes.get(paneId);
      if (!r) return;
      const data = r.highlighter ? r.highlighter.push(bytes) : bytes;
      const text = typeof bytes === "string" ? bytes : utf8.decode(bytes, { stream: true });
      const hits = triggers.scan(paneId, text);
      r.term.write(data, () => {
        onOutput(paneId);
        for (const h of hits) {
          if (h.trigger.highlight) triggers.highlightCurrentRow(r.term);
          if (h.trigger.notify) {
            const pane = terminalStore.get().panes[paneId];
            void triggers.notifyHit(pane?.title ?? "", h);
          }
          if (h.trigger.reply) void sendInput(paneId, triggers.unescapeReply(h.trigger.reply));
        }
      });
    })
    .then((info) => {
      patchPane(paneId, {
        title: info.title,
        subtitle: info.target,
        protocol: info.protocol,
        hostId: info.hostId,
        algorithms: info.algorithms,
        via: info.via,
        hostTheme: info.colorScheme,
        startedAt: info.startedAt,
        status: "connected",
        message: null,
        progress: null,
        shell: info.shell,
        reconnecting: false,
        zmodem: null,
      });
      flushPendingInput(paneId);
      retries.delete(paneId);
      appendLog(paneId, tr("Session opened"));
      applyPaneLook(paneId);
      if (info.protocol === "multiplayer") {
        void viewerJoined(paneId);
        return;
      }
      const t = runtimes.get(paneId)?.term;
      if (t) ipc.terminalResize(paneId, t.cols, t.rows).catch(() => undefined);
      if (info.shell) scheduleIntegration(paneId, info.shell);
      if (info.hostId) {
        ipc
          .terminalHostIdentity(paneId)
          .then((label) => {
            const r = runtimes.get(paneId);
            if (r) r.identityLabel = label;
          })
          .catch(() => undefined);
      }
    })
    .catch((e: unknown) => {
      const pane = terminalStore.get().panes[paneId];
      if (!pane || pane.status === "closed" || pane.status === "error") return;
      const message = errorMessage(e);
      if (message.startsWith("cancelled") || /cancel/i.test(message)) {
        pendingInput.delete(paneId);
        patchPane(paneId, { status: "closed", message: tr("Cancelled") });
      } else {
        pendingInput.delete(paneId);
        patchPane(paneId, { status: "error", message });
        appendLog(paneId, message, "error");
        writeSystemLine(paneId, message, "31");
        if (retries.has(paneId)) queueReconnect(paneId);
      }
    });
}

export interface OpenOptions {
  /** Add as a split pane to this tab instead of opening a new tab. */
  intoTab?: string;
  direction?: SplitDirection;
  /** Open without switching to the tab. */
  background?: boolean;
  /** Open in a new workspace tab with this name instead of a plain session tab. */
  workspaceName?: string;
}

function newPane(paneId: Uuid, target: OpenTarget): Pane {
  const { title, subtitle } = describe(target);
  return {
    id: paneId,
    target,
    title,
    subtitle,
    protocol: null,
    hostId: target.kind === "host" ? target.host_id : null,
    algorithms: null,
    via: [],
    hostTheme: null,
    startedAt: null,
    status: "connecting",
    message: null,
    progress: null,
    log: [],
    shell: null,
    integration: false,
    cwd: null,
    command: null,
    lastExit: null,
    autocomplete: true,
    reconnecting: false,
    zmodem: null,
  };
}

/**
 * Open a terminal for `target` in a new tab, or split the target tab's active
 * pane. Returns `null` when the tab already holds `MAX_PANES` panes.
 */
/** Team permissions for the transport (client-enforced; team vaults only). */
function connectAllowed(target: OpenTarget): boolean {
  switch (target.kind) {
    case "host": {
      const vaultId = target.vault_id ?? null;
      const perm =
        target.protocol === "telnet"
          ? "connect.telnet"
          : target.protocol === "mosh"
            ? "connect.mosh"
            : "connect.ssh";
      return requirePerm(vaultId, perm);
    }
    case "serial":
      return requireAnywhere("connect.serial");
    case "local":
      return requireAnywhere("connect.local_terminal");
    default:
      return true;
  }
}

export function openTerminal(target: OpenTarget, opts: OpenOptions = {}): Uuid | null {
  if (!connectAllowed(target)) return null;
  const state = terminalStore.get();
  const existing = opts.intoTab ? state.tabs.find((t) => t.id === opts.intoTab) : undefined;
  if (existing && existing.paneIds.length >= MAX_PANES) return null;

  const paneId = uuid();
  const pane = newPane(paneId, target);
  runtimes.set(paneId, createRuntime(paneId));

  update((s) => {
    const panes = { ...s.panes, [paneId]: pane };
    if (existing) {
      const tabs = s.tabs.map((t) =>
        t.id === existing.id
          ? {
              ...withLayout(
                t,
                splitLeaf(t.layout, t.activePaneId, paneId, opts.direction ?? "row", uuid()),
              ),
              activePaneId: paneId,
            }
          : t,
      );
      return { ...s, panes, tabs, activeTabId: opts.background ? s.activeTabId : existing.id };
    }
    const tab = newTab(leaf(paneId), { name: opts.workspaceName ?? null });
    return {
      ...s,
      panes,
      tabs: [...s.tabs, tab],
      activeTabId: opts.background ? s.activeTabId : tab.id,
    };
  });
  applyPaneLook(paneId);
  startSession(paneId, target);
  return paneId;
}

export interface OpenLayoutOptions {
  name?: string | null;
  viewMode?: TabViewMode;
  templateId?: Uuid | null;
  background?: boolean;
}

/**
 * Open every leaf of a saved layout at once as one tab (a workspace template
 * or a tab from the previous session). Splits beyond `MAX_PANES` are dropped
 * from the right. Returns the new tab id.
 */
export function openLayout(template: LayoutTemplate, opts: OpenLayoutOptions = {}): string {
  const opened: { paneId: Uuid; target: OpenTarget; restore: Runtime["restore"] }[] = [];
  const build = (node: LayoutTemplate): SplitNode | null => {
    if (node.kind === "leaf") {
      if (opened.length >= MAX_PANES) return null;
      const paneId = uuid();
      opened.push({ paneId, target: node.target, restore: leafState(node) });
      return leaf(paneId);
    }
    const first = build(node.first);
    const second = build(node.second);
    if (!first) return second;
    if (!second) return first;
    return {
      kind: "split",
      id: uuid(),
      direction: node.direction,
      ratio: node.ratio,
      first,
      second,
    };
  };
  let layout = build(template);
  if (!layout) {
    const paneId = uuid();
    opened.push({ paneId, target: { kind: "local" }, restore: null });
    layout = leaf(paneId);
  }
  const panes: Record<Uuid, Pane> = {};
  for (const { paneId, target, restore } of opened) {
    panes[paneId] = newPane(paneId, target);
    const rt = createRuntime(paneId);
    rt.restore = restore;
    runtimes.set(paneId, rt);
  }
  const tab = newTab(layout, {
    name: opts.name ?? null,
    viewMode: opts.viewMode ?? "split",
    focused: false,
    templateId: opts.templateId ?? null,
  });
  update((s) => ({
    ...s,
    panes: { ...s.panes, ...panes },
    tabs: [...s.tabs, tab],
    activeTabId: opts.background ? s.activeTabId : tab.id,
  }));
  for (const { paneId, target } of opened) {
    applyPaneLook(paneId);
    startSession(paneId, target);
  }
  return tab.id;
}

/**
 * Serialisable copy of a tab's split tree: targets, ratios and what the shell
 * last reported (working directory, running command) — never screen contents.
 */
export function tabLayoutTemplate(
  tab: TerminalTab,
  s: TerminalState = terminalStore.get(),
): LayoutTemplate | null {
  const walk = (node: SplitNode): LayoutTemplate | null => {
    if (node.kind === "leaf") {
      const pane = s.panes[node.paneId];
      if (!pane) return null;
      return withLeafState({ kind: "leaf", target: pane.target }, pane);
    }
    const first = walk(node.first);
    const second = walk(node.second);
    if (!first) return second;
    if (!second) return first;
    return { kind: "split", direction: node.direction, ratio: node.ratio, first, second };
  };
  return walk(tab.layout);
}

/** Give the tab a workspace name (`null` turns it back into a plain session tab). */
export function renameTab(tabId: string, name: string | null) {
  const trimmed = name?.trim() ?? "";
  patchTab(tabId, { name: trimmed ? trimmed : null });
}

export function toggleFocus(tabId: string) {
  const tab = terminalStore.get().tabs.find((t) => t.id === tabId);
  if (!tab) return;
  const focused = !tab.focused && tab.paneIds.length > 1;
  update((s) => ({
    ...s,
    tabs: s.tabs.map((t) => (t.id === tabId ? { ...t, focused } : t)),
  }));
  focusPane(tab.activePaneId);
}

export function setTabViewMode(tabId: string, viewMode: TabViewMode) {
  patchTab(tabId, { viewMode });
  const tab = terminalStore.get().tabs.find((t) => t.id === tabId);
  if (tab) requestAnimationFrame(() => tab.paneIds.forEach(fitPane));
}

export function toggleTabViewMode(tabId: string) {
  const tab = terminalStore.get().tabs.find((t) => t.id === tabId);
  if (tab) setTabViewMode(tabId, tab.viewMode === "split" ? "list" : "split");
}

export function setTabTemplate(tabId: string, templateId: Uuid | null) {
  patchTab(tabId, { templateId });
}

/** Open workspace tabs (named tabs), in strip order. */
export function workspaceTabs(s: TerminalState = terminalStore.get()): TerminalTab[] {
  return s.tabs.filter(isWorkspaceTab);
}

/** Split the tab's active pane with a fresh session to the same target. */
export function splitActivePane(tabId: string, direction: SplitDirection) {
  const s = terminalStore.get();
  const tab = s.tabs.find((t) => t.id === tabId);
  const pane = tab ? s.panes[tab.activePaneId] : undefined;
  if (!tab || !pane) return;
  openTerminal(pane.target, { intoTab: tabId, direction });
}

export function setSplitRatio(tabId: string, splitId: string, ratio: number) {
  update((s) => ({
    ...s,
    tabs: s.tabs.map((t) =>
      t.id === tabId ? withLayout(t, setRatio(t.layout, splitId, ratio)) : t,
    ),
  }));
}

/** Move keyboard focus to the pane next to the active one. */
export function focusNeighbor(tabId: string, side: Side) {
  const s = terminalStore.get();
  const tab = s.tabs.find((t) => t.id === tabId);
  if (!tab || tab.paneIds.length < 2) return;
  const rectOf = (id: Uuid): Rect | null => {
    const el = runtimes.get(id)?.container;
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { left: r.left, top: r.top, width: r.width, height: r.height };
  };
  const from = rectOf(tab.activePaneId);
  if (!from) return;
  const others = new Map<Uuid, Rect>();
  for (const id of tab.paneIds) {
    if (id === tab.activePaneId) continue;
    const r = rectOf(id);
    if (r) others.set(id, r);
  }
  const next = neighbor(from, others, side);
  if (next) {
    setActivePane(next);
    focusPane(next);
  }
}

/** Detach a pane from its split tab into a tab of its own. */
export function movePaneToNewTab(paneId: Uuid) {
  const s = terminalStore.get();
  const tab = tabOf(s, paneId);
  if (!tab || tab.paneIds.length < 2) return;
  update((st) => {
    const tabs: TerminalTab[] = [];
    let fresh: TerminalTab | null = null;
    for (const t of st.tabs) {
      if (t.id !== tab.id) {
        tabs.push(t);
        continue;
      }
      const rest = removeLeaf(t.layout, paneId);
      if (rest) {
        const kept = withLayout(t, rest);
        tabs.push({
          ...kept,
          activePaneId: kept.paneIds.includes(t.activePaneId)
            ? t.activePaneId
            : (kept.paneIds[0] ?? t.activePaneId),
          broadcast: kept.paneIds.length > 1 && t.broadcast,
        });
      }
      fresh = newTab(leaf(paneId), { zoom: t.zoom, themeOverride: t.themeOverride });
      tabs.push(fresh);
    }
    return fresh ? { ...st, tabs, activeTabId: fresh.id } : st;
  });
  requestAnimationFrame(() => fitPane(paneId));
}

// ───────────────────────────── reconnect ─────────────────────────────

/** Attempts already made for a pane whose session dropped; absent = not auto-reconnecting. */
const retries = new Map<Uuid, number>();
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

function autoReconnects(pane: Pane): boolean {
  return (
    currentSettings?.autoReconnect !== false &&
    (pane.protocol === "ssh" || pane.protocol === "mosh" || pane.protocol === "telnet") &&
    pane.startedAt !== null
  );
}

/**
 * A live session dropped without the user asking for it: put the pane on the
 * reconnection queue. Panes that joined while a countdown is running share it.
 */
function queueReconnect(paneId: Uuid) {
  const attempts = retries.get(paneId) ?? 0;
  if (attempts >= RECONNECT_ATTEMPTS) {
    retries.delete(paneId);
    return;
  }
  retries.set(paneId, attempts);
  update((s) => {
    const reconnect = enqueueReconnect(s.reconnect, paneId, attempts, Date.now());
    return reconnect === s.reconnect ? s : { ...s, reconnect };
  });
  armReconnectTimer();
}

function armReconnectTimer() {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  const q = terminalStore.get().reconnect;
  if (!q) return;
  reconnectTimer = setTimeout(fireReconnect, Math.max(0, q.dueAt - Date.now()));
}

function fireReconnect() {
  reconnectTimer = null;
  const q = terminalStore.get().reconnect;
  update((s) => ({ ...s, reconnect: null }));
  for (const id of q?.paneIds ?? []) {
    retries.set(id, (retries.get(id) ?? 0) + 1);
    void reconnectPane(id);
  }
}

function dequeueReconnect(paneId: Uuid) {
  update((s) => {
    const reconnect = dequeueReconnectQueue(s.reconnect, paneId);
    return reconnect === s.reconnect ? s : { ...s, reconnect };
  });
  if (!terminalStore.get().reconnect && reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

/** Snackbar "Reconnect": try every queued pane right away. */
export function reconnectNow() {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  fireReconnect();
}

/** Snackbar "Close terminal": drop every queued pane. */
export function closeDisconnected() {
  const ids = terminalStore.get().reconnect?.paneIds ?? [];
  update((s) => ({ ...s, reconnect: null }));
  for (const id of ids) void closePane(id);
}

/** Snackbar "×": stop retrying; the panes keep their buffer and the manual Reconnect button. */
export function dismissReconnect() {
  const ids = terminalStore.get().reconnect?.paneIds ?? [];
  for (const id of ids) retries.delete(id);
  update((s) => ({ ...s, reconnect: null }));
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

/**
 * Open a new session to the pane's target in the same xterm, keeping the
 * scrollback; the pane id stays the session id.
 */
export async function reconnectPane(paneId: Uuid) {
  const pane = terminalStore.get().panes[paneId];
  if (!pane || pane.status === "connecting" || pane.status === "connected") return;
  dequeueReconnect(paneId);
  const rt = runtimes.get(paneId);
  if (rt) {
    if (rt.injectTimer) clearTimeout(rt.injectTimer);
    rt.injectTimer = null;
    rt.shell = newTracker();
    rt.integration = "pending";
    rt.pendingCommand = null;
    rt.typedStart = null;
    rt.identityLabel = null;
    hideSuggest(paneId);
  }
  patchPane(paneId, {
    status: "connecting",
    message: null,
    progress: null,
    log: [],
    startedAt: null,
    integration: false,
    cwd: null,
    command: null,
    lastExit: null,
    shell: null,
    reconnecting: pane.startedAt !== null || pane.reconnecting,
  });
  writeSystemLine(paneId, tr("Reconnecting…"));
  await ipc.terminalClose(paneId).catch(() => undefined);
  if (terminalStore.get().panes[paneId]?.status !== "connecting") return;
  startSession(paneId, pane.target);
}

function removePane(paneId: Uuid) {
  retries.delete(paneId);
  dequeueReconnect(paneId);
  disposeRuntime(paneId);
  update((s) => {
    const panes = omit(s.panes, paneId);
    let activeTabId = s.activeTabId;
    const tabs: TerminalTab[] = [];
    for (const t of s.tabs) {
      if (!t.paneIds.includes(paneId)) {
        tabs.push(t);
        continue;
      }
      const rest = removeLeaf(t.layout, paneId);
      if (rest === null) {
        if (activeTabId === t.id) {
          const i = s.tabs.indexOf(t);
          const next = s.tabs[i + 1] ?? s.tabs[i - 1];
          activeTabId = next?.id ?? HOME_TAB;
        }
        continue;
      }
      const kept = withLayout(t, rest);
      const last = kept.paneIds[kept.paneIds.length - 1] ?? t.activePaneId;
      tabs.push({
        ...kept,
        activePaneId: t.activePaneId === paneId ? last : t.activePaneId,
        broadcast: kept.paneIds.length > 1 && t.broadcast,
      });
    }
    const contextMenu = s.contextMenu?.paneId === paneId ? null : s.contextMenu;
    const pendingClose = s.pendingClose?.filter((id) => id !== paneId) ?? null;
    return {
      ...s,
      panes,
      tabs,
      activeTabId,
      pendingClose: pendingClose?.length ? pendingClose : null,
      contextMenu,
    };
  });
}

/** Close a pane, asking first when it is still connected and the setting says so. */
export function requestClosePane(paneId: Uuid) {
  const pane = terminalStore.get().panes[paneId];
  if (!pane) return;
  if (pane.status === "connected" && currentSettings?.confirmCloseTab) {
    update((s) => ({ ...s, pendingClose: [paneId] }));
    return;
  }
  void closePane(paneId);
}

export function confirmPendingClose(accept: boolean) {
  const ids = terminalStore.get().pendingClose;
  update((s) => ({ ...s, pendingClose: null }));
  if (ids && accept) for (const id of ids) void closePane(id);
}

export async function closePane(paneId: Uuid) {
  const pane = terminalStore.get().panes[paneId];
  if (!pane) return;
  patchPane(paneId, { status: "closed" });
  removePane(paneId);
  await ipc.terminalClose(paneId).catch(() => undefined);
}

/** Close every tab except `tabId` (each goes through the usual close confirmation). */
export function closeOtherTabs(tabId: string) {
  for (const t of terminalStore.get().tabs) if (t.id !== tabId) closeTab(t.id);
}

export function closeTab(tabId: string) {
  const tab = terminalStore.get().tabs.find((t) => t.id === tabId);
  if (!tab) return;
  const live = tab.paneIds.some((id) => terminalStore.get().panes[id]?.status === "connected");
  if (live && currentSettings?.confirmCloseTab) {
    update((s) => ({ ...s, pendingClose: [...tab.paneIds] }));
    return;
  }
  for (const id of tab.paneIds) void closePane(id);
}

/** Vault locked: Rust already closed every session, so drop the tabs without asking. */
export function dropAllTabs() {
  const s = terminalStore.get();
  for (const t of s.tabs) for (const id of t.paneIds) void closePane(id);
}

export function setActiveTab(tabId: string) {
  update((s) => (s.activeTabId === tabId ? s : { ...s, activeTabId: tabId }));
}

/** Switch to the tab `offset` places away, wrapping around. */
export function cycleTab(offset: number) {
  const s = terminalStore.get();
  if (s.tabs.length === 0) return;
  const i = s.tabs.findIndex((t) => t.id === s.activeTabId);
  const next =
    s.tabs[((((i === -1 ? 0 : i) + offset) % s.tabs.length) + s.tabs.length) % s.tabs.length];
  if (next) setActiveTab(next.id);
}

/** Reorder: place `tabId` where `beforeId` is (or at the end when `null`). */
export function moveTab(tabId: string, beforeId: string | null) {
  update((s) => {
    if (tabId === beforeId) return s;
    const moving = s.tabs.find((t) => t.id === tabId);
    if (!moving) return s;
    const rest = s.tabs.filter((t) => t.id !== tabId);
    const at = beforeId === null ? rest.length : rest.findIndex((t) => t.id === beforeId);
    if (at === -1) return s;
    const tabs = [...rest.slice(0, at), moving, ...rest.slice(at)];
    return { ...s, tabs };
  });
}

export function setActivePane(paneId: Uuid) {
  update((s) => {
    const tab = tabOf(s, paneId);
    if (!tab || tab.activePaneId === paneId) return s;
    return {
      ...s,
      tabs: s.tabs.map((t) => (t.id === tab.id ? { ...t, activePaneId: paneId } : t)),
    };
  });
}

export function toggleBroadcast(tabId: string) {
  update((s) => ({
    ...s,
    tabs: s.tabs.map((t) => (t.id === tabId ? { ...t, broadcast: !t.broadcast } : t)),
  }));
}

/** Search lives in the side panel's Terminal section (like Termius). */
export function setSearchOpen(open: boolean) {
  update((s) => {
    if (open) return s.sidePanel === "search" ? s : { ...s, sidePanel: "search" };
    return s.sidePanel === "search" ? { ...s, sidePanel: null } : s;
  });
}

export const isSearchOpen = (s: TerminalState) => s.sidePanel === "search";

export function setSidePanel(panel: SidePanelTab | null) {
  update((s) => (s.sidePanel === panel ? s : { ...s, sidePanel: panel }));
}

/** Open the side panel on `panel`, or close it when that section is already showing. */
export function toggleSidePanel(panel: SidePanelTab = "snippets") {
  update((s) => ({ ...s, sidePanel: s.sidePanel === null ? panel : null }));
}

/** Send text to a pane (e.g. a snippet); goes through the same broadcast rules. */
export function sendText(paneId: Uuid, text: string) {
  void sendInput(paneId, text);
}

export function activeSshPane(): Pane | null {
  const s = terminalStore.get();
  const tab = s.tabs.find((t) => t.id === s.activeTabId);
  const pane = tab ? s.panes[tab.activePaneId] : undefined;
  return pane?.protocol === "ssh" && pane.status === "connected" ? pane : null;
}

// ───────────────────────────── events from Rust ─────────────────────────────

/** Ask where `sz` files go (a folder) or which files `rz` gets; declining tells the remote to stop. */
async function pickZmodemTarget(paneId: Uuid, kind: ZmodemKind) {
  try {
    if (kind === "receive") {
      const picked = await openDialog({
        directory: true,
        multiple: false,
        title: tr("Save received files to"),
        defaultPath: await downloadDir().catch(() => undefined),
      });
      if (typeof picked === "string") await ipc.zmodemReceive(paneId, picked);
      else await ipc.zmodemCancel(paneId);
    } else {
      const picked = await openDialog({ multiple: true, title: tr("Files to send") });
      const paths = Array.isArray(picked) ? picked : typeof picked === "string" ? [picked] : [];
      if (paths.length > 0) await ipc.zmodemSend(paneId, paths);
      else await ipc.zmodemCancel(paneId);
    }
  } catch (e) {
    patchPane(paneId, { zmodem: null });
    writeSystemLine(paneId, tr("ZMODEM: {error}", { error: errorMessage(e) }), "33");
  }
}

export function cancelZmodem(paneId: Uuid) {
  void ipc.zmodemCancel(paneId).catch(() => undefined);
}

function onSessionEvent(ev: SessionEvent) {
  const pane = terminalStore.get().panes[ev.id];
  if (!pane) return;
  switch (ev.type) {
    case "connecting":
      patchPane(ev.id, {
        title: ev.info.title,
        subtitle: ev.info.target,
        protocol: ev.info.protocol,
        hostId: ev.info.hostId,
        hostTheme: ev.info.colorScheme,
      });
      appendLog(ev.id, tr("Connecting to {value}", { value: ev.info.target || ev.info.title }));
      applyPaneLook(ev.id);
      break;
    case "connected":
      break;
    case "progress":
      if (pane.status === "connecting") {
        const progress = { hop: ev.hop, phase: ev.phase };
        patchPane(ev.id, { progress });
        appendLog(ev.id, phaseLine(progress));
      }
      break;
    case "shell":
      patchPane(ev.id, { shell: ev.shell });
      scheduleIntegration(ev.id, ev.shell);
      break;
    case "notice":
      if (pane.status === "connecting") appendLog(ev.id, ev.message);
      writeSystemLine(ev.id, ev.message);
      break;
    case "zmodem":
      patchPane(ev.id, { zmodem: { kind: ev.kind, name: "", done: 0, total: null, files: 0 } });
      void pickZmodemTarget(ev.id, ev.kind);
      break;
    case "zmodem_progress":
      patchPane(ev.id, {
        zmodem: { kind: ev.kind, name: ev.name, done: ev.done, total: ev.total, files: ev.files },
      });
      break;
    case "zmodem_done": {
      const z = pane.zmodem;
      patchPane(ev.id, { zmodem: null });
      if (ev.ok) {
        writeSystemLine(
          ev.id,
          z?.kind === "send"
            ? trn(ev.files, "ZMODEM: sent {count} file", "ZMODEM: sent {count} files")
            : trn(ev.files, "ZMODEM: received {count} file", "ZMODEM: received {count} files"),
        );
      } else {
        writeSystemLine(ev.id, tr("ZMODEM: {error}", { error: ev.error ?? tr("failed") }), "33");
      }
      break;
    }
    case "exit": {
      const detail =
        ev.signal !== null
          ? `signal ${ev.signal}`
          : ev.code !== null
            ? `exit code ${ev.code}`
            : "session ended";
      const wasLive = pane.status === "connected";
      patchPane(ev.id, { status: "exited", message: detail });
      writeSystemLine(ev.id, `[${detail}]`);
      // A shell that returned an exit code was ended on purpose (`exit`, Ctrl-D);
      // anything else is a drop.
      if (wasLive && ev.code === null) {
        reportDrop(ev.id);
        if (autoReconnects(pane)) queueReconnect(ev.id);
      }
      break;
    }
    case "error":
      if (pane.status !== "closed" && pane.status !== "error") {
        const wasLive = pane.status === "connected";
        patchPane(ev.id, { status: "error", message: ev.message });
        appendLog(ev.id, ev.message, "error");
        writeSystemLine(ev.id, ev.message, "31");
        if (wasLive) reportDrop(ev.id);
        if ((wasLive && autoReconnects(pane)) || retries.has(ev.id)) queueReconnect(ev.id);
      }
      break;
    case "closed":
      if (pane.status === "connected" || pane.status === "connecting") {
        const wasLive = pane.status === "connected";
        patchPane(ev.id, { status: "exited", message: tr("Connection closed") });
        writeSystemLine(ev.id, tr("[connection closed]"));
        if (wasLive) {
          reportDrop(ev.id);
          if (autoReconnects(pane)) queueReconnect(ev.id);
        }
      }
      break;
  }
}

let started = false;
/** Subscribe to Rust session events once for the app lifetime. */
export function startTerminalEvents(qc: QueryClient) {
  queryClient = qc;
  if (started) return;
  started = true;
  void ipc.onSessionEvent(onSessionEvent);
}

/** Only web / mail targets open from the terminal; file:, ssh: and friends are ignored. */
function safeLinkTarget(uri: string): boolean {
  return /^(https?|mailto):/i.test(uri);
}
