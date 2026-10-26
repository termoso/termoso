// Output triggers: regexes from Settings watched on every terminal pane.
// Each chunk of output is ANSI-stripped and appended to a short per-pane tail;
// a match fires at most once per trigger per pane every 2 s so a scrolling log
// cannot flood notifications.
import { isPermissionGranted, sendNotification } from "@tauri-apps/plugin-notification";
import type { Terminal } from "@xterm/xterm";
import type { Trigger, Uuid } from "@/ipc/types";
import { tr } from "@/i18n";

const TAIL = 4096;
const COOLDOWN_MS = 2000;
// eslint-disable-next-line no-control-regex
const ANSI = /\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\|[@-Z\\-_])/g;

let triggers: Trigger[] = [];
const compiled = new Map<string, RegExp | null>();
const tails = new Map<Uuid, string>();
const lastFired = new Map<string, number>();

export function setTriggers(list: Trigger[]) {
  triggers = list.filter((t) => t.enabled && t.pattern.trim() !== "");
  for (const k of [...compiled.keys()]) {
    if (!triggers.some((t) => t.pattern === k)) compiled.delete(k);
  }
}

function regexFor(pattern: string): RegExp | null {
  const hit = compiled.get(pattern);
  if (hit !== undefined) return hit;
  let re: RegExp | null;
  try {
    re = new RegExp(pattern, "m");
  } catch {
    re = null;
  }
  compiled.set(pattern, re);
  return re;
}

export function forgetPane(paneId: Uuid) {
  tails.delete(paneId);
  for (const k of [...lastFired.keys()]) if (k.startsWith(paneId)) lastFired.delete(k);
}

export interface TriggerHit {
  trigger: Trigger;
  line: string;
}

/** Feed a chunk; returns the triggers that fired on it. */
export function scan(paneId: Uuid, chunk: string): TriggerHit[] {
  if (triggers.length === 0) return [];
  const plain = chunk.replace(ANSI, "");
  if (!plain) return [];
  const prev = tails.get(paneId) ?? "";
  const text = (prev + plain).slice(-TAIL);
  tails.set(paneId, text);
  // Only the part that includes the new chunk (plus the tail of the previous
  // line, so a line split across chunks still matches).
  const start = Math.max(0, prev.lastIndexOf("\n") + 1 - (prev.length - Math.max(0, text.length - plain.length)));
  const window = text.slice(Math.max(0, text.length - plain.length - (prev.length - start)));
  const now = Date.now();
  const hits: TriggerHit[] = [];
  for (const t of triggers) {
    const re = regexFor(t.pattern);
    if (!re) continue;
    const m = re.exec(window);
    if (!m) continue;
    const key = `${paneId}:${t.id}`;
    if ((lastFired.get(key) ?? 0) + COOLDOWN_MS > now) continue;
    lastFired.set(key, now);
    const at = m.index;
    const ls = window.lastIndexOf("\n", at) + 1;
    const le = window.indexOf("\n", at);
    hits.push({ trigger: t, line: window.slice(ls, le === -1 ? undefined : le).trim() });
  }
  return hits;
}

export function highlightCurrentRow(term: Terminal) {
  try {
    const marker = term.registerMarker(0);
    const deco = term.registerDecoration({
      marker,
      width: term.cols,
      backgroundColor: "#f9a825",
      layer: "bottom",
    });
    setTimeout(() => deco?.dispose(), 4000);
  } catch {
    // Decorations need the proposed API; ignore when unavailable.
  }
}

export async function notifyHit(title: string, hit: TriggerHit) {
  try {
    if (!(await isPermissionGranted())) return;
    sendNotification({
      title: hit.trigger.name || tr("Trigger"),
      body: hit.line ? `${title}: ${hit.line}` : title,
    });
  } catch {
    // Notifications unavailable on this platform.
  }
}

/** `\n` → Enter, `\t` → Tab, `\\` → backslash. */
export const unescapeReply = (s: string) =>
  s.replace(/\\(n|t|\\)/g, (_m, c: string) => (c === "n" ? "\r" : c === "t" ? "\t" : "\\"));
