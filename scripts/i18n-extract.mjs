#!/usr/bin/env node
// Builds src/i18n/en.json (the Weblate source template, key = value = English
// text) for the desktop app and the web cabinet. Keys come from:
//  - string literals passed to tr() / trx() / msg(), and the `other` form of
//    trn(count, one, other) (`other` indexes the table; `one` is the English
//    fallback and is never looked up);
//  - entries already in ru.json whose key still appears as a string literal in
//    the TypeScript sources or in the Rust crates (strings keyed through
//    variables, e.g. `tr(option.label)` or server-sent labels).
// Keys built as `prefix:${x}` keep every ru.json entry with that prefix.
// ru.json entries that appear nowhere (or only as the `one` form of a trn
// call) are stale: reported, and removed with
// `--prune`. `--check` exits 1 when a committed en.json is out of date or when
// ru.json has stale entries.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const apps = [
  { name: "desktop", src: join(root, "apps/desktop/src") },
  { name: "web", src: join(root, "web/src") },
];
const check = process.argv.includes("--check");
const prune = process.argv.includes("--prune");
const listStale = process.argv.includes("--stale");

function* walk(dir, ext) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!["node_modules", "i18n", "docs", "target"].includes(e.name))
        yield* walk(p, ext);
    } else if (ext.test(e.name) && !/\.test\.tsx?$/.test(e.name)) yield p;
  }
}

// A JS string literal: "…" or '…' with escapes; template literals are skipped
// (they carry runtime values and are not translation keys).
const LIT = String.raw`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`;
const CALL = new RegExp(
  String.raw`\b(tr[xn]?|msg)\(\s*(?:[^,()]+,\s*)?(?:${LIT})(?:\s*,\s*(?:${LIT}))?`,
  "g",
);
const unescape = (s) =>
  JSON.parse('"' + s.replace(/\\'/g, "'").replace(/"/g, '\\"') + '"');

let rust = "";
for (const file of walk(join(root, "crates"), /\.rs$/))
  rust += readFileSync(file, "utf8");

let failed = false;
for (const app of apps) {
  const keys = new Set();
  const oneForms = new Set();
  const prefixes = new Set();
  let sources = "";
  for (const file of walk(app.src, /\.tsx?$/)) {
    const text = readFileSync(file, "utf8");
    sources += text;
    for (const m of text.matchAll(CALL)) {
      const first = m[2] ?? m[3];
      const second = m[4] ?? m[5];
      if (m[1] === "trn") {
        if (first !== undefined) oneForms.add(unescape(first));
        if (second !== undefined) keys.add(unescape(second));
      } else if (first !== undefined) keys.add(unescape(first));
    }
    // `prefix:${x}` builds keys at runtime: entries starting with the static
    // part of such a template are live.
    for (const m of text.matchAll(/`([^`$\\]{6,})\$\{/g)) prefixes.add(m[1]);
  }
  const ruPath = join(app.src, "i18n/ru.json");
  const ru = JSON.parse(readFileSync(ruPath, "utf8"));
  const live = (k) => {
    if (oneForms.has(k)) return false;
    const q = JSON.stringify(k);
    return (
      sources.includes(q) ||
      sources.includes(`'${k}'`) ||
      rust.includes(q) ||
      [...prefixes].some((p) => k.startsWith(p))
    );
  };
  const dynamic = Object.keys(ru).filter((k) => !keys.has(k) && live(k));
  const stale = Object.keys(ru).filter((k) => !keys.has(k) && !live(k));
  for (const k of dynamic) keys.add(k);

  const sorted = [...keys].sort((a, b) => a.localeCompare(b, "en"));
  const next =
    JSON.stringify(Object.fromEntries(sorted.map((k) => [k, k])), null, 2) +
    "\n";
  const out = join(app.src, "i18n/en.json");
  const prev = existsSync(out) ? readFileSync(out, "utf8") : "";
  if (check) {
    if (prev !== next) {
      console.error(
        `${app.name}: en.json is out of date, run node scripts/i18n-extract.mjs`,
      );
      failed = true;
    }
    if (stale.length) {
      console.error(
        `${app.name}: ru.json has ${stale.length} stale entries, run node scripts/i18n-extract.mjs --prune`,
      );
      failed = true;
    }
  } else {
    writeFileSync(out, next);
    if (prune && stale.length) {
      for (const k of stale) delete ru[k];
      writeFileSync(ruPath, JSON.stringify(ru, null, 2) + "\n");
    }
  }
  console.log(
    `${app.name}: ${sorted.length} source strings (${dynamic.length} keyed through variables), ${Object.keys(ru).length} ru entries, ${stale.length} stale`,
  );
  if (listStale) for (const k of stale) console.log("  " + JSON.stringify(k));
}
process.exit(failed ? 1 : 0);
