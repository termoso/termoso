#!/usr/bin/env node
// Collects every UI string passed to tr() / trx() / trn() in the desktop app
// and the web cabinet into src/i18n/en.json (the Weblate source template,
// key = value = English text), and counts translations with no literal
// source (most are keys passed through variables, e.g. `tr(option.label)`;
// review before deleting). `--check` exits 1 when a committed en.json is out of date.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const apps = [
  { name: "desktop", src: join(root, "apps/desktop/src") },
  { name: "web", src: join(root, "web/src") },
];
const check = process.argv.includes("--check");

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== "node_modules" && e.name !== "i18n" && e.name !== "docs")
        yield* walk(p);
    } else if (/\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name)) yield p;
  }
}

// A JS string literal: "…" or '…' with escapes; template literals are skipped
// (they carry runtime values and are not translation keys).
const LIT = String.raw`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`;
const CALL = new RegExp(
  String.raw`\btr[xn]?\(\s*(?:[^,()]+,\s*)?(?:${LIT})(?:\s*,\s*(?:${LIT}))?`,
  "g",
);
const unescape = (s) =>
  JSON.parse('"' + s.replace(/\\'/g, "'").replace(/"/g, '\\"') + '"');

let failed = false;
for (const app of apps) {
  const keys = new Set();
  for (const file of walk(app.src)) {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(CALL)) {
      const isTrn = m[0].startsWith("trn(");
      const first = m[1] ?? m[2];
      const second = m[3] ?? m[4];
      if (first !== undefined) keys.add(unescape(first));
      // trn(count, one, other): both forms are keys (`other` indexes the table).
      if (isTrn && second !== undefined) keys.add(unescape(second));
    }
  }
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
  } else {
    writeFileSync(out, next);
  }
  const ru = JSON.parse(readFileSync(join(app.src, "i18n/ru.json"), "utf8"));
  const stale = Object.keys(ru).filter((k) => !keys.has(k));
  console.log(
    `${app.name}: ${sorted.length} source strings, ${Object.keys(ru).length} ru entries, ${stale.length} ru entries without a literal source (keys passed through variables are not seen)`,
  );
  if (process.argv.includes("--stale"))
    for (const k of stale) console.log("  " + JSON.stringify(k));
}
process.exit(failed ? 1 : 0);
