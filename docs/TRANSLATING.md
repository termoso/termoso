# Translating Termoso

English is the source language and lives in code; Russian ships with every
app. Each app keeps its strings in a Weblate-readable file, so a new language
is a new file plus one line to register it:

| App                   | Source                                             | Translations                        | Format                             |
| --------------------- | -------------------------------------------------- | ----------------------------------- | ---------------------------------- |
| Desktop               | `apps/desktop/src/i18n/en.json` (generated)        | `apps/desktop/src/i18n/<lang>.json` | JSON key-value, key = English text |
| Web cabinet + landing | `web/src/i18n/en.json` (generated)                 | `web/src/i18n/<lang>.json`          | JSON key-value                     |
| Android               | `apps/android/app/src/main/res/values/strings.xml` | `values-<lang>/strings.xml`         | Android resources                  |
| iOS                   | `apps/ios`                                         | not open for translation yet        |                                    |

## Rules

- Keys are the English sentence as written in code (`tr("Save")`). Placeholders
  are `{name}`; keep every placeholder of the source in the translation.
- Plural entries (used with `trn(count, one, other)`) are keyed by the English
  plural form only (`other`; the singular is just the English fallback) and
  list the forms for the language separated by `|`: Russian uses
  `one|few|many`, English `one|other` (order per language is in
  `src/i18n/index.ts`).
- Do not add an entry identical to the source; the desktop tests
  (`apps/desktop/src/i18n/i18n.test.ts`) fail on identity entries and on
  missing placeholders.
- Android strings follow the usual `strings.xml` rules; names stay as in
  `values/strings.xml`.

## Workflow

1. `node scripts/i18n-extract.mjs` regenerates `en.json` for the desktop app and
   the web cabinet from the `tr()` / `trx()` / `msg()` calls and the `other`
   form of `trn()`. Strings keyed through variables (`tr(option.label)`,
   labels sent by the server, `` `perm_group:${g}` ``) are kept as long as the
   key still appears as a literal in the TypeScript sources or the Rust crates;
   `ru.json` entries found nowhere are stale (`--stale` lists them, `--prune`
   deletes them). Commit the regenerated `en.json` together with UI changes;
   `--check` (run in CI) fails when it is out of date or `ru.json` has stale
   entries.
2. Translate in `ru.json` / `strings.xml` directly, or through Weblate once the
   project is registered there: `.weblate` in the repository root describes the
   three components (desktop, web, android) for the hosted instance. Weblate
   commits land as pull requests like any other change.
3. Adding a language: create the file, then register it in
   `apps/desktop/src/i18n/index.ts` / `web/src/i18n/index.ts` (the table lookup
   and the language picker) or `values-<lang>/` for Android.
