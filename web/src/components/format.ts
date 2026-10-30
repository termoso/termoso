import { activeLocale, tr, trn } from "@/i18n";

const dateFmt = () =>
  new Intl.DateTimeFormat(activeLocale(), { dateStyle: "medium", timeStyle: "short" });
const dayFmt = () => new Intl.DateTimeFormat(activeLocale(), { dateStyle: "medium" });

export function formatDateTime(iso: string | undefined | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : dateFmt().format(d);
}

export function formatDate(iso: string | undefined | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : dayFmt().format(d);
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat(activeLocale()).format(n);
}

const CLOCK_SKEW_MS = 2 * 60_000;

export function formatRelative(iso: string | undefined | null): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  let diff = Date.now() - t;
  // Server timestamps run a few seconds ahead of a browser whose clock lags;
  // a fresh event is "just now", not "in a moment". Real future times
  // (scheduled runs, expiry) are minutes away and keep the future wording.
  if (diff < 0 && diff > -CLOCK_SKEW_MS) diff = 0;
  const future = diff < 0;
  const min = Math.round(Math.abs(diff) / 60_000);
  if (min < 1) return future ? tr("in a moment") : tr("just now");
  if (min < 60)
    return future
      ? trn(min, "in {count} minute", "in {count} minutes")
      : trn(min, "{count} minute ago", "{count} minutes ago");
  const h = Math.round(min / 60);
  if (h < 24)
    return future
      ? trn(h, "in {count} hour", "in {count} hours")
      : trn(h, "{count} hour ago", "{count} hours ago");
  const d = Math.round(h / 24);
  if (d < 30)
    return future
      ? trn(d, "in {count} day", "in {count} days")
      : trn(d, "{count} day ago", "{count} days ago");
  return dayFmt().format(new Date(t));
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} ${tr("B")}`;
  const units = [tr("KB"), tr("MB"), tr("GB"), tr("TB")];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
