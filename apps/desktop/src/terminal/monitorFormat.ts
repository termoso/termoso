// Formatting for the remote monitor bar. Pure, so it is unit-tested.

const UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/** `1536` → `1.5 KB`; one decimal below 10, none above. */
export function formatBytes(bytes: number): string {
  let v = Math.max(0, bytes);
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) {
    v /= 1024;
    u++;
  }
  const digits = v < 10 && u > 0 ? 1 : 0;
  return `${v.toFixed(digits)} ${UNITS[u]}`;
}

/** KiB → bytes-style text: `16318464` → `15.6 GB`. */
export function formatKib(kib: number): string {
  return formatBytes(kib * 1024);
}

/** Bytes per second → `12 KB/s`. */
export function formatRate(bps: number | null): string {
  return bps === null ? "…" : `${formatBytes(bps)}/s`;
}

/** Seconds since boot → `1d 2h`, `3h 5m`, `7m`. */
export function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** Share in percent, rounded; `null` while only one probe exists. */
export function formatPercent(p: number | null): string {
  return p === null ? "…" : `${Math.round(p)}%`;
}

/** Used / total share, 0–100. */
export function usedPercent(used: number, total: number): number {
  return total > 0 ? Math.min(100, Math.max(0, (used / total) * 100)) : 0;
}

export type Level = "ok" | "warn" | "crit";

/** Colour band for a percentage gauge. */
export function level(percent: number | null): Level {
  if (percent === null || percent < 70) return "ok";
  return percent < 90 ? "warn" : "crit";
}
