import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatKib,
  formatPercent,
  formatRate,
  formatUptime,
  level,
  usedPercent,
} from "./monitorFormat";

describe("monitorFormat", () => {
  it("formats bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(15 * 1024 * 1024)).toBe("15 MB");
    expect(formatBytes(-5)).toBe("0 B");
    expect(formatKib(16318464)).toBe("16 GB");
  });
  it("formats rates and percents, with a placeholder before the second probe", () => {
    expect(formatRate(2048)).toBe("2.0 KB/s");
    expect(formatRate(null)).toBe("…");
    expect(formatPercent(12.4)).toBe("12%");
    expect(formatPercent(null)).toBe("…");
  });
  it("formats uptime", () => {
    expect(formatUptime(59)).toBe("0m");
    expect(formatUptime(7 * 60)).toBe("7m");
    expect(formatUptime(3 * 3600 + 5 * 60)).toBe("3h 5m");
    expect(formatUptime(93784)).toBe("1d 2h");
  });
  it("computes used share and colour level", () => {
    expect(usedPercent(50, 200)).toBe(25);
    expect(usedPercent(5, 0)).toBe(0);
    expect(usedPercent(500, 200)).toBe(100);
    expect(level(null)).toBe("ok");
    expect(level(69.9)).toBe("ok");
    expect(level(70)).toBe("warn");
    expect(level(90)).toBe("crit");
  });
});
