import { useEffect, useState } from "react";
import { Box, Tooltip, Typography } from "@mui/material";
import ArrowDownwardRoundedIcon from "@mui/icons-material/ArrowDownwardRounded";
import ArrowUpwardRoundedIcon from "@mui/icons-material/ArrowUpwardRounded";
import { useSettings } from "@/ipc/hooks";
import * as ipc from "@/ipc/commands";
import type { MonitorSnapshot, Uuid } from "@/ipc/types";
import { monoFontFamily } from "@/theme/theme";
import { tr } from "@/i18n";
import {
  formatKib,
  formatPercent,
  formatRate,
  formatUptime,
  level,
  usedPercent,
  type Level,
} from "./monitorFormat";
import { monitorOn, type Pane } from "./store";
import type { TerminalTheme } from "./themes";

/** Seconds between probes. */
const INTERVAL_MS = 3000;

const LEVEL_COLOR: Record<Level, string> = {
  ok: "#4CAF50",
  warn: "#FFB300",
  crit: "#F44336",
};

type State =
  | { kind: "loading" }
  | { kind: "ok"; snapshot: MonitorSnapshot }
  | { kind: "unsupported" }
  | { kind: "error"; message: string };

/**
 * MobaXterm-style status bar under an SSH terminal: host, CPU, memory, network
 * throughput, uptime, logged-in users and disk usage of the remote machine.
 * Polls only while it is shown, the session is connected and the window is
 * visible, and stops for good when the server has no /proc.
 */
export function MonitorBar({ pane, theme }: { pane: Pane; theme: TerminalTheme }) {
  const settings = useSettings();
  const enabled = monitorOn(pane, settings.data) && pane.status === "connected";
  // Mounted only while enabled, so switching it off (or a reconnect) discards
  // the old numbers and the poller's counters with the component.
  return enabled ? <Poller key={pane.id} id={pane.id} theme={theme} /> : null;
}

function Poller({ id, theme }: { id: Uuid; theme: TerminalTheme }) {
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    let stopped = false;
    // A function, so TypeScript does not treat the flag as constant across awaits.
    const isStopped = () => stopped;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      if (isStopped()) return;
      if (document.visibilityState === "visible") {
        try {
          const reply = await ipc.terminalMonitor(id);
          if (isStopped()) return;
          if (reply.kind === "unsupported") {
            setState({ kind: "unsupported" });
            return; // nothing to poll for
          }
          setState({ kind: "ok", snapshot: reply.snapshot });
        } catch (e) {
          if (isStopped()) return;
          setState({ kind: "error", message: e instanceof Error ? e.message : String(e) });
        }
      }
      timer = setTimeout(() => void tick(), INTERVAL_MS);
    };
    void tick();

    return () => {
      stopped = true;
      clearTimeout(timer);
      ipc.terminalMonitorReset(id).catch(() => undefined);
    };
  }, [id]);

  return (
    <Box
      role="status"
      aria-label={tr("Remote monitoring")}
      sx={{
        flexShrink: 0,
        display: "flex",
        alignItems: "center",
        gap: 2,
        px: 1.5,
        py: 0.5,
        minHeight: 28,
        overflow: "hidden",
        whiteSpace: "nowrap",
        fontFamily: monoFontFamily,
        fontSize: 12,
        color: theme.foreground,
        bgcolor: "rgba(127,127,127,0.14)",
        borderTop: "1px solid rgba(127,127,127,0.25)",
      }}
    >
      {state.kind === "loading" && <Muted>{tr("Reading server load…")}</Muted>}
      {state.kind === "unsupported" && (
        <Muted>{tr("Monitoring needs a Linux server (/proc); this host does not offer it.")}</Muted>
      )}
      {state.kind === "error" && (
        <Muted>{tr("Monitoring unavailable: {message}", { message: state.message })}</Muted>
      )}
      {state.kind === "ok" && <Readout s={state.snapshot} />}
    </Box>
  );
}

function Muted({ children }: { children: string }) {
  return (
    <Typography component="span" sx={{ fontSize: 12, opacity: 0.7, fontFamily: "inherit" }}>
      {children}
    </Typography>
  );
}

function Readout({ s }: { s: MonitorSnapshot }) {
  const mem = usedPercent(s.memUsedKb, s.memTotalKb);
  return (
    <>
      <Tooltip title={tr("Load average: {a} {b} {c}", loadVars(s.load))}>
        <Item label={s.host} strong />
      </Tooltip>
      <Gauge label={tr("CPU")} percent={s.cpuPercent} text={formatPercent(s.cpuPercent)} />
      <Gauge
        label={tr("Mem")}
        percent={mem}
        text={`${formatKib(s.memUsedKb)} / ${formatKib(s.memTotalKb)}`}
      />
      <Item
        icon={<ArrowUpwardRoundedIcon sx={{ fontSize: 14 }} />}
        label={formatRate(s.txBps)}
        title={tr("Upload")}
      />
      <Item
        icon={<ArrowDownwardRoundedIcon sx={{ fontSize: 14 }} />}
        label={formatRate(s.rxBps)}
        title={tr("Download")}
      />
      <Item label={`${tr("up")} ${formatUptime(s.uptimeSecs)}`} title={tr("Uptime")} />
      <Tooltip title={s.users.join(", ") || tr("No logged-in users")}>
        <Item label={`${s.users.length} ${s.users.length === 1 ? tr("user") : tr("users")}`} />
      </Tooltip>
      {s.disks.map((d) => (
        <Gauge
          key={d.mount}
          label={d.mount}
          percent={usedPercent(d.usedKb, d.totalKb)}
          text={`${formatKib(d.usedKb)} / ${formatKib(d.totalKb)}`}
        />
      ))}
    </>
  );
}

function loadVars(load: MonitorSnapshot["load"]) {
  const [a, b, c] = load ?? [0, 0, 0];
  return { a: a.toFixed(2), b: b.toFixed(2), c: c.toFixed(2) };
}

function Item({
  label,
  icon,
  title,
  strong,
  ...rest
}: {
  label: string;
  icon?: React.ReactNode;
  title?: string;
  strong?: boolean;
}) {
  return (
    <Box
      {...rest}
      title={title}
      sx={{
        display: "inline-flex",
        alignItems: "center",
        gap: 0.5,
        fontWeight: strong ? 700 : 400,
        flexShrink: 0,
      }}
    >
      {icon}
      {label}
    </Box>
  );
}

function Gauge({ label, percent, text }: { label: string; percent: number | null; text: string }) {
  const lvl = level(percent);
  return (
    <Box sx={{ display: "inline-flex", alignItems: "center", gap: 0.75, flexShrink: 0 }}>
      <span style={{ opacity: 0.75 }}>{label}</span>
      <Box
        aria-hidden
        sx={{
          width: 46,
          height: 7,
          borderRadius: 4,
          bgcolor: "rgba(127,127,127,0.35)",
          overflow: "hidden",
        }}
      >
        <Box
          sx={{
            width: `${Math.round(percent ?? 0)}%`,
            height: "100%",
            bgcolor: LEVEL_COLOR[lvl],
          }}
        />
      </Box>
      <span>{text}</span>
    </Box>
  );
}
