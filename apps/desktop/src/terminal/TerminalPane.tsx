import { useEffect, useRef, useState } from "react";
import { Box, Button, IconButton, Stack, Tooltip, Typography, alpha } from "@mui/material";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import KeyboardAltRoundedIcon from "@mui/icons-material/KeyboardAltRounded";
import CampaignRoundedIcon from "@mui/icons-material/CampaignRounded";
import MoreHorizRoundedIcon from "@mui/icons-material/MoreHorizRounded";
import VerticalSplitRoundedIcon from "@mui/icons-material/VerticalSplitRounded";
import HorizontalSplitRoundedIcon from "@mui/icons-material/HorizontalSplitRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import type { SshAlgorithms, Uuid } from "@/ipc/types";
import { isPostQuantumKex } from "@/ipc/types";
import { useHosts } from "@/ipc/hooks";
import { ActionMenu, type MenuAction } from "@/components/ui";
import { HostGlyph } from "@/hosts/HostAvatar";
import {
  closePane,
  focusPane,
  mountPane,
  openTerminal,
  reconnectPane,
  setActivePane,
  splitActivePane,
  toggleBroadcast,
  useTerminal,
  type Pane,
} from "./store";
import { AutocompletePopup } from "./AutocompletePopup";
import { ConnectionView } from "./ConnectionView";
import { usePaneTheme } from "./useTerminalTheme";
import { dismissControlHint, useMultiplayer } from "./multiplayer";
import type { TerminalTheme } from "./themes";
import { tr } from "@/i18n";
import { TypingBadge } from "./TypingBadge";
import { ZmodemBar } from "./ZmodemBar";
import { MonitorBar } from "./MonitorBar";

interface Props {
  paneId: Uuid;
  active: boolean;
  showFrame: boolean;
}

export function TerminalPane({ paneId, active, showFrame }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const pane = useTerminal((s) => s.panes[paneId]);
  const queued = useTerminal((s) => s.reconnect?.paneIds.includes(paneId) ?? false);
  const theme = usePaneTheme(paneId);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    return mountPane(paneId, host);
  }, [paneId]);

  const status = pane?.status;
  useEffect(() => {
    if (active && status !== "connecting") focusPane(paneId);
  }, [active, paneId, status]);

  if (!pane) return null;
  const finished = pane.status === "exited" || pane.status === "error" || pane.status === "closed";
  // Never got a session: show the connection view with the failure instead of
  // an empty terminal. A dropped session keeps its buffer while it reconnects.
  const failedToConnect =
    finished && pane.startedAt === null && pane.status !== "exited" && !pane.reconnecting;
  const connecting = pane.status === "connecting" && !pane.reconnecting;

  return (
    <Box
      onMouseDown={() => setActivePane(paneId)}
      sx={{
        position: "relative",
        flex: 1,
        minWidth: 0,
        minHeight: 0,
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        bgcolor: theme.background,
        borderRadius: 2,
        overflow: "hidden",
        boxShadow: showFrame
          ? active
            ? "0 0 0 1px var(--mui-palette-primary-main)"
            : "0 0 0 1px var(--mui-palette-border-light)"
          : "none",
        transition: "box-shadow 120ms",
      }}
    >
      {showFrame && <PaneHeader pane={pane} active={active} theme={theme} />}
      <Box sx={{ flex: 1, minHeight: 0, position: "relative", display: "flex" }}>
        <Box
          ref={hostRef}
          sx={{
            flex: 1,
            minWidth: 0,
            minHeight: 0,
            position: "relative",
            visibility: connecting || failedToConnect ? "hidden" : "visible",
          }}
        />
        <AutocompletePopup paneId={paneId} />
        <RemoteControlHint paneId={paneId} />
        <TypingBadge paneId={paneId} />
        <ZmodemBar paneId={paneId} />
        {(connecting || failedToConnect) && <ConnectionView pane={pane} />}
      </Box>

      <MonitorBar pane={pane} theme={theme} />

      {finished && !failedToConnect && !queued && (
        <Overlay theme={theme} dim>
          <Typography
            variant="body2"
            color={pane.status === "error" ? "error" : "inherit"}
            sx={{ opacity: pane.status === "error" ? 1 : 0.8 }}
          >
            {pane.message ?? tr("Session ended")}
          </Typography>
          <Stack direction="row" spacing={1}>
            {pane.target.kind !== "live" && (
              <Button
                size="small"
                variant="contained"
                startIcon={<ReplayRoundedIcon />}
                onClick={() => void reconnectPane(paneId)}
              >
                {tr("Reconnect")}
              </Button>
            )}
            <Button
              size="small"
              color="inherit"
              startIcon={<CloseRoundedIcon />}
              onClick={() => void closePane(paneId)}
            >
              {tr("Close")}
            </Button>
          </Stack>
        </Overlay>
      )}
    </Box>
  );
}

/**
 * Termius-style pane header in a split: host icon, title, address, and the
 * pane's actions (broadcast, more, close).
 */
function PaneHeader({
  pane,
  active,
  theme,
}: {
  pane: Pane;
  active: boolean;
  theme: TerminalTheme;
}) {
  const hosts = useHosts(null);
  const tab = useTerminal((s) => s.tabs.find((t) => t.paneIds.includes(pane.id)));
  const [menu, setMenu] = useState<HTMLElement | null>(null);
  const host = pane.hostId ? hosts.data?.find((h) => h.id === pane.hostId) : undefined;
  if (!tab) return null;
  const split = (direction: "row" | "column") => {
    setActivePane(pane.id);
    splitActivePane(tab.id, direction);
  };
  const items: MenuAction[] = [
    {
      label: tr("Split right"),
      icon: <VerticalSplitRoundedIcon fontSize="small" />,
      onClick: () => split("row"),
    },
    {
      label: tr("Split down"),
      icon: <HorizontalSplitRoundedIcon fontSize="small" />,
      divider: true,
      onClick: () => split("column"),
    },
    {
      label: tr("Duplicate session"),
      icon: <ContentCopyRoundedIcon fontSize="small" />,
      divider: true,
      onClick: () => openTerminal(pane.target),
    },
    {
      label: tr("Close"),
      icon: <CloseRoundedIcon fontSize="small" />,
      danger: true,
      onClick: () => void closePane(pane.id),
    },
  ];
  const iconSx = {
    width: 22,
    height: 22,
    color: "inherit",
    opacity: 0.7,
    "&:hover": { opacity: 1, bgcolor: alpha(theme.foreground, 0.1) },
    "& svg": { fontSize: 15 },
  };
  return (
    <Stack
      direction="row"
      spacing={0.75}
      sx={{
        alignItems: "center",
        pl: 1,
        pr: 0.5,
        height: 28,
        flexShrink: 0,
        color: theme.foreground,
        bgcolor: alpha(theme.foreground, active ? 0.06 : 0.035),
        opacity: active ? 1 : 0.75,
        "& .pane-actions": { opacity: active ? 1 : 0, transition: "opacity 120ms" },
        "&:hover .pane-actions": { opacity: 1 },
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", "& svg": { fontSize: 14 } }}>
        {pane.protocol === "local" ? (
          <StatusDot status={pane.status} />
        ) : (
          <HostGlyph osName={host?.osName} icon={host?.icon} protocol={pane.protocol ?? "ssh"} />
        )}
      </Box>
      <Typography variant="caption" noWrap sx={{ fontWeight: 600 }}>
        {pane.title}
      </Typography>
      <Typography variant="caption" noWrap sx={{ opacity: 0.55, flex: 1, minWidth: 0 }}>
        {pane.subtitle}
      </Typography>
      <PqBadge algorithms={pane.algorithms} size={13} />
      <Stack direction="row" className="pane-actions" sx={{ alignItems: "center", gap: 0.25 }}>
        {tab.paneIds.length > 1 && (
          <Tooltip
            title={tab.broadcast ? tr("Broadcast input: on") : tr("Broadcast input to all panes")}
          >
            <IconButton
              size="small"
              aria-label={tr("Broadcast input to all panes")}
              aria-pressed={tab.broadcast}
              onClick={() => toggleBroadcast(tab.id)}
              sx={{ ...iconSx, ...(tab.broadcast ? { opacity: 1, color: "primary.main" } : {}) }}
            >
              <CampaignRoundedIcon />
            </IconButton>
          </Tooltip>
        )}
        <IconButton
          size="small"
          aria-label={tr("Pane actions")}
          aria-haspopup="menu"
          onClick={(e) => setMenu(e.currentTarget)}
          sx={iconSx}
        >
          <MoreHorizRoundedIcon />
        </IconButton>
        <IconButton
          size="small"
          aria-label={tr("Close")}
          onClick={() => void closePane(pane.id)}
          sx={iconSx}
        >
          <CloseRoundedIcon />
        </IconButton>
      </Stack>
      <ActionMenu anchor={menu} onClose={() => setMenu(null)} items={items} />
    </Stack>
  );
}

/** Termius-style "You've got remote control" hint on a multiplayer viewer pane. */
function RemoteControlHint({ paneId }: { paneId: Uuid }) {
  const shown = useMultiplayer((s) => s.controlHint === paneId);
  useEffect(() => {
    if (!shown) return;
    const t = setTimeout(dismissControlHint, 8_000);
    return () => clearTimeout(t);
  }, [shown]);
  if (!shown) return null;
  return (
    <Stack
      direction="row"
      spacing={1}
      onClick={dismissControlHint}
      sx={{
        position: "absolute",
        top: 12,
        left: 16,
        zIndex: 2,
        alignItems: "center",
        px: 1.5,
        height: 36,
        borderRadius: 1.5,
        cursor: "pointer",
        color: "info.main",
        bgcolor: (t) => alpha(t.palette.info.main, 0.12),
        border: "1px solid",
        borderColor: "info.main",
        backdropFilter: "blur(6px)",
      }}
    >
      <KeyboardAltRoundedIcon sx={{ fontSize: 16 }} />
      <Typography variant="body2" sx={{ fontWeight: 500 }}>
        {tr("You've got remote control. Start typing.")}
      </Typography>
    </Stack>
  );
}

function Overlay({
  children,
  theme,
  dim,
}: {
  children: React.ReactNode;
  theme: TerminalTheme;
  dim?: boolean;
}) {
  return (
    <Stack
      spacing={1.5}
      sx={{
        alignItems: "center",
        justifyContent: "flex-end",
        position: "absolute",
        inset: 0,
        zIndex: 6,
        pb: 4,
        color: theme.foreground,
        pointerEvents: dim ? "auto" : "none",
        background: dim
          ? `linear-gradient(to bottom, transparent 40%, ${alpha(theme.background, 0.92)})`
          : "transparent",
      }}
    >
      {children}
    </Stack>
  );
}

export function algorithmsSummary(a: SshAlgorithms): string {
  return tr("KEX {kex}\nHost key {hostKey}\nCipher {cipher}\nMAC {mac}", {
    kex: a.kex,
    hostKey: a.hostKey,
    cipher: a.cipher,
    mac: a.mac,
  });
}

/** Shield shown when the session negotiated a post-quantum key exchange. */
export function PqBadge({ algorithms, size }: { algorithms: SshAlgorithms | null; size: number }) {
  if (!algorithms || !isPostQuantumKex(algorithms)) return null;
  return (
    <Tooltip
      title={
        <Box sx={{ whiteSpace: "pre-line" }}>
          {tr("Quantum-safe key exchange") + "\n" + algorithmsSummary(algorithms)}
        </Box>
      }
    >
      <ShieldRoundedIcon sx={{ fontSize: size, color: "primary.main" }} />
    </Tooltip>
  );
}

export function StatusDot({ status }: { status: string }) {
  const color =
    status === "connected"
      ? "success.main"
      : status === "connecting"
        ? "warning.main"
        : status === "error"
          ? "error.main"
          : "text.disabled";
  return <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: color, flexShrink: 0 }} />;
}
