import { useEffect, useRef, useState, type DragEvent } from "react";
import { createPortal } from "react-dom";
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
  mergeInto,
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
import { tr, trn } from "@/i18n";
import { useSnackbar } from "@/components/Snackbar";
import { MAX_PANES, nearestSide, type DropSide } from "./layout";
import {
  hideDockPreview,
  setSessionDrag,
  showDockPreview,
  useDockPreview,
  useSessionDrag,
} from "./dragState";
import { TypingBadge } from "./TypingBadge";
import { ZmodemBar } from "./ZmodemBar";

interface Props {
  paneId: Uuid;
}

/**
 * One session's terminal. Rendered once per pane by `PaneLayer` and moved
 * between layout slots, so docking or detaching never rebuilds it.
 */
export function TerminalPane({ paneId }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const tab = useTerminal((s) => s.tabs.find((t) => t.paneIds.includes(paneId)));
  const active = tab?.activePaneId === paneId;
  // Panes of a split are framed (with a header); a list-mode pane stands alone.
  const showFrame = tab !== undefined && tab.viewMode !== "list" && tab.paneIds.length > 1;
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
      <DockOverlay paneId={paneId} />
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

const PANE_MIME = "application/x-termoso-pane";

/**
 * While a tab or another pane is being dragged, covers this pane with drop
 * zones: the nearest edge shows where the dragged session will dock.
 */
function DockOverlay({ paneId }: { paneId: Uuid }) {
  const drag = useSessionDrag();
  const tab = useTerminal((s) => s.tabs.find((t) => t.paneIds.includes(paneId)));
  const incoming = useTerminal((s) => {
    if (!drag) return 0;
    if (drag.kind === "pane") return 1;
    return s.tabs.find((t) => t.id === drag.id)?.paneIds.length ?? 0;
  });
  const snackbar = useSnackbar();
  if (!drag || !tab) return null;
  if (drag.kind === "tab" && drag.id === tab.id) return null;
  if (drag.kind === "pane" && drag.id === paneId) return null;
  const sameTab = drag.kind === "pane" && tab.paneIds.includes(drag.id);
  const full = !sameTab && tab.paneIds.length + incoming > MAX_PANES;
  return (
    <Box
      onDragOver={(e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = full ? "none" : "move";
        showDockPreview({ rect: dockTargetAt(e).rect, full });
      }}
      onDragLeave={hideDockPreview}
      onDrop={(e) => {
        e.preventDefault();
        const at = dockTargetAt(e);
        hideDockPreview();
        const result = mergeInto(drag, tab.id, paneId, at.side, at.scope);
        if (result === "full") {
          snackbar.notify(
            trn(
              MAX_PANES,
              "A window holds up to {count} session",
              "A window holds up to {count} sessions",
            ),
          );
        }
      }}
      sx={{ position: "absolute", inset: 0, zIndex: 30 }}
    ></Box>
  );
}

/** The one docking preview: glides between zones and fades in and out. Mount once. */
export function DockPreviewLayer() {
  const { preview, last: at, slide } = useDockPreview();
  const shown = preview !== null;
  if (!at) return null;
  return createPortal(
    <Box
      sx={{
        position: "fixed",
        ...at.rect,
        zIndex: 1500,
        borderRadius: 1.5,
        pointerEvents: "none",
        opacity: shown ? 1 : 0,
        bgcolor: (t) => alpha(at.full ? t.palette.error.main : t.palette.primary.main, 0.22),
        border: 2,
        borderColor: at.full ? "error.main" : "primary.main",
        transition: slide
          ? "left 140ms cubic-bezier(0.2, 0.8, 0.2, 1), top 140ms cubic-bezier(0.2, 0.8, 0.2, 1), width 140ms cubic-bezier(0.2, 0.8, 0.2, 1), height 140ms cubic-bezier(0.2, 0.8, 0.2, 1), opacity 120ms"
          : "opacity 120ms",
      }}
    />,
    document.body,
  );
}

interface DockTarget {
  side: DropSide;
  /** `window`: along the whole window's edge; `pane`: beside this pane only. */
  scope: "pane" | "window";
  /** Viewport rectangle of the half that the docked session will take. */
  rect: { left: number; top: number; width: number; height: number };
}

const EDGE_SLACK = 12;

/**
 * Where a drag over a pane would dock. When the nearest edge is also an edge of
 * the window, the session docks along the whole window (and previews half of
 * it); an edge shared with a neighbouring pane docks beside this pane only.
 */
function dockTargetAt(e: DragEvent<HTMLElement>): DockTarget {
  const pane = e.currentTarget.getBoundingClientRect();
  const side = nearestSide(
    (e.clientX - pane.left) / pane.width,
    (e.clientY - pane.top) / pane.height,
  );
  const rootEl = e.currentTarget.closest("[data-dock-root]");
  let box = pane;
  let scope: "pane" | "window" = "pane";
  if (rootEl) {
    const r = rootEl.getBoundingClientRect();
    const pad = parseFloat(getComputedStyle(rootEl).paddingLeft) || 0;
    const root = new DOMRect(r.left + pad, r.top + pad, r.width - 2 * pad, r.height - 2 * pad);
    const onEdge =
      (side === "left" && Math.abs(pane.left - root.left) <= EDGE_SLACK) ||
      (side === "right" && Math.abs(pane.right - root.right) <= EDGE_SLACK) ||
      (side === "up" && Math.abs(pane.top - root.top) <= EDGE_SLACK) ||
      (side === "down" && Math.abs(pane.bottom - root.bottom) <= EDGE_SLACK);
    if (onEdge) {
      box = root;
      scope = "window";
    }
  }
  const w = box.width / 2;
  const h = box.height / 2;
  const rect =
    side === "left"
      ? { left: box.left, top: box.top, width: w, height: box.height }
      : side === "right"
        ? { left: box.left + w, top: box.top, width: w, height: box.height }
        : side === "up"
          ? { left: box.left, top: box.top, width: box.width, height: h }
          : { left: box.left, top: box.top + h, width: box.width, height: h };
  return { side, scope, rect };
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
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData(PANE_MIME, pane.id);
        e.dataTransfer.setData("text/plain", pane.title);
        e.dataTransfer.effectAllowed = "move";
        setSessionDrag({ kind: "pane", id: pane.id });
      }}
      sx={{
        alignItems: "center",
        cursor: "grab",
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
