import { useEffect } from "react";
import { Box, IconButton, Tooltip, Typography } from "@mui/material";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import { SplitView } from "./SplitView";
import { StatusDot } from "./TerminalPane";
import { PaneSlot } from "./PaneHost";
import { TerminalSidePanel } from "./TerminalSidePanel";
import { closePane, focusPane, setActivePane, useTerminal } from "./store";
import { HostAvatar } from "@/hosts/HostAvatar";
import { IconTile } from "@/components/ui";
import { useHosts } from "@/ipc/hooks";
import type { Uuid } from "@/ipc/types";
import { tr } from "@/i18n";

interface Props {
  tabId: string;
}

/**
 * Panes of one tab — side by side as nested resizable splits, or (workspace
 * list mode) one at a time with a session list on the left — plus the side panel.
 */
export function TerminalWorkspace({ tabId }: Props) {
  const tab = useTerminal((s) => s.tabs.find((t) => t.id === tabId));
  const visible = useTerminal((s) => s.activeTabId === tabId);
  const activePaneId = tab?.activePaneId;

  useEffect(() => {
    if (visible && activePaneId) focusPane(activePaneId);
  }, [visible, activePaneId]);

  if (!tab) return null;
  const list = tab.viewMode === "list";
  const single = list || (tab.focused && tab.paneIds.length > 1);

  return (
    <Box sx={{ flex: 1, minHeight: 0, display: "flex" }}>
      {list && <SessionList paneIds={tab.paneIds} activePaneId={tab.activePaneId} />}
      <Box
        data-dock-root
        sx={{ position: "relative", flex: 1, minWidth: 0, minHeight: 0, display: "flex", p: 0.75 }}
      >
        {single ? (
          <PaneSlot key={tab.activePaneId} paneId={tab.activePaneId} />
        ) : (
          <SplitView
            tabId={tabId}
            node={tab.layout}
            activePaneId={tab.activePaneId}
            showFrame={tab.paneIds.length > 1}
          />
        )}
      </Box>
      <TerminalSidePanel tab={tab} />
    </Box>
  );
}

/** Left column of a list-mode workspace: one row per session. */
function SessionList({ paneIds, activePaneId }: { paneIds: Uuid[]; activePaneId: Uuid }) {
  return (
    <Box
      component="nav"
      aria-label={tr("Sessions")}
      sx={{
        width: 224,
        flexShrink: 0,
        display: "flex",
        flexDirection: "column",
        bgcolor: "surface.base",
        borderRight: 1,
        borderColor: "border.light",
        overflowY: "auto",
        py: 0.75,
        px: 0.75,
        gap: 0.25,
      }}
    >
      {paneIds.map((id) => (
        <SessionRow key={id} paneId={id} active={id === activePaneId} />
      ))}
    </Box>
  );
}

function SessionRow({ paneId, active }: { paneId: Uuid; active: boolean }) {
  const pane = useTerminal((s) => s.panes[paneId]);
  const hosts = useHosts(null);
  if (!pane) return null;
  const host = pane.hostId ? hosts.data?.find((h) => h.id === pane.hostId) : undefined;
  const subtitle =
    pane.protocol === "local"
      ? tr("Local terminal")
      : (host?.address ?? (pane.target.kind === "quick" ? pane.target.address : ""));
  return (
    <Box
      role="button"
      tabIndex={0}
      onClick={() => setActivePane(paneId)}
      onKeyDown={(e) => {
        if (e.key === "Enter") setActivePane(paneId);
      }}
      sx={{
        display: "flex",
        alignItems: "center",
        gap: 1,
        px: 1,
        height: 44,
        borderRadius: 1.5,
        cursor: "default",
        bgcolor: active ? "surface.highest" : "transparent",
        "&:hover": { bgcolor: active ? "surface.highest" : "action.hover" },
        "&:hover .row-close": { opacity: 1 },
      }}
    >
      {host ? (
        <HostAvatar host={host} size={28} />
      ) : (
        <IconTile size={28}>
          {pane.protocol === "local" ? (
            <TerminalRoundedIcon sx={{ fontSize: 16 }} />
          ) : (
            <DnsRoundedIcon sx={{ fontSize: 16 }} />
          )}
        </IconTile>
      )}
      <Box sx={{ minWidth: 0, flex: 1 }}>
        <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
          {pane.title}
        </Typography>
        <Typography variant="caption" noWrap sx={{ color: "text.secondary", display: "block" }}>
          {subtitle}
        </Typography>
      </Box>
      <StatusDot status={pane.status} />
      <Tooltip title={tr("Close session")}>
        <IconButton
          className="row-close"
          onClick={(e) => {
            e.stopPropagation();
            void closePane(paneId);
          }}
          sx={{ width: 22, height: 22, opacity: 0, ml: 0.25 }}
          aria-label={tr("Close {title}", { title: pane.title })}
        >
          <CloseRoundedIcon sx={{ fontSize: 14 }} />
        </IconButton>
      </Tooltip>
    </Box>
  );
}
