import { Box, Divider, IconButton, Tooltip, Typography, alpha, keyframes } from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import AddBoxRoundedIcon from "@mui/icons-material/AddBoxRounded";
import UsbRoundedIcon from "@mui/icons-material/UsbRounded";
import VerticalSplitRoundedIcon from "@mui/icons-material/VerticalSplitRounded";
import HorizontalSplitRoundedIcon from "@mui/icons-material/HorizontalSplitRounded";
import CampaignRoundedIcon from "@mui/icons-material/CampaignRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import FolderCopyRoundedIcon from "@mui/icons-material/FolderCopyRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import DeleteSweepRoundedIcon from "@mui/icons-material/DeleteSweepRounded";
import ViewSidebarRoundedIcon from "@mui/icons-material/ViewSidebarRounded";
import GridViewRoundedIcon from "@mui/icons-material/GridViewRounded";
import ViewListRoundedIcon from "@mui/icons-material/ViewListRounded";
import DriveFileRenameOutlineRoundedIcon from "@mui/icons-material/DriveFileRenameOutlineRounded";
import BookmarkAddedRoundedIcon from "@mui/icons-material/BookmarkAddedRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import { Fragment, type DragEvent, type MouseEvent, type ReactNode } from "react";
import type { HostCard, Uuid } from "@/ipc/types";
import { PqBadge, StatusDot } from "@/terminal/TerminalPane";
import { dragStore, setSessionDrag, useSessionDrag, type SessionDrag } from "@/terminal/dragState";
import { MAX_PANES } from "@/terminal/layout";
import { MultiplayerTabButton } from "@/terminal/MultiplayerControl";
import {
  HOME_TAB,
  clearBuffer,
  closeTab,
  isWorkspaceTab,
  mergeInto,
  moveTab,
  movePaneToNewTab,
  openTerminal,
  renameTab,
  resetZoom,
  setActiveTab,
  closeOtherTabs,
  setSearchOpen,
  splitActivePane,
  tabTitle,
  terminalStore,
  toggleBroadcast,
  toggleSidePanel,
  toggleTabViewMode,
  useTerminal,
  type TerminalTab,
} from "@/terminal/store";
import { addToWorkspace, saveTabAsTemplate, useWorkspaces } from "@/terminal/workspaces";
import { MIME as HOST_MIME, droppedHostIds, isHostDrag, parseDragData } from "@/hosts/dnd";
import { ActionMenu, InlineName, type MenuAction } from "@/components/ui";
import { useSnackbar } from "@/components/Snackbar";
import { openSftpForSession, useSftp } from "@/sftp/store";
import { useHosts } from "@/ipc/hooks";
import { DistroGlyph, hostIcon } from "@/hosts/HostAvatar";
import { sizes } from "@/theme/theme";
import {
  NEW_TAB,
  SERIAL_TAB,
  SFTP_TAB,
  goHome,
  goToNewTab,
  goToSerial,
  goToSftp,
} from "./navigation";
import { AppMenuButton } from "./AppMenu";
import { TeamBlock } from "./TeamBlock";
import { WindowControls } from "./WindowControls";
import { VaultMenu, useActiveVault } from "./vault";
import { IS_MAC, MAC_TRAFFIC_LIGHTS_WIDTH } from "@/lib/platform";
import { withHint } from "./shortcuts";
import { useEffect, useState } from "react";
import { tr, trn } from "@/i18n";

/**
 * Persistent top strip, doubling as the window title bar (the native frame is
 * off): Vaults · SFTP · terminal tabs · [+]  ……  pane tools · avatar + team ·
 * window controls. Empty space drags the window; double-click toggles maximize.
 * On macOS the native traffic lights overlay the left edge and the window
 * buttons on the right are the system's, so neither is drawn here.
 */
export function TopBar() {
  const tabs = useTerminal((s) => s.tabs);
  const activeTabId = useTerminal((s) => s.activeTabId);
  const sftpCount = useSftp((s) => s.order.length);
  const active = tabs.find((t) => t.id === activeTabId);
  const [dragging, setDragging] = useState<string | null>(null);
  // A pane dragged out of a split is over free tab-strip space: preview its new tab there.
  const sessionDrag = useSessionDrag();
  /** Where the detached pane's tab would land: before this tab id (`null` = at the end). */
  const [ghostAt, setGhostAt] = useState<{
    beforeId: string | null;
    drag: SessionDrag | null;
  } | null>(null);
  // Tied to the drag that set it, so a stale spot never shows in the next drag.
  const setGhost = (at: { beforeId: string | null } | null) =>
    setGhostAt(at && { ...at, drag: dragStore.get().drag });
  const ghost = ghostAt?.drag === sessionDrag ? ghostAt : null;
  const draggedPaneTitle = useTerminal((s) =>
    sessionDrag?.kind === "pane" ? (s.panes[sessionDrag.id]?.title ?? null) : null,
  );
  const showGhost = sessionDrag?.kind === "pane" && ghost !== null;
  const ghostTab = (
    <Box
      aria-hidden
      sx={{
        display: "flex",
        alignItems: "center",
        alignSelf: "center",
        height: 30,
        px: 1.25,
        mx: 0.25,
        maxWidth: 220,
        flexShrink: 0,
        borderRadius: 1.5,
        border: "1.5px dashed var(--mui-palette-primary-main)",
        bgcolor: (t) => alpha(t.palette.primary.main, 0.14),
        color: "text.primary",
        pointerEvents: "none",
        transformOrigin: "left center",
        animation: `${ghostIn} 150ms cubic-bezier(0.2, 0.8, 0.2, 1)`,
      }}
    >
      <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
        {draggedPaneTitle ?? tr("New Tab")}
      </Typography>
    </Box>
  );
  const [newWorkspaceOver, mountNewWorkspaceDrop] = useHostDropNewWorkspace();
  const vault = useActiveVault();
  const [vaultMenu, setVaultMenu] = useState<HTMLElement | null>(null);
  const multiVault = vault.vaults.length > 1;

  return (
    <Box
      data-tauri-drag-region
      sx={{
        display: "flex",
        alignItems: "stretch",
        height: sizes.topbar,
        flexShrink: 0,
        bgcolor: "surface.lowest",
        borderBottom: 1,
        borderColor: "border.light",
        pl: IS_MAC ? `${MAC_TRAFFIC_LIGHTS_WIDTH}px` : 1,
        userSelect: "none",
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", pr: 0.5 }}>
        <AppMenuButton />
      </Box>
      <TopTab
        active={activeTabId === HOME_TAB}
        onClick={() => setActiveTab(HOME_TAB)}
        icon={<LockRoundedIcon sx={{ fontSize: 16 }} />}
        label={tr("Vaults")}
        trailing={
          multiVault ? (
            <Tooltip
              title={
                vault.data ? tr("Vault: {name}", { name: vault.data.name }) : tr("Switch vault")
              }
            >
              <IconButton
                aria-label={tr("Switch vault")}
                aria-haspopup="menu"
                aria-expanded={vaultMenu !== null}
                onClick={(e) => {
                  e.stopPropagation();
                  setVaultMenu(e.currentTarget);
                }}
                sx={{ width: 22, height: 22, mr: -0.5, color: "inherit" }}
              >
                <ExpandMoreRoundedIcon
                  sx={{
                    fontSize: 18,
                    transition: "transform 120ms",
                    transform: vaultMenu ? "rotate(180deg)" : "none",
                  }}
                />
              </IconButton>
            </Tooltip>
          ) : null
        }
      />
      <VaultMenu anchor={vaultMenu} onClose={() => setVaultMenu(null)} />
      <TopTab
        active={activeTabId === SFTP_TAB}
        onClick={goToSftp}
        icon={<FolderCopyRoundedIcon sx={{ fontSize: 16 }} />}
        label={sftpCount > 0 ? tr("SFTP ({sftpCount})", { sftpCount }) : "SFTP"}
      />
      {tabs.length > 0 && <Divider orientation="vertical" flexItem sx={{ my: 1.25, mx: 0.5 }} />}
      <Box
        data-tauri-drag-region
        // A pane dragged out of a split and dropped on free space becomes its own tab.
        onDragOver={(e) => {
          if (dragStore.get().drag?.kind !== "pane") return;
          e.preventDefault();
          e.dataTransfer.dropEffect = "move";
          // Over a tab, that tab reports the spot; free space means the end of the strip.
          const onTab = e.target instanceof Element && e.target.closest('[role="tab"]') !== null;
          if (!onTab) setGhost({ beforeId: null });
        }}
        onDragLeave={(e) => {
          if (!(e.relatedTarget instanceof Node) || !e.currentTarget.contains(e.relatedTarget)) {
            setGhost(null);
          }
        }}
        onDrop={(e) => {
          setGhost(null);
          const sd = dragStore.get().drag;
          if (e.defaultPrevented || sd?.kind !== "pane") return;
          e.preventDefault();
          movePaneToNewTab(sd.id, null);
        }}
        sx={{
          flex: 1,
          minWidth: 0,
          display: "flex",
          alignItems: "stretch",
          overflowX: "auto",
          "&::-webkit-scrollbar": { height: 0 },
        }}
      >
        {tabs.map((t) => (
          <Fragment key={t.id}>
            {showGhost && ghost.beforeId === t.id && ghostTab}
            <TerminalTopTab
              tab={t}
              active={t.id === activeTabId}
              dragging={dragging}
              onDragState={setDragging}
              onGhost={setGhost}
            />
          </Fragment>
        ))}
        {showGhost && ghost.beforeId === null && ghostTab}
        {activeTabId === NEW_TAB && (
          <TopTab
            active
            onClick={goToNewTab}
            onClose={goHome}
            icon={<AddBoxRoundedIcon sx={{ fontSize: 16 }} />}
            label={tr("New Tab")}
          />
        )}
        {activeTabId === SERIAL_TAB && (
          <TopTab
            active
            onClick={goToSerial}
            onClose={goHome}
            icon={<UsbRoundedIcon sx={{ fontSize: 16 }} />}
            label={tr("Serial")}
          />
        )}
        <Box
          ref={mountNewWorkspaceDrop}
          sx={{
            alignSelf: "center",
            mx: 0.5,
            borderRadius: "50%",
            boxShadow: newWorkspaceOver
              ? "inset 0 0 0 1.5px var(--mui-palette-primary-main)"
              : "none",
            bgcolor: newWorkspaceOver ? "action.selected" : undefined,
          }}
        >
          <Tooltip title={tr("New tab")}>
            <IconButton
              onClick={goToNewTab}
              sx={{ width: 28, height: 28 }}
              aria-label={tr("New tab")}
            >
              <AddRoundedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>
      {active && <PaneTools tab={active} />}
      <Box sx={{ display: "flex", alignItems: "center", pl: 0.5, pr: 1 }}>
        {active && <Divider orientation="vertical" flexItem sx={{ my: 1.25, mr: 1 }} />}
        <TeamBlock />
      </Box>
      {!IS_MAC && <WindowControls />}
    </Box>
  );
}

function PaneTools({ tab }: { tab: TerminalTab }) {
  const sidePanel = useTerminal((s) => s.sidePanel);
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 0.25, px: 1 }}>
      {tab.zoom !== 1 && (
        <Tooltip title={withHint(tr("Reset zoom"), "term.zoomReset")}>
          <Box
            component="button"
            onClick={() => resetZoom(tab.id)}
            sx={{
              all: "unset",
              cursor: "pointer",
              px: 0.75,
              height: 20,
              mr: 0.5,
              borderRadius: 1,
              fontSize: 11,
              fontWeight: 600,
              color: "text.secondary",
              bgcolor: "action.selected",
              "&:hover": { color: "text.primary" },
            }}
          >
            {Math.round(tab.zoom * 100)}%
          </Box>
        </Tooltip>
      )}
      <Tooltip
        title={withHint(tr("Side panel: snippets, history, themes, info"), "term.sidePanel")}
      >
        <IconButton
          onClick={() => toggleSidePanel()}
          sx={sidePanel ? { color: "text.primary", bgcolor: "action.selected" } : undefined}
        >
          <ViewSidebarRoundedIcon fontSize="small" />
        </IconButton>
      </Tooltip>
    </Box>
  );
}

const TAB_MIME = "application/x-termoso-tab";

const ghostIn = keyframes`
  from { opacity: 0; transform: scaleX(0.6); }
  to { opacity: 1; transform: scaleX(1); }
`;

/** Where a drag hovers a tab: reorder before / after it, or drop hosts into it. */
type DropSide = "before" | "after" | "into" | null;

/** Workspace tabs are terminals, so WebDAV-only hosts are left out. */
const hostTargets = (ids: Uuid[], hosts: readonly HostCard[] | undefined) =>
  ids
    .map((id) => hosts?.find((h) => h.id === id))
    .filter((h): h is HostCard => h !== undefined && h.protocol !== "webdav")
    .map((h) => ({ kind: "host" as const, host_id: h.id, vault_id: h.vaultId }));

function TerminalTopTab({
  tab,
  active,
  dragging,
  onDragState,
  onGhost,
}: {
  tab: TerminalTab;
  active: boolean;
  /** Id of the tab currently being dragged, if any. */
  dragging: string | null;
  onDragState: (id: string | null) => void;
  /** A pane being dragged out would become a tab before `beforeId` (`null` = the end); `null` = nowhere. */
  onGhost: (at: { beforeId: string | null } | null) => void;
}) {
  const pane = useTerminal((s) => s.panes[tab.activePaneId]);
  const title = useTerminal((s) => tabTitle(tab, s));
  const tabs = useTerminal((s) => s.tabs);
  const hosts = useHosts(null);
  const snackbar = useSnackbar();
  const templateName = useWorkspaces(
    (s) => s.templates.find((t) => t.id === tab.templateId)?.name ?? null,
  );
  const [over, setOver] = useState<DropSide>(null);
  const [menu, setMenu] = useState<{ left: number; top: number } | null>(null);
  const [renaming, setRenaming] = useState(false);
  if (!pane) return null;
  const paneHost = pane.hostId ? hosts.data?.find((h) => h.id === pane.hostId) : null;
  const distro = pane.status === "connected" ? hostIcon(paneHost) : null;
  const workspace = isWorkspaceTab(tab);

  const canSftp = pane.protocol === "ssh" && pane.status === "connected";
  const menuItems: MenuAction[] = [
    {
      label: tr("Split right"),
      icon: <VerticalSplitRoundedIcon fontSize="small" />,
      onClick: () => splitActivePane(tab.id, "row"),
    },
    {
      label: tr("Split down"),
      icon: <HorizontalSplitRoundedIcon fontSize="small" />,
      onClick: () => splitActivePane(tab.id, "column"),
    },
    {
      label: tab.viewMode === "split" ? tr("Show as list") : tr("Show side by side"),
      icon:
        tab.viewMode === "split" ? (
          <ViewListRoundedIcon fontSize="small" />
        ) : (
          <GridViewRoundedIcon fontSize="small" />
        ),
      disabled: tab.paneIds.length < 2 && tab.viewMode === "split",
      onClick: () => toggleTabViewMode(tab.id),
    },
    {
      label: tab.broadcast ? tr("Broadcast input: on") : tr("Broadcast input to all panes"),
      icon: <CampaignRoundedIcon fontSize="small" />,
      disabled: tab.paneIds.length < 2,
      divider: true,
      onClick: () => toggleBroadcast(tab.id),
    },
    {
      label: tr("Duplicate session"),
      icon: <ContentCopyRoundedIcon fontSize="small" />,
      onClick: () => openTerminal(pane.target),
    },
    {
      label: tr("Rename"),
      icon: <DriveFileRenameOutlineRoundedIcon fontSize="small" />,
      onClick: () => setRenaming(true),
    },
    {
      label: tr("Open SFTP for this connection"),
      icon: <FolderCopyRoundedIcon fontSize="small" />,
      disabled: !canSftp,
      onClick: () => {
        openSftpForSession(pane.id, pane.title, pane.hostId);
        goToSftp();
      },
    },
    {
      label: tr("Find"),
      icon: <SearchRoundedIcon fontSize="small" />,
      onClick: () => {
        setActiveTab(tab.id);
        setSearchOpen(true);
      },
    },
    {
      label: tr("Clear buffer"),
      icon: <DeleteSweepRoundedIcon fontSize="small" />,
      onClick: () => clearBuffer(tab.activePaneId),
    },
    {
      label: templateName
        ? tr("Save to “{templateName}”", { templateName })
        : tr("Save as workspace template"),
      icon: <BookmarkAddedRoundedIcon fontSize="small" />,
      divider: true,
      onClick: () => {
        const tpl = saveTabAsTemplate(tab.id);
        if (tpl) snackbar.notify(tr("Workspace “{name}” saved", { name: tpl.name }));
      },
    },
    {
      label: tr("Close others"),
      icon: <CloseRoundedIcon fontSize="small" />,
      disabled: tabs.length < 2,
      onClick: () => closeOtherTabs(tab.id),
    },
    {
      label: workspace ? tr("Close workspace") : tr("Close"),
      icon: <CloseRoundedIcon fontSize="small" />,
      onClick: () => closeTab(tab.id),
    },
  ];

  const onContextMenu = (e: MouseEvent<HTMLElement>) => {
    e.preventDefault();
    setMenu({ left: e.clientX, top: e.clientY });
  };

  /**
   * Dropping on a tab reorders as it always did: before or after, by which half. Holding
   * Shift docks the dragged session into this tab's window instead.
   */
  const zone = (e: DragEvent<HTMLElement>): "before" | "after" | "into" => {
    if (e.shiftKey) return "into";
    const r = e.currentTarget.getBoundingClientRect();
    return e.clientX < r.left + r.width / 2 ? "before" : "after";
  };
  const nextTabId = () => {
    const all = terminalStore.get().tabs;
    return all[all.findIndex((t) => t.id === tab.id) + 1]?.id ?? null;
  };
  const drag = {
    draggable: true,
    onDragStart: (e: DragEvent<HTMLElement>) => {
      e.dataTransfer.setData(TAB_MIME, tab.id);
      e.dataTransfer.effectAllowed = "move";
      onDragState(tab.id);
      setSessionDrag({ kind: "tab", id: tab.id });
    },
    onDragEnd: () => {
      onDragState(null);
      setOver(null);
    },
    onDragOver: (e: DragEvent<HTMLElement>) => {
      if (isHostDrag(e)) {
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        setOver("into");
        return;
      }
      const sd = dragStore.get().drag;
      if (sd?.kind === "pane") {
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        const where = zone(e);
        // Shift: docks into this tab (outlined). Otherwise a ghost tab shows the new spot.
        setOver(where === "into" ? "into" : null);
        onGhost(
          where === "into"
            ? null
            : { beforeId: where === "before" ? tab.id : (nextTabId() ?? null) },
        );
        return;
      }
      if (!dragging || dragging === tab.id) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      setOver(zone(e));
    },
    onDragLeave: () => {
      setOver(null);
      onGhost(null);
    },
    onDrop: (e: DragEvent<HTMLElement>) => {
      setOver(null);
      onGhost(null);
      const dropped = droppedHostIds(e);
      if (dropped.length > 0) {
        e.preventDefault();
        const targets = hostTargets(dropped, hosts.data);
        const added =
          targets.length > 0 &&
          addToWorkspace({ kind: "tab", id: tab.id, name: tab.name ?? "" }, targets, true);
        if (added) {
          const where = workspace ? `“${tab.name}”` : title;
          snackbar.notify(
            targets.length === 1
              ? tr("Opened in {where}", { where })
              : tr("Opened {length} hosts in {where}", { length: targets.length, where }),
          );
        }
        return;
      }
      const where = zone(e);
      const full = () =>
        snackbar.notify(
          trn(
            MAX_PANES,
            "A window holds up to {count} session",
            "A window holds up to {count} sessions",
          ),
        );
      const sd = dragStore.get().drag;
      if (sd?.kind === "pane") {
        // A pane dragged out of a split: dock it here, or make it a tab at this spot.
        e.preventDefault();
        if (where === "into") {
          if (mergeInto(sd, tab.id, tab.activePaneId, "right") === "full") full();
        } else {
          movePaneToNewTab(sd.id, where === "before" ? tab.id : nextTabId());
        }
        return;
      }
      const id = e.dataTransfer.getData(TAB_MIME) || dragging;
      if (!id || id === tab.id) return;
      e.preventDefault();
      if (where === "into") {
        // Drop one session tab onto another: they share a window, split side by side.
        if (mergeInto({ kind: "tab", id }, tab.id, tab.activePaneId, "right") === "full") full();
      } else if (where === "before") moveTab(id, tab.id);
      else moveTab(id, nextTabId());
    },
  };

  return (
    <>
      <TopTab
        active={active}
        drag={drag}
        dropSide={over}
        faded={dragging === tab.id}
        fluid
        onClick={() => setActiveTab(tab.id)}
        onDoubleClick={() => setRenaming(true)}
        onContextMenu={onContextMenu}
        onMiddleClick={() => closeTab(tab.id)}
        icon={
          workspace ? (
            <GridViewRoundedIcon sx={{ fontSize: 16 }} />
          ) : pane.protocol === "local" ? (
            <TerminalRoundedIcon sx={{ fontSize: 16 }} />
          ) : distro ? (
            <DistroGlyph icon={distro} sx={{ fontSize: 15 }} />
          ) : (
            <StatusDot status={pane.status} />
          )
        }
        label={title}
        editor={
          renaming ? (
            <InlineName
              value={tab.name ?? title}
              placeholder={tr("Workspace name")}
              onCommit={(name) => {
                setRenaming(false);
                renameTab(tab.id, name.trim() ? name : tab.name);
              }}
              onCancel={() => setRenaming(false)}
              sx={{ width: 140 }}
            />
          ) : null
        }
        trailing={
          !workspace && tab.paneIds.length === 1 ? (
            <>
              <PqBadge algorithms={pane.algorithms} size={13} />
              {active && pane.status === "connected" && <MultiplayerTabButton paneId={pane.id} />}
            </>
          ) : null
        }
        onClose={() => closeTab(tab.id)}
      />
      <ActionMenu position={menu} anchor={null} onClose={() => setMenu(null)} items={menuItems} />
    </>
  );
}

interface TopTabProps {
  active: boolean;
  icon: ReactNode;
  label: string;
  /** Replaces the label while a rename is in progress. */
  editor?: ReactNode;
  trailing?: ReactNode;
  onClick: () => void;
  onDoubleClick?: () => void;
  onContextMenu?: (e: MouseEvent<HTMLElement>) => void;
  onClose?: () => void;
  onMiddleClick?: () => void;
  /** HTML5 drag handlers for reorderable tabs. */
  drag?: Partial<DragHandlers> & { draggable?: boolean };
  dropSide?: DropSide;
  faded?: boolean;
  /** Session tabs: start at full width and shrink as more open; others fit their content. */
  fluid?: boolean;
}

interface DragHandlers {
  onDragStart: (e: DragEvent<HTMLElement>) => void;
  onDragEnd: () => void;
  onDragOver: (e: DragEvent<HTMLElement>) => void;
  onDragLeave: () => void;
  onDrop: (e: DragEvent<HTMLElement>) => void;
}

/** Drop hosts on a non-terminal tab or the “+” button to open them as a new workspace. */
/**
 * Native drag listeners for the "+" button: a host dropped there opens in a new
 * workspace. Bound directly because WebKitGTK delivers the drag events to the
 * icon inside the button, where React's delegated handlers never saw them.
 */
function useHostDropNewWorkspace() {
  const [over, setOver] = useState(false);
  const [el, setEl] = useState<HTMLDivElement | null>(null);
  const snackbar = useSnackbar();
  const hostCards = useHosts(null).data;
  useEffect(() => {
    if (!el) return;
    const hosts = (e: globalThis.DragEvent) =>
      Array.from(e.dataTransfer?.types ?? []).includes(HOST_MIME);
    const onDragOver = (e: globalThis.DragEvent) => {
      if (!hosts(e) || !e.dataTransfer) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      setOver(true);
    };
    const onDragLeave = (e: globalThis.DragEvent) => {
      if (e.relatedTarget instanceof Node && el.contains(e.relatedTarget)) return;
      setOver(false);
    };
    const onDrop = (e: globalThis.DragEvent) => {
      setOver(false);
      if (!hosts(e) || !e.dataTransfer) return;
      const ids = parseDragData(e.dataTransfer.getData(HOST_MIME))?.ids ?? [];
      if (ids.length === 0) return;
      e.preventDefault();
      const targets = hostTargets(ids, hostCards);
      if (targets.length > 0 && addToWorkspace(null, targets)) {
        snackbar.notify(
          targets.length === 1
            ? tr("Opened in a new workspace")
            : tr("Opened {length} hosts in a new workspace", { length: targets.length }),
        );
      }
    };
    el.addEventListener("dragenter", onDragOver);
    el.addEventListener("dragover", onDragOver);
    el.addEventListener("dragleave", onDragLeave);
    el.addEventListener("drop", onDrop);
    return () => {
      el.removeEventListener("dragenter", onDragOver);
      el.removeEventListener("dragover", onDragOver);
      el.removeEventListener("dragleave", onDragLeave);
      el.removeEventListener("drop", onDrop);
    };
  }, [el, snackbar, hostCards]);
  return [over, setEl] as const;
}

function TopTab({
  active,
  icon,
  label,
  editor,
  trailing,
  onClick,
  onDoubleClick,
  onContextMenu,
  onClose,
  onMiddleClick,
  drag,
  dropSide,
  faded,
  fluid,
}: TopTabProps) {
  return (
    <Tooltip title={editor ? "" : label} enterDelay={0} enterNextDelay={0} placement="bottom">
      <Box
        role="tab"
        aria-selected={active}
        onClick={onClick}
        onDoubleClick={onDoubleClick}
        onContextMenu={onContextMenu}
        onAuxClick={(e) => {
          if (e.button === 1) onMiddleClick?.();
        }}
        {...drag}
        sx={{
          display: "flex",
          alignItems: "center",
          alignSelf: "center",
          gap: 0.75,
          height: 30,
          pl: 1.25,
          pr: onClose ? 0.5 : 1.25,
          mx: 0.25,
          // Chrome-style: every tab shrinks evenly as more open, the label
          // truncates, and the close button always stays inside the tab.
          flex: fluid ? "0 1 220px" : "0 0 auto",
          minWidth: fluid ? (active ? 84 : 52) : 0,
          maxWidth: 220,
          borderRadius: 1.5,
          cursor: "default",
          opacity: faded ? 0.4 : 1,
          boxShadow:
            dropSide === "before"
              ? "-2px 0 0 0 var(--mui-palette-primary-main)"
              : dropSide === "after"
                ? "2px 0 0 0 var(--mui-palette-primary-main)"
                : dropSide === "into"
                  ? "inset 0 0 0 1.5px var(--mui-palette-primary-main)"
                  : "none",
          bgcolor:
            dropSide === "into" ? "action.selected" : active ? "surface.highest" : "transparent",
          color: active ? "text.primary" : "text.secondary",
          "&:hover": {
            bgcolor: active ? "surface.highest" : "action.hover",
            color: "text.primary",
          },
          "&:hover .tab-close": { opacity: 1 },
          "& > svg": { color: active ? "text.primary" : "text.secondary" },
        }}
      >
        {icon}
        {editor ?? (
          <Typography
            variant="body2"
            noWrap
            sx={{ fontWeight: 500, flex: "1 1 auto", minWidth: 0 }}
          >
            {label}
          </Typography>
        )}
        {trailing}
        {onClose && (
          <IconButton
            className="tab-close"
            onClick={(e) => {
              e.stopPropagation();
              onClose();
            }}
            sx={{ opacity: active ? 0.7 : 0, width: 20, height: 20, ml: 0.25, flexShrink: 0 }}
            aria-label={tr("Close {label}", { label })}
          >
            <CloseRoundedIcon sx={{ fontSize: 14 }} />
          </IconButton>
        )}
      </Box>
    </Tooltip>
  );
}
