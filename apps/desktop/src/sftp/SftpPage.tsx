import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  InputAdornment,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListSubheader,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import AdminPanelSettingsRoundedIcon from "@mui/icons-material/AdminPanelSettingsRounded";
import ArrowDropDownRoundedIcon from "@mui/icons-material/ArrowDropDownRounded";
import FolderCopyRoundedIcon from "@mui/icons-material/FolderCopyRounded";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import SyncRoundedIcon from "@mui/icons-material/SyncRounded";
import { useActiveVault } from "@/app/vault";
import * as ipc from "@/ipc/commands";
import type { Conflict, Direction, FsEntry, HostCard, Uuid } from "@/ipc/types";
import { errorMessage, hasSsh, hasWebDav } from "@/ipc/types";
import { useHosts, useSettings } from "@/ipc/hooks";
import { useSnackbar } from "@/components/Snackbar";
import { IconTile, Toolbar } from "@/components/ui";
import { HostAvatar } from "@/hosts/HostAvatar";
import { useTerminal } from "@/terminal/store";
import { ConflictDialog, type ConflictDecision, type ConflictPrompt } from "./ConflictDialog";
import { FilePane, type PaneKey } from "./FilePane";
import { OpenWithDialog, extensionOf } from "./OpenWithDialog";
import { TransfersPanel } from "./TransfersPanel";
import { SyncBar } from "./SyncBar";
import { SyncDialog } from "./SyncDialog";
import { DiffDialog, type CompareRequest } from "./DiffDialog";
import { dropTargetAt, stageDrop, statPaths } from "./drop";
import { joinPath } from "./format";
import {
  closeSftp,
  connCapabilities,
  editingPaths,
  openEdit,
  openSftpForHost,
  openSftpForHostAsRoot,
  openSftpForSession,
  openSftpOffline,
  openWebDavForHost,
  reconnectSftp,
  setActiveSftp,
  setLeftSource,
  sftpStore,
  startLeftPick,
  startTransfer,
  type SftpConn,
  useSftp,
} from "./store";
import { tr } from "@/i18n";
import { skipToken, useQuery } from "@tanstack/react-query";

interface Planned {
  entry: FsEntry;
  local: string;
  remote: string;
  existing: FsEntry | null;
}

type Source = { kind: "local" } | { kind: "none" } | { kind: "conn"; conn: SftpConn };

interface Batch {
  sftpId: Uuid;
  toSftpId: Uuid | null;
  direction: Direction;
  entries: FsEntry[];
  dest: string;
  temp: boolean;
}

const otherPane = (p: PaneKey): PaneKey => (p === "left" ? "right" : "left");

export function SftpPage() {
  const order = useSftp((s) => s.order);
  const conns = useSftp((s) => s.conns);
  const activeId = useSftp((s) => s.activeId);
  const leftId = useSftp((s) => s.leftId);
  const leftPicking = useSftp((s) => s.leftPicking);
  const active = activeId ? conns[activeId] : undefined;
  const left = leftId ? conns[leftId] : undefined;
  const [leftPath, setLeftPath] = useState<string | null>(null);
  const [rightPath, setRightPath] = useState<string | null>(null);
  const [prompt, setPrompt] = useState<ConflictPrompt | null>(null);
  const [openWith, setOpenWith] = useState<{ pane: PaneKey; entry: FsEntry } | null>(null);
  const [compare, setCompare] = useState<CompareRequest | null>(null);
  const [syncFor, setSyncFor] = useState<Uuid | null>(null);
  const snack = useSnackbar();
  const settings = useSettings();
  const edits = useSftp((s) => s.edits);
  const editList = useMemo(() => Object.values(edits), [edits]);
  /** Batches wait for each other so only one conflict dialog is up at a time. */
  const queue = useRef(Promise.resolve());

  const onLeftPath = useCallback((p: string) => setLeftPath(p), []);
  const onRightPath = useCallback((p: string) => setRightPath(p), []);

  const connOf = (pane: PaneKey): SftpConn | undefined => (pane === "left" ? left : active);
  const sourceOf = (pane: PaneKey): Source => {
    const c = connOf(pane);
    if (c) return { kind: "conn", conn: c };
    return pane === "left" && !leftPicking ? { kind: "local" } : { kind: "none" };
  };
  const ready = (s: Source) =>
    s.kind === "local" || (s.kind === "conn" && s.conn.status === "open");
  const pathOf = (pane: PaneKey) => (pane === "left" ? leftPath : rightPath);
  const oppositePath = (pane: PaneKey) => {
    const o = otherPane(pane);
    return ready(sourceOf(o)) ? pathOf(o) : null;
  };

  const ask = (p: Omit<ConflictPrompt, "resolve">) =>
    new Promise<ConflictDecision | null>((resolve) => {
      setPrompt({
        ...p,
        resolve: (d) => {
          setPrompt(null);
          resolve(d);
        },
      });
    });

  const runBatch = async (b: Batch) => {
    const items: Planned[] = await Promise.all(
      b.entries.map(async (entry) => {
        // Upload: local source → remote destination. Download and relay: the
        // source is `remote`, the destination `local` (a path on the other remote for relays).
        const local = b.direction === "upload" ? entry.path : joinPath(b.dest, entry.name);
        const remote = b.direction === "upload" ? joinPath(b.dest, entry.name) : entry.path;
        const existing = await ipc
          .transferProbe({
            sftpId: b.sftpId,
            toSftpId: b.toSftpId,
            direction: b.direction,
            local,
            remote,
          })
          .catch(() => null);
        return { entry, local, remote, existing };
      }),
    );
    const conflicts = items.flatMap((i) =>
      i.existing ? [{ entry: i.entry, existing: i.existing }] : [],
    );
    const decisions = new Map<string, Conflict>();
    let forAll: Conflict | null = null;
    const destConn = sftpStore.get().conns[b.toSftpId ?? b.sftpId];
    for (const [i, c] of conflicts.entries()) {
      if (forAll) {
        decisions.set(c.entry.path, forAll);
        continue;
      }
      const d = await ask({
        direction: b.direction,
        incoming: c.entry,
        existing: c.existing,
        dest: b.dest,
        resumeUpload: connCapabilities(destConn).resumeUpload,
        remaining: conflicts.length - i - 1,
      });
      if (!d) return false;
      decisions.set(c.entry.path, d.conflict);
      if (d.all) forAll = d.conflict;
    }
    for (const it of items) {
      await startTransfer({
        sftpId: b.sftpId,
        toSftpId: b.toSftpId,
        direction: b.direction,
        local: it.local,
        remote: it.remote,
        conflict: decisions.get(it.entry.path) ?? "replace",
        temp: b.temp,
      });
    }
    return true;
  };

  const enqueue = (batch: Batch, staging?: string) => {
    queue.current = queue.current
      .then(() => runBatch(batch))
      .then(async (started) => {
        if (!started && staging) await ipc.dropAbort(staging);
      })
      .catch((err: unknown) => {
        snack.error(errorMessage(err));
        if (staging) void ipc.dropAbort(staging).catch(() => undefined);
      });
  };

  /** Copy `entries` shown in `from` into the other pane (into `dest` there, or its current directory). */
  const transfer = (from: PaneKey, entries: FsEntry[], dest?: string, staging?: string) => {
    const to = otherPane(from);
    const src = sourceOf(from);
    const dst = sourceOf(to);
    const target = dest ?? pathOf(to);
    const abort = () => {
      if (staging) void ipc.dropAbort(staging).catch(() => undefined);
    };
    if (!ready(src) || !ready(dst) || !target || entries.length === 0) return abort();
    let head: Pick<Batch, "sftpId" | "toSftpId" | "direction">;
    if (src.kind === "local" && dst.kind === "conn")
      head = { sftpId: dst.conn.id, toSftpId: null, direction: "upload" };
    else if (src.kind === "conn" && dst.kind === "local")
      head = { sftpId: src.conn.id, toSftpId: null, direction: "download" };
    else if (src.kind === "conn" && dst.kind === "conn")
      head = { sftpId: src.conn.id, toSftpId: dst.conn.id, direction: "relay" };
    else {
      snack.error(tr("Pick a server on one side first."));
      return abort();
    }
    enqueue({ ...head, entries, dest: target, temp: staging !== undefined }, staging);
  };

  /** Files from the OS dropped into a remote pane: upload them there. */
  const uploadInto = (pane: PaneKey, entries: FsEntry[], dest: string, staging?: string) => {
    const c = connOf(pane);
    if (c?.status !== "open" || entries.length === 0) {
      if (staging) void ipc.dropAbort(staging).catch(() => undefined);
      return;
    }
    enqueue(
      {
        sftpId: c.id,
        toSftpId: null,
        direction: "upload",
        entries,
        dest,
        temp: staging !== undefined,
      },
      staging,
    );
  };

  const receiveFiles = (pane: PaneKey, dt: DataTransfer, dest: string) => {
    stageDrop(dt)
      .then((staged) => {
        if (staged) uploadInto(pane, staged.entries, dest, staged.dir ?? undefined);
      })
      .catch((err: unknown) => snack.error(errorMessage(err)));
  };

  // Native drops (Tauri drag-drop handler) carry real paths and land wherever
  // the cursor is; the pane marks its drop zones with data attributes.
  const onPaths = (pane: PaneKey, paths: string[], dest: string) => {
    statPaths(paths)
      .then((entries) => uploadInto(pane, entries, dest))
      .catch((err: unknown) => snack.error(errorMessage(err)));
  };
  const receivePaths = useRef(onPaths);
  useEffect(() => {
    receivePaths.current = onPaths;
  });
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let alive = true;
    void getCurrentWebview()
      .onDragDropEvent((e) => {
        if (e.payload.type !== "drop" || e.payload.paths.length === 0) return;
        const { x, y } = e.payload.position.toLogical(window.devicePixelRatio);
        const target = dropTargetAt(x, y);
        if (target?.side === "left" || target?.side === "right")
          receivePaths.current(target.side, e.payload.paths, target.dest);
      })
      .then((off) => {
        if (alive) unlisten = off;
        else off();
      })
      .catch(() => undefined);
    return () => {
      alive = false;
      unlisten?.();
    };
  }, []);

  const assoc = useMemo(() => settings.data?.sftpOpenWith ?? {}, [settings.data]);
  const openEntry = (pane: PaneKey, entry: FsEntry, app: string | null) => {
    const c = connOf(pane);
    const run = !c
      ? ipc.localOpen(entry.path, app)
      : c.status === "open"
        ? openEdit(c.id, entry.path, app)
        : Promise.resolve();
    run.catch((err: unknown) => snack.error(errorMessage(err)));
  };
  const onCompare = (pane: PaneKey) => (entry: FsEntry) => {
    const other = oppositePath(pane);
    if (other === null) return;
    const idOf = (p: PaneKey) => {
      if (sourceOf(p).kind === "local") return null;
      const c = connOf(p);
      return c?.status === "open" ? c.id : null;
    };
    setCompare({
      name: entry.name,
      left: { sftpId: idOf(pane), path: entry.path },
      right: { sftpId: idOf(otherPane(pane)), path: joinPath(other, entry.name) },
    });
  };
  const onOpen = (pane: PaneKey) => (entry: FsEntry, mode: "default" | "with") => {
    if (mode === "with") setOpenWith({ pane, entry });
    else openEntry(pane, entry, assoc[extensionOf(entry.name)] ?? null);
  };

  const renderPane = (pane: PaneKey) => {
    const conn = connOf(pane);
    const picking = pane === "left" ? leftPicking && !conn : !conn;
    const src = sourceOf(pane);
    const menu = <SourceMenu pane={pane} current={conn ?? null} />;
    if (src.kind === "local") {
      return (
        <PaneFrame>
          <FilePane
            key="local"
            paneKey={pane}
            side="local"
            title={tr("Local")}
            headerExtra={menu}
            sftpId={null}
            initialPath={null}
            oppositePath={oppositePath(pane)}
            onPathChange={pane === "left" ? onLeftPath : onRightPath}
            onTransfer={(entries) => transfer(pane, entries)}
            onReceive={(entries, dest) => transfer(otherPane(pane), entries, dest)}
            onOpen={onOpen(pane)}
            onCompare={onCompare(pane)}
          />
        </PaneFrame>
      );
    }
    if (conn?.status === "open" && !picking) {
      return (
        <PaneFrame>
          <FilePane
            key={conn.id}
            paneKey={pane}
            side="remote"
            title={conn.title}
            headerExtra={menu}
            sftpId={conn.id}
            capabilities={connCapabilities(conn)}
            initialPath={conn.info?.home ?? null}
            oppositePath={oppositePath(pane)}
            onPathChange={pane === "left" ? onLeftPath : onRightPath}
            onTransfer={(entries) => transfer(pane, entries)}
            onReceive={(entries, dest) => transfer(otherPane(pane), entries, dest)}
            onReceiveFiles={(dt, dest) => receiveFiles(pane, dt, dest)}
            onOpen={onOpen(pane)}
            onCompare={onCompare(pane)}
            editing={editingPaths(editList, conn.id)}
            onClose={() => void closeSftp(conn.id)}
          />
        </PaneFrame>
      );
    }
    const hid = conn?.hostId ?? null;
    return (
      <PaneFrame title={picking ? tr("Remote") : conn?.title} menu={menu}>
        <RemotePlaceholder
          side={pane}
          status={picking ? null : (conn?.status ?? null)}
          webdav={conn?.target.kind === "webdav"}
          message={picking ? null : (conn?.message ?? null)}
          onRetry={conn && !picking ? () => reconnectSftp(conn.id) : undefined}
          onBrowseOffline={
            conn && !picking && hid && conn.target.kind !== "offline"
              ? () => {
                  void closeSftp(conn.id);
                  openSftpOffline(hid, conn.title, pane);
                }
              : undefined
          }
          hostId={conn && !picking ? conn.hostId : null}
        />
      </PaneFrame>
    );
  };

  return (
    <Box sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      {order.length > 0 && (
        <Toolbar>
          <Stack direction="row" spacing={0.75} sx={{ overflowX: "auto", py: 0.5 }}>
            {order.map((id) => {
              const c = conns[id];
              if (!c) return null;
              return (
                <Chip
                  key={id}
                  label={c.title}
                  size="small"
                  variant={id === activeId || id === leftId ? "filled" : "outlined"}
                  color={
                    c.status === "error"
                      ? "error"
                      : id === activeId || id === leftId
                        ? "primary"
                        : "default"
                  }
                  icon={
                    c.status === "connecting" ? (
                      <CircularProgress size={12} sx={{ ml: 0.75 }} />
                    ) : undefined
                  }
                  onClick={() => setActiveSftp(id)}
                  onDelete={() => void closeSftp(id)}
                />
              );
            })}
          </Stack>
          <Box sx={{ flex: 1 }} />
          {active && leftId === null && (
            <Tooltip title={tr("Watch & upload: mirror saves from a local folder to this server")}>
              <IconButton
                size="small"
                aria-label={tr("Watch & upload")}
                onClick={() => setSyncFor(active.id)}
              >
                <SyncRoundedIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </Toolbar>
      )}

      <Stack direction="row" sx={{ flex: 1, minHeight: 0 }}>
        {renderPane("left")}
        <Box sx={{ width: "1px", bgcolor: "border.light", flexShrink: 0 }} />
        {renderPane("right")}
      </Stack>

      <SyncBar />
      <TransfersPanel />
      <ConflictDialog prompt={prompt} />
      <SyncDialog
        key={syncFor ?? ""}
        sftpId={syncFor}
        defaultLocal={leftPath}
        defaultRemote={rightPath}
        onClose={() => setSyncFor(null)}
      />
      <DiffDialog
        key={compare ? `${compare.left.path}|${compare.right.path}` : ""}
        request={compare}
        onClose={() => setCompare(null)}
      />
      <OpenWithDialog
        key={openWith ? `${openWith.pane}:${openWith.entry.path}` : ""}
        entry={openWith?.entry ?? null}
        onCancel={() => setOpenWith(null)}
        onConfirm={(app) => {
          if (openWith) openEntry(openWith.pane, openWith.entry, app);
          setOpenWith(null);
        }}
      />
    </Box>
  );
}

/** Switches what a pane shows: the local disk (left pane), an open connection, or the host picker. */
function SourceMenu({ pane, current }: { pane: PaneKey; current: SftpConn | null }) {
  const order = useSftp((s) => s.order);
  const conns = useSftp((s) => s.conns);
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const close = () => setAnchor(null);
  const choose = (id: Uuid | null) => {
    if (pane === "left") setLeftSource(id);
    else setActiveSftp(id);
    close();
  };
  const pick = () => {
    if (pane === "left") startLeftPick();
    else setActiveSftp(null);
    close();
  };
  const open = order.map((id) => conns[id]).filter((c): c is SftpConn => c !== undefined);
  return (
    <>
      <IconButton
        size="small"
        aria-label={tr("Choose source")}
        onClick={(e) => setAnchor(e.currentTarget)}
        sx={{ ml: 0.25 }}
      >
        <ArrowDropDownRoundedIcon fontSize="small" />
      </IconButton>
      <Menu anchorEl={anchor} open={anchor !== null} onClose={close}>
        {pane === "left" && (
          <MenuItem selected={current === null} onClick={() => choose(null)}>
            {tr("Local")}
          </MenuItem>
        )}
        {open.map((c) => (
          <MenuItem key={c.id} selected={current?.id === c.id} onClick={() => choose(c.id)}>
            {c.title}
          </MenuItem>
        ))}
        {(pane === "left" || open.length > 0) && <Divider />}
        <MenuItem onClick={pick}>{tr("Choose a server…")}</MenuItem>
      </Menu>
    </>
  );
}

function PaneFrame({
  title,
  menu,
  children,
}: {
  title?: string;
  menu?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
      {title && (
        <Box sx={{ px: 1.5, height: 36, display: "flex", alignItems: "center", flexShrink: 0 }}>
          <Typography variant="subtitle2" color="text.secondary" noWrap>
            {title}
          </Typography>
          {menu}
        </Box>
      )}
      <Box sx={{ flex: 1, minHeight: 0 }}>{children}</Box>
    </Box>
  );
}

function RemotePlaceholder({
  side,
  status,
  webdav,
  message,
  onRetry,
  onBrowseOffline,
  hostId,
}: {
  side: PaneKey;
  status: "connecting" | "open" | "error" | "closed" | null;
  webdav?: boolean;
  message: string | null;
  onRetry?: () => void;
  onBrowseOffline?: () => void;
  hostId?: Uuid | null;
}) {
  const offline = useQuery({
    queryKey: ["sftpOffline", hostId],
    queryFn:
      hostId && (status === "error" || status === "closed")
        ? () => ipc.sftpOfflineAvailable(hostId)
        : skipToken,
  });
  return (
    <Stack
      spacing={1.5}
      sx={{ alignItems: "center", justifyContent: "flex-start", height: "100%", p: 3, pt: 6 }}
    >
      {status === "connecting" ? (
        <>
          <CircularProgress size={24} />
          <Typography variant="body2" color="text.secondary">
            {webdav ? tr("Connecting to the WebDAV share…") : tr("Opening SFTP channel…")}
          </Typography>
        </>
      ) : (
        <>
          <IconTile size={48}>
            <FolderCopyRoundedIcon />
          </IconTile>
          <Typography
            variant="body2"
            color={status === "error" ? "error" : "text.secondary"}
            align="center"
          >
            {message ??
              tr("Pick a host, a WebDAV share or an open SSH session to browse its files.")}
          </Typography>
          {onRetry && (status === "error" || status === "closed") && (
            <Button startIcon={<ReplayRoundedIcon />} onClick={onRetry}>
              {tr("Retry")}
            </Button>
          )}
          {onBrowseOffline && offline.data && (status === "error" || status === "closed") && (
            <Button size="small" onClick={onBrowseOffline}>
              {tr("Browse local copies")}
            </Button>
          )}
          {side === "left" && (
            <Button size="small" onClick={() => setLeftSource(null)}>
              {tr("Use local files")}
            </Button>
          )}
          <Box sx={{ width: "100%", maxWidth: 420, minHeight: 0, display: "flex" }}>
            <HostPickerList side={side} />
          </Box>
        </>
      )}
    </Stack>
  );
}

/** Termius-style "Select host" list rendered inside the empty remote pane. */
function HostPickerList({ side }: { side: PaneKey }) {
  const vault = useActiveVault();
  const hosts = useHosts(vault.data?.id ?? null);
  const panes = useTerminal((s) => s.panes);
  const [filter, setFilter] = useState("");
  const [sudoFor, setSudoFor] = useState<HostCard | null>(null);
  const [sudoPassword, setSudoPassword] = useState("");
  const closeSudo = () => {
    setSudoFor(null);
    setSudoPassword("");
  };
  const openAsRoot = () => {
    if (!sudoFor || !sudoPassword) return;
    openSftpForHostAsRoot(sudoFor.id, sudoFor.label, sudoFor.vaultId, sudoPassword, side);
    closeSudo();
  };
  const q = filter.trim().toLowerCase();
  const matches = (h: HostCard) =>
    !q ||
    h.label.toLowerCase().includes(q) ||
    h.address.toLowerCase().includes(q) ||
    (h.webdavUrl ?? "").toLowerCase().includes(q);
  const all = hosts.data ?? [];
  const sshHosts = all.filter((h) => hasSsh(h) && matches(h));
  const davHosts = all.filter((h) => hasWebDav(h) && matches(h));
  const sessions = Object.values(panes).filter(
    (p) => p.protocol === "ssh" && p.status === "connected",
  );
  const pickHost = (h: HostCard, kind: "host" | "webdav") => {
    if (kind === "host") openSftpForHost(h.id, h.label, h.vaultId, side);
    else openWebDavForHost(h.id, h.label, h.vaultId, side);
  };
  const pickSession = (id: Uuid, title: string, hostId: Uuid | null) => {
    openSftpForSession(id, title, hostId, side);
  };
  return (
    <Stack
      sx={{
        flex: 1,
        minHeight: 0,
        borderRadius: 2,
        bgcolor: "surface.high",
        overflow: "hidden",
      }}
    >
      <Box sx={{ p: 1.5, pb: 0.5 }}>
        <TextField
          size="small"
          fullWidth
          placeholder={tr("Search hosts")}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchRoundedIcon fontSize="small" />
                </InputAdornment>
              ),
            },
          }}
        />
      </Box>
      <List dense sx={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {sessions.length > 0 && !q && (
          <>
            <ListSubheader disableSticky>{tr("Open sessions")}</ListSubheader>
            {sessions.map((p) => (
              <ListItemButton key={p.id} onClick={() => pickSession(p.id, p.title, p.hostId)}>
                <ListItemText primary={p.title} secondary={p.subtitle} />
              </ListItemButton>
            ))}
          </>
        )}
        {sshHosts.length > 0 && <ListSubheader disableSticky>SFTP</ListSubheader>}
        {sshHosts.map((h) => (
          <ListItem
            key={h.id}
            disablePadding
            secondaryAction={
              <Tooltip title={tr("Browse as root (sudo)")}>
                <IconButton edge="end" size="small" onClick={() => setSudoFor(h)}>
                  <AdminPanelSettingsRoundedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            }
          >
            <ListItemButton onClick={() => pickHost(h, "host")}>
              <Box sx={{ mr: 1.5 }}>
                <HostAvatar host={h} size={28} />
              </Box>
              <ListItemText primary={h.label} secondary={`${h.username}@${h.address}:${h.port}`} />
            </ListItemButton>
          </ListItem>
        ))}
        <Dialog open={sudoFor !== null} onClose={closeSudo} maxWidth="xs" fullWidth>
          <DialogTitle>{tr("Browse as root")}</DialogTitle>
          <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
            <Typography variant="body2" color="text.secondary">
              {tr(
                "Starts sftp-server through sudo on {host}. The password is sent once over the SSH channel and is not stored.",
                { host: sudoFor?.label ?? "" },
              )}
            </Typography>
            <TextField
              autoFocus
              size="small"
              type="password"
              label={tr("sudo password")}
              value={sudoPassword}
              onChange={(e) => setSudoPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") openAsRoot();
              }}
            />
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={closeSudo}>{tr("Cancel")}</Button>
            <Button variant="contained" onClick={openAsRoot} disabled={!sudoPassword}>
              {tr("Open")}
            </Button>
          </DialogActions>
        </Dialog>
        {davHosts.length > 0 && <ListSubheader disableSticky>{tr("WebDAV")}</ListSubheader>}
        {davHosts.map((h) => (
          <ListItemButton key={`dav-${h.id}`} onClick={() => pickHost(h, "webdav")}>
            <Box sx={{ mr: 1.5 }}>
              <HostAvatar host={h} size={28} />
            </Box>
            <ListItemText primary={h.label} secondary={h.webdavUrl ?? h.address} />
          </ListItemButton>
        ))}
        {sshHosts.length === 0 && davHosts.length === 0 && (
          <Typography variant="body2" color="text.disabled" sx={{ px: 3, py: 2 }}>
            {tr("No SSH or WebDAV hosts saved yet.")}
          </Typography>
        )}
      </List>
    </Stack>
  );
}
