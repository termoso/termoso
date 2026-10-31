import type { ReactNode } from "react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
  type MouseEvent,
} from "react";
import { copyToClipboard } from "@/lib/clipboard";
import {
  Box,
  Button,
  CircularProgress,
  Divider,
  InputBase,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TableSortLabel,
  Tooltip,
  Typography,
} from "@mui/material";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import ArrowForwardRoundedIcon from "@mui/icons-material/ArrowForwardRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import CreateNewFolderRoundedIcon from "@mui/icons-material/CreateNewFolderRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import VisibilityOffRoundedIcon from "@mui/icons-material/VisibilityOffRounded";
import SelectAllRoundedIcon from "@mui/icons-material/SelectAllRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import InsertDriveFileOutlinedIcon from "@mui/icons-material/InsertDriveFileOutlined";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import DriveFileRenameOutlineRoundedIcon from "@mui/icons-material/DriveFileRenameOutlineRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import UploadRoundedIcon from "@mui/icons-material/UploadRounded";
import DifferenceRoundedIcon from "@mui/icons-material/DifferenceRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import AppsRoundedIcon from "@mui/icons-material/AppsRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as ipc from "@/ipc/commands";
import type { FsEntry, Listing, RemoteCapabilities, Uuid } from "@/ipc/types";
import { SFTP_CAPABILITIES, errorMessage } from "@/ipc/types";
import { useSnackbar } from "@/components/Snackbar";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ToolIconButton } from "@/components/ui";
import { monoFontFamily, sizes } from "@/theme/theme";
import { ChmodDialog, NameDialog } from "./dialogs";
import { DROP_DEST_ATTR, DROP_SIDE_ATTR, PANE_MIME, hasOsFiles } from "./drop";
import {
  formatMtime,
  formatSize,
  isBrokenLink,
  isDirLike,
  isHidden,
  joinPath,
  kindLabel,
  sortEntries,
  type Sort,
  type SortKey,
  formatMode,
} from "./format";
import { fsQueryKey } from "./store";
import { tr, trn, msg } from "@/i18n";

export type Side = "local" | "remote";

/** Payload of a drag that started in a pane. */
interface DragPayload {
  side: Side;
  entries: FsEntry[];
}

export type PaneKey = "left" | "right";
const otherKey = (k: PaneKey): PaneKey => (k === "left" ? "right" : "left");
const mimeFor = (key: PaneKey) => `${PANE_MIME}-${key}`;

interface Props {
  side: Side;
  /** Which pane this is; drags are accepted only from the other one. */
  paneKey: PaneKey;
  /** Pane heading: `Local` or the host's title. */
  title: string;
  /** Rendered right after the heading (source switcher). */
  headerExtra?: ReactNode;
  /** Remote connection; `null` for the local side. */
  sftpId: Uuid | null;
  /** What the remote side supports; unsupported actions are not offered. */
  capabilities?: RemoteCapabilities;
  /** Directory to start in; `null` = home. */
  initialPath: string | null;
  /** Current directory of the opposite pane (transfer destination). */
  oppositePath: string | null;
  onPathChange: (path: string) => void;
  /** Send entries of this pane to the opposite pane's current directory. */
  onTransfer: (entries: FsEntry[]) => void;
  /** Entries dragged over from the opposite pane and dropped on `dest`. */
  onReceive: (entries: FsEntry[], dest: string) => void;
  /** Files dropped from the OS onto `dest` (remote side only). */
  onReceiveFiles?: (dt: DataTransfer, dest: string) => void;
  /** Open a file locally (`with` asks for the application first). */
  onOpen: (entry: FsEntry, mode: "default" | "with") => void;
  /** Diff a file against the one of the same name in the opposite pane. */
  onCompare?: (entry: FsEntry) => void;
  /** Paths currently open for editing (remote side). */
  editing?: ReadonlySet<string>;
  /** Actions → Close; closes the connection behind a remote pane. */
  onClose?: () => void;
  disabled?: boolean;
}

interface FsApi {
  list: (path: string | null) => Promise<Listing>;
  mkdir: (path: string) => Promise<null>;
  rename: (from: string, to: string) => Promise<null>;
  remove: (path: string, recursive: boolean) => Promise<null>;
  chmod: ((path: string, mode: number) => Promise<null>) | null;
}

function apiFor(side: Side, sftpId: Uuid | null, caps: RemoteCapabilities): FsApi {
  if (side === "remote" && sftpId) {
    return {
      list: (p) => ipc.sftpList(sftpId, p),
      mkdir: (p) => ipc.sftpMkdir(sftpId, p),
      rename: (a, b) => ipc.sftpRename(sftpId, a, b),
      remove: (p, r) => ipc.sftpRemove(sftpId, p, r),
      chmod: caps.permissions ? (p, m) => ipc.sftpChmod(sftpId, p, m) : null,
    };
  }
  return {
    list: ipc.localList,
    mkdir: ipc.localMkdir,
    rename: ipc.localRename,
    remove: ipc.localRemove,
    chmod: null,
  };
}

type Dialog =
  | { kind: "mkdir" }
  | { kind: "rename"; entry: FsEntry }
  | { kind: "delete"; entries: FsEntry[] }
  | { kind: "chmod"; entry: FsEntry }
  | null;

const COLUMNS: { key: SortKey; label: string; width?: number; align?: "right" }[] = [
  { key: "name", label: msg("Name") },
  { key: "mtime", label: msg("Date Modified"), width: 140 },
  { key: "size", label: msg("Size"), width: 84, align: "right" },
  { key: "kind", label: msg("Kind"), width: 96 },
];

/** `/a/b/c` → `[{label: "/", path: "/"}, {label: "a", path: "/a"}, …]`; Windows drives keep their root. */
function crumbsOf(path: string): { label: string; path: string }[] {
  const win = /^[A-Za-z]:[\\/]/.test(path);
  const sep = win ? "\\" : "/";
  const parts = path.split(/[\\/]+/).filter((p) => p.length > 0);
  if (win) {
    const root = `${parts[0] ?? ""}${sep}`;
    let acc = root;
    return [
      { label: root, path: root },
      ...parts.slice(1).map((p) => {
        acc = acc.endsWith(sep) ? acc + p : `${acc}${sep}${p}`;
        return { label: p, path: acc };
      }),
    ];
  }
  let acc = "";
  return [
    { label: "/", path: "/" },
    ...parts.map((p) => {
      acc = `${acc}/${p}`;
      return { label: p, path: acc };
    }),
  ];
}

export function FilePane(props: Props) {
  const {
    side,
    paneKey,
    headerExtra,
    title,
    sftpId,
    capabilities = SFTP_CAPABILITIES,
    initialPath,
    oppositePath,
    onPathChange,
    onTransfer,
    onReceive,
    onReceiveFiles,
    onOpen,
    onCompare,
    editing,
    onClose,
    disabled = false,
  } = props;
  const api = useMemo(() => apiFor(side, sftpId, capabilities), [side, sftpId, capabilities]);
  const [path, setPath] = useState<string | null>(initialPath);
  /** Text of the path field while it is being edited; `null` = breadcrumbs. */
  const [pathDraft, setPathDraft] = useState<string | null>(null);
  /** Inline name filter; `null` = closed. */
  const [filter, setFilter] = useState<string | null>(null);
  const [sort, setSort] = useState<Sort>({ key: "name", dir: "asc" });
  const [showHidden, setShowHidden] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [menu, setMenu] = useState<{ x: number; y: number; entry: FsEntry | null } | null>(null);
  const [actionsAnchor, setActionsAnchor] = useState<HTMLElement | null>(null);
  const [drivesAnchor, setDrivesAnchor] = useState<HTMLElement | null>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  /** Visited directories for Back / Forward. */
  const [history, setHistory] = useState<{ stack: string[]; idx: number }>({ stack: [], idx: -1 });
  const viaHistory = useRef(false);
  /** Directory a drag is currently hovering (pane root or a folder row). */
  const [dropOver, setDropOver] = useState<string | null>(null);
  const dragDepth = useRef(0);
  const qc = useQueryClient();
  const snack = useSnackbar();

  const listing = useQuery({
    queryKey: fsQueryKey(side, sftpId, path),
    queryFn: () => api.list(path),
    enabled: !disabled,
    staleTime: 5_000,
  });

  const drives = useQuery({
    queryKey: ["localDrives"],
    queryFn: ipc.localDrives,
    enabled: side === "local",
    staleTime: 60_000,
  });
  // The query cache is shared by both panes; only the local side may offer drives.
  const driveList = side === "local" ? (drives.data ?? []) : [];

  const resolvedPath = listing.data?.path ?? null;
  useEffect(() => {
    if (resolvedPath === null) return;
    onPathChange(resolvedPath);
    if (viaHistory.current) {
      viaHistory.current = false;
      return;
    }
    setHistory((h) => {
      if (h.stack[h.idx] === resolvedPath) return h;
      const stack = [...h.stack.slice(0, h.idx + 1), resolvedPath];
      return { stack, idx: stack.length - 1 };
    });
  }, [resolvedPath, onPathChange]);

  const entries = useMemo(() => {
    const all = listing.data?.entries ?? [];
    const visible = showHidden ? all : all.filter((e) => !isHidden(e));
    const needle = filter?.trim().toLowerCase() ?? "";
    const matched = needle ? visible.filter((e) => e.name.toLowerCase().includes(needle)) : visible;
    return sortEntries(matched, sort);
  }, [listing.data, showHidden, filter, sort]);

  const navigate = useCallback((next: string | null) => {
    setPath(next);
    setPathDraft(null);
    setFilter(null);
    setSelected(new Set());
  }, []);

  const step = (delta: number) => {
    const idx = history.idx + delta;
    const target = history.stack[idx];
    if (target === undefined) return;
    viaHistory.current = true;
    setHistory((h) => ({ ...h, idx }));
    navigate(target);
  };

  const toggleSort = (key: SortKey) =>
    setSort((s) =>
      s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" },
    );

  const selectAll = () => setSelected(new Set(entries.map((e) => e.path)));

  const refresh = () => void qc.invalidateQueries({ queryKey: fsQueryKey(side, sftpId, path) });

  const mutate = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => {
      setDialog(null);
      setSelected(new Set());
      refresh();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  const selectedEntries = entries.filter((e) => selected.has(e.path));

  const onRowClick = (e: MouseEvent, entry: FsEntry) => {
    setSelected((prev) => {
      if (e.ctrlKey || e.metaKey) {
        const next = new Set(prev);
        if (next.has(entry.path)) next.delete(entry.path);
        else next.add(entry.path);
        return next;
      }
      if (e.shiftKey && prev.size > 0) {
        const idx = entries.findIndex((x) => x.path === entry.path);
        const anchor = entries.findIndex((x) => prev.has(x.path));
        const [a, b] = idx < anchor ? [idx, anchor] : [anchor, idx];
        return new Set(entries.slice(a, b + 1).map((x) => x.path));
      }
      return new Set([entry.path]);
    });
  };

  const openEntry = (entry: FsEntry) => {
    if (isDirLike(entry)) navigate(entry.path);
    else if (isBrokenLink(entry))
      snack.error(
        tr(
          'Cannot open "{name}": this symbolic link is broken or points to something that no longer exists',
          { name: entry.name },
        ),
      );
    else if (entry.kind === "other")
      snack.error(tr('Cannot open "{name}": not a regular file', { name: entry.name }));
    else onOpen(entry, "default");
  };

  // ── drag & drop ──
  const canReceive = !disabled && oppositePath !== null;
  const accepts = (dt: DataTransfer) =>
    canReceive &&
    (Array.from(dt.types).includes(mimeFor(otherKey(paneKey))) ||
      (onReceiveFiles !== undefined && hasOsFiles(dt)));

  const osZone = canReceive && onReceiveFiles !== undefined;
  const dropZoneAttrs = (dest: string) => ({
    [DROP_SIDE_ATTR]: paneKey,
    [DROP_DEST_ATTR]: dest,
  });

  const onRowDragStart = (e: DragEvent, entry: FsEntry) => {
    const targets = selected.has(entry.path) ? selectedEntries : [entry];
    if (!selected.has(entry.path)) setSelected(new Set([entry.path]));
    const payload: DragPayload = { side, entries: targets };
    e.dataTransfer.setData(mimeFor(paneKey), JSON.stringify(payload));
    e.dataTransfer.effectAllowed = "copy";
  };

  const onDragOverZone = (e: DragEvent, dest: string | null) => {
    if (!accepts(e.dataTransfer) || dest === null) return;
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = "copy";
    if (dropOver !== dest) setDropOver(dest);
  };

  const onDragEnterPane = (e: DragEvent) => {
    if (!accepts(e.dataTransfer)) return;
    dragDepth.current += 1;
  };

  const onDragLeavePane = (e: DragEvent) => {
    if (!accepts(e.dataTransfer)) return;
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setDropOver(null);
  };

  const onDropZone = (e: DragEvent, dest: string | null) => {
    dragDepth.current = 0;
    setDropOver(null);
    if (!accepts(e.dataTransfer) || dest === null) return;
    e.preventDefault();
    e.stopPropagation();
    const raw = e.dataTransfer.getData(mimeFor(otherKey(paneKey)));
    if (raw) {
      try {
        const payload = JSON.parse(raw) as DragPayload;
        if (payload.entries.length > 0) onReceive(payload.entries, dest);
      } catch {
        // not ours
      }
      return;
    }
    if (onReceiveFiles && hasOsFiles(e.dataTransfer)) onReceiveFiles(e.dataTransfer, dest);
  };

  const onContext = (e: MouseEvent, entry: FsEntry | null) => {
    e.preventDefault();
    if (entry && !selected.has(entry.path)) setSelected(new Set([entry.path]));
    setMenu({ x: e.clientX, y: e.clientY, entry });
  };

  const TransferIcon = side === "local" ? UploadRoundedIcon : DownloadRoundedIcon;
  const menuTargets = menu?.entry ? (selected.size > 1 ? selectedEntries : [menu.entry]) : [];
  const menuSingle = menuTargets.length === 1 ? menuTargets[0] : undefined;
  const menuFile = menuSingle && !isDirLike(menuSingle) ? menuSingle : undefined;
  const actionSingle = selectedEntries.length === 1 ? selectedEntries[0] : undefined;
  const actionFile = actionSingle && !isDirLike(actionSingle) ? actionSingle : undefined;
  const chmod = api.chmod;
  const currentDir = listing.data?.path ?? null;
  const paneOver = dropOver !== null && dropOver === currentDir;

  return (
    <Box
      tabIndex={-1}
      sx={{
        flex: 1,
        minWidth: 0,
        display: "flex",
        flexDirection: "column",
        height: "100%",
        outline: "none",
      }}
      onContextMenu={(e) => {
        if (e.target === e.currentTarget) onContext(e, null);
      }}
      onKeyDown={(e) => {
        if (e.target instanceof HTMLInputElement) return;
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a") {
          e.preventDefault();
          selectAll();
        }
      }}
    >
      <Stack
        direction="row"
        spacing={0.5}
        sx={{ alignItems: "center", pl: 1.5, pr: 0.75, height: 36, flexShrink: 0 }}
      >
        <Typography
          variant="subtitle2"
          color="text.secondary"
          noWrap
          sx={{ flex: filter === null ? 1 : undefined, minWidth: 0 }}
        >
          {title}
        </Typography>
        {headerExtra}
        {filter !== null ? (
          <InputBase
            autoFocus
            value={filter}
            placeholder={tr("Filter")}
            onChange={(e) => setFilter(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setFilter(null);
            }}
            startAdornment={
              <SearchRoundedIcon sx={{ fontSize: 16, mr: 0.5, color: "text.secondary" }} />
            }
            endAdornment={
              <ToolIconButton title={tr("Close filter")} onClick={() => setFilter(null)}>
                <CloseRoundedIcon sx={{ fontSize: 14 }} />
              </ToolIconButton>
            }
            sx={{
              flex: 1,
              minWidth: 0,
              px: 1,
              height: sizes.control,
              fontSize: 12.5,
              borderRadius: 1.5,
              bgcolor: "surface.high",
              "&.Mui-focused": { outline: "1px solid", outlineColor: "primary.main" },
            }}
          />
        ) : (
          <Button
            color="inherit"
            size="small"
            disabled={disabled}
            startIcon={<SearchRoundedIcon />}
            onClick={() => setFilter("")}
            sx={{ minWidth: 0, px: 1 }}
          >
            {tr("Filter")}
          </Button>
        )}
        <Button
          color="inherit"
          size="small"
          disabled={disabled}
          endIcon={<ExpandMoreRoundedIcon />}
          onClick={(e) => setActionsAnchor(e.currentTarget)}
          sx={{ minWidth: 0, px: 1 }}
        >
          {tr("Actions")}
        </Button>
      </Stack>
      <Stack
        direction="row"
        spacing={0.25}
        sx={{
          alignItems: "center",
          px: 0.75,
          height: 36,
          borderBottom: 1,
          borderColor: "border.light",
          flexShrink: 0,
        }}
      >
        <ToolIconButton
          title={tr("Back")}
          disabled={disabled || history.idx <= 0}
          onClick={() => step(-1)}
        >
          <ArrowBackRoundedIcon fontSize="small" />
        </ToolIconButton>
        <ToolIconButton
          title={tr("Forward")}
          disabled={disabled || history.idx >= history.stack.length - 1}
          onClick={() => step(1)}
        >
          <ArrowForwardRoundedIcon fontSize="small" />
        </ToolIconButton>
        {driveList.length > 0 && (
          <Button
            color="inherit"
            size="small"
            disabled={disabled}
            startIcon={<StorageRoundedIcon />}
            endIcon={<ExpandMoreRoundedIcon />}
            onClick={(e) => setDrivesAnchor(e.currentTarget)}
            sx={{ minWidth: 0, px: 1, fontFamily: monoFontFamily, fontSize: 12.5 }}
          >
            {crumbsOf(resolvedPath ?? "")[0]?.label ?? tr("Drives")}
          </Button>
        )}
        {pathDraft !== null ? (
          <InputBase
            autoFocus
            value={pathDraft}
            disabled={disabled}
            onChange={(e) => setPathDraft(e.target.value)}
            onBlur={() => setPathDraft(null)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                const trimmed = pathDraft.trim();
                navigate(trimmed.length > 0 ? trimmed : null);
              }
              if (e.key === "Escape") setPathDraft(null);
            }}
            sx={{
              flex: 1,
              mx: 0.5,
              px: 1.25,
              height: sizes.control,
              fontSize: 12.5,
              fontFamily: monoFontFamily,
              borderRadius: 1.5,
              bgcolor: "surface.high",
              "&.Mui-focused": { outline: "1px solid", outlineColor: "primary.main" },
            }}
          />
        ) : (
          <Tooltip title={tr("Click to edit the path")} enterDelay={800}>
            <Stack
              direction="row"
              onClick={() => {
                if (!disabled) setPathDraft(resolvedPath ?? "");
              }}
              sx={{
                flex: 1,
                minWidth: 0,
                mx: 0.5,
                px: 0.75,
                height: sizes.control,
                alignItems: "center",
                overflow: "hidden",
                borderRadius: 1.5,
                cursor: disabled ? "default" : "text",
                fontFamily: monoFontFamily,
                fontSize: 12.5,
                "&:hover": { bgcolor: disabled ? undefined : "surface.high" },
              }}
            >
              {crumbsOf(resolvedPath ?? "").map((c, i, arr) => (
                <Stack key={c.path} direction="row" sx={{ alignItems: "center", minWidth: 0 }}>
                  {i > 0 && (
                    <Typography component="span" sx={{ color: "text.disabled", px: 0.25 }}>
                      ›
                    </Typography>
                  )}
                  <Stack
                    direction="row"
                    spacing={0.5}
                    onClick={(e) => {
                      e.stopPropagation();
                      if (!disabled && i < arr.length - 1) navigate(c.path);
                    }}
                    sx={{
                      alignItems: "center",
                      minWidth: 0,
                      px: 0.5,
                      borderRadius: 1,
                      color: i === arr.length - 1 ? "text.primary" : "text.secondary",
                      cursor: i < arr.length - 1 ? "pointer" : "text",
                      "&:hover": i < arr.length - 1 ? { bgcolor: "action.hover" } : undefined,
                    }}
                  >
                    {i > 0 && <FolderRoundedIcon sx={{ fontSize: 14, color: "secondary.main" }} />}
                    <Typography
                      component="span"
                      noWrap
                      sx={{ fontFamily: "inherit", fontSize: "inherit" }}
                    >
                      {tr(c.label)}
                    </Typography>
                  </Stack>
                </Stack>
              ))}
            </Stack>
          </Tooltip>
        )}
      </Stack>

      <Menu
        open={drivesAnchor !== null}
        anchorEl={drivesAnchor}
        onClose={() => setDrivesAnchor(null)}
        onClick={() => setDrivesAnchor(null)}
      >
        {driveList.map((d) => (
          <MenuItem
            key={d}
            selected={resolvedPath?.toLowerCase().startsWith(d.toLowerCase()) ?? false}
            onClick={() => navigate(d)}
            sx={{ fontFamily: monoFontFamily }}
          >
            {d}
          </MenuItem>
        ))}
      </Menu>

      <Menu
        open={actionsAnchor !== null}
        anchorEl={actionsAnchor}
        onClose={() => setActionsAnchor(null)}
        onClick={() => setActionsAnchor(null)}
        slotProps={{ paper: { sx: { minWidth: 220 } } }}
      >
        {actionFile && (
          <MenuItem onClick={() => onOpen(actionFile, "default")}>
            <ListItemIcon>
              <OpenInNewRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Open")}</ListItemText>
          </MenuItem>
        )}
        {actionFile && (
          <MenuItem onClick={() => onOpen(actionFile, "with")}>
            <ListItemIcon>
              <AppsRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Open with…")}</ListItemText>
          </MenuItem>
        )}
        {actionFile && onCompare && (
          <MenuItem disabled={oppositePath === null} onClick={() => onCompare(actionFile)}>
            <ListItemIcon>
              <DifferenceRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Compare with other pane")}</ListItemText>
          </MenuItem>
        )}
        {selectedEntries.length > 0 && (
          <MenuItem disabled={oppositePath === null} onClick={() => onTransfer(selectedEntries)}>
            <ListItemIcon>
              <TransferIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>
              {tr("Copy to target directory")}
              {selectedEntries.length > 1 ? ` (${selectedEntries.length})` : ""}
            </ListItemText>
          </MenuItem>
        )}
        {actionSingle && (
          <MenuItem onClick={() => setDialog({ kind: "rename", entry: actionSingle })}>
            <ListItemIcon>
              <DriveFileRenameOutlineRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Rename")}</ListItemText>
          </MenuItem>
        )}
        {selectedEntries.length > 0 && (
          <MenuItem
            onClick={() => setDialog({ kind: "delete", entries: selectedEntries })}
            sx={{ color: "error.main" }}
          >
            <ListItemIcon>
              <DeleteOutlineRoundedIcon fontSize="small" color="error" />
            </ListItemIcon>
            <ListItemText>
              {tr("Delete")}
              {selectedEntries.length > 1 ? ` (${selectedEntries.length})` : ""}
            </ListItemText>
          </MenuItem>
        )}
        {selectedEntries.length > 0 && <Divider />}
        <MenuItem onClick={refresh}>
          <ListItemIcon>
            <RefreshRoundedIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>{tr("Refresh")}</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => setDialog({ kind: "mkdir" })}>
          <ListItemIcon>
            <CreateNewFolderRoundedIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>{tr("New Folder")}</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => setShowHidden((v) => !v)}>
          <ListItemIcon>
            {showHidden ? (
              <VisibilityOffRoundedIcon fontSize="small" />
            ) : (
              <VisibilityRoundedIcon fontSize="small" />
            )}
          </ListItemIcon>
          <ListItemText>
            {showHidden ? tr("Hide Hidden Files") : tr("Show Hidden Files")}
          </ListItemText>
        </MenuItem>
        {actionSingle && chmod && (
          <MenuItem onClick={() => setDialog({ kind: "chmod", entry: actionSingle })}>
            <ListItemIcon>
              <LockOutlinedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Edit Permissions")}</ListItemText>
          </MenuItem>
        )}
        <MenuItem disabled={entries.length === 0} onClick={selectAll}>
          <ListItemIcon>
            <SelectAllRoundedIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>{tr("Select All")}</ListItemText>
        </MenuItem>
        {onClose && (
          <MenuItem onClick={onClose} sx={{ color: "error.main" }}>
            <ListItemIcon>
              <CloseRoundedIcon fontSize="small" color="error" />
            </ListItemIcon>
            <ListItemText>{tr("Close")}</ListItemText>
          </MenuItem>
        )}
      </Menu>
      <Box
        sx={{
          flex: 1,
          minHeight: 0,
          overflow: "auto",
          position: "relative",
          outline: paneOver ? "2px solid" : "2px solid transparent",
          outlineColor: paneOver ? "primary.main" : "transparent",
          outlineOffset: -2,
          bgcolor: paneOver ? "action.hover" : undefined,
          transition: "background-color 120ms",
        }}
        onContextMenu={(e) => {
          if (e.target === e.currentTarget) onContext(e, null);
        }}
        onClick={(e) => {
          if (e.target === e.currentTarget) setSelected(new Set());
        }}
        onDragEnter={onDragEnterPane}
        onDragLeave={onDragLeavePane}
        onDragOver={(e) => onDragOverZone(e, currentDir)}
        onDrop={(e) => onDropZone(e, currentDir)}
        {...(osZone && currentDir ? dropZoneAttrs(currentDir) : {})}
      >
        {listing.isPending && !disabled && (
          <Stack sx={{ alignItems: "center", pt: 6 }}>
            <CircularProgress size={22} />
          </Stack>
        )}
        {listing.error && (
          <Typography variant="body2" color="error" sx={{ p: 2, userSelect: "text" }}>
            {errorMessage(listing.error)}
          </Typography>
        )}
        {listing.data && (
          <Table size="small" stickyHeader sx={{ tableLayout: "fixed" }}>
            <TableHead>
              <TableRow
                sx={{
                  "& th": {
                    py: 0.5,
                    fontSize: 12,
                    color: "text.secondary",
                    bgcolor: "surface.base",
                    borderColor: "border.light",
                  },
                }}
              >
                {COLUMNS.map((c) => (
                  <TableCell
                    key={c.key}
                    align={c.align}
                    sortDirection={sort.key === c.key ? sort.dir : false}
                    sx={{ width: c.width }}
                  >
                    <TableSortLabel
                      active={sort.key === c.key}
                      direction={sort.key === c.key ? sort.dir : "asc"}
                      onClick={() => toggleSort(c.key)}
                      sx={{
                        fontSize: 12,
                        "& .MuiTableSortLabel-icon": { fontSize: 14 },
                        ...(c.align === "right" && { flexDirection: "row-reverse" }),
                      }}
                    >
                      {tr(c.label)}
                    </TableSortLabel>
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {entries.map((e) => {
                const sel = selected.has(e.path);
                const dir = isDirLike(e);
                const over = dir && dropOver === e.path;
                const inEdit = editing?.has(e.path) ?? false;
                return (
                  <TableRow
                    key={e.path}
                    hover
                    selected={sel}
                    draggable={!disabled}
                    onDragStart={(ev) => onRowDragStart(ev, e)}
                    onDragOver={dir ? (ev) => onDragOverZone(ev, e.path) : undefined}
                    onDrop={dir ? (ev) => onDropZone(ev, e.path) : undefined}
                    {...(osZone && dir ? dropZoneAttrs(e.path) : {})}
                    onClick={(ev) => onRowClick(ev, e)}
                    onDoubleClick={() => openEntry(e)}
                    onContextMenu={(ev) => onContext(ev, e)}
                    sx={{
                      cursor: "default",
                      "& td": {
                        py: 0.4,
                        fontSize: 13,
                        borderColor: "border.light",
                        ...(over && { bgcolor: "action.selected" }),
                      },
                      // Termius: a selected row is a solid accent bar with light text.
                      "&.Mui-selected td, &.Mui-selected:hover td": {
                        bgcolor: "primary.main",
                        color: "primary.contrastText",
                        borderColor: "primary.main",
                        "& .MuiTypography-root": { color: "inherit" },
                      },
                      ...(over && {
                        "& td:first-of-type": { boxShadow: "inset 2px 0 0", color: "primary.main" },
                      }),
                    }}
                  >
                    <TableCell sx={{ overflow: "hidden" }}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center", minWidth: 0 }}>
                        <EntryIcon entry={e} />
                        <Box sx={{ minWidth: 0 }}>
                          <Typography variant="body2" noWrap sx={{ fontSize: 13, lineHeight: 1.3 }}>
                            {e.name}
                          </Typography>
                          {e.mode !== null && (
                            <Typography
                              variant="caption"
                              noWrap
                              sx={{
                                display: "block",
                                lineHeight: 1.2,
                                fontSize: 11,
                                color: "text.disabled",
                                fontFamily: monoFontFamily,
                              }}
                            >
                              {formatMode(e.mode, e.kind)}
                            </Typography>
                          )}
                        </Box>
                        {inEdit && (
                          <Tooltip
                            title={tr("Open in a local application — saves are uploaded back")}
                          >
                            <EditRoundedIcon sx={{ fontSize: 14, color: "primary.main" }} />
                          </Tooltip>
                        )}
                        {e.link_target && (
                          <Typography
                            variant="caption"
                            color={isBrokenLink(e) ? "error" : "text.disabled"}
                            noWrap
                          >
                            → {e.link_target}
                            {isBrokenLink(e) ? ` (${tr("missing")})` : ""}
                          </Typography>
                        )}
                      </Stack>
                    </TableCell>
                    <TableCell sx={{ color: "text.secondary", whiteSpace: "nowrap" }}>
                      {formatMtime(e.mtime)}
                    </TableCell>
                    <TableCell
                      align="right"
                      sx={{ color: "text.secondary", fontVariantNumeric: "tabular-nums" }}
                    >
                      {dir ? "" : formatSize(e.size)}
                    </TableCell>
                    <TableCell sx={{ color: "text.secondary", whiteSpace: "nowrap" }}>
                      {kindLabel(e)}
                    </TableCell>
                  </TableRow>
                );
              })}
              {entries.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    sx={{ color: "text.disabled", textAlign: "center", py: 4 }}
                  >
                    {filter
                      ? tr("No matching items")
                      : canReceive
                        ? tr("Empty directory — drop files here")
                        : tr("Empty directory")}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </Box>

      <Stack
        direction="row"
        sx={{
          px: 1.5,
          height: 24,
          alignItems: "center",
          borderTop: 1,
          borderColor: "border.light",
        }}
      >
        <Typography variant="caption" color="text.secondary">
          {trn(entries.length, "{count} item", "{count} items")}
          {selected.size > 0 ? ` · ${tr("{count} selected", { count: selected.size })}` : ""}
        </Typography>
      </Stack>

      <Menu
        open={menu !== null}
        onClose={() => setMenu(null)}
        anchorReference="anchorPosition"
        anchorPosition={menu ? { top: menu.y, left: menu.x } : undefined}
        onClick={() => setMenu(null)}
        slotProps={{ paper: { sx: { minWidth: 200 } } }}
      >
        {menuFile && (
          <MenuItem onClick={() => onOpen(menuFile, "default")}>
            <ListItemIcon>
              <OpenInNewRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Open")}</ListItemText>
          </MenuItem>
        )}
        {menuFile && (
          <MenuItem onClick={() => onOpen(menuFile, "with")}>
            <ListItemIcon>
              <AppsRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Open with…")}</ListItemText>
          </MenuItem>
        )}
        {menuFile && <Divider />}
        {menu?.entry && (
          <MenuItem disabled={oppositePath === null} onClick={() => onTransfer(menuTargets)}>
            <ListItemIcon>
              <TransferIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>
              {tr("Copy to target directory")}
              {menuTargets.length > 1 ? ` (${menuTargets.length})` : ""}
            </ListItemText>
          </MenuItem>
        )}
        {menuSingle && (
          <MenuItem onClick={() => setDialog({ kind: "rename", entry: menuSingle })}>
            <ListItemIcon>
              <DriveFileRenameOutlineRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Rename")}</ListItemText>
          </MenuItem>
        )}
        {menuSingle && chmod && (
          <MenuItem onClick={() => setDialog({ kind: "chmod", entry: menuSingle })}>
            <ListItemIcon>
              <LockOutlinedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Edit Permissions")}</ListItemText>
          </MenuItem>
        )}
        {menuSingle && (
          <MenuItem
            onClick={() => {
              void copyToClipboard(menuSingle.path).catch(() => undefined);
            }}
          >
            <ListItemIcon>
              <ContentCopyRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Copy path")}</ListItemText>
          </MenuItem>
        )}
        {menu?.entry && <Divider />}
        {menu?.entry && (
          <MenuItem
            onClick={() => setDialog({ kind: "delete", entries: menuTargets })}
            sx={{ color: "error.main" }}
          >
            <ListItemIcon>
              <DeleteOutlineRoundedIcon fontSize="small" color="error" />
            </ListItemIcon>
            <ListItemText>
              {menuTargets.length > 1
                ? tr("Delete {count} items", { count: menuTargets.length })
                : tr("Delete")}
            </ListItemText>
          </MenuItem>
        )}
        {!menu?.entry && (
          <MenuItem onClick={() => setDialog({ kind: "mkdir" })}>
            <ListItemIcon>
              <CreateNewFolderRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("New Folder")}</ListItemText>
          </MenuItem>
        )}
        {!menu?.entry && (
          <MenuItem onClick={refresh}>
            <ListItemIcon>
              <RefreshRoundedIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{tr("Refresh")}</ListItemText>
          </MenuItem>
        )}
      </Menu>

      {dialog?.kind === "mkdir" && listing.data && (
        <NameDialog
          open
          title={tr("New folder")}
          label={tr("Folder name")}
          confirmLabel={tr("Create")}
          busy={mutate.isPending}
          onCancel={() => setDialog(null)}
          onConfirm={(name) => mutate.mutate(() => api.mkdir(joinPath(listing.data.path, name)))}
        />
      )}
      {dialog?.kind === "rename" && listing.data && (
        <NameDialog
          open
          title={tr("Rename")}
          label={tr("New name")}
          initial={dialog.entry.name}
          confirmLabel={tr("Rename")}
          busy={mutate.isPending}
          onCancel={() => setDialog(null)}
          onConfirm={(name) =>
            mutate.mutate(() => api.rename(dialog.entry.path, joinPath(listing.data.path, name)))
          }
        />
      )}
      {dialog?.kind === "chmod" && chmod && (
        <ChmodDialog
          open
          name={dialog.entry.name}
          mode={dialog.entry.mode ?? 0o644}
          busy={mutate.isPending}
          onCancel={() => setDialog(null)}
          onConfirm={(mode) => mutate.mutate(() => chmod(dialog.entry.path, mode))}
        />
      )}
      <ConfirmDialog
        open={dialog?.kind === "delete"}
        title={
          dialog?.kind === "delete" && dialog.entries.length > 1
            ? tr("Delete {length} items?", { length: dialog.entries.length })
            : tr("Delete?")
        }
        confirmLabel={tr("Delete")}
        danger
        busy={mutate.isPending}
        onCancel={() => setDialog(null)}
        onConfirm={() => {
          if (dialog?.kind !== "delete") return;
          mutate.mutate(async () => {
            for (const e of dialog.entries) await api.remove(e.path, e.kind === "dir");
          });
        }}
      >
        {dialog?.kind === "delete" && (
          <Box component="ul" sx={{ m: 0, pl: 2.5, maxHeight: 160, overflow: "auto" }}>
            {dialog.entries.map((e) => (
              <li key={e.path}>
                {e.name}
                {e.kind === "dir" ? `/ ${tr("(and everything inside)")}` : ""}
              </li>
            ))}
          </Box>
        )}
        <Typography variant="body2" sx={{ mt: 1 }}>
          {tr("This cannot be undone.")}
        </Typography>
      </ConfirmDialog>
    </Box>
  );
}

function EntryIcon({ entry }: { entry: FsEntry }) {
  if (entry.kind === "dir")
    return <FolderRoundedIcon fontSize="small" sx={{ color: "secondary.main" }} />;
  if (entry.kind === "symlink")
    return (
      <LinkRoundedIcon
        fontSize="small"
        sx={{ color: isBrokenLink(entry) ? "error.main" : "text.disabled" }}
      />
    );
  return <InsertDriveFileOutlinedIcon fontSize="small" sx={{ color: "text.disabled" }} />;
}
