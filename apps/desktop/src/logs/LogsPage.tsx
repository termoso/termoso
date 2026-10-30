import { useCallback, useMemo, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import ArticleRoundedIcon from "@mui/icons-material/ArticleRounded";
import BookmarkAddRoundedIcon from "@mui/icons-material/BookmarkAddRounded";
import BookmarkRoundedIcon from "@mui/icons-material/BookmarkRounded";
import ChatBubbleOutlineRoundedIcon from "@mui/icons-material/ChatBubbleOutlineRounded";
import CloudDownloadOutlinedIcon from "@mui/icons-material/CloudDownloadOutlined";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import FileDownloadRoundedIcon from "@mui/icons-material/FileDownloadRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import FiberManualRecordRoundedIcon from "@mui/icons-material/FiberManualRecordRounded";
import GroupsRoundedIcon from "@mui/icons-material/GroupsRounded";
import PushPinOutlinedIcon from "@mui/icons-material/PushPinOutlined";
import PushPinRoundedIcon from "@mui/icons-material/PushPinRounded";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { save as saveFile } from "@tauri-apps/plugin-dialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { goToSettings, goToSettingsWith } from "@/app/navigation";
import { useActiveVault } from "@/app/vault";
import { Page, PageBody, PageHeader } from "@/components/PageHeader";
import {
  EntityCard,
  Field,
  IconTile,
  InfoBar,
  Loading,
  SectionTitle,
  ToolIconButton,
} from "@/components/ui";
import { ConnectionHistoryList } from "@/history/ShellHistory";
import { useSnackbar } from "@/components/Snackbar";
import * as ipc from "@/ipc/commands";
import { keys, useBookmarks, useLogBody, useLogs, useSettings } from "@/ipc/hooks";
import { errorMessage, type LogAuthor, type LogCard, type Uuid } from "@/ipc/types";
import { formatSize } from "@/sftp/format";
import { PersonAvatar, initialsOf } from "@/team/PersonAvatar";
import { sizes } from "@/theme/theme";
import { LogViewer, type ViewerHandle } from "./LogViewer";
import { authorName, authorsOf, recordingState, visibleLogs } from "./team";
import { tr, trn, trx } from "@/i18n";
import { requirePerm } from "@/team/perms";

function duration(secs: number | null): string {
  if (secs === null) return "—";
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  if (m < 60) return `${m}m ${secs % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function BookmarkDialog({
  line,
  busy,
  onCancel,
  onConfirm,
}: {
  line: number;
  busy: boolean;
  onCancel: () => void;
  onConfirm: (note: string) => void;
}) {
  const [note, setNote] = useState("");
  return (
    <Dialog open onClose={busy ? undefined : onCancel} maxWidth="xs" fullWidth>
      <DialogTitle>
        {tr("Bookmark line")} {line + 1}
      </DialogTitle>
      <DialogContent>
        <Field label={tr("Note")}>
          <TextField
            autoFocus
            fullWidth
            value={note}
            onChange={(e) => setNote(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && note.trim()) onConfirm(note.trim());
            }}
            sx={{ mt: 0.5 }}
          />
        </Field>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onCancel} disabled={busy} color="inherit">
          {tr("Cancel")}
        </Button>
        <Button
          variant="contained"
          disabled={busy || note.trim().length === 0}
          onClick={() => onConfirm(note.trim())}
        >
          {tr("Add")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Shared comment under the viewer header: read-only text, or an editor for those who may write. */
function NoteBar({
  log,
  busy,
  onSave,
}: {
  log: LogCard;
  busy: boolean;
  onSave: (note: string) => void;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  if (draft === null && !log.note) {
    if (!log.canAnnotate || !log.team) return null;
    return (
      <Box sx={{ px: 2, py: 0.5, borderBottom: 1, borderColor: "border.light" }}>
        <Button
          size="small"
          color="inherit"
          startIcon={<ChatBubbleOutlineRoundedIcon sx={{ fontSize: 16 }} />}
          onClick={() => setDraft("")}
          sx={{ color: "text.secondary", fontWeight: 400 }}
        >
          {tr("Add a comment for the team")}
        </Button>
      </Box>
    );
  }
  if (draft !== null) {
    return (
      <Box
        sx={{
          px: 2,
          py: 1,
          borderBottom: 1,
          borderColor: "border.light",
          display: "flex",
          gap: 1,
          alignItems: "flex-start",
        }}
      >
        <TextField
          autoFocus
          fullWidth
          multiline
          minRows={1}
          maxRows={6}
          size="small"
          placeholder={tr("What happened in this session?")}
          value={draft}
          disabled={busy}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") setDraft(null);
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) onSave(draft.trim());
          }}
          slotProps={{ htmlInput: { maxLength: 2000 } }}
        />
        <Button size="small" color="inherit" disabled={busy} onClick={() => setDraft(null)}>
          {tr("Cancel")}
        </Button>
        <Button
          size="small"
          variant="contained"
          disabled={busy || draft.trim() === log.note}
          onClick={() => onSave(draft.trim())}
        >
          {tr("Save")}
        </Button>
      </Box>
    );
  }
  return (
    <Box
      sx={{
        px: 2,
        py: 1,
        borderBottom: 1,
        borderColor: "border.light",
        display: "flex",
        gap: 1,
        alignItems: "flex-start",
        bgcolor: "surface.low",
      }}
    >
      <ChatBubbleOutlineRoundedIcon sx={{ fontSize: 16, mt: 0.3, color: "text.secondary" }} />
      <Typography variant="body2" sx={{ flex: 1, whiteSpace: "pre-wrap", minWidth: 0 }}>
        {log.note}
      </Typography>
      {log.canAnnotate && (
        <Button
          size="small"
          color="inherit"
          disabled={busy}
          onClick={() => setDraft(log.note)}
          sx={{ color: "text.secondary", fontWeight: 400 }}
        >
          {tr("Edit")}
        </Button>
      )}
    </Box>
  );
}

export function Viewer({
  log,
  onClose,
  onDeleted,
}: {
  log: LogCard;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const snackbar = useSnackbar();
  const qc = useQueryClient();
  const body = useLogBody(log.id);
  const bookmarks = useBookmarks(log.id);
  const settings = useSettings();
  const [handle, setHandle] = useState<ViewerHandle | null>(null);
  const [dialog, setDialog] = useState<
    { kind: "none" } | { kind: "bookmark"; line: number } | { kind: "delete" }
  >({ kind: "none" });
  const onReady = useCallback((h: ViewerHandle) => setHandle(h), []);

  const op = useMutation({
    mutationFn: async (job: () => Promise<string | null>) => job(),
    onSuccess: (msg) => {
      void qc.invalidateQueries({ queryKey: keys.bookmarks(log.id) });
      void qc.invalidateQueries({ queryKey: keys.logs });
      setDialog({ kind: "none" });
      if (msg) snackbar.notify(msg);
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });

  const exportLog = async () => {
    if (!requirePerm(log.vaultId, "logs.export")) return null;
    const stamp = log.startedAt.replace(/[:.]/g, "-");
    const path = await saveFile({
      title: tr("Export recording"),
      defaultPath: `${log.label.replace(/[^\w.-]+/g, "_")}-${stamp}.log`,
    });
    if (path === null) return null;
    const n = await ipc.logExport(log.id, path);
    return tr("Exported {formatSize} to {path}", { formatSize: formatSize(n), path });
  };

  const annotate = (patch: { pinned?: boolean; note?: string }, msg: string | null) =>
    op.mutate(async () => {
      await ipc.logAnnotate(log.id, patch);
      return msg;
    });

  const who = log.author && !log.mine ? authorName(log.author) : null;

  return (
    <Box sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <Box
        sx={{
          px: 2,
          py: 1,
          display: "flex",
          alignItems: "center",
          gap: 1.5,
          borderBottom: 1,
          borderColor: "border.light",
          minHeight: 48,
        }}
      >
        {log.author && (
          <PersonAvatar
            size={28}
            label={initialsOf(log.author.displayName, log.author.email)}
            seed={log.author.email}
            userId={log.author.userId}
            avatar={log.author.avatar}
          />
        )}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography variant="subtitle2" noWrap>
            {log.label}
            <Typography
              component="span"
              variant="caption"
              color="text.secondary"
              sx={{ ml: 1, fontFamily: "monospace" }}
            >
              {log.target}
            </Typography>
          </Typography>
          <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
            {who && `${who} · `}
            {new Date(log.startedAt).toLocaleString()} · {duration(log.durationSecs)} ·{" "}
            {formatSize(log.sizeBytes)} · {log.cols}×{log.rows}
            {!log.completed && " · " + tr("in progress")}
          </Typography>
        </Box>
        {log.team && (
          <ToolIconButton
            title={
              !log.canAnnotate
                ? tr("Editors can pin recordings for the team")
                : log.pinned
                  ? tr("Unpin")
                  : tr("Pin for the team")
            }
            disabled={!log.canAnnotate || op.isPending}
            onClick={() =>
              annotate({ pinned: !log.pinned }, log.pinned ? tr("Unpinned") : tr("Pinned"))
            }
          >
            {log.pinned ? (
              <PushPinRoundedIcon fontSize="small" color="primary" />
            ) : (
              <PushPinOutlinedIcon fontSize="small" />
            )}
          </ToolIconButton>
        )}
        <ToolIconButton
          title={tr("Bookmark the line at the top of the view")}
          disabled={!handle}
          onClick={() => handle && setDialog({ kind: "bookmark", line: handle.topLine() })}
        >
          <BookmarkAddRoundedIcon fontSize="small" />
        </ToolIconButton>
        <ToolIconButton title={tr("Export as plain file")} onClick={() => op.mutate(exportLog)}>
          <FileDownloadRoundedIcon fontSize="small" />
        </ToolIconButton>
        <ToolIconButton
          title={
            log.canDelete
              ? tr("Delete recording")
              : tr("Only the author or a vault manager can delete this recording")
          }
          disabled={!log.canDelete}
          onClick={() => setDialog({ kind: "delete" })}
        >
          <DeleteOutlineRoundedIcon fontSize="small" />
        </ToolIconButton>
        <ToolIconButton title={tr("Close")} onClick={onClose}>
          <CloseRoundedIcon fontSize="small" />
        </ToolIconButton>
      </Box>
      <NoteBar
        key={log.note}
        log={log}
        busy={op.isPending}
        onSave={(note) => annotate({ note }, note ? tr("Comment saved") : tr("Comment removed"))}
      />
      <Box sx={{ flex: 1, minHeight: 0, display: "flex" }}>
        {body.isPending || settings.isPending ? (
          <Box sx={{ flex: 1 }}>
            {log.cached ? (
              <Loading />
            ) : (
              <EmptyState
                icon={<CloudDownloadOutlinedIcon />}
                title={tr("Downloading recording")}
                description={tr(
                  "Fetching the encrypted recording from the server; it is decrypted on this device only.",
                )}
              />
            )}
          </Box>
        ) : body.error ? (
          <Box sx={{ flex: 1 }}>
            <EmptyState
              title={tr("Could not read recording")}
              description={errorMessage(body.error)}
            />
          </Box>
        ) : settings.error ? (
          <Box sx={{ flex: 1 }}>
            <EmptyState
              title={tr("Settings unavailable")}
              description={errorMessage(settings.error)}
            />
          </Box>
        ) : (
          <LogViewer
            text={body.data.text}
            cols={log.cols}
            settings={settings.data}
            onReady={onReady}
          />
        )}
        {(bookmarks.data ?? []).length > 0 && (
          <Box
            sx={{
              width: 240,
              flexShrink: 0,
              borderLeft: 1,
              borderColor: "border.light",
              overflowY: "auto",
            }}
          >
            <Typography variant="subtitle2" sx={{ px: 2, pt: 1.5, pb: 0.5, display: "block" }}>
              {tr("Bookmarks")}
            </Typography>
            <List dense disablePadding>
              {(bookmarks.data ?? []).map((b) => (
                <ListItemButton
                  key={b.id}
                  onClick={() => handle?.scrollTo(b.offset)}
                  sx={{ pr: 0.5, "&:hover .bm-del": { opacity: 1 } }}
                >
                  <BookmarkRoundedIcon
                    sx={{ fontSize: 16, mr: 1, color: "primary.main", flexShrink: 0 }}
                  />
                  <ListItemText
                    primary={b.note}
                    secondary={tr("line {line}", { line: b.offset + 1 })}
                    slotProps={{ primary: { noWrap: true, variant: "body2" } }}
                  />
                  <IconButton
                    size="small"
                    className="bm-del"
                    sx={{ opacity: 0 }}
                    aria-label={tr("Remove bookmark")}
                    onClick={(e) => {
                      e.stopPropagation();
                      op.mutate(async () => {
                        await ipc.logBookmarkDelete(b.id);
                        return null;
                      });
                    }}
                  >
                    <CloseRoundedIcon sx={{ fontSize: 14 }} />
                  </IconButton>
                </ListItemButton>
              ))}
            </List>
          </Box>
        )}
      </Box>

      {dialog.kind === "bookmark" && (
        <BookmarkDialog
          line={dialog.line}
          busy={op.isPending}
          onCancel={() => setDialog({ kind: "none" })}
          onConfirm={(note) => {
            const line = dialog.line;
            op.mutate(async () => {
              await ipc.logBookmarkAdd(log.id, line, note);
              return null;
            });
          }}
        />
      )}
      {dialog.kind === "delete" && (
        <ConfirmDialog
          open
          title={tr("Delete recording?")}
          confirmLabel={tr("Delete")}
          danger
          busy={op.isPending}
          onCancel={() => setDialog({ kind: "none" })}
          onConfirm={() =>
            op.mutate(async () => {
              if (!requirePerm(log.vaultId, "logs.delete")) return null;
              await ipc.logDelete(log.id);
              onDeleted();
              return tr("Recording deleted");
            })
          }
        >
          {log.team ? (
            <>
              {who
                ? trx(
                    "The recording of {label} by {who} will be removed for everyone in the vault, together with your bookmarks.",
                    { label: <b>{log.label}</b>, who: <b>{who}</b> },
                  )
                : trx(
                    "The recording of {label} will be removed for everyone in the vault, together with your bookmarks.",
                    { label: <b>{log.label}</b> },
                  )}
            </>
          ) : (
            <>
              {trx(
                log.uploaded
                  ? "The recording of {label} and its bookmarks will be removed from this device and your other devices."
                  : "The recording of {label} and its bookmarks will be removed from this device.",
                { label: <b>{log.label}</b> },
              )}
            </>
          )}
        </ConfirmDialog>
      )}
    </Box>
  );
}

function AuthorFilter({
  authors,
  list,
  value,
  onChange,
}: {
  authors: LogAuthor[];
  list: LogCard[];
  value: Uuid | null;
  onChange: (id: Uuid | null) => void;
}) {
  if (authors.length < 2) return null;
  return (
    <Box sx={{ display: "flex", gap: 0.75, flexWrap: "wrap", pb: 1.5 }}>
      <Chip
        size="small"
        label={tr("Everyone · {length}", { length: list.length })}
        color={value === null ? "primary" : "default"}
        variant={value === null ? "filled" : "outlined"}
        onClick={() => onChange(null)}
      />
      {authors.map((a) => {
        const n = list.filter((l) => l.author?.userId === a.userId).length;
        return (
          <Chip
            key={a.userId}
            size="small"
            avatar={
              <Box component="span" sx={{ display: "flex", ml: "2px !important" }}>
                <PersonAvatar
                  size={18}
                  label={initialsOf(a.displayName, a.email)}
                  seed={a.email}
                  userId={a.userId}
                  avatar={a.avatar}
                />
              </Box>
            }
            label={`${authorName(a)} · ${n}`}
            color={value === a.userId ? "primary" : "default"}
            variant={value === a.userId ? "filled" : "outlined"}
            onClick={() => onChange(value === a.userId ? null : a.userId)}
          />
        );
      })}
    </Box>
  );
}

export function LogsPage() {
  const logs = useLogs();
  const settings = useSettings();
  const vault = useActiveVault();
  const snackbar = useSnackbar();
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<Uuid | null>(null);
  const [authorId, setAuthorId] = useState<Uuid | null>(null);

  const vaultId = vault.data?.id ?? null;
  const isTeam = vault.data?.kind === "team";
  const manager = isTeam && vault.data?.role === "manager";
  const inVault = useMemo(() => visibleLogs(logs.data ?? [], vaultId, null), [logs.data, vaultId]);
  const authors = useMemo(() => authorsOf(inVault), [inVault]);
  const list = useMemo(() => visibleLogs(inVault, null, authorId), [inVault, authorId]);
  const selected = useMemo(
    () => inVault.find((l) => l.id === selectedId) ?? null,
    [inVault, selectedId],
  );

  const state = recordingState(vault.data, settings.data?.recordSessions ?? true);
  const recordingOff = settings.data !== undefined && state === "off";

  const teamToggle = useMutation({
    mutationFn: (on: boolean) => ipc.vaultSessionLoggingSet(vaultId ?? "", on),
    onSuccess: (_r, on) => {
      void qc.invalidateQueries({ queryKey: keys.vaults });
      snackbar.notify(
        on ? tr("Sessions in this vault are now recorded") : tr("Team recording turned off"),
      );
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });

  const headerAction =
    state === "team" ? (
      <Chip
        size="small"
        icon={<GroupsRoundedIcon />}
        label={tr("Recording for the team")}
        title={tr(
          "A vault manager turned on session logging: every member's sessions to this vault's hosts are recorded and shared with the vault.",
        )}
        onClick={() => vault.data && goToSettingsWith({ kind: "vault", id: vault.data.id })}
        sx={{ "& .MuiChip-icon": { color: "error.main", fontSize: 14 } }}
      />
    ) : manager && vaultId ? (
      <Button
        variant="tonal"
        startIcon={<GroupsRoundedIcon />}
        disabled={teamToggle.isPending}
        onClick={() => teamToggle.mutate(true)}
      >
        {tr("Record for the team")}
      </Button>
    ) : recordingOff ? (
      <Button
        variant="tonal"
        startIcon={<FiberManualRecordRoundedIcon color="error" />}
        onClick={() => goToSettings("logs")}
      >
        {tr("Enable recording")}
      </Button>
    ) : (
      <Chip
        size="small"
        icon={<FiberManualRecordRoundedIcon />}
        label={tr("Recording new sessions")}
        sx={{ "& .MuiChip-icon": { color: "error.main", fontSize: 12 } }}
      />
    );

  return (
    <Page>
      <PageHeader
        actions={
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            {headerAction}
            {state !== "team" && manager && vaultId && !recordingOff && (
              <Tooltip title={tr("Sessions are recorded for you only until team recording is on")}>
                <Chip
                  size="small"
                  icon={<FiberManualRecordRoundedIcon />}
                  label={tr("Recording for you")}
                  sx={{ "& .MuiChip-icon": { color: "error.main", fontSize: 12 } }}
                />
              </Tooltip>
            )}
          </Box>
        }
        trailing={
          inVault.length > 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ px: 1 }}>
              {isTeam && vault.data ? `${vault.data.name} · ` : ""}
              {trn(inVault.length, "{count} recording", "{count} recordings")} ·{" "}
              {formatSize(inVault.reduce((n, l) => n + l.sizeBytes, 0))}
            </Typography>
          )
        }
      />
      <Box sx={{ flex: 1, minHeight: 0, display: "flex" }}>
        <Box
          sx={{
            width: selected ? 320 : "100%",
            flexShrink: 0,
            borderRight: selected ? 1 : 0,
            borderColor: "border.light",
            display: "flex",
            flexDirection: "column",
            minHeight: 0,
          }}
        >
          <PageBody>
            {recordingOff && inVault.length > 0 && (
              <InfoBar
                action={
                  <Button size="small" onClick={() => goToSettings("logs")}>
                    {tr("Settings")}
                  </Button>
                }
              >
                {tr("Session recording is off — new terminals are not captured.")}
              </InfoBar>
            )}
            {isTeam && !selected && (
              <AuthorFilter
                authors={authors}
                list={inVault}
                value={authorId}
                onChange={setAuthorId}
              />
            )}
            {logs.isPending || vault.isPending ? (
              <Loading />
            ) : logs.error ? (
              <EmptyState
                title={tr("Could not load logs")}
                description={errorMessage(logs.error)}
              />
            ) : list.length === 0 ? (
              <Stack spacing={3}>
                <EmptyState
                  icon={isTeam ? <GroupsRoundedIcon /> : <ArticleRoundedIcon />}
                  title={isTeam ? tr("No team recordings yet") : tr("No recordings")}
                  description={
                    isTeam
                      ? state === "team"
                        ? tr(
                            "Sessions to this vault's hosts are recorded on each member's device and shared here, encrypted with the vault key.",
                          )
                        : manager
                          ? tr(
                              "Turn on session logging for this vault and every member's sessions to its hosts will be captured here, readable by the whole vault.",
                            )
                          : tr(
                              "A vault manager can turn on session logging so the whole vault sees each other's recordings. Your own recordings appear here when recording is on in Settings.",
                            )
                      : tr(
                          "Turn on session recording in Settings and every terminal session will be captured here, encrypted and stored locally.",
                        )
                  }
                  action={
                    isTeam && manager && state !== "team" ? (
                      <Button
                        variant="contained"
                        disabled={teamToggle.isPending}
                        onClick={() => teamToggle.mutate(true)}
                      >
                        {tr("Record for the team")}
                      </Button>
                    ) : (
                      recordingOff && (
                        <Button variant="contained" onClick={() => goToSettings("logs")}>
                          {tr("Open settings")}
                        </Button>
                      )
                    )
                  }
                />
                {!isTeam && (
                  <Box>
                    <SectionTitle sx={{ mb: 1 }}>{tr("Connection history")}</SectionTitle>
                    <ConnectionHistoryList query="" hideClear />
                  </Box>
                )}
              </Stack>
            ) : (
              <Stack spacing={1}>
                {list.map((l) => (
                  <EntityCard
                    key={l.id}
                    dense
                    selected={l.id === selectedId}
                    onClick={() => setSelectedId(l.id)}
                    tile={
                      l.author && l.team ? (
                        <PersonAvatar
                          size={sizes.tileSmall}
                          label={initialsOf(l.author.displayName, l.author.email)}
                          seed={l.author.email}
                          userId={l.author.userId}
                          avatar={l.author.avatar}
                        />
                      ) : (
                        <IconTile size={sizes.tileSmall} tone={l.completed ? "neutral" : "danger"}>
                          <ArticleRoundedIcon />
                        </IconTile>
                      )
                    }
                    title={
                      <>
                        {l.label}
                        <Typography
                          component="span"
                          variant="caption"
                          color="text.secondary"
                          sx={{ ml: 1 }}
                        >
                          {l.protocol.toUpperCase()}
                        </Typography>
                        {!l.completed && (
                          <Typography
                            component="span"
                            variant="caption"
                            color="error.main"
                            sx={{ ml: 1 }}
                          >
                            {tr("recording")}
                          </Typography>
                        )}
                      </>
                    }
                    subtitle={`${
                      l.author && l.team ? `${l.mine ? tr("You") : authorName(l.author)} · ` : ""
                    }${new Date(l.startedAt).toLocaleString()} · ${duration(
                      l.durationSecs,
                    )} · ${formatSize(l.sizeBytes)}`}
                    meta={
                      l.note ? (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          noWrap
                          sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 0.25 }}
                        >
                          <ChatBubbleOutlineRoundedIcon sx={{ fontSize: 13, flexShrink: 0 }} />
                          <Box
                            component="span"
                            sx={{ overflow: "hidden", textOverflow: "ellipsis" }}
                          >
                            {l.note}
                          </Box>
                        </Typography>
                      ) : undefined
                    }
                    trailing={
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                        {l.pinned && (
                          <PushPinRoundedIcon
                            sx={{ fontSize: 16, color: "primary.main" }}
                            titleAccess={tr("Pinned")}
                          />
                        )}
                        {!l.cached && l.uploaded && (
                          <CloudDownloadOutlinedIcon
                            sx={{ fontSize: 16, color: "text.disabled" }}
                            titleAccess={tr("Not downloaded yet")}
                          />
                        )}
                        {l.bookmarks > 0 && (
                          <Chip
                            size="small"
                            variant="outlined"
                            icon={<BookmarkRoundedIcon />}
                            label={l.bookmarks}
                          />
                        )}
                      </Box>
                    }
                  />
                ))}
              </Stack>
            )}
          </PageBody>
        </Box>
        {selected && (
          <Viewer
            key={selected.id}
            log={selected}
            onClose={() => setSelectedId(null)}
            onDeleted={() => setSelectedId(null)}
          />
        )}
      </Box>
    </Page>
  );
}
