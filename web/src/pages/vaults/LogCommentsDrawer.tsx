import { useState } from "react";
import {
  Box,
  Button,
  Chip,
  Drawer,
  IconButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { logsApi } from "@/api/endpoints";
import type { LogComment, SessionLog } from "@/api/types";
import { Loading } from "@/components/Loading";
import { useSnackbar } from "@/components/Snackbar";
import { UserCell } from "@/components/UserCell";
import { formatDateTime } from "@/components/format";
import { tr } from "@/i18n";

export interface CommentTarget {
  log: SessionLog;
  /** Shown in the header: host label from the decrypted metadata, if any. */
  title: string;
}

/** `mm:ss` of a point in the recording. */
export function formatOffset(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const mm = String(m % 60).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

/** `mm:ss`, `h:mm:ss` or plain seconds typed by the user → milliseconds. */
export function parseOffset(text: string): number | null {
  const t = text.trim();
  if (t === "") return null;
  const parts = t.split(":").map((p) => Number(p));
  if (parts.some((p) => !Number.isFinite(p) || p < 0)) return Number.NaN;
  const secs = parts.reduce((acc, p) => acc * 60 + p, 0);
  return Math.round(secs * 1000);
}

/**
 * The thread under one recording: who said what, when, and at which point of
 * the session. Editors and the author post; the author of a comment or a
 * vault manager removes it.
 */
export function LogCommentsDrawer({
  target,
  me,
  canComment,
  canManage,
  onClose,
}: {
  target: CommentTarget | null;
  me: string | undefined;
  canComment: boolean;
  canManage: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const logId = target?.log.id ?? null;
  const key = ["logs", logId, "comments"] as const;
  const thread = useQuery({
    queryKey: key,
    queryFn: () => logsApi.comments(logId ?? ""),
    enabled: logId !== null,
  });
  const [body, setBody] = useState("");
  const [offset, setOffset] = useState("");
  const offsetMs = parseOffset(offset);
  const offsetBad = Number.isNaN(offsetMs);
  const add = useMutation({
    mutationFn: () => logsApi.addComment(logId ?? "", body.trim(), offsetMs ?? undefined),
    onSuccess: () => {
      setBody("");
      setOffset("");
      void qc.invalidateQueries({ queryKey: key });
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (c: LogComment) => logsApi.deleteComment(logId ?? "", c.id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
    onError: (e) => snack.error(errorMessage(e)),
  });
  const comments = thread.data?.comments ?? [];
  return (
    <Drawer
      anchor="right"
      open={target !== null}
      onClose={onClose}
      slotProps={{ paper: { sx: { width: { xs: "100%", sm: 440 }, p: 2.5 } } }}
    >
      <Stack direction="row" sx={{ alignItems: "center", mb: 1 }}>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Typography variant="h6" noWrap>
            {tr("Comments")}
          </Typography>
          <Typography variant="body2" color="text.secondary" noWrap>
            {target?.title ?? ""}
          </Typography>
        </Box>
        <IconButton onClick={onClose} aria-label={tr("Close")}>
          <CloseRoundedIcon />
        </IconButton>
      </Stack>
      {thread.isPending && target && <Loading />}
      {thread.isError && (
        <Typography color="error" variant="body2">
          {errorMessage(thread.error)}
        </Typography>
      )}
      {thread.isSuccess && comments.length === 0 && (
        <Typography variant="body2" color="text.secondary" sx={{ my: 2 }}>
          {canComment
            ? tr("No comments yet. Leave the first one, with the moment it refers to if you like.")
            : tr("No comments yet.")}
        </Typography>
      )}
      <Stack spacing={2} sx={{ flex: 1, overflow: "auto", my: 1 }}>
        {comments.map((c) => (
          <Box key={c.id}>
            <Stack direction="row" sx={{ alignItems: "center", gap: 1 }}>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <UserCell
                  userId={c.user_id}
                  email={c.author?.email ?? ""}
                  displayName={c.author?.display_name}
                  avatar={c.author?.avatar_tag}
                  you={c.user_id === me}
                />
              </Box>
              {c.offset_ms !== undefined && (
                <Chip
                  size="small"
                  label={formatOffset(c.offset_ms)}
                  sx={{ fontFamily: "monospace" }}
                />
              )}
              {(c.user_id === me || canManage) && (
                <Tooltip title={tr("Delete comment")}>
                  <IconButton
                    size="small"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(c)}
                  >
                    <DeleteOutlineRoundedIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}
            </Stack>
            <Typography variant="body2" sx={{ mt: 0.5, whiteSpace: "pre-wrap" }}>
              {c.body}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {formatDateTime(c.created_at)}
            </Typography>
          </Box>
        ))}
      </Stack>
      {canComment && (
        <Stack spacing={1} sx={{ pt: 1, borderTop: 1, borderColor: "divider" }}>
          <TextField
            label={tr("Comment")}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            multiline
            minRows={2}
            maxRows={6}
            size="small"
            slotProps={{ htmlInput: { maxLength: 2000 } }}
          />
          <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start" }}>
            <TextField
              label={tr("At (mm:ss)")}
              value={offset}
              onChange={(e) => setOffset(e.target.value)}
              size="small"
              error={offsetBad}
              helperText={offsetBad ? tr("Use mm:ss or seconds") : undefined}
              sx={{ width: 150 }}
            />
            <Box sx={{ flex: 1 }} />
            <Button
              variant="contained"
              disabled={add.isPending || body.trim() === "" || offsetBad}
              onClick={() => add.mutate()}
            >
              {tr("Post")}
            </Button>
          </Stack>
        </Stack>
      )}
    </Drawer>
  );
}
