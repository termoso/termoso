import { useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { tr, trn } from "@/i18n";
import * as ipc from "@/ipc/commands";
import { useTeamMembers } from "@/ipc/hooks";
import { errorMessage, type AccessReview, type Team, type Uuid } from "@/ipc/types";
import { Loading, Mono } from "@/components/ui";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { useSnackbar } from "@/components/Snackbar";
import { Section } from "./Section";

const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");

/** Audit chain verification, periodic access reviews and the break-glass account. */
export function ComplianceTab({ team }: { team: Team }) {
  return (
    <Stack spacing={2}>
      <AuditSection teamId={team.id} />
      <ReviewsSection teamId={team.id} />
      <BreakGlassSection teamId={team.id} />
    </Stack>
  );
}

function AuditSection({ teamId }: { teamId: Uuid }) {
  const snackbar = useSnackbar();
  const verify = useMutation({
    mutationFn: () => ipc.teamAuditVerify(teamId),
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const v = verify.data;
  return (
    <Section
      title={tr("Audit log integrity")}
      description={tr(
        "Every audit entry carries a hash chained to the previous one and the server signs the head hourly. Verification walks the whole chain and reports the first broken link.",
      )}
      actions={
        <Button variant="outlined" size="small" onClick={() => verify.mutate()} disabled={verify.isPending}>
          {verify.isPending ? tr("Verifying…") : tr("Verify now")}
        </Button>
      }
    >
      {v && (
        <Alert severity={v.ok ? "success" : "error"} variant="outlined">
          {v.ok
            ? trn(v.events, "{count} entry checked, chain intact.", "{count} entries checked, chain intact.")
            : tr("Chain broken at entry #{id} ({reason}).", {
                id: String(v.broken_at ?? "?"),
                reason: v.reason ?? "?",
              })}
          {v.checkpoint_ok === false && ` ${tr("The latest signed checkpoint does not match.")}`}
          {v.head_hash && (
            <Box sx={{ mt: 0.5 }}>
              <Mono sx={{ fontSize: 12, wordBreak: "break-all" }}>{v.head_hash}</Mono>
            </Box>
          )}
        </Alert>
      )}
    </Section>
  );
}

function ReviewsSection({ teamId }: { teamId: Uuid }) {
  const qc = useQueryClient();
  const snackbar = useSnackbar();
  const reviews = useQuery({
    queryKey: ["team", teamId, "access-reviews"],
    queryFn: () => ipc.teamAccessReviews(teamId),
  });
  const [openId, setOpenId] = useState<Uuid | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["team", teamId, "access-reviews"] });
  const open = useMutation({
    mutationFn: () => ipc.teamAccessReviewOpen(teamId),
    onSuccess: (d) => {
      refresh();
      setOpenId(d.review.id);
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const list = reviews.data?.reviews ?? [];
  const hasOpen = list.some((r) => r.status === "open");
  return (
    <Section
      title={tr("Access reviews")}
      description={tr(
        "A snapshot of every member and vault access for an admin to confirm or remove. Completing the review applies the removals through the usual paths and is recorded in the audit log.",
      )}
      actions={
        <Button variant="outlined" size="small" onClick={() => open.mutate()} disabled={open.isPending || hasOpen}>
          {tr("Start review")}
        </Button>
      }
    >
      {reviews.isPending ? (
        <Loading />
      ) : list.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {tr("No reviews yet. The access_review_days policy opens them on a schedule.")}
        </Typography>
      ) : (
        <Stack spacing={0.5}>
          {list.map((r) => (
            <ReviewRow key={r.id} review={r} onOpen={() => setOpenId(r.id)} />
          ))}
        </Stack>
      )}
      {openId && (
        <ReviewDialog
          teamId={teamId}
          reviewId={openId}
          onClose={() => {
            setOpenId(null);
            refresh();
          }}
        />
      )}
    </Section>
  );
}

function ReviewRow({ review: r, onOpen }: { review: AccessReview; onOpen: () => void }) {
  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "center",
        gap: 1.5,
        px: 1.5,
        py: 1,
        borderRadius: 2,
        bgcolor: "surface.high",
      }}
    >
      <Chip
        size="small"
        label={r.status}
        color={r.status === "open" ? "warning" : r.status === "completed" ? "success" : "default"}
      />
      <Typography variant="body2" sx={{ flex: 1 }}>
        {tr("Opened {date}, due {due}", { date: when(r.opened_at), due: when(r.due_at) })}
      </Typography>
      <Typography variant="caption" color="text.secondary">
        {tr("{decided}/{total} decided · {kept} kept · {removed} removed", {
          decided: String(r.decided),
          total: String(r.items),
          kept: String(r.kept),
          removed: String(r.removed),
        })}
      </Typography>
      <Button size="small" onClick={onOpen}>
        {r.status === "open" ? tr("Review") : tr("Details")}
      </Button>
    </Box>
  );
}

function ReviewDialog({ teamId, reviewId, onClose }: { teamId: Uuid; reviewId: Uuid; onClose: () => void }) {
  const qc = useQueryClient();
  const snackbar = useSnackbar();
  const key = ["team", teamId, "access-review", reviewId];
  const detail = useQuery({ queryKey: key, queryFn: () => ipc.teamAccessReview(teamId, reviewId) });
  const decide = useMutation({
    mutationFn: (p: { itemId: Uuid; decision: "keep" | "remove" }) =>
      ipc.teamAccessReviewDecide(teamId, reviewId, p.itemId, p.decision, null),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const complete = useMutation({
    mutationFn: () => ipc.teamAccessReviewComplete(teamId, reviewId, "keep"),
    onSuccess: () => {
      snackbar.notify(tr("Review completed"));
      onClose();
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const cancel = useMutation({
    mutationFn: () => ipc.teamAccessReviewCancel(teamId, reviewId),
    onSuccess: onClose,
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const [confirm, setConfirm] = useState(false);
  const d = detail.data;
  const isOpen = d?.review.status === "open";
  const removals = d?.items.filter((i) => i.decision === "remove").length ?? 0;
  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{tr("Access review")}</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
        {!d ? (
          <Loading />
        ) : (
          d.items.map((i) => (
            <Box key={i.id} sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography variant="body2" noWrap>
                  {i.display_name ?? i.email ?? i.user_id}
                  <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                    {i.kind === "member"
                      ? tr("team · {role}", { role: i.role })
                      : tr("{vault} · {role}", { vault: i.vault_name ?? "?", role: i.role })}
                  </Typography>
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {tr("Last seen {date}", { date: when(i.last_seen_at) })}
                </Typography>
              </Box>
              {isOpen ? (
                <>
                  <Button
                    size="small"
                    variant={i.decision === "keep" ? "contained" : "outlined"}
                    onClick={() => decide.mutate({ itemId: i.id, decision: "keep" })}
                  >
                    {tr("Keep")}
                  </Button>
                  <Button
                    size="small"
                    color="error"
                    variant={i.decision === "remove" ? "contained" : "outlined"}
                    onClick={() => decide.mutate({ itemId: i.id, decision: "remove" })}
                  >
                    {tr("Remove")}
                  </Button>
                </>
              ) : (
                <Chip size="small" label={i.decision ?? tr("undecided")} />
              )}
            </Box>
          ))
        )}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        {isOpen && (
          <Button color="error" onClick={() => cancel.mutate()} disabled={cancel.isPending}>
            {tr("Cancel review")}
          </Button>
        )}
        <Box sx={{ flex: 1 }} />
        <Button onClick={onClose}>{tr("Close")}</Button>
        {isOpen && (
          <Button variant="contained" onClick={() => setConfirm(true)} disabled={complete.isPending}>
            {tr("Complete")}
          </Button>
        )}
      </DialogActions>
      <ConfirmDialog
        open={confirm}
        title={tr("Complete the review?")}
        children={trn(
          removals,
          "{count} access will be removed; undecided items are kept.",
          "{count} accesses will be removed; undecided items are kept.",
        )}
        confirmLabel={tr("Complete")}
        danger={removals > 0}
        onCancel={() => setConfirm(false)}
        onConfirm={() => {
          setConfirm(false);
          complete.mutate();
        }}
      />
    </Dialog>
  );
}

function BreakGlassSection({ teamId }: { teamId: Uuid }) {
  const qc = useQueryClient();
  const snackbar = useSnackbar();
  const key = ["team", teamId, "break-glass"];
  const bg = useQuery({ queryKey: key, queryFn: () => ipc.teamBreakGlass(teamId) });
  const members = useTeamMembers(teamId);
  const [userId, setUserId] = useState("");
  const [hours, setHours] = useState(4);
  const [secret, setSecret] = useState<string | null>(null);
  const [useOpen, setUseOpen] = useState(false);
  const [useSecret, setUseSecret] = useState("");
  const [reason, setReason] = useState("");
  const refresh = () => void qc.invalidateQueries({ queryKey: key });
  const configure = useMutation({
    mutationFn: () => ipc.teamBreakGlassConfigure(teamId, userId, hours),
    onSuccess: (b) => {
      setSecret(b.secret ?? null);
      refresh();
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: () => ipc.teamBreakGlassDelete(teamId),
    onSuccess: refresh,
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const use = useMutation({
    mutationFn: () => ipc.teamBreakGlassUse(teamId, useSecret.trim(), reason.trim()),
    onSuccess: () => {
      setUseOpen(false);
      setUseSecret("");
      setReason("");
      snackbar.notify(tr("Emergency admin access granted"));
      refresh();
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const end = useMutation({
    mutationFn: () => ipc.teamBreakGlassEnd(teamId),
    onSuccess: refresh,
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const b = bg.data ?? null;
  const candidates = (members.data ?? []).filter((m) => m.role !== "owner");
  return (
    <Section
      title={tr("Break-glass account")}
      description={tr(
        "A member who can become an admin for a limited time with a one-time secret when no owner is reachable. Every use is audited with the reason and mailed to owners and admins.",
      )}
    >
      {bg.isPending ? (
        <Loading />
      ) : b ? (
        <Stack spacing={1}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <Chip size="small" label={b.status} color={b.status === "active" ? "warning" : "default"} />
            <Typography variant="body2" sx={{ flex: 1 }}>
              {b.email ?? b.user_id} · {trn(b.duration_hours, "{count} hour", "{count} hours")}
              {b.status === "active" && b.expires_at && ` · ${tr("until {date}", { date: when(b.expires_at) })}`}
            </Typography>
            {b.status === "active" ? (
              <Button size="small" color="warning" onClick={() => end.mutate()} disabled={end.isPending}>
                {tr("End now")}
              </Button>
            ) : (
              <Button size="small" onClick={() => setUseOpen(true)}>
                {tr("Use")}
              </Button>
            )}
            <Button size="small" color="error" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {tr("Remove")}
            </Button>
          </Box>
        </Stack>
      ) : (
        <Box sx={{ display: "flex", gap: 1.5, alignItems: "center", flexWrap: "wrap" }}>
          <TextField
            select
            size="small"
            label={tr("Member")}
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            sx={{ minWidth: 240 }}
          >
            {candidates.map((m) => (
              <MenuItem key={m.user_id} value={m.user_id}>
                {m.display_name ?? m.email}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            size="small"
            type="number"
            label={tr("Hours")}
            value={hours}
            onChange={(e) => setHours(Math.max(1, Math.min(72, Number(e.target.value) || 1)))}
            sx={{ width: 100 }}
          />
          <Button variant="contained" size="small" disabled={!userId || configure.isPending} onClick={() => configure.mutate()}>
            {tr("Arm")}
          </Button>
        </Box>
      )}
      <Dialog open={secret !== null} onClose={() => setSecret(null)} maxWidth="sm" fullWidth>
        <DialogTitle>{tr("Break-glass secret")}</DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          <Alert severity="warning" variant="outlined">
            {tr("Shown once. Store it offline (a sealed envelope, a safe) — the server keeps only a hash.")}
          </Alert>
          <Mono sx={{ fontSize: 14, wordBreak: "break-all", userSelect: "all" }}>{secret}</Mono>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button variant="contained" onClick={() => setSecret(null)}>
            {tr("I stored it")}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={useOpen} onClose={() => setUseOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{tr("Use the break-glass account")}</DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          <TextField
            autoFocus
            size="small"
            label={tr("Secret")}
            value={useSecret}
            onChange={(e) => setUseSecret(e.target.value)}
          />
          <TextField
            size="small"
            label={tr("Reason")}
            multiline
            minRows={2}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setUseOpen(false)}>{tr("Cancel")}</Button>
          <Button
            variant="contained"
            color="warning"
            disabled={!useSecret.trim() || !reason.trim() || use.isPending}
            onClick={() => use.mutate()}
          >
            {tr("Become admin")}
          </Button>
        </DialogActions>
      </Dialog>
    </Section>
  );
}
