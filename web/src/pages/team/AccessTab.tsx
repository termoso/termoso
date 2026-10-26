import { useState, type ReactNode } from "react";
import { tr } from "@/i18n";
import {
  Alert,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { teamsApi, vaultsApi } from "@/api/endpoints";
import { queryKeys, useAccount } from "@/api/hooks";
import type { AccessRequest, AccessRole, Team } from "@/api/types";
import { useServerPager } from "@/components/Pager";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { formatDateTime, formatRelative } from "@/components/format";

const STATUS: Record<
  AccessRequest["status"],
  { label: () => string; color: "default" | "warning" | "success" | "error" }
> = {
  pending: { label: () => tr("Pending"), color: "warning" },
  approved: { label: () => tr("Active"), color: "success" },
  denied: { label: () => tr("Denied"), color: "error" },
  revoked: { label: () => tr("Revoked"), color: "default" },
  expired: { label: () => tr("Expired"), color: "default" },
  cancelled: { label: () => tr("Cancelled"), color: "default" },
};

export function AccessTab({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const me = useAccount().data?.user.id;
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list });
  const [creating, setCreating] = useState(false);
  const [deciding, setDeciding] = useState<AccessRequest | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: queryKeys.teamAccess(team.id) });
  const act = useMutation({
    mutationFn: ({
      r,
      op,
      note,
    }: {
      r: AccessRequest;
      op: "cancel" | "deny" | "revoke";
      note?: string;
    }) =>
      op === "cancel"
        ? teamsApi.cancelAccessRequest(team.id, r.id)
        : op === "deny"
          ? teamsApi.denyAccessRequest(team.id, r.id, note)
          : teamsApi.revokeAccessRequest(team.id, r.id, note),
    onSuccess: async () => {
      await refresh();
      await qc.invalidateQueries({ queryKey: queryKeys.vaults });
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const teamVaults = (vaults.data?.vaults ?? []).filter((v) => v.team_id === team.id);
  return (
    <Stack spacing={2}>
      <RequestTable
        team={team}
        status="open"
        me={me}
        empty={
          <EmptyState icon={<KeyRoundedIcon fontSize="inherit" />} title={tr("No open requests")} />
        }
        onDecide={setDeciding}
        onAct={(a) => act.mutate(a)}
      >
        {(table) => (
          <Section
            title={tr("Access requests")}
            description={tr(
              "Temporary (just-in-time) access to a team vault: a member asks for viewer or editor rights for a number of hours, an approver grants them, and the server removes the membership when the time is up. Approval needs a manager's client to seal the vault key for the member.",
            )}
            actions={
              teamVaults.length > 0 && (
                <Button variant="contained" onClick={() => setCreating(true)}>
                  {tr("Request access")}
                </Button>
              )
            }
          >
            {table}
          </Section>
        )}
      </RequestTable>
      <RequestTable
        team={team}
        status="closed"
        me={me}
        onDecide={setDeciding}
        onAct={(a) => act.mutate(a)}
      >
        {(table) => <Section title={tr("History")}>{table}</Section>}
      </RequestTable>
      <RequestDialog
        open={creating}
        team={team}
        vaults={teamVaults.map((v) => ({ id: v.id, name: v.name }))}
        onClose={() => setCreating(false)}
        onDone={() => {
          setCreating(false);
          void refresh();
        }}
      />
      <DecideDialog
        request={deciding}
        team={team}
        onClose={() => setDeciding(null)}
        onDone={() => {
          setDeciding(null);
          void refresh();
          void qc.invalidateQueries({ queryKey: queryKeys.vaults });
        }}
      />
    </Stack>
  );
}

function RequestDialog({
  open,
  team,
  vaults,
  onClose,
  onDone,
}: {
  open: boolean;
  team: Team;
  vaults: { id: string; name: string }[];
  onClose: () => void;
  onDone: () => void;
}) {
  const snack = useSnackbar();
  const [vault, setVault] = useState(vaults[0]?.id ?? "");
  const [role, setRole] = useState<AccessRole>("viewer");
  const [hours, setHours] = useState(8);
  const [reason, setReason] = useState("");
  const m = useMutation({
    mutationFn: () =>
      teamsApi.createAccessRequest(team.id, {
        vault_id: vault !== "" ? vault : (vaults[0]?.id ?? ""),
        role,
        hours,
        reason,
      }),
    onSuccess: () => {
      snack.notify(tr("Request sent to the approvers"));
      setReason("");
      onDone();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{tr("Request access")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <TextField
            select
            size="small"
            label={tr("Vault")}
            value={vault !== "" ? vault : (vaults[0]?.id ?? "")}
            onChange={(e) => setVault(e.target.value)}
          >
            {vaults.map((v) => (
              <MenuItem key={v.id} value={v.id}>
                {v.name}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            select
            size="small"
            label={tr("Access")}
            value={role}
            onChange={(e) => setRole(e.target.value as AccessRole)}
          >
            <MenuItem value="viewer">{tr("Viewer")}</MenuItem>
            <MenuItem value="editor">{tr("Editor")}</MenuItem>
          </TextField>
          <TextField
            size="small"
            type="number"
            label={tr("Hours")}
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            slotProps={{ htmlInput: { min: 1, max: 720 } }}
          />
          <TextField
            size="small"
            multiline
            minRows={2}
            label={tr("Reason")}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            helperText={tr("Shown to the approvers and kept in the audit log.")}
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button
          variant="contained"
          disabled={!reason.trim() || hours < 1 || m.isPending}
          onClick={() => m.mutate()}
        >
          {tr("Send")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function DecideDialog({
  request,
  team,
  onClose,
  onDone,
}: {
  request: AccessRequest | null;
  team: Team;
  onClose: () => void;
  onDone: () => void;
}) {
  const snack = useSnackbar();
  const [hours, setHours] = useState<number | null>(null);
  const [role, setRole] = useState<AccessRole | null>(null);
  const [note, setNote] = useState("");
  const m = useMutation({
    mutationFn: () => {
      if (!request) return Promise.reject(new Error("no request"));
      return teamsApi.approveAccessRequest(team.id, request.id, {
        hours: hours ?? undefined,
        role: role ?? undefined,
        note: note.trim() || undefined,
      });
    },
    onSuccess: () => {
      snack.notify(
        tr(
          "Access granted — open the vault in a desktop or mobile client to seal the key for the member.",
        ),
      );
      setHours(null);
      setRole(null);
      setNote("");
      onDone();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  if (!request) return null;
  return (
    <Dialog open onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{tr("Approve access")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <Typography variant="body2" color="text.secondary">
            {tr("{v1} asks for {v2} access to {v3} for {v4} h: {v5}", {
              v1: request.user_email,
              v2: request.role === "editor" ? tr("editor") : tr("viewer"),
              v3: request.vault_name,
              v4: request.hours,
              v5: request.reason,
            })}
          </Typography>
          <TextField
            select
            size="small"
            label={tr("Access")}
            value={role ?? request.role}
            onChange={(e) => setRole(e.target.value as AccessRole)}
          >
            <MenuItem value="viewer">{tr("Viewer")}</MenuItem>
            <MenuItem value="editor">{tr("Editor")}</MenuItem>
          </TextField>
          <TextField
            size="small"
            type="number"
            label={tr("Hours")}
            value={hours ?? request.hours}
            onChange={(e) => setHours(Number(e.target.value))}
            slotProps={{ htmlInput: { min: 1, max: request.hours } }}
            helperText={tr("You can shorten the request, not extend it.")}
          />
          <TextField
            size="small"
            label={tr("Note (optional)")}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button variant="contained" disabled={m.isPending} onClick={() => m.mutate()}>
          {tr("Approve")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function RequestTable({
  team,
  status,
  me,
  empty,
  onDecide,
  onAct,
  children,
}: {
  team: Team;
  status: "open" | "closed";
  me: string | undefined;
  empty?: ReactNode;
  onDecide: (r: AccessRequest) => void;
  onAct: (a: { r: AccessRequest; op: "deny" | "cancel" | "revoke" }) => void;
  children: (table: ReactNode) => ReactNode;
}) {
  const pg = useServerPager();
  const q = useQuery({
    queryKey: [...queryKeys.teamAccess(team.id), status, pg.offset, pg.limit],
    queryFn: () => teamsApi.accessRequests(team.id, { status, ...pg.window }),
    placeholderData: (prev) => prev,
  });
  if (q.isPending) return children(<Loading minHeight={80} />);
  if (q.isError) return children(<Alert severity="error">{errorMessage(q.error)}</Alert>);
  const rows = q.data.requests;
  if (q.data.total === 0) return empty === undefined ? null : children(empty);
  return children(
    <>
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>{tr("Member")}</TableCell>
              <TableCell>{tr("Vault")}</TableCell>
              <TableCell>{tr("Access")}</TableCell>
              <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                {tr("Reason")}
              </TableCell>
              <TableCell>{tr("Status")}</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((r) => {
              const st = STATUS[r.status];
              const mine = r.user_id === me;
              return (
                <TableRow key={r.id} hover>
                  <TableCell>{mine ? tr("You") : r.user_email}</TableCell>
                  <TableCell>{r.vault_name}</TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {r.role === "editor" ? tr("Editor") : tr("Viewer")} ·{" "}
                      {tr("{v1} h", { v1: r.hours })}
                    </Typography>
                    {r.expires_at && r.status === "approved" && (
                      <Typography variant="caption" color="text.secondary">
                        {tr("until {v1}", { v1: formatDateTime(r.expires_at) })}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell sx={{ display: { xs: "none", md: "table-cell" }, maxWidth: 280 }}>
                    <Typography variant="body2" noWrap title={r.reason}>
                      {r.reason}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {formatRelative(r.created_at)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      color={st.color}
                      variant={st.color === "default" ? "outlined" : "filled"}
                      label={st.label()}
                    />
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} sx={{ justifyContent: "flex-end" }}>
                      {r.status === "pending" && q.data.can_approve && (
                        <>
                          <Button size="small" variant="contained" onClick={() => onDecide(r)}>
                            {tr("Approve")}
                          </Button>
                          <Button
                            size="small"
                            color="error"
                            onClick={() => onAct({ r, op: "deny" })}
                          >
                            {tr("Deny")}
                          </Button>
                        </>
                      )}
                      {r.status === "pending" && mine && (
                        <Button size="small" onClick={() => onAct({ r, op: "cancel" })}>
                          {tr("Withdraw")}
                        </Button>
                      )}
                      {r.status === "approved" && q.data.can_approve && (
                        <Button
                          size="small"
                          color="error"
                          onClick={() => onAct({ r, op: "revoke" })}
                        >
                          {tr("Revoke")}
                        </Button>
                      )}
                    </Stack>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
      {pg.pager(q.data.total)}
    </>,
  );
}
