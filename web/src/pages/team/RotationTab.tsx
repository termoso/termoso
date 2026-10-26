import { useMemo, useState } from "react";
import { tr } from "@/i18n";
import {
  Alert,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
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
import AutorenewRoundedIcon from "@mui/icons-material/AutorenewRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { teamsApi, vaultsApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { RotationDue, RotationJob, Team } from "@/api/types";
import { Paged } from "@/components/Pager";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { formatDate, formatRelative } from "@/components/format";

const KIND: Record<string, () => string> = {
  key: () => tr("SSH key"),
  certificate: () => tr("Certificate"),
  identity: () => tr("Identity"),
  host: () => tr("Host password"),
};

const JOB: Record<
  RotationJob["status"],
  { label: () => string; color: "default" | "warning" | "info" | "success" | "error" }
> = {
  pending: { label: () => tr("Queued"), color: "warning" },
  running: { label: () => tr("Running"), color: "info" },
  done: { label: () => tr("Done"), color: "success" },
  failed: { label: () => tr("Failed"), color: "error" },
  cancelled: { label: () => tr("Cancelled"), color: "default" },
};

export function RotationTab({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const q = useQuery({
    queryKey: queryKeys.teamRotation(team.id),
    queryFn: () => teamsApi.rotation(team.id),
  });
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [queueing, setQueueing] = useState(false);
  const [note, setNote] = useState("");
  const refresh = () => qc.invalidateQueries({ queryKey: queryKeys.teamRotation(team.id) });
  const vaultName = (id: string) =>
    vaults.data?.vaults.find((v) => v.id === id)?.name ?? id.slice(0, 8);
  const create = useMutation({
    mutationFn: async () => {
      const due = q.data?.due ?? [];
      const byVault = new Map<string, string[]>();
      for (const d of due)
        if (selected.has(d.entity_id))
          byVault.set(d.vault_id, [...(byVault.get(d.vault_id) ?? []), d.entity_id]);
      for (const [vault_id, entity_ids] of byVault)
        await teamsApi.createRotationJobs(team.id, { vault_id, entity_ids, note: note.trim() });
      return byVault.size;
    },
    onSuccess: async () => {
      await refresh();
      setSelected(new Set());
      setQueueing(false);
      setNote("");
      snack.notify(
        tr("Rotation jobs queued; a client with write access to the vault will perform them"),
      );
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const cancel = useMutation({
    mutationFn: (j: RotationJob) => teamsApi.cancelRotationJob(j.id),
    onSuccess: refresh,
    onError: (e) => snack.error(errorMessage(e)),
  });
  const dueSorted = useMemo(
    () => [...(q.data?.due ?? [])].sort((a, b) => b.age_days - a.age_days),
    [q.data],
  );
  if (q.isPending) return <Loading />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const o = q.data;
  const policyOff = o.key_max_age_days === 0 && o.password_max_age_days === 0;
  const toggle = (d: RotationDue) => {
    const next = new Set(selected);
    if (next.has(d.entity_id)) next.delete(d.entity_id);
    else next.add(d.entity_id);
    setSelected(next);
  };
  const selectable = dueSorted.filter((d) => !d.job_id);
  const allSelected = selectable.length > 0 && selectable.every((d) => selected.has(d.entity_id));
  return (
    <Stack spacing={2}>
      {policyOff && (
        <Alert severity="info">
          {tr(
            "Rotation ages are not set in the team policies, so nothing is reported as due. Set “Key rotation age” or “Password rotation age” to start tracking.",
          )}
        </Alert>
      )}
      <Section
        title={tr("Due for rotation")}
        description={tr(
          "Secrets older than the policy allows. The server only sees when a secret was last rotated — never the secret itself. Queue a job and a client with write access to the vault generates the new key, deploys it to the host and replaces it in the vault.",
        )}
        actions={
          selected.size > 0 && (
            <Button variant="contained" onClick={() => setQueueing(true)}>
              {tr("Queue rotation ({v1})", { v1: selected.size })}
            </Button>
          )
        }
      >
        {dueSorted.length === 0 ? (
          <EmptyState
            icon={<AutorenewRoundedIcon fontSize="inherit" />}
            title={tr("Nothing is due")}
          />
        ) : (
          <Paged items={dueSorted}>
            {(page) => (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell padding="checkbox">
                        <Checkbox
                          size="small"
                          checked={allSelected}
                          indeterminate={selected.size > 0 && !allSelected}
                          onChange={() =>
                            setSelected(
                              allSelected ? new Set() : new Set(selectable.map((d) => d.entity_id)),
                            )
                          }
                        />
                      </TableCell>
                      <TableCell>{tr("Kind")}</TableCell>
                      <TableCell>{tr("Vault")}</TableCell>
                      <TableCell align="right">{tr("Age")}</TableCell>
                      <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                        {tr("Last rotated")}
                      </TableCell>
                      <TableCell>{tr("Status")}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {page.map((d) => (
                      <TableRow key={d.entity_id} hover>
                        <TableCell padding="checkbox">
                          <Checkbox
                            size="small"
                            disabled={!!d.job_id}
                            checked={selected.has(d.entity_id)}
                            onChange={() => toggle(d)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {(KIND[d.kind] ?? (() => d.kind))()}
                          </Typography>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ fontFamily: "monospace" }}
                          >
                            {d.entity_id.slice(0, 8)}
                          </Typography>
                        </TableCell>
                        <TableCell>{vaultName(d.vault_id)}</TableCell>
                        <TableCell align="right">{tr("{v1} days", { v1: d.age_days })}</TableCell>
                        <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                          {d.secret_rotated_at ? formatDate(d.secret_rotated_at) : tr("Never")}
                        </TableCell>
                        <TableCell>
                          {d.job_id ? (
                            <Chip size="small" color="warning" label={tr("Job queued")} />
                          ) : (
                            <Chip
                              size="small"
                              color="error"
                              variant="outlined"
                              label={tr("Overdue")}
                            />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paged>
        )}
      </Section>
      <Section
        title={tr("Rotation jobs")}
        description={tr(
          "Names of hosts and keys are encrypted; the cabinet shows entity IDs, the desktop and mobile clients show names.",
        )}
      >
        {o.jobs.length === 0 ? (
          <EmptyState title={tr("No jobs yet")} />
        ) : (
          <Paged items={o.jobs}>
            {(page) => (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>{tr("Entity")}</TableCell>
                      <TableCell>{tr("Vault")}</TableCell>
                      <TableCell>{tr("Status")}</TableCell>
                      <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                        {tr("Requested")}
                      </TableCell>
                      <TableCell align="right" />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {page.map((j) => {
                      const st = JOB[j.status];
                      return (
                        <TableRow key={j.id} hover>
                          <TableCell>
                            <Typography variant="body2">
                              {(KIND[j.entity_kind] ?? (() => j.entity_kind))()}
                            </Typography>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                              sx={{ fontFamily: "monospace" }}
                            >
                              {j.entity_id.slice(0, 8)}
                              {j.note ? ` · ${j.note}` : ""}
                            </Typography>
                          </TableCell>
                          <TableCell>{vaultName(j.vault_id)}</TableCell>
                          <TableCell>
                            <Chip
                              size="small"
                              color={st.color}
                              variant={st.color === "default" ? "outlined" : "filled"}
                              label={st.label()}
                            />
                            {j.error && (
                              <Typography variant="caption" color="error" sx={{ display: "block" }}>
                                {j.error}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                            <Typography variant="body2">{j.requested_by_email}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {formatRelative(j.created_at)}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            {(j.status === "pending" || j.status === "running") && (
                              <Button
                                size="small"
                                color="error"
                                disabled={cancel.isPending}
                                onClick={() => cancel.mutate(j)}
                              >
                                {tr("Cancel")}
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paged>
        )}
      </Section>
      <Dialog open={queueing} onClose={() => setQueueing(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{tr("Queue rotation")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {tr(
                "{v1} secrets will be rotated by the next client with write access to their vaults. Members are not interrupted; old keys stop working once the new ones are deployed.",
                { v1: selected.size },
              )}
            </Typography>
            <TextField
              size="small"
              label={tr("Note (optional)")}
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQueueing(false)}>{tr("Cancel")}</Button>
          <Button variant="contained" disabled={create.isPending} onClick={() => create.mutate()}>
            {tr("Queue")}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
