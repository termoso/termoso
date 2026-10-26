import { useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  Chip,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
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
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { tr } from "@/i18n";
import * as ipc from "@/ipc/commands";
import {
  AUTOMATION_ALERT_ON,
  AUTOMATION_HOSTS_MAX,
  AUTOMATION_TIMEOUT_MAX,
  AUTOMATION_TIMEOUT_MIN,
  errorMessage,
  type Automation,
  type AutomationAlertOn,
  type AutomationRun,
  type CreateAutomationRequest,
  type HostRunResult,
  type Team,
  type Uuid,
} from "@/ipc/types";
import { Loading, Mono } from "@/components/ui";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { useSnackbar } from "@/components/Snackbar";
import { Section } from "./Section";
import { can } from "./roles";

const PRESETS: { key: string; label: () => string; expr: string }[] = [
  { key: "hourly", label: () => tr("Every hour"), expr: "0 * * * *" },
  { key: "daily", label: () => tr("Every day at 03:00"), expr: "0 3 * * *" },
  { key: "weekdays", label: () => tr("Weekdays at 08:00"), expr: "0 8 * * 1-5" },
  { key: "weekly", label: () => tr("Every Monday at 03:00"), expr: "0 3 * * 1" },
  { key: "monthly", label: () => tr("First day of the month at 03:00"), expr: "0 3 1 * *" },
];

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function fmt(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

function statusColor(s: string | null): "default" | "success" | "error" | "warning" | "info" {
  switch (s) {
    case "done":
      return "success";
    case "failed":
      return "error";
    case "missed":
    case "cancelled":
      return "warning";
    case "running":
    case "pending":
      return "info";
    default:
      return "default";
  }
}

function statusLabel(s: string | null): string {
  switch (s) {
    case "done":
      return tr("Done");
    case "failed":
      return tr("Failed");
    case "missed":
      return tr("Missed");
    case "cancelled":
      return tr("Cancelled");
    case "running":
      return tr("Running");
    case "pending":
      return tr("Pending");
    default:
      return tr("Never ran");
  }
}

function alertLabel(a: AutomationAlertOn): string {
  switch (a) {
    case "never":
      return tr("Never");
    case "failure":
      return tr("On failure");
    case "always":
      return tr("After every run");
  }
}

export function AutomationsTab({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const manage = can(team, "automations.manage");
  const key = ["team", team.id, "automations"];
  const q = useQuery({ queryKey: key, queryFn: () => ipc.teamAutomations(team.id) });
  const [editing, setEditing] = useState<Automation | "new" | null>(null);
  const [runsOf, setRunsOf] = useState<Automation | null>(null);
  const [deleting, setDeleting] = useState<Automation | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: key });

  const toggle = useMutation({
    mutationFn: (a: Automation) => ipc.teamAutomationUpdate(team.id, a.id, { enabled: !a.enabled }),
    onSuccess: refresh,
    onError: (e) => snack.error(errorMessage(e)),
  });
  const runNow = useMutation({
    mutationFn: (a: Automation) => ipc.teamAutomationRunNow(team.id, a.id),
    onSuccess: () => {
      snack.notify(
        tr("Run queued. It starts when an executor with the vault picks it up."),
        "success",
      );
      refresh();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (a: Automation) => ipc.teamAutomationDelete(team.id, a.id),
    onSuccess: () => {
      setDeleting(null);
      refresh();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  if (q.isLoading) return <Loading />;
  if (q.error) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const list = q.data?.automations ?? [];

  return (
    <Stack spacing={3}>
      <Section
        title={tr("Automations")}
        description={tr(
          "Run a snippet on a set of hosts on a schedule. The server only keeps the schedule and opaque ids: the snippet and host credentials are resolved by an executor that holds the vault key — the API bridge, or a member's desktop with “Run team automations” enabled in Settings.",
        )}
        actions={
          manage ? (
            <Button variant="contained" size="small" onClick={() => setEditing("new")}>
              {tr("New automation")}
            </Button>
          ) : undefined
        }
      >
        {list.length === 0 ? (
          <EmptyState
            title={tr("No automations yet")}
            description={tr(
              "Schedule a snippet on a group of hosts and get alerted when it fails.",
            )}
          />
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{tr("Name")}</TableCell>
                  <TableCell>{tr("Schedule")}</TableCell>
                  <TableCell>{tr("Next run")}</TableCell>
                  <TableCell>{tr("Last run")}</TableCell>
                  <TableCell align="right" />
                </TableRow>
              </TableHead>
              <TableBody>
                {list.map((a) => (
                  <TableRow key={a.id} hover>
                    <TableCell>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Typography variant="body2">{a.name}</Typography>
                        {!a.enabled && <Chip size="small" label={tr("Paused")} />}
                      </Stack>
                      <Typography variant="caption" color="text.secondary">
                        {a.host_ids.length > 0 && tr("{n} hosts", { n: String(a.host_ids.length) })}
                        {a.host_ids.length > 0 && a.group_id && " · "}
                        {a.group_id && tr("group")}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Mono>{a.schedule}</Mono>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: "block" }}
                      >
                        {a.timezone}
                      </Typography>
                    </TableCell>
                    <TableCell>{a.enabled ? fmt(a.next_run_at) : "—"}</TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Chip
                          size="small"
                          color={statusColor(a.last_status)}
                          label={statusLabel(a.last_status)}
                        />
                        <Typography variant="caption" color="text.secondary">
                          {fmt(a.last_run_at)}
                        </Typography>
                      </Stack>
                    </TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} sx={{ justifyContent: "flex-end" }}>
                        <Button size="small" onClick={() => setRunsOf(a)}>
                          {tr("History")}
                        </Button>
                        {manage && (
                          <>
                            <Button
                              size="small"
                              disabled={runNow.isPending}
                              onClick={() => runNow.mutate(a)}
                            >
                              {tr("Run now")}
                            </Button>
                            <Button size="small" onClick={() => toggle.mutate(a)}>
                              {a.enabled ? tr("Pause") : tr("Resume")}
                            </Button>
                            <Button size="small" onClick={() => setEditing(a)}>
                              {tr("Edit")}
                            </Button>
                            <Button size="small" color="error" onClick={() => setDeleting(a)}>
                              {tr("Delete")}
                            </Button>
                          </>
                        )}
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>

      {editing && (
        <AutomationDialog
          team={team}
          existing={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}
      {runsOf && <RunsDialog team={team} automation={runsOf} onClose={() => setRunsOf(null)} />}
      <ConfirmDialog
        open={!!deleting}
        title={tr("Delete automation?")}
        confirmLabel={tr("Delete")}
        danger
        busy={remove.isPending}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting);
        }}
      >
        {tr("Its run history is deleted too. Hosts and the snippet stay in the vault.")}
      </ConfirmDialog>
    </Stack>
  );
}

function AutomationDialog({
  team,
  existing,
  onClose,
  onSaved,
}: {
  team: Team;
  existing: Automation | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const snack = useSnackbar();
  const vaults = useQuery({ queryKey: ["vaults"], queryFn: ipc.vaultsList });
  const teamVaults = (vaults.data ?? []).filter((v) => v.team_id === team.id && v.unlocked);
  const [vaultId, setVaultId] = useState<string>(existing?.vault_id ?? teamVaults[0]?.id ?? "");
  const effectiveVault = vaultId !== "" ? vaultId : (teamVaults[0]?.id ?? "");
  const snippets = useQuery({
    queryKey: ["snippets", effectiveVault],
    queryFn: () => ipc.snippetsList(effectiveVault),
    enabled: !!effectiveVault,
  });
  const hosts = useQuery({
    queryKey: ["hosts", effectiveVault],
    queryFn: () => ipc.hostsList(effectiveVault),
    enabled: !!effectiveVault,
  });
  const groups = useQuery({
    queryKey: ["groups", effectiveVault],
    queryFn: () => ipc.groupsList(effectiveVault),
    enabled: !!effectiveVault,
  });

  const [name, setName] = useState(existing?.name ?? "");
  const [snippetId, setSnippetId] = useState<string>(existing?.snippet_id ?? "");
  const [hostIds, setHostIds] = useState<Uuid[]>(existing?.host_ids ?? []);
  const [groupId, setGroupId] = useState<string>(existing?.group_id ?? "");
  const initialPreset = PRESETS.find((p) => p.expr === (existing?.schedule ?? "0 3 * * *"));
  const [preset, setPreset] = useState<string>(initialPreset?.key ?? "custom");
  const [schedule, setSchedule] = useState(existing?.schedule ?? "0 3 * * *");
  const [timezone, setTimezone] = useState(existing?.timezone ?? "UTC");
  const [timeout, setTimeout_] = useState(String(existing?.timeout_secs ?? 300));
  const [alertOn, setAlertOn] = useState<AutomationAlertOn>(existing?.alert_on ?? "failure");
  const [alertEmails, setAlertEmails] = useState((existing?.alert_emails ?? []).join(", "));
  const [alertAdmins, setAlertAdmins] = useState(existing?.alert_admins ?? true);

  const emails = alertEmails
    .split(/[,\s]+/)
    .map((e) => e.trim())
    .filter(Boolean);
  const badEmail = emails.find((e) => !EMAIL.test(e));
  const timeoutNum = Number(timeout);
  const timeoutOk =
    Number.isInteger(timeoutNum) &&
    timeoutNum >= AUTOMATION_TIMEOUT_MIN &&
    timeoutNum <= AUTOMATION_TIMEOUT_MAX;
  const valid =
    name.trim().length > 0 &&
    !!effectiveVault &&
    !!snippetId &&
    (hostIds.length > 0 || !!groupId) &&
    hostIds.length <= AUTOMATION_HOSTS_MAX &&
    schedule.trim().length > 0 &&
    timeoutOk &&
    !badEmail;

  const save = useMutation({
    mutationFn: async () => {
      const body: CreateAutomationRequest = {
        vault_id: effectiveVault,
        snippet_id: snippetId,
        name: name.trim(),
        host_ids: hostIds,
        group_id: groupId || null,
        schedule: schedule.trim(),
        timezone: timezone.trim() || "UTC",
        timeout_secs: timeoutNum,
        alert_on: alertOn,
        alert_emails: emails,
        alert_admins: alertAdmins,
      };
      if (existing) {
        return ipc.teamAutomationUpdate(team.id, existing.id, {
          snippet_id: body.snippet_id,
          name: body.name,
          host_ids: body.host_ids,
          group_id: body.group_id,
          schedule: body.schedule,
          timezone: body.timezone,
          timeout_secs: body.timeout_secs,
          alert_on: body.alert_on,
          alert_emails: body.alert_emails,
          alert_admins: body.alert_admins,
        });
      }
      return ipc.teamAutomationCreate(team.id, body);
    },
    onSuccess: onSaved,
    onError: (e) => snack.error(errorMessage(e)),
  });

  const pickPreset = (k: string) => {
    setPreset(k);
    const p = PRESETS.find((x) => x.key === k);
    if (p) setSchedule(p.expr);
  };
  const toggleHost = (id: Uuid) =>
    setHostIds((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>{existing ? tr("Edit automation") : tr("New automation")}</DialogTitle>
      <DialogContent>
        {teamVaults.length === 0 && !existing ? (
          <Alert severity="warning">
            {tr("Unlock one of this team's vaults first: the snippet and hosts come from it.")}
          </Alert>
        ) : (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label={tr("Name")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              fullWidth
            />
            {!existing && teamVaults.length > 1 && (
              <TextField
                select
                label={tr("Vault")}
                value={effectiveVault}
                onChange={(e) => {
                  setVaultId(e.target.value);
                  setSnippetId("");
                  setHostIds([]);
                  setGroupId("");
                }}
                fullWidth
              >
                {teamVaults.map((v) => (
                  <MenuItem key={v.id} value={v.id}>
                    {v.name}
                  </MenuItem>
                ))}
              </TextField>
            )}
            <TextField
              select
              label={tr("Snippet")}
              value={snippetId}
              onChange={(e) => setSnippetId(e.target.value)}
              fullWidth
              helperText={
                snippets.data?.length === 0
                  ? tr("This vault has no snippets yet.")
                  : tr("Variables are not prompted for on a schedule; use fixed values.")
              }
            >
              {(snippets.data ?? []).map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  {s.label}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label={tr("Host group (all hosts inside, including subgroups)")}
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
              fullWidth
            >
              <MenuItem value="">{tr("None")}</MenuItem>
              {(groups.data ?? []).map((g) => (
                <MenuItem key={g.id} value={g.id}>
                  {g.label}
                </MenuItem>
              ))}
            </TextField>
            <div>
              <Typography variant="subtitle2" gutterBottom>
                {tr("Hosts")} ({hostIds.length})
              </Typography>
              <Stack sx={{ maxHeight: 220, overflow: "auto" }}>
                {(hosts.data ?? []).map((h) => (
                  <FormControlLabel
                    key={h.id}
                    control={
                      <Checkbox
                        size="small"
                        checked={hostIds.includes(h.id)}
                        onChange={() => toggleHost(h.id)}
                      />
                    }
                    label={
                      <span>
                        {h.label}{" "}
                        <Typography component="span" variant="caption" color="text.secondary">
                          {h.groupPath.join(" / ")}
                        </Typography>
                      </span>
                    }
                  />
                ))}
                {hosts.data?.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    {tr("This vault has no hosts.")}
                  </Typography>
                )}
              </Stack>
            </div>
            <Stack direction="row" spacing={2}>
              <TextField
                select
                label={tr("Schedule")}
                value={preset}
                onChange={(e) => pickPreset(e.target.value)}
                sx={{ minWidth: 240 }}
              >
                {PRESETS.map((p) => (
                  <MenuItem key={p.key} value={p.key}>
                    {p.label()}
                  </MenuItem>
                ))}
                <MenuItem value="custom">{tr("Custom (cron)")}</MenuItem>
              </TextField>
              <TextField
                label={tr("Cron expression")}
                value={schedule}
                onChange={(e) => {
                  setSchedule(e.target.value);
                  setPreset("custom");
                }}
                helperText={tr(
                  "minute hour day month weekday, or @hourly / @daily / @weekly / @monthly",
                )}
                fullWidth
                slotProps={{ input: { sx: { fontFamily: "monospace" } } }}
              />
              <TextField
                label={tr("Time zone")}
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                helperText={tr("UTC or a fixed offset like +03:00")}
                sx={{ minWidth: 160 }}
              />
            </Stack>
            <Stack direction="row" spacing={2}>
              <TextField
                label={tr("Timeout per host, seconds")}
                value={timeout}
                onChange={(e) => setTimeout_(e.target.value)}
                error={!timeoutOk}
                helperText={`${AUTOMATION_TIMEOUT_MIN}–${AUTOMATION_TIMEOUT_MAX}`}
                sx={{ minWidth: 200 }}
              />
              <TextField
                select
                label={tr("E-mail alert")}
                value={alertOn}
                onChange={(e) => setAlertOn(e.target.value as AutomationAlertOn)}
                sx={{ minWidth: 200 }}
              >
                {AUTOMATION_ALERT_ON.map((a) => (
                  <MenuItem key={a} value={a}>
                    {alertLabel(a)}
                  </MenuItem>
                ))}
              </TextField>
            </Stack>
            {alertOn !== "never" && (
              <>
                <TextField
                  label={tr("Extra recipients")}
                  value={alertEmails}
                  onChange={(e) => setAlertEmails(e.target.value)}
                  error={!!badEmail}
                  helperText={
                    badEmail
                      ? tr("Not an e-mail address: {v}", { v: badEmail })
                      : tr("Comma-separated. Audit events and webhooks fire regardless.")
                  }
                  fullWidth
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={alertAdmins}
                      onChange={(e) => setAlertAdmins(e.target.checked)}
                    />
                  }
                  label={tr("Also e-mail team owners and admins")}
                />
              </>
            )}
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button
          variant="contained"
          disabled={!valid || save.isPending}
          onClick={() => save.mutate()}
        >
          {existing ? tr("Save") : tr("Create")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function RunsDialog({
  team,
  automation,
  onClose,
}: {
  team: Team;
  automation: Automation;
  onClose: () => void;
}) {
  const q = useQuery({
    queryKey: ["team", team.id, "automations", automation.id, "runs"],
    queryFn: () => ipc.teamAutomationRuns(team.id, automation.id),
    refetchInterval: 10_000,
  });
  const [open, setOpen] = useState<Uuid | null>(null);
  const runs = q.data?.runs ?? [];
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>{tr("Run history: {name}", { name: automation.name })}</DialogTitle>
      <DialogContent>
        {q.isLoading ? (
          <Loading />
        ) : runs.length === 0 ? (
          <EmptyState title={tr("No runs yet")} />
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{tr("Scheduled")}</TableCell>
                  <TableCell>{tr("Status")}</TableCell>
                  <TableCell>{tr("Hosts")}</TableCell>
                  <TableCell>{tr("Executor")}</TableCell>
                  <TableCell>{tr("Finished")}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {runs.map((r) => (
                  <RunRow
                    key={r.id}
                    run={r}
                    open={open === r.id}
                    onToggle={() => setOpen(open === r.id ? null : r.id)}
                  />
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Close")}</Button>
      </DialogActions>
    </Dialog>
  );
}

function RunRow({
  run,
  open,
  onToggle,
}: {
  run: AutomationRun;
  open: boolean;
  onToggle: () => void;
}) {
  const locked = !!run.sealed && run.results.length === 0;
  const expandable = run.results.length > 0 || !!run.error || locked;
  return (
    <>
      <TableRow
        hover
        sx={{ cursor: expandable ? "pointer" : undefined }}
        onClick={expandable ? onToggle : undefined}
      >
        <TableCell>
          {fmt(run.scheduled_for)}
          {run.manual && (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
              {tr("manual")}
            </Typography>
          )}
        </TableCell>
        <TableCell>
          <Chip size="small" color={statusColor(run.status)} label={statusLabel(run.status)} />
        </TableCell>
        <TableCell>
          {run.hosts_total > 0
            ? run.hosts_failed > 0
              ? tr("{failed} of {total} failed", {
                  failed: String(run.hosts_failed),
                  total: String(run.hosts_total),
                })
              : tr("{total} ok", { total: String(run.hosts_total) })
            : "—"}
        </TableCell>
        <TableCell>{run.claimed_by_name ?? "—"}</TableCell>
        <TableCell>
          {fmt(run.finished_at)}
          {expandable && (
            <IconButton
              size="small"
              sx={{ ml: 1 }}
              aria-label={open ? tr("Collapse") : tr("Expand")}
            >
              {open ? "▾" : "▸"}
            </IconButton>
          )}
        </TableCell>
      </TableRow>
      {expandable && (
        <TableRow>
          <TableCell colSpan={5} sx={{ p: 0, borderBottom: open ? undefined : 0 }}>
            <Collapse in={open} unmountOnExit>
              <Stack spacing={1.5} sx={{ p: 2 }}>
                {run.error && <Alert severity="error">{run.error}</Alert>}
                {locked && (
                  <Alert severity="info">
                    {tr("Per-host output is encrypted with the vault key — unlock the vault to see it.")}
                  </Alert>
                )}
                {run.results.map((r) => (
                  <HostResult key={r.host_id} r={r} />
                ))}
              </Stack>
            </Collapse>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function HostResult({ r }: { r: HostRunResult }) {
  const ok = !r.error && r.exit_code === 0;
  return (
    <div>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <Chip
          size="small"
          color={ok ? "success" : "error"}
          label={r.error ? tr("Error") : tr("exit {code}", { code: String(r.exit_code ?? "?") })}
        />
        <Typography variant="body2">{r.label}</Typography>
        <Typography variant="caption" color="text.secondary">
          {r.target} · {(r.ms / 1000).toFixed(1)}s
        </Typography>
      </Stack>
      {r.error && (
        <Typography variant="body2" color="error">
          {r.error}
        </Typography>
      )}
      {r.stdout && (
        <Mono sx={{ whiteSpace: "pre-wrap", display: "block", mt: 0.5 }}>{r.stdout}</Mono>
      )}
      {r.stderr && (
        <Mono sx={{ whiteSpace: "pre-wrap", display: "block", mt: 0.5, color: "error.main" }}>
          {r.stderr}
        </Mono>
      )}
    </div>
  );
}
