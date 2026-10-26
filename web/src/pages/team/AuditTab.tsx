import { useState } from "react";
import { msg, tr, trn, trx } from "@/i18n";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import SendRoundedIcon from "@mui/icons-material/SendRounded";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { teamsApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { AuditEvent, Team, Webhook, WebhookKind } from "@/api/types";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { saveBlob } from "@/components/download";
import { useSnackbar } from "@/components/Snackbar";
import { UserCell } from "@/components/UserCell";
import { formatDateTime, formatRelative } from "@/components/format";
import { can } from "./perm";

export function AuditTab({ team }: { team: Team }) {
  return (
    <>
      {can(team, "audit.view") && <AuditSection team={team} />}
      {can(team, "webhooks.manage") && <WebhooksSection team={team} />}
    </>
  );
}

const KINDS: { value: WebhookKind; label: string; hint: string }[] = [
  {
    value: "generic",
    label: msg("Generic JSON (HMAC)"),
    hint: msg("POST batches signed with X-Termoso-Signature"),
  },
  { value: "splunk_hec", label: msg("Splunk HEC"), hint: msg("secret = HEC token") },
  {
    value: "elastic",
    label: msg("Elasticsearch / OpenSearch"),
    hint: msg("bulk NDJSON; secret = API key"),
  },
  { value: "datadog", label: msg("Datadog Logs"), hint: msg("secret = API key") },
  {
    value: "syslog_tls",
    label: msg("Syslog over TLS (CEF)"),
    hint: msg("syslog+tls://host:6514; no secret"),
  },
];

function AuditSection({ team }: { team: Team }) {
  const [action, setAction] = useState("");
  const [applied, setApplied] = useState("");
  const snack = useSnackbar();
  const q = useInfiniteQuery({
    queryKey: queryKeys.teamAudit(team.id, applied),
    queryFn: ({ pageParam }) =>
      teamsApi.audit(team.id, { before: pageParam, limit: 100, action: applied || undefined }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before ?? undefined,
  });
  const [exporting, setExporting] = useState<"csv" | "jsonl" | null>(null);
  const exportAs = async (format: "csv" | "jsonl") => {
    setExporting(format);
    try {
      const blob = await teamsApi.auditExport(team.id, { format, action: applied || undefined });
      if (!blob) return;
      saveBlob(blob, `termoso-audit-${team.name.replace(/\W+/g, "-")}.${format}`);
    } catch (e) {
      snack.error(errorMessage(e));
    } finally {
      setExporting(null);
    }
  };
  const events = q.data?.pages.flatMap((p) => p.events) ?? [];
  return (
    <Section
      title={tr("Audit log")}
      description={tr(
        "Who did what in this team. Filter by action (exact, or a family like “vault.”); export up to a million rows as CSV or JSON Lines.",
      )}
      actions={
        can(team, "audit.export") && (
          <Stack direction="row" spacing={1}>
            <Button
              startIcon={<DownloadRoundedIcon />}
              disabled={exporting !== null}
              onClick={() => exportAs("csv")}
            >
              {tr("CSV")}
            </Button>
            <Button
              startIcon={<DownloadRoundedIcon />}
              disabled={exporting !== null}
              onClick={() => exportAs("jsonl")}
            >
              {tr("JSONL")}
            </Button>
          </Stack>
        )
      }
      disablePadding
    >
      <Box
        component="form"
        onSubmit={(e) => {
          e.preventDefault();
          setApplied(action.trim());
        }}
        sx={{ p: 2, display: "flex", gap: 1, alignItems: "center" }}
      >
        <TextField
          size="small"
          label={tr("Action")}
          placeholder={tr("vault. / member.removed")}
          value={action}
          onChange={(e) => setAction(e.target.value)}
          sx={{ width: 280 }}
        />
        <Button type="submit" variant="outlined" size="small" sx={{ flexShrink: 0 }}>
          {tr("Filter")}
        </Button>
      </Box>
      {q.isPending ? (
        <Loading minHeight={120} />
      ) : q.isError ? (
        <Box sx={{ p: 3 }}>
          <Alert severity="error">{errorMessage(q.error)}</Alert>
        </Box>
      ) : events.length === 0 ? (
        <EmptyState title={tr("No events")} />
      ) : (
        <>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{tr("When")}</TableCell>
                  <TableCell>{tr("Actor")}</TableCell>
                  <TableCell>{tr("Action")}</TableCell>
                  <TableCell>{tr("Details")}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {events.map((e) => (
                  <EventRow key={e.id} e={e} />
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          {q.hasNextPage && (
            <Box sx={{ p: 2, textAlign: "center" }}>
              <Button disabled={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>
                {tr("Load older")}
              </Button>
            </Box>
          )}
        </>
      )}
    </Section>
  );
}

function EventRow({ e }: { e: AuditEvent }) {
  const details =
    e.details && typeof e.details === "object" && Object.keys(e.details).length > 0
      ? JSON.stringify(e.details)
      : "";
  return (
    <TableRow hover>
      <TableCell sx={{ whiteSpace: "nowrap" }}>
        <Tooltip title={formatDateTime(e.created_at)}>
          <span>{formatRelative(e.created_at)}</span>
        </Tooltip>
      </TableCell>
      <TableCell>
        {e.actor_id ? (
          <UserCell
            userId={e.actor_id}
            email={e.actor_email ?? ""}
            displayName={e.actor_name}
            avatar={e.actor_avatar}
          />
        ) : (
          <Typography variant="body2" color="text.secondary">
            {tr("system")}
          </Typography>
        )}
      </TableCell>
      <TableCell>
        <Chip size="small" label={e.action} sx={{ fontFamily: "monospace" }} />
        {e.target_email && (
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            → {e.target_email}
          </Typography>
        )}
      </TableCell>
      <TableCell sx={{ maxWidth: 420 }}>
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ fontFamily: "monospace", wordBreak: "break-all" }}
        >
          {details}
        </Typography>
      </TableCell>
    </TableRow>
  );
}

function WebhooksSection({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const q = useQuery({
    queryKey: queryKeys.teamWebhooks(team.id),
    queryFn: () => teamsApi.webhooks(team.id),
  });
  const [createOpen, setCreateOpen] = useState(false);
  const [deleting, setDeleting] = useState<Webhook | null>(null);
  const [history, setHistory] = useState<Webhook | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: queryKeys.teamWebhooks(team.id) });
  const toggle = useMutation({
    mutationFn: (w: Webhook) => teamsApi.updateWebhook(team.id, w.id, { enabled: !w.enabled }),
    onSuccess: invalidate,
    onError: (e) => snack.error(errorMessage(e)),
  });
  const test = useMutation({
    mutationFn: (w: Webhook) => teamsApi.testWebhook(team.id, w.id),
    onSuccess: async (r, w) => {
      await invalidate();
      const ok = r.deliveries.filter((d) => d.status === "ok").length;
      snack.notify(tr("{ok}/{total} deliveries succeeded", { ok, total: r.deliveries.length }));
      setHistory(w);
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (w: Webhook) => teamsApi.deleteWebhook(team.id, w.id),
    onSuccess: async () => {
      setDeleting(null);
      await invalidate();
      snack.notify(tr("Webhook deleted"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  if (q.isPending) return <Loading minHeight={120} />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const hooks = q.data.webhooks;
  return (
    <Section
      title={tr("Webhooks / SIEM")}
      description={tr(
        "Every audit event is queued per webhook and delivered in batches with retries (30 s → 6 h). A hook is switched off after 50 consecutive failures and everyone who can manage webhooks is e-mailed. Up to 10 per team.",
      )}
      actions={
        <Button
          startIcon={<AddRoundedIcon />}
          disabled={hooks.length >= 10}
          onClick={() => setCreateOpen(true)}
        >
          {tr("Add webhook")}
        </Button>
      }
      disablePadding={hooks.length > 0}
    >
      {hooks.length === 0 ? (
        <EmptyState
          title={tr("No webhooks")}
          description={tr("Stream the audit log to your SIEM.")}
        />
      ) : (
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>{tr("Destination")}</TableCell>
                <TableCell>{tr("Kind")}</TableCell>
                <TableCell>{tr("Last delivery")}</TableCell>
                <TableCell>{tr("On")}</TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {hooks.map((w) => (
                <TableRow key={w.id} hover>
                  <TableCell sx={{ maxWidth: 360 }}>
                    <Typography variant="body2" noWrap title={w.url}>
                      {w.url}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {w.actions?.length ? w.actions.join(", ") : tr("all events")}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {tr(KINDS.find((k) => k.value === w.kind)?.label ?? w.kind)}
                  </TableCell>
                  <TableCell>
                    {w.last_delivered_at ? (
                      <Tooltip title={formatDateTime(w.last_delivered_at)}>
                        <span>{formatRelative(w.last_delivered_at)}</span>
                      </Tooltip>
                    ) : (
                      <Typography variant="caption" color="text.secondary">
                        {tr("never")}
                      </Typography>
                    )}
                    {w.failures > 0 && (
                      <Tooltip title={w.last_error ?? ""}>
                        <Chip
                          size="small"
                          color={w.enabled ? "warning" : "error"}
                          label={trn(w.failures, "{count} failure", "{count} failures")}
                          sx={{ ml: 1 }}
                        />
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell>
                    <Switch
                      size="small"
                      checked={w.enabled}
                      disabled={toggle.isPending}
                      onChange={() => toggle.mutate(w)}
                      slotProps={{ input: { "aria-label": tr("Enabled") } }}
                    />
                  </TableCell>
                  <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>
                    <Tooltip title={tr("Send a test event and flush the queue")}>
                      <IconButton
                        size="small"
                        disabled={test.isPending}
                        onClick={() => test.mutate(w)}
                        aria-label={tr("Test")}
                      >
                        <SendRoundedIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={tr("Delivery history")}>
                      <IconButton
                        size="small"
                        onClick={() => setHistory(w)}
                        aria-label={tr("History")}
                      >
                        <HistoryRoundedIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={tr("Delete")}>
                      <IconButton
                        size="small"
                        onClick={() => setDeleting(w)}
                        aria-label={tr("Delete")}
                      >
                        <DeleteOutlineRoundedIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <CreateWebhookDialog open={createOpen} team={team} onClose={() => setCreateOpen(false)} />
      <DeliveriesDialog team={team} hook={history} onClose={() => setHistory(null)} />
      <ConfirmDialog
        open={deleting !== null}
        title={tr("Delete webhook?")}
        confirmLabel={tr("Delete")}
        danger
        busy={remove.isPending}
        onCancel={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
      >
        {tr("Queued deliveries for it are dropped.")}
      </ConfirmDialog>
    </Section>
  );
}

function CreateWebhookDialog({
  open,
  team,
  onClose,
}: {
  open: boolean;
  team: Team;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const [kind, setKind] = useState<WebhookKind>("generic");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [actions, setActions] = useState("");
  const create = useMutation({
    mutationFn: () => {
      const list = actions
        .split(/[,\s]+/)
        .map((a) => a.trim())
        .filter(Boolean);
      return teamsApi.createWebhook(team.id, {
        kind,
        url: url.trim(),
        secret,
        actions: list.length ? list : null,
      });
    },
    onSuccess: async () => {
      onClose();
      setUrl("");
      setSecret("");
      setActions("");
      await qc.invalidateQueries({ queryKey: queryKeys.teamWebhooks(team.id) });
      snack.notify(tr("Webhook added"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const k = KINDS.find((x) => x.value === kind);
  const syslog = kind === "syslog_tls";
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{tr("Add webhook")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <FormControl size="small" fullWidth>
            <InputLabel id="kind-label">{tr("Kind")}</InputLabel>
            <Select
              labelId="kind-label"
              label={tr("Kind")}
              value={kind}
              onChange={(e) => setKind(e.target.value)}
            >
              {KINDS.map((x) => (
                <MenuItem key={x.value} value={x.value}>
                  {tr(x.label)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Typography variant="caption" color="text.secondary">
            {k ? tr(k.hint) : null}
          </Typography>
          <TextField
            label={syslog ? tr("Destination (syslog+tls://host:port)") : tr("URL (https://…)")}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            fullWidth
            autoFocus
          />
          {!syslog && (
            <TextField
              label={
                kind === "generic" ? tr("Signing secret (8–512 chars)") : tr("Token / API key")
              }
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              fullWidth
            />
          )}
          <TextField
            label={tr("Only these actions (optional)")}
            placeholder={tr("member., vault.deleted, policy.updated")}
            helperText={tr("Comma-separated; a trailing dot matches a family. Empty = everything.")}
            value={actions}
            onChange={(e) => setActions(e.target.value)}
            fullWidth
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button
          variant="contained"
          disabled={!url.trim() || (!syslog && secret.length < 8) || create.isPending}
          onClick={() => create.mutate()}
        >
          {tr("Add")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function DeliveriesDialog({
  team,
  hook,
  onClose,
}: {
  team: Team;
  hook: Webhook | null;
  onClose: () => void;
}) {
  const q = useQuery({
    queryKey: queryKeys.teamWebhookDeliveries(team.id, hook?.id ?? ""),
    queryFn: () => teamsApi.webhookDeliveries(team.id, hook?.id ?? ""),
    enabled: hook !== null,
  });
  return (
    <Dialog open={hook !== null} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{trx("Deliveries · {url}", { url: hook?.url })}</DialogTitle>
      <DialogContent sx={{ p: 0 }}>
        {q.isPending ? (
          <Loading minHeight={120} />
        ) : q.isError ? (
          <Box sx={{ p: 3 }}>
            <Alert severity="error">{errorMessage(q.error)}</Alert>
          </Box>
        ) : q.data.deliveries.length === 0 ? (
          <EmptyState title={tr("Nothing delivered yet")} />
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{tr("Event")}</TableCell>
                  <TableCell>{tr("Status")}</TableCell>
                  <TableCell>{tr("Attempt")}</TableCell>
                  <TableCell>{tr("Response")}</TableCell>
                  <TableCell>{tr("When")}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {q.data.deliveries.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell sx={{ fontFamily: "monospace" }}>{d.action}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={d.status}
                        color={
                          d.status === "ok" ? "success" : d.status === "dead" ? "error" : "default"
                        }
                      />
                    </TableCell>
                    <TableCell>{d.attempt}</TableCell>
                    <TableCell sx={{ maxWidth: 320 }}>
                      <Typography variant="caption" sx={{ fontFamily: "monospace" }} noWrap>
                        {d.response_status ?? "—"} {d.response_body ?? ""}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ whiteSpace: "nowrap" }}>
                      {formatRelative(d.delivered_at ?? d.next_at)}
                    </TableCell>
                  </TableRow>
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
