import { useEffect, useMemo, useState } from "react";
import { tr } from "@/i18n";
import {
  Alert,
  Button,
  Chip,
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
  Tooltip,
  Typography,
} from "@mui/material";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import PushPinRoundedIcon from "@mui/icons-material/PushPinRounded";
import VideocamOutlinedIcon from "@mui/icons-material/VideocamOutlined";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { logsApi, teamsApi, vaultsApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { LogMeta, SessionLog, Team, Vault } from "@/api/types";
import { useAuthState } from "@/auth/store";
import { Paged } from "@/components/Pager";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { UserCell } from "@/components/UserCell";
import { saveBlob } from "@/components/download";
import { formatBytes, formatDateTime } from "@/components/format";
import { loadCrypto } from "@/crypto";
import { openMyVaultKey } from "@/vaults/keys";
import { decryptMeta, durationOf, sortLogs } from "../vaults/logs";
import { can } from "./perm";

/** Session recordings of every member across the team's vaults. Metadata is
 *  decrypted with the vault keys this browser can open; recordings in vaults
 *  the viewer is not a member of stay labelled as encrypted. */
export function RecordingsTab({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const { session, privateKey } = useAuthState();
  const me = session?.user.id;
  const [vaultId, setVaultId] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const filters = useMemo(
    () => ({
      vault_id: vaultId || undefined,
      from: from ? new Date(from).toISOString() : undefined,
      to: to ? new Date(`${to}T23:59:59`).toISOString() : undefined,
    }),
    [vaultId, from, to],
  );
  const logs = useQuery({
    queryKey: queryKeys.teamLogs(team.id, filters),
    queryFn: () => teamsApi.logs(team.id, filters),
  });
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list });
  const policies = useQuery({
    queryKey: queryKeys.teamPolicies(team.id),
    queryFn: () => teamsApi.policies(team.id),
  });
  const teamVaults = useMemo(
    () => (vaults.data?.vaults ?? []).filter((v) => v.team_id === team.id),
    [vaults.data, team.id],
  );
  const vaultById = useMemo(() => new Map(teamVaults.map((v) => [v.id, v])), [teamVaults]);

  // Vault keys: opened silently for vaults where this account holds a sealed key.
  const [keys, setKeys] = useState<Record<string, string | null>>({});
  useEffect(() => {
    if (!privateKey) return;
    const pending = teamVaults.filter((v) => v.sealed_key && !(v.id in keys));
    if (pending.length === 0) return;
    let cancelled = false;
    void Promise.all(
      pending.map((v: Vault) =>
        openMyVaultKey(v)
          .then((k) => [v.id, k] as const)
          .catch(() => [v.id, null] as const),
      ),
    ).then((pairs) => {
      if (cancelled) return;
      setKeys((prev) => ({ ...prev, ...Object.fromEntries(pairs) }));
    });
    return () => {
      cancelled = true;
    };
  }, [privateKey, teamVaults, keys]);

  const [metas, setMetas] = useState<Record<string, LogMeta | null>>({});
  const list = useMemo(
    () => sortLogs((logs.data?.logs ?? []).filter((l) => !l.deleted)),
    [logs.data],
  );
  useEffect(() => {
    const pending = list.filter((l) => !(l.id in metas) && keys[l.vault_id]);
    if (pending.length === 0) return;
    let cancelled = false;
    void loadCrypto().then(() => {
      if (cancelled) return;
      const next: Record<string, LogMeta | null> = {};
      for (const l of pending) {
        const k = keys[l.vault_id];
        if (k) next[l.id] = decryptMeta(k, l);
      }
      setMetas((m) => ({ ...m, ...next }));
    });
    return () => {
      cancelled = true;
    };
  }, [list, keys, metas]);

  const [deleting, setDeleting] = useState<SessionLog | null>(null);
  const del = useMutation({
    mutationFn: (l: SessionLog) => logsApi.delete(l.id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["teams", team.id, "logs"] });
      setDeleting(null);
      snack.notify(tr("Recording deleted"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const exp = useMutation({
    mutationFn: async () => {
      const blob = await teamsApi.logsExport(team.id);
      if (!blob) throw new Error(tr("Nothing to export"));
      saveBlob(
        blob,
        `termoso-recordings-${team.name.replace(/[^\w.-]+/g, "_")}-${new Date().toISOString().slice(0, 10)}.ndjson`,
      );
    },
    onSuccess: () => snack.notify(tr("Export downloaded")),
    onError: (e) => snack.error(errorMessage(e)),
  });

  if (logs.isPending) return <Loading />;
  if (logs.isError) return <Alert severity="error">{errorMessage(logs.error)}</Alert>;
  const required = policies.data?.policies.session_recording === "required";
  const canDelete = can(team, "logs.delete");
  const totalBytes = list.reduce((n, l) => n + l.size_bytes, 0);
  return (
    <Stack spacing={2}>
      <Alert severity={required ? "info" : "warning"}>
        {required
          ? tr(
              "Team policy requires recording: every session in a team vault is recorded and members cannot turn it off.",
            )
          : tr(
              "Recording is optional in this team — each vault decides. Set the policy “Session recording: required” to record everything.",
            )}
      </Alert>
      <Section
        title={tr("Session recordings")}
        description={tr(
          "Everything members recorded in this team's vaults. Retention follows the team policy; pinned recordings are never auto-deleted. What a session was — host, command line, output — is decrypted in this browser with the vault key; the server stores ciphertext only.",
        )}
        actions={
          can(team, "logs.export") && (
            <Button
              variant="outlined"
              disabled={exp.isPending || list.length === 0}
              onClick={() => exp.mutate()}
            >
              {tr("Export NDJSON")}
            </Button>
          )
        }
      >
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mb: 2 }}>
          <TextField
            select
            size="small"
            label={tr("Vault")}
            value={vaultId}
            onChange={(e) => setVaultId(e.target.value)}
            sx={{ minWidth: 180 }}
          >
            <MenuItem value="">{tr("All vaults")}</MenuItem>
            {teamVaults.map((v) => (
              <MenuItem key={v.id} value={v.id}>
                {v.name}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            size="small"
            type="date"
            label={tr("From")}
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            slotProps={{ inputLabel: { shrink: true } }}
          />
          <TextField
            size="small"
            type="date"
            label={tr("To")}
            value={to}
            onChange={(e) => setTo(e.target.value)}
            slotProps={{ inputLabel: { shrink: true } }}
          />
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ alignSelf: "center", ml: { sm: "auto" } }}
          >
            {tr("{v1} recordings · {v2}", { v1: list.length, v2: formatBytes(totalBytes) })}
          </Typography>
        </Stack>
        {list.length === 0 ? (
          <EmptyState
            icon={<VideocamOutlinedIcon fontSize="inherit" />}
            title={tr("No recordings")}
          />
        ) : (
          <Paged items={list}>
            {(page) => (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>{tr("Member")}</TableCell>
                      <TableCell>{tr("Session")}</TableCell>
                      <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                        {tr("Vault")}
                      </TableCell>
                      <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }} align="right">
                        {tr("Size")}
                      </TableCell>
                      <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                        {tr("Recorded")}
                      </TableCell>
                      {canDelete && <TableCell align="right" />}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {page.map((l) => {
                      const meta = metas[l.id];
                      return (
                        <TableRow key={l.id} hover>
                          <TableCell sx={{ minWidth: 180 }}>
                            <UserCell
                              userId={l.user_id}
                              email={l.author?.email ?? tr("Former member")}
                              displayName={l.author?.display_name}
                              avatar={l.author?.avatar_tag}
                              you={l.user_id === me}
                            />
                          </TableCell>
                          <TableCell sx={{ minWidth: 200 }}>
                            <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
                              {l.pinned && (
                                <Tooltip title={tr("Pinned")}>
                                  <PushPinRoundedIcon color="primary" sx={{ fontSize: 16 }} />
                                </Tooltip>
                              )}
                              <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
                                {meta ? meta.label : tr("Encrypted recording")}
                              </Typography>
                              {!l.completed && (
                                <Chip size="small" variant="outlined" label={tr("Uploading")} />
                              )}
                            </Stack>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                              noWrap
                              sx={{ display: "block" }}
                            >
                              {meta
                                ? `${meta.protocol} · ${meta.target} · ${durationOf(meta)}`
                                : keys[l.vault_id] === undefined &&
                                    vaultById.get(l.vault_id)?.sealed_key
                                  ? tr("Decrypting…")
                                  : tr("No key for this vault in this browser")}
                            </Typography>
                          </TableCell>
                          <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                            {vaultById.get(l.vault_id)?.name ?? "—"}
                          </TableCell>
                          <TableCell
                            sx={{ display: { xs: "none", sm: "table-cell" } }}
                            align="right"
                          >
                            {formatBytes(l.size_bytes)}
                          </TableCell>
                          <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                            {formatDateTime(l.created_at)}
                          </TableCell>
                          {canDelete && (
                            <TableCell align="right">
                              <Tooltip title={tr("Delete recording")}>
                                <IconButton
                                  size="small"
                                  onClick={() => setDeleting(l)}
                                  aria-label={tr("Delete recording")}
                                >
                                  <DeleteOutlineRoundedIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            </TableCell>
                          )}
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
      <ConfirmDialog
        open={deleting !== null}
        title={tr("Delete recording?")}
        confirmLabel={tr("Delete")}
        danger
        busy={del.isPending}
        onCancel={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting)}
      >
        {tr(
          "The recording is removed from the server for every member; copies already downloaded to members' devices stay with them.",
        )}
      </ConfirmDialog>
    </Stack>
  );
}
