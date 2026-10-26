import { useState } from "react";
import { tr, trx } from "@/i18n";
import {
  Alert,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  MenuItem,
  Select,
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
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { teamsApi, vaultsApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { CreatedScimToken, ScimGroupInfo, ScimGroupVault, Team } from "@/api/types";
import { Paged } from "@/components/Pager";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CopyField } from "@/components/CopyField";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { formatDate, formatRelative } from "@/components/format";
import { can } from "./perm";

export function ScimTab({ team }: { team: Team }) {
  return (
    <>
      {can(team, "scim.tokens") && <TokensSection team={team} />}
      <GroupsSection team={team} manage={can(team, "scim.manage")} />
    </>
  );
}

function TokensSection({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const q = useQuery({
    queryKey: queryKeys.teamScimTokens(team.id),
    queryFn: () => teamsApi.scimTokens(team.id),
  });
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [days, setDays] = useState("");
  const [created, setCreated] = useState<CreatedScimToken | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: queryKeys.teamScimTokens(team.id) });
  const create = useMutation({
    mutationFn: () =>
      teamsApi.createScimToken(team.id, {
        name: name.trim(),
        expires_in_days: days ? Number(days) : undefined,
      }),
    onSuccess: async (t) => {
      setCreateOpen(false);
      setName("");
      setDays("");
      setCreated(t);
      await invalidate();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const revoke = useMutation({
    mutationFn: (tid: string) => teamsApi.revokeScimToken(team.id, tid),
    onSuccess: async () => {
      setRevoking(null);
      await invalidate();
      snack.notify(tr("Token revoked"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  if (q.isPending) return <Loading minHeight={120} />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  return (
    <Section
      title={tr("SCIM provisioning")}
      description={
        <>
          {trx(
            "Point your identity provider (Okta, Entra ID, Google, …) at  {v1}  with a bearer token below. Users and groups are created, updated and deprovisioned by the provider; up to three active tokens.",
            {
              v1: (
                <Typography component="code" variant="body2" sx={{ fontFamily: "monospace" }}>
                  {q.data.base_url}
                </Typography>
              ),
            },
          )}
        </>
      }
      actions={
        <Button
          startIcon={<AddRoundedIcon />}
          disabled={q.data.tokens.length >= 3}
          onClick={() => setCreateOpen(true)}
        >
          {tr("New token")}
        </Button>
      }
      disablePadding={q.data.tokens.length > 0}
    >
      {q.data.tokens.length === 0 ? (
        <EmptyState
          title={tr("No SCIM tokens")}
          description={tr("Create one and paste it into your IdP.")}
        />
      ) : (
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>{tr("Name")}</TableCell>
                <TableCell>{tr("Created")}</TableCell>
                <TableCell>{tr("Expires")}</TableCell>
                <TableCell>{tr("Last used")}</TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.tokens.map((t) => (
                <TableRow key={t.id} hover>
                  <TableCell>{t.name}</TableCell>
                  <TableCell>{formatDate(t.created_at)}</TableCell>
                  <TableCell>{t.expires_at ? formatDate(t.expires_at) : "never"}</TableCell>
                  <TableCell>{t.last_used_at ? formatRelative(t.last_used_at) : "never"}</TableCell>
                  <TableCell align="right">
                    <Tooltip title={tr("Revoke token")}>
                      <IconButton
                        size="small"
                        onClick={() => setRevoking(t.id)}
                        aria-label={tr("Revoke")}
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
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{tr("New SCIM token")}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <TextField
              label={tr("Name")}
              placeholder={tr("Okta production")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              fullWidth
            />
            <TextField
              label={tr("Expires in days")}
              placeholder={tr("never")}
              type="number"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              fullWidth
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>{tr("Cancel")}</Button>
          <Button
            variant="contained"
            disabled={!name.trim() || create.isPending}
            onClick={() => create.mutate()}
          >
            {tr("Create")}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={created !== null} onClose={() => setCreated(null)} maxWidth="sm" fullWidth>
        <DialogTitle>{tr("Token created")}</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            {tr("Copy the secret now — it is shown once and stored only as a hash.")}
          </DialogContentText>
          <Stack spacing={2}>
            <CopyField label={tr("SCIM base URL")} value={created?.base_url ?? ""} />
            <CopyField label={tr("Bearer token")} value={created?.secret ?? ""} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button variant="contained" onClick={() => setCreated(null)}>
            {tr("Done")}
          </Button>
        </DialogActions>
      </Dialog>
      <ConfirmDialog
        open={revoking !== null}
        title={tr("Revoke SCIM token?")}
        confirmLabel={tr("Revoke")}
        danger
        busy={revoke.isPending}
        onCancel={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking)}
      >
        {tr(
          "The identity provider using it stops syncing immediately. Users already provisioned keep their access.",
        )}
      </ConfirmDialog>
    </Section>
  );
}

function GroupsSection({ team, manage }: { team: Team; manage: boolean }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const q = useQuery({
    queryKey: queryKeys.teamScimGroups(team.id),
    queryFn: () => teamsApi.scimGroups(team.id),
  });
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list, enabled: manage });
  const teamVaults = (vaults.data?.vaults ?? []).filter((v) => v.team_id === team.id);
  const [editing, setEditing] = useState<ScimGroupInfo | null>(null);
  const [draft, setDraft] = useState<ScimGroupVault[]>([]);
  const save = useMutation({
    mutationFn: () => teamsApi.setScimGroupVaults(team.id, editing?.id ?? "", draft),
    onSuccess: async () => {
      setEditing(null);
      await qc.invalidateQueries({ queryKey: queryKeys.teamScimGroups(team.id) });
      snack.notify(tr("Vault grants saved"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  if (q.isPending) return <Loading minHeight={120} />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const vaultName = (id: string) => teamVaults.find((v) => v.id === id)?.name ?? id.slice(0, 8);
  return (
    <Section
      title={tr("Provisioned groups")}
      description={tr(
        "Groups pushed by the identity provider. Map them to roles on the Roles tab; here you grant team vaults to a group — members get a pending key the next time an admin is online.",
      )}
      disablePadding={q.data.groups.length > 0}
    >
      {q.data.groups.length === 0 ? (
        <EmptyState
          title={tr("No groups yet")}
          description={tr("Groups appear once the identity provider pushes them.")}
        />
      ) : (
        <Paged items={q.data.groups}>
          {(page) => (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>{tr("Group")}</TableCell>
                    <TableCell>{tr("Members")}</TableCell>
                    <TableCell>{tr("Vaults")}</TableCell>
                    {manage && <TableCell align="right" />}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {page.map((g) => (
                    <TableRow key={g.id} hover>
                      <TableCell>
                        <Typography variant="body2">{g.display_name}</Typography>
                        {g.external_id && (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ fontFamily: "monospace" }}
                          >
                            {g.external_id}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>{g.member_count}</TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                          {g.vaults.length === 0 && (
                            <Typography variant="caption" color="text.secondary">
                              {tr("none")}
                            </Typography>
                          )}
                          {g.vaults.map((v) => (
                            <Chip
                              key={v.vault_id}
                              size="small"
                              variant="outlined"
                              label={`${vaultName(v.vault_id)} · ${v.role}`}
                            />
                          ))}
                        </Stack>
                      </TableCell>
                      {manage && (
                        <TableCell align="right">
                          <Button
                            size="small"
                            onClick={() => {
                              setEditing(g);
                              setDraft(g.vaults);
                            }}
                          >
                            {tr("Vault access")}
                          </Button>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paged>
      )}
      <Dialog open={editing !== null} onClose={() => setEditing(null)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {trx("Vaults for “{display_name}”", { display_name: editing?.display_name })}
        </DialogTitle>
        <DialogContent>
          {teamVaults.length === 0 ? (
            <DialogContentText>{tr("This team has no shared vaults yet.")}</DialogContentText>
          ) : (
            <Stack spacing={1} sx={{ pt: 1 }}>
              {teamVaults.map((v) => {
                const cur = draft.find((d) => d.vault_id === v.id);
                return (
                  <Stack
                    key={v.id}
                    direction="row"
                    spacing={2}
                    sx={{ alignItems: "center", justifyContent: "space-between" }}
                  >
                    <Typography variant="body2">{v.name}</Typography>
                    <Select
                      size="small"
                      value={cur?.role ?? "none"}
                      onChange={(e) => {
                        const role = e.target.value;
                        setDraft(
                          role === "none"
                            ? draft.filter((d) => d.vault_id !== v.id)
                            : [
                                ...draft.filter((d) => d.vault_id !== v.id),
                                { vault_id: v.id, role },
                              ],
                        );
                      }}
                      sx={{ minWidth: 140 }}
                    >
                      <MenuItem value="none">{tr("No access")}</MenuItem>
                      <MenuItem value="viewer">{tr("Viewer")}</MenuItem>
                      <MenuItem value="editor">{tr("Editor")}</MenuItem>
                      <MenuItem value="manager">{tr("Manager")}</MenuItem>
                    </Select>
                  </Stack>
                );
              })}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditing(null)}>{tr("Cancel")}</Button>
          <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
            {tr("Save")}
          </Button>
        </DialogActions>
      </Dialog>
    </Section>
  );
}
