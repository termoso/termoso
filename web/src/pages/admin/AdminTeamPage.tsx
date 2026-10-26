import { useState } from "react";
import { tr } from "@/i18n";
import {
  Alert,
  Autocomplete,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
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
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import PersonRemoveOutlinedIcon from "@mui/icons-material/PersonRemoveOutlined";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link as RouterLink, useParams } from "react-router";
import { errorMessage } from "@/api/client";
import { adminApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { AdminTeamMember, AdminUser } from "@/api/types";
import { Paged } from "@/components/Pager";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Loading } from "@/components/Loading";
import { PageHeader } from "@/components/PageHeader";
import { Section, SettingRow } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { formatBytes, formatDateTime, formatRelative } from "@/components/format";

export function AdminTeamPage() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const snack = useSnackbar();
  const q = useQuery({ queryKey: queryKeys.adminTeam(id), queryFn: () => adminApi.teamDetail(id) });
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<AdminTeamMember | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: queryKeys.adminTeam(id) });
  const remove = useMutation({
    mutationFn: (m: AdminTeamMember) => adminApi.removeTeamMember(id, m.user_id),
    onSuccess: async () => {
      await refresh();
      setRemoving(null);
      snack.notify(tr("Member removed"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const { team, members, policies, audit } = q.data;
  const yes = (v: boolean | undefined) => (v ? tr("Yes") : tr("No"));
  return (
    <>
      <PageHeader
        title={team.name}
        subtitle={tr("Owner {v1} · created {v2}", {
          v1: team.owner_email,
          v2: formatDateTime(team.created_at),
        })}
        actions={
          <Button component={RouterLink} to="/admin/teams" startIcon={<ArrowBackRoundedIcon />}>
            {tr("All teams")}
          </Button>
        }
      />
      <Stack spacing={2}>
        {team.deletion_scheduled_at && (
          <Alert severity="warning">
            {tr("The owner scheduled deletion for {v1}.", {
              v1: formatDateTime(team.deletion_scheduled_at),
            })}
          </Alert>
        )}
        <Section title={tr("Summary")}>
          <SettingRow
            label={tr("Members")}
            control={<Typography variant="body2">{team.member_count}</Typography>}
          />
          <SettingRow
            label={tr("Vaults")}
            control={<Typography variant="body2">{team.vault_count}</Typography>}
          />
          <SettingRow
            label={tr("Session recordings")}
            control={<Typography variant="body2">{formatBytes(team.log_bytes ?? 0)}</Typography>}
          />
          <SettingRow
            label={tr("Data region")}
            control={<Typography variant="body2">{team.region ?? "—"}</Typography>}
          />
          <SettingRow
            label={tr("Home team")}
            control={<Typography variant="body2">{yes(team.is_home)}</Typography>}
          />
          <SettingRow
            label={tr("Team identity provider")}
            control={<Typography variant="body2">{yes(team.idp)}</Typography>}
          />
          <SettingRow
            label={tr("SCIM provisioning")}
            control={<Typography variant="body2">{yes(team.scim)}</Typography>}
          />
          <SettingRow
            label={tr("Webhooks")}
            divider={false}
            control={<Typography variant="body2">{team.webhooks ?? 0}</Typography>}
          />
        </Section>
        <Section
          title={tr("Members")}
          disablePadding
          actions={
            <Button variant="outlined" onClick={() => setAdding(true)}>
              {tr("Add account")}
            </Button>
          }
        >
          <Paged items={members}>
            {(page) => (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>{tr("E-mail")}</TableCell>
                      <TableCell>{tr("Role")}</TableCell>
                      <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                        {tr("Source")}
                      </TableCell>
                      <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                        {tr("Last seen")}
                      </TableCell>
                      <TableCell align="right" />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {page.map((m) => (
                      <TableRow key={m.user_id} hover>
                        <TableCell>{m.email}</TableCell>
                        <TableCell>
                          <Chip size="small" variant="outlined" label={tr(m.role)} />
                        </TableCell>
                        <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                          {m.role_source}
                        </TableCell>
                        <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                          {m.last_seen_at ? formatRelative(m.last_seen_at) : "—"}
                        </TableCell>
                        <TableCell align="right">
                          {m.level !== "owner" && (
                            <Tooltip title={tr("Remove from team")}>
                              <IconButton
                                size="small"
                                aria-label={tr("Remove from team")}
                                onClick={() => setRemoving(m)}
                              >
                                <PersonRemoveOutlinedIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paged>
        </Section>
        <Section
          title={tr("Policies")}
          description={tr(
            "Read-only; the team's owner and admins change them in the team settings.",
          )}
        >
          <SettingRow
            label={tr("Two-factor")}
            control={<Typography variant="body2">{policies.mfa}</Typography>}
          />
          <SettingRow
            label={tr("Sign in only through SSO")}
            control={<Typography variant="body2">{yes(policies.sso_only)}</Typography>}
          />
          <SettingRow
            label={tr("Session recording")}
            control={<Typography variant="body2">{policies.session_recording}</Typography>}
          />
          <SettingRow
            label={tr("Admin approval for new devices")}
            control={<Typography variant="body2">{yes(policies.device_admin_approval)}</Typography>}
          />
          <SettingRow
            label={tr("IP allow-list")}
            control={
              <Typography variant="body2">
                {policies.ip_allowlist.length > 0
                  ? policies.ip_allowlist.join(", ")
                  : tr("Everywhere")}
              </Typography>
            }
          />
          <SettingRow
            label={tr("Audit retention")}
            divider={false}
            control={
              <Typography variant="body2">
                {tr("{v1} days", { v1: policies.audit_retention_days })}
              </Typography>
            }
          />
        </Section>
        {audit.length > 0 && (
          <Section title={tr("Recent activity")} disablePadding>
            <Paged items={audit}>
              {(page) => (
                <TableContainer>
                  <Table size="small">
                    <TableBody>
                      {page.map((e) => (
                        <TableRow key={e.id} hover>
                          <TableCell sx={{ whiteSpace: "nowrap" }}>
                            {formatDateTime(e.created_at)}
                          </TableCell>
                          <TableCell sx={{ fontFamily: "monospace" }}>{e.action}</TableCell>
                          <TableCell>{e.actor_email ?? "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Paged>
          </Section>
        )}
      </Stack>
      <AddMemberDialog
        open={adding}
        teamId={id}
        onClose={() => setAdding(false)}
        onDone={() => {
          setAdding(false);
          void refresh();
        }}
      />
      <ConfirmDialog
        open={removing !== null}
        title={tr("Remove from team?")}
        confirmLabel={tr("Remove")}
        danger
        busy={remove.isPending}
        onCancel={() => setRemoving(null)}
        onConfirm={() => removing && remove.mutate(removing)}
      >
        {removing &&
          tr(
            "{v1} loses access to the team and its vaults. Vault keys should be rotated by a manager.",
            { v1: removing.email },
          )}
      </ConfirmDialog>
    </>
  );
}

function AddMemberDialog({
  open,
  teamId,
  onClose,
  onDone,
}: {
  open: boolean;
  teamId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const snack = useSnackbar();
  const [search, setSearch] = useState("");
  const [user, setUser] = useState<AdminUser | null>(null);
  const users = useQuery({
    queryKey: ["admin", "users", "pick", search],
    queryFn: () => adminApi.users({ q: search, offset: 0, limit: 20 }),
    enabled: open && search.length >= 2,
  });
  const m = useMutation({
    mutationFn: () => adminApi.addTeamMember(teamId, user?.id ?? ""),
    onSuccess: () => {
      snack.notify(tr("Account added with the default role"));
      setUser(null);
      setSearch("");
      onDone();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{tr("Add account to team")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <Autocomplete
            options={users.data?.items ?? []}
            getOptionLabel={(u) => u.email}
            value={user}
            onChange={(_e, v) => setUser(v)}
            inputValue={search}
            onInputChange={(_e, v) => setSearch(v)}
            loading={users.isFetching}
            noOptionsText={
              search.length < 2 ? tr("Type at least two characters") : tr("No accounts match")
            }
            renderInput={(params) => (
              <TextField {...params} size="small" label={tr("Account e-mail")} autoFocus />
            )}
          />
          <Typography variant="body2" color="text.secondary">
            {tr(
              "The account joins with the team's default role; the vault keys are sealed to it by a vault manager afterwards.",
            )}
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button variant="contained" disabled={!user || m.isPending} onClick={() => m.mutate()}>
          {tr("Add")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
