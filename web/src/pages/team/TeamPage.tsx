import { useMemo, useState, type SubmitEvent } from "react";
import { tr, trn, trx } from "@/i18n";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  FormControl,
  FormControlLabel,
  FormGroup,
  IconButton,
  InputLabel,
  Link,
  List,
  ListItem,
  ListItemText,
  MenuItem,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
  TableContainer,
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import MailOutlineRoundedIcon from "@mui/icons-material/MailOutlineRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import LockOpenRoundedIcon from "@mui/icons-material/LockOpenRounded";
import PersonAddAltRoundedIcon from "@mui/icons-material/PersonAddAltRounded";
import PersonRemoveRoundedIcon from "@mui/icons-material/PersonRemoveRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link as RouterLink, useNavigate, useParams, useSearchParams } from "react-router";
import { Tab, Tabs } from "@mui/material";
import { AuditTab } from "./AuditTab";
import { PoliciesTab } from "./PoliciesTab";
import { RolesTab } from "./RolesTab";
import { ScimTab } from "./ScimTab";
import { AccessTab } from "./AccessTab";
import { DataTab } from "./DataTab";
import { DevicesTab } from "./DevicesTab";
import { RecordingsTab } from "./RecordingsTab";
import { RotationTab } from "./RotationTab";
import { SsoTab } from "./SsoTab";
import { can } from "./perm";
import { errorMessage } from "@/api/client";
import { teamsApi, vaultsApi } from "@/api/endpoints";
import { queryKeys, useServerInfo } from "@/api/hooks";
import type {
  DigestCadence,
  PendingVaultKey,
  Team,
  TeamMember,
  TeamRole,
  Vault,
  VaultRole,
} from "@/api/types";
import { useAuthState } from "@/auth/store";
import { UnlockCancelled, withStepUp } from "@/auth/unlock";
import { Paged } from "@/components/Pager";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CopyField } from "@/components/CopyField";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { PageHeader } from "@/components/PageHeader";
import { MfaBadge } from "@/components/MfaBadge";
import { RoleChip } from "@/components/RoleChip";
import { Section, SettingRow } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { UserCell } from "@/components/UserCell";
import { formatDate, formatRelative } from "@/components/format";
import { grantPendingKey, newSealedVaultKey } from "@/vaults/keys";

const isAdmin = (r: TeamRole) => r === "owner" || r === "admin";

export function TeamPage() {
  const { id = "" } = useParams();
  const team = useQuery({ queryKey: queryKeys.team(id), queryFn: () => teamsApi.get(id) });
  if (team.isPending) return <Loading />;
  if (team.isError) return <Alert severity="error">{errorMessage(team.error)}</Alert>;
  return <TeamDetail team={team.data} />;
}

function TeamDetail({ team }: { team: Team }) {
  const admin = isAdmin(team.my_role);
  return (
    <>
      <PageHeader
        title={team.name}
        subtitle={
          <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
            <RoleChip role={team.my_role} />
            <span>
              {tr("{members} · created {v2}", {
                members: trn(team.member_count, "{count} member", "{count} members"),
                v2: formatDate(team.created_at),
              })}
            </span>
          </Stack>
        }
        actions={<TeamActions team={team} />}
      />
      <TeamTabs team={team} admin={admin} />
    </>
  );
}

type TabKey =
  | "members"
  | "roles"
  | "policies"
  | "audit"
  | "scim"
  | "sso"
  | "access"
  | "devices"
  | "rotation"
  | "logs"
  | "data";

function TeamTabs({ team, admin }: { team: Team; admin: boolean }) {
  const [params, setParams] = useSearchParams();
  const info = useServerInfo();
  const all: { key: TabKey; label: string; show: boolean }[] = [
    { key: "members", label: tr("Members"), show: true },
    { key: "roles", label: tr("Roles"), show: can(team, "roles.manage") },
    { key: "policies", label: tr("Policies"), show: can(team, "policies.manage") },
    {
      key: "audit",
      label: tr("Audit"),
      show: can(team, "audit.view") || can(team, "webhooks.manage"),
    },
    { key: "scim", label: tr("SCIM"), show: can(team, "scim.manage") || can(team, "scim.tokens") },
    {
      key: "sso",
      label: tr("SSO"),
      show: can(team, "policies.manage") && info.data?.team_idp !== false,
    },
    { key: "access", label: tr("Access"), show: true },
    { key: "rotation", label: tr("Rotation"), show: can(team, "rotation.manage") },
    { key: "devices", label: tr("Devices"), show: can(team, "devices.approve") },
    { key: "logs", label: tr("Recordings"), show: can(team, "logs.view_team") },
    { key: "data", label: tr("Data"), show: true },
  ];
  const tabs = all.filter((t) => t.show);
  const requested = params.get("tab");
  const tab: TabKey = tabs.find((t) => t.key === requested)?.key ?? "members";
  return (
    <>
      {tabs.length > 1 && (
        <Tabs
          value={tab}
          onChange={(_, v: TabKey) => {
            const next = new URLSearchParams(params);
            if (v === "members") next.delete("tab");
            else next.set("tab", v);
            setParams(next, { replace: true });
          }}
          variant="scrollable"
          scrollButtons="auto"
          allowScrollButtonsMobile
          sx={{ mb: 2, borderBottom: 1, borderColor: "divider" }}
        >
          {tabs.map((t) => (
            <Tab key={t.key} value={t.key} label={t.label} />
          ))}
        </Tabs>
      )}
      {tab === "members" && (
        <>
          {admin && <PendingKeysSection team={team} />}
          <MembersSection team={team} />
          {admin && <InvitesSection team={team} />}
          <TeamVaultsSection team={team} />
          {admin && <DigestSection team={team} />}
        </>
      )}
      {tab === "roles" && <RolesTab team={team} />}
      {tab === "policies" && <PoliciesTab team={team} />}
      {tab === "audit" && <AuditTab team={team} />}
      {tab === "scim" && <ScimTab team={team} />}
      {tab === "sso" && <SsoTab team={team} />}
      {tab === "access" && <AccessTab team={team} />}
      {tab === "rotation" && <RotationTab team={team} />}
      {tab === "devices" && <DevicesTab team={team} />}
      {tab === "logs" && <RecordingsTab team={team} />}
      {tab === "data" && <DataTab team={team} />}
    </>
  );
}

function TeamActions({ team }: { team: Team }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const snack = useSnackbar();
  const [renameOpen, setRenameOpen] = useState(false);
  const [name, setName] = useState(team.name);
  const [leaveOpen, setLeaveOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const invalidate = async () => {
    await qc.invalidateQueries({ queryKey: queryKeys.teams });
    await qc.invalidateQueries({ queryKey: queryKeys.vaults });
  };
  const rename = useMutation({
    mutationFn: () => teamsApi.update(team.id, name.trim()),
    onSuccess: async () => {
      setRenameOpen(false);
      await invalidate();
      snack.notify(tr("Team renamed"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const leave = useMutation({
    mutationFn: () => teamsApi.leave(team.id),
    onSuccess: async () => {
      await invalidate();
      void navigate("/team", { replace: true });
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const del = useMutation({
    mutationFn: () => teamsApi.delete(team.id),
    onSuccess: async () => {
      await invalidate();
      void navigate("/team", { replace: true });
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  return (
    <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: "wrap" }}>
      {isAdmin(team.my_role) && (
        <Button variant="outlined" onClick={() => setRenameOpen(true)}>
          {tr("Rename")}
        </Button>
      )}
      {team.my_role !== "owner" && (
        <Button variant="outlined" color="error" onClick={() => setLeaveOpen(true)}>
          {tr("Leave team")}
        </Button>
      )}
      {team.my_role === "owner" && (
        <Button variant="outlined" color="error" onClick={() => setDeleteOpen(true)}>
          {tr("Delete team")}
        </Button>
      )}

      <Dialog
        open={renameOpen}
        onClose={rename.isPending ? undefined : () => setRenameOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <form
          onSubmit={(e: SubmitEvent) => {
            e.preventDefault();
            rename.mutate();
          }}
        >
          <DialogTitle>{tr("Rename team")}</DialogTitle>
          <DialogContent>
            <TextField
              autoFocus
              fullWidth
              label={tr("Team name")}
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              sx={{ mt: 1 }}
            />
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setRenameOpen(false)} color="inherit">
              {tr("Cancel")}
            </Button>
            <Button
              type="submit"
              variant="contained"
              disabled={rename.isPending || name.trim() === ""}
            >
              {tr("Save")}
            </Button>
          </DialogActions>
        </form>
      </Dialog>
      <ConfirmDialog
        open={leaveOpen}
        title={tr("Leave team?")}
        confirmLabel={tr("Leave")}
        danger
        busy={leave.isPending}
        onCancel={() => setLeaveOpen(false)}
        onConfirm={() => leave.mutate()}
      >
        {trx(
          "You lose access to all vaults of “{name}”. A manager should rotate the vault keys afterwards.",
          { name: team.name },
        )}
      </ConfirmDialog>
      <ConfirmDialog
        open={deleteOpen}
        title={tr("Delete team?")}
        confirmLabel={tr("Delete")}
        danger
        busy={del.isPending}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={() => del.mutate()}
      >
        {trx(
          "Every team vault and all data inside it is deleted for all {member_count} members. This cannot be undone.",
          { member_count: team.member_count },
        )}
      </ConfirmDialog>
    </Stack>
  );
}

function MembersSection({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const { session } = useAuthState();
  const me = session?.user.id;
  const members = useQuery({
    queryKey: queryKeys.teamMembers(team.id),
    queryFn: () => teamsApi.members(team.id),
  });
  const [removing, setRemoving] = useState<TeamMember | null>(null);
  const [transfer, setTransfer] = useState<TeamMember | null>(null);

  const invalidate = async () => {
    await qc.invalidateQueries({ queryKey: queryKeys.teamMembers(team.id) });
    await qc.invalidateQueries({ queryKey: queryKeys.teams });
    await qc.invalidateQueries({ queryKey: queryKeys.team(team.id) });
  };
  const setRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: TeamRole }) =>
      teamsApi.updateMember(team.id, userId, role),
    onSuccess: async () => {
      setTransfer(null);
      await invalidate();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const rolesQuery = useQuery({
    queryKey: queryKeys.teamRoles(team.id),
    queryFn: () => teamsApi.roles(team.id),
    enabled: isAdmin(team.my_role),
  });
  const roleDefs = rolesQuery.data
    ? [...rolesQuery.data.roles].sort((a, b) => a.position - b.position)
    : null;
  const setRoleId = useMutation({
    mutationFn: ({ userId, role, roleId }: { userId: string; role: TeamRole; roleId: string }) =>
      teamsApi.setMemberRole(team.id, userId, role, roleId),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeys.teamMembers(team.id) });
      await qc.invalidateQueries({ queryKey: queryKeys.teamRoles(team.id) });
      snack.notify(tr("Role updated"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: ({ userId, action }: { userId: string; action: MemberRemoval }) =>
      action === "delete_account"
        ? withStepUp(() => teamsApi.deleteMemberAccount(team.id, userId))
        : teamsApi.removeMember(team.id, userId),
    onSuccess: async (_data, { action }) => {
      setRemoving(null);
      await invalidate();
      snack.notify(
        action === "delete_account"
          ? tr("Account deleted. Rotate affected vault keys to revoke their stale copies.")
          : tr("Member removed. Rotate affected vault keys to revoke their stale copies."),
        "info",
      );
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });

  const admin = isAdmin(team.my_role);

  return (
    <Section title={tr("Members")} disablePadding>
      {members.isPending ? (
        <Loading minHeight={120} />
      ) : members.isError ? (
        <Box sx={{ p: 3 }}>
          <Alert severity="error">{errorMessage(members.error)}</Alert>
        </Box>
      ) : (
        <Paged items={members.data.members}>
          {(page) => (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>{tr("Member")}</TableCell>
                    <TableCell>{tr("Role")}</TableCell>
                    <TableCell>{tr("Joined")}</TableCell>
                    {admin && <TableCell align="right" />}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {page.map((m) => {
                    const canEdit = admin && m.user_id !== me && m.role !== "owner";
                    return (
                      <TableRow key={m.user_id} hover>
                        <TableCell>
                          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                            <UserCell
                              userId={m.user_id}
                              email={m.email}
                              displayName={m.display_name}
                              avatar={m.avatar}
                              you={m.user_id === me}
                            />
                            <MfaBadge m={m} required={team.require_mfa === true} />
                            {m.managed && (
                              <Tooltip
                                title={tr(
                                  "Account was created through this team's invitation; the owner can delete it",
                                )}
                              >
                                <Chip label={tr("Team account")} size="small" variant="outlined" />
                              </Tooltip>
                            )}
                          </Stack>
                        </TableCell>
                        <TableCell>
                          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                            {canEdit && roleDefs ? (
                              <Select
                                size="small"
                                value={m.role_ref?.id ?? ""}
                                onChange={(e) => {
                                  const def = roleDefs.find((r) => r.id === e.target.value);
                                  if (!def) return;
                                  if (def.slug === "owner") setTransfer(m);
                                  else
                                    setRoleId.mutate({
                                      userId: m.user_id,
                                      role: def.slug === "admin" ? "admin" : "member",
                                      roleId: def.id,
                                    });
                                }}
                                sx={{ minWidth: 150 }}
                              >
                                {roleDefs
                                  .filter((r) => r.slug !== "owner" || team.my_role === "owner")
                                  .map((r) => (
                                    <MenuItem key={r.id} value={r.id}>
                                      {r.slug === "owner" ? tr("Owner (transfer)") : r.name}
                                    </MenuItem>
                                  ))}
                              </Select>
                            ) : canEdit ? (
                              <Select
                                size="small"
                                value={m.role}
                                onChange={(e) => {
                                  const role = e.target.value;
                                  if (role === "owner") setTransfer(m);
                                  else setRole.mutate({ userId: m.user_id, role });
                                }}
                                sx={{ minWidth: 130 }}
                              >
                                <MenuItem value="member">{tr("Member")}</MenuItem>
                                <MenuItem value="admin">{tr("Admin")}</MenuItem>
                                {team.my_role === "owner" && (
                                  <MenuItem value="owner">{tr("Owner (transfer)")}</MenuItem>
                                )}
                              </Select>
                            ) : m.role_ref &&
                              !["owner", "admin", "member"].includes(m.role_ref.slug) ? (
                              <Chip
                                size="small"
                                label={m.role_ref.name}
                                sx={{ color: "text.secondary" }}
                              />
                            ) : (
                              <RoleChip role={m.role} />
                            )}
                            {m.role_source && m.role_source !== "manual" && (
                              <Tooltip
                                title={tr("Assigned from {v1} groups", {
                                  v1: m.role_source === "scim" ? "SCIM" : "identity provider",
                                })}
                              >
                                <Chip
                                  size="small"
                                  variant="outlined"
                                  label={m.role_source === "scim" ? "SCIM" : tr("IdP")}
                                  sx={{ height: 20 }}
                                />
                              </Tooltip>
                            )}
                          </Stack>
                        </TableCell>
                        <TableCell>{formatDate(m.joined_at)}</TableCell>
                        {admin && (
                          <TableCell align="right">
                            {canEdit && (
                              <Tooltip title={tr("Remove from team")}>
                                <IconButton
                                  size="small"
                                  onClick={() => setRemoving(m)}
                                  aria-label={tr("Remove member")}
                                >
                                  <PersonRemoveRoundedIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            )}
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
      <RemoveMemberDialog
        key={removing?.user_id ?? ""}
        member={removing}
        canDeleteAccount={team.my_role === "owner"}
        busy={remove.isPending}
        onCancel={() => setRemoving(null)}
        onConfirm={(action) => {
          if (removing) remove.mutate({ userId: removing.user_id, action });
        }}
      />
      <ConfirmDialog
        open={transfer !== null}
        title={tr("Transfer ownership?")}
        confirmLabel={tr("Transfer")}
        busy={setRole.isPending}
        onCancel={() => setTransfer(null)}
        onConfirm={() => {
          if (transfer) setRole.mutate({ userId: transfer.user_id, role: "owner" });
        }}
      >
        {trx("{email} becomes the owner of “{name}” and you become an admin.", {
          email: transfer?.email,
          name: team.name,
        })}
      </ConfirmDialog>
    </Section>
  );
}

type MemberRemoval = "remove" | "delete_account";

function RemoveMemberDialog({
  member,
  canDeleteAccount,
  busy,
  onCancel,
  onConfirm,
}: {
  member: TeamMember | null;
  canDeleteAccount: boolean;
  busy: boolean;
  onCancel: () => void;
  onConfirm: (action: MemberRemoval) => void;
}) {
  const [action, setAction] = useState<MemberRemoval>("remove");
  const [typed, setTyped] = useState("");
  const email = member?.email ?? "";
  const offerDelete = canDeleteAccount && member?.managed === true;
  const deleting = offerDelete && action === "delete_account";
  const confirmed = !deleting || typed.trim().toLowerCase() === email.toLowerCase();

  return (
    <Dialog open={member !== null} onClose={busy ? undefined : onCancel} maxWidth="xs" fullWidth>
      <DialogTitle>{deleting ? tr("Delete account?") : tr("Remove member?")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          {offerDelete ? (
            <>
              <DialogContentText>
                {trx(
                  "{email} was created through this team's invitation. Choose what happens to the account.",
                  { email: email },
                )}
              </DialogContentText>
              <RadioGroup
                value={action}
                onChange={(e) => setAction(e.target.value as MemberRemoval)}
              >
                <FormControlLabel
                  value="remove"
                  control={<Radio size="small" />}
                  label={
                    <>
                      <Typography variant="body2">{tr("Remove from team")}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {tr(
                          "Becomes an individual account and keeps its personal vault; loses access to the team and its vaults.",
                        )}
                      </Typography>
                    </>
                  }
                />
                <FormControlLabel
                  value="delete_account"
                  control={<Radio size="small" color="error" />}
                  label={
                    <>
                      <Typography variant="body2" color="error">
                        {tr("Delete the account")}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {tr(
                          "Permanently deletes the account, its personal vault, devices and session logs. Cannot be undone.",
                        )}
                      </Typography>
                    </>
                  }
                />
              </RadioGroup>
              {deleting && (
                <TextField
                  label={tr("Type {email} to confirm", { email })}
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  autoComplete="off"
                  size="small"
                  fullWidth
                  autoFocus
                />
              )}
            </>
          ) : (
            <DialogContentText>
              {trx("{email} loses access to the team and its vaults.", { email: email })}
            </DialogContentText>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onCancel} disabled={busy} color="inherit">
          {tr("Cancel")}
        </Button>
        <Button
          onClick={() => onConfirm(deleting ? "delete_account" : "remove")}
          variant="contained"
          color="error"
          disabled={busy || !confirmed}
        >
          {deleting ? tr("Delete account") : tr("Remove")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function InvitesSection({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const invites = useQuery({
    queryKey: queryKeys.teamInvites(team.id),
    queryFn: () => teamsApi.invites(team.id),
  });
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list });
  const teamVaults = useMemo(
    () => (vaults.data?.vaults ?? []).filter((v) => v.team_id === team.id),
    [vaults.data, team.id],
  );
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<TeamRole>("member");
  const [vaultIds, setVaultIds] = useState<string[]>([]);
  const [createdUrl, setCreatedUrl] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => teamsApi.createInvite(team.id, email.trim(), role, vaultIds),
    onSuccess: async (r) => {
      setOpen(false);
      setEmail("");
      setVaultIds([]);
      setCreatedUrl(r.url);
      await qc.invalidateQueries({ queryKey: queryKeys.teamInvites(team.id) });
    },
  });
  const revoke = useMutation({
    mutationFn: (inviteId: string) => teamsApi.deleteInvite(team.id, inviteId),
    onSuccess: async () => {
      setRevoking(null);
      await qc.invalidateQueries({ queryKey: queryKeys.teamInvites(team.id) });
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  return (
    <Section
      title={tr("Invitations")}
      description={tr(
        "Pending invitations expire automatically. The invitee receives a link by email when SMTP is configured; you can also copy it.",
      )}
      actions={
        <Button
          variant="outlined"
          startIcon={<PersonAddAltRoundedIcon />}
          onClick={() => setOpen(true)}
        >
          {tr("Invite")}
        </Button>
      }
      disablePadding
    >
      {invites.isPending ? (
        <Loading minHeight={100} />
      ) : invites.isError ? (
        <Box sx={{ p: 3 }}>
          <Alert severity="error">{errorMessage(invites.error)}</Alert>
        </Box>
      ) : invites.data.invites.length === 0 ? (
        <EmptyState title={tr("No pending invitations")} />
      ) : (
        <Paged items={invites.data.invites}>
          {(page) => (
            <List disablePadding>
              {page.map((i) => (
                <ListItem
                  key={i.id}
                  divider
                  secondaryAction={
                    <Tooltip title={tr("Revoke invitation")}>
                      <IconButton
                        edge="end"
                        onClick={() => setRevoking(i.id)}
                        aria-label={tr("Revoke invitation")}
                      >
                        <DeleteOutlineRoundedIcon />
                      </IconButton>
                    </Tooltip>
                  }
                >
                  <ListItemText
                    primary={
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <span>{i.email}</span>
                        <RoleChip role={i.role} />
                      </Stack>
                    }
                    secondary={tr("Sent {v1} · expires {v2}", {
                      v1: formatRelative(i.created_at),
                      v2: formatDate(i.expires_at),
                    })}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </Paged>
      )}

      <Dialog
        open={open}
        onClose={create.isPending ? undefined : () => setOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <form
          onSubmit={(e: SubmitEvent) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <DialogTitle>{trx("Invite to {name}", { name: team.name })}</DialogTitle>
          <DialogContent sx={{ display: "grid", gap: 2 }}>
            {create.isError && <Alert severity="error">{errorMessage(create.error)}</Alert>}
            <TextField
              autoFocus
              label={tr("Email")}
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={create.isPending}
            />
            <FormControl>
              <InputLabel id="invite-role">{tr("Team role")}</InputLabel>
              <Select
                labelId="invite-role"
                label={tr("Team role")}
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <MenuItem value="member">{tr("Member")}</MenuItem>
                <MenuItem value="admin">{tr("Admin")}</MenuItem>
              </Select>
            </FormControl>
            {teamVaults.length > 0 && (
              <FormControl component="fieldset" variant="standard">
                <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
                  {tr("Grant access to vaults (as viewer)")}
                </Typography>
                <FormGroup>
                  {teamVaults.map((v) => (
                    <FormControlLabel
                      key={v.id}
                      control={
                        <Checkbox
                          checked={vaultIds.includes(v.id)}
                          onChange={(e) =>
                            setVaultIds((ids) =>
                              e.target.checked ? [...ids, v.id] : ids.filter((x) => x !== v.id),
                            )
                          }
                        />
                      }
                      label={v.name}
                    />
                  ))}
                </FormGroup>
                <Typography variant="caption" color="text.secondary">
                  {tr(
                    "After they join, a vault manager seals the key to them under “Pending vault keys”.",
                  )}
                </Typography>
              </FormControl>
            )}
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setOpen(false)} color="inherit" disabled={create.isPending}>
              {tr("Cancel")}
            </Button>
            <Button
              type="submit"
              variant="contained"
              disabled={create.isPending || email.trim() === ""}
            >
              {tr("Send invitation")}
            </Button>
          </DialogActions>
        </form>
      </Dialog>

      <Dialog
        open={createdUrl !== null}
        onClose={() => setCreatedUrl(null)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{tr("Invitation created")}</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2 }}>
          <DialogContentText>
            {tr(
              "Share this link with the invitee. It works once and only for their email address.",
            )}
          </DialogContentText>
          <CopyField label={tr("Invitation link")} value={createdUrl ?? ""} />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button variant="contained" onClick={() => setCreatedUrl(null)}>
            {tr("Done")}
          </Button>
        </DialogActions>
      </Dialog>

      <ConfirmDialog
        open={revoking !== null}
        title={tr("Revoke invitation?")}
        confirmLabel={tr("Revoke")}
        danger
        busy={revoke.isPending}
        onCancel={() => setRevoking(null)}
        onConfirm={() => {
          if (revoking) revoke.mutate(revoking);
        }}
      >
        {tr("The invitation link stops working immediately.")}
      </ConfirmDialog>
    </Section>
  );
}

type DigestChoice = DigestCadence | "off";

const digestLabel: Record<DigestChoice, string> = {
  off: "Off",
  daily: "Daily",
  weekly: "Weekly",
};

/** Opt-in e-mail digest of the activity log — the caller's own subscription only. */
function DigestSection({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const { session } = useAuthState();
  const info = useServerInfo();
  const sub = useQuery({
    queryKey: queryKeys.teamDigest(team.id),
    queryFn: () => teamsApi.digest(team.id),
  });
  const emailOk = info.data?.features.email ?? false;
  const verified = session?.user.email_verified ?? false;
  const cadence: DigestChoice = sub.data?.cadence ?? "off";

  const update = useMutation({
    mutationFn: (next: DigestChoice) =>
      teamsApi.updateDigest(team.id, next === "off" ? null : next),
    onSuccess: async (r, next) => {
      qc.setQueryData(queryKeys.teamDigest(team.id), r);
      await qc.invalidateQueries({ queryKey: queryKeys.teamDigest(team.id) });
      snack.notify(
        next === "off"
          ? tr("Activity digest turned off")
          : tr("You'll receive the {v1} digest at {v2}", {
              v1: digestLabel[next].toLowerCase(),
              v2: session?.user.email ?? "your address",
            }),
      );
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const send = useMutation({
    mutationFn: () => teamsApi.sendDigest(team.id, cadence === "weekly" ? "weekly" : "daily"),
    onSuccess: (r) => {
      snack.notify(
        r.sent
          ? tr("Sent — {events} {v1}", {
              events: r.events,
              v1: r.events === 1 ? "event" : "events",
            })
          : tr("Nothing to send: no activity in the last {v1}", {
              v1: cadence === "weekly" ? "week" : "day",
            }),
      );
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  const disabled = !emailOk || !verified || update.isPending;
  const hint = !emailOk
    ? tr("This server has no outgoing e-mail configured, so digests can't be sent.")
    : !verified
      ? tr("Verify your e-mail address in Account first.")
      : undefined;

  return (
    <Section
      title={tr("Activity digest")}
      description={tr(
        "Get the team activity log by e-mail. It goes only to you, contains the same events as the log (who did what, never vault contents), and is skipped for quiet periods.",
      )}
      actions={
        <Button
          variant="outlined"
          startIcon={<MailOutlineRoundedIcon />}
          disabled={disabled || send.isPending}
          onClick={() => send.mutate()}
        >
          {tr("Send now")}
        </Button>
      }
    >
      {hint && (
        <Alert severity="info" sx={{ mb: 1.5 }}>
          {hint}
        </Alert>
      )}
      <SettingRow
        label={tr("Frequency")}
        description={
          cadence === "off"
            ? tr("Not subscribed.")
            : cadence === "daily"
              ? tr("Every morning (07:00 UTC) for the previous day.")
              : tr("Every Monday morning (07:00 UTC) for the previous week.")
        }
        control={
          <Select<DigestChoice>
            size="small"
            value={cadence}
            disabled={disabled || sub.isPending}
            onChange={(e) => update.mutate(e.target.value)}
            sx={{ minWidth: 120 }}
          >
            {(["off", "daily", "weekly"] as const).map((c) => (
              <MenuItem key={c} value={c}>
                {digestLabel[c]}
              </MenuItem>
            ))}
          </Select>
        }
        divider={cadence !== "off"}
      />
      {cadence !== "off" && sub.data?.last_sent_at && (
        <SettingRow
          label={tr("Last sent")}
          control={
            <Typography variant="body2" color="text.secondary">
              {formatRelative(sub.data.last_sent_at)}
            </Typography>
          }
          divider={false}
        />
      )}
    </Section>
  );
}

function PendingKeysSection({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const pending = useQuery({
    queryKey: queryKeys.teamPendingKeys(team.id),
    queryFn: () => teamsApi.pendingKeys(team.id),
  });
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list });
  const members = useQuery({
    queryKey: queryKeys.teamMembers(team.id),
    queryFn: () => teamsApi.members(team.id),
  });

  const grant = useMutation({
    mutationFn: async (items: PendingVaultKey[]) => {
      const byId = new Map((vaults.data?.vaults ?? []).map((v) => [v.id, v]));
      let granted = 0;
      for (const p of items) {
        const vault = byId.get(p.vault_id);
        if (!vault?.sealed_key) continue;
        await grantPendingKey(vault, p);
        granted += 1;
      }
      return granted;
    },
    onSuccess: async (n) => {
      await qc.invalidateQueries({ queryKey: queryKeys.teamPendingKeys(team.id) });
      await qc.invalidateQueries({ queryKey: ["vaults"] });
      snack.notify(n === 1 ? tr("Vault key granted") : tr("{n} vault keys granted", { n }));
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });

  const items = pending.data?.items ?? [];
  if (pending.isPending || items.length === 0) return null;

  const vaultName = (id: string) =>
    vaults.data?.vaults.find((v) => v.id === id)?.name ?? tr("Vault");
  const memberOf = (id: string) => members.data?.members.find((m) => m.user_id === id);
  const grantable = items.filter(
    (p) => vaults.data?.vaults.find((v) => v.id === p.vault_id)?.sealed_key,
  );

  return (
    <Section
      title={tr("Pending vault keys")}
      description={tr(
        "These members joined a vault but do not have its key yet. Granting seals the key to their public key in your browser — the server never sees it.",
      )}
      actions={
        <Button
          variant="contained"
          startIcon={<LockOpenRoundedIcon />}
          disabled={grant.isPending || grantable.length === 0}
          onClick={() => grant.mutate(grantable)}
        >
          {trx("Grant all ({length})", { length: grantable.length })}
        </Button>
      }
      disablePadding
    >
      <Paged items={items}>
        {(page) => (
          <List disablePadding>
            {page.map((p) => {
              const m = memberOf(p.user_id);
              const canGrant = grantable.includes(p);
              return (
                <ListItem
                  key={`${p.vault_id}:${p.user_id}`}
                  divider
                  secondaryAction={
                    <Button
                      size="small"
                      variant="outlined"
                      disabled={grant.isPending || !canGrant}
                      onClick={() => grant.mutate([p])}
                    >
                      {tr("Grant")}
                    </Button>
                  }
                >
                  <ListItemText
                    primary={m ? (m.display_name ?? m.email) : p.user_id}
                    secondary={
                      <>
                        <Link component={RouterLink} to={`/vaults/${p.vault_id}`}>
                          {vaultName(p.vault_id)}
                        </Link>{" "}
                        as {p.role}
                        {!canGrant && " · you do not hold this vault's key"}
                      </>
                    }
                  />
                </ListItem>
              );
            })}
          </List>
        )}
      </Paged>
    </Section>
  );
}

function TeamVaultsSection({ team }: { team: Team }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const snack = useSnackbar();
  const { session } = useAuthState();
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list });
  const members = useQuery({
    queryKey: queryKeys.teamMembers(team.id),
    queryFn: () => teamsApi.members(team.id),
  });
  const teamVaults = (vaults.data?.vaults ?? []).filter((v) => v.team_id === team.id);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [roles, setRoles] = useState<Record<string, VaultRole | "none">>({});

  const create = useMutation({
    mutationFn: async () => {
      const me = session?.user;
      if (!me) throw new Error("Not signed in");
      const all = members.data?.members ?? [];
      const chosen = all.filter(
        (m) => m.user_id === me.id || (roles[m.user_id] ?? "none") !== "none",
      );
      const sealed = await newSealedVaultKey(chosen);
      const upserts = sealed.map((s) => {
        const role: VaultRole = s.user_id === me.id ? "manager" : (roles[s.user_id] as VaultRole);
        return { user_id: s.user_id, role, sealed_key: s.sealed_key };
      });
      return teamsApi.createVault(team.id, name.trim(), upserts);
    },
    onSuccess: async (v: Vault) => {
      setOpen(false);
      setName("");
      setRoles({});
      await qc.invalidateQueries({ queryKey: queryKeys.vaults });
      void navigate(`/vaults/${v.id}`);
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  const admin = isAdmin(team.my_role);

  return (
    <Section
      title={tr("Team vaults")}
      description={tr(
        "Each vault has its own key, sealed to every member. You are always the first manager of a vault you create.",
      )}
      actions={
        admin && (
          <Button variant="outlined" startIcon={<AddRoundedIcon />} onClick={() => setOpen(true)}>
            {tr("New vault")}
          </Button>
        )
      }
      disablePadding
    >
      {vaults.isPending ? (
        <Loading minHeight={100} />
      ) : teamVaults.length === 0 ? (
        <EmptyState
          title={tr("No team vaults yet")}
          description={admin ? tr("Create a vault to start sharing hosts and keys.") : undefined}
        />
      ) : (
        <Paged items={teamVaults}>
          {(page) => (
            <List disablePadding>
              {page.map((v) => (
                <ListItem
                  key={v.id}
                  divider
                  component={RouterLink}
                  to={`/vaults/${v.id}`}
                  sx={{ color: "inherit", textDecoration: "none" }}
                >
                  <ListItemText
                    primary={
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <span>{v.name}</span>
                        <RoleChip role={v.my_role} />
                        {!v.sealed_key && (
                          <Typography variant="caption" color="warning.main">
                            {tr("key pending")}
                          </Typography>
                        )}
                      </Stack>
                    }
                    secondary={tr("Key version {key_version} · created {v1}", {
                      key_version: v.key_version,
                      v1: formatDate(v.created_at),
                    })}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </Paged>
      )}

      <Dialog
        open={open}
        onClose={create.isPending ? undefined : () => setOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <form
          onSubmit={(e: SubmitEvent) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <DialogTitle>{tr("New team vault")}</DialogTitle>
          <DialogContent sx={{ display: "grid", gap: 2 }}>
            <TextField
              autoFocus
              label={tr("Vault name")}
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={create.isPending}
            />
            <Typography variant="subtitle2">{tr("Members")}</Typography>
            <TableContainer>
              <Table size="small">
                <TableBody>
                  {(members.data?.members ?? []).map((m) => {
                    const isMe = m.user_id === session?.user.id;
                    return (
                      <TableRow key={m.user_id}>
                        <TableCell sx={{ pl: 0 }}>
                          <UserCell
                            userId={m.user_id}
                            email={m.email}
                            displayName={m.display_name}
                            avatar={m.avatar}
                            you={isMe}
                          />
                        </TableCell>
                        <TableCell align="right" sx={{ pr: 0 }}>
                          {isMe ? (
                            <RoleChip role="manager" />
                          ) : (
                            <Select
                              size="small"
                              value={roles[m.user_id] ?? "none"}
                              onChange={(e) =>
                                setRoles((r) => ({ ...r, [m.user_id]: e.target.value }))
                              }
                              sx={{ minWidth: 130 }}
                            >
                              <MenuItem value="none">{tr("No access")}</MenuItem>
                              <MenuItem value="viewer">{tr("Viewer")}</MenuItem>
                              <MenuItem value="editor">{tr("Editor")}</MenuItem>
                              <MenuItem value="manager">{tr("Manager")}</MenuItem>
                            </Select>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setOpen(false)} color="inherit" disabled={create.isPending}>
              {tr("Cancel")}
            </Button>
            <Button
              type="submit"
              variant="contained"
              disabled={create.isPending || name.trim() === ""}
            >
              {tr("Create")}
            </Button>
          </DialogActions>
        </form>
      </Dialog>
    </Section>
  );
}
