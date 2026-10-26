import { useMemo, useState } from "react";
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
  DialogTitle,
  FormControl,
  IconButton,
  InputLabel,
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
import StarRoundedIcon from "@mui/icons-material/StarRounded";
import StarOutlineRoundedIcon from "@mui/icons-material/StarOutlineRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { teamsApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { PermissionInfo, RoleMapping, Team, TeamRoleDef } from "@/api/types";
import { Paged } from "@/components/Pager";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { can } from "./perm";

function groupLabel(group: string): string {
  const k = `perm_group:${group}`;
  const v = tr(k);
  return v === k ? group : v;
}

export function RolesTab({ team }: { team: Team }) {
  const manage = can(team, "roles.manage");
  const catalog = useQuery({
    queryKey: queryKeys.teamPermissions(team.id),
    queryFn: () => teamsApi.permissions(team.id),
    staleTime: 10 * 60_000,
  });
  const roles = useQuery({
    queryKey: queryKeys.teamRoles(team.id),
    queryFn: () => teamsApi.roles(team.id),
  });
  if (catalog.isPending || roles.isPending) return <Loading />;
  if (catalog.isError) return <Alert severity="error">{errorMessage(catalog.error)}</Alert>;
  if (roles.isError) return <Alert severity="error">{errorMessage(roles.error)}</Alert>;
  return (
    <>
      <Matrix
        team={team}
        permissions={catalog.data.permissions}
        roles={roles.data.roles}
        defaultRoleId={roles.data.default_role_id}
        manage={manage}
      />
      {manage && <MappingsSection team={team} roles={roles.data.roles} />}
    </>
  );
}

function Matrix({
  team,
  permissions,
  roles,
  defaultRoleId,
  manage,
}: {
  team: Team;
  permissions: PermissionInfo[];
  roles: TeamRoleDef[];
  defaultRoleId: string | null;
  manage: boolean;
}) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const [createOpen, setCreateOpen] = useState(false);
  const [deleting, setDeleting] = useState<TeamRoleDef | null>(null);
  const [reassign, setReassign] = useState<string>("");
  const invalidate = () => qc.invalidateQueries({ queryKey: queryKeys.teamRoles(team.id) });

  const toggle = useMutation({
    mutationFn: ({ role, key, on }: { role: TeamRoleDef; key: string; on: boolean }) =>
      teamsApi.updateRole(team.id, role.id, {
        permissions: on ? [...role.permissions, key] : role.permissions.filter((p) => p !== key),
      }),
    onSuccess: invalidate,
    onError: (e) => snack.error(errorMessage(e)),
  });
  const setDefault = useMutation({
    mutationFn: (roleId: string) => teamsApi.setDefaultRole(team.id, roleId),
    onSuccess: async () => {
      await invalidate();
      snack.notify(tr("Default role updated"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: ({ role, to }: { role: TeamRoleDef; to?: string }) =>
      teamsApi.deleteRole(team.id, role.id, to),
    onSuccess: async () => {
      setDeleting(null);
      await invalidate();
      await qc.invalidateQueries({ queryKey: queryKeys.teamMembers(team.id) });
      snack.notify(tr("Role deleted"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  const groups = useMemo(() => {
    const m = new Map<string, PermissionInfo[]>();
    for (const p of permissions) m.set(p.group, [...(m.get(p.group) ?? []), p]);
    return [...m.entries()];
  }, [permissions]);
  const sorted = [...roles].sort((a, b) => a.position - b.position);
  const mine = new Set(team.my_permissions ?? []);
  const iHave = (key: string) => mine.has("*") || mine.has(key);

  return (
    <Section
      title={tr("Roles")}
      description={tr(
        "One role per member. Built-in roles are fixed; custom roles start as a copy of one of them. Permissions marked “client” are honoured by the apps and are not a server-side boundary.",
      )}
      actions={
        manage && (
          <Button startIcon={<AddRoundedIcon />} onClick={() => setCreateOpen(true)}>
            {tr("New role")}
          </Button>
        )
      }
      disablePadding
    >
      <TableContainer sx={{ maxHeight: "70vh" }}>
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell sx={{ minWidth: 260 }}>{tr("Permission")}</TableCell>
              {sorted.map((r) => (
                <TableCell key={r.id} align="center" sx={{ minWidth: 110 }}>
                  <Stack spacing={0.25} sx={{ alignItems: "center" }}>
                    <Stack direction="row" spacing={0.25} sx={{ alignItems: "center" }}>
                      <Typography variant="subtitle2" noWrap>
                        {tr(r.name)}
                      </Typography>
                      {manage && r.slug !== "owner" && (
                        <Tooltip
                          title={
                            r.id === defaultRoleId
                              ? tr("Default role for new members")
                              : tr("Make default")
                          }
                        >
                          <span>
                            <IconButton
                              size="small"
                              disabled={r.id === defaultRoleId || setDefault.isPending}
                              onClick={() => setDefault.mutate(r.id)}
                              aria-label={tr("Make default role")}
                            >
                              {r.id === defaultRoleId ? (
                                <StarRoundedIcon fontSize="inherit" color="primary" />
                              ) : (
                                <StarOutlineRoundedIcon fontSize="inherit" />
                              )}
                            </IconButton>
                          </span>
                        </Tooltip>
                      )}
                      {manage && !r.builtin && (
                        <Tooltip title={tr("Delete role")}>
                          <IconButton
                            size="small"
                            onClick={() => {
                              setReassign(defaultRoleId ?? "");
                              setDeleting(r);
                            }}
                            aria-label={tr("Delete role")}
                          >
                            <DeleteOutlineRoundedIcon fontSize="inherit" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Stack>
                    <Typography variant="caption" color="text.secondary">
                      {trn(r.member_count, "{count} member", "{count} members")}
                      {r.builtin ? tr(" · built-in") : ""}
                    </Typography>
                  </Stack>
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {groups.map(([group, perms]) => (
              <GroupRows
                key={group}
                group={group}
                perms={perms}
                roles={sorted}
                manage={manage}
                iHave={iHave}
                busy={toggle.isPending}
                onToggle={(role, key, on) => toggle.mutate({ role, key, on })}
              />
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <CreateRoleDialog
        open={createOpen}
        team={team}
        roles={sorted}
        onClose={() => setCreateOpen(false)}
      />
      <Dialog open={deleting !== null} onClose={() => setDeleting(null)} maxWidth="xs" fullWidth>
        <DialogTitle>{trx("Delete role “{name}”?", { name: deleting?.name })}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {trx("{v1} member(s) currently hold it and will be moved to:", {
                v1: deleting?.member_count ?? 0,
              })}
            </Typography>
            <FormControl size="small" fullWidth>
              <InputLabel id="reassign-label">{tr("Role")}</InputLabel>
              <Select
                labelId="reassign-label"
                label={tr("Role")}
                value={reassign}
                onChange={(e) => setReassign(e.target.value)}
              >
                {sorted
                  .filter((r) => r.id !== deleting?.id && r.slug !== "owner")
                  .map((r) => (
                    <MenuItem key={r.id} value={r.id}>
                      {tr(r.name)}
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleting(null)}>{tr("Cancel")}</Button>
          <Button
            color="error"
            variant="contained"
            disabled={remove.isPending || !reassign}
            onClick={() => deleting && remove.mutate({ role: deleting, to: reassign })}
          >
            {tr("Delete")}
          </Button>
        </DialogActions>
      </Dialog>
    </Section>
  );
}

function GroupRows({
  group,
  perms,
  roles,
  manage,
  iHave,
  busy,
  onToggle,
}: {
  group: string;
  perms: PermissionInfo[];
  roles: TeamRoleDef[];
  manage: boolean;
  iHave: (key: string) => boolean;
  busy: boolean;
  onToggle: (role: TeamRoleDef, key: string, on: boolean) => void;
}) {
  return (
    <>
      <TableRow>
        <TableCell colSpan={roles.length + 1} sx={{ bgcolor: "action.hover" }}>
          <Typography variant="overline">{groupLabel(group)}</Typography>
        </TableCell>
      </TableRow>
      {perms.map((p) => (
        <TableRow key={p.key} hover>
          <TableCell>
            <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
              <Tooltip title={tr(p.description)} placement="right">
                <Typography variant="body2">{tr(p.title)}</Typography>
              </Tooltip>
              {p.enforced_by === "client" && (
                <Chip label={tr("client")} size="small" variant="outlined" sx={{ height: 18 }} />
              )}
              {p.dangerous && (
                <Chip label={tr("sensitive")} size="small" color="warning" sx={{ height: 18 }} />
              )}
            </Stack>
            <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
              {p.key}
            </Typography>
          </TableCell>
          {roles.map((r) => {
            const on = r.permissions.includes("*") || r.permissions.includes(p.key);
            const editable = manage && !r.builtin && iHave(p.key);
            return (
              <TableCell key={r.id} align="center" padding="checkbox">
                <Checkbox
                  size="small"
                  checked={on}
                  disabled={!editable || busy}
                  onChange={(e) => onToggle(r, p.key, e.target.checked)}
                  slotProps={{ input: { "aria-label": `${tr(r.name)}: ${p.title}` } }}
                />
              </TableCell>
            );
          })}
        </TableRow>
      ))}
    </>
  );
}

function CreateRoleDialog({
  open,
  team,
  roles,
  onClose,
}: {
  open: boolean;
  team: Team;
  roles: TeamRoleDef[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [copyFrom, setCopyFrom] = useState(roles.find((r) => r.slug === "member")?.id ?? "");
  const create = useMutation({
    mutationFn: () => {
      const base = roles.find((r) => r.id === copyFrom);
      return teamsApi.createRole(team.id, {
        name: name.trim(),
        description: description.trim(),
        permissions: base ? base.permissions.filter((p) => p !== "*") : [],
        copy_from: copyFrom || undefined,
      });
    },
    onSuccess: async () => {
      onClose();
      setName("");
      setDescription("");
      await qc.invalidateQueries({ queryKey: queryKeys.teamRoles(team.id) });
      snack.notify(tr("Role created"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{tr("New role")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <TextField
            label={tr("Name")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            fullWidth
            slotProps={{ htmlInput: { maxLength: 40 } }}
          />
          <TextField
            label={tr("Description")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            fullWidth
            slotProps={{ htmlInput: { maxLength: 200 } }}
          />
          <FormControl size="small" fullWidth>
            <InputLabel id="copy-label">{tr("Start from")}</InputLabel>
            <Select
              labelId="copy-label"
              label={tr("Start from")}
              value={copyFrom}
              onChange={(e) => setCopyFrom(e.target.value)}
            >
              {roles
                .filter((r) => r.slug !== "owner")
                .map((r) => (
                  <MenuItem key={r.id} value={r.id}>
                    {tr(r.name)}
                  </MenuItem>
                ))}
            </Select>
          </FormControl>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button
          variant="contained"
          disabled={!name.trim() || create.isPending}
          onClick={() => create.mutate()}
        >
          {tr("Create")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function MappingsSection({ team, roles }: { team: Team; roles: TeamRoleDef[] }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const q = useQuery({
    queryKey: queryKeys.teamRoleMappings(team.id),
    queryFn: () => teamsApi.roleMappings(team.id),
  });
  const [draft, setDraft] = useState<RoleMapping[] | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const rows = draft ?? q.data?.mappings ?? [];
  const save = useMutation({
    mutationFn: (mappings: RoleMapping[]) => teamsApi.setRoleMappings(team.id, mappings),
    onSuccess: async () => {
      setDraft(null);
      await qc.invalidateQueries({ queryKey: queryKeys.teamRoleMappings(team.id) });
      snack.notify(tr("Group mappings saved"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const assignable = roles.filter((r) => r.slug !== "owner");
  const update = (i: number, patch: Partial<RoleMapping>) =>
    setDraft(rows.map((m, j) => (j === i ? { ...m, ...patch } : m)));
  if (q.isPending) return <Loading minHeight={80} />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  return (
    <Section
      title={tr("Roles from identity provider groups")}
      description={tr(
        "Members who sign in through SSO or arrive via SCIM get the role of the first matching group (lowest priority number wins). Matching is case-insensitive; the owner is never changed.",
      )}
      actions={
        <Stack direction="row" spacing={1}>
          {rows.length > 0 && (
            <Button color="inherit" onClick={() => setConfirmClear(true)}>
              {tr("Clear")}
            </Button>
          )}
          <Button
            startIcon={<AddRoundedIcon />}
            onClick={() =>
              setDraft([
                ...rows,
                {
                  group_name: "",
                  role_id: assignable[0]?.id ?? "",
                  priority: (rows.at(-1)?.priority ?? 0) + 10,
                },
              ])
            }
          >
            {tr("Add mapping")}
          </Button>
        </Stack>
      }
      disablePadding={rows.length > 0}
    >
      {rows.length === 0 ? (
        <EmptyState
          title={tr("No group mappings")}
          description={tr("Roles are assigned manually.")}
        />
      ) : (
        <>
          <Paged items={rows}>
            {(page, start) => (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>{tr("IdP group")}</TableCell>
                      <TableCell>{tr("Role")}</TableCell>
                      <TableCell sx={{ width: 110 }}>{tr("Priority")}</TableCell>
                      <TableCell align="right" />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {page.map((m, k) => {
                      const i = start + k;
                      return (
                        <TableRow key={i}>
                          <TableCell>
                            <TextField
                              size="small"
                              value={m.group_name}
                              placeholder={tr("e.g. engineering")}
                              onChange={(e) => update(i, { group_name: e.target.value })}
                              fullWidth
                            />
                          </TableCell>
                          <TableCell>
                            <Select
                              size="small"
                              value={m.role_id}
                              onChange={(e) => update(i, { role_id: e.target.value })}
                              sx={{ minWidth: 160 }}
                            >
                              {assignable.map((r) => (
                                <MenuItem key={r.id} value={r.id}>
                                  {tr(r.name)}
                                </MenuItem>
                              ))}
                            </Select>
                          </TableCell>
                          <TableCell>
                            <TextField
                              size="small"
                              type="number"
                              value={m.priority}
                              onChange={(e) => update(i, { priority: Number(e.target.value) })}
                            />
                          </TableCell>
                          <TableCell align="right">
                            <IconButton
                              size="small"
                              onClick={() => setDraft(rows.filter((_, j) => j !== i))}
                              aria-label={tr("Remove mapping")}
                            >
                              <DeleteOutlineRoundedIcon fontSize="small" />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paged>
          {draft && (
            <Box sx={{ p: 2, display: "flex", gap: 1, justifyContent: "flex-end" }}>
              <Button onClick={() => setDraft(null)}>{tr("Discard")}</Button>
              <Button
                variant="contained"
                disabled={save.isPending || rows.some((m) => !m.group_name.trim() || !m.role_id)}
                onClick={() => save.mutate(rows)}
              >
                {tr("Save mappings")}
              </Button>
            </Box>
          )}
        </>
      )}
      <ConfirmDialog
        open={confirmClear}
        title={tr("Remove all group mappings?")}
        confirmLabel={tr("Remove")}
        danger
        busy={save.isPending}
        onCancel={() => setConfirmClear(false)}
        onConfirm={() => {
          setConfirmClear(false);
          save.mutate([]);
        }}
      >
        {tr("Members keep their current roles; new sign-ins get the team default.")}
      </ConfirmDialog>
    </Section>
  );
}
