import { useState } from "react";
import { tr } from "@/i18n";
import {
  Alert,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
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
import type {
  AclEntityKind,
  AclMode,
  AclPrincipalKind,
  EntityAclRule,
  Team,
  Vault,
} from "@/api/types";
import { useServerPager } from "@/components/Pager";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { can } from "../team/perm";

const MODES: { value: AclMode; label: () => string; hint: () => string }[] = [
  { value: "none", label: () => tr("Hidden"), hint: () => tr("Not shown at all") },
  {
    value: "connect",
    label: () => tr("Connect only"),
    hint: () => tr("Can connect, secrets stay hidden"),
  },
  { value: "read", label: () => tr("Read"), hint: () => tr("Sees everything, cannot change") },
  { value: "edit", label: () => tr("Edit"), hint: () => tr("Full access to the host or group") },
];

/** Group/host access rules of a team vault. Entities are ciphertext to the
 *  server, so the cabinet works with entity IDs; names are visible in the
 *  desktop and mobile apps, where rules are normally created. */
export function AclSection({ vault, team }: { vault: Vault; team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const manage = can(team, "acl.manage");
  const pg = useServerPager();
  const q = useQuery({
    queryKey: [...queryKeys.vaultAcl(team.id, vault.id), pg.offset, pg.limit],
    queryFn: () => teamsApi.acl(team.id, vault.id, pg.window),
    placeholderData: (prev) => prev,
  });
  const [adding, setAdding] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: queryKeys.vaultAcl(team.id, vault.id) });
  const setMode = useMutation({
    mutationFn: ({ r, mode }: { r: EntityAclRule; mode: AclMode }) =>
      teamsApi.upsertAcl(team.id, vault.id, {
        entity_id: r.entity_id,
        entity_kind: r.entity_kind,
        principal_kind: r.principal_kind,
        role_id: r.role_id ?? undefined,
        user_id: r.user_id ?? undefined,
        group_name: r.group_name ?? undefined,
        mode,
      }),
    onSuccess: refresh,
    onError: (e) => snack.error(errorMessage(e)),
  });
  const del = useMutation({
    mutationFn: (r: EntityAclRule) => teamsApi.deleteAcl(team.id, vault.id, r.id),
    onSuccess: async () => {
      await refresh();
      snack.notify(tr("Rule removed"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const rules = q.data.rules;
  if (!manage && rules.length === 0) return null;
  const principalChip = (r: EntityAclRule) =>
    r.principal_kind === "role"
      ? tr("Role")
      : r.principal_kind === "member"
        ? tr("Member")
        : tr("IdP group");
  return (
    <Section
      title={tr("Group and host access")}
      description={tr(
        "Rules narrow what a role, a member or an IdP group sees inside this vault: a group or host can be hidden, connect-only (no secrets), read-only or editable. Most specific rule wins (member › IdP group › role); a group rule covers the hosts inside it. Owners and admins are not limited.",
      )}
      actions={
        manage && (
          <Button variant="outlined" startIcon={<AddRoundedIcon />} onClick={() => setAdding(true)}>
            {tr("Add rule")}
          </Button>
        )
      }
    >
      <Alert severity="info" sx={{ mb: 2 }}>
        <strong>{tr("ACL does not replace a separate vault.")}</strong>{" "}
        {tr(
          "Every member of this vault holds its key and could decrypt everything in it with a modified client. Rules are for order and discipline inside the vault; hosts that some members must never see belong in a vault they are not a member of.",
        )}
      </Alert>
      {rules.length === 0 ? (
        <EmptyState
          title={tr("No rules")}
          description={tr(
            "Everyone in the vault sees every group and host according to their team permissions.",
          )}
        />
      ) : (
        <>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{tr("Who")}</TableCell>
                  <TableCell>{tr("What")}</TableCell>
                  <TableCell>{tr("Access")}</TableCell>
                  {manage && <TableCell align="right" />}
                </TableRow>
              </TableHead>
              <TableBody>
                {rules.map((r) => (
                  <TableRow key={r.id} hover>
                    <TableCell>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Chip size="small" variant="outlined" label={principalChip(r)} />
                        <Typography variant="body2">{r.principal_name}</Typography>
                      </Stack>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {r.entity_kind === "group" ? tr("Group") : tr("Host")}
                      </Typography>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ fontFamily: "monospace" }}
                      >
                        {r.entity_id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {manage ? (
                        <Select
                          size="small"
                          value={r.mode}
                          disabled={setMode.isPending}
                          onChange={(e) => setMode.mutate({ r, mode: e.target.value })}
                          sx={{ minWidth: 150 }}
                        >
                          {MODES.map((m) => (
                            <MenuItem key={m.value} value={m.value}>
                              {m.label()}
                            </MenuItem>
                          ))}
                        </Select>
                      ) : (
                        (MODES.find((m) => m.value === r.mode)?.label() ?? r.mode)
                      )}
                    </TableCell>
                    {manage && (
                      <TableCell align="right">
                        <Tooltip title={tr("Remove rule")}>
                          <IconButton
                            size="small"
                            aria-label={tr("Remove rule")}
                            disabled={del.isPending}
                            onClick={() => del.mutate(r)}
                          >
                            <DeleteOutlineRoundedIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          {pg.pager(q.data.total)}
        </>
      )}
      {manage && (
        <AddRuleDialog
          open={adding}
          vault={vault}
          team={team}
          onClose={() => setAdding(false)}
          onDone={() => {
            setAdding(false);
            void refresh();
          }}
        />
      )}
    </Section>
  );
}

function AddRuleDialog({
  open,
  vault,
  team,
  onClose,
  onDone,
}: {
  open: boolean;
  vault: Vault;
  team: Team;
  onClose: () => void;
  onDone: () => void;
}) {
  const snack = useSnackbar();
  const roles = useQuery({
    queryKey: queryKeys.teamRoles(team.id),
    queryFn: () => teamsApi.roles(team.id),
    enabled: open,
  });
  const members = useQuery({
    queryKey: queryKeys.vaultMembers(vault.id),
    queryFn: () => vaultsApi.members(vault.id),
    enabled: open,
  });
  const [principalKind, setPrincipalKind] = useState<AclPrincipalKind>("role");
  const [roleId, setRoleId] = useState("");
  const [userId, setUserId] = useState("");
  const [groupName, setGroupName] = useState("");
  const [entityKind, setEntityKind] = useState<AclEntityKind>("group");
  const [entityId, setEntityId] = useState("");
  const [mode, setMode] = useState<AclMode>("connect");
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const principalOk =
    principalKind === "role"
      ? roleId !== ""
      : principalKind === "member"
        ? userId !== ""
        : groupName.trim() !== "";
  const valid = principalOk && uuid.test(entityId.trim());
  const m = useMutation({
    mutationFn: () =>
      teamsApi.upsertAcl(team.id, vault.id, {
        entity_id: entityId.trim().toLowerCase(),
        entity_kind: entityKind,
        principal_kind: principalKind,
        role_id: principalKind === "role" ? roleId : undefined,
        user_id: principalKind === "member" ? userId : undefined,
        group_name: principalKind === "group" ? groupName.trim() : undefined,
        mode,
      }),
    onSuccess: () => {
      snack.notify(tr("Rule added"));
      setEntityId("");
      onDone();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const nonOwnerRoles = (roles.data?.roles ?? []).filter((r) => r.slug !== "owner");
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{tr("Add access rule")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <TextField
            select
            size="small"
            label={tr("Applies to")}
            value={principalKind}
            onChange={(e) => setPrincipalKind(e.target.value as AclPrincipalKind)}
          >
            <MenuItem value="role">{tr("Team role")}</MenuItem>
            <MenuItem value="member">{tr("Vault member")}</MenuItem>
            <MenuItem value="group">{tr("IdP / SCIM group")}</MenuItem>
          </TextField>
          {principalKind === "role" && (
            <TextField
              select
              size="small"
              label={tr("Role")}
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
            >
              {nonOwnerRoles.map((r) => (
                <MenuItem key={r.id} value={r.id}>
                  {tr(r.name)}
                </MenuItem>
              ))}
            </TextField>
          )}
          {principalKind === "member" && (
            <TextField
              select
              size="small"
              label={tr("Member")}
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
            >
              {(members.data?.members ?? []).map((u) => (
                <MenuItem key={u.user_id} value={u.user_id}>
                  {u.display_name ?? u.email}
                </MenuItem>
              ))}
            </TextField>
          )}
          {principalKind === "group" && (
            <TextField
              size="small"
              label={tr("Group name")}
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              helperText={tr("Exactly as the IdP or SCIM sends it.")}
            />
          )}
          <TextField
            select
            size="small"
            label={tr("Object")}
            value={entityKind}
            onChange={(e) => setEntityKind(e.target.value as AclEntityKind)}
          >
            <MenuItem value="group">{tr("Group (and the hosts inside)")}</MenuItem>
            <MenuItem value="host">{tr("Host")}</MenuItem>
          </TextField>
          <TextField
            size="small"
            label={tr("Entity ID")}
            value={entityId}
            onChange={(e) => setEntityId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            helperText={tr(
              "Names are encrypted, so the cabinet takes the ID. Copy it from the desktop app (host or group → Details), or create the rule there by name.",
            )}
            slotProps={{ htmlInput: { style: { fontFamily: "monospace" } } }}
          />
          <TextField
            select
            size="small"
            label={tr("Access")}
            value={mode}
            onChange={(e) => setMode(e.target.value as AclMode)}
            helperText={MODES.find((x) => x.value === mode)?.hint()}
          >
            {MODES.map((x) => (
              <MenuItem key={x.value} value={x.value}>
                {x.label()}
              </MenuItem>
            ))}
          </TextField>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button variant="contained" disabled={!valid || m.isPending} onClick={() => m.mutate()}>
          {tr("Add")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
