import { useEffect, useState } from "react";
import { tr, trx, trn } from "@/i18n";
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Drawer,
  FormControlLabel,
  IconButton,
  InputAdornment,
  MenuItem,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { adminApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { AdminUpdateUserRequest, AdminUser } from "@/api/types";
import { useAuthState } from "@/auth/store";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { PageHeader } from "@/components/PageHeader";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { UserCell } from "@/components/UserCell";
import { formatDateTime, formatRelative } from "@/components/format";

/** Team chips shown inline per user; the rest collapse into a "+N more" tooltip. */
const TEAM_CHIPS = 3;

function useDebounced(value: string, ms = 300): string {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function AdminUsersPage() {
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim());
  const [page, setPage] = useState(0);
  const [limit, setLimit] = useState(25);
  const [selected, setSelected] = useState<string | null>(null);
  const [team, setTeam] = useState("");
  const [sort, setSort] = useState("created");
  const teamList = useQuery({
    queryKey: ["admin", "teams", "all"],
    queryFn: () => adminApi.teams({ offset: 0, limit: 200 }),
  });
  const offset = page * limit;
  const users = useQuery({
    queryKey: [...queryKeys.adminUsers(q, offset, limit), team, sort],
    queryFn: () => adminApi.users({ q, offset, limit, team: team || undefined, sort }),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader
        title={tr("Users")}
        subtitle={tr(
          "Everyone registered on this server. The server never sees passwords or vault contents, so there is nothing to reset except MFA and sessions.",
        )}
        actions={
          <TextField
            size="small"
            placeholder={tr("Search by email or name")}
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchRoundedIcon fontSize="small" />
                  </InputAdornment>
                ),
              },
            }}
            sx={{ minWidth: 280 }}
          />
        }
      />
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mb: 2 }}>
        <TextField
          select
          size="small"
          label={tr("Team")}
          value={team}
          onChange={(e) => {
            setTeam(e.target.value);
            setPage(0);
          }}
          sx={{ minWidth: 200 }}
        >
          <MenuItem value="">{tr("All teams")}</MenuItem>
          {(teamList.data?.items ?? []).map((t) => (
            <MenuItem key={t.id} value={t.id}>
              {t.name}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          select
          size="small"
          label={tr("Sort by")}
          value={sort}
          onChange={(e) => {
            setSort(e.target.value);
            setPage(0);
          }}
          sx={{ minWidth: 180 }}
        >
          <MenuItem value="created">{tr("Newest first")}</MenuItem>
          <MenuItem value="last_seen">{tr("Last seen")}</MenuItem>
          <MenuItem value="email">{tr("E-mail")}</MenuItem>
          <MenuItem value="devices">{tr("Devices")}</MenuItem>
        </TextField>
      </Stack>
      <Section
        title={users.data ? trn(users.data.total, "{count} user", "{count} users") : tr("Users")}
        disablePadding
      >
        {users.isPending ? (
          <Loading />
        ) : users.isError ? (
          <Box sx={{ p: 3 }}>
            <Alert severity="error">{errorMessage(users.error)}</Alert>
          </Box>
        ) : users.data.items.length === 0 ? (
          <EmptyState title={tr("No users match")} />
        ) : (
          <>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>{tr("User")}</TableCell>
                    <TableCell>{tr("Status")}</TableCell>
                    <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                      {tr("Teams")}
                    </TableCell>
                    <TableCell align="right">{tr("Devices")}</TableCell>
                    <TableCell>{tr("Last seen")}</TableCell>
                    <TableCell>{tr("Joined")}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {users.data.items.map((u) => (
                    <TableRow
                      key={u.id}
                      hover
                      sx={{ cursor: "pointer" }}
                      onClick={() => setSelected(u.id)}
                      selected={selected === u.id}
                    >
                      <TableCell>
                        <UserCell
                          userId={u.id}
                          email={u.email}
                          displayName={u.display_name}
                          avatar={u.avatar}
                        />
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: "wrap" }}>
                          {u.is_owner && (
                            <Chip size="small" color="secondary" label={tr("Owner")} />
                          )}
                          {u.is_admin && !u.is_owner && (
                            <Chip size="small" color="primary" label={tr("Admin")} />
                          )}
                          {u.disabled && <Chip size="small" color="error" label={tr("Disabled")} />}
                          {u.email_verified ? (
                            <Chip
                              size="small"
                              variant="outlined"
                              color="success"
                              label={tr("Verified")}
                            />
                          ) : (
                            <Chip
                              size="small"
                              variant="outlined"
                              color="warning"
                              label={tr("Unverified")}
                            />
                          )}
                          {u.mfa_enabled && (
                            <Chip size="small" variant="outlined" label={tr("MFA")} />
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell sx={{ display: { xs: "none", md: "table-cell" }, maxWidth: 360 }}>
                        <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: "wrap" }}>
                          {(u.teams ?? []).slice(0, TEAM_CHIPS).map((t) => (
                            <Chip
                              key={t.id}
                              size="small"
                              variant="outlined"
                              label={`${t.name} · ${tr(t.role)}`}
                              sx={{ maxWidth: 160 }}
                            />
                          ))}
                          {(u.teams ?? []).length > TEAM_CHIPS && (
                            <Tooltip
                              title={
                                <Stack component="span" spacing={0.25}>
                                  {(u.teams ?? []).slice(TEAM_CHIPS).map((t) => (
                                    <span key={t.id}>{`${t.name} · ${tr(t.role)}`}</span>
                                  ))}
                                </Stack>
                              }
                            >
                              <Chip
                                size="small"
                                variant="outlined"
                                label={tr("+{n} more", {
                                  n: String((u.teams ?? []).length - TEAM_CHIPS),
                                })}
                              />
                            </Tooltip>
                          )}
                          {u.source && u.source !== "password" && (
                            <Chip
                              size="small"
                              color="info"
                              variant="outlined"
                              label={u.source.toUpperCase()}
                            />
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell align="right">{u.devices}</TableCell>
                      <TableCell>{formatRelative(u.last_seen_at)}</TableCell>
                      <TableCell>{formatDateTime(u.created_at)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              component="div"
              count={users.data.total}
              page={page}
              onPageChange={(_e, p) => setPage(p)}
              rowsPerPage={limit}
              onRowsPerPageChange={(e) => {
                setLimit(Number(e.target.value));
                setPage(0);
              }}
              rowsPerPageOptions={[25, 50, 100]}
            />
          </>
        )}
      </Section>
      <UserDrawer id={selected} onClose={() => setSelected(null)} />
    </>
  );
}

function UserDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const { session } = useAuthState();
  const isMe = id !== null && id === session?.user.id;
  const isOwner = session?.user.is_owner === true;
  const user = useQuery({
    queryKey: ["admin", "user", id],
    queryFn: () => adminApi.user(id ?? ""),
    enabled: id !== null,
  });
  const [confirm, setConfirm] = useState<"revoke" | "reset-mfa" | "delete" | null>(null);

  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: ["admin", "user", id] });
    await qc.invalidateQueries({ queryKey: ["admin", "users"] });
    await qc.invalidateQueries({ queryKey: queryKeys.adminStats });
  };
  const update = useMutation({
    mutationFn: (req: AdminUpdateUserRequest) => adminApi.updateUser(id ?? "", req),
    onSuccess: refresh,
    onError: (e) => snack.error(errorMessage(e)),
  });
  const action = useMutation({
    mutationFn: async (kind: "revoke" | "reset-mfa" | "delete") => {
      const uid = id ?? "";
      if (kind === "revoke") await adminApi.revokeSessions(uid);
      else if (kind === "reset-mfa") await adminApi.resetMfa(uid);
      else await adminApi.deleteUser(uid);
      return kind;
    },
    onSuccess: async (kind) => {
      setConfirm(null);
      if (kind === "delete") {
        onClose();
        snack.notify(tr("User deleted"));
      } else {
        snack.notify(
          kind === "revoke"
            ? tr("All sessions revoked")
            : tr("MFA reset; the user can sign in with password only"),
        );
      }
      await refresh();
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  const u: AdminUser | undefined = user.data;
  return (
    <Drawer
      anchor="right"
      open={id !== null}
      onClose={onClose}
      slotProps={{ paper: { sx: { width: { xs: "100%", sm: 420 }, p: 3 } } }}
    >
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 2 }}>
        <Typography variant="h6">{tr("User")}</Typography>
        <IconButton onClick={onClose} aria-label={tr("Close")}>
          <CloseRoundedIcon />
        </IconButton>
      </Stack>
      {user.isPending && <Loading />}
      {user.isError && <Alert severity="error">{errorMessage(user.error)}</Alert>}
      {u && (
        <Stack spacing={2.5}>
          <UserCell
            userId={u.id}
            email={u.email}
            displayName={u.display_name}
            avatar={u.avatar}
            you={isMe}
          />
          <Stack spacing={0.5}>
            <Row label={tr("Joined")} value={formatDateTime(u.created_at)} />
            <Row label={tr("Last seen")} value={formatRelative(u.last_seen_at)} />
            <Row label={tr("Devices")} value={String(u.devices)} />
            <Row label={tr("MFA")} value={u.mfa_enabled ? tr("Enabled") : tr("Off")} />
          </Stack>
          <Divider />
          <Stack>
            <FormControlLabel
              control={
                <Switch
                  checked={u.is_admin}
                  disabled={isMe || u.is_owner || !isOwner || update.isPending}
                  onChange={(e) => update.mutate({ is_admin: e.target.checked })}
                />
              }
              label={tr("Server administrator")}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={u.email_verified}
                  disabled={update.isPending}
                  onChange={(e) => update.mutate({ email_verified: e.target.checked })}
                />
              }
              label={tr("Email verified")}
            />
            <FormControlLabel
              control={
                <Switch
                  color="error"
                  checked={u.disabled}
                  disabled={isMe || update.isPending}
                  onChange={(e) => update.mutate({ disabled: e.target.checked })}
                />
              }
              label={tr("Disabled (cannot sign in; sessions revoked)")}
            />
          </Stack>
          <Divider />
          <Stack spacing={1}>
            <Button
              variant="outlined"
              onClick={() => setConfirm("revoke")}
              disabled={u.devices === 0}
            >
              {tr("Sign out all devices")}
            </Button>
            <Tooltip title={u.mfa_enabled ? "" : tr("The user has no MFA configured")}>
              <span>
                <Button
                  variant="outlined"
                  fullWidth
                  onClick={() => setConfirm("reset-mfa")}
                  disabled={!u.mfa_enabled || (u.is_owner && !isMe)}
                >
                  {tr("Reset MFA")}
                </Button>
              </span>
            </Tooltip>
            <Button
              variant="outlined"
              color="error"
              onClick={() => setConfirm("delete")}
              disabled={isMe || u.is_owner}
            >
              {tr("Delete user")}
            </Button>
          </Stack>
        </Stack>
      )}
      <ConfirmDialog
        open={confirm === "revoke"}
        title={tr("Sign out all devices?")}
        confirmLabel={tr("Sign out")}
        busy={action.isPending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => action.mutate("revoke")}
      >
        {trx("Every session of {email} is revoked. They must sign in again on each device.", {
          email: u?.email,
        })}
      </ConfirmDialog>
      <ConfirmDialog
        open={confirm === "reset-mfa"}
        title={tr("Reset two-factor authentication?")}
        confirmLabel={tr("Reset MFA")}
        danger
        busy={action.isPending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => action.mutate("reset-mfa")}
      >
        {trx(
          "TOTP, security keys and backup codes of {email} are removed and all sessions revoked. Verify the request out of band first.",
          { email: u?.email },
        )}
      </ConfirmDialog>
      <ConfirmDialog
        open={confirm === "delete"}
        title={tr("Delete user?")}
        confirmLabel={tr("Delete")}
        danger
        busy={action.isPending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => action.mutate("delete")}
      >
        {trx(
          "{email} and all their encrypted data, devices and session logs are removed permanently. Users who own teams cannot be deleted.",
          { email: u?.email },
        )}
      </ConfirmDialog>
    </Drawer>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <Stack direction="row" sx={{ justifyContent: "space-between" }}>
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
      <Typography variant="body2">{value}</Typography>
    </Stack>
  );
}
