import { useMemo, useState, type ReactNode } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  MenuItem,
  Radio,
  RadioGroup,
  Stack,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import GroupsRoundedIcon from "@mui/icons-material/GroupsRounded";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import MoreHorizRoundedIcon from "@mui/icons-material/MoreHorizRounded";
import PersonAddAltRoundedIcon from "@mui/icons-material/PersonAddAltRounded";
import ReplayRoundedIcon from "@mui/icons-material/ReplayRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import ChevronRightRoundedIcon from "@mui/icons-material/ChevronRightRounded";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import WorkspacePremiumRoundedIcon from "@mui/icons-material/WorkspacePremiumRounded";
import { MfaBadge } from "./MfaBadge";
import { denyPerm } from "@/team/perms";
import { RolesTab } from "./RolesTab";
import { PoliciesTab } from "./PoliciesTab";
import { WebhooksTab } from "./WebhooksTab";
import { SsoTab } from "./SsoTab";
import { AccessTab } from "./AccessTab";
import { RotationTab } from "./RotationTab";
import { DevicesTab } from "./DevicesTab";
import { CaTab } from "./CaTab";
import { DataTab } from "./DataTab";
import { RecordingsTab } from "./RecordingsTab";
import { useMutation } from "@tanstack/react-query";
import { isReauthCancelled, withReauth } from "@/account/reauth";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { Page, PageBody } from "@/components/PageHeader";
import { useSnackbar } from "@/components/Snackbar";
import {
  ActionMenu,
  EntityCard,
  Field,
  IconTile,
  InlineName,
  Loading,
  SectionCard,
  type MenuAction,
} from "@/components/ui";
import * as ipc from "@/ipc/commands";
import {
  useAccount,
  useInvalidateTeam,
  useTeamInvites,
  useTeamMembers,
  useTeamPendingKeys,
  useTeams,
  useVaults,
} from "@/ipc/hooks";
import {
  errorMessage,
  type InviteResult,
  type LocalVault,
  type PendingVaultKey,
  type Team,
  type TeamInvite,
  type TeamMember,
  type TeamRole,
  type Uuid,
  isDesktopError,
} from "@/ipc/types";
import { goToSettings, goToSettingsWith, useSettingsIntent } from "@/app/navigation";
import { vaultIcon } from "@/app/vault";
import { ActivityCard, ActivityLog } from "./ActivityLog";
import { InviteDialog, InviteResultRow } from "./InviteDialog";
import { PersonAvatar, initialsOf } from "./PersonAvatar";
import { teamRoleHint, teamRoleLabel, vaultRoleLabel, can, canManageMembers } from "./roles";
import { tr, trn } from "@/i18n";

/**
 * Settings → Team, laid out like Termius: a compact "My Team" card (Member /
 * Status rows, Resend invite, Copy invitation link) and a Security card
 * (Multiplayer, Require 2FA). "Manage" opens the full in-app management view
 * (roles, removal, vaults, rename, leave/delete) where Termius sends you to
 * its web portal. Everything that touches keys stays in Rust.
 */
export function TeamPage() {
  const account = useAccount();
  const signedIn = Boolean(account.data?.account);
  const teams = useTeams(signedIn);
  const [selected, setSelected] = useState<Uuid | null>(null);
  const [creating, setCreating] = useState(false);
  const [joining, setJoining] = useState(false);
  const [inviting, setInviting] = useState(false);
  const [managing, setManaging] = useState(false);
  const [activity, setActivity] = useState(false);

  const list = teams.data ?? [];
  const team = list.find((t) => t.id === selected) ?? list[0] ?? null;
  const myId = account.data?.account?.userId ?? null;

  useSettingsIntent(["invite"], () => {
    if (team && can(team, "members.invite")) setInviting(true);
  });

  if (account.isPending || (signedIn && teams.isPending)) {
    return (
      <Page>
        <Loading />
      </Page>
    );
  }

  if (!signedIn) {
    return (
      <Page>
        <EmptyState
          icon={<GroupsRoundedIcon />}
          title={tr("Teams live in your account")}
          description={tr(
            "Sign in to Termoso Cloud or your own server to create a team, invite people and share vaults with them.",
          )}
          action={
            <Button variant="contained" onClick={() => goToSettings("account")}>
              {tr("Go to Account & sync")}
            </Button>
          }
        />
      </Page>
    );
  }

  if (teams.error) {
    const mfa = isDesktopError(teams.error) && teams.error.kind === "mfa_required";
    return (
      <Page>
        <PageBody>
          {mfa ? (
            <Alert
              severity="info"
              action={
                <Button color="inherit" size="small" onClick={() => goToSettings("security")}>
                  {tr("Set up two-factor")}
                </Button>
              }
            >
              {tr(
                "A team you belong to requires two-factor authentication. Turn it on in Security to see team data.",
              )}
            </Alert>
          ) : (
            <Alert severity="error">{errorMessage(teams.error)}</Alert>
          )}
        </PageBody>
      </Page>
    );
  }

  return (
    <Page>
      <PageBody>
        {team ? (
          <TeamView
            team={team}
            teams={list}
            myId={myId}
            onSelect={setSelected}
            onCreate={() => setCreating(true)}
            onJoin={() => setJoining(true)}
            inviting={inviting}
            setInviting={setInviting}
            managing={managing}
            setManaging={setManaging}
            activity={activity}
            setActivity={setActivity}
          />
        ) : (
          <NoTeam onCreate={() => setCreating(true)} onJoin={() => setJoining(true)} />
        )}
      </PageBody>
      <CreateTeamDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(t) => setSelected(t.id)}
      />
      <JoinTeamDialog
        open={joining}
        onClose={() => setJoining(false)}
        onJoined={(t) => setSelected(t.id)}
      />
    </Page>
  );
}

function NoTeam({ onCreate, onJoin }: { onCreate: () => void; onJoin: () => void }) {
  return (
    <Stack spacing={1.5}>
      <SectionCard>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <IconTile tone="accent" size={44}>
            <GroupsRoundedIcon />
          </IconTile>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="subtitle1">{tr("Work together in a team")}</Typography>
            <Typography variant="body2" color="text.secondary">
              {tr(
                "A team owns shared vaults: hosts, keys, snippets and port-forwarding rules everyone you invite can use. Keys are sealed per member — the server never sees them.",
              )}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1, mt: 2 }}>
          <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={onCreate}>
            {tr("Create a team")}
          </Button>
          <Button variant="tonal" startIcon={<LinkRoundedIcon />} onClick={onJoin}>
            {tr("Join with an invitation link")}
          </Button>
        </Box>
      </SectionCard>
    </Stack>
  );
}

type TeamTab =
  | "members"
  | "roles"
  | "policies"
  | "webhooks"
  | "sso"
  | "access"
  | "rotation"
  | "devices"
  | "ca"
  | "logs"
  | "data";

function TeamView({
  team,
  teams,
  myId,
  onSelect,
  onCreate,
  onJoin,
  inviting,
  setInviting,
  managing,
  setManaging,
  activity,
  setActivity,
}: {
  team: Team;
  teams: Team[];
  myId: Uuid | null;
  onSelect: (id: Uuid) => void;
  onCreate: () => void;
  onJoin: () => void;
  inviting: boolean;
  setInviting: (v: boolean) => void;
  managing: boolean;
  setManaging: (v: boolean) => void;
  activity: boolean;
  setActivity: (v: boolean) => void;
}) {
  const snackbar = useSnackbar();
  const invalidate = useInvalidateTeam();
  const admin = canManageMembers(team);
  const owner = team.my_role === "owner";
  const [tab, setTab] = useState<TeamTab>("members");
  const teamTabs = useMemo(() => {
    const all: { key: TeamTab; label: string; show: boolean }[] = [
      { key: "members", label: tr("Members"), show: true },
      { key: "roles", label: tr("Roles"), show: can(team, "roles.manage") },
      { key: "policies", label: tr("Policies"), show: can(team, "policies.manage") },
      { key: "webhooks", label: tr("Webhooks"), show: can(team, "webhooks.manage") },
      { key: "sso", label: tr("SSO"), show: can(team, "policies.manage") },
      { key: "access", label: tr("Access"), show: true },
      { key: "rotation", label: tr("Rotation"), show: can(team, "rotation.manage") },
      { key: "devices", label: tr("Devices"), show: can(team, "devices.approve") },
      { key: "ca", label: tr("SSH CA"), show: true },
      { key: "logs", label: tr("Recordings"), show: true },
      { key: "data", label: tr("Data"), show: true },
    ];
    return all.filter((t) => t.show);
  }, [team]);
  const activeTab = teamTabs.some((t) => t.key === tab) ? tab : "members";
  const members = useTeamMembers(team.id);
  const invites = useTeamInvites(team.id, admin);
  const vaults = useVaults();
  const teamVaults = useMemo(
    () => (vaults.data ?? []).filter((v) => v.kind === "team" && v.team_id === team.id),
    [vaults.data, team.id],
  );
  const managed = teamVaults.filter((v) => v.role === "manager" && v.unlocked);
  const pending = useTeamPendingKeys(team.id, admin || managed.length > 0);

  const [menu, setMenu] = useState<HTMLElement | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [confirm, setConfirm] = useState<"leave" | "delete" | null>(null);
  const [resent, setResent] = useState<InviteResult[] | null>(null);

  const op = useMutation({
    mutationFn: async (job: () => Promise<string | null>) => job(),
    onSuccess: (msg) => {
      invalidate();
      if (msg) snackbar.notify(msg);
    },
    onError: (e) => {
      if (!isReauthCancelled(e)) snackbar.error(errorMessage(e));
    },
  });

  const menuItems: MenuAction[] = [
    {
      label: tr("Rename team"),
      icon: <EditRoundedIcon fontSize="small" />,
      disabled: !admin,
      onClick: () => setRenaming(true),
    },
    {
      label: tr("Create another team"),
      icon: <AddRoundedIcon fontSize="small" />,
      onClick: onCreate,
    },
    {
      label: tr("Join with an invitation link"),
      icon: <LinkRoundedIcon fontSize="small" />,
      onClick: onJoin,
      divider: true,
    },
    owner
      ? {
          label: tr("Delete team"),
          icon: <DeleteOutlineRoundedIcon fontSize="small" />,
          danger: true,
          onClick: () => setConfirm("delete"),
        }
      : {
          label: tr("Leave team"),
          icon: <LogoutRoundedIcon fontSize="small" />,
          danger: true,
          onClick: () => setConfirm("leave"),
        },
  ];

  const memberList = members.data ?? [];
  const withoutMfa = memberList.filter((m) => m.mfa_enabled === false).length;
  const inviteList = invites.data ?? [];
  const pendingList = pending.data ?? [];

  const resend = (inv: TeamInvite) =>
    op.mutate(async () => {
      await ipc.teamInviteRevoke(team.id, inv.id);
      const r = await ipc.teamInvite(team.id, [inv.email], inv.role, []);
      setResent(r);
      return null;
    });

  const pendingKeys = pendingList.length > 0 && (
    <PendingKeys
      team={team}
      pending={pendingList}
      members={memberList}
      vaults={teamVaults}
      onGrant={(k) =>
        op.mutate(() =>
          ipc.teamVaultSetAccess(k.vault_id, k.user_id, k.role).then(() => tr("Key handed over")),
        )
      }
    />
  );

  const dialogs = (
    <>
      <InviteDialog
        team={team}
        vaults={managed}
        open={inviting}
        onClose={() => setInviting(false)}
      />
      <ResentDialog results={resent} onClose={() => setResent(null)} />
    </>
  );

  if (activity) {
    return (
      <Stack spacing={1.5} sx={{ maxWidth: 760, mx: "auto", width: "100%" }}>
        <Button
          startIcon={<ArrowBackRoundedIcon />}
          onClick={() => setActivity(false)}
          sx={{ alignSelf: "flex-start", color: "text.secondary" }}
        >
          {tr("Back to team")}
        </Button>
        <ActivityLog team={team} />
      </Stack>
    );
  }

  if (!managing) {
    return (
      <Stack spacing={1.5} sx={{ maxWidth: 640, mx: "auto", width: "100%" }}>
        {teams.length > 1 && (
          <TextField
            select
            size="small"
            value={team.id}
            onChange={(e) => onSelect(e.target.value)}
            sx={{ alignSelf: "flex-end", width: 200 }}
          >
            {teams.map((t) => (
              <MenuItem key={t.id} value={t.id}>
                {t.name}
              </MenuItem>
            ))}
          </TextField>
        )}
        {pendingKeys}
        <SectionCard sx={{ p: 2.5, gap: 1.25 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Typography variant="subtitle1" noWrap sx={{ flex: 1, fontWeight: 600 }}>
              {team.name}
            </Typography>
            <Button
              size="small"
              endIcon={<ChevronRightRoundedIcon sx={{ fontSize: 16 }} />}
              onClick={() => setManaging(true)}
              sx={{ minWidth: 0, px: 0.75 }}
            >
              {tr("Manage")}
            </Button>
          </Box>
          <Box sx={{ borderRadius: 2, overflow: "hidden" }}>
            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: "1fr 150px",
                px: 2,
                py: 1.25,
                bgcolor: "surface.highest",
                typography: "body2",
                fontWeight: 600,
              }}
            >
              <span>{tr("Member")}</span>
              <span>{tr("Status")}</span>
            </Box>
            {members.isPending ? (
              <Loading pt={2} />
            ) : (
              <>
                {memberList.map((m) => (
                  <CompactRow
                    key={m.user_id}
                    avatar={
                      <PersonAvatar
                        size={36}
                        seed={m.email}
                        label={initialsOf(null, m.email)}
                        userId={m.user_id}
                        avatar={m.avatar}
                      />
                    }
                    primary={m.display_name ?? m.email}
                    owner={m.role === "owner"}
                    me={m.user_id === myId}
                    badge={<MfaBadge m={m} required={team.require_mfa} />}
                    status={
                      <Typography variant="body2" color="text.secondary">
                        {tr("Active")}
                      </Typography>
                    }
                  />
                ))}
                {inviteList.map((inv) => (
                  <CompactRow
                    key={inv.id}
                    avatar={
                      <PersonAvatar
                        size={36}
                        kind="invite"
                        seed={inv.email}
                        label={initialsOf(null, inv.email)}
                      />
                    }
                    primary={inv.email}
                    muted
                    status={
                      admin ? (
                        <Button
                          size="small"
                          onClick={() => resend(inv)}
                          disabled={op.isPending}
                          sx={{ minWidth: 0, px: 0, justifyContent: "flex-start" }}
                        >
                          {tr("Resend invite")}
                        </Button>
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          {tr("Invited")}
                        </Typography>
                      )
                    }
                  />
                ))}
              </>
            )}
          </Box>
          {admin && (
            <Button
              startIcon={<LinkRoundedIcon />}
              onClick={() => setInviting(true)}
              sx={{ alignSelf: "flex-start", color: "text.primary", px: 0.5 }}
            >
              {tr("Copy invitation link")}
            </Button>
          )}
        </SectionCard>

        <SectionCard sx={{ p: 2.5, gap: 0.5 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>
            {tr("Security")}
          </Typography>
          <SecurityRow
            label={
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                {tr("Multiplayer")}
                <Typography variant="caption" color="text.secondary">
                  {tr("Beta")}
                </Typography>
              </Box>
            }
            hint={tr("Members can share a live terminal with each other.")}
            enabled={team.multiplayer_enabled}
            canChange={admin}
            onChange={(on) =>
              op.mutate(() =>
                ipc
                  .teamSetSecurity(team.id, { multiplayerEnabled: on })
                  .then(() => (on ? tr("Multiplayer enabled") : tr("Multiplayer disabled"))),
              )
            }
          />
          <SecurityRow
            label={tr("Require 2FA for all team members")}
            hint={
              withoutMfa > 0
                ? trn(
                    withoutMfa,
                    "Members without two-factor authentication cannot open team vaults. {count} member has no 2FA yet.",
                    "Members without two-factor authentication cannot open team vaults. {count} members have no 2FA yet.",
                  )
                : tr("Members without two-factor authentication cannot open team vaults.")
            }
            enabled={team.require_mfa}
            canChange={admin}
            onChange={(on) =>
              op.mutate(() =>
                ipc
                  .teamSetSecurity(team.id, { requireMfa: on })
                  .then(() => (on ? tr("2FA is now required") : tr("2FA is no longer required"))),
              )
            }
          />
          <SecurityRow
            label={tr("Show who is connected")}
            hint={tr(
              "Members see which team-vault hosts teammates are connected to right now. Only the host and protocol are shared — never what happens inside a session. Anyone can hide themselves in Account.",
            )}
            enabled={team.presence_enabled}
            canChange={admin}
            onChange={(on) =>
              op.mutate(() =>
                ipc
                  .teamSetSecurity(team.id, { presenceEnabled: on })
                  .then(() => (on ? tr("Presence enabled") : tr("Presence disabled"))),
              )
            }
          />
        </SectionCard>
        <ActivityCard team={team} onOpen={() => setActivity(true)} />
        {dialogs}
      </Stack>
    );
  }

  return (
    <Stack spacing={1.5}>
      <Button
        startIcon={<ArrowBackRoundedIcon />}
        onClick={() => setManaging(false)}
        sx={{ alignSelf: "flex-start", color: "text.secondary" }}
      >
        {tr("Back to team")}
      </Button>
      <SectionCard>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <IconTile tone="accent" size={44}>
            <GroupsRoundedIcon />
          </IconTile>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            {renaming ? (
              <InlineName
                value={team.name}
                placeholder={tr("Team name")}
                onCancel={() => setRenaming(false)}
                onCommit={(name) => {
                  setRenaming(false);
                  const n = name.trim();
                  if (!n || n === team.name) return;
                  op.mutate(() => ipc.teamRename(team.id, n).then(() => tr("Team renamed")));
                }}
                sx={{ fontSize: 15, height: 28 }}
              />
            ) : (
              <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, minWidth: 0 }}>
                <Typography variant="subtitle1" noWrap>
                  {team.name}
                </Typography>
                {admin && (
                  <Tooltip title={tr("Rename")}>
                    <IconButton size="small" onClick={() => setRenaming(true)}>
                      <EditRoundedIcon sx={{ fontSize: 15 }} />
                    </IconButton>
                  </Tooltip>
                )}
              </Box>
            )}
            <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
              {trn(team.member_count, "{count} member", "{count} members")} ·{" "}
              {tr("you are {role}", {
                role: team.my_role_ref?.name ?? tr(teamRoleLabel[team.my_role]).toLowerCase(),
              })}
              {teamVaults.length > 0 &&
                ` · ${trn(teamVaults.length, "{count} vault", "{count} vaults")}`}
            </Typography>
          </Box>
          {teams.length > 1 && (
            <TextField
              select
              size="small"
              value={team.id}
              onChange={(e) => onSelect(e.target.value)}
              sx={{ width: 180 }}
            >
              {teams.map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name}
                </MenuItem>
              ))}
            </TextField>
          )}
          {admin && (
            <Button
              variant="contained"
              startIcon={<PersonAddAltRoundedIcon />}
              onClick={() => setInviting(true)}
            >
              {tr("Invite members")}
            </Button>
          )}
          <IconButton onClick={(e) => setMenu(e.currentTarget)} aria-label={tr("Team actions")}>
            <MoreHorizRoundedIcon fontSize="small" />
          </IconButton>
        </Box>
      </SectionCard>
      {teamTabs.length > 1 && (
        <Tabs
          value={activeTab}
          onChange={(_, v: TeamTab) => setTab(v)}
          variant="scrollable"
          allowScrollButtonsMobile
          sx={{ minHeight: 36, "& .MuiTab-root": { minHeight: 36, py: 0.5 } }}
        >
          {teamTabs.map((t) => (
            <Tab key={t.key} value={t.key} label={t.label} />
          ))}
        </Tabs>
      )}
      {activeTab === "roles" ? (
        <RolesTab team={team} />
      ) : activeTab === "policies" ? (
        <PoliciesTab team={team} />
      ) : activeTab === "webhooks" ? (
        <WebhooksTab team={team} />
      ) : activeTab === "sso" ? (
        <SsoTab team={team} />
      ) : activeTab === "access" ? (
        <AccessTab team={team} myId={myId} />
      ) : activeTab === "rotation" ? (
        <RotationTab team={team} />
      ) : activeTab === "devices" ? (
        <DevicesTab team={team} />
      ) : activeTab === "ca" ? (
        <CaTab team={team} />
      ) : activeTab === "logs" ? (
        <RecordingsTab team={team} />
      ) : activeTab === "data" ? (
        <DataTab team={team} />
      ) : (
        <>
          {pendingKeys}

          <SectionCard
            title={tr("Members")}
            description={
              admin
                ? tr(
                    "Change a role from the dropdown; remove someone with the cross. Removing a member rotates the keys of vaults they could open.",
                  )
                : undefined
            }
          >
            {members.isPending ? (
              <Loading pt={2} />
            ) : (
              <Stack spacing={0.5}>
                <Box
                  sx={{
                    display: "grid",
                    gridTemplateColumns: "1fr 150px 130px 36px",
                    px: 1.5,
                    py: 0.5,
                    color: "text.secondary",
                    typography: "caption",
                  }}
                >
                  <span>{tr("Member")}</span>
                  <span>{tr("Role")}</span>
                  <span>{tr("Status")}</span>
                  <span />
                </Box>
                {memberList.map((m) => (
                  <MemberRow
                    key={m.user_id}
                    team={team}
                    m={m}
                    me={m.user_id === myId}
                    onRole={(role) =>
                      op.mutate(() =>
                        ipc
                          .teamMemberSetRole(team.id, m.user_id, role)
                          .then(() =>
                            role === "owner"
                              ? tr("{value} is now the owner", { value: m.display_name ?? m.email })
                              : tr("Role updated"),
                          ),
                      )
                    }
                    onRemove={() =>
                      op.mutate(() =>
                        ipc.teamMemberRemove(team.id, m.user_id).then(() =>
                          tr("{who} removed from {team}", {
                            who: m.display_name ?? m.email,
                            team: team.name,
                          }),
                        ),
                      )
                    }
                    onDeleteAccount={() =>
                      op.mutate(() =>
                        withReauth(() => ipc.teamMemberDeleteAccount(team.id, m.user_id)).then(() =>
                          tr("Account {email} deleted", { email: m.email }),
                        ),
                      )
                    }
                  />
                ))}
                {inviteList.map((inv) => (
                  <InviteRow
                    key={inv.id}
                    inv={inv}
                    onRevoke={() =>
                      op.mutate(() =>
                        ipc.teamInviteRevoke(team.id, inv.id).then(() => tr("Invitation revoked")),
                      )
                    }
                    onResend={() => resend(inv)}
                  />
                ))}
              </Stack>
            )}
          </SectionCard>

          <SectionCard
            title={tr("Team vaults")}
            description={tr(
              "Each vault has its own key and its own list of people. Members connect with what is inside; managers decide who gets in.",
            )}
            action={
              admin ? (
                <Button
                  variant="tonal"
                  size="small"
                  startIcon={<AddRoundedIcon />}
                  onClick={() => goToSettingsWith({ kind: "newVault", teamId: team.id })}
                >
                  {tr("New vault")}
                </Button>
              ) : undefined
            }
          >
            {vaults.isPending ? (
              <Loading pt={2} />
            ) : teamVaults.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {admin
                  ? tr("No vaults yet — create one to start sharing hosts and keys.")
                  : tr("You have not been given access to any vault of this team yet.")}
              </Typography>
            ) : (
              <Stack spacing={0.75}>
                {teamVaults.map((v) => (
                  <EntityCard
                    key={v.id}
                    dense
                    tile={
                      <IconTile tone={v.unlocked ? "accent" : "neutral"} size={32}>
                        {vaultIcon(v)}
                      </IconTile>
                    }
                    title={v.name}
                    subtitle={
                      v.unlocked
                        ? tr("You {value}", { value: tr(vaultRoleLabel[v.role]) })
                        : tr("Locked on this device — waiting for a manager to hand you the key")
                    }
                    trailing={
                      <ChevronRightRoundedIcon fontSize="small" sx={{ color: "text.disabled" }} />
                    }
                    onClick={() => goToSettingsWith({ kind: "vault", id: v.id })}
                  />
                ))}
              </Stack>
            )}
          </SectionCard>

          <ActionMenu anchor={menu} onClose={() => setMenu(null)} items={menuItems} />
          {dialogs}
          <ConfirmDialog
            open={confirm === "leave"}
            title={tr("Leave {name}?", { name: team.name })}
            confirmLabel={tr("Leave team")}
            danger
            busy={op.isPending}
            onCancel={() => setConfirm(null)}
            onConfirm={() =>
              op.mutate(
                () => ipc.teamLeave(team.id).then(() => tr("You left {name}", { name: team.name })),
                {
                  onSuccess: () => setConfirm(null),
                },
              )
            }
          >
            {tr(
              "Its vaults disappear from this device and you lose access to everything inside. Managers of those vaults can rotate their keys afterwards.",
            )}
          </ConfirmDialog>
          <ConfirmDialog
            open={confirm === "delete"}
            title={tr("Delete {name}?", { name: team.name })}
            confirmLabel={tr("Delete team")}
            danger
            busy={op.isPending}
            onCancel={() => setConfirm(null)}
            onConfirm={() => {
              if (!can(team, "team.delete")) {
                denyPerm("team.delete");
                return;
              }
              op.mutate(
                () => ipc.teamDelete(team.id).then(() => tr("{name} deleted", { name: team.name })),
                {
                  onSuccess: () => setConfirm(null),
                },
              );
            }}
          >
            {tr(
              "Every team vault and everything inside is deleted for all {count} members. This cannot be undone.",
              { count: team.member_count },
            )}
          </ConfirmDialog>
        </>
      )}
    </Stack>
  );
}

/** One line of the compact "My Team" table: avatar, name (+ owner crown, YOU), status column. */
function CompactRow({
  avatar,
  primary,
  owner,
  me,
  muted,
  status,
  badge,
}: {
  avatar: ReactNode;
  primary: string;
  owner?: boolean;
  me?: boolean;
  muted?: boolean;
  status: ReactNode;
  badge?: ReactNode;
}) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "1fr 150px",
        alignItems: "center",
        px: 2,
        minHeight: 58,
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, minWidth: 0 }}>
        {avatar}
        <Typography
          variant="body2"
          noWrap
          sx={{ color: muted ? "text.secondary" : "text.primary", minWidth: 0 }}
        >
          {primary}
        </Typography>
        {owner && (
          <Tooltip title={tr("Team owner")}>
            <WorkspacePremiumRoundedIcon sx={{ fontSize: 16, color: "info.main" }} />
          </Tooltip>
        )}
        {me && (
          <Chip
            size="small"
            label="YOU"
            color="info"
            sx={{ height: 16, fontSize: 9, fontWeight: 700, "& .MuiChip-label": { px: 0.75 } }}
          />
        )}
        {badge}
      </Box>
      <Box sx={{ minWidth: 0 }}>{status}</Box>
    </Box>
  );
}

/** `Label ……… Enabled ▾` line of a policy card; the dropdown is read-only for those who cannot change it. */
export function SecurityRow({
  label,
  hint,
  enabled,
  canChange,
  onChange,
}: {
  label: ReactNode;
  hint: string;
  enabled: boolean;
  canChange: boolean;
  onChange: (on: boolean) => void;
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const text = enabled ? tr("Enabled") : tr("Disabled");
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 2, minHeight: 44 }}>
      <Tooltip title={hint} placement="top-start" enterDelay={600}>
        <Typography variant="body2" sx={{ flex: 1, minWidth: 0 }} component="div">
          {label}
        </Typography>
      </Tooltip>
      {canChange ? (
        <Button
          size="small"
          color="inherit"
          endIcon={<ExpandMoreRoundedIcon sx={{ fontSize: 18 }} />}
          onClick={(e) => setAnchor(e.currentTarget)}
          sx={{ color: "text.secondary", minWidth: 0, px: 0.75, fontWeight: 400 }}
        >
          {text}
        </Button>
      ) : (
        <Typography variant="body2" color="text.secondary">
          {text}
        </Typography>
      )}
      <ActionMenu
        anchor={anchor}
        onClose={() => setAnchor(null)}
        items={[
          { label: tr("Enabled"), disabled: enabled, onClick: () => onChange(true) },
          { label: tr("Disabled"), disabled: !enabled, onClick: () => onChange(false) },
        ]}
      />
    </Box>
  );
}

function MemberRow({
  team,
  m,
  me,
  onRole,
  onRemove,
  onDeleteAccount,
}: {
  team: Team;
  m: TeamMember;
  me: boolean;
  onRole: (role: TeamRole) => void;
  onRemove: () => void;
  onDeleteAccount: () => void;
}) {
  const admin = canManageMembers(team);
  const owner = team.my_role === "owner";
  const [confirmOwner, setConfirmOwner] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const canChange = can(team, "members.role") && !me && m.role !== "owner";
  const canRemove = can(team, "members.remove") && !me && m.role !== "owner";
  const canDeleteAccount = canRemove && owner && m.managed;
  const name = m.display_name ?? m.email;
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "1fr 150px 130px 36px",
        alignItems: "center",
        px: 1.5,
        minHeight: 48,
        borderRadius: 2,
        bgcolor: "surface.high",
        "& .row-actions": { opacity: 0, transition: "opacity 100ms" },
        "&:hover .row-actions, &:focus-within .row-actions": { opacity: 1 },
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.25, minWidth: 0 }}>
        <PersonAvatar
          label={initialsOf(m.display_name, m.email)}
          userId={m.user_id}
          avatar={m.avatar}
        />
        <Box sx={{ minWidth: 0 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, minWidth: 0 }}>
            <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
              {name}
            </Typography>
            {me && <Chip size="small" label={tr("you")} />}
            <MfaBadge m={m} required={team.require_mfa} />
            {m.managed && admin && (
              <Tooltip title={tr("Account was created through this team's invitation")}>
                <Chip size="small" variant="outlined" label={tr("team account")} />
              </Tooltip>
            )}
          </Box>
          {m.display_name && (
            <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
              {m.email}
            </Typography>
          )}
        </Box>
      </Box>
      <Box>
        {canChange ? (
          <TextField
            select
            size="small"
            value={m.role}
            onChange={(e) => {
              const r = e.target.value as TeamRole;
              if (r === "owner") setConfirmOwner(true);
              else onRole(r);
            }}
            sx={{ width: 136 }}
          >
            <MenuItem value="member">{teamRoleLabel.member}</MenuItem>
            <MenuItem value="admin">{teamRoleLabel.admin}</MenuItem>
            {owner && <MenuItem value="owner">{tr("Make owner…")}</MenuItem>}
          </TextField>
        ) : (
          <Tooltip title={tr(teamRoleHint[m.role])}>
            <Typography variant="body2" color="text.secondary">
              {tr(teamRoleLabel[m.role])}
            </Typography>
          </Tooltip>
        )}
      </Box>
      <Box>
        <Chip size="small" color="success" label={tr("Active")} />
      </Box>
      <Box className="row-actions" sx={{ display: "flex", justifyContent: "flex-end" }}>
        {canRemove && (
          <Tooltip title={tr("Remove from team")}>
            <IconButton size="small" onClick={() => setConfirmRemove(true)}>
              <CloseRoundedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        )}
      </Box>
      <ConfirmDialog
        open={confirmOwner}
        title={tr("Make {name} the owner?", { name })}
        confirmLabel={tr("Transfer ownership")}
        onCancel={() => setConfirmOwner(false)}
        onConfirm={() => {
          setConfirmOwner(false);
          onRole("owner");
        }}
      >
        {tr("You become an admin. Only the owner can delete the team or hand ownership on again.")}
      </ConfirmDialog>
      {canDeleteAccount ? (
        <RemoveOrDeleteDialog
          open={confirmRemove}
          member={m}
          teamName={team.name}
          onCancel={() => setConfirmRemove(false)}
          onRemove={() => {
            setConfirmRemove(false);
            onRemove();
          }}
          onDeleteAccount={() => {
            setConfirmRemove(false);
            onDeleteAccount();
          }}
        />
      ) : (
        <ConfirmDialog
          open={confirmRemove}
          title={tr("Remove {name}?", { name })}
          confirmLabel={tr("Remove")}
          danger
          onCancel={() => setConfirmRemove(false)}
          onConfirm={() => {
            setConfirmRemove(false);
            onRemove();
          }}
        >
          {tr(
            "They lose access to every vault of {team}. Keys of the vaults they could open are rotated so old copies stop working.",
            { team: team.name },
          )}
        </ConfirmDialog>
      )}
    </Box>
  );
}

// Owner removing a member whose account this team created: keep the account
// as an individual one, or delete it outright (typed confirmation + re-auth).
function RemoveOrDeleteDialog({
  open,
  member,
  teamName,
  onCancel,
  onRemove,
  onDeleteAccount,
}: {
  open: boolean;
  member: TeamMember;
  teamName: string;
  onCancel: () => void;
  onRemove: () => void;
  onDeleteAccount: () => void;
}) {
  const [action, setAction] = useState<"remove" | "delete">("remove");
  const [typed, setTyped] = useState("");
  const deleting = action === "delete";
  const confirmed = !deleting || typed.trim().toLowerCase() === member.email.toLowerCase();
  const name = member.display_name ?? member.email;
  const close = () => {
    setAction("remove");
    setTyped("");
    onCancel();
  };
  return (
    <Dialog open={open} onClose={close} maxWidth="xs" fullWidth>
      <DialogTitle>
        {deleting ? tr("Delete {name}'s account?", { name }) : tr("Remove {name}?", { name })}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={1.5}>
          <Typography variant="body2" color="text.secondary">
            {tr(
              "This account was created through {team}'s invitation. Choose what happens to it.",
              {
                team: teamName,
              },
            )}
          </Typography>
          <RadioGroup
            value={action}
            onChange={(e) => setAction(e.target.value as "remove" | "delete")}
          >
            <FormControlLabel
              value="remove"
              control={<Radio size="small" />}
              label={
                <Box>
                  <Typography variant="body2">{tr("Remove from team")}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {tr(
                      "Keeps the account as an individual one with its personal vault; loses access to every vault of {team}.",
                      { team: teamName },
                    )}
                  </Typography>
                </Box>
              }
            />
            <FormControlLabel
              value="delete"
              control={<Radio size="small" color="error" />}
              label={
                <Box>
                  <Typography variant="body2" color="error">
                    {tr("Delete the account")}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {tr(
                      "Permanently deletes the account, its personal vault, devices and session logs. Cannot be undone.",
                    )}
                  </Typography>
                </Box>
              }
            />
          </RadioGroup>
          {deleting && (
            <TextField
              size="small"
              label={tr("Type {email} to confirm", { email: member.email })}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              autoFocus
              fullWidth
            />
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={close} color="inherit">
          {tr("Cancel")}
        </Button>
        <Button
          variant="contained"
          color="error"
          disabled={!confirmed}
          onClick={() => {
            const run = deleting ? onDeleteAccount : onRemove;
            setAction("remove");
            setTyped("");
            run();
          }}
        >
          {deleting ? tr("Delete account") : tr("Remove")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function InviteRow({
  inv,
  onRevoke,
  onResend,
}: {
  inv: TeamInvite;
  onRevoke: () => void;
  onResend: () => void;
}) {
  const [now] = useState(() => Date.now());
  const expired = new Date(inv.expires_at).getTime() < now;
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "1fr 150px 130px 72px",
        alignItems: "center",
        px: 1.5,
        minHeight: 48,
        borderRadius: 2,
        bgcolor: "surface.high",
        "& .row-actions": { opacity: 0, transition: "opacity 100ms" },
        "&:hover .row-actions, &:focus-within .row-actions": { opacity: 1 },
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.25, minWidth: 0 }}>
        <PersonAvatar kind="invite" label="" />
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
            {inv.email}
          </Typography>
          <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
            {expired
              ? tr("Invitation expired")
              : tr("Invited {toLocaleDateString} · expires {toLocaleDateString2}", {
                  toLocaleDateString: new Date(inv.created_at).toLocaleDateString(),
                  toLocaleDateString2: new Date(inv.expires_at).toLocaleDateString(),
                })}
          </Typography>
        </Box>
      </Box>
      <Typography variant="body2" color="text.secondary">
        {tr(teamRoleLabel[inv.role])}
      </Typography>
      <Box>
        <Chip
          size="small"
          color={expired ? "default" : "warning"}
          label={expired ? tr("Expired") : tr("Pending")}
        />
      </Box>
      <Box className="row-actions" sx={{ display: "flex", justifyContent: "flex-end" }}>
        <Tooltip title={tr("Issue a new link")}>
          <IconButton size="small" onClick={onResend}>
            <ReplayRoundedIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title={tr("Revoke invitation")}>
          <IconButton size="small" onClick={onRevoke}>
            <CloseRoundedIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
    </Box>
  );
}

function PendingKeys({
  team,
  pending,
  members,
  vaults,
  onGrant,
}: {
  team: Team;
  pending: PendingVaultKey[];
  members: TeamMember[];
  vaults: LocalVault[];
  onGrant: (k: PendingVaultKey) => void;
}) {
  const grantable = pending.filter((k) => {
    const v = vaults.find((x) => x.id === k.vault_id);
    return v?.unlocked && v.role === "manager";
  });
  return (
    <SectionCard
      title={tr("Waiting for a vault key")}
      description={tr(
        "Members who were given access to a vault of {name} but have not received its key yet. Handing it over seals the key to their account on this device.",
        { name: team.name },
      )}
      tone="warning"
    >
      <Stack spacing={0.75}>
        {pending.map((k) => {
          const v = vaults.find((x) => x.id === k.vault_id);
          const m = members.find((x) => x.user_id === k.user_id);
          const can = grantable.includes(k);
          return (
            <EntityCard
              key={`${k.vault_id}:${k.user_id}`}
              dense
              tile={
                <PersonAvatar
                  label={initialsOf(m?.display_name, m?.email ?? "?")}
                  userId={m?.user_id}
                  avatar={m?.avatar}
                />
              }
              title={m?.display_name ?? m?.email ?? tr("Unknown member")}
              subtitle={`${v?.name ?? tr("Vault")} · ${tr(vaultRoleLabel[k.role])}`}
              trailing={
                can ? (
                  <Button
                    size="small"
                    variant="tonal"
                    startIcon={<KeyRoundedIcon />}
                    onClick={() => onGrant(k)}
                  >
                    {tr("Hand over key")}
                  </Button>
                ) : (
                  <Tooltip
                    title={
                      v && !v.unlocked
                        ? tr("This vault is locked on your device")
                        : tr("Only a manager of this vault can hand over its key")
                    }
                  >
                    <LockRoundedIcon fontSize="small" sx={{ color: "text.disabled" }} />
                  </Tooltip>
                )
              }
            />
          );
        })}
      </Stack>
    </SectionCard>
  );
}

function ResentDialog({
  results,
  onClose,
}: {
  results: InviteResult[] | null;
  onClose: () => void;
}) {
  return (
    <Dialog open={results !== null} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{tr("New invitation link")}</DialogTitle>
      <DialogContent>
        <Stack spacing={1}>
          {(results ?? []).map((r) => (
            <InviteResultRow key={r.email} result={r} />
          ))}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button variant="contained" onClick={onClose}>
          {tr("Done")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function CreateTeamDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (t: Team) => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      {open && <CreateTeamBody onClose={onClose} onCreated={onCreated} />}
    </Dialog>
  );
}

function CreateTeamBody({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (t: Team) => void;
}) {
  const snackbar = useSnackbar();
  const invalidate = useInvalidateTeam();
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => ipc.teamCreate(name.trim()),
    onSuccess: (t) => {
      invalidate();
      onCreated(t);
      onClose();
      snackbar.notify(tr("{name} created", { name: t.name }));
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  return (
    <>
      <DialogTitle>{tr("New team")}</DialogTitle>
      <DialogContent>
        <Stack spacing={1.5}>
          <Field label={tr("Team name")}>
            <TextField
              autoFocus
              fullWidth
              size="small"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && name.trim()) create.mutate();
              }}
            />
          </Field>
          <Typography variant="caption" color="text.secondary">
            {tr(
              "You become the owner. A first vault named after the team is created and sealed to your account; invite people afterwards.",
            )}
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button color="inherit" onClick={onClose} disabled={create.isPending}>
          {tr("Cancel")}
        </Button>
        <Button
          variant="contained"
          disabled={!name.trim() || create.isPending}
          onClick={() => create.mutate()}
        >
          {create.isPending ? tr("Creating…") : tr("Create team")}
        </Button>
      </DialogActions>
    </>
  );
}

function JoinTeamDialog({
  open,
  onClose,
  onJoined,
}: {
  open: boolean;
  onClose: () => void;
  onJoined: (t: Team) => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      {open && <JoinTeamBody onClose={onClose} onJoined={onJoined} />}
    </Dialog>
  );
}

function JoinTeamBody({ onClose, onJoined }: { onClose: () => void; onJoined: (t: Team) => void }) {
  const snackbar = useSnackbar();
  const invalidate = useInvalidateTeam();
  const [link, setLink] = useState("");
  const join = useMutation({
    mutationFn: () => ipc.teamAcceptInvite(link.trim()),
    onSuccess: (t) => {
      invalidate();
      onJoined(t);
      onClose();
      snackbar.notify(tr("You joined {name}", { name: t.name }));
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  return (
    <>
      <DialogTitle>{tr("Join a team")}</DialogTitle>
      <DialogContent>
        <Stack spacing={1.5}>
          <Field label={tr("Invitation link or code")}>
            <TextField
              autoFocus
              fullWidth
              size="small"
              value={link}
              onChange={(e) => setLink(e.target.value)}
              placeholder="https://…/invite/…"
              onKeyDown={(e) => {
                if (e.key === "Enter" && link.trim()) join.mutate();
              }}
            />
          </Field>
          <Typography variant="caption" color="text.secondary">
            {tr("The link must have been issued for the e-mail address of this account.")}
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button color="inherit" onClick={onClose} disabled={join.isPending}>
          {tr("Cancel")}
        </Button>
        <Button
          variant="contained"
          disabled={!link.trim() || join.isPending}
          onClick={() => join.mutate()}
        >
          {join.isPending ? tr("Joining…") : tr("Join")}
        </Button>
      </DialogActions>
    </>
  );
}
