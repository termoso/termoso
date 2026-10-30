import { useState, type ReactNode } from "react";
import {
  Box,
  Button,
  Dialog,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import PersonRoundedIcon from "@mui/icons-material/PersonRounded";
import GroupsRoundedIcon from "@mui/icons-material/GroupsRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import FingerprintRoundedIcon from "@mui/icons-material/FingerprintRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import KeyboardRoundedIcon from "@mui/icons-material/KeyboardRounded";
import FolderCopyRoundedIcon from "@mui/icons-material/FolderCopyRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import ArticleRoundedIcon from "@mui/icons-material/ArticleRounded";
import SystemUpdateAltRoundedIcon from "@mui/icons-material/SystemUpdateAltRounded";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import ShieldRoundedIcon from "@mui/icons-material/ShieldRounded";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AccountPage } from "@/account/AccountPage";
import {
  type SettingsPage as PageId,
  closeSettings,
  setSettingsPage,
  useNav,
} from "@/app/navigation";
import { EmptyState } from "@/components/EmptyState";
import { Page, PageBody } from "@/components/PageHeader";
import { useSnackbar } from "@/components/Snackbar";
import { Loading, Mono, SectionCard, SettingRow } from "@/components/ui";
import * as ipc from "@/ipc/commands";
import { useAppInfo, useSaveSettings, useSettings } from "@/ipc/hooks";
import { UpdatesCard } from "@/update/UpdatesCard";
import { FontPicker, FontPreview } from "./FontPicker";
import { KeyboardPage } from "./KeyboardPage";
import { SecurityPage } from "./SecurityPage";
import { SftpPage } from "./SftpPage";
import { TriggersCard } from "./TriggersCard";
import { TeamPage } from "@/team/TeamPage";
import { VaultsPage } from "@/team/VaultsPage";
import { IS_MAC } from "@/lib/platform";
import { SshIdPage } from "@/sshid/SshIdPage";
import { ThemeGallery } from "./ThemeGallery";
import {
  errorMessage,
  TERM_TYPES,
  type CursorStyle,
  type RestoreCommands,
  type Settings,
  type SyncConflict,
  type TermType,
  type ThemeMode,
} from "@/ipc/types";
import { tr, trn, msg, LOCALE_NAMES, type Language } from "@/i18n";

const PAGES: { id: PageId; label: string; icon: ReactNode }[] = [
  { id: "account", label: msg("Account & sync"), icon: <PersonRoundedIcon /> },
  { id: "team", label: msg("Team"), icon: <GroupsRoundedIcon /> },
  { id: "vaults", label: msg("Vaults"), icon: <LockRoundedIcon /> },
  { id: "sshid", label: msg("SSH ID"), icon: <FingerprintRoundedIcon /> },
  { id: "security", label: msg("Security"), icon: <ShieldRoundedIcon /> },
  { id: "general", label: msg("General"), icon: <TuneRoundedIcon /> },
  { id: "terminal", label: msg("Terminal"), icon: <TerminalRoundedIcon /> },
  { id: "keyboard", label: msg("Keyboard"), icon: <KeyboardRoundedIcon /> },
  { id: "sftp", label: msg("SFTP"), icon: <FolderCopyRoundedIcon /> },
  { id: "logs", label: msg("Session logs"), icon: <ArticleRoundedIcon /> },
  { id: "updates", label: msg("Updates"), icon: <SystemUpdateAltRoundedIcon /> },
  { id: "about", label: msg("About"), icon: <InfoOutlinedIcon /> },
];

export function SettingsPage() {
  const page = useNav((s) => s.settingsPage);
  return (
    <Box sx={{ flex: 1, minHeight: 0, display: "flex" }}>
      <Box
        sx={{
          width: 200,
          flexShrink: 0,
          borderRight: 1,
          borderColor: "border.light",
          py: 1,
          px: 1,
          overflowY: "auto",
        }}
      >
        <List dense disablePadding>
          {PAGES.map((p) => (
            <ListItemButton
              key={p.id}
              selected={page === p.id}
              onClick={() => setSettingsPage(p.id)}
              sx={{ "& .MuiListItemIcon-root": { minWidth: 32, "& svg": { fontSize: 18 } } }}
            >
              <ListItemIcon>{p.icon}</ListItemIcon>
              <ListItemText primary={tr(p.label)} />
            </ListItemButton>
          ))}
        </List>
      </Box>
      {page === "team" ? (
        <TeamPage />
      ) : page === "vaults" ? (
        <VaultsPage />
      ) : page === "sshid" ? (
        <SshIdPage />
      ) : (
        <Page>{page === "account" ? <AccountPage /> : <PreferencesPage page={page} />}</Page>
      )}
    </Box>
  );
}

function PreferencesPage({
  page,
}: {
  page: Exclude<PageId, "account" | "team" | "vaults" | "sshid">;
}) {
  const snackbar = useSnackbar();
  const settings = useSettings();
  const save = useSaveSettings();

  const update = (patch: Partial<Settings>) => {
    if (!settings.data) return;
    save.mutate(
      { ...settings.data, ...patch },
      { onError: (e) => snackbar.error(errorMessage(e)) },
    );
  };

  if (settings.isPending) return <Loading />;
  if (settings.error)
    return (
      <EmptyState title={tr("Settings unavailable")} description={errorMessage(settings.error)} />
    );
  const s = settings.data;

  return (
    <PageBody>
      <Box sx={{ maxWidth: 760, display: "flex", flexDirection: "column", gap: 1.5 }}>
        {page === "security" && <SecurityPage s={s} update={update} />}
        {page === "general" && <General s={s} update={update} />}
        {page === "terminal" && <Terminal s={s} update={update} />}
        {page === "keyboard" && <KeyboardPage s={s} update={update} />}
        {page === "sftp" && <SftpPage s={s} update={update} />}
        {page === "logs" && <Logs s={s} update={update} />}
        {page === "updates" && <UpdatesCard settings={s} onChange={update} />}
        {page === "about" && <About />}
      </Box>
    </PageBody>
  );
}

interface SectionProps {
  s: Settings;
  update: (patch: Partial<Settings>) => void;
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return <Switch checked={checked} onChange={(e) => onChange(e.target.checked)} />;
}

function NumberInput({
  value,
  onChange,
  min,
  max,
  step,
  width = 120,
}: {
  value: number;
  onChange: (n: number) => void;
  min: number;
  max: number;
  step?: number;
  width?: number;
}) {
  return (
    <TextField
      type="number"
      value={value}
      onChange={(e) => onChange(Math.max(min, Number(e.target.value)))}
      slotProps={{ htmlInput: { min, max, step } }}
      sx={{ width }}
    />
  );
}

function DeepLinksRow() {
  const snackbar = useSnackbar();
  const register = useMutation({
    mutationFn: ipc.deepLinksRegister,
    onSuccess: (schemes) =>
      snackbar.notify(
        schemes.length
          ? tr("Termoso now opens {schemes} links", {
              schemes: schemes.map((s) => `${s}://`).join(", "),
            })
          : tr("Registration ran, but the system reports no handler — check your desktop settings"),
      ),
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  return (
    <SettingRow
      label={tr("Open ssh://, telnet:// and termoso:// links")}
      hint={tr(
        "Installers register the handler already; use this for AppImage or portable builds. Links open a saved host or a quick connection — passwords in URLs are ignored.",
      )}
      last
      control={
        <Button
          variant="outlined"
          size="small"
          onClick={() => register.mutate()}
          disabled={register.isPending}
        >
          {tr("Register as handler")}
        </Button>
      }
    />
  );
}

function General({ s, update }: SectionProps) {
  return (
    <>
      <SectionCard title={tr("Appearance")}>
        <SettingRow
          label={tr("Theme")}
          control={
            <TextField
              select
              value={s.theme}
              onChange={(e) => update({ theme: e.target.value as ThemeMode })}
              sx={{ width: 200 }}
            >
              <MenuItem value="dark">{tr("Dark")}</MenuItem>
              <MenuItem value="light">{tr("Light")}</MenuItem>
              <MenuItem value="system">{tr("Follow system")}</MenuItem>
            </TextField>
          }
        />
        <SettingRow
          label={tr("Language")}
          last
          control={
            <TextField
              select
              value={s.language}
              onChange={(e) => update({ language: e.target.value as Language })}
              sx={{ width: 200 }}
            >
              <MenuItem value="system">{tr("Follow system")}</MenuItem>
              <MenuItem value="en">{LOCALE_NAMES.en}</MenuItem>
              <MenuItem value="ru">{LOCALE_NAMES.ru}</MenuItem>
            </TextField>
          }
        />
      </SectionCard>

      <SectionCard title={tr("Connections")}>
        <SettingRow
          label={tr("Keep-alive interval")}
          hint={tr("Seconds between SSH keep-alive packets. 0 turns it off.")}
          control={
            <NumberInput
              value={s.keepAliveSeconds}
              onChange={(n) => update({ keepAliveSeconds: n })}
              min={0}
              max={3600}
            />
          }
        />
        <SettingRow
          label={tr("Start forwarding rules on launch")}
          hint={tr("Rules marked auto-start are brought up when the app opens.")}
          control={
            <Toggle
              checked={s.autostartForwarding}
              onChange={(v) => update({ autostartForwarding: v })}
            />
          }
        />
        <SettingRow
          label={tr("Keep running in the tray")}
          hint={tr(
            "Closing the window hides Termoso to the system tray; sessions and port forwards stay up. Quit from the tray menu or with {keys}.",
            { keys: IS_MAC ? "⌘Q" : "Ctrl+Q" },
          )}
          control={
            <Toggle checked={s.minimizeToTray} onChange={(v) => update({ minimizeToTray: v })} />
          }
        />
        <SettingRow
          label={tr("Detect OS on first connection")}
          hint={tr(
            "Reads /etc/os-release once after connecting to pick the host's icon. Nothing leaves the SSH session.",
          )}
          control={<Toggle checked={s.detectOs} onChange={(v) => update({ detectOs: v })} />}
        />
        <SettingRow
          label={tr("Post-quantum key exchange")}
          hint={tr(
            "Offers hybrid ML-KEM-768 + X25519 (mlkem768x25519-sha256) first; servers without it negotiate a classical exchange.",
          )}
          last={IS_MAC}
          control={
            <Toggle checked={s.postQuantumKex} onChange={(v) => update({ postQuantumKex: v })} />
          }
        />
        {!IS_MAC && <DeepLinksRow />}
      </SectionCard>

      <SectionCard title={tr("Notifications")}>
        <SettingRow
          label={tr("System notifications")}
          hint={tr(
            "Shown by the operating system for things that happen while the window or tab is not in front. Only the host or file name and a status are included, never command text.",
          )}
          last={!s.notifications}
          control={
            <Toggle checked={s.notifications} onChange={(v) => update({ notifications: v })} />
          }
        />
        {s.notifications && (
          <>
            <SettingRow
              label={tr("Command finished in a background tab")}
              hint={tr("Needs shell integration on the host.")}
              control={
                <Toggle
                  checked={s.notifyCommands}
                  onChange={(v) => update({ notifyCommands: v })}
                />
              }
            />
            {s.notifyCommands && (
              <SettingRow
                label={tr("Only commands longer than")}
                hint={tr("Seconds. 0 reports every command.")}
                control={
                  <NumberInput
                    value={s.notifyCommandSeconds}
                    onChange={(n) => update({ notifyCommandSeconds: n })}
                    min={0}
                    max={3600}
                  />
                }
              />
            )}
            <SettingRow
              label={tr("Transfer finished or failed")}
              control={
                <Toggle
                  checked={s.notifyTransfers}
                  onChange={(v) => update({ notifyTransfers: v })}
                />
              }
            />
            <SettingRow
              label={tr("Connection lost")}
              hint={tr("A live session was closed by the server or the network.")}
              control={
                <Toggle
                  checked={s.notifySessions}
                  onChange={(v) => update({ notifySessions: v })}
                />
              }
            />
            <SettingRow
              label={tr("Team and account")}
              hint={tr(
                "A vault was shared with you, someone joined your shared terminal, this device was signed out.",
              )}
              last
              control={
                <Toggle checked={s.notifyAccount} onChange={(v) => update({ notifyAccount: v })} />
              }
            />
          </>
        )}
      </SectionCard>

      <SectionCard title={tr("SSH agent")}>
        <SettingRow
          label={tr("Use the system SSH agent")}
          hint={tr(
            "Offers keys held by ssh-agent (SSH_AUTH_SOCK), the Windows OpenSSH agent or Pageant after the host's own key. Private keys never leave the agent.",
          )}
          last={!s.useSshAgent}
          control={<Toggle checked={s.useSshAgent} onChange={(v) => update({ useSshAgent: v })} />}
        />
        {s.useSshAgent && <AgentKeyList />}
        <SettingRow
          label={tr("Serve vault keys as an SSH agent")}
          hint={tr(
            "Termoso runs its own agent: ssh, git and editors on this computer can sign with keys from the vault without the private keys ever being written to disk. Point SSH_AUTH_SOCK at it (line below).",
          )}
          control={
            <Toggle checked={s.serveSshAgent} onChange={(v) => update({ serveSshAgent: v })} />
          }
        />
        {s.serveSshAgent && (
          <>
            <SettingRow
              label={tr("Confirm every signature")}
              hint={tr("Ask before a program uses a key; off = sign silently (logged).")}
              control={
                <Toggle checked={s.agentConfirm} onChange={(v) => update({ agentConfirm: v })} />
              }
            />
            <AgentServerCard />
          </>
        )}
        <SettingRow
          label={tr("Run team automations on this computer")}
          hint={tr(
            "Scheduled snippets of your teams run here when their vault is unlocked (otherwise the API bridge or another member's desktop picks them up). Results go to the team page.",
          )}
          last
          control={
            <Toggle checked={s.runAutomations} onChange={(v) => update({ runAutomations: v })} />
          }
        />
      </SectionCard>

      <SectionCard title={tr("Sync")}>
        <SettingRow
          label={tr("On conflict")}
          hint={tr("Which copy wins when the same item changed on two devices.")}
          control={
            <TextField
              select
              value={s.syncConflict}
              onChange={(e) => update({ syncConflict: e.target.value as SyncConflict })}
              sx={{ width: 200 }}
            >
              <MenuItem value="newest_wins">{tr("Newest change wins")}</MenuItem>
              <MenuItem value="local_wins">{tr("This device wins")}</MenuItem>
              <MenuItem value="server_wins">{tr("Server wins")}</MenuItem>
            </TextField>
          }
        />
        <SettingRow
          label={tr("Background sync interval")}
          hint={tr("Seconds. 0 syncs only when something changes or the server signals an update.")}
          last
          control={
            <NumberInput
              value={s.syncIntervalSeconds}
              onChange={(n) => update({ syncIntervalSeconds: n === 0 ? 0 : Math.max(30, n) })}
              min={0}
              max={86_400}
              step={30}
            />
          }
        />
      </SectionCard>
    </>
  );
}

function AgentServerCard() {
  const snackbar = useSnackbar();
  const q = useQuery({
    queryKey: ["agentServer"],
    queryFn: ipc.agentServerStatus,
    refetchInterval: 15_000,
  });
  const a = q.data;
  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    snackbar.notify(tr("Copied"));
  };
  return (
    <Box sx={{ py: 1 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 0.75 }}>
        <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
          {q.isPending
            ? tr("Starting the agent…")
            : a?.running
              ? trn(a.keys.length, "Agent running · {count} key", "Agent running · {count} keys")
              : tr("Agent not running: {value}", { value: errorMessage(q.error) })}
        </Typography>
        <Button
          size="small"
          color="inherit"
          onClick={() =>
            void ipc
              .agentServerRefresh()
              .then(() => q.refetch())
              .catch((e: unknown) => snackbar.error(errorMessage(e)))
          }
          disabled={q.isFetching}
        >
          {tr("Refresh")}
        </Button>
      </Box>
      {a?.exportHint && (
        <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 0.75, minWidth: 0 }}>
          <Mono
            sx={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          >
            {a.exportHint}
          </Mono>
          <Button size="small" color="inherit" onClick={() => void copy(a.exportHint ?? "")}>
            {tr("Copy")}
          </Button>
        </Box>
      )}
      {a?.keys.map((k) => (
        <Box
          key={k.fingerprint}
          sx={{ display: "flex", gap: 1.5, alignItems: "baseline", minWidth: 0, py: 0.25 }}
        >
          <Mono secondary>{k.keyType}</Mono>
          <Mono
            sx={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          >
            {k.fingerprint}
          </Mono>
          <Typography variant="caption" color="text.secondary" noWrap sx={{ maxWidth: 200 }}>
            {k.label}
          </Typography>
        </Box>
      ))}
      {a?.skipped.map((k) => (
        <Typography
          key={k.label}
          variant="caption"
          color="text.secondary"
          sx={{ display: "block" }}
        >
          {tr("{label} not served: {reason}", { label: k.label, reason: k.reason })}
        </Typography>
      ))}
    </Box>
  );
}

function AgentKeyList() {
  const q = useQuery({ queryKey: ["agentKeys"], queryFn: ipc.agentKeys, staleTime: 10_000 });
  const a = q.data;
  return (
    <Box sx={{ py: 1 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: a?.keys.length ? 0.75 : 0 }}>
        <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
          {q.isPending
            ? tr("Looking for an agent…")
            : a?.available
              ? a.keys.length === 0
                ? tr("Agent reachable, no keys loaded (ssh-add to add one).")
                : trn(
                    a.keys.length,
                    "Agent reachable · {count} key",
                    "Agent reachable · {count} keys",
                  )
              : tr("No agent: {value}", { value: a?.error ?? errorMessage(q.error) })}
        </Typography>
        <Button
          size="small"
          color="inherit"
          onClick={() => void q.refetch()}
          disabled={q.isFetching}
        >
          {tr("Refresh")}
        </Button>
      </Box>
      {a?.keys.map((k) => (
        <Box
          key={k.fingerprint}
          sx={{ display: "flex", gap: 1.5, alignItems: "baseline", minWidth: 0, py: 0.25 }}
        >
          <Mono secondary>{k.keyType}</Mono>
          <Mono
            sx={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          >
            {k.fingerprint}
          </Mono>
          {k.comment && (
            <Typography variant="caption" color="text.secondary" noWrap sx={{ maxWidth: 200 }}>
              {k.comment}
            </Typography>
          )}
        </Box>
      ))}
    </Box>
  );
}

function Terminal({ s, update }: SectionProps) {
  return (
    <>
      <ThemeGallery value={s.terminalTheme} onChange={(id) => update({ terminalTheme: id })} />

      <SectionCard title={tr("Text")}>
        <SettingRow
          label={tr("Font family")}
          hint={tr(
            "Bundled faces ship with the app; Nerd Font symbols are always available as a fallback.",
          )}
          control={
            <FontPicker
              value={s.terminalFontFamily}
              onChange={(name) => update({ terminalFontFamily: name })}
            />
          }
        />
        <SettingRow
          label={tr("Font size")}
          control={
            <NumberInput
              value={s.terminalFontSize}
              onChange={(n) => update({ terminalFontSize: n })}
              min={8}
              max={40}
              width={90}
            />
          }
        />
        <SettingRow
          label={tr("Line height")}
          hint={tr("Multiplier of the font's natural height.")}
          control={
            <NumberInput
              value={s.terminalLineHeight}
              onChange={(n) => update({ terminalLineHeight: Math.min(2, Math.max(0.8, n)) })}
              min={0.8}
              max={2}
              step={0.05}
              width={90}
            />
          }
        />
        <FontPreview
          family={s.terminalFontFamily}
          size={s.terminalFontSize}
          lineHeight={s.terminalLineHeight}
        />
        <SettingRow
          label={tr("Scrollback lines")}
          last
          control={
            <NumberInput
              value={s.scrollback}
              onChange={(n) => update({ scrollback: n })}
              min={100}
              max={100_000}
              step={100}
            />
          }
        />
      </SectionCard>

      <SectionCard title={tr("Colors")}>
        <SettingRow
          label={tr("Bright bold colors")}
          hint={tr("Draw bold text in the bright variant of its color, as classic terminals do.")}
          control={<Toggle checked={s.brightBold} onChange={(v) => update({ brightBold: v })} />}
        />
        <SettingRow
          label={tr("Keyword highlighting")}
          hint={tr(
            "Colors Error, Warning, OK, Info and Debug words plus IP and MAC addresses in the output. Applied locally while rendering; nothing is sent to the host.",
          )}
          last
          control={
            <Toggle
              checked={s.keywordHighlight}
              onChange={(v) => update({ keywordHighlight: v })}
            />
          }
        />
      </SectionCard>

      <SectionCard title={tr("Cursor")}>
        <SettingRow
          label={tr("Style")}
          control={
            <TextField
              select
              value={s.cursorStyle}
              onChange={(e) => update({ cursorStyle: e.target.value as CursorStyle })}
              sx={{ width: 160 }}
            >
              <MenuItem value="bar">{tr("Bar")}</MenuItem>
              <MenuItem value="block">{tr("Block")}</MenuItem>
              <MenuItem value="underline">{tr("Underline")}</MenuItem>
            </TextField>
          }
        />
        <SettingRow
          label={tr("Blinking")}
          last
          control={<Toggle checked={s.cursorBlink} onChange={(v) => update({ cursorBlink: v })} />}
        />
      </SectionCard>

      <SectionCard title={tr("Connection")}>
        <SettingRow
          label={tr("Autoreconnect")}
          hint={tr(
            "When an SSH or Telnet session drops, retry up to 6 times (30–60 s apart) while keeping the terminal contents. Sessions you close yourself are left alone.",
          )}
          control={
            <Toggle checked={s.autoReconnect} onChange={(v) => update({ autoReconnect: v })} />
          }
        />
        <SettingRow
          label={tr("Terminal type")}
          hint={tr(
            "Sent as TERM to the remote side and to the local shell. Takes effect for new sessions.",
          )}
          control={
            <TextField
              select
              value={s.termType}
              onChange={(e) => update({ termType: e.target.value as TermType })}
              sx={{ width: 200 }}
            >
              {TERM_TYPES.map((t) => (
                <MenuItem key={t} value={t}>
                  {t}
                </MenuItem>
              ))}
            </TextField>
          }
        />
        <LocalShellRow value={s.localShell} onChange={(v) => update({ localShell: v })} />
      </SectionCard>

      <TriggersCard s={s} update={update} />
      <SectionCard title={tr("Behaviour")}>
        <SettingRow
          label={tr("Audible bell")}
          control={
            <Toggle checked={s.terminalBell} onChange={(v) => update({ terminalBell: v })} />
          }
        />
        <SettingRow
          label={tr("Copy on select")}
          control={
            <Toggle checked={s.copyOnSelect} onChange={(v) => update({ copyOnSelect: v })} />
          }
        />
        <SettingRow
          label={tr("Paste on right click")}
          control={
            <Toggle
              checked={s.pasteOnRightClick}
              onChange={(v) => update({ pasteOnRightClick: v })}
            />
          }
        />
        <SettingRow
          label={tr("Confirm before pasting multiple lines")}
          control={
            <Toggle
              checked={s.confirmPasteMultiline}
              onChange={(v) => update({ confirmPasteMultiline: v })}
            />
          }
        />
        <SettingRow
          label={tr("Confirm before closing a connected tab")}
          control={
            <Toggle checked={s.confirmCloseTab} onChange={(v) => update({ confirmCloseTab: v })} />
          }
        />
        <SettingRow
          label={tr("Shell integration")}
          hint={tr(
            "Marks prompts and commands in bash, zsh and fish (OSC 133) so history, exit codes and the working directory are tracked. Nothing is written to your dotfiles.",
          )}
          control={
            <Toggle
              checked={s.shellIntegration}
              onChange={(v) => update({ shellIntegration: v })}
            />
          }
        />
        <SettingRow
          label={tr("Restore running commands")}
          hint={tr(
            "Workspaces and the previous session remember each pane's working directory and the command it was running. Reopening always returns to the directory; the command can be placed on the prompt for you to confirm, run right away, or dropped.",
          )}
          control={
            <TextField
              select
              value={s.restoreCommands}
              onChange={(e) => update({ restoreCommands: e.target.value as RestoreCommands })}
              sx={{ width: 200 }}
            >
              <MenuItem value="type">{tr("Type, don't run")}</MenuItem>
              <MenuItem value="run">{tr("Run automatically")}</MenuItem>
              <MenuItem value="never">{tr("Directory only")}</MenuItem>
            </TextField>
          }
        />
        <SettingRow
          label={tr("Command autocomplete")}
          hint={tr(
            "Offline suggestions from ~500 commands, their options, paths, snippets and your encrypted history. Tab inserts, Esc dismisses. Can be paused per session from the terminal menu.",
          )}
          last
          control={
            <Toggle checked={s.autocomplete} onChange={(v) => update({ autocomplete: v })} />
          }
        />
      </SectionCard>
    </>
  );
}

const CUSTOM_SHELL = "\u0000custom";

/** Shells found on this machine plus a free-form path with arguments. */
function LocalShellRow({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const shells = useQuery({
    queryKey: ["localShells"],
    queryFn: ipc.localShells,
    staleTime: 60_000,
  });
  const found = shells.data ?? [];
  const listed = value === "" || found.includes(value);
  const [custom, setCustom] = useState(!listed);
  const [draft, setDraft] = useState(listed ? "" : value);
  const selectValue = custom || !listed ? CUSTOM_SHELL : value;
  const commit = () => {
    const next = draft.trim();
    if (next !== value) onChange(next);
  };
  return (
    <SettingRow
      label={tr("Local terminal shell")}
      hint={tr(
        'Program started by Local Terminal, optionally with arguments. Default is your login shell (or PowerShell on Windows). Quote a path that contains spaces: "C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoLogo.',
      )}
      last
      control={
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1, alignItems: "flex-end" }}>
          <TextField
            select
            value={selectValue}
            onChange={(e) => {
              if (e.target.value === CUSTOM_SHELL) {
                setCustom(true);
                setDraft(listed ? "" : value);
                return;
              }
              setCustom(false);
              onChange(e.target.value);
            }}
            sx={{ width: 280 }}
          >
            <MenuItem value="">{tr("Default shell")}</MenuItem>
            {found.map((sh) => (
              <MenuItem key={sh} value={sh} sx={{ fontFamily: "monospace", fontSize: 13 }}>
                {sh}
              </MenuItem>
            ))}
            <MenuItem value={CUSTOM_SHELL}>{tr("Custom command…")}</MenuItem>
          </TextField>
          {(custom || !listed) && (
            <TextField
              value={draft}
              placeholder="/usr/bin/fish --login"
              onChange={(e) => setDraft(e.target.value)}
              onBlur={commit}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  commit();
                }
              }}
              sx={{ width: 280 }}
              slotProps={{ htmlInput: { spellCheck: false } }}
            />
          )}
        </Box>
      }
    />
  );
}

function Logs({ s, update }: SectionProps) {
  return (
    <SectionCard title={tr("Session recording")}>
      <SettingRow
        label={tr("Record terminal sessions")}
        hint={tr("Recordings are encrypted with your master key and stay on this device.")}
        control={
          <Toggle checked={s.recordSessions} onChange={(v) => update({ recordSessions: v })} />
        }
      />
      <SettingRow
        label={tr("Keep recordings for")}
        hint={tr("Days. 0 keeps them forever.")}
        control={
          <NumberInput
            value={s.logRetentionDays}
            onChange={(n) => update({ logRetentionDays: n })}
            min={0}
            max={3650}
          />
        }
      />
      <SettingRow
        label={tr("Upload to the account server")}
        hint={tr(
          "Encrypted with your vault key before leaving the device; requires being signed in. Team vaults with session recording turned on by a manager always share their recordings.",
        )}
        last
        control={<Toggle checked={s.uploadLogs} onChange={(v) => update({ uploadLogs: v })} />}
      />
    </SectionCard>
  );
}

function About() {
  const info = useAppInfo();
  const d = info.data;

  return (
    <>
      <SectionCard title={tr("Termoso")}>
        <SettingRow label={tr("Version")} control={<Value>{d ? d.version : "…"}</Value>} />
        <SettingRow label={tr("Platform")} control={<Value>{d?.platform ?? "…"}</Value>} />
        <SettingRow
          label={tr("Profile")}
          last
          control={
            <Value>
              <Mono>{d?.profileDir ?? "…"}</Mono>
            </Value>
          }
        />
      </SectionCard>

      <SectionCard title={tr("Privacy")}>
        <Typography variant="body2" color="text.secondary">
          {tr(
            "Termoso sends nothing anywhere unless you sign in to a server you chose or ask it to check for updates. No analytics, no crash reports, no background pings.",
          )}
        </Typography>
      </SectionCard>
    </>
  );
}

function Value({ children }: { children: ReactNode }) {
  return (
    <Typography
      variant="body2"
      color="text.secondary"
      sx={{ maxWidth: 360, textAlign: "right", wordBreak: "break-all" }}
    >
      {children}
    </Typography>
  );
}

/**
 * Settings as a window over whatever is open (Termius style): the sidebar
 * item, Ctrl+, and every "open Settings" link land here; Esc / × close it.
 */
export function SettingsDialog() {
  const open = useNav((s) => s.settingsOpen);
  return (
    <Dialog
      open={open}
      onClose={closeSettings}
      maxWidth={false}
      slotProps={{
        paper: {
          sx: {
            width: "min(1040px, 94vw)",
            height: "min(720px, 90vh)",
            display: "flex",
            flexDirection: "column",
            bgcolor: "surface.base",
            backgroundImage: "none",
            borderRadius: 3,
            overflow: "hidden",
          },
        },
      }}
    >
      <Box sx={{ flex: 1, minHeight: 0, display: "flex", position: "relative" }}>
        <SettingsPage />
        <IconButton
          onClick={closeSettings}
          aria-label={tr("Close settings")}
          size="small"
          sx={{ position: "absolute", top: 10, right: 10 }}
        >
          <CloseRoundedIcon fontSize="small" />
        </IconButton>
      </Box>
    </Dialog>
  );
}
