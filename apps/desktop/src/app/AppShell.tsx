import { useEffect } from "react";
import { Box } from "@mui/material";
import { useQueryClient } from "@tanstack/react-query";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { HostsPage } from "@/hosts/HostsPage";
import { SettingsDialog } from "@/settings/SettingsPage";
import { SftpPage } from "@/sftp/SftpPage";
import { ForwardingPage } from "@/forwarding/ForwardingPage";
import { SnippetsPage } from "@/snippets/SnippetsPage";
import { KeychainPage } from "@/keychain/KeychainPage";
import { KnownHostsPage } from "@/knownhosts/KnownHostsPage";
import { LogsPage } from "@/logs/LogsPage";
import { PromptHost } from "@/prompts/PromptHost";
import { TerminalWorkspace } from "@/terminal/TerminalWorkspace";
import { TerminalOverlays } from "@/terminal/TerminalOverlays";
import { DockPreviewLayer } from "@/terminal/TerminalPane";
import { PaneLayer } from "@/terminal/PaneHost";
import { dropAllTabs, startTerminalEvents, useTerminal } from "@/terminal/store";
import { startMultiplayerEvents } from "@/terminal/multiplayer";
import { startWorkspaces } from "@/terminal/workspaces";
import { RestoreBanner } from "@/terminal/RestoreBanner";
import { dropAllSftp, startSftpEvents } from "@/sftp/store";
import { startUpdateEvents } from "@/update/store";
import { UpdateBanner } from "@/update/UpdateBanner";
import {
  useAccount,
  useCloudSyncEvents,
  useSettings,
  useSyncNotices,
  useVaultEvents,
  useVaultStatus,
} from "@/ipc/hooks";
import * as ipc from "@/ipc/commands";
import { errorMessage } from "@/ipc/types";
import { EmptyState } from "@/components/EmptyState";
import { LockScreen } from "./LockScreen";
import { WelcomeScreen } from "@/welcome/WelcomeScreen";
import { RecoveryPrompt } from "@/account/SignIn";
import { goToSettings, isHomeTab, isNewTab, isSerialTab, isSftpTab, useNav } from "./navigation";
import { NewTabPage } from "./NewTabPage";
import { SerialPage } from "@/hosts/SerialPage";
import { startCommands } from "./commands";
import { applyShortcutOverrides } from "./shortcuts";
import { CommandPalette } from "./CommandPalette";
import { startDeepLinks } from "./deepLinks";
import { startNotifications } from "./notifications";
import { startTray } from "./tray";
import { tr } from "@/i18n";
import { usePermsSync } from "@/team/perms";

/** Report user input to Rust for the inactivity timer, at most once per interval. */
const ACTIVITY_INTERVAL_MS = 15_000;

function useActivityReporter(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    let last = 0;
    const report = () => {
      const now = Date.now();
      if (now - last < ACTIVITY_INTERVAL_MS) return;
      last = now;
      void ipc.vaultActivity().catch(() => undefined);
    };
    const events = ["keydown", "pointerdown", "wheel"] as const;
    for (const ev of events) window.addEventListener(ev, report, { capture: true, passive: true });
    return () => {
      for (const ev of events) window.removeEventListener(ev, report, { capture: true });
    };
  }, [enabled]);
}

/**
 * Lock gate: the whole shell (queries, event listeners, terminals) lives only
 * while the vault is open, so a lock tears everything down and an unlock
 * starts from a clean slate.
 */
export function AppShell() {
  usePermsSync();
  const status = useVaultStatus();
  useVaultEvents();
  // Outside the lock gate: a hidden window must stay reachable while locked.
  useEffect(startTray, []);
  useEffect(() => {
    let active = true;
    const un = ipc.onVaultEvent((e) => {
      if (!active || e.type !== "locked") return;
      dropAllTabs();
      dropAllSftp();
    });
    return () => {
      active = false;
      void un.then((f) => f());
    };
  }, []);
  useActivityReporter(status.data?.passwordProtected === true && !status.data.locked);

  if (status.isPending) return <Box sx={{ height: "100%", bgcolor: "surface.lowest" }} />;
  if (status.error)
    return <EmptyState title={tr("Vault unavailable")} description={errorMessage(status.error)} />;
  if (status.data.locked) return <LockScreen />;
  return <UnlockedShell />;
}

function UnlockedShell() {
  const section = useNav((s) => s.section);
  const queryClient = useQueryClient();
  const tabs = useTerminal((s) => s.tabs);
  const activeTabId = useTerminal((s) => s.activeTabId);
  const home = isHomeTab(activeTabId);
  const sftp = isSftpTab(activeTabId);
  const newTab = isNewTab(activeTabId);
  const serial = isSerialTab(activeTabId);
  const account = useAccount();
  const settings = useSettings();

  useSyncNotices();
  useCloudSyncEvents();
  useEffect(() => {
    startTerminalEvents(queryClient);
    startMultiplayerEvents();
    startWorkspaces();
    startSftpEvents(queryClient);
    startUpdateEvents();
    const stopCommands = startCommands();
    const stopLinks = startDeepLinks();
    const stopNotifications = startNotifications();
    return () => {
      stopCommands();
      stopLinks();
      stopNotifications();
    };
  }, [queryClient]);
  useEffect(() => {
    if (settings.data) applyShortcutOverrides(settings.data.shortcuts);
  }, [settings.data]);

  if (account.isPending || settings.isPending) {
    return <Box sx={{ height: "100%", bgcolor: "surface.lowest" }} />;
  }
  if (settings.data && account.data && !account.data.account && !settings.data.welcomeSeen) {
    return (
      <>
        <WelcomeScreen settings={settings.data} />
        <RecoveryPrompt />
      </>
    );
  }

  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        bgcolor: "background.default",
      }}
    >
      <TopBar />
      <Box sx={{ flex: 1, minHeight: 0, display: "flex" }}>
        {(home || sftp) && <Sidebar />}
        <Box
          sx={{
            flex: 1,
            minWidth: 0,
            display: "flex",
            flexDirection: "column",
            bgcolor: "surface.base",
            position: "relative",
          }}
        >
          {home && <UpdateBanner onOpenSettings={() => goToSettings("updates")} />}
          {home && <RestoreBanner />}
          {tabs.map((t) => (
            <Box
              key={t.id}
              sx={{
                flex: 1,
                minHeight: 0,
                display: t.id === activeTabId ? "flex" : "none",
                flexDirection: "column",
              }}
            >
              <TerminalWorkspace tabId={t.id} />
            </Box>
          ))}
          <Box
            sx={{
              flex: 1,
              minHeight: 0,
              display: sftp ? "flex" : "none",
              flexDirection: "column",
            }}
          >
            <SftpPage />
          </Box>
          {newTab && <NewTabPage />}
          {serial && <SerialPage />}
          <Box
            sx={{
              flex: 1,
              minHeight: 0,
              display: home ? "flex" : "none",
              flexDirection: "column",
            }}
          >
            {section === "hosts" && <HostsPage />}
            {section === "forwarding" && <ForwardingPage />}
            {section === "snippets" && <SnippetsPage />}
            {section === "keychain" && <KeychainPage />}
            {section === "knownHosts" && <KnownHostsPage />}
            {section === "logs" && <LogsPage />}
          </Box>
        </Box>
      </Box>
      <TerminalOverlays />
      <PaneLayer />
      <DockPreviewLayer />
      <CommandPalette />
      <SettingsDialog />
      <PromptHost />
      <RecoveryPrompt />
    </Box>
  );
}
