import { useMemo, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
} from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import MoreVertRoundedIcon from "@mui/icons-material/MoreVertRounded";
import ContentPasteRoundedIcon from "@mui/icons-material/ContentPasteRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import TabRoundedIcon from "@mui/icons-material/TabRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import DataObjectRoundedIcon from "@mui/icons-material/DataObjectRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import HistoryRoundedIcon from "@mui/icons-material/HistoryRounded";
import PaletteRoundedIcon from "@mui/icons-material/PaletteRounded";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import RocketLaunchOutlinedIcon from "@mui/icons-material/RocketLaunchOutlined";
import SwapHorizRoundedIcon from "@mui/icons-material/SwapHorizRounded";
import StopRoundedIcon from "@mui/icons-material/StopRounded";
import AutoAwesomeOutlinedIcon from "@mui/icons-material/AutoAwesomeOutlined";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import RemoveRoundedIcon from "@mui/icons-material/RemoveRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { SnippetCard, Uuid } from "@/ipc/types";
import { errorMessage, isPostQuantumKex } from "@/ipc/types";
import * as ipc from "@/ipc/commands";
import { keys, useHosts, usePfRules, useSaveSettings, useSettings, useSnippets } from "@/ipc/hooks";
import { useActiveVault } from "@/app/vault";
import { goToSection, requestCreate, requestForwardingRule } from "@/app/navigation";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { useSnackbar } from "@/components/Snackbar";
import { ActionMenu, Loading, Mono, SearchField, type MenuAction } from "@/components/ui";
import { ThemeCard } from "@/settings/ThemeGallery";
import { RuleTile, RuntimeLine } from "@/forwarding/ForwardingPanels";
import { routeLine, ruleTitle } from "@/forwarding/model";
import { FontPicker } from "@/settings/FontPicker";
import { SearchBar } from "./SearchBar";
import { AskAiPanel } from "./AskAiPanel";
import { VariablesDialog } from "@/snippets/SnippetsPage";
import { ALL_HOSTS, CommandHistoryList, ConnectionHistoryList } from "@/history/ShellHistory";
import { RunTargets } from "@/snippets/RunStatus";
import { startRun, summarize, useRuns, watchRun } from "@/snippets/run";
import { AUTO_THEME, allTerminalThemes, terminalThemeById, useCustomThemes } from "./themes";
import {
  autocompleteOn,
  copyText,
  endOfToday,
  monitorOn,
  pauseSuggestions,
  runCommand,
  setPaneAutocomplete,
  setPaneMonitor,
  setSidePanel,
  setTabTheme,
  terminalStore,
  useTerminal,
  type Pane,
  type SidePanelTab,
  type TerminalTab,
} from "./store";
import { tr, trx, msg } from "@/i18n";
import { requirePerm } from "@/team/perms";

export const SIDE_PANEL_WIDTH = 300;

const TABS: { id: SidePanelTab; label: string; icon: React.ReactNode }[] = [
  { id: "search", label: msg("Terminal"), icon: <RocketLaunchOutlinedIcon /> },
  { id: "forwarding", label: msg("Port forwarding"), icon: <SwapHorizRoundedIcon /> },
  { id: "snippets", label: msg("Snippets"), icon: <DataObjectRoundedIcon /> },
  { id: "history", label: msg("History"), icon: <HistoryRoundedIcon /> },
  { id: "themes", label: msg("Themes"), icon: <PaletteRoundedIcon /> },
  { id: "ask", label: msg("Ask AI"), icon: <AutoAwesomeOutlinedIcon /> },
  { id: "info", label: msg("Session info"), icon: <InfoOutlinedIcon /> },
];

export function TerminalSidePanel({ tab }: { tab: TerminalTab }) {
  const panel = useTerminal((s) => s.sidePanel);
  const pane = useTerminal((s) => s.panes[tab.activePaneId]);
  if (!panel || !pane) return null;
  return (
    <Box sx={{ flexShrink: 0, display: "flex", minHeight: 0, py: 0.75, pr: 0.75 }}>
      <Box
        sx={{
          width: SIDE_PANEL_WIDTH,
          display: "flex",
          flexDirection: "column",
          minHeight: 0,
          borderRadius: 2,
          bgcolor: "surface.high",
          overflow: "hidden",
        }}
      >
        <Stack direction="row" sx={{ alignItems: "center", gap: 0.5, px: 1.25, pt: 1.25, pb: 0.5 }}>
          {TABS.map((t) => {
            const active = panel === t.id;
            return (
              <Tooltip key={t.id} title={tr(t.label)} enterDelay={600}>
                <IconButton
                  size="small"
                  aria-label={tr(t.label)}
                  aria-pressed={active}
                  onClick={() => setSidePanel(t.id)}
                  sx={{
                    width: 32,
                    height: 32,
                    borderRadius: 1.5,
                    color: active ? "primary.main" : "text.secondary",
                    bgcolor: active ? "rgba(43,184,132,0.18)" : "transparent",
                    "&:hover": { bgcolor: active ? "rgba(43,184,132,0.26)" : "surface.highest" },
                    "& svg": { fontSize: 18 },
                  }}
                >
                  {t.icon}
                </IconButton>
              </Tooltip>
            );
          })}
          <Box sx={{ flex: 1 }} />
          <IconButton
            size="small"
            onClick={() => setSidePanel(null)}
            aria-label={tr("Close panel")}
            sx={{ width: 32, height: 32, borderRadius: 1.5, color: "text.secondary" }}
          >
            <CloseRoundedIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Stack>
        <Box sx={{ flex: 1, minHeight: 0, overflow: "auto" }}>
          {panel === "search" && <TerminalPanel pane={pane} />}
          {panel === "forwarding" && <ForwardingPanel pane={pane} />}
          {panel === "snippets" && <SnippetsPanel pane={pane} />}
          {panel === "history" && <HistoryPanel pane={pane} />}
          {panel === "themes" && <ThemesPanel tab={tab} pane={pane} />}
          {panel === "ask" && <AskAiPanel pane={pane} />}
          {panel === "info" && <InfoPanel pane={pane} tab={tab} />}
        </Box>
      </Box>
    </Box>
  );
}

/* ----------------------------------------------------------- forwarding */

/** Port-forwarding rules of the pane's host with start / stop, like Termius' side panel. */
function ForwardingPanel({ pane }: { pane: Pane }) {
  const vault = useActiveVault();
  const rules = usePfRules(vault.data?.id ?? null);
  const qc = useQueryClient();
  const snackbar = useSnackbar();
  const hostId = pane.hostId;
  const mine = (rules.data ?? []).filter((r) => r.hostId === hostId);
  const toggle = useMutation({
    mutationFn: (rule: (typeof mine)[number]) =>
      rule.runtime.state === "stopped"
        ? requirePerm(rule.vaultId, "connect.port_forward")
          ? ipc.pfStart(rule.id)
          : Promise.resolve(null)
        : ipc.pfStop(rule.id),
    onSettled: () => void qc.invalidateQueries({ queryKey: keys.pfRules(vault.data?.id ?? null) }),
    onError: (e) => snackbar.error(errorMessage(e)),
  });

  if (!hostId) {
    return (
      <Stack sx={{ p: 1.5 }}>
        <Typography variant="body2" color="text.secondary">
          {tr("Port forwarding needs a saved host — this session was opened without one.")}
        </Typography>
      </Stack>
    );
  }
  return (
    <Stack sx={{ p: 1.5, gap: 1 }}>
      <Stack direction="row" sx={{ alignItems: "center", gap: 1 }}>
        <Button
          size="small"
          variant="tonal"
          startIcon={<AddRoundedIcon />}
          onClick={() => requestForwardingRule(hostId)}
        >
          {tr("New rule")}
        </Button>
        <Box sx={{ flex: 1 }} />
        <Button size="small" color="inherit" onClick={() => goToSection("forwarding")}>
          {tr("Open all")}
        </Button>
      </Stack>
      {rules.isPending ? (
        <Loading pt={2} />
      ) : mine.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ px: 0.5 }}>
          {tr("No port forwarding rules for this host yet.")}
        </Typography>
      ) : (
        mine.map((r) => {
          const running = r.runtime.state !== "stopped";
          return (
            <Stack
              key={r.id}
              direction="row"
              sx={{
                alignItems: "center",
                gap: 1,
                p: 1,
                borderRadius: 1.5,
                bgcolor: "surface.highest",
              }}
            >
              <RuleTile kind={r.kind} active={running} size={32} />
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography variant="body2" noWrap sx={{ fontWeight: 600 }}>
                  {ruleTitle(r)}
                </Typography>
                <Typography
                  variant="caption"
                  color="text.secondary"
                  noWrap
                  sx={{ display: "block" }}
                >
                  {routeLine(r)}
                </Typography>
                <RuntimeLine rule={r} />
              </Box>
              <Tooltip title={running ? tr("Stop") : tr("Start")}>
                <IconButton
                  size="small"
                  aria-label={running ? tr("Stop") : tr("Start")}
                  disabled={toggle.isPending}
                  onClick={() => toggle.mutate(r)}
                  sx={{ color: running ? "primary.main" : "text.secondary" }}
                >
                  {running ? (
                    <StopRoundedIcon fontSize="small" />
                  ) : (
                    <PlayArrowRoundedIcon fontSize="small" />
                  )}
                </IconButton>
              </Tooltip>
            </Stack>
          );
        })
      )}
    </Stack>
  );
}

/* ------------------------------------------------------------- terminal */

/** Termius' first section: buffer search on top, autocomplete state below. */
function TerminalPanel({ pane }: { pane: Pane }) {
  const settings = useSettings();
  const save = useSaveSettings();
  const snackbar = useSnackbar();
  const paused = useTerminal(
    (s) => s.suggestPausedUntil !== null && s.suggestPausedUntil > Date.now(),
  );
  const on = useTerminal((s) => autocompleteOn(pane.id, s));
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const globalOff = settings.data?.autocomplete === false;
  const label = globalOff
    ? tr("Disabled")
    : paused
      ? tr("Paused today")
      : pane.autocomplete
        ? tr("Enabled")
        : tr("Off in this tab");

  const setGlobal = (autocomplete: boolean) => {
    if (!settings.data) return;
    save.mutate(
      { ...settings.data, autocomplete },
      { onError: (e) => snackbar.error(errorMessage(e)) },
    );
  };

  return (
    <Stack sx={{ p: 1.5, gap: 1.25 }}>
      <SearchBar key={pane.id} paneId={pane.id} onClose={() => setSidePanel(null)} />
      <Divider />
      <Stack direction="row" sx={{ alignItems: "center", gap: 1, px: 0.5 }}>
        <Typography variant="subtitle2" sx={{ flex: 1 }}>
          {tr("Autocomplete")}
        </Typography>
        <Button
          size="small"
          color="inherit"
          endIcon={<ExpandMoreRoundedIcon />}
          onClick={(e) => setAnchor(e.currentTarget)}
          sx={{ color: on ? "text.primary" : "text.secondary", fontWeight: 500 }}
          aria-label={tr("Autocomplete: {label}", { label })}
        >
          {label}
        </Button>
        <Menu open={anchor !== null} anchorEl={anchor} onClose={() => setAnchor(null)}>
          <MenuItem
            selected={on}
            onClick={() => {
              setAnchor(null);
              if (globalOff) setGlobal(true);
              if (paused) pauseSuggestions(null);
              setPaneAutocomplete(pane.id, true);
            }}
          >
            {tr("Enabled")}
          </MenuItem>
          <MenuItem
            selected={!globalOff && !paused && !pane.autocomplete}
            onClick={() => {
              setAnchor(null);
              setPaneAutocomplete(pane.id, false);
            }}
          >
            {tr("Off in this tab")}
          </MenuItem>
          <MenuItem
            selected={paused}
            onClick={() => {
              setAnchor(null);
              pauseSuggestions(endOfToday());
            }}
          >
            {tr("Pause until tomorrow")}
          </MenuItem>
          <MenuItem
            selected={globalOff}
            onClick={() => {
              setAnchor(null);
              setGlobal(false);
            }}
          >
            {tr("Disabled everywhere")}
          </MenuItem>
        </Menu>
      </Stack>
      <Typography variant="caption" color="text.secondary" sx={{ px: 0.5 }}>
        {tr(
          "Offline suggestions from commands, paths, snippets and your history. Tab inserts, Esc dismisses.",
        )}
      </Typography>
      {pane.protocol === "ssh" && <MonitorSwitch pane={pane} />}
    </Stack>
  );
}

/** Remote monitoring: on / off for this session, defaulting to the app setting. */
function MonitorSwitch({ pane }: { pane: Pane }) {
  const settings = useSettings();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const on = monitorOn(pane, settings.data);
  const label = on ? tr("Enabled") : tr("Off in this tab");
  return (
    <>
      <Divider />
      <Stack direction="row" sx={{ alignItems: "center", gap: 1, px: 0.5 }}>
        <Typography variant="subtitle2" sx={{ flex: 1 }}>
          {tr("Remote monitoring")}
        </Typography>
        <Button
          size="small"
          color="inherit"
          endIcon={<ExpandMoreRoundedIcon />}
          onClick={(e) => setAnchor(e.currentTarget)}
          sx={{ color: on ? "text.primary" : "text.secondary", fontWeight: 500 }}
          aria-label={tr("Remote monitoring: {label}", { label })}
        >
          {label}
        </Button>
        <Menu open={anchor !== null} anchorEl={anchor} onClose={() => setAnchor(null)}>
          <MenuItem
            selected={on}
            onClick={() => {
              setAnchor(null);
              setPaneMonitor(pane.id, true);
            }}
          >
            {tr("Enabled")}
          </MenuItem>
          <MenuItem
            selected={!on}
            onClick={() => {
              setAnchor(null);
              setPaneMonitor(pane.id, false);
            }}
          >
            {tr("Off in this tab")}
          </MenuItem>
        </Menu>
      </Stack>
      <Typography variant="caption" color="text.secondary" sx={{ px: 0.5 }}>
        {tr(
          "Shows CPU, memory, network, uptime, users and disks of the server under the terminal. Reads /proc on a separate channel every few seconds; nothing is installed or written.",
        )}
      </Typography>
    </>
  );
}

/* ------------------------------------------------------------- snippets */

type SnippetAction = "run" | "paste" | "all" | "targets";

const ACTION_LABEL: Record<SnippetAction, string> = {
  run: msg("Run in this terminal"),
  paste: msg("Paste into this terminal"),
  all: msg("Run in all tabs"),
  targets: msg("Run on configured targets"),
};

function SnippetsPanel({ pane }: { pane: Pane }) {
  const vault = useActiveVault();
  const vaultId = vault.data?.id ?? null;
  const snippets = useSnippets(vaultId);
  const hosts = useHosts(vaultId);
  const qc = useQueryClient();
  const [query, setQuery] = useState("");
  const [menu, setMenu] = useState<{
    snippet: SnippetCard;
    anchor: HTMLElement | null;
    position: { left: number; top: number } | null;
  } | null>(null);
  const [pending, setPending] = useState<{ snippet: SnippetCard; action: SnippetAction } | null>(
    null,
  );
  const [remove, setRemove] = useState<SnippetCard | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const run = useRuns((s) => (runId ? s.runs.find((r) => r.id === runId) : undefined));
  const snackbar = useSnackbar();
  const del = useMutation({
    mutationFn: (id: Uuid) => ipc.snippetDelete(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["snippets"] });
      setRemove(null);
      snackbar.notify(tr("Snippet deleted"));
    },
    onError: (e) => snackbar.error(errorMessage(e)),
  });
  const q = query.trim().toLowerCase();
  const items = (snippets.data ?? []).filter(
    (s) => !q || s.label.toLowerCase().includes(q) || s.script.toLowerCase().includes(q),
  );
  const connected = pane.status === "connected";
  const panes = useTerminal((s) => s.panes);
  const openCount = useMemo(
    () =>
      Object.values(panes).filter((p) => p.status === "connected" && p.protocol !== null).length,
    [panes],
  );

  const execute = (snippet: SnippetCard, action: SnippetAction, vars: Record<string, string>) => {
    const sessionIds =
      action === "all"
        ? Object.values(terminalStore.get().panes)
            .filter((p) => p.status === "connected" && p.protocol !== null)
            .map((p) => p.id)
        : action === "targets"
          ? []
          : [pane.id];
    const started = startRun({
      snippet,
      vars,
      sessionIds,
      hostIds: action === "targets" ? snippet.targetHostIds : [],
      hosts: hosts.data ?? [],
      paste: action === "paste",
    });
    if (started.targets.length === 0) {
      snackbar.error(tr("Nothing to run on"));
      return;
    }
    setRunId(started.id);
    watchRun(started.id, (done) => {
      if (done.targets.length === 1 && action !== "targets") return;
      if (done.targets.some((t) => t.state === "failed")) snackbar.error(summarize(done));
      else snackbar.notify(summarize(done));
    });
  };
  const trigger = (snippet: SnippetCard, action: SnippetAction) => {
    if (snippet.variables.length > 0) setPending({ snippet, action });
    else execute(snippet, action, {});
  };

  const menuItems = (s: SnippetCard): MenuAction[] => [
    {
      label: tr("Run"),
      icon: <PlayArrowRoundedIcon fontSize="small" />,
      disabled: !connected,
      onClick: () => trigger(s, "run"),
    },
    {
      label: tr("Paste"),
      icon: <ContentPasteRoundedIcon fontSize="small" />,
      disabled: !connected,
      onClick: () => trigger(s, "paste"),
    },
    {
      label:
        openCount > 1 ? tr("Run in all tabs ({openCount})", { openCount }) : tr("Run in all tabs"),
      icon: <TabRoundedIcon fontSize="small" />,
      disabled: openCount === 0,
      onClick: () => trigger(s, "all"),
    },
    {
      label:
        s.targetHostIds.length > 0
          ? tr("Run on targets ({length})", { length: s.targetHostIds.length })
          : tr("Run on targets"),
      icon: <DnsRoundedIcon fontSize="small" />,
      disabled: s.targetHostIds.length === 0,
      divider: true,
      onClick: () => trigger(s, "targets"),
    },
    {
      label: tr("Copy script"),
      icon: <ContentCopyRoundedIcon fontSize="small" />,
      onClick: () => void copyText(s.script).then(() => snackbar.notify(tr("Copied"))),
    },
    {
      label: tr("Open in Snippets"),
      icon: <OpenInNewRoundedIcon fontSize="small" />,
      divider: true,
      onClick: () => goToSection("snippets"),
    },
    {
      label: tr("Remove"),
      icon: <DeleteOutlineRoundedIcon fontSize="small" />,
      danger: true,
      onClick: () => setRemove(s),
    },
  ];

  return (
    <Stack sx={{ p: 1.5, gap: 1.5 }}>
      <Stack direction="row" sx={{ alignItems: "center", gap: 1 }}>
        <Button
          size="small"
          variant="tonal"
          startIcon={<DataObjectRoundedIcon />}
          onClick={() => requestCreate("snippet")}
          sx={{ flexShrink: 0 }}
        >
          {tr("New snippet")}
        </Button>
        <SearchField value={query} onChange={setQuery} placeholder={tr("Search")} width="100%" />
      </Stack>
      {snippets.isPending ? (
        <Loading pt={4} />
      ) : snippets.error ? (
        <EmptyState
          compact
          title={tr("Could not load snippets")}
          description={errorMessage(snippets.error)}
        />
      ) : items.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ px: 0.5 }}>
          {q
            ? tr("Nothing matches “{query}”.", { query })
            : tr("No snippets yet — add them in the Snippets section.")}
        </Typography>
      ) : (
        <List dense disablePadding>
          {items.map((s) => (
            <ListItemButton
              key={s.id}
              disabled={!connected}
              onClick={() => trigger(s, "run")}
              onContextMenu={(e) => {
                e.preventDefault();
                setMenu({
                  snippet: s,
                  anchor: null,
                  position: { left: e.clientX, top: e.clientY },
                });
              }}
              sx={{
                borderRadius: 1.5,
                alignItems: "flex-start",
                gap: 0.5,
                pr: 0.5,
                "&:hover .snippet-more, &.Mui-focusVisible .snippet-more": { opacity: 1 },
              }}
            >
              <ListItemText
                primary={s.label}
                secondary={
                  <Mono secondary sx={{ fontSize: 11, display: "block" }}>
                    {firstLine(s.script)}
                  </Mono>
                }
                slotProps={{
                  primary: { variant: "body2", noWrap: true, sx: { fontWeight: 600 } },
                  secondary: { component: "div", noWrap: true },
                }}
              />
              {s.targetHostIds.length > 0 && (
                <Tooltip
                  title={tr("{length} configured targets", { length: s.targetHostIds.length })}
                >
                  <Chip
                    size="small"
                    variant="outlined"
                    icon={<DnsRoundedIcon />}
                    label={s.targetHostIds.length}
                    sx={{ mt: 0.25, height: 20, "& .MuiChip-label": { px: 0.5 } }}
                  />
                </Tooltip>
              )}
              <IconButton
                className="snippet-more"
                size="small"
                aria-label={tr("Snippet actions")}
                onClick={(e) => {
                  e.stopPropagation();
                  setMenu({ snippet: s, anchor: e.currentTarget, position: null });
                }}
                sx={{ opacity: 0, transition: "opacity 120ms", mt: -0.25 }}
              >
                <MoreVertRoundedIcon fontSize="small" />
              </IconButton>
            </ListItemButton>
          ))}
        </List>
      )}
      {!connected && (
        <Typography variant="caption" color="text.secondary" sx={{ px: 0.5 }}>
          {tr("Snippets run once the terminal is connected. Right-click for more actions.")}
        </Typography>
      )}
      {run && (
        <Box
          sx={{
            p: 1.25,
            borderRadius: 2,
            bgcolor: "surface.high",
            display: "flex",
            flexDirection: "column",
            gap: 0.75,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography variant="body2" noWrap sx={{ fontWeight: 600 }}>
                {run.label}
              </Typography>
              <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
                {summarize(run)}
              </Typography>
            </Box>
            <IconButton size="small" aria-label={tr("Dismiss")} onClick={() => setRunId(null)}>
              <CloseRoundedIcon sx={{ fontSize: 16 }} />
            </IconButton>
          </Box>
          <RunTargets run={run} dense />
        </Box>
      )}
      {menu && (
        <ActionMenu
          anchor={menu.anchor}
          position={menu.position}
          onClose={() => setMenu(null)}
          items={menuItems(menu.snippet)}
        />
      )}
      {pending && (
        <VariablesDialog
          snippet={pending.snippet}
          description={tr(ACTION_LABEL[pending.action])}
          onCancel={() => setPending(null)}
          onConfirm={(vars) => {
            execute(pending.snippet, pending.action, vars);
            setPending(null);
          }}
        />
      )}
      {remove && (
        <ConfirmDialog
          open
          title={tr("Delete snippet?")}
          confirmLabel={tr("Delete")}
          danger
          busy={del.isPending}
          onCancel={() => setRemove(null)}
          onConfirm={() => del.mutate(remove.id)}
        >
          {trx("{snippet} will be removed, including its targets and host bindings.", {
            snippet: <b>{remove.label}</b>,
          })}
        </ConfirmDialog>
      )}
    </Stack>
  );
}

function firstLine(script: string): string {
  return (
    script
      .split("\n")
      .find((l) => l.trim().length > 0)
      ?.trim() ?? ""
  );
}

/* -------------------------------------------------------------- history */

function HistoryPanel({ pane }: { pane: Pane }) {
  const [mode, setMode] = useState<"commands" | "connections">("commands");
  const [query, setQuery] = useState("");
  const [thisHost, setThisHost] = useState(true);
  const filterHost = thisHost && pane.hostId !== null;
  const connected = pane.status === "connected";
  return (
    <Stack sx={{ p: 1.5, gap: 1.5 }}>
      <ToggleButtonGroup
        exclusive
        fullWidth
        size="small"
        value={mode}
        onChange={(_, v: "commands" | "connections" | null) => v && setMode(v)}
      >
        <ToggleButton value="commands">{tr("Commands")}</ToggleButton>
        <ToggleButton value="connections">{tr("Connections")}</ToggleButton>
      </ToggleButtonGroup>
      <SearchField
        value={query}
        onChange={setQuery}
        placeholder={mode === "commands" ? tr("Search commands") : tr("Search connections")}
        width={SIDE_PANEL_WIDTH - 24}
      />
      {mode === "commands" ? (
        <CommandHistoryList
          query={query}
          host={filterHost && pane.hostId ? { kind: "host", id: pane.hostId } : ALL_HOSTS}
          onRun={connected ? (cmd) => runCommand(pane.id, cmd) : undefined}
          emptyHint={filterHost ? tr("No commands recorded on this host yet.") : undefined}
          leading={
            <Chip
              size="small"
              variant={filterHost ? "filled" : "outlined"}
              color={filterHost ? "primary" : "default"}
              label={pane.hostId ? tr("This host") : tr("All hosts")}
              disabled={pane.hostId === null}
              onClick={() => setThisHost((v) => !v)}
            />
          }
        />
      ) : (
        <ConnectionHistoryList query={query} />
      )}
    </Stack>
  );
}

/* --------------------------------------------------------------- themes */

const TEXT_SIZE_MIN = 8;
const TEXT_SIZE_MAX = 40;

/** Termius layout: Font, Text Size (− value +), then the theme list. */
function ThemesPanel({ tab, pane }: { tab: TerminalTab; pane: Pane }) {
  const settings = useSettings();
  const save = useSaveSettings();
  const snackbar = useSnackbar();
  const [filter, setFilter] = useState<"all" | "dark" | "light">("all");
  const s = settings.data;
  const updateText = (patch: { terminalFontFamily?: string; terminalFontSize?: number }) => {
    if (!s) return;
    save.mutate({ ...s, ...patch }, { onError: (e) => snackbar.error(errorMessage(e)) });
  };
  const size = s?.terminalFontSize ?? 14;
  const custom = useCustomThemes();
  const list = useMemo(
    () => allTerminalThemes().filter((t) => filter === "all" || (filter === "dark") === t.dark),
    // `custom` only re-runs the memo; `allTerminalThemes` already includes it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [filter, custom],
  );
  const inherited = pane.hostTheme ?? settings.data?.terminalTheme ?? AUTO_THEME;
  const inheritedName =
    inherited === AUTO_THEME
      ? tr("Auto (follows app theme)")
      : (terminalThemeById(inherited)?.name ?? inherited);
  const current = tab.themeOverride ?? inherited;

  return (
    <Stack sx={{ p: 1.5, gap: 1.5 }}>
      <Stack sx={{ gap: 1 }}>
        <Typography variant="subtitle2" sx={{ color: "primary.main", px: 0.5 }}>
          {tr("Font")}
        </Typography>
        <FontPicker
          value={s?.terminalFontFamily ?? ""}
          onChange={(name) => updateText({ terminalFontFamily: name })}
          fullWidth
        />
        <Stack direction="row" sx={{ alignItems: "center", gap: 0.5, px: 0.5 }}>
          <Typography variant="body2" sx={{ flex: 1 }}>
            {tr("Text Size")}
          </Typography>
          <IconButton
            size="small"
            aria-label={tr("Smaller text")}
            disabled={!s || size <= TEXT_SIZE_MIN}
            onClick={() => updateText({ terminalFontSize: size - 1 })}
            sx={{ width: 32, height: 32, borderRadius: 1.5, bgcolor: "surface.highest" }}
          >
            <RemoveRoundedIcon sx={{ fontSize: 18 }} />
          </IconButton>
          <Box
            sx={{
              width: 44,
              height: 32,
              borderRadius: 1.5,
              bgcolor: "surface.highest",
              display: "grid",
              placeItems: "center",
              fontSize: 13,
              fontVariantNumeric: "tabular-nums",
            }}
            aria-label={tr("Text size")}
          >
            {size}
          </Box>
          <IconButton
            size="small"
            aria-label={tr("Larger text")}
            disabled={!s || size >= TEXT_SIZE_MAX}
            onClick={() => updateText({ terminalFontSize: size + 1 })}
            sx={{ width: 32, height: 32, borderRadius: 1.5, bgcolor: "surface.highest" }}
          >
            <AddRoundedIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Stack>
      </Stack>
      <Divider />
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 1 }}>
        <Typography variant="subtitle2" sx={{ px: 0.5 }}>
          {tr("Themes")}
        </Typography>
        <ToggleButtonGroup
          exclusive
          size="small"
          value={filter}
          onChange={(_, v: "all" | "dark" | "light" | null) => v && setFilter(v)}
        >
          <ToggleButton value="all">{tr("All")}</ToggleButton>
          <ToggleButton value="dark">{tr("Dark")}</ToggleButton>
          <ToggleButton value="light">{tr("Light")}</ToggleButton>
        </ToggleButtonGroup>
        <Button
          size="small"
          color="inherit"
          disabled={tab.themeOverride === null}
          onClick={() => setTabTheme(tab.id, null)}
        >
          {tr("Reset")}
        </Button>
      </Stack>
      <Typography variant="caption" color="text.secondary" sx={{ px: 0.5 }}>
        {trx(
          pane.hostTheme
            ? "Applies to this tab only. Default for this session: {theme} (from host)."
            : "Applies to this tab only. Default for this session: {theme}.",
          {
            theme: (
              <Box component="span" sx={{ color: "text.primary" }}>
                {inheritedName}
              </Box>
            ),
          },
        )}
      </Typography>
      <Stack spacing={0.25} sx={{ mx: -0.75 }}>
        {list.map((t) => (
          <ThemeCard
            key={t.id}
            theme={t}
            label={t.name}
            compact
            selected={current === t.id}
            onClick={() => setTabTheme(tab.id, t.id)}
          />
        ))}
      </Stack>
    </Stack>
  );
}

/* ----------------------------------------------------------------- info */

function InfoPanel({ pane, tab }: { pane: Pane; tab: TerminalTab }) {
  const a = pane.algorithms;
  const rows: [string, React.ReactNode][] = [
    [tr("Name"), pane.title],
    [tr("Target"), <Mono key="t">{pane.subtitle || "—"}</Mono>],
    [tr("Protocol"), pane.protocol ? pane.protocol.toUpperCase() : "—"],
    [tr("State"), <StateChip key="s" status={pane.status} message={pane.message} />],
    [tr("Started"), pane.startedAt ? new Date(pane.startedAt).toLocaleString() : "—"],
  ];
  if (pane.via.length > 0) {
    rows.push([tr("Via"), <Mono key="v">{pane.via.join(" → ")}</Mono>]);
  }
  if (tab.paneIds.length > 1) {
    rows.push([tr("Panes in tab"), String(tab.paneIds.length)]);
  }
  rows.push([tr("Zoom"), `${Math.round(tab.zoom * 100)}%`]);

  const shellRows: [string, React.ReactNode][] = [
    [tr("Shell"), pane.shell ? <Mono key="sh">{pane.shell}</Mono> : tr("unknown")],
    [
      tr("Integration"),
      pane.integration ? (
        <Chip
          key="i"
          size="small"
          color="success"
          variant="outlined"
          label={tr("active")}
          sx={{ height: 20 }}
        />
      ) : pane.shell && ["bash", "zsh", "fish"].includes(pane.shell) ? (
        tr("waiting for prompt")
      ) : (
        tr("not available")
      ),
    ],
    [tr("Directory"), pane.cwd ? <Mono key="cwd">{pane.cwd}</Mono> : "—"],
    [tr("Last exit"), pane.lastExit === null ? "—" : String(pane.lastExit)],
    [tr("Suggestions"), suggestionsState(pane)],
  ];

  return (
    <Stack sx={{ p: 1.5, gap: 1.5 }}>
      <Section title={tr("Session")}>
        {rows.map(([k, v]) => (
          <Row key={k} label={k} value={v} />
        ))}
      </Section>
      <Section title={tr("Shell")}>
        {shellRows.map(([k, v]) => (
          <Row key={k} label={k} value={v} />
        ))}
      </Section>
      {a && (
        <Section
          title={tr("Encryption")}
          action={
            isPostQuantumKex(a) ? (
              <Chip size="small" color="primary" variant="outlined" label={tr("Quantum-safe")} />
            ) : null
          }
        >
          <Row label={tr("Key exchange")} value={<Mono>{a.kex}</Mono>} />
          <Row label={tr("Host key")} value={<Mono>{a.hostKey}</Mono>} />
          <Row label={tr("Cipher")} value={<Mono>{a.cipher}</Mono>} />
          <Row label="MAC" value={<Mono>{a.mac}</Mono>} />
        </Section>
      )}
      <Typography variant="caption" color="text.secondary" sx={{ px: 0.5 }}>
        {tr("Credentials and keys are never shown here.")}
      </Typography>
    </Stack>
  );
}

function suggestionsState(pane: Pane): string {
  if (!pane.autocomplete) return tr("off for this session");
  return autocompleteOn(pane.id) ? tr("on") : tr("paused");
}

function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Box sx={{ bgcolor: "surface.highest", borderRadius: 2, p: 1.5 }}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 1 }}>
        <Typography variant="subtitle2">{title}</Typography>
        {action}
      </Stack>
      <Stack divider={<Divider flexItem />} spacing={0.75}>
        {children}
      </Stack>
    </Box>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Stack direction="row" sx={{ gap: 1, alignItems: "baseline", py: 0.25 }}>
      <Typography variant="caption" color="text.secondary" sx={{ width: 92, flexShrink: 0 }}>
        {label}
      </Typography>
      <Typography
        variant="body2"
        component="div"
        sx={{ flex: 1, minWidth: 0, overflowWrap: "anywhere", fontSize: 12.5 }}
      >
        {value}
      </Typography>
    </Stack>
  );
}

function StateChip({ status, message }: { status: Pane["status"]; message: string | null }) {
  const color =
    status === "connected"
      ? "success"
      : status === "connecting"
        ? "warning"
        : status === "error"
          ? "error"
          : "default";
  return (
    <Tooltip title={message ?? ""}>
      <Chip size="small" color={color} variant="outlined" label={status} sx={{ height: 20 }} />
    </Tooltip>
  );
}
