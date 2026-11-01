import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type MouseEvent,
  type ReactElement,
} from "react";
import { copyToClipboard } from "@/lib/clipboard";
import {
  Box,
  Breadcrumbs,
  Button,
  Chip,
  IconButton,
  InputAdornment,
  Link,
  Menu,
  MenuItem,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import GridViewRoundedIcon from "@mui/icons-material/GridViewRounded";
import ViewListRoundedIcon from "@mui/icons-material/ViewListRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import CreateNewFolderRoundedIcon from "@mui/icons-material/CreateNewFolderRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import VpnKeyOutlinedIcon from "@mui/icons-material/VpnKeyOutlined";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import SellOutlinedIcon from "@mui/icons-material/SellOutlined";
import SwapVertRoundedIcon from "@mui/icons-material/SwapVertRounded";
import FolderCopyRoundedIcon from "@mui/icons-material/FolderCopyRounded";
import CloudRoundedIcon from "@mui/icons-material/CloudRounded";
import FolderOpenRoundedIcon from "@mui/icons-material/FolderOpenRounded";
import EditOutlinedIcon from "@mui/icons-material/EditOutlined";
import MoreHorizRoundedIcon from "@mui/icons-material/MoreHorizRounded";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import TabRoundedIcon from "@mui/icons-material/TabRounded";
import AddBoxOutlinedIcon from "@mui/icons-material/AddBoxOutlined";
import DriveFileMoveOutlinedIcon from "@mui/icons-material/DriveFileMoveOutlined";
import LibraryAddOutlinedIcon from "@mui/icons-material/LibraryAddOutlined";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import SelectAllRoundedIcon from "@mui/icons-material/SelectAllRounded";
import FileDownloadOutlinedIcon from "@mui/icons-material/FileDownloadOutlined";
import FileUploadOutlinedIcon from "@mui/icons-material/FileUploadOutlined";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import SwapHorizRoundedIcon from "@mui/icons-material/SwapHorizRounded";
import UsbRoundedIcon from "@mui/icons-material/UsbRounded";
import CloudOutlinedIcon from "@mui/icons-material/CloudOutlined";
import HubOutlinedIcon from "@mui/icons-material/HubOutlined";
import LanOutlinedIcon from "@mui/icons-material/LanOutlined";
import { EmptyState } from "@/components/EmptyState";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import * as ipc from "@/ipc/commands";
import { useSnackbar } from "@/components/Snackbar";
import {
  ActionMenu,
  Loading,
  SplitButton,
  ToolIconButton,
  Toolbar,
  type MenuAction,
  useNarrowWindow,
} from "@/components/ui";
import {
  useDeleteHosts,
  useCloudSyncGroups,
  useDuplicateGroup,
  useDuplicateHost,
  useGroups,
  useHosts,
  useKnownHosts,
  useCopyHostsToVault,
  useMoveHosts,
  useSaveSettings,
  useSettings,
  useTags,
  useSshKeys,
} from "@/ipc/hooks";
import { useActiveVault, vaultIcon, ViewOnlyChip } from "@/app/vault";
import type { CloudProvider, GroupNode, HostCard, HostsView, Uuid } from "@/ipc/types";
import { connectProtocols, errorMessage, hasSsh, hasWebDav, hostProtocols } from "@/ipc/types";
import { openTerminal, useTerminal } from "@/terminal/store";
import { addToWorkspace, useWorkspaces, workspaceChoices } from "@/terminal/workspaces";
import { openSftpForHost, openWebDavForHost } from "@/sftp/store";
import {
  goToSerial,
  goToSettingsWith,
  goToSftp,
  requestForwardingRule,
  useCreateRequests,
  useEditRequests,
  useOpenFileRequests,
} from "@/app/navigation";
import { isSshConfigFile } from "@/app/deepLinks";
import { HostGrid, hostTarget } from "./HostGrid";
import { HostList } from "./HostList";
import { useVaultPresence } from "./PresenceViews";
import { HostEditPanel } from "./HostEditPanel";
import { DeleteGroupDialog, GroupPanel } from "./GroupPanel";
import { MoveCopyDialog, type MoveCopyRequest } from "./MoveCopyDialog";
import { AddKeyToHostDialog } from "@/keychain/KeyDialogs";
import { ImportDialog } from "./ImportDialog";
import { CLOUD_PROVIDERS, CloudImportDialog } from "./CloudImportDialog";
import { LanDiscoveryDialog } from "./LanDiscoveryDialog";
import { TailnetImportDialog } from "./TailnetImportDialog";
import { ExportCsvDialog } from "./ExportCsvDialog";
import { TagManagerDialog } from "./TagManagerDialog";
import { TagsPopover } from "./TagsPopover";
import { TeamSteps } from "@/team/TeamSteps";
import { TagChip, tagColorMap } from "./TagChip";
import { connectActions } from "./ConnectSplit";
import { useHostDnd } from "./dnd";
import { IS_MAC } from "@/lib/platform";
import {
  hostLink,
  looksLikeTarget,
  parseKnownHostName,
  isLiveLink,
  parseQuickConnect,
  protocolLink,
  quickLabel,
  type KnownSuggestion,
} from "./links";
import { focusFirstHostItem } from "./keyboardNav";
import { tr, trn, msg } from "@/i18n";

type Panel =
  | { mode: "closed" }
  | { mode: "new"; groupId: Uuid | null }
  | { mode: "edit"; id: Uuid }
  | { mode: "group"; id: Uuid | null; parentId: Uuid | null };

type SortKey = "manual" | "label" | "address" | "updated" | "lastConnected";

const comparators: Record<SortKey, (a: HostCard, b: HostCard) => number> = {
  manual: (a, b) => a.sortOrder - b.sortOrder || a.label.localeCompare(b.label),
  label: (a, b) => a.label.localeCompare(b.label),
  address: (a, b) => a.address.localeCompare(b.address),
  updated: (a, b) => b.updatedAt.localeCompare(a.updatedAt),
  lastConnected: (a, b) => {
    if (a.lastConnected && b.lastConnected) {
      return b.lastConnected.localeCompare(a.lastConnected) || a.label.localeCompare(b.label);
    }
    if (a.lastConnected) return -1;
    if (b.lastConnected) return 1;
    return a.label.localeCompare(b.label);
  },
};

const sortLabel: Record<SortKey, string> = {
  manual: msg("Manual"),
  label: msg("Name"),
  address: msg("Address"),
  updated: msg("Recently edited"),
  lastConnected: msg("Recently connected"),
};

type Ctx =
  | { kind: "host"; host: HostCard; left: number; top: number }
  | { kind: "group"; group: GroupNode; left: number; top: number };

const isEditable = (t: EventTarget | null) =>
  t instanceof HTMLElement &&
  (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);

export function HostsPage() {
  const snackbar = useSnackbar();
  const terminalTabs = useTerminal((s) => s.tabs);
  const templates = useWorkspaces((s) => s.templates);
  const workspaces = useMemo(
    () => workspaceChoices(terminalTabs, templates),
    [terminalTabs, templates],
  );
  const vault = useActiveVault();
  const vaultId = vault.data?.id ?? null;
  const readOnly = vault.readOnly;
  const hosts = useHosts(vaultId);
  const groups = useGroups(vaultId);
  const tags = useTags(vaultId);
  const presence = useVaultPresence(vaultId);
  const cloudSyncGroups = useCloudSyncGroups(vaultId);
  const cloudSynced = useMemo(
    () => new Set((cloudSyncGroups.data ?? []).map((g) => g.groupId)),
    [cloudSyncGroups.data],
  );
  const settings = useSettings();
  const saveSettings = useSaveSettings();
  const deleteHosts = useDeleteHosts();
  const duplicateHost = useDuplicateHost();
  const duplicateGroup = useDuplicateGroup();
  const moveHosts = useMoveHosts();
  const copyToVault = useCopyHostsToVault();

  const [groupId, setGroupId] = useState<Uuid | null>(null);
  const [search, setSearch] = useState("");
  /** Search only inside the open group (Termius default) or across the vault. */
  const [searchEverywhere, setSearchEverywhere] = useState(false);
  const [tagsOpen, setTagsOpen] = useState(false);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [sort, setSort] = useState<SortKey>("manual");
  const [panel, setPanel] = useState<Panel>({ mode: "closed" });
  const [tagAnchor, setTagAnchor] = useState<HTMLElement | null>(null);
  const [sortAnchor, setSortAnchor] = useState<HTMLElement | null>(null);
  const [copyAnchor, setCopyAnchor] = useState<HTMLElement | null>(null);
  const [ctx, setCtx] = useState<Ctx | null>(null);
  const [checked, setChecked] = useState<ReadonlySet<Uuid>>(() => new Set());
  const [anchorId, setAnchorId] = useState<Uuid | null>(null);
  const [moveCopy, setMoveCopy] = useState<MoveCopyRequest | null>(null);
  const [addKeyHost, setAddKeyHost] = useState<HostCard | null>(null);
  const [addKeyBusy, setAddKeyBusy] = useState(false);
  const sshKeys = useSshKeys(vaultId);
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<string | null>(null);
  useOpenFileRequests(isSshConfigFile, (path) => {
    setImportFile(path);
    setImportOpen(true);
  });
  const [cloudProvider, setCloudProvider] = useState<CloudProvider | null>(null);
  const [lanOpen, setLanOpen] = useState(false);
  const [tailnetOpen, setTailnetOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState<HostCard[] | null>(null);
  const [confirmGroup, setConfirmGroup] = useState<GroupNode | null>(null);

  const view: HostsView = settings.data?.hostsView ?? "grid";
  const setView = (v: HostsView | null) => {
    if (!v || !settings.data) return;
    saveSettings.mutate(
      { ...settings.data, hostsView: v },
      { onError: (e) => snackbar.error(errorMessage(e)) },
    );
  };

  const groupById = useMemo(
    () => new Map((groups.data ?? []).map((g) => [g.id, g])),
    [groups.data],
  );
  const crumbs = useMemo(() => {
    const out: GroupNode[] = [];
    let cur = groupId ? groupById.get(groupId) : undefined;
    while (cur) {
      out.unshift(cur);
      cur = cur.parentId ? groupById.get(cur.parentId) : undefined;
    }
    return out;
  }, [groupId, groupById]);

  const tagColors = useMemo(() => tagColorMap(tags.data), [tags.data]);
  const tagFilterIds = useMemo(
    () =>
      new Set(
        (tags.data ?? []).filter((t) => tagFilter.includes(t.label)).map((t) => t.id),
      ) as ReadonlySet<Uuid>,
    [tags.data, tagFilter],
  );

  const q = search.trim().toLowerCase();
  const filtering = q.length > 0 || tagFilter.length > 0;
  /** The open group and everything nested under it. */
  const subtree = useMemo(() => {
    if (!groupId) return null;
    const ids = new Set<Uuid>([groupId]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const g of groups.data ?? []) {
        if (g.parentId && ids.has(g.parentId) && !ids.has(g.id)) {
          ids.add(g.id);
          grew = true;
        }
      }
    }
    return ids;
  }, [groups.data, groupId]);
  const scope = filtering && !searchEverywhere ? subtree : null;
  const scopedToGroup = scope !== null;
  const childGroups = useMemo(
    () =>
      filtering
        ? []
        : (groups.data ?? [])
            .filter((g) => g.parentId === groupId)
            .sort((a, b) => a.sortOrder - b.sortOrder || a.label.localeCompare(b.label)),
    [groups.data, groupId, filtering],
  );
  const visibleHosts = useMemo(() => {
    const all = hosts.data ?? [];
    let scoped = filtering
      ? scope
        ? all.filter((h) => h.groupId !== null && scope.has(h.groupId))
        : all
      : all.filter((h) => h.groupId === groupId);
    if (q) {
      scoped = scoped.filter((h) =>
        [h.label, h.address, h.username, hostTarget(h), ...h.tags, ...h.groupPath].some((s) =>
          s.toLowerCase().includes(q),
        ),
      );
    }
    if (tagFilter.length) scoped = scoped.filter((h) => tagFilter.every((t) => h.tags.includes(t)));
    return [...scoped].sort(comparators[sort]);
  }, [hosts.data, groupId, q, tagFilter, filtering, sort, scope]);

  /* ------------------------------------------------------------ selection */

  // Only hosts currently on screen count as selected, so bulk actions never hit stale ids.
  const selectedHosts = useMemo(
    () => visibleHosts.filter((h) => checked.has(h.id)),
    [visibleHosts, checked],
  );
  const visibleChecked = useMemo(
    () => new Set(selectedHosts.map((h) => h.id)) as ReadonlySet<Uuid>,
    [selectedHosts],
  );

  const clearSelection = () => setChecked(new Set());
  const toggleHost = (h: HostCard) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(h.id)) next.delete(h.id);
      else next.add(h.id);
      return next;
    });
    setAnchorId(h.id);
  };
  const selectRange = (h: HostCard) => {
    const ids = visibleHosts.map((x) => x.id);
    const from = anchorId ? ids.indexOf(anchorId) : -1;
    const to = ids.indexOf(h.id);
    if (from < 0 || to < 0) return toggleHost(h);
    const [a, b] = from < to ? [from, to] : [to, from];
    setChecked((prev) => new Set([...prev, ...ids.slice(a, b + 1)]));
  };
  const selectAll = () => {
    setChecked(new Set(visibleHosts.map((h) => h.id)));
  };
  const updateSearch = (s: string) => {
    setSearch(s);
    if (visibleChecked.size > 0) clearSelection();
  };
  const updateTagFilter = (fn: (f: string[]) => string[]) => {
    setTagFilter(fn);
    if (visibleChecked.size > 0) clearSelection();
  };

  useCreateRequests(["host", "group"], (kind) => {
    if (kind === "host") setPanel({ mode: "new", groupId });
    else setPanel({ mode: "group", id: null, parentId: groupId });
  });
  useEditRequests((id) => setPanel({ mode: "edit", id }));

  const parentId = crumbs.length > 0 ? (crumbs[crumbs.length - 1]?.parentId ?? null) : null;
  const goBack = useCallback(() => {
    if (!groupId) return;
    setChecked(new Set());
    setGroupId(parentId);
  }, [groupId, parentId]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isEditable(e.target)) return;
      if (e.key === "Escape" && visibleChecked.size > 0) {
        clearSelection();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a" && visibleHosts.length) {
        e.preventDefault();
        setChecked(new Set(visibleHosts.map((h) => h.id)));
      } else if (
        groupId &&
        !filtering &&
        (e.key === "Backspace" || (e.altKey && e.key === "ArrowLeft"))
      ) {
        e.preventDefault();
        goBack();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [visibleChecked.size, visibleHosts, groupId, filtering, goBack]);

  /* ------------------------------------------------------------ drag & drop */

  const onDropMove = useCallback(
    (ids: Uuid[], target: Uuid | null) => {
      if (!vaultId || readOnly) return;
      const dest = target ? (groupById.get(target)?.label ?? tr("group")) : tr("All hosts");
      moveHosts.mutate(
        { ids, groupId: target, vaultId },
        {
          onSuccess: () => {
            snackbar.notify(
              ids.length === 1
                ? tr("Moved to {dest}", { dest })
                : tr("Moved {length} hosts to {dest}", { length: ids.length, dest }),
            );
            setChecked(new Set());
          },
          onError: (e) => snackbar.error(errorMessage(e)),
        },
      );
    },
    [vaultId, readOnly, groupById, moveHosts, snackbar],
  );
  const dnd = useHostDnd({
    selection: visibleChecked,
    hosts: hosts.data ?? [],
    onMove: onDropMove,
  });

  /* -------------------------------------------------------------- actions */

  const openHost = (h: HostCard, e?: MouseEvent<HTMLElement>) => {
    if (e && (e.ctrlKey || e.metaKey)) return toggleHost(h);
    if (e?.shiftKey) return selectRange(h);
    if (visibleChecked.size > 0) return toggleHost(h);
    setPanel({ mode: "edit", id: h.id });
  };
  /** Terminal for hosts that have one; a WebDAV-only host opens its share in Files. */
  const connectHosts = (list: HostCard[], background = false) => {
    const terminal = list.filter((h) => hostProtocols(h).length > 0);
    terminal.forEach((h, i) =>
      openTerminal(
        { kind: "host", host_id: h.id, vault_id: h.vaultId },
        { background: background || i > 0 },
      ),
    );
    const files = list.filter((h) => hostProtocols(h).length === 0 && hasWebDav(h));
    files.forEach((h) => openWebDavForHost(h.id, h.label, h.vaultId));
    if (files.length > 0 && terminal.length === 0) goToSftp();
  };
  const connectHost = (h: HostCard) => connectHosts([h]);
  /** Workspace tabs are terminals, so WebDAV-only hosts are left out. */
  const hostTargets = (list: HostCard[]) =>
    list
      .filter((h) => hostProtocols(h).length > 0)
      .map((h) => ({ kind: "host" as const, host_id: h.id, vault_id: h.vaultId }));
  const sftpHost = (h: HostCard) => {
    openSftpForHost(h.id, h.label, h.vaultId);
    goToSftp();
  };
  const webdavHost = (h: HostCard) => {
    openWebDavForHost(h.id, h.label, h.vaultId);
    goToSftp();
  };
  const liveLink = isLiveLink(search) ? search.trim() : null;
  const quickTarget =
    !liveLink && looksLikeTarget(search.trim()) ? parseQuickConnect(search) : null;
  const knownHosts = useKnownHosts();
  /** Hosts we already trust (known_hosts) but haven't saved, matching the typed address. */
  const knownSuggestions = useMemo(() => {
    if (!quickTarget || quickTarget.address.length < 2) return [];
    const typed = quickTarget.address.toLowerCase();
    const saved = new Set((hosts.data ?? []).map((h) => `${h.address.toLowerCase()}:${h.port}`));
    const seen = new Set<string>();
    const out: KnownSuggestion[] = [];
    for (const k of knownHosts.data ?? []) {
      const s = parseKnownHostName(k.hostname);
      const name = s.address.toLowerCase();
      const key = `${name}:${s.port ?? 22}`;
      const exact = name === typed && (s.port ?? 22) === (quickTarget.port ?? 22);
      if (exact || !name.includes(typed) || saved.has(key) || seen.has(key)) continue;
      seen.add(key);
      out.push(s);
      if (out.length === 6) break;
    }
    return out;
  }, [quickTarget, hosts.data, knownHosts.data]);
  const connectKnown = (s: KnownSuggestion) => {
    if (!quickTarget) return;
    openTerminal({ ...quickTarget, address: s.address, port: s.port ?? quickTarget.port });
    setSearch("");
  };
  const onSearchEnter = () => {
    if (liveLink) {
      openTerminal({ kind: "live", link: liveLink });
      setSearch("");
      return;
    }
    if (visibleHosts.length === 1 && visibleHosts[0]) {
      connectHost(visibleHosts[0]);
      setSearch("");
      return;
    }
    if (quickTarget) {
      openTerminal(quickTarget);
      setSearch("");
    }
  };
  const removeHosts = (list: HostCard[]) => {
    if (!vaultId || list.length === 0) return;
    deleteHosts.mutate(
      { ids: list.map((h) => h.id), vaultId },
      {
        onSuccess: () => {
          snackbar.notify(
            list.length === 1
              ? `Removed ${list[0]?.label ?? "host"}`
              : tr("Removed {length} hosts", { length: list.length }),
            "info",
          );
          if (panel.mode === "edit" && list.some((h) => h.id === panel.id)) {
            setPanel({ mode: "closed" });
          }
          clearSelection();
          setConfirmRemove(null);
        },
        onError: (e) => snackbar.error(errorMessage(e)),
      },
    );
  };
  const duplicateHosts = async (list: HostCard[]) => {
    try {
      for (const h of list) await duplicateHost.mutateAsync(h.id);
      snackbar.notify(
        list.length === 1
          ? `Duplicated ${list[0]?.label ?? "host"}`
          : tr("Duplicated {length} hosts", { length: list.length }),
      );
      clearSelection();
    } catch (e) {
      snackbar.error(errorMessage(e));
    }
  };
  const copyText = (text: string, what: string) =>
    copyToClipboard(text)
      .then(() => snackbar.notify(tr("{what} copied", { what })))
      .catch(() => snackbar.error(tr("Clipboard is not available")));
  const copyLinks = (list: HostCard[]) =>
    copyText(list.map(hostLink).join("\n"), list.length === 1 ? tr("Link") : tr("Links"));
  const copyProtocolLinks = (list: HostCard[]) => {
    const links = list.flatMap((h) => {
      const l = protocolLink(h);
      return l ? [l] : [];
    });
    if (links.length === 0) return;
    void copyText(links.join("\n"), links.length === 1 ? tr("Link") : tr("Links"));
  };

  const onHostContext = (h: HostCard, e: MouseEvent<HTMLElement>) => {
    e.preventDefault();
    setCtx({ kind: "host", host: h, left: e.clientX, top: e.clientY });
  };
  const onGroupContext = (g: GroupNode, e: MouseEvent<HTMLElement>) => {
    e.preventDefault();
    setCtx({ kind: "group", group: g, left: e.clientX, top: e.clientY });
  };
  const openGroupPanel = (g: GroupNode) =>
    setPanel({ mode: "group", id: g.id, parentId: g.parentId });
  const onDuplicateGroup = (g: GroupNode) =>
    duplicateGroup.mutate(g.id, {
      onSuccess: (copy) => snackbar.notify(tr("Duplicated as “{label}”", { label: copy.label })),
      onError: (e) => snackbar.error(errorMessage(e)),
    });

  /** Context-menu targets: the whole selection when the clicked host is part of it. */
  const ctxTargets = (h: HostCard) =>
    visibleChecked.has(h.id) && visibleChecked.size > 1 ? selectedHosts : [h];

  const hostMenu = (h: HostCard): MenuAction[] => {
    const targets = ctxTargets(h);
    const many = targets.length > 1;
    const n = targets.length;
    const terminalTargets = hostTargets(targets).length;
    return [
      many
        ? {
            label: tr("Connect {n} hosts", { n }),
            icon: <PlayArrowRoundedIcon fontSize="small" />,
            onClick: () => connectHosts(targets),
          }
        : {
            label: tr("Connect"),
            icon: <PlayArrowRoundedIcon fontSize="small" />,
            items: connectActions(h, connectProtocols(h), hasWebDav(h)),
          },
      ...(hasWebDav(h) && !hasSsh(h)
        ? []
        : [
            {
              label: tr("Open SFTP"),
              icon: <FolderCopyRoundedIcon fontSize="small" />,
              onClick: () => sftpHost(h),
              disabled: many || !hasSsh(h),
            },
          ]),
      ...(hasWebDav(h)
        ? [
            {
              label: tr("Open WebDAV"),
              icon: <CloudRoundedIcon fontSize="small" />,
              onClick: () => webdavHost(h),
              disabled: many,
            },
          ]
        : []),
      ...(terminalTargets > 0
        ? [
            {
              label: tr("Add to Workspace"),
              icon: <TabRoundedIcon fontSize="small" />,
              divider: true,
              items: [
                {
                  label: tr("New Workspace"),
                  icon: <AddBoxOutlinedIcon fontSize="small" />,
                  divider: workspaces.length > 0,
                  onClick: () => addToWorkspace(null, hostTargets(targets)),
                },
                ...workspaces.map((w) => ({
                  label: w.name,
                  icon: <GridViewRoundedIcon fontSize="small" />,
                  onClick: () => {
                    addToWorkspace(w, hostTargets(targets), true);
                    snackbar.notify(
                      terminalTargets > 1
                        ? tr("{terminalTargets} hosts added to “{name}”", {
                            terminalTargets,
                            name: w.name,
                          })
                        : tr("Added to “{name}”", { name: w.name }),
                    );
                  },
                })),
              ],
            },
          ]
        : []),
      {
        label: tr("Edit"),
        icon: <EditOutlinedIcon fontSize="small" />,
        onClick: () => setPanel({ mode: "edit", id: h.id }),
        disabled: many,
      },
      {
        label: tr("Duplicate"),
        icon: <ContentCopyRoundedIcon fontSize="small" />,
        disabled: readOnly,
        onClick: () => void duplicateHosts(targets),
      },
      {
        label: tr("Move to…"),
        icon: <DriveFileMoveOutlinedIcon fontSize="small" />,
        disabled: readOnly,
        onClick: () => setMoveCopy({ kind: "group", hosts: targets }),
      },
      {
        label: tr("Copy to"),
        icon: <LibraryAddOutlinedIcon fontSize="small" />,
        items: copyToItems(targets),
        divider: true,
      },
      {
        label: tr("More"),
        icon: <MoreHorizRoundedIcon fontSize="small" />,
        divider: true,
        items: [
          {
            label: tr("Add SSH key to host…"),
            icon: <VpnKeyOutlinedIcon fontSize="small" />,
            onClick: () => setAddKeyHost(h),
            disabled: many || !hasSsh(h),
          },
          {
            label: tr("Port forwarding"),
            icon: <SwapHorizRoundedIcon fontSize="small" />,
            onClick: () => requestForwardingRule(h.id),
            disabled: many || !hasSsh(h),
          },
          {
            label: many ? tr("Copy links") : tr("Copy link"),
            icon: <LinkRoundedIcon fontSize="small" />,
            items: [
              {
                label: tr("Termoso link"),
                icon: <LinkRoundedIcon fontSize="small" />,
                onClick: () => void copyLinks(targets),
              },
              {
                label: targets.every((t) => !hostProtocols(t).includes("ssh"))
                  ? tr("telnet:// link")
                  : tr("ssh:// link"),
                icon: <TerminalRoundedIcon fontSize="small" />,
                onClick: () => copyProtocolLinks(targets),
              },
            ],
          },
          {
            label: tr("Copy address"),
            icon: <ContentCopyRoundedIcon fontSize="small" />,
            onClick: () => void copyText(targets.map((t) => t.address).join("\n"), "Address"),
          },
        ],
      },
      {
        label: many ? tr("Remove {n} hosts", { n }) : tr("Remove"),
        icon: <DeleteOutlineRoundedIcon fontSize="small" />,
        disabled: readOnly,
        onClick: () => setConfirmRemove(targets),
        danger: true,
      },
    ];
  };

  /** `Copy to ▸` — every other vault plus “Add vault”, like Termius. */
  const copyToItems = (targets: HostCard[]): MenuAction[] => [
    ...vault.vaults
      .filter((v) => v.id !== vaultId)
      .map((v) => ({
        label: v.name,
        icon: vaultIcon(v),
        disabled: !v.unlocked || v.role === "viewer",
        onClick: () => copyHostsTo(targets, v.id),
      })),
    {
      label: tr("Add vault"),
      icon: <AddRoundedIcon fontSize="small" />,
      divider: vault.vaults.length > 1,
      onClick: () => goToSettingsWith({ kind: "newVault" }),
    },
  ];

  const copyHostsTo = (targets: HostCard[], to: Uuid) => {
    const dest = vault.vaults.find((v) => v.id === to);
    if (!dest || !vaultId) return;
    if (dest.kind === "team") {
      setMoveCopy({ kind: "vault", hosts: targets, move: false, target: to });
      return;
    }
    const what =
      targets.length === 1
        ? `“${targets[0]?.label ?? ""}”`
        : trn(targets.length, "{count} host", "{count} hosts");
    copyToVault.mutate(
      { ids: targets.map((t) => t.id), vaultId: to, move: false, withCredentials: true },
      {
        onSuccess: () => snackbar.notify(tr("Copied {what} to {name}", { what, name: dest.name })),
        onError: (e) => snackbar.error(errorMessage(e)),
      },
    );
  };

  const groupMenu = (g: GroupNode): MenuAction[] => [
    {
      label: tr("Open"),
      icon: <FolderOpenRoundedIcon fontSize="small" />,
      onClick: () => setGroupId(g.id),
    },
    {
      label: tr("Group details"),
      icon: <EditOutlinedIcon fontSize="small" />,
      onClick: () => openGroupPanel(g),
      divider: true,
    },
    {
      label: tr("New host here"),
      icon: <DnsRoundedIcon fontSize="small" />,
      disabled: readOnly,
      onClick: () => setPanel({ mode: "new", groupId: g.id }),
    },
    {
      label: tr("New sub-group"),
      icon: <CreateNewFolderRoundedIcon fontSize="small" />,
      disabled: readOnly,
      onClick: () => setPanel({ mode: "group", id: null, parentId: g.id }),
      divider: true,
    },
    {
      label: tr("Duplicate"),
      icon: <ContentCopyRoundedIcon fontSize="small" />,
      disabled: readOnly,
      onClick: () => onDuplicateGroup(g),
      divider: true,
    },
    {
      label: tr("Remove"),
      icon: <DeleteOutlineRoundedIcon fontSize="small" />,
      disabled: readOnly,
      onClick: () => setConfirmGroup(g),
      danger: true,
    },
  ];

  const selectedId = panel.mode === "edit" ? panel.id : null;
  const loading = vault.isPending || hosts.isPending || groups.isPending;
  const loadError = vault.error ?? hosts.error ?? groups.error;
  const collection = {
    groups: childGroups,
    hosts: visibleHosts,
    selectedId,
    checked: visibleChecked,
    showPath: filtering,
    onOpenGroup: (id: Uuid) => {
      clearSelection();
      setGroupId(id);
    },
    onEditGroup: openGroupPanel,
    onGroupContext,
    onOpenHost: openHost,
    onToggleHost: toggleHost,
    onConnectHost: connectHost,
    onHostContext,
    dnd,
    tagColors,
    presence,
    cloudSynced,
  };

  const crumbSx = (active: boolean) => ({
    fontWeight: 600,
    fontSize: 14,
    px: 0.5,
    mx: -0.5,
    borderRadius: 1,
    outline: "1px solid transparent",
    ...(active && { outlineColor: "primary.main", bgcolor: "surface.strong" }),
  });

  /** Bulk-action bar replaces the breadcrumbs, except mid-drag so the crumbs stay droppable. */
  const selecting = visibleChecked.size > 0 && dnd.dragging.size === 0;
  const narrow = useNarrowWindow();

  return (
    <Box sx={{ display: "flex", flex: 1, minHeight: 0 }}>
      <Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
        <Stack direction="row" spacing={1} sx={{ px: 2, pt: 1.5, pb: 1, alignItems: "center" }}>
          <TextField
            placeholder={
              groupId
                ? tr("Search this group, or type user@host:port and press Enter to connect")
                : tr(
                    "Search hosts, or type user@host:port / ssh:// / telnet:// and press Enter to connect",
                  )
            }
            value={search}
            onChange={(e) => updateSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSearchEnter();
              if (e.key === "Escape") updateSearch("");
              if (e.key === "ArrowDown" && focusFirstHostItem()) e.preventDefault();
            }}
            sx={{ flex: 1 }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchRoundedIcon fontSize="small" />
                  </InputAdornment>
                ),
              },
            }}
          />
          <Tooltip
            title={
              liveLink
                ? tr("Join this multiplayer session")
                : quickTarget
                  ? tr("Connect to {quickLabel}", { quickLabel: quickLabel(quickTarget) })
                  : visibleHosts.length === 1 && search.trim() && visibleHosts[0]
                    ? tr("Connect to {label}", { label: visibleHosts[0].label })
                    : ""
            }
          >
            <span>
              <Button
                variant="contained"
                startIcon={<PlayArrowRoundedIcon />}
                disabled={
                  !quickTarget && !liveLink && !(visibleHosts.length === 1 && search.trim())
                }
                onClick={onSearchEnter}
                sx={{ flexShrink: 0, height: 36 }}
              >
                {tr("Connect")}
              </Button>
            </span>
          </Tooltip>
        </Stack>

        <Toolbar
          trailing={
            <>
              <ToggleButtonGroup
                exclusive
                value={view}
                onChange={(_e, v: HostsView | null) => setView(v)}
              >
                <ToggleButton value="grid" aria-label={tr("Grid view")}>
                  <GridViewRoundedIcon sx={{ fontSize: 18 }} />
                </ToggleButton>
                <ToggleButton value="list" aria-label={tr("List view")}>
                  <ViewListRoundedIcon sx={{ fontSize: 18 }} />
                </ToggleButton>
              </ToggleButtonGroup>
              <ToolIconButton
                title={tr("Filter by tag")}
                active={tagFilter.length > 0}
                onClick={(e) => setTagAnchor(e.currentTarget)}
              >
                <SellOutlinedIcon fontSize="small" />
              </ToolIconButton>
              <Button
                variant="text"
                size="small"
                startIcon={<SwapVertRoundedIcon />}
                onClick={(e) => setSortAnchor(e.currentTarget)}
                sx={{ color: "text.secondary" }}
              >
                {tr(sortLabel[sort])}
              </Button>
            </>
          }
        >
          <SplitButton
            label={tr("New host")}
            icon={<AddRoundedIcon />}
            disabled={!vaultId}
            onClick={() => {
              if (!readOnly) setPanel({ mode: "new", groupId });
            }}
            items={[
              {
                label: tr("New host"),
                icon: <DnsRoundedIcon fontSize="small" />,
                disabled: readOnly,
                onClick: () => setPanel({ mode: "new", groupId }),
              },
              {
                label: tr("New group"),
                icon: <CreateNewFolderRoundedIcon fontSize="small" />,
                disabled: readOnly,
                onClick: () => setPanel({ mode: "group", id: null, parentId: groupId }),
              },
              {
                label: tr("Import…"),
                icon: <FileDownloadOutlinedIcon fontSize="small" />,
                disabled: readOnly,
                onClick: () => setImportOpen(true),
              },
              {
                label: tr("Export CSV…"),
                icon: <FileUploadOutlinedIcon fontSize="small" />,
                onClick: () => setExportOpen(true),
              },
              {
                label: tr("Discover on local network…"),
                icon: <LanOutlinedIcon fontSize="small" />,
                disabled: readOnly,
                divider: true,
                onClick: () => setLanOpen(true),
              },
              {
                label: tr("Import from Tailscale / NetBird…"),
                icon: <HubOutlinedIcon fontSize="small" />,
                disabled: readOnly,
                onClick: () => setTailnetOpen(true),
              },
              ...CLOUD_PROVIDERS.map((p, i) => ({
                label: tr("{short} Integration", { short: p.short }),
                icon: <CloudOutlinedIcon fontSize="small" />,
                disabled: readOnly,
                divider: i === 0,
                onClick: () => setCloudProvider(p.id),
              })),
            ]}
          />
          <Button
            variant="tonal"
            startIcon={<TerminalRoundedIcon />}
            onClick={() => openTerminal({ kind: "local" })}
          >
            {tr("Terminal")}
          </Button>
          <Button variant="tonal" startIcon={<UsbRoundedIcon />} onClick={goToSerial}>
            {tr("Serial")}
          </Button>
          {readOnly && <ViewOnlyChip sx={{ ml: 1 }} />}
        </Toolbar>

        <Box sx={{ px: 3, pt: 1.5, pb: 1 }}>
          {knownSuggestions.length > 0 && (
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, mb: 1, flexWrap: "wrap" }}>
              <Typography variant="caption" color="text.secondary">
                {tr("Known hosts:")}
              </Typography>
              {knownSuggestions.map((s) => (
                <Chip
                  key={`${s.address}:${s.port ?? ""}`}
                  size="small"
                  variant="outlined"
                  icon={<DnsRoundedIcon />}
                  label={
                    quickTarget
                      ? quickLabel({
                          ...quickTarget,
                          address: s.address,
                          port: s.port ?? quickTarget.port,
                        })
                      : s.address
                  }
                  onClick={() => connectKnown(s)}
                  sx={{ "& .MuiChip-icon": { fontSize: 14 } }}
                />
              ))}
            </Box>
          )}
          {selecting ? (
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                flexWrap: "wrap",
                minHeight: 28,
                gap: 0.5,
                pl: 1,
                pr: 0.5,
                py: 0.25,
                borderRadius: 1.5,
                bgcolor: "surface.high",
              }}
            >
              <Typography variant="body2" noWrap sx={{ fontWeight: 600, mr: 1 }}>
                {tr("{count} selected", { count: visibleChecked.size })}
              </Typography>
              {(
                [
                  {
                    label: tr("Connect"),
                    icon: <PlayArrowRoundedIcon fontSize="small" />,
                    onClick: () => connectHosts(selectedHosts),
                  },
                  {
                    label: tr("Move to"),
                    icon: <DriveFileMoveOutlinedIcon fontSize="small" />,
                    disabled: readOnly,
                    onClick: () => setMoveCopy({ kind: "group", hosts: selectedHosts }),
                  },
                  {
                    label: tr("Copy to"),
                    icon: <LibraryAddOutlinedIcon fontSize="small" />,
                    onClick: (e: MouseEvent<HTMLElement>) => setCopyAnchor(e.currentTarget),
                  },
                  {
                    label: tr("Duplicate"),
                    icon: <ContentCopyRoundedIcon fontSize="small" />,
                    disabled: readOnly,
                    onClick: () => void duplicateHosts(selectedHosts),
                  },
                  {
                    label: tr("Remove"),
                    icon: <DeleteOutlineRoundedIcon fontSize="small" />,
                    disabled: readOnly,
                    color: "error" as const,
                    onClick: () => setConfirmRemove(selectedHosts),
                  },
                ] as {
                  label: string;
                  icon: ReactElement;
                  disabled?: boolean;
                  color?: "error";
                  onClick: (e: MouseEvent<HTMLElement>) => void;
                }[]
              ).map((a) =>
                narrow ? (
                  <Tooltip key={a.label} title={a.label}>
                    <span>
                      <IconButton
                        size="small"
                        color={a.color}
                        aria-label={a.label}
                        disabled={a.disabled}
                        onClick={a.onClick}
                      >
                        {a.icon}
                      </IconButton>
                    </span>
                  </Tooltip>
                ) : (
                  <Button
                    key={a.label}
                    size="small"
                    variant="text"
                    color={a.color ?? "inherit"}
                    startIcon={a.icon}
                    disabled={a.disabled}
                    onClick={a.onClick}
                    sx={{ whiteSpace: "nowrap", flexShrink: 0 }}
                  >
                    {a.label}
                  </Button>
                ),
              )}
              <Box sx={{ flex: 1 }} />
              <Tooltip title={`Select all (${IS_MAC ? "Cmd" : "Ctrl"}+A)`}>
                <IconButton
                  size="small"
                  aria-label={tr("Select all")}
                  onClick={selectAll}
                  disabled={visibleChecked.size === visibleHosts.length}
                >
                  <SelectAllRoundedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title={tr("Clear selection (Esc)")}>
                <IconButton
                  size="small"
                  aria-label={tr("Clear selection")}
                  onClick={clearSelection}
                >
                  <CloseRoundedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
          ) : (
            <Box sx={{ display: "flex", alignItems: "center", minHeight: 28, gap: 1 }}>
              {filtering ? (
                <>
                  <Typography variant="body2" color="text.secondary">
                    {trn(visibleHosts.length, "{count} result", "{count} results")}
                  </Typography>
                  {subtree !== null && (
                    <Chip
                      size="small"
                      variant={searchEverywhere ? "outlined" : "filled"}
                      icon={<FolderOpenRoundedIcon />}
                      label={
                        searchEverywhere
                          ? tr("Everywhere")
                          : tr("In {group}", {
                              group: crumbs[crumbs.length - 1]?.label ?? tr("group"),
                            })
                      }
                      onClick={() => setSearchEverywhere((v) => !v)}
                      sx={{ "& .MuiChip-icon": { fontSize: 16 } }}
                    />
                  )}
                </>
              ) : (
                <>
                  {groupId && (
                    <Tooltip title={tr("Back (Backspace)")}>
                      <IconButton
                        size="small"
                        aria-label={tr("Back")}
                        onClick={goBack}
                        sx={{ ml: -0.75 }}
                      >
                        <ArrowBackRoundedIcon sx={{ fontSize: 18 }} />
                      </IconButton>
                    </Tooltip>
                  )}
                  <Breadcrumbs>
                    <Link
                      component="button"
                      underline={groupId ? "hover" : "none"}
                      color={groupId ? "text.secondary" : "text.primary"}
                      onClick={() => {
                        clearSelection();
                        setGroupId(null);
                      }}
                      sx={crumbSx(dnd.dropping === "root")}
                      {...(groupId ? dnd.dropInto(null) : {})}
                    >
                      {tr("All hosts")}
                    </Link>
                    {crumbs.map((g, i) => {
                      const last = i === crumbs.length - 1;
                      return (
                        <Link
                          key={g.id}
                          component="button"
                          underline={last ? "none" : "hover"}
                          color={last ? "text.primary" : "text.secondary"}
                          onClick={() => {
                            if (last) return openGroupPanel(g);
                            clearSelection();
                            setGroupId(g.id);
                          }}
                          onContextMenu={(e) => onGroupContext(g, e)}
                          sx={crumbSx(dnd.dropping === g.id)}
                          {...(last ? {} : dnd.dropInto(g.id))}
                        >
                          {g.label}
                        </Link>
                      );
                    })}
                  </Breadcrumbs>
                </>
              )}
              {!filtering && crumbs.length > 0 && (
                <Tooltip title={tr("Group details")}>
                  <IconButton
                    size="small"
                    aria-label={tr("Group details")}
                    onClick={() => {
                      const g = crumbs[crumbs.length - 1];
                      if (g) openGroupPanel(g);
                    }}
                    sx={{ ml: -0.5 }}
                  >
                    <EditOutlinedIcon sx={{ fontSize: 16 }} />
                  </IconButton>
                </Tooltip>
              )}
              {tagFilter.map((t) => (
                <TagChip
                  key={t}
                  label={t}
                  color={tagColors.get(t)}
                  variant="filled"
                  onDelete={() => updateTagFilter((f) => f.filter((x) => x !== t))}
                />
              ))}
              {tagFilter.length > 0 && (
                <Button size="small" variant="text" onClick={() => updateTagFilter(() => [])}>
                  {tr("Clear")}
                </Button>
              )}
            </Box>
          )}
        </Box>

        <Box sx={{ flex: 1, minHeight: 0, overflowY: "auto", px: 3, pb: 3 }}>
          {!filtering && groupId === null && <TeamSteps />}
          {loading ? (
            <Loading />
          ) : loadError ? (
            <EmptyState
              title={tr("Could not open the vault")}
              description={errorMessage(loadError)}
            />
          ) : childGroups.length === 0 && visibleHosts.length === 0 ? (
            <EmptyState
              icon={<DnsRoundedIcon />}
              title={
                filtering
                  ? tr("Nothing matches")
                  : groupId
                    ? tr("This group is empty")
                    : tr("No hosts yet")
              }
              description={
                filtering
                  ? liveLink
                    ? tr("Press Enter to join this multiplayer session.")
                    : quickTarget
                      ? tr("Press Enter to connect to {quickLabel}.", {
                          quickLabel: quickLabel(quickTarget),
                        })
                      : scopedToGroup
                        ? tr(
                            "Nothing in this group — switch to Everywhere to search the whole vault.",
                          )
                        : tr("Try a different label, address or tag.")
                  : tr("Add your first server — everything is stored encrypted on this device.")
              }
              action={
                filtering ? undefined : (
                  <Button
                    variant="contained"
                    startIcon={<AddRoundedIcon />}
                    onClick={() => setPanel({ mode: "new", groupId })}
                  >
                    {tr("New host")}
                  </Button>
                )
              }
            />
          ) : view === "grid" ? (
            <HostGrid {...collection} />
          ) : (
            <HostList {...collection} />
          )}
        </Box>
      </Box>

      {(panel.mode === "new" || panel.mode === "edit") && vaultId && (
        <HostEditPanel
          key={panel.mode === "edit" ? panel.id : "new"}
          vaultId={vaultId}
          hostId={panel.mode === "edit" ? panel.id : null}
          initialGroupId={panel.mode === "new" ? panel.groupId : null}
          onClose={() => setPanel({ mode: "closed" })}
        />
      )}

      {panel.mode === "group" && vaultId && (
        <GroupPanel
          key={panel.id ?? "new-group"}
          vaultId={vaultId}
          groupId={panel.id}
          initialParentId={panel.parentId}
          onClose={() => setPanel({ mode: "closed" })}
          onDeleted={(id, parentId) => {
            if (groupId === id) setGroupId(parentId);
          }}
          onDuplicated={(g) => setPanel({ mode: "group", id: g.id, parentId: g.parentId })}
        />
      )}

      {vaultId && (
        <ImportDialog
          open={importOpen}
          initialFile={importFile}
          vaultId={vaultId}
          onClose={() => {
            setImportOpen(false);
            setImportFile(null);
          }}
          onImported={clearSelection}
        />
      )}

      {vaultId && (
        <LanDiscoveryDialog
          open={lanOpen}
          vaultId={vaultId}
          onClose={() => setLanOpen(false)}
          onImported={clearSelection}
        />
      )}
      {vaultId && (
        <TailnetImportDialog
          open={tailnetOpen}
          vaultId={vaultId}
          onClose={() => setTailnetOpen(false)}
          onImported={clearSelection}
        />
      )}

      {vaultId && cloudProvider && (
        <CloudImportDialog
          open
          vaultId={vaultId}
          provider={cloudProvider}
          onClose={() => setCloudProvider(null)}
          onImported={clearSelection}
        />
      )}

      <ExportCsvDialog
        open={exportOpen}
        vault={vault.data ?? null}
        hostCount={hosts.data?.length ?? 0}
        onClose={() => setExportOpen(false)}
      />

      <TagManagerDialog open={tagsOpen} vaultId={vaultId} onClose={() => setTagsOpen(false)} />

      {vaultId && (
        <MoveCopyDialog
          request={moveCopy}
          vaultId={vaultId}
          onClose={() => setMoveCopy(null)}
          onDone={clearSelection}
        />
      )}

      {addKeyHost && (
        <AddKeyToHostDialog
          open
          host={addKeyHost}
          keys={sshKeys.data ?? []}
          busy={addKeyBusy}
          onCancel={() => setAddKeyHost(null)}
          onConfirm={(key) => {
            const host = addKeyHost;
            setAddKeyBusy(true);
            ipc
              .keyExportToHost(key.id, host.id)
              .then((r) => {
                snackbar.notify(
                  r.outcome === "added"
                    ? tr("{label} added to authorized_keys on {target}", {
                        label: key.label,
                        target: r.target,
                      })
                    : tr("{label} is already authorized on {target}", {
                        label: key.label,
                        target: r.target,
                      }),
                );
                setAddKeyHost(null);
              })
              .catch((e: unknown) => snackbar.error(errorMessage(e)))
              .finally(() => setAddKeyBusy(false));
          }}
        />
      )}

      <ConfirmDialog
        open={confirmRemove !== null}
        title={
          confirmRemove && confirmRemove.length > 1
            ? tr("Remove {length} hosts?", { length: confirmRemove.length })
            : `Remove ${confirmRemove?.[0]?.label ?? "host"}?`
        }
        danger
        confirmLabel={tr("Remove")}
        busy={deleteHosts.isPending}
        onCancel={() => setConfirmRemove(null)}
        onConfirm={() => confirmRemove && removeHosts(confirmRemove)}
      >
        {confirmRemove && confirmRemove.length > 1 ? (
          <>
            {confirmRemove.slice(0, 6).map((h) => (
              <Typography key={h.id} variant="body2">
                {h.label}
              </Typography>
            ))}
            {confirmRemove.length > 6 && (
              <Typography variant="body2" color="text.secondary">
                {tr("…and {count} more", { count: confirmRemove.length - 6 })}
              </Typography>
            )}
            <Typography variant="body2" sx={{ mt: 1 }}>
              {tr(
                "Their inline credentials are removed too. Shared identities and keys stay in the Keychain.",
              )}
            </Typography>
          </>
        ) : (
          tr(
            "The host and its inline credentials are removed. Shared identities and keys stay in the Keychain.",
          )
        )}
      </ConfirmDialog>

      <DeleteGroupDialog
        group={confirmGroup}
        onClose={() => setConfirmGroup(null)}
        onDeleted={(id, parentId) => {
          if (groupId === id) setGroupId(parentId);
          if (panel.mode === "group" && panel.id === id) setPanel({ mode: "closed" });
        }}
      />

      <TagsPopover
        anchor={tagAnchor}
        vaultId={vaultId}
        title={tr("Filter by tag")}
        selected={tagFilterIds}
        onToggle={(t, on) =>
          updateTagFilter((f) => (on ? [...f, t.label] : f.filter((x) => x !== t.label)))
        }
        onRenamed={(t, label) => updateTagFilter((f) => f.map((x) => (x === t.label ? label : x)))}
        onDeleted={(t) => updateTagFilter((f) => f.filter((x) => x !== t.label))}
        onManage={() => {
          setTagAnchor(null);
          setTagsOpen(true);
        }}
        onClose={() => setTagAnchor(null)}
      />

      <Menu
        open={Boolean(sortAnchor)}
        anchorEl={sortAnchor}
        onClose={() => setSortAnchor(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
        slotProps={{ paper: { sx: { minWidth: 200 } } }}
      >
        {(Object.keys(sortLabel) as SortKey[]).map((k) => (
          <MenuItem
            key={k}
            selected={sort === k}
            onClick={() => {
              setSort(k);
              setSortAnchor(null);
            }}
          >
            {tr(sortLabel[k])}
          </MenuItem>
        ))}
      </Menu>

      <ActionMenu
        anchor={copyAnchor}
        onClose={() => setCopyAnchor(null)}
        items={copyToItems(selectedHosts)}
      />

      <ActionMenu
        anchor={null}
        position={ctx ? { left: ctx.left, top: ctx.top } : null}
        onClose={() => setCtx(null)}
        items={ctx ? (ctx.kind === "host" ? hostMenu(ctx.host) : groupMenu(ctx.group)) : []}
      />
    </Box>
  );
}
