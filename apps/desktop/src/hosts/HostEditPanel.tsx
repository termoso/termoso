import { useEffect, useMemo, useRef, useState } from "react";
import {
  Box,
  Button,
  Divider,
  FormControlLabel,
  IconButton,
  ListSubheader,
  MenuItem,
  Stack,
  Switch,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
} from "@mui/material";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import ExpandLessRoundedIcon from "@mui/icons-material/ExpandLessRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import AddCircleOutlineRoundedIcon from "@mui/icons-material/AddCircleOutlineRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import LabelOutlinedIcon from "@mui/icons-material/LabelOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { useSnackbar } from "@/components/Snackbar";
import { distroIcon } from "./distroIcons";
import { IconPicker } from "./IconPicker";
import { pickedIcon } from "./icons";
import { DistroGlyph, ProtocolGlyph } from "./HostAvatar";
import { ConnectButton, connectTo, type ConnectTarget } from "./ConnectSplit";
import { TagsPopover } from "./TagsPopover";
import { AgentForwardingRow, CredentialsFields, X11ForwardingRow } from "./CredentialsFields";
import { WebDavAuthFields } from "./WebDavAuthFields";
import { ServerKeyField } from "./ServerKeyField";
import {
  Field,
  Loading,
  SectionCard,
  SidePanel,
  ToolIconButton,
  CompactFields,
} from "@/components/ui";
import {
  useDeleteHost,
  useGroups,
  useHostChains,
  useHostForm,
  useInherited,
  useProxies,
  useSaveHost,
  useSnippets,
  useTags,
  useGateways,
} from "@/ipc/hooks";
import {
  emptyHostForm,
  emptyWebDavForm,
  errorMessage,
  type ConnectProtocol,
  type HostForm,
  type HostProtocol,
  type IpVersion,
  type TelnetForm,
  type Uuid,
  type WebDavForm,
} from "@/ipc/types";
import * as ipc from "@/ipc/commands";
import { useActiveVault } from "@/app/vault";
import { allTerminalThemes, useCustomThemes } from "@/terminal/themes";
import { monoFontFamily, sizes } from "@/theme/theme";
import { ChainDialog, ProxyDialog } from "./HostAdvancedDialogs";
import { ConnectedNowCard, useVaultPresence } from "./PresenceViews";
import { tr, trn, msg } from "@/i18n";
import { requirePerm } from "@/team/perms";

const IP_VERSIONS: { value: IpVersion; label: string }[] = [
  { value: "auto", label: msg("Auto") },
  { value: "4", label: msg("IPv4") },
  { value: "6", label: msg("IPv6") },
];

const emptyTelnet = (): TelnetForm => ({
  port: null,
  username: "",
  password: null,
  identityId: null,
  colorScheme: null,
  hasPassword: false,
});

const emptyWebDav = emptyWebDavForm;

/** TCP port text: empty (default) or 1–65535. */
const isPortText = (raw: string) => {
  const t = raw.trim();
  if (t === "") return true;
  return /^\d{1,5}$/.test(t) && Number(t) >= 1 && Number(t) <= 65535;
};

/** A DNS name for SNI: labels of letters, digits and hyphens. */
const isServerName = (raw: string) => {
  const t = raw.trim().toLowerCase();
  return (
    t.length > 0 &&
    t.length <= 253 &&
    t.split(".").every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))
  );
};

const isPemBundle = (raw: string) => raw.includes("-----BEGIN CERTIFICATE-----");

/** SHA-256 fingerprint as `sha256:<hex>`, bare hex or colon-separated hex. */
const isFingerprint = (raw: string) => {
  const s = raw
    .trim()
    .replace(/^sha256:/i, "")
    .replace(/:/g, "");
  return /^[0-9a-f]{64}$/i.test(s);
};

interface Props {
  vaultId: Uuid;
  hostId: Uuid | null;
  initialGroupId: Uuid | null;
  onClose: () => void;
}

/** Loads the form for an existing host (or starts blank) and hands it to the editor. */
export function HostEditPanel({ vaultId, hostId, initialGroupId, onClose }: Props) {
  const loaded = useHostForm(hostId);
  const blank = useMemo(() => emptyHostForm(vaultId, initialGroupId), [vaultId, initialGroupId]);
  if (hostId !== null && loaded.data === undefined) {
    return (
      <SidePanel title={tr("Host Details")} onClose={onClose} width={sizes.panel}>
        {loaded.error ? (
          <Typography color="error">{errorMessage(loaded.error)}</Typography>
        ) : (
          <Loading pt={6} />
        )}
      </SidePanel>
    );
  }
  return (
    <HostEditor
      vaultId={vaultId}
      hostId={hostId}
      initial={loaded.data ?? blank}
      onClose={onClose}
    />
  );
}

/** Same default as the `mosh` wrapper and Termius; shown as the placeholder. */
const MOSH_DEFAULT_SERVER_COMMAND = "mosh-server new -s -c 256 -l LANG=en_US.UTF-8";

const clampPort = (raw: string) =>
  raw === "" ? null : Math.max(1, Math.min(65535, Number(raw) || 1));

const clampSeconds = (raw: string) =>
  raw === "" ? null : Math.max(0, Math.min(86400, Math.floor(Number(raw) || 0)));

const protocolsOf = (f: HostForm): ConnectProtocol[] => [
  ...(f.ssh ? (["ssh"] as const) : []),
  ...(f.ssh && f.useMosh ? (["mosh"] as const) : []),
  ...(f.telnet ? (["telnet"] as const) : []),
];

/** What the bottom Connect opens: Mosh when enabled, else the first section; Files for WebDAV-only. */
const primaryOf = (f: HostForm): ConnectTarget | null =>
  f.ssh ? (f.useMosh ? "mosh" : "ssh") : f.telnet ? "telnet" : f.webdav ? "webdav" : null;

/** Terminal sections need an address; a WebDAV-only host carries its own URL. */

/**
 * Host Details laid out the Termius way: Address → General → "SSH on … port"
 * (credentials, Show more) → "Telnet on … port" (or "+ Add Telnet"), with
 * Connect pinned at the bottom.
 */
function HostEditor({
  vaultId,
  hostId,
  initial,
  onClose,
}: {
  vaultId: Uuid;
  hostId: Uuid | null;
  initial: HostForm;
  onClose: () => void;
}) {
  const snackbar = useSnackbar();
  const groups = useGroups(vaultId);
  const tags = useTags(vaultId);
  const snippets = useSnippets(vaultId);
  const proxies = useProxies(vaultId);
  const gateways = useGateways();
  const wake = async () => {
    const mac = (form.macAddress ?? "").trim();
    if (!mac) return;
    try {
      const n = await ipc.wakeHost(mac, null);
      snackbar.notify(
        trn(n, "Sent {count} Wake-on-LAN packet", "Sent {count} Wake-on-LAN packets"),
      );
    } catch (e) {
      snackbar.error(errorMessage(e));
    }
  };
  const chains = useHostChains(vaultId);
  const presence = useVaultPresence(vaultId);
  const save = useSaveHost();
  const del = useDeleteHost();

  const [form, setForm] = useState<HostForm>(initial);
  const [seen, setSeen] = useState(initial);
  const [touched, setTouched] = useState(false);
  const [edits, setEdits] = useState(0);
  const [saved, setSaved] = useState(false);
  const markEdited = () => {
    setTouched(true);
    setSaved(false);
    setEdits((n) => n + 1);
  };
  /** The stored host: the one being edited, or the one autosave just created. */
  const id = form.id;
  // The host can change underneath an untouched editor (cloud import, sync):
  // follow the stored form until the user starts editing.
  if (seen !== initial) {
    setSeen(initial);
    if (!touched) setForm(initial);
  }
  const inherited = useInherited(form.groupId);
  const inh = inherited.data ?? null;
  const inheritedFrom = inh && inh.groupPath.length > 0 ? inh.groupPath.join(" / ") : null;
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [more, setMore] = useState(
    initial.hostChainId !== null ||
      initial.proxyId !== null ||
      initial.startupSnippetId !== null ||
      initial.shellIntegration !== null ||
      initial.envVariables.length > 0 ||
      initial.agentForwarding ||
      initial.forwardX11 ||
      initial.keepAliveInterval !== null ||
      initial.timeout !== null ||
      initial.useMosh ||
      initial.colorScheme !== null,
  );
  const [dialog, setDialog] = useState<"proxy" | "chain" | null>(null);
  const [tagAnchor, setTagAnchor] = useState<HTMLElement | null>(null);

  const set = <K extends keyof HostForm>(k: K, v: HostForm[K]) => {
    markEdited();
    setForm((f) => ({ ...f, [k]: v }));
  };
  const patch = (p: Partial<HostForm>) => {
    markEdited();
    setForm((f) => ({ ...f, ...p }));
  };
  const patchTelnet = (p: Partial<TelnetForm>) => {
    markEdited();
    setForm((f) => ({ ...f, telnet: { ...(f.telnet ?? emptyTelnet()), ...p } }));
  };
  const patchWebDav = (p: Partial<WebDavForm>) => {
    markEdited();
    setForm((f) => ({ ...f, webdav: { ...(f.webdav ?? emptyWebDav()), ...p } }));
  };

  const readOnly = useActiveVault().readOnly;
  const protocols = protocolsOf(form);
  const addressOk = form.address.trim().length > 0;
  const webdavOk =
    form.webdav === null ||
    (isPortText(form.webdav.port === null ? "" : String(form.webdav.port)) &&
      (form.webdav.tlsServerName === null || isServerName(form.webdav.tlsServerName)) &&
      (form.webdav.caCertificate === null || isPemBundle(form.webdav.caCertificate)) &&
      (form.webdav.certificateFingerprint === null ||
        form.webdav.certificateFingerprint.trim() === "" ||
        isFingerprint(form.webdav.certificateFingerprint)));
  const hasSection = protocols.length > 0 || form.webdav !== null;
  const canSave = addressOk && webdavOk && hasSection && !save.isPending && !readOnly;
  const sshPortPlaceholder = String(inh?.port ?? 22);
  const chainName = (id: Uuid | null) =>
    (chains.data ?? []).find((c) => c.id === id)?.data.label ?? null;
  const proxyName = (id: Uuid | null) => {
    const p = (proxies.data ?? []).find((c) => c.id === id);
    return p ? `${p.data.kind.toUpperCase()} ${p.data.host}:${p.data.port}` : null;
  };
  const icon = pickedIcon(form.icon) ?? distroIcon(form.osName);
  const glyphProtocol: HostProtocol = form.ssh ? "ssh" : form.telnet ? "telnet" : "webdav";
  const selectedTags = (tags.data ?? []).filter((t) => form.tagIds.includes(t.id));
  const selectedTagIds = new Set(form.tagIds);

  // Termius-style autosave: edits persist shortly after the last change (a
  // new host is created once it has an address); Connect flushes first.
  const latest = useRef({ form, canSave });
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const inFlight = useRef(false);
  const dirty = useRef(false);
  useEffect(() => {
    latest.current = { form, canSave };
  });

  const persist = (after?: (card: Parameters<typeof connectTo>[0]) => void) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    if (inFlight.current) {
      timer.current = setTimeout(() => persist(after), 250);
      return;
    }
    const { form: f, canSave: ok } = latest.current;
    if (!ok) return;
    dirty.current = false;
    inFlight.current = true;
    // An empty name falls back to the address; an explicit name always wins.
    save.mutate(
      { ...f, label: f.label.trim() || f.address.trim() },
      {
        onSuccess: (card) => {
          if (f.id === null) {
            latest.current = { ...latest.current, form: { ...latest.current.form, id: card.id } };
            setForm((cur) => ({ ...cur, id: card.id }));
            snackbar.notify(tr("Host “{label}” added", { label: card.label }));
          }
          setSaved(true);
          after?.(card);
        },
        onError: (e) => snackbar.error(errorMessage(e)),
        onSettled: () => {
          inFlight.current = false;
        },
      },
    );
  };
  const persistRef = useRef(persist);
  useEffect(() => {
    persistRef.current = persist;
  });

  useEffect(() => {
    if (edits === 0) return;
    dirty.current = true;
    timer.current = setTimeout(() => persistRef.current(), 600);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [edits]);

  // Closing the panel with a pending edit still saves it.
  useEffect(
    () => () => {
      if (dirty.current) persistRef.current();
    },
    [],
  );

  const connect = () => {
    const target = primaryOf(form);
    if (id !== null && (!dirty.current || !canSave)) {
      connectTo({ id, vaultId, label: form.label }, target);
      return;
    }
    persist((card) => connectTo(card, target));
  };
  const canConnect = id !== null ? !save.isPending : canSave;

  const onDelete = () => {
    if (!id) return;
    if (!requirePerm(vaultId, "entities.delete")) return;
    del.mutate(
      { id, vaultId },
      {
        onSuccess: () => {
          snackbar.notify(tr("Host deleted"));
          setConfirmDelete(false);
          onClose();
        },
        onError: (e) => snackbar.error(errorMessage(e)),
      },
    );
  };

  const footer = (
    <Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 0.5 }}>
      <Typography
        variant="caption"
        color="text.secondary"
        noWrap
        sx={{ minHeight: 16, lineHeight: "16px", textAlign: "center" }}
      >
        {save.isPending ? tr("Saving…") : saved ? tr("Saved") : ""}
      </Typography>
      <ConnectButton
        hostId={id}
        vaultId={vaultId}
        label={form.label}
        target={primaryOf(form)}
        disabled={!canConnect}
        onClick={connect}
      />
    </Box>
  );

  const proxyField = (
    <Field label={tr("Proxy")}>
      <TextField
        select
        value={form.proxyId ?? ""}
        onChange={(e) => {
          const v = e.target.value;
          if (v === "__new") setDialog("proxy");
          else set("proxyId", v === "" ? null : v);
        }}
      >
        <MenuItem value="">
          <em>
            {inh?.proxyId && proxyName(inh.proxyId)
              ? tr("Inherited — {name}", { name: proxyName(inh.proxyId) ?? "" })
              : tr("None")}
          </em>
        </MenuItem>
        {(proxies.data ?? []).map((p) => (
          <MenuItem key={p.id} value={p.id}>
            {p.data.kind.toUpperCase()}
            <Typography
              component="span"
              variant="caption"
              color="text.secondary"
              sx={{ ml: 1, fontFamily: monoFontFamily }}
            >
              {p.data.host}:{p.data.port}
            </Typography>
          </MenuItem>
        ))}
        <MenuItem value="__new" sx={{ color: "primary.main" }}>
          <AddRoundedIcon fontSize="small" sx={{ mr: 1 }} />
          {tr("New proxy…")}
        </MenuItem>
      </TextField>
    </Field>
  );

  return (
    <CompactFields.Provider value>
      <SidePanel
        title={tr("Host Details")}
        subtitle={id ? form.label || form.address : tr("New host")}
        onClose={onClose}
        width={sizes.panel}
        actions={
          id && (
            <ToolIconButton
              title={tr("Delete host")}
              color="error"
              onClick={() => setConfirmDelete(true)}
            >
              <DeleteOutlineRoundedIcon fontSize="small" />
            </ToolIconButton>
          )
        }
        footer={footer}
      >
        <Box
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSave) persist();
          }}
          sx={{ display: "contents" }}
        >
          {id && <ConnectedNowCard viewers={presence.get(id) ?? []} />}
          <SectionCard title={tr("Address")}>
            <Box sx={{ display: "flex", gap: 1.5, alignItems: "center" }}>
              <IconPicker
                value={form.icon}
                onChange={(v) => set("icon", v)}
                disabled={readOnly}
                autoLabel={tr("Automatic (detected OS)")}
                fallback={
                  icon ? <DistroGlyph icon={icon} /> : <ProtocolGlyph protocol={glyphProtocol} />
                }
              />
              <TextField
                required
                autoFocus={!hostId}
                value={form.address}
                onChange={(e) => set("address", e.target.value)}
                placeholder={tr("IP or Hostname")}
                slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                error={touched && form.address.trim().length === 0}
                sx={{ flex: 1 }}
              />
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
                {tr("IP version")}
              </Typography>
              <ToggleButtonGroup
                exclusive
                size="small"
                value={form.ipVersion}
                onChange={(_e, v: IpVersion | null) => {
                  if (v) set("ipVersion", v);
                }}
              >
                {IP_VERSIONS.map((o) => (
                  <ToggleButton key={o.value} value={o.value} sx={{ px: 1.5 }}>
                    {tr(o.label)}
                  </ToggleButton>
                ))}
              </ToggleButtonGroup>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <TextField
                size="small"
                value={form.macAddress ?? ""}
                onChange={(e) => set("macAddress", e.target.value === "" ? null : e.target.value)}
                placeholder={tr("MAC address for Wake-on-LAN")}
                slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                sx={{ flex: 1 }}
              />
              <Button
                size="small"
                variant="outlined"
                disabled={!(form.macAddress ?? "").trim()}
                onClick={wake}
              >
                {tr("Wake")}
              </Button>
            </Box>
          </SectionCard>

          <SectionCard title={tr("General")}>
            <TextField
              value={form.label}
              onChange={(e) => set("label", e.target.value)}
              placeholder={tr("Label")}
            />
            <TextField
              select
              value={form.groupId ?? ""}
              onChange={(e) => set("groupId", e.target.value === "" ? null : e.target.value)}
              slotProps={{
                select: {
                  displayEmpty: true,
                  renderValue: (v) => {
                    const g = (groups.data ?? []).find((x) => x.id === v);
                    return (
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1.25 }}>
                        <FolderOutlinedIcon fontSize="small" sx={{ color: "text.secondary" }} />
                        <Box component="span" sx={{ color: g ? "text.primary" : "text.disabled" }}>
                          {g?.label ?? tr("Parent Group")}
                        </Box>
                      </Box>
                    );
                  },
                },
              }}
            >
              <MenuItem value="">
                <em>{tr("No group")}</em>
              </MenuItem>
              {(groups.data ?? []).map((g) => (
                <MenuItem key={g.id} value={g.id}>
                  {g.label}
                </MenuItem>
              ))}
            </TextField>
            {inheritedFrom &&
              inh &&
              (inh.username !== null ||
                inh.hasPassword ||
                inh.sshKeyId !== null ||
                inh.identityId !== null ||
                inh.port !== null) && (
                <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
                  {tr("Inherits credentials and connection defaults from {group}.", {
                    group: inheritedFrom,
                  })}
                </Typography>
              )}
            <Box
              component="button"
              type="button"
              onClick={(e) => setTagAnchor(e.currentTarget)}
              aria-label={tr("Tags")}
              sx={{
                all: "unset",
                boxSizing: "border-box",
                display: "flex",
                alignItems: "center",
                gap: 1.25,
                minHeight: sizes.control,
                px: 1.5,
                py: 0.5,
                borderRadius: 1.5,
                border: 1,
                borderColor: "border.basic",
                cursor: "pointer",
                "&:hover": { borderColor: "border.strong" },
                "&:focus-visible": { borderColor: "primary.main" },
              }}
            >
              <LabelOutlinedIcon fontSize="small" sx={{ color: "text.secondary" }} />
              {selectedTags.length === 0 ? (
                <Typography variant="body1" sx={{ color: "text.disabled" }}>
                  {tr("Tags")}
                </Typography>
              ) : (
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, flex: 1 }}>
                  {selectedTags.map((t) => (
                    <Box
                      key={t.id}
                      component="span"
                      sx={{
                        px: 1,
                        height: 22,
                        lineHeight: "22px",
                        borderRadius: 1,
                        bgcolor: "surface.highest",
                        fontSize: 12,
                        fontWeight: 500,
                      }}
                    >
                      {t.label}
                    </Box>
                  ))}
                </Box>
              )}
            </Box>
            <TextField
              multiline
              minRows={1}
              maxRows={6}
              value={form.notes}
              onChange={(e) => set("notes", e.target.value)}
              placeholder={tr("Notes")}
            />
          </SectionCard>

          {form.ssh ? (
            <SectionCard
              title={
                <PortTitle
                  name="SSH"
                  value={form.port}
                  placeholder={sshPortPlaceholder}
                  onChange={(v) => set("port", v)}
                />
              }
              action={
                (form.telnet !== null || form.webdav !== null) && (
                  <Tooltip title={tr("Remove SSH")}>
                    <IconButton
                      size="small"
                      aria-label={tr("Remove SSH")}
                      onClick={() => set("ssh", false)}
                    >
                      <CloseRoundedIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                )
              }
            >
              <Divider />
              <CredentialsFields
                vaultId={vaultId}
                ssh
                agentForwarding={false}
                inherited={inh}
                inlineLabel={tr("Set on this host")}
                value={form}
                onChange={patch}
              />

              <Button
                variant="text"
                color="inherit"
                onClick={() => setMore((v) => !v)}
                endIcon={more ? <ExpandLessRoundedIcon /> : <ExpandMoreRoundedIcon />}
                sx={{ alignSelf: "flex-start", color: "text.secondary", ml: -1 }}
              >
                {more ? tr("Show less") : tr("Show more")}
              </Button>

              {more && (
                <>
                  <AgentForwardingRow value={form} onChange={patch} inherited={inh} />
                  <X11ForwardingRow value={form} onChange={patch} inherited={inh} />
                  <Field
                    label={tr("Startup snippet")}
                    hint={tr("Runs right after the shell opens.")}
                  >
                    <TextField
                      select
                      value={form.startupSnippetId ?? ""}
                      onChange={(e) =>
                        set("startupSnippetId", e.target.value === "" ? null : e.target.value)
                      }
                    >
                      <MenuItem value="">
                        <em>{tr("None")}</em>
                      </MenuItem>
                      {(snippets.data ?? []).map((s) => (
                        <MenuItem key={s.id} value={s.id}>
                          {s.label}
                        </MenuItem>
                      ))}
                    </TextField>
                  </Field>
                  <Field
                    label={tr("Shell integration")}
                    hint={tr(
                      "Prompt marks for history and autocomplete. Turn off for routers, jump hosts and hosts that open a program instead of a shell.",
                    )}
                  >
                    <TextField
                      select
                      value={
                        form.shellIntegration === null ? "" : form.shellIntegration ? "on" : "off"
                      }
                      onChange={(e) =>
                        set(
                          "shellIntegration",
                          e.target.value === "" ? null : e.target.value === "on",
                        )
                      }
                    >
                      <MenuItem value="">
                        <em>{tr("Follow the app setting")}</em>
                      </MenuItem>
                      <MenuItem value="on">{tr("On")}</MenuItem>
                      <MenuItem value="off">{tr("Off for this host")}</MenuItem>
                    </TextField>
                  </Field>
                  <Field label={tr("Host Chaining")}>
                    <TextField
                      select
                      value={form.hostChainId ?? ""}
                      onChange={(e) => {
                        const v = e.target.value;
                        if (v === "__new") setDialog("chain");
                        else set("hostChainId", v === "" ? null : v);
                      }}
                    >
                      <MenuItem value="">
                        <em>
                          {inh?.hostChainId && chainName(inh.hostChainId)
                            ? tr("Inherited — {name}", { name: chainName(inh.hostChainId) ?? "" })
                            : tr("Direct connection")}
                        </em>
                      </MenuItem>
                      {(chains.data ?? []).map((c) => (
                        <MenuItem key={c.id} value={c.id}>
                          {c.data.label}
                          <Typography
                            component="span"
                            variant="caption"
                            color="text.secondary"
                            sx={{ ml: 1 }}
                          >
                            {trn(c.data.host_ids.length, "{count} hop", "{count} hops")}
                          </Typography>
                        </MenuItem>
                      ))}
                      <MenuItem value="__new" sx={{ color: "primary.main" }}>
                        <AddRoundedIcon fontSize="small" sx={{ mr: 1 }} />
                        {tr("New host chain…")}
                      </MenuItem>
                    </TextField>
                  </Field>
                  {proxyField}
                  <Field label={tr("Gateway")}>
                    <TextField
                      select
                      value={form.gatewayId ?? ""}
                      onChange={(e) =>
                        set("gatewayId", e.target.value === "" ? null : e.target.value)
                      }
                      helperText={tr(
                        "Tunnel through an API bridge running `termoso-bridge gateway` next to the host — for hosts without a public address.",
                      )}
                    >
                      <MenuItem value="">
                        <em>{tr("None (direct)")}</em>
                      </MenuItem>
                      {(gateways.data ?? [])
                        .filter((g) => g.vault_ids.includes(vaultId) || g.id === form.gatewayId)
                        .map((g) => (
                          <MenuItem key={g.id} value={g.id}>
                            {g.name}
                            <Typography
                              component="span"
                              variant="caption"
                              color={g.online ? "success.main" : "text.secondary"}
                              sx={{ ml: 1 }}
                            >
                              {g.online ? tr("online") : tr("offline")}
                            </Typography>
                          </MenuItem>
                        ))}
                    </TextField>
                  </Field>
                  <Field
                    label={tr("Environment Variables")}
                    hint={
                      inh && inh.envVariables.length > 0 && inheritedFrom
                        ? `From ${inheritedFrom}: ${inh.envVariables.map(([k, v]) => `${k}=${v}`).join(", ")}`
                        : tr("Sent with the session; the server must accept them (AcceptEnv).")
                    }
                  >
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                      {form.envVariables.map(([k, v], i) => (
                        <Box key={i} sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                          <TextField
                            value={k}
                            placeholder="NAME"
                            onChange={(e) =>
                              set(
                                "envVariables",
                                form.envVariables.map((row, j) =>
                                  j === i ? [e.target.value, row[1]] : row,
                                ),
                              )
                            }
                            slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                            sx={{ flex: 1 }}
                          />
                          <TextField
                            value={v}
                            placeholder="value"
                            onChange={(e) =>
                              set(
                                "envVariables",
                                form.envVariables.map((row, j) =>
                                  j === i ? [row[0], e.target.value] : row,
                                ),
                              )
                            }
                            slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                            sx={{ flex: 1.4 }}
                          />
                          <IconButton
                            size="small"
                            aria-label={tr("Remove variable")}
                            onClick={() =>
                              set(
                                "envVariables",
                                form.envVariables.filter((_row, j) => j !== i),
                              )
                            }
                          >
                            <CloseRoundedIcon fontSize="small" />
                          </IconButton>
                        </Box>
                      ))}
                      <Button
                        size="small"
                        color="inherit"
                        startIcon={<AddRoundedIcon />}
                        onClick={() => set("envVariables", [...form.envVariables, ["", ""]])}
                        sx={{ alignSelf: "flex-start", color: "text.secondary" }}
                      >
                        {tr("Add variable")}
                      </Button>
                    </Box>
                  </Field>
                  <Box sx={{ display: "flex", gap: 1.5 }}>
                    <Field label={tr("Keep-alive, s")} sx={{ flex: 1 }}>
                      <TextField
                        type="number"
                        value={form.keepAliveInterval ?? ""}
                        onChange={(e) => set("keepAliveInterval", clampSeconds(e.target.value))}
                        placeholder={inh?.keepAliveInterval?.toString() ?? tr("default")}
                        slotProps={{ htmlInput: { min: 0, max: 86400 } }}
                      />
                    </Field>
                    <Field label={tr("Timeout, s")} sx={{ flex: 1 }}>
                      <TextField
                        type="number"
                        value={form.timeout ?? ""}
                        onChange={(e) => set("timeout", clampSeconds(e.target.value))}
                        placeholder={inh?.timeout?.toString() ?? tr("default")}
                        slotProps={{ htmlInput: { min: 0, max: 86400 } }}
                      />
                    </Field>
                  </Box>
                  <ServerKeyField
                    vaultId={vaultId}
                    host={form.address}
                    port={form.port ?? inh?.port ?? 22}
                    readOnly={readOnly}
                  />
                  <Field
                    label={tr("Mosh")}
                    hint={
                      form.useMosh
                        ? tr(
                            "Connect runs mosh-server over SSH, then hands the session to a local mosh-client (UDP). Needs Mosh on both ends.",
                          )
                        : undefined
                    }
                  >
                    <TextField
                      select
                      value={form.useMosh ? "on" : "off"}
                      onChange={(e) => set("useMosh", e.target.value === "on")}
                    >
                      <MenuItem value="off">{tr("Disabled")}</MenuItem>
                      <MenuItem value="on">{tr("Enabled")}</MenuItem>
                    </TextField>
                  </Field>
                  {form.useMosh && (
                    <Field label={tr("Mosh server command")}>
                      <TextField
                        value={form.moshServerCommand ?? ""}
                        onChange={(e) => set("moshServerCommand", e.target.value || null)}
                        placeholder={MOSH_DEFAULT_SERVER_COMMAND}
                        slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                      />
                    </Field>
                  )}
                  <ThemeField value={form.colorScheme} onChange={(v) => set("colorScheme", v)} />
                </>
              )}
            </SectionCard>
          ) : (
            <AddSectionButton label={tr("Add SSH")} onClick={() => set("ssh", true)} />
          )}

          {form.telnet ? (
            <SectionCard
              title={
                <PortTitle
                  name="Telnet"
                  value={form.telnet.port}
                  placeholder="23"
                  onChange={(v) => patchTelnet({ port: v })}
                />
              }
              action={
                <Tooltip title={tr("Remove Telnet")}>
                  <IconButton
                    size="small"
                    aria-label={tr("Remove Telnet")}
                    onClick={() => set("telnet", null)}
                  >
                    <CloseRoundedIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              }
            >
              <Divider />
              <CredentialsFields
                vaultId={vaultId}
                ssh={false}
                inlineLabel={tr("Set on this host")}
                value={{
                  identityId: form.telnet.identityId,
                  username: form.telnet.username,
                  password: form.telnet.password,
                  hasPassword: form.telnet.hasPassword,
                  totpSecret: null,
                  hasTotp: false,
                  sshKeyId: null,
                  sshCertificateId: null,
                  sshId: false,
                  sshIdKeyType: null,
                  agentForwarding: false,
                  forwardX11: false,
                }}
                onChange={({ identityId, username, password }) => {
                  const p: Partial<TelnetForm> = {};
                  if (identityId !== undefined) p.identityId = identityId;
                  if (username !== undefined) p.username = username;
                  if (password !== undefined) p.password = password;
                  patchTelnet(p);
                }}
              />
              <ThemeField
                value={form.telnet.colorScheme}
                onChange={(v) => patchTelnet({ colorScheme: v })}
              />
              {proxyField}
            </SectionCard>
          ) : (
            <AddSectionButton
              label={tr("Add Telnet")}
              onClick={() => set("telnet", emptyTelnet())}
            />
          )}

          {form.webdav ? (
            <SectionCard
              title="WebDAV"
              action={
                <Tooltip title={tr("Remove WebDAV")}>
                  <IconButton
                    size="small"
                    aria-label={tr("Remove WebDAV")}
                    onClick={() => set("webdav", null)}
                  >
                    <CloseRoundedIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              }
            >
              <Stack direction="row" spacing={1.5}>
                <Field label={tr("Port")} sx={{ width: 120 }}>
                  <TextField
                    value={form.webdav.port ?? ""}
                    onChange={(e) => {
                      const t = e.target.value.replace(/\D/g, "");
                      patchWebDav({ port: t === "" ? null : Number(t) });
                    }}
                    placeholder={form.webdav.http ? "80" : "443"}
                    slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                  />
                </Field>
                <Field label={tr("Path")} sx={{ flex: 1 }}>
                  <TextField
                    value={form.webdav.path}
                    onChange={(e) => patchWebDav({ path: e.target.value })}
                    placeholder="/remote.php/dav/files/user/"
                    slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                  />
                </Field>
              </Stack>
              <Typography variant="caption" color="text.secondary">
                {tr(
                  "The share is reached at the host's address above; the port defaults to 443 (80 over plain HTTP).",
                )}
              </Typography>
              {proxyField}
              <Divider />
              <WebDavAuthFields vaultId={vaultId} value={form.webdav} onChange={patchWebDav} />
              <Divider />
              <Typography variant="subtitle2">{tr("Security")}</Typography>
              <FormControlLabel
                sx={{ ml: 0, mr: 0, alignSelf: "flex-start" }}
                control={
                  <Switch
                    size="small"
                    checked={form.webdav.http}
                    onChange={(e) => patchWebDav({ http: e.target.checked })}
                    sx={{ mr: 0.5 }}
                  />
                }
                label={tr("Plain HTTP (no TLS)")}
              />
              {!form.webdav.http && (
                <>
                  <Field
                    label={tr("Server name (SNI)")}
                    hint={tr(
                      "Only when the certificate is issued to a different name than the address — a share behind a reverse proxy reached by IP, or a name that is not in DNS. Sent as SNI and Host and checked against the certificate.",
                    )}
                  >
                    <TextField
                      value={form.webdav.tlsServerName ?? ""}
                      onChange={(e) =>
                        patchWebDav({ tlsServerName: e.target.value.trim() || null })
                      }
                      placeholder={form.address.trim() || "dav.internal"}
                      error={
                        touched &&
                        form.webdav.tlsServerName !== null &&
                        !isServerName(form.webdav.tlsServerName)
                      }
                      slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                    />
                  </Field>
                  <Field
                    label={tr("Certificate authority (PEM)")}
                    hint={tr(
                      "Your own CA that signed the server certificate, instead of the system trust store. Several certificates may follow one another.",
                    )}
                  >
                    <TextField
                      multiline
                      minRows={3}
                      maxRows={8}
                      value={form.webdav.caCertificate ?? ""}
                      onChange={(e) =>
                        patchWebDav({ caCertificate: e.target.value.trim() || null })
                      }
                      placeholder="-----BEGIN CERTIFICATE-----"
                      error={
                        touched &&
                        form.webdav.caCertificate !== null &&
                        !isPemBundle(form.webdav.caCertificate)
                      }
                      slotProps={{
                        input: { sx: { fontFamily: monoFontFamily, fontSize: 12 } },
                      }}
                    />
                  </Field>
                  <Field
                    label={tr("Server certificate fingerprint")}
                    hint={tr(
                      "Alternatively pin exactly one server certificate by its SHA-256; a pin takes precedence over the CA. Left empty with no CA, the system trust store decides and an unknown certificate is offered on first connect.",
                    )}
                  >
                    <TextField
                      value={form.webdav.certificateFingerprint ?? ""}
                      onChange={(e) =>
                        patchWebDav({ certificateFingerprint: e.target.value.trim() || null })
                      }
                      placeholder="sha256:…"
                      error={
                        touched &&
                        form.webdav.certificateFingerprint !== null &&
                        !isFingerprint(form.webdav.certificateFingerprint)
                      }
                      slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
                    />
                  </Field>
                </>
              )}
            </SectionCard>
          ) : (
            <AddSectionButton
              label={tr("Add WebDAV")}
              onClick={() => set("webdav", emptyWebDav())}
            />
          )}
        </Box>

        <TagsPopover
          anchor={tagAnchor}
          vaultId={vaultId}
          selected={selectedTagIds}
          allowCreate
          onCreated={(id) => set("tagIds", [...form.tagIds, id])}
          onToggle={(t, on) =>
            set("tagIds", on ? [...form.tagIds, t.id] : form.tagIds.filter((x) => x !== t.id))
          }
          onDeleted={(t) => setForm((f) => ({ ...f, tagIds: f.tagIds.filter((x) => x !== t.id) }))}
          onClose={() => setTagAnchor(null)}
        />

        <ProxyDialog
          open={dialog === "proxy"}
          vaultId={vaultId}
          onClose={() => setDialog(null)}
          onCreated={(id) => set("proxyId", id)}
        />
        <ChainDialog
          open={dialog === "chain"}
          vaultId={vaultId}
          excludeHostId={id}
          onClose={() => setDialog(null)}
          onCreated={(id) => set("hostChainId", id)}
        />

        <ConfirmDialog
          open={confirmDelete}
          title={tr("Delete host?")}
          danger
          confirmLabel={tr("Delete")}
          busy={del.isPending}
          onCancel={() => setConfirmDelete(false)}
          onConfirm={onDelete}
        >
          {tr("“{name}” and its inline credentials will be removed from this device.", {
            name: form.label || form.address,
          })}
        </ConfirmDialog>
      </SidePanel>
    </CompactFields.Provider>
  );
}

/** "SSH on [22] port" — the section title doubles as the port field. */
function PortTitle({
  name,
  value,
  placeholder,
  onChange,
}: {
  name: string;
  value: number | null;
  placeholder: string;
  onChange: (v: number | null) => void;
}) {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
      <Typography variant="subtitle2">
        {name} {tr("on")}
      </Typography>
      <TextField
        type="number"
        size="small"
        value={value ?? ""}
        onChange={(e) => onChange(clampPort(e.target.value))}
        placeholder={placeholder}
        aria-label={tr("{name} port", { name })}
        slotProps={{
          htmlInput: { min: 1, max: 65535, sx: { textAlign: "center", px: 0.5 } },
          input: { sx: { fontFamily: monoFontFamily, height: 28 } },
        }}
        sx={{ width: 72 }}
      />
      <Typography variant="subtitle2">{tr("port")}</Typography>
    </Box>
  );
}

/** Full-width tonal "+ Add Telnet" row between the section cards. */
function AddSectionButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <Button
      variant="tonal"
      size="large"
      startIcon={<AddCircleOutlineRoundedIcon />}
      onClick={onClick}
      sx={{ borderRadius: 2, height: 44 }}
    >
      {label}
    </Button>
  );
}

/** Colour scheme the terminal opens with for this section; empty follows Settings. */
function ThemeField({
  value,
  onChange,
}: {
  value: string | null;
  onChange: (v: string | null) => void;
}) {
  const custom = useCustomThemes();
  const all = allTerminalThemes();
  const dark = all.filter((t) => t.dark && !custom.includes(t));
  const light = all.filter((t) => !t.dark && !custom.includes(t));
  const current = all.find((t) => t.id === value) ?? null;
  return (
    <TextField
      select
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value === "" ? null : e.target.value)}
      slotProps={{
        select: {
          displayEmpty: true,
          renderValue: () => (
            <Box sx={{ display: "flex", alignItems: "center" }}>
              {current ? (
                <>
                  <ThemeSwatch background={current.background} ansi={current.ansi} />
                  {current.name}
                </>
              ) : (
                <Box component="span" sx={{ color: "text.disabled" }}>
                  {tr("Terminal theme · app default")}
                </Box>
              )}
            </Box>
          ),
        },
      }}
    >
      <MenuItem value="">
        <em>{tr("App default")}</em>
      </MenuItem>
      <ListSubheader disableSticky>{tr("Dark")}</ListSubheader>
      {dark.map((t) => (
        <MenuItem key={t.id} value={t.id}>
          <ThemeSwatch background={t.background} ansi={t.ansi} />
          {t.name}
        </MenuItem>
      ))}
      <ListSubheader disableSticky>{tr("Light")}</ListSubheader>
      {light.map((t) => (
        <MenuItem key={t.id} value={t.id}>
          <ThemeSwatch background={t.background} ansi={t.ansi} />
          {t.name}
        </MenuItem>
      ))}
      {custom.length > 0 && <ListSubheader disableSticky>{tr("My schemes")}</ListSubheader>}
      {custom.map((t) => (
        <MenuItem key={t.id} value={t.id}>
          <ThemeSwatch background={t.background} ansi={t.ansi} />
          {t.name}
        </MenuItem>
      ))}
    </TextField>
  );
}

function ThemeSwatch({ background, ansi }: { background: string; ansi: readonly string[] }) {
  return (
    <Box
      sx={{
        display: "inline-flex",
        gap: "2px",
        p: "3px",
        mr: 1.25,
        borderRadius: "4px",
        bgcolor: background,
        border: 1,
        borderColor: "border.light",
      }}
    >
      {[1, 2, 3, 4, 5, 6].map((i) => (
        <Box key={i} sx={{ width: 6, height: 10, borderRadius: "1px", bgcolor: ansi[i] }} />
      ))}
    </Box>
  );
}
