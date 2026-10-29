import { useMemo, useState } from "react";
import { tr, trx } from "@/i18n";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  FormControlLabel,
  IconButton,
  Link,
  List,
  ListItem,
  ListItemAvatar,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import HubOutlinedIcon from "@mui/icons-material/HubOutlined";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { bridgesApi, vaultsApi } from "@/api/endpoints";
import { Navigate } from "react-router";
import { queryKeys, useServerInfo } from "@/api/hooks";
import type { Bridge, BridgeCredentials, BridgeVault, Vault } from "@/api/types";
import { UnlockCancelled, withStepUp } from "@/auth/unlock";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CopyField } from "@/components/CopyField";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { PageHeader } from "@/components/PageHeader";
import { RoleChip } from "@/components/RoleChip";
import { Section } from "@/components/Section";
import { Paged } from "@/components/Pager";
import { useSnackbar } from "@/components/Snackbar";
import { formatDateTime, formatRelative } from "@/components/format";
import { generateKeyPair, loadCrypto } from "@/crypto";
import { bridgeEligible, sealVaultKeysFor } from "@/vaults/keys";

const DOCS_URL = "https://github.com/termoso/termoso/blob/main/docs/API_BRIDGE.md";
const IMAGE = "ghcr.io/termoso/termoso-bridge:latest";
const MAX_NAME = 100;

function credentialsFileName(bridge: Bridge): string {
  const slug = bridge.name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `termoso-bridge-${slug || bridge.id.slice(0, 8)}.json`;
}

function dockerSnippet(file: string): string {
  return [
    "docker run -d --name termoso-bridge --restart unless-stopped \\",
    "  -p 127.0.0.1:8080:8080 \\",
    `  -v "$PWD/${file}:/etc/termoso/bridge.json:ro" \\`,
    '  -e TERMOSO_BRIDGE_API_KEY="$(openssl rand -hex 32)" \\',
    `  ${IMAGE}`,
  ].join("\n");
}

function downloadJson(name: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function isPending(v: BridgeVault): boolean {
  return !v.sealed_key;
}

/** Checkbox list of vaults the caller can hand to a bridge. */
function VaultPicker({
  vaults,
  selected,
  onToggle,
  bridge,
}: {
  vaults: Vault[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  bridge?: Bridge;
}) {
  if (vaults.length === 0) {
    return (
      <Alert severity="info">
        {tr(
          "No vault is available: a bridge needs a vault where you are an editor or manager and hold the current key.",
        )}
      </Alert>
    );
  }
  return (
    <List dense disablePadding sx={{ bgcolor: "surface.high", borderRadius: 2 }}>
      {vaults.map((v) => {
        const assigned = bridge?.vaults.find((b) => b.vault_id === v.id);
        return (
          <ListItem key={v.id} disablePadding>
            <ListItemButton onClick={() => onToggle(v.id)} dense>
              <ListItemIcon sx={{ minWidth: 36 }}>
                <Checkbox edge="start" checked={selected.has(v.id)} tabIndex={-1} disableRipple />
              </ListItemIcon>
              <ListItemText
                primary={
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                    {v.name}
                    <RoleChip role={v.my_role} />
                    {assigned && isPending(assigned) && (
                      <Chip size="small" color="warning" label={tr("Key rotated — will re-seal")} />
                    )}
                  </Box>
                }
                secondary={v.kind === "team" ? tr("Team vault") : tr("Personal vault")}
              />
            </ListItemButton>
          </ListItem>
        );
      })}
    </List>
  );
}

function useToggleSet(initial: Iterable<string>) {
  const [set, setSet] = useState(() => new Set(initial));
  const toggle = (id: string) =>
    setSet((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return [set, toggle] as const;
}

/**
 * Create flow: keypair + sealing happen in this tab, the server gets the public key
 * and sealed boxes only; the private key leaves the page solely inside the file.
 */
function CreateBridgeDialog({
  vaults,
  onClose,
  onCreated,
}: {
  vaults: Vault[];
  onClose: () => void;
  onCreated: (creds: BridgeCredentials, bridge: Bridge) => void;
}) {
  const snack = useSnackbar();
  const [name, setName] = useState("");
  const [selected, toggle] = useToggleSet([]);
  const chosen = vaults.filter((v) => selected.has(v.id));

  const create = useMutation({
    mutationFn: async () => {
      await loadCrypto();
      const pair = generateKeyPair();
      const sealed = await sealVaultKeysFor(pair.publicKey, chosen);
      const r = await withStepUp(() => bridgesApi.create(name.trim(), pair.publicKey, sealed));
      const creds: BridgeCredentials = {
        version: 1,
        server: window.location.origin,
        bridge_id: r.bridge.id,
        private_key: pair.privateKey,
        token: r.token,
      };
      return { creds, bridge: r.bridge };
    },
    onSuccess: ({ creds, bridge }) => onCreated(creds, bridge),
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });

  const canCreate = name.trim().length > 0 && name.trim().length <= MAX_NAME && chosen.length > 0;

  return (
    <Dialog open onClose={create.isPending ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{tr("New API bridge")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <TextField
            label={tr("Name")}
            placeholder={tr("ansible-prod")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            fullWidth
            slotProps={{ htmlInput: { maxLength: MAX_NAME } }}
            helperText={tr(
              "Shown here and in the team activity log; the bridge appears as a device.",
            )}
          />
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {tr("Vaults the bridge may write to")}
            </Typography>
            <VaultPicker vaults={vaults} selected={selected} onToggle={toggle} />
          </Box>
          <Alert severity="info" icon={<LockOutlinedIcon fontSize="inherit" />}>
            {tr(
              "The bridge key pair is generated in this browser. Each selected vault key is sealed to it here; the server stores only the sealed boxes and never sees the private key or the vault contents.",
            )}
          </Alert>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} disabled={create.isPending} color="inherit">
          {tr("Cancel")}
        </Button>
        <Button
          variant="contained"
          onClick={() => create.mutate()}
          disabled={!canCreate || create.isPending}
        >
          {tr("Create bridge")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Shown exactly once: the file holds the bridge private key and token. */
function CredentialsDialog({
  creds,
  bridge,
  onClose,
}: {
  creds: BridgeCredentials;
  bridge: Bridge;
  onClose: () => void;
}) {
  const [downloaded, setDownloaded] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const file = credentialsFileName(bridge);
  return (
    <Dialog open maxWidth="sm" fullWidth>
      <DialogTitle>{tr("Download bridge credentials")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <Alert severity="warning">
            {trx(
              "This file is shown {v1}. It contains the bridge private key and its access token; the server keeps neither. Store it like an SSH private key and never commit it. If it is lost, revoke the bridge and create a new one.",
              { v1: <strong>{tr("once")}</strong> },
            )}
          </Alert>
          <Button
            variant="contained"
            size="large"
            startIcon={<DownloadRoundedIcon />}
            onClick={() => {
              downloadJson(file, creds);
              setDownloaded(true);
            }}
            sx={{
              alignSelf: "flex-start",
              maxWidth: "100%",
              textAlign: "left",
              wordBreak: "break-all",
            }}
          >
            {downloaded ? tr("Download {file} again", { file }) : tr("Download {file}", { file })}
          </Button>
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {tr("Run it next to your automation")}
            </Typography>
            <CopyField value={dockerSnippet(file)} multiline />
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
              {trx(
                "Keep the port bound to localhost or set {v1}; callers then send it as {v2}. Full REST reference in the  {v3} .",
                {
                  v1: <code>{tr("TERMOSO_BRIDGE_API_KEY")}</code>,
                  v2: <code>{tr("Authorization: Bearer")}</code>,
                  v3: (
                    <Link href={DOCS_URL} target="_blank" rel="noreferrer">
                      {tr("API Bridge docs")}
                    </Link>
                  ),
                },
              )}
            </Typography>
          </Box>
          <FormControlLabel
            control={
              <Checkbox
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                disabled={!downloaded}
              />
            }
            label={tr("I have saved the file in a safe place")}
          />
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button variant="contained" onClick={onClose} disabled={!confirmed}>
          {tr("Done")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Add/remove vaults or re-seal after a rotation; every kept vault is re-sealed with its current key. */
function EditVaultsDialog({
  bridge,
  vaults,
  onClose,
  onSaved,
}: {
  bridge: Bridge;
  vaults: Vault[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const snack = useSnackbar();
  const [selected, toggle] = useToggleSet(bridge.vaults.map((v) => v.vault_id));
  const chosen = vaults.filter((v) => selected.has(v.id));
  const eligibleIds = useMemo(() => new Set(vaults.map((v) => v.id)), [vaults]);
  const dropped = bridge.vaults.filter((v) => !eligibleIds.has(v.vault_id));

  const save = useMutation({
    mutationFn: async () => {
      const sealed = await sealVaultKeysFor(bridge.public_key, chosen);
      return withStepUp(() => bridgesApi.setVaults(bridge.id, sealed));
    },
    onSuccess: () => {
      snack.notify(tr("Bridge vaults updated"));
      onSaved();
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });

  return (
    <Dialog open onClose={save.isPending ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{trx("Vaults for “{name}”", { name: bridge.name })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <VaultPicker vaults={vaults} selected={selected} onToggle={toggle} bridge={bridge} />
          {dropped.length > 0 && (
            <Alert severity="warning">
              {trx(
                "You no longer hold a writable key for {v1}; saving removes {v2} from the bridge.",
                {
                  v1: dropped.map((v) => `“${v.name}”`).join(", "),
                  v2: dropped.length === 1 ? "it" : "them",
                },
              )}
            </Alert>
          )}
          <DialogContentText variant="body2">
            {tr(
              "Saving seals the current key of every selected vault to the bridge in this browser, so it also clears “key rotated” states. Unselected vaults are removed immediately.",
            )}
          </DialogContentText>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} disabled={save.isPending} color="inherit">
          {tr("Cancel")}
        </Button>
        <Button variant="contained" onClick={() => save.mutate()} disabled={save.isPending}>
          {tr("Save")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function BridgesPage() {
  const info = useServerInfo();
  const qc = useQueryClient();
  const snack = useSnackbar();
  const bridges = useQuery({ queryKey: queryKeys.bridges, queryFn: bridgesApi.list });
  const vaults = useQuery({ queryKey: queryKeys.vaults, queryFn: vaultsApi.list });
  const [creating, setCreating] = useState(false);
  const [issued, setIssued] = useState<{ creds: BridgeCredentials; bridge: Bridge } | null>(null);
  const [editing, setEditing] = useState<Bridge | null>(null);
  const [revoking, setRevoking] = useState<Bridge | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: queryKeys.bridges });

  const revoke = useMutation({
    mutationFn: (id: string) => withStepUp(() => bridgesApi.revoke(id)),
    onSuccess: async () => {
      setRevoking(null);
      await refresh();
      snack.notify(tr("Bridge revoked"));
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });

  if (info.data?.features.bridges === false) return <Navigate to="/account" replace />;
  if (bridges.isPending || vaults.isPending) return <Loading />;
  if (bridges.isError) return <Alert severity="error">{errorMessage(bridges.error)}</Alert>;
  if (vaults.isError) return <Alert severity="error">{errorMessage(vaults.error)}</Alert>;

  const eligible = bridgeEligible(vaults.data.vaults);
  const list = [...bridges.data.bridges].sort((a, b) => b.created_at.localeCompare(a.created_at));

  return (
    <>
      <PageHeader
        title={tr("API Bridge")}
        subtitle={tr(
          "A container in your own infrastructure that lets scripts and CI manage hosts and groups over a Termius-compatible REST API. It encrypts locally; the server only ever relays sealed data.",
        )}
        actions={
          <Button
            variant="contained"
            startIcon={<AddRoundedIcon />}
            onClick={() => setCreating(true)}
            disabled={eligible.length === 0}
          >
            {tr("New bridge")}
          </Button>
        }
      />

      <Section title={`${list.length} ${list.length === 1 ? "bridge" : "bridges"}`} disablePadding>
        {list.length === 0 ? (
          <EmptyState
            icon={<HubOutlinedIcon />}
            title={tr("No API bridges yet")}
            description={
              eligible.length === 0
                ? tr("You need a vault where you are an editor or manager to create one.")
                : tr(
                    "Create a bridge, download its credentials once and run the container next to your automation.",
                  )
            }
          />
        ) : (
          <Paged items={list}>
            {(rows) => (
              <List disablePadding>
                {rows.map((b) => {
                  const pending = b.vaults.filter(isPending);
                  return (
                    <ListItem
                      key={b.id}
                      divider
                      alignItems="flex-start"
                      secondaryAction={
                        <Stack direction="row" spacing={0.5}>
                          <Tooltip title={tr("Vaults")}>
                            <IconButton
                              onClick={() => setEditing(b)}
                              aria-label={tr("Edit vaults")}
                            >
                              <KeyRoundedIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={tr("Revoke bridge")}>
                            <IconButton
                              edge="end"
                              color="error"
                              onClick={() => setRevoking(b)}
                              aria-label={tr("Revoke bridge")}
                            >
                              <DeleteOutlineRoundedIcon />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      }
                    >
                      <ListItemAvatar>
                        <Avatar
                          variant="rounded"
                          sx={{
                            width: 36,
                            height: 36,
                            borderRadius: 2,
                            bgcolor: "surface.highest",
                            color: pending.length ? "warning.main" : "primary.main",
                            "& svg": { fontSize: 20 },
                          }}
                        >
                          <HubOutlinedIcon />
                        </Avatar>
                      </ListItemAvatar>
                      <ListItemText
                        disableTypography
                        primary={
                          <Box
                            sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}
                          >
                            <Typography variant="body1">{b.name}</Typography>
                            {pending.length > 0 && (
                              <Chip
                                size="small"
                                color="warning"
                                label={tr("{length} {v1} rotated — re-seal", {
                                  length: pending.length,
                                  v1: pending.length === 1 ? "key" : "keys",
                                })}
                                onClick={() => setEditing(b)}
                              />
                            )}
                          </Box>
                        }
                        secondary={
                          <Box sx={{ mt: 0.5, pr: 10 }}>
                            <Typography variant="body2" color="text.secondary">
                              {trx("{v1} {v2}Created {v3}", {
                                v1: b.last_used_at
                                  ? b.last_ip
                                    ? tr("Last used {v1} from {v2}", {
                                        v1: formatRelative(b.last_used_at),
                                        v2: b.last_ip,
                                      })
                                    : tr("Last used {v1}", { v1: formatRelative(b.last_used_at) })
                                  : tr("Never used"),
                                v2: " · ",
                                v3: formatDateTime(b.created_at),
                              })}
                            </Typography>
                            <Box sx={{ display: "flex", gap: 0.75, flexWrap: "wrap", mt: 1 }}>
                              {b.vaults.length === 0 && (
                                <Chip size="small" variant="outlined" label={tr("No vaults")} />
                              )}
                              {b.vaults.map((v) => (
                                <Chip
                                  key={v.vault_id}
                                  size="small"
                                  variant="outlined"
                                  color={isPending(v) ? "warning" : "default"}
                                  icon={<LockOutlinedIcon />}
                                  label={`${v.name} · ${v.role}${isPending(v) ? tr(" · pending") : ""}`}
                                />
                              ))}
                            </Box>
                          </Box>
                        }
                      />
                    </ListItem>
                  );
                })}
              </List>
            )}
          </Paged>
        )}
      </Section>

      <Section
        title={tr("How it stays private")}
        description={tr(
          "The central server never receives host addresses, usernames, passwords or keys from a bridge.",
        )}
      >
        <Typography variant="body2" color="text.secondary" component="div">
          <ol style={{ margin: 0, paddingLeft: "1.25em" }}>
            <li>{tr("You create the bridge here: a key pair is generated in this browser.")}</li>
            <li>
              {tr(
                "Your copy of each chosen vault key is sealed to that key pair; only sealed boxes and the public key reach the server.",
              )}
            </li>
            <li>
              {trx(
                "The credentials file (private key + token) is downloaded once and mounted into the  {v1} container.",
                { v1: <code>{tr("termoso-bridge")}</code> },
              )}
            </li>
            <li>
              {tr(
                "Your scripts talk plaintext to the container on your network; it encrypts with the vault key and pushes ciphertext through ordinary sync.",
              )}
            </li>
            <li>
              {tr(
                "Revoking a bridge kills its token at once. After a vault key rotation the bridge pauses writes to that vault until you re-seal the new key here.",
              )}
            </li>
          </ol>
          <Box sx={{ mt: 1.5 }}>
            <Link href={DOCS_URL} target="_blank" rel="noreferrer">
              {tr("REST reference and deployment guide")}
            </Link>
          </Box>
        </Typography>
      </Section>

      {creating && (
        <CreateBridgeDialog
          vaults={eligible}
          onClose={() => setCreating(false)}
          onCreated={async (creds, bridge) => {
            setCreating(false);
            setIssued({ creds, bridge });
            await refresh();
          }}
        />
      )}
      {issued && (
        <CredentialsDialog
          creds={issued.creds}
          bridge={issued.bridge}
          onClose={() => setIssued(null)}
        />
      )}
      {editing && (
        <EditVaultsDialog
          key={editing.id}
          bridge={editing}
          vaults={eligible}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await refresh();
          }}
        />
      )}
      <ConfirmDialog
        open={revoking !== null}
        title={tr("Revoke bridge?")}
        confirmLabel={tr("Revoke")}
        danger
        busy={revoke.isPending}
        onCancel={() => setRevoking(null)}
        onConfirm={() => {
          if (revoking) revoke.mutate(revoking.id);
        }}
      >
        {trx(
          "“{name}” stops working immediately: its token is invalidated and its sealed vault keys are deleted. Hosts it already created stay in the vaults.",
          { name: revoking?.name },
        )}
      </ConfirmDialog>
    </>
  );
}
