import { useState } from "react";
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Switch,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import { save as saveFile } from "@tauri-apps/plugin-dialog";
import { useSnackbar } from "@/components/Snackbar";
import { Mono, SettingRow } from "@/components/ui";
import * as ipc from "@/ipc/commands";
import { errorMessage, type LocalVault } from "@/ipc/types";
import { tr, trn, trx, msg } from "@/i18n";
import { requirePerm } from "@/team/perms";

const COLUMNS: [string, string][] = [
  [msg("Groups"), msg("group path, joined with /")],
  [msg("Label"), msg("host name")],
  [msg("Tags"), msg("comma separated")],
  [msg("Hostname/IP"), msg("address")],
  [msg("Protocol"), msg("ssh or telnet")],
  [msg("Port"), msg("effective port")],
  [msg("Username"), msg("effective username (own or inherited)")],
  [msg("Password"), msg("empty unless enabled below")],
];

type Format = "csv" | "ssh_config" | "ansible";

const FORMAT_ORDER: Format[] = ["csv", "ssh_config", "ansible"];
const FORMATS: Record<Format, { label: string; ext: string; filter: string }> = {
  csv: { label: msg("CSV"), ext: "csv", filter: "CSV" },
  ssh_config: { label: msg("OpenSSH config"), ext: "", filter: "ssh_config" },
  ansible: { label: msg("Ansible inventory"), ext: "ini", filter: "INI" },
};

/**
 * Hosts of the current vault as Termius-compatible CSV, an OpenSSH `ssh_config`
 * or an Ansible INI inventory. Keys, certificates and proxies never leave the
 * app; only the CSV can carry passwords.
 */
export function ExportCsvDialog({
  open,
  vault,
  hostCount,
  onClose,
}: {
  open: boolean;
  vault: LocalVault | null;
  hostCount: number;
  onClose: () => void;
}) {
  const snackbar = useSnackbar();
  const [passwords, setPasswords] = useState(false);
  const [format, setFormat] = useState<Format>("csv");
  const [busy, setBusy] = useState(false);

  const close = () => {
    setPasswords(false);
    setFormat("csv");
    onClose();
  };
  const fmt = FORMATS[format];

  const run = async () => {
    if (!vault) return;
    const slug = vault.name.toLowerCase().replace(/\s+/g, "-");
    const path = await saveFile({
      title: tr("Export hosts"),
      defaultPath:
        format === "ssh_config" ? `termoso-${slug}-ssh_config` : `termoso-${slug}-hosts.${fmt.ext}`,
      filters: fmt.ext ? [{ name: fmt.filter, extensions: [fmt.ext] }] : [],
    });
    if (!path) return;
    setBusy(true);
    try {
      if (!requirePerm(vault.id, "export.vault")) return;
      if (format === "csv" && passwords && !requirePerm(vault.id, "secrets.reveal")) return;
      const r =
        format === "csv"
          ? await ipc.hostsExportCsv(vault.id, passwords, path)
          : await ipc.hostsExportAs(vault.id, format, path);
      snackbar.notify(
        trn(r.hosts, "Exported {count} host", "Exported {count} hosts") +
          (r.passwordsIncluded ? ` ${tr("with passwords")}` : ""),
      );
      close();
    } catch (e) {
      snackbar.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} maxWidth="sm" fullWidth>
      <DialogTitle>{tr("Export hosts")}</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
        <ToggleButtonGroup
          exclusive
          size="small"
          value={format}
          onChange={(_, v: Format | null) => v && setFormat(v)}
          aria-label={tr("Format")}
        >
          {FORMAT_ORDER.map((id) => (
            <ToggleButton key={id} value={id}>
              {tr(FORMATS[id].label)}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
        <Typography variant="body2" color="text.secondary">
          {format === "csv" &&
            trx(
              trn(
                hostCount,
                "{count} host from {vault} in the same column layout Termius and Termoso import. SSH keys, certificates, proxies and jump chains are not part of the file.",
                "{count} hosts from {vault} in the same column layout Termius and Termoso import. SSH keys, certificates, proxies and jump chains are not part of the file.",
              ),
              { vault: <b>{vault?.name ?? "—"}</b> },
            )}
          {format === "ssh_config" &&
            trx(
              tr(
                "SSH hosts of {vault} as Host blocks (HostName, Port, User, ProxyJump for jump chains), ready to include from ~/.ssh/config. Passwords and keys are never written.",
              ),
              { vault: <b>{vault?.name ?? "—"}</b> },
            )}
          {format === "ansible" &&
            trx(
              tr(
                "SSH hosts of {vault} as an INI inventory with ansible_host/ansible_port/ansible_user, grouped by folder and tag. Passwords and keys are never written.",
              ),
              { vault: <b>{vault?.name ?? "—"}</b> },
            )}
        </Typography>
        {format === "csv" && (
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: "auto 1fr",
              columnGap: 2,
              rowGap: 0.25,
              px: 1.5,
              py: 1,
              borderRadius: 2,
              bgcolor: "surface.high",
            }}
          >
            {COLUMNS.map(([name, hint]) => (
              <Box key={name} sx={{ display: "contents" }}>
                <Mono sx={{ fontSize: 12 }}>{name}</Mono>
                <Typography variant="caption" color="text.secondary">
                  {tr(hint)}
                </Typography>
              </Box>
            ))}
          </Box>
        )}
        {format === "csv" && (
          <SettingRow
            label={tr("Include passwords")}
            hint={tr("Writes host passwords as plaintext into the file.")}
            control={
              <Switch checked={passwords} onChange={(e) => setPasswords(e.target.checked)} />
            }
            last
          />
        )}
        {format === "csv" && passwords && (
          <Alert severity="warning" variant="outlined">
            {tr(
              "The CSV will contain plaintext passwords. Store it somewhere safe and delete it after importing elsewhere.",
            )}
          </Alert>
        )}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={close}>{tr("Cancel")}</Button>
        <Button variant="contained" onClick={run} disabled={busy || !vault || hostCount === 0}>
          {tr("Export…")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
