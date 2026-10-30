import { useMemo, useState, type ReactNode } from "react";
import {
  Box,
  Button,
  Checkbox,
  Collapse,
  Dialog,
  IconButton,
  InputBase,
  Radio,
  Typography,
} from "@mui/material";
import { useQueryClient } from "@tanstack/react-query";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import SwapHorizRoundedIcon from "@mui/icons-material/SwapHorizRounded";
import GroupsRoundedIcon from "@mui/icons-material/GroupsRounded";
import PersonRoundedIcon from "@mui/icons-material/PersonRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import ChevronRightRoundedIcon from "@mui/icons-material/ChevronRightRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import { useSnackbar } from "@/components/Snackbar";
import * as ipc from "@/ipc/commands";
import { useHosts, usePfRules, useSshKeys } from "@/ipc/hooks";
import { errorMessage, type LocalVault, type Uuid } from "@/ipc/types";
import { tr, trn, trx } from "@/i18n";

type Category = "hosts" | "keys" | "forwarding";

interface Item {
  id: Uuid;
  label: string;
  hint: string;
}

/**
 * “Share data with your team”: move personal hosts / keys / forwarding rules into a team vault
 * with an explicit choice of whether credentials travel along (Termius' share-data step).
 * Credentials themselves never reach this layer — Rust strips or re-seals them.
 */
export function ShareDataDialog({
  open,
  source,
  target,
  onClose,
  onDone,
}: {
  open: boolean;
  /** Personal vault the data comes from. */
  source: LocalVault | null;
  /** Team vault the data goes to. */
  target: LocalVault | null;
  onClose: () => void;
  onDone?: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      {source && target && (
        <Body source={source} target={target} onClose={onClose} onDone={onDone} />
      )}
    </Dialog>
  );
}

function Body({
  source,
  target,
  onClose,
  onDone,
}: {
  source: LocalVault;
  target: LocalVault;
  onClose: () => void;
  onDone?: () => void;
}) {
  const snackbar = useSnackbar();
  const qc = useQueryClient();
  const hosts = useHosts(source.id);
  const sshKeys = useSshKeys(source.id);
  const rules = usePfRules(source.id);

  const [shared, setShared] = useState<boolean | null>(null);
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Record<Category, boolean>>({
    hosts: false,
    keys: false,
    forwarding: false,
  });
  const [excluded, setExcluded] = useState<ReadonlySet<Uuid>>(() => new Set());
  const [busy, setBusy] = useState(false);

  const categories = useMemo(() => {
    const list: { key: Category; title: string; icon: ReactNode; items: Item[] }[] = [
      {
        key: "hosts",
        title: tr("Hosts"),
        icon: <DnsRoundedIcon fontSize="small" />,
        items: (hosts.data ?? []).map((h) => ({
          id: h.id,
          label: h.label,
          hint: [h.username, h.address].filter(Boolean).join("@"),
        })),
      },
      {
        key: "keys",
        title: tr("Keys"),
        icon: <KeyRoundedIcon fontSize="small" />,
        items: (sshKeys.data ?? []).map((k) => ({
          id: k.id,
          label: k.label,
          hint: k.fingerprint,
        })),
      },
      {
        key: "forwarding",
        title: tr("Port forwarding"),
        icon: <SwapHorizRoundedIcon fontSize="small" />,
        items: (rules.data ?? []).map((r) => ({
          id: r.id,
          label: r.label,
          hint: r.hostLabel,
        })),
      },
    ];
    return list.filter((c) => c.items.length > 0);
  }, [hosts.data, sshKeys.data, rules.data]);

  // Keys are credentials: with “own credentials” they stay in the personal vault.
  const keysLocked = shared === false;
  const q = filter.trim().toLowerCase();
  const visible = (items: Item[]) =>
    q ? items.filter((i) => `${i.label} ${i.hint}`.toLowerCase().includes(q)) : items;
  const isOn = (c: Category, id: Uuid) => !(c === "keys" && keysLocked) && !excluded.has(id);
  const selectedIn = (c: Category, items: Item[]) => items.filter((i) => isOn(c, i.id));
  const selectedTotal = categories.reduce((n, c) => n + selectedIn(c.key, c.items).length, 0);

  const toggleItem = (id: Uuid) =>
    setExcluded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const toggleCategory = (items: Item[]) =>
    setExcluded((prev) => {
      const next = new Set(prev);
      const all = items.every((i) => !next.has(i.id));
      for (const i of items) {
        if (all) next.add(i.id);
        else next.delete(i.id);
      }
      return next;
    });

  const run = async () => {
    if (shared === null) return;
    setBusy(true);
    try {
      let moved = 0;
      const pick = (c: Category) =>
        selectedIn(c, categories.find((x) => x.key === c)?.items ?? []).map((i) => i.id);
      const hostIds = pick("hosts");
      // Hosts are copied first so forwarding rules find their host in the team
      // vault (reused by label + address); the originals go last.
      if (hostIds.length > 0) {
        await ipc.hostsCopyToVault(hostIds, target.id, false, shared);
        moved += hostIds.length;
      }
      for (const id of pick("forwarding")) {
        await ipc.pfCopyToVault(id, target.id, true);
        moved += 1;
      }
      for (const id of pick("keys")) {
        await ipc.keyCopyToVault(id, target.id, true);
        moved += 1;
      }
      if (hostIds.length > 0) await ipc.hostsDelete(hostIds);
      await Promise.all(
        ["hosts", "groups", "tags", "identities", "sshKeys", "pfRules", "hostForm"].map((k) =>
          qc.invalidateQueries({ queryKey: [k] }),
        ),
      );
      snackbar.notify(
        trn(moved, "Moved {count} item to {name}", "Moved {count} items to {name}", {
          name: target.name,
        }) + (shared ? "" : ` — ${tr("members use their own credentials")}`),
      );
      onDone?.();
      onClose();
    } catch (e) {
      snackbar.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box sx={{ display: "flex", flexDirection: "column" }}>
      <Box sx={{ display: "flex", gap: 2, p: 2 }}>
        <Box
          sx={{
            flex: "0 0 380px",
            bgcolor: "surface.high",
            borderRadius: 2.5,
            p: 2.5,
            display: "flex",
            flexDirection: "column",
            gap: 1.5,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            {tr("Share data with your team")}
          </Typography>
          <Typography variant="body2" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            {trx("Move your data to the {vault} to share.", {
              vault: <VaultChip name={target.name} team />,
            })}
          </Typography>
          <Box sx={{ borderTop: "1px solid", borderColor: "divider", my: 0.5 }} />
          <Typography variant="caption" color="text.secondary">
            {tr("What access is used in your team?")}
          </Typography>
          <AccessChoice
            selected={shared === true}
            onSelect={() => setShared(true)}
            title={tr("Members share one set of credentials")}
            text={
              <>
                {trx("Username, passwords and keys will be shared in the {vault}", {
                  vault: <VaultChip name={target.name} team />,
                })}
              </>
            }
          />
          <AccessChoice
            selected={shared === false}
            onSelect={() => setShared(false)}
            title={tr("Members use their own credentials")}
            text={
              <>
                {trx("Credentials are not shared and stored in {vault}", {
                  vault: <VaultChip name={tr("Personal vaults")} />,
                })}
              </>
            }
          />
        </Box>

        <Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 1 }}>
          <InputBase
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={tr("Filter")}
            sx={{
              px: 1.25,
              height: 36,
              borderRadius: 1.5,
              border: "1px solid",
              borderColor: "divider",
              fontSize: 14,
            }}
          />
          <Typography variant="body2" sx={{ fontWeight: 600, py: 0.5 }}>
            {trn(selectedTotal, "{count} item selected", "{count} items selected")}
          </Typography>
          <Box sx={{ borderTop: "1px solid", borderColor: "divider" }} />
          {categories.length === 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
              {tr("Nothing to share yet — {vault} is empty.", { vault: source.name })}
            </Typography>
          )}
          <Box sx={{ overflowY: "auto", maxHeight: 360 }}>
            {categories.map((c) => {
              const items = visible(c.items);
              const on = selectedIn(c.key, c.items).length;
              const locked = c.key === "keys" && keysLocked;
              return (
                <Box key={c.key}>
                  <Box
                    sx={{
                      display: "flex",
                      alignItems: "center",
                      gap: 0.5,
                      height: 40,
                      opacity: locked ? 0.5 : 1,
                    }}
                  >
                    <IconButton
                      size="small"
                      onClick={() => setOpen((o) => ({ ...o, [c.key]: !o[c.key] }))}
                      aria-label={open[c.key] ? tr("Hide details") : tr("Show details")}
                      aria-expanded={open[c.key]}
                    >
                      {open[c.key] ? (
                        <ExpandMoreRoundedIcon fontSize="small" />
                      ) : (
                        <ChevronRightRoundedIcon fontSize="small" />
                      )}
                    </IconButton>
                    {c.icon}
                    <Typography variant="body2" sx={{ fontWeight: 600, flex: 1, ml: 0.5 }}>
                      {c.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {locked ? tr("kept personal") : on}
                    </Typography>
                    <Checkbox
                      size="small"
                      icon={<CheckCircleRoundedIcon sx={{ opacity: 0.3 }} />}
                      checkedIcon={<CheckCircleRoundedIcon />}
                      checked={on === c.items.length && on > 0}
                      indeterminate={on > 0 && on < c.items.length}
                      disabled={locked}
                      onChange={() => toggleCategory(c.items)}
                    />
                  </Box>
                  <Collapse in={open[c.key]}>
                    {items.map((i) => (
                      <Box
                        key={i.id}
                        sx={{
                          display: "flex",
                          alignItems: "center",
                          gap: 1,
                          pl: 5,
                          height: 36,
                          opacity: locked ? 0.5 : 1,
                        }}
                      >
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography variant="body2" noWrap>
                            {i.label}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" noWrap>
                            {i.hint}
                          </Typography>
                        </Box>
                        <Checkbox
                          size="small"
                          checked={isOn(c.key, i.id)}
                          disabled={locked}
                          onChange={() => toggleItem(i.id)}
                        />
                      </Box>
                    ))}
                    {items.length === 0 && (
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: "block", pl: 5, py: 1 }}
                      >
                        {tr("No matches")}
                      </Typography>
                    )}
                  </Collapse>
                </Box>
              );
            })}
          </Box>
        </Box>
      </Box>

      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          px: 3,
          py: 1.5,
          borderTop: "1px solid",
          borderColor: "divider",
        }}
      >
        <Button color="inherit" onClick={onClose} disabled={busy}>
          {tr("Do it later")}
        </Button>
        <Button
          variant="contained"
          onClick={() => void run()}
          disabled={busy || shared === null || selectedTotal === 0}
        >
          {busy ? tr("Moving…") : tr("Move to {name}", { name: target.name })}
        </Button>
      </Box>
    </Box>
  );
}

function VaultChip({ name, team }: { name: string; team?: boolean }) {
  return (
    <Box
      component="span"
      sx={{
        display: "inline-flex",
        alignItems: "center",
        gap: 0.5,
        px: 0.75,
        py: 0.125,
        borderRadius: 1,
        bgcolor: "surface.strong",
        fontWeight: 600,
        fontSize: 13,
        whiteSpace: "nowrap",
      }}
    >
      {team ? (
        <GroupsRoundedIcon sx={{ fontSize: 14 }} />
      ) : (
        <PersonRoundedIcon sx={{ fontSize: 14 }} />
      )}
      {name}
    </Box>
  );
}

function AccessChoice({
  selected,
  onSelect,
  title,
  text,
}: {
  selected: boolean;
  onSelect: () => void;
  title: string;
  text: ReactNode;
}) {
  return (
    <Box
      role="radio"
      aria-checked={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === " " || e.key === "Enter") onSelect();
      }}
      sx={{
        display: "flex",
        alignItems: "center",
        gap: 1,
        p: 1.5,
        borderRadius: 2,
        cursor: "pointer",
        bgcolor: "surface.highest",
        outline: "1px solid",
        outlineColor: selected ? "primary.main" : "divider",
        outlineOffset: -1,
      }}
    >
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {title}
        </Typography>
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ display: "block", mt: 0.25, lineHeight: 1.6 }}
        >
          {text}
        </Typography>
      </Box>
      <Radio checked={selected} size="small" sx={{ p: 0.25 }} tabIndex={-1} />
    </Box>
  );
}
