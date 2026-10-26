import { useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  Chip,
  FormControlLabel,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { tr } from "@/i18n";
import * as ipc from "@/ipc/commands";
import {
  CA_EXTENSIONS,
  errorMessage,
  type IssuedCertificate,
  type Team,
  type TeamCa,
} from "@/ipc/types";
import { Loading, Mono } from "@/components/ui";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { useSnackbar } from "@/components/Snackbar";
import { Section } from "./Section";
import { can } from "./roles";

const PRINCIPAL = /^[a-z_][a-z0-9_-]{0,31}$/;

function provisionCommand(url: string): string {
  return [
    `curl -fsS ${url} | sudo tee /etc/ssh/termoso_ca.pub >/dev/null`,
    `echo 'TrustedUserCAKeys /etc/ssh/termoso_ca.pub' | sudo tee -a /etc/ssh/sshd_config >/dev/null`,
    `sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd`,
  ].join("\n");
}

export function CaTab({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const manage = can(team, "ca.manage");
  const key = ["team", team.id, "ca"];
  const q = useQuery({ queryKey: key, queryFn: () => ipc.teamCa(team.id) });
  const certs = useQuery({
    queryKey: [...key, "certificates"],
    queryFn: () => ipc.teamCaCertificates(team.id),
    enabled: !!q.data,
  });
  const local = useQuery({
    queryKey: [...key, "local"],
    queryFn: () => ipc.teamCaLocal(team.id),
    enabled: !!q.data,
  });
  const refreshAll = () => qc.invalidateQueries({ queryKey: key });

  const create = useMutation({
    mutationFn: () => ipc.teamUpdateCa(team.id, { principals: [], ttl_hours: 8 }),
    onSuccess: async () => {
      await refreshAll();
      snack.notify(tr("Certificate authority created"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => ipc.teamUpdateCa(team.id, { enabled }),
    onSuccess: refreshAll,
    onError: (e) => snack.error(errorMessage(e)),
  });
  const [rotating, setRotating] = useState(false);
  const [grace, setGrace] = useState("24");
  const rotate = useMutation({
    mutationFn: () => ipc.teamRotateCa(team.id, Number(grace) || 0),
    onSuccess: async () => {
      setRotating(false);
      await refreshAll();
      snack.notify(tr("CA key rotated; hosts keep trusting the old key for the grace period"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const [deleting, setDeleting] = useState(false);
  const remove = useMutation({
    mutationFn: () => ipc.teamDeleteCa(team.id),
    onSuccess: async () => {
      setDeleting(false);
      await refreshAll();
      snack.notify(tr("Certificate authority deleted"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const [revoking, setRevoking] = useState<IssuedCertificate | null>(null);
  const revoke = useMutation({
    mutationFn: (c: IssuedCertificate) => ipc.teamCaRevoke(team.id, c.id),
    onSuccess: async () => {
      setRevoking(null);
      await refreshAll();
      snack.notify(tr("Certificate revoked"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });

  if (q.isPending) return <Loading />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const ca: TeamCa | null = q.data;

  if (!ca) {
    return (
      <Section
        title={tr("SSH certificate authority")}
        description={tr(
          "The server signs short-lived certificates for members' devices; hosts trust one CA key instead of per-user authorized_keys. Leaving the team or losing a device stops new certificates without touching any host.",
        )}
      >
        {manage ? (
          <Button variant="contained" onClick={() => create.mutate()} disabled={create.isPending}>
            {tr("Create certificate authority")}
          </Button>
        ) : (
          <EmptyState
            title={tr("No certificate authority")}
            description={tr("A team admin can create one.")}
          />
        )}
      </Section>
    );
  }

  const copy = (text: string) => {
    void navigator.clipboard.writeText(text);
    snack.notify(tr("Copied"));
  };
  const when = (iso: string) => new Date(iso).toLocaleString();
  const mine = local.data;

  return (
    <Stack spacing={2}>
      <Section
        title={tr("SSH certificate authority")}
        actions={
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            {ca.enabled ? (
              <Chip size="small" color="success" variant="outlined" label={tr("Issuing")} />
            ) : (
              <Chip size="small" color="warning" label={tr("Paused")} />
            )}
            {manage && (
              <Switch
                size="small"
                checked={ca.enabled}
                onChange={(_, v) => toggle.mutate(v)}
                disabled={toggle.isPending}
                slotProps={{ input: { "aria-label": tr("Issue certificates") } }}
              />
            )}
          </Stack>
        }
        description={tr("Hosts need one line in sshd_config. Run this on every host of the team:")}
      >
        <Stack spacing={1.5}>
          <Mono>{provisionCommand(ca.trusted_keys_url)}</Mono>
          <Stack direction="row" spacing={1}>
            <Button size="small" onClick={() => copy(provisionCommand(ca.trusted_keys_url))}>
              {tr("Copy command")}
            </Button>
            <Button size="small" onClick={() => copy(ca.public_key)}>
              {tr("Copy CA public key")}
            </Button>
          </Stack>
          <Typography variant="caption" color="text.secondary">
            {ca.fingerprint}
            {ca.rotated_at ? ` · ${tr("rotated {when}", { when: when(ca.rotated_at) })}` : ""}
            {ca.retired_until
              ? ` · ${tr("previous key trusted until {when}", { when: when(ca.retired_until) })}`
              : ""}
            {` · ${tr("{count} active certificates", { count: ca.active_certificates })}`}
          </Typography>
        </Stack>
      </Section>

      <CaSettings
        key={ca.updated_at}
        team={team}
        ca={ca}
        manage={manage}
        onSaved={refreshAll}
        onRotate={() => setRotating(true)}
        onDelete={() => setDeleting(true)}
      />

      <Section
        title={tr("This device")}
        actions={
          <Button size="small" onClick={() => local.refetch()} disabled={local.isFetching}>
            {tr("Refresh")}
          </Button>
        }
      >
        {local.isPending ? (
          <Loading pt={1} />
        ) : !mine?.certificate ? (
          <Typography variant="body2" color="text.secondary">
            {mine?.refusal === "forbidden"
              ? tr("This device is not approved for the team yet; no certificate.")
              : mine?.refusal === "disabled"
                ? tr("Issuing is paused; this device has no certificate.")
                : tr("No certificate yet — it is requested with the next sync.")}
          </Typography>
        ) : (
          <Typography variant="body2">
            {tr("Valid until {when}", { when: when(mine.valid_before ?? "") })}
            {" · "}
            {(mine.principals ?? []).join(", ")}
          </Typography>
        )}
      </Section>

      <Section
        title={tr("Issued certificates")}
        description={manage ? undefined : tr("Your certificates. Admins see everyone's.")}
        disablePadding
      >
        {certs.isPending ? (
          <Loading pt={1} />
        ) : certs.isError ? (
          <Alert severity="error">{errorMessage(certs.error)}</Alert>
        ) : certs.data.certificates.length === 0 ? (
          <EmptyState title={tr("No certificates issued yet")} />
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{tr("Member")}</TableCell>
                  <TableCell>{tr("Device")}</TableCell>
                  <TableCell>{tr("Principals")}</TableCell>
                  <TableCell>{tr("Serial")}</TableCell>
                  <TableCell>{tr("Valid until")}</TableCell>
                  <TableCell>{tr("Status")}</TableCell>
                  <TableCell align="right" />
                </TableRow>
              </TableHead>
              <TableBody>
                {certs.data.certificates.map((c) => (
                  <TableRow key={c.id} hover>
                    <TableCell>{c.user_email}</TableCell>
                    <TableCell>
                      {c.device_name ?? "—"}
                      {c.current_device ? ` (${tr("this device")})` : ""}
                    </TableCell>
                    <TableCell>{c.principals.join(", ")}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>{c.serial}</TableCell>
                    <TableCell>{when(c.valid_before)}</TableCell>
                    <TableCell>
                      {c.revoked_at ? (
                        <Chip size="small" color="error" variant="outlined" label={tr("Revoked")} />
                      ) : c.active ? (
                        <Chip
                          size="small"
                          color="success"
                          variant="outlined"
                          label={tr("Active")}
                        />
                      ) : (
                        <Chip size="small" variant="outlined" label={tr("Expired")} />
                      )}
                    </TableCell>
                    <TableCell align="right">
                      {c.active && (manage || c.current_device) && (
                        <Button size="small" color="error" onClick={() => setRevoking(c)}>
                          {tr("Revoke")}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>

      <ConfirmDialog
        open={rotating}
        title={tr("Rotate the CA key?")}
        confirmLabel={tr("Rotate")}
        busy={rotate.isPending}
        onCancel={() => setRotating(false)}
        onConfirm={() => rotate.mutate()}
      >
        <Stack spacing={1.5}>
          <Typography variant="body2">
            {tr(
              "A new key is generated and published; the previous one stays in the trusted list for the grace period so hosts that re-fetch it keep accepting unexpired certificates.",
            )}
          </Typography>
          <TextField
            label={tr("Grace period (hours)")}
            value={grace}
            onChange={(e) => setGrace(e.target.value)}
            size="small"
            sx={{ maxWidth: 240 }}
          />
        </Stack>
      </ConfirmDialog>
      <ConfirmDialog
        open={deleting}
        title={tr("Delete the certificate authority?")}
        confirmLabel={tr("Delete")}
        danger
        busy={remove.isPending}
        onCancel={() => setDeleting(false)}
        onConfirm={() => remove.mutate()}
      >
        {tr(
          "No more certificates will be issued and the records are gone. Hosts that still trust the key accept unexpired certificates until they expire.",
        )}
      </ConfirmDialog>
      <ConfirmDialog
        open={revoking !== null}
        title={tr("Revoke certificate?")}
        confirmLabel={tr("Revoke")}
        danger
        busy={revoke.isPending}
        onCancel={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking)}
      >
        {tr(
          "The device gets a new certificate on its next sync only if it is still allowed to. Hosts enforce revocation through the KRL list (Settings → revoked certificates).",
        )}
      </ConfirmDialog>
    </Stack>
  );
}

function CaSettings({
  team,
  ca,
  manage,
  onSaved,
  onRotate,
  onDelete,
}: {
  team: Team;
  ca: TeamCa;
  manage: boolean;
  onSaved: () => void;
  onRotate: () => void;
  onDelete: () => void;
}) {
  const snack = useSnackbar();
  const [principals, setPrincipals] = useState(ca.principals.join(", "));
  const [ttl, setTtl] = useState(String(ca.ttl_hours));
  const [extensions, setExtensions] = useState<string[]>(ca.extensions);
  const [dirty, setDirty] = useState(false);
  const parsedPrincipals = principals
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const badPrincipal = parsedPrincipals.find((p) => !PRINCIPAL.test(p));
  const ttlNum = Number(ttl);
  const ttlOk = Number.isInteger(ttlNum) && ttlNum >= 1 && ttlNum <= 168;
  const save = useMutation({
    mutationFn: () =>
      ipc.teamUpdateCa(team.id, {
        principals: parsedPrincipals,
        ttl_hours: ttlNum,
        extensions,
      }),
    onSuccess: () => {
      setDirty(false);
      onSaved();
      snack.notify(tr("CA settings saved"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  return (
    <Section
      title={tr("Settings")}
      description={tr(
        "Principals are the login names a certificate may carry (ubuntu, deploy…). A member asks for all of them or a subset; sshd matches the one they log in as.",
      )}
      actions={
        manage ? (
          <Button
            variant="contained"
            size="small"
            disabled={!dirty || !!badPrincipal || !ttlOk || save.isPending}
            onClick={() => save.mutate()}
          >
            {tr("Save")}
          </Button>
        ) : undefined
      }
    >
      <Stack spacing={1.5}>
        <TextField
          label={tr("Principals (login names)")}
          value={principals}
          onChange={(e) => {
            setPrincipals(e.target.value);
            setDirty(true);
          }}
          placeholder="ubuntu, deploy"
          error={!!badPrincipal}
          helperText={
            badPrincipal
              ? tr("`{name}` is not a valid login name", { name: badPrincipal })
              : parsedPrincipals.length === 0
                ? tr("No principals yet — certificates are not issued until at least one is set.")
                : undefined
          }
          disabled={!manage}
          size="small"
          fullWidth
        />
        <TextField
          label={tr("Certificate lifetime (hours)")}
          value={ttl}
          onChange={(e) => {
            setTtl(e.target.value);
            setDirty(true);
          }}
          error={!ttlOk}
          helperText={ttlOk ? undefined : tr("1 to 168 hours")}
          disabled={!manage}
          size="small"
          sx={{ maxWidth: 240 }}
        />
        <Stack direction="row" useFlexGap spacing={1} sx={{ flexWrap: "wrap" }}>
          {CA_EXTENSIONS.map((ext) => (
            <FormControlLabel
              key={ext}
              control={
                <Checkbox
                  size="small"
                  checked={extensions.includes(ext)}
                  disabled={!manage}
                  onChange={(_, v) => {
                    setExtensions((cur) => (v ? [...cur, ext] : cur.filter((x) => x !== ext)));
                    setDirty(true);
                  }}
                />
              }
              label={<Typography variant="body2">{ext}</Typography>}
            />
          ))}
        </Stack>
        {manage && (
          <Stack direction="row" spacing={1}>
            <Button size="small" onClick={onRotate}>
              {tr("Rotate key…")}
            </Button>
            <Button size="small" color="error" onClick={onDelete}>
              {tr("Delete CA…")}
            </Button>
          </Stack>
        )}
      </Stack>
    </Section>
  );
}
