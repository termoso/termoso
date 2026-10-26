import { useEffect, useState, type SubmitEvent } from "react";
import { tr, trx } from "@/i18n";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
  TableContainer,
  TablePagination,
  Divider,
} from "@mui/material";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import { QRCodeSVG } from "qrcode.react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
} from "@simplewebauthn/browser";
import { errorMessage } from "@/api/client";
import { accountApi } from "@/api/endpoints";
import { queryKeys, useServerInfo } from "@/api/hooks";
import type { SsoIdentity, WebauthnCredentialInfo } from "@/api/types";
import { useLocation } from "react-router";
import { startSsoLink } from "@/auth/sso";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CopyField } from "@/components/CopyField";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { PageHeader } from "@/components/PageHeader";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { formatDateTime, formatRelative, titleCase } from "@/components/format";
import { UnlockCancelled, withStepUp } from "@/auth/unlock";
import { monoFontFamily } from "@/theme/theme";

export function SecurityPage() {
  const mfa = useQuery({ queryKey: queryKeys.mfa, queryFn: accountApi.mfa });
  const info = useServerInfo();
  if (mfa.isPending) return <Loading />;
  if (mfa.isError) return <Alert severity="error">{errorMessage(mfa.error)}</Alert>;
  return (
    <>
      <PageHeader
        title={tr("Security")}
        subtitle={tr("Two-factor authentication and recent account activity.")}
      />
      <TotpSection enabled={mfa.data.totp_enabled} />
      {info.data?.features.webauthn && (
        <WebauthnSection credentials={mfa.data.webauthn_credentials} />
      )}
      {mfa.data.totp_enabled && <BackupCodesSection remaining={mfa.data.backup_codes_remaining} />}
      <ConnectedAccountsSection />
      <SecurityEventsSection />
    </>
  );
}

function CodesDialog({ codes, onClose }: { codes: string[] | null; onClose: () => void }) {
  return (
    <Dialog open={codes !== null} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{tr("Backup codes")}</DialogTitle>
      <DialogContent sx={{ display: "grid", gap: 2 }}>
        <DialogContentText>
          {tr("Each code works once. Store them like a password — they bypass your authenticator.")}
        </DialogContentText>
        <Box
          sx={{
            p: 2,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 1,
            fontFamily: monoFontFamily,
            fontSize: "0.9rem",
            borderRadius: 2,
            bgcolor: "surface.lowest",
          }}
        >
          {(codes ?? []).map((c) => (
            <Box key={c} sx={{ userSelect: "all" }}>
              {c}
            </Box>
          ))}
        </Box>
        <Button
          variant="outlined"
          onClick={() => void navigator.clipboard.writeText((codes ?? []).join("\n"))}
        >
          {tr("Copy all")}
        </Button>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button variant="contained" onClick={onClose}>
          {tr("Done")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function TotpSection({ enabled }: { enabled: boolean }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const [setupOpen, setSetupOpen] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const setup = useMutation({
    mutationFn: accountApi.totpSetup,
    onError: (e) => setError(errorMessage(e)),
  });
  const confirm = useMutation({
    mutationFn: () => accountApi.totpConfirm(code.trim()),
    onSuccess: async (r) => {
      setSetupOpen(false);
      setCode("");
      setCodes(r.codes);
      await qc.invalidateQueries({ queryKey: queryKeys.mfa });
      await qc.invalidateQueries({ queryKey: queryKeys.account });
    },
    onError: (e) => setError(errorMessage(e)),
  });
  const disable = useMutation({
    mutationFn: () => withStepUp(() => accountApi.totpDisable(code.trim())),
    onSuccess: async () => {
      setDisableOpen(false);
      setCode("");
      await qc.invalidateQueries({ queryKey: queryKeys.mfa });
      await qc.invalidateQueries({ queryKey: queryKeys.account });
      snack.notify(tr("Authenticator app disabled"));
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) setError(errorMessage(e));
    },
  });

  const openSetup = () => {
    setError(null);
    setCode("");
    setSetupOpen(true);
    setup.mutate();
  };

  return (
    <Section
      title={tr("Authenticator app")}
      description={tr("Time-based one-time codes (TOTP) from any authenticator app.")}
      actions={
        <>
          <Chip
            size="small"
            color={enabled ? "success" : "default"}
            label={enabled ? tr("Enabled") : tr("Not enabled")}
            sx={{ alignSelf: "center" }}
          />
          {enabled ? (
            <Button
              variant="outlined"
              color="error"
              onClick={() => {
                setError(null);
                setCode("");
                setDisableOpen(true);
              }}
            >
              {tr("Disable")}
            </Button>
          ) : (
            <Button variant="contained" onClick={openSetup}>
              {tr("Set up")}
            </Button>
          )}
        </>
      }
    >
      <Dialog
        open={setupOpen}
        onClose={confirm.isPending ? undefined : () => setSetupOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <form
          onSubmit={(e: SubmitEvent) => {
            e.preventDefault();
            confirm.mutate();
          }}
        >
          <DialogTitle>{tr("Set up authenticator")}</DialogTitle>
          <DialogContent sx={{ display: "grid", gap: 2 }}>
            {error && <Alert severity="error">{error}</Alert>}
            {setup.isPending && <Loading minHeight={200} />}
            {setup.data && (
              <>
                <DialogContentText>
                  {tr("Scan the QR code or enter the secret manually, then type the current code.")}
                </DialogContentText>
                <Box
                  sx={{
                    display: "grid",
                    placeItems: "center",
                    p: 2,
                    bgcolor: "#fff",
                    borderRadius: 2,
                  }}
                >
                  <QRCodeSVG value={setup.data.otpauth_url} size={180} />
                </Box>
                <CopyField label={tr("Secret")} value={setup.data.secret} />
                <TextField
                  autoFocus
                  label={tr("6-digit code")}
                  required
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  disabled={confirm.isPending}
                />
              </>
            )}
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button
              onClick={() => setSetupOpen(false)}
              color="inherit"
              disabled={confirm.isPending}
            >
              {tr("Cancel")}
            </Button>
            <Button
              type="submit"
              variant="contained"
              disabled={!setup.data || confirm.isPending || code.trim() === ""}
            >
              {tr("Enable")}
            </Button>
          </DialogActions>
        </form>
      </Dialog>

      <Dialog
        open={disableOpen}
        onClose={disable.isPending ? undefined : () => setDisableOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <form
          onSubmit={(e: SubmitEvent) => {
            e.preventDefault();
            disable.mutate();
          }}
        >
          <DialogTitle>{tr("Disable authenticator app")}</DialogTitle>
          <DialogContent sx={{ display: "grid", gap: 2 }}>
            {error && <Alert severity="error">{error}</Alert>}
            <DialogContentText>
              {tr("Enter a current code (or a backup code) to confirm.")}
            </DialogContentText>
            <TextField
              autoFocus
              label={tr("Code")}
              required
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              disabled={disable.isPending}
            />
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button
              onClick={() => setDisableOpen(false)}
              color="inherit"
              disabled={disable.isPending}
            >
              {tr("Cancel")}
            </Button>
            <Button
              type="submit"
              variant="contained"
              color="error"
              disabled={disable.isPending || code.trim() === ""}
            >
              {tr("Disable")}
            </Button>
          </DialogActions>
        </form>
      </Dialog>

      <CodesDialog codes={codes} onClose={() => setCodes(null)} />
    </Section>
  );
}

function BackupCodesSection({ remaining }: { remaining: number }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const regen = useMutation({
    mutationFn: () => withStepUp(accountApi.backupCodes),
    onSuccess: async (r) => {
      setConfirmOpen(false);
      setCodes(r.codes);
      await qc.invalidateQueries({ queryKey: queryKeys.mfa });
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });
  return (
    <Section
      title={tr("Backup codes")}
      description={tr("One-time codes for when you cannot reach your authenticator.")}
      actions={
        <Button variant="outlined" onClick={() => setConfirmOpen(true)}>
          {tr("Regenerate")}
        </Button>
      }
    >
      <Typography variant="body2">
        <b>{remaining}</b> unused {remaining === 1 ? "code" : "codes"} remaining
      </Typography>
      <ConfirmDialog
        open={confirmOpen}
        title={tr("Regenerate backup codes?")}
        confirmLabel={tr("Regenerate")}
        busy={regen.isPending}
        onCancel={() => setConfirmOpen(false)}
        onConfirm={() => regen.mutate()}
      >
        {tr("All existing backup codes stop working and a new set of ten is generated.")}
      </ConfirmDialog>
      <CodesDialog codes={codes} onClose={() => setCodes(null)} />
    </Section>
  );
}

function isCreationChallenge(
  v: unknown,
): v is { publicKey: PublicKeyCredentialCreationOptionsJSON } {
  return typeof v === "object" && v !== null && "publicKey" in v;
}

function WebauthnSection({ credentials }: { credentials: WebauthnCredentialInfo[] }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const [addOpen, setAddOpen] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<WebauthnCredentialInfo | null>(null);

  const add = useMutation({
    mutationFn: async () => {
      const challenge = await accountApi.webauthnRegisterStart();
      if (!isCreationChallenge(challenge)) throw new Error("Malformed WebAuthn challenge");
      const credential = await startRegistration({ optionsJSON: challenge.publicKey });
      return accountApi.webauthnRegisterFinish(name.trim(), credential);
    },
    onSuccess: async () => {
      setAddOpen(false);
      setName("");
      await qc.invalidateQueries({ queryKey: queryKeys.mfa });
      await qc.invalidateQueries({ queryKey: queryKeys.account });
      snack.notify(tr("Security key added"));
    },
    onError: (e) => setError(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (id: string) => withStepUp(() => accountApi.webauthnDelete(id)),
    onSuccess: async () => {
      setRemoving(null);
      await qc.invalidateQueries({ queryKey: queryKeys.mfa });
      await qc.invalidateQueries({ queryKey: queryKeys.account });
      snack.notify(tr("Security key removed"));
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });

  return (
    <Section
      title={tr("Security keys & passkeys")}
      description={tr("Hardware keys (YubiKey etc.) or platform passkeys via WebAuthn.")}
      actions={
        <Button
          variant="outlined"
          startIcon={<KeyRoundedIcon />}
          onClick={() => {
            setError(null);
            setAddOpen(true);
          }}
        >
          {tr("Add key")}
        </Button>
      }
      disablePadding
    >
      {credentials.length === 0 ? (
        <EmptyState
          title={tr("No security keys")}
          description={tr("Add a hardware key or passkey as a second factor.")}
        />
      ) : (
        <List disablePadding>
          {credentials.map((c) => (
            <ListItem
              key={c.id}
              divider
              secondaryAction={
                <Tooltip title={tr("Remove")}>
                  <IconButton
                    edge="end"
                    onClick={() => setRemoving(c)}
                    aria-label={tr("Remove key")}
                  >
                    <DeleteOutlineRoundedIcon />
                  </IconButton>
                </Tooltip>
              }
            >
              <ListItemText
                primary={c.name}
                secondary={tr("Added {v1} · Last used {v2}", {
                  v1: formatDateTime(c.created_at),
                  v2: formatRelative(c.last_used_at),
                })}
              />
            </ListItem>
          ))}
        </List>
      )}

      <Dialog
        open={addOpen}
        onClose={add.isPending ? undefined : () => setAddOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <form
          onSubmit={(e: SubmitEvent) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <DialogTitle>{tr("Add security key")}</DialogTitle>
          <DialogContent sx={{ display: "grid", gap: 2 }}>
            {error && <Alert severity="error">{error}</Alert>}
            <DialogContentText>
              {tr("Give the key a name, then follow your browser's prompt.")}
            </DialogContentText>
            <TextField
              autoFocus
              label={tr("Name")}
              required
              placeholder={tr("YubiKey 5C")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={add.isPending}
            />
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setAddOpen(false)} color="inherit" disabled={add.isPending}>
              {tr("Cancel")}
            </Button>
            <Button
              type="submit"
              variant="contained"
              disabled={add.isPending || name.trim() === ""}
            >
              {tr("Continue")}
            </Button>
          </DialogActions>
        </form>
      </Dialog>

      <ConfirmDialog
        open={removing !== null}
        title={tr("Remove security key?")}
        confirmLabel={tr("Remove")}
        danger
        busy={remove.isPending}
        onCancel={() => setRemoving(null)}
        onConfirm={() => {
          if (removing) remove.mutate(removing.id);
        }}
      >
        {trx("“{name}” will no longer be accepted for two-factor sign-in.", {
          name: removing?.name,
        })}
      </ConfirmDialog>
    </Section>
  );
}

function SecurityEventsSection() {
  const [limit, setLimit] = useState(10);
  // Cursor per page: `cursors[i]` is the `before` of page i (page 0 has none).
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [page, setPage] = useState(0);
  const before = cursors[page];
  const events = useQuery({
    queryKey: [...queryKeys.securityEvents, before ?? "", limit],
    queryFn: () => accountApi.securityEvents(before, limit),
    placeholderData: (prev) => prev,
  });
  const rows = events.data?.events ?? [];
  const goTo = (next: number) => {
    if (next > page) {
      const last = rows.at(-1)?.created_at;
      if (!last) return;
      setCursors((c) => (c.length > next ? c : [...c, last]));
    }
    setPage(next);
  };
  return (
    <Section
      title={tr("Recent activity")}
      description={tr("Sign-ins, device changes and security settings updates.")}
      disablePadding
    >
      {events.isPending ? (
        <Loading minHeight={120} />
      ) : events.isError ? (
        <Box sx={{ p: 3 }}>
          <Alert severity="error">{errorMessage(events.error)}</Alert>
        </Box>
      ) : rows.length === 0 ? (
        <EmptyState title={tr("No activity yet")} />
      ) : (
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>{tr("Event")}</TableCell>
                <TableCell>{tr("IP")}</TableCell>
                <TableCell>{tr("Client")}</TableCell>
                <TableCell align="right">{tr("When")}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((ev) => (
                <TableRow key={ev.id} hover>
                  <TableCell>{titleCase(ev.kind)}</TableCell>
                  <TableCell sx={{ fontFamily: monoFontFamily, fontSize: "0.8rem" }}>
                    {ev.ip ?? "—"}
                  </TableCell>
                  <TableCell sx={{ maxWidth: 320 }}>
                    <Typography variant="body2" noWrap title={ev.user_agent}>
                      {ev.user_agent ?? "—"}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title={formatDateTime(ev.created_at)}>
                      <Stack component="span">{formatRelative(ev.created_at)}</Stack>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {events.data && (page > 0 || events.data.has_more || rows.length >= limit) && (
        <TablePagination
          component="div"
          count={-1}
          page={page}
          onPageChange={(_e, p) => goTo(p)}
          rowsPerPage={limit}
          onRowsPerPageChange={(e) => {
            setLimit(Number(e.target.value));
            setCursors([undefined]);
            setPage(0);
          }}
          rowsPerPageOptions={[10, 25, 50]}
          labelDisplayedRows={({ from, to }) => `${from}–${to}`}
          slotProps={{
            actions: {
              nextButton: { disabled: !events.data.has_more || events.isFetching },
              previousButton: { disabled: page === 0 || events.isFetching },
            },
          }}
        />
      )}
    </Section>
  );
}

function ConnectedAccountsSection() {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const location = useLocation();
  const info = useServerInfo();
  const identities = useQuery({
    queryKey: queryKeys.ssoIdentities,
    queryFn: accountApi.ssoIdentities,
  });
  const [removing, setRemoving] = useState<SsoIdentity | null>(null);
  const [connecting, setConnecting] = useState<string | null>(null);
  const linked = (location.state as { ssoLinked?: { provider: string; email: string } } | null)
    ?.ssoLinked;
  useEffect(() => {
    if (!linked) return;
    snack.notify(
      tr("{provider} account {email} connected", {
        provider: linked.provider,
        email: linked.email,
      }),
    );
    window.history.replaceState({}, "");
  }, [linked, snack]);
  const unlink = useMutation({
    mutationFn: (provider: string) => withStepUp(() => accountApi.ssoUnlink(provider)),
    onSuccess: () => {
      setRemoving(null);
      void qc.invalidateQueries({ queryKey: queryKeys.ssoIdentities });
      void qc.invalidateQueries({ queryKey: queryKeys.securityEvents });
      snack.notify(tr("Account disconnected"));
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });
  const providers = info.data?.sso_providers ?? [];
  if (providers.length === 0) return null;
  const byProvider = new Map((identities.data ?? []).map((i) => [i.provider, i]));
  return (
    <Section
      title={tr("Connected accounts")}
      description={tr(
        "Sign in with these identity providers. Your password is still needed to unlock the vault; a connected account skips e-mail codes and new-device approval.",
      )}
      disablePadding
    >
      {identities.isPending ? (
        <Loading minHeight={80} />
      ) : identities.isError ? (
        <Box sx={{ p: 3 }}>
          <Alert severity="error">{errorMessage(identities.error)}</Alert>
        </Box>
      ) : (
        <Stack divider={<Divider />}>
          {providers.map((p) => {
            const id = byProvider.get(p.id);
            return (
              <Stack
                key={p.id}
                direction="row"
                spacing={2}
                sx={{ px: 3, py: 1.5, alignItems: "center", justifyContent: "space-between" }}
              >
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {p.name}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" noWrap component="div">
                    {id
                      ? tr("{v1} · since {v2}", {
                          v1: id.email ?? "connected",
                          v2: formatDateTime(id.linked_at),
                        })
                      : tr("Not connected")}
                  </Typography>
                </Box>
                {id ? (
                  <Button size="small" color="inherit" onClick={() => setRemoving(id)}>
                    {tr("Disconnect")}
                  </Button>
                ) : (
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={connecting !== null}
                    onClick={() => {
                      setConnecting(p.id);
                      startSsoLink(p.id).catch((e: unknown) => {
                        setConnecting(null);
                        snack.error(errorMessage(e));
                      });
                    }}
                  >
                    {connecting === p.id ? tr("Redirecting…") : tr("Connect")}
                  </Button>
                )}
              </Stack>
            );
          })}
        </Stack>
      )}
      <ConfirmDialog
        open={removing !== null}
        title={tr("Disconnect {v1}?", { v1: removing?.name ?? "" })}
        confirmLabel={tr("Disconnect")}
        onCancel={() => setRemoving(null)}
        onConfirm={() => removing && unlink.mutate(removing.provider)}
        busy={unlink.isPending}
      >
        {trx(
          "Signing in with {name} will ask for your password and e-mail codes like a new device again.",
          { name: removing?.name },
        )}
      </ConfirmDialog>
    </Section>
  );
}
