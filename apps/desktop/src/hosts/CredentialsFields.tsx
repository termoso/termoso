import { useState, type ReactNode } from "react";
import {
  Box,
  Button,
  IconButton,
  InputAdornment,
  Menu,
  MenuItem,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import BadgeOutlinedIcon from "@mui/icons-material/BadgeOutlined";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import FingerprintRoundedIcon from "@mui/icons-material/FingerprintRounded";
import UsbRoundedIcon from "@mui/icons-material/UsbRounded";
import PasswordRoundedIcon from "@mui/icons-material/PasswordRounded";
import PersonOutlineRoundedIcon from "@mui/icons-material/PersonOutlineRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import VisibilityOffRoundedIcon from "@mui/icons-material/VisibilityOffRounded";
import WorkspacePremiumOutlinedIcon from "@mui/icons-material/WorkspacePremiumOutlined";
import { SettingRow } from "@/components/ui";
import { goToSection } from "@/app/navigation";
import { useIdentities, useSshKeys, useTeams, useVaults } from "@/ipc/hooks";
import { requirePerm } from "@/team/perms";
import { certificateName, certificateSummary, isHardwareKey } from "@/keychain/model";
import {
  SSH_ID_DEFAULT_TYPE,
  SSH_ID_KEY_TYPES,
  sshIdTypeLabel,
  type Inherited,
  type SshIdKeyType,
  type Uuid,
} from "@/ipc/types";
import { tr } from "@/i18n";

/** The credential slice shared by the host and group editors. */
export interface CredentialValues {
  identityId: Uuid | null;
  username: string;
  /** `null` = keep the stored password (see `hasPassword`). */
  password: string | null;
  hasPassword: boolean;
  /** `null` = keep the stored TOTP secret (see `hasTotp`); `""` clears it. */
  totpSecret: string | null;
  hasTotp: boolean;
  sshKeyId: Uuid | null;
  /** Certificate pinned here; `null` = the key's own certificate. */
  sshCertificateId: Uuid | null;
  /** Log in with the account's SSH ID passkeys. */
  sshId: boolean;
  sshIdKeyType: SshIdKeyType | null;
  agentForwarding: boolean;
  forwardX11: boolean;
}

type AuthRow = "sshid" | "key" | "certificate" | "fido2";

const adornment = (icon: ReactNode) => (
  <InputAdornment position="start" sx={{ color: "text.secondary" }}>
    {icon}
  </InputAdornment>
);

/**
 * Credentials the Termius way: a "Credentials" / "Credentials from <identity>"
 * header, then username and password, and the auth rows only once added via
 * "+ SSH ID, Key, Certificate, FIDO2" (or when one is already set).
 */
export function CredentialsFields({
  vaultId,
  value,
  onChange,
  ssh,
  agentForwarding = ssh,
  inherited,
  inlineLabel,
}: {
  vaultId: Uuid;
  value: CredentialValues;
  onChange: (patch: Partial<CredentialValues>) => void;
  ssh: boolean;
  /** Render the Agent forwarding switch here (the host panel keeps it under Show more). */
  agentForwarding?: boolean;
  /** Effective values coming from the group chain, shown as placeholders. */
  inherited?: Inherited | null;
  inlineLabel: string;
}) {
  const identities = useIdentities(vaultId);
  const sshKeys = useSshKeys(vaultId);
  const vaults = useVaults();
  const teamId = (vaults.data ?? []).find((v) => v.id === vaultId)?.team_id ?? null;
  const teams = useTeams(teamId !== null);
  // Team policy `local_keys = deny`: keys must live in the team vault, so keys
  // that only reference the system SSH agent are hidden (client-enforced).
  const denyLocalKeys =
    teamId !== null &&
    (teams.data ?? []).some((t) => t.id === teamId && t.policies?.local_keys === "deny");
  const [showPassword, setShowPassword] = useState(false);
  const [keyRow, setKeyRow] = useState<"key" | "fido2" | null>(null);
  const [certRow, setCertRow] = useState(false);
  const [addAnchor, setAddAnchor] = useState<HTMLElement | null>(null);
  const [sourceAnchor, setSourceAnchor] = useState<HTMLElement | null>(null);

  const identity = (identities.data ?? []).find((i) => i.id === value.identityId) ?? null;
  const usingIdentity = value.identityId !== null;
  const from = inherited && inherited.groupPath.length > 0 ? inherited.groupPath.join(" / ") : null;
  const inheritedKey = inherited?.sshKeyLabel ?? null;
  const allKeys = (sshKeys.data ?? []).filter((k) => !denyLocalKeys || !k.agentBacked);
  const selectedKey = value.sshKeyId
    ? (allKeys.find((k) => k.id === value.sshKeyId) ?? null)
    : null;
  const keyKnown = value.sshKeyId === null || selectedKey !== null;
  const certified = allKeys.filter((k) => k.certificate !== null);
  const certKey = value.sshCertificateId
    ? (certified.find((k) => k.certificate?.id === value.sshCertificateId) ?? null)
    : null;
  // Which of Key / FIDO2 to render: the stored key decides, else what was added.
  const shownKeyRow: "key" | "fido2" | null = !ssh
    ? null
    : selectedKey
      ? isHardwareKey(selectedKey)
        ? "fido2"
        : "key"
      : value.sshKeyId
        ? (keyRow ?? "key")
        : keyRow;
  const showSshId = ssh && value.sshId;
  // Certificates ride on software keys only; a pinned certificate always shows.
  const showCert = ssh && shownKeyRow !== "fido2" && (value.sshCertificateId !== null || certRow);
  const missing: AuthRow[] = !ssh
    ? []
    : (["sshid", "key", "certificate", "fido2"] as AuthRow[]).filter((r) =>
        r === "sshid"
          ? !showSshId
          : r === "certificate"
            ? !showCert && shownKeyRow !== "fido2"
            : shownKeyRow === null,
      );
  const rowTitle: Record<AuthRow, string> = {
    sshid: tr("SSH ID"),
    key: "Key",
    certificate: "Certificate",
    fido2: "FIDO2",
  };
  const rowIcon: Record<AuthRow, ReactNode> = {
    sshid: <FingerprintRoundedIcon fontSize="small" />,
    key: <KeyOutlinedIcon fontSize="small" />,
    certificate: <WorkspacePremiumOutlinedIcon fontSize="small" />,
    fido2: <UsbRoundedIcon fontSize="small" />,
  };
  const addRow = (r: AuthRow) => {
    if (r === "sshid") onChange({ sshId: true, sshIdKeyType: null });
    else if (r === "certificate") setCertRow(true);
    else {
      setKeyRow(r);
      if (r === "fido2") {
        setCertRow(false);
        if (value.sshCertificateId) onChange({ sshCertificateId: null });
      }
    }
    setAddAnchor(null);
  };
  const chooseKey = (id: Uuid | null) => {
    const k = id ? allKeys.find((x) => x.id === id) : undefined;
    const keepCert =
      value.sshCertificateId !== null && k?.certificate?.id === value.sshCertificateId;
    onChange({ sshKeyId: id, sshCertificateId: keepCert ? value.sshCertificateId : null });
  };
  const chooseCert = (id: Uuid | null) => {
    const k = id ? certified.find((c) => c.certificate?.id === id) : undefined;
    if (k) {
      setKeyRow("key");
      onChange({ sshCertificateId: id, sshKeyId: k.id });
    } else onChange({ sshCertificateId: id });
  };

  const sourceLabel = usingIdentity
    ? (identity?.label ?? (identities.data ? tr("Unknown identity") : tr("Loading…")))
    : null;
  // Nothing set here and the group provides something → the group is the source.
  const ownEmpty =
    !usingIdentity &&
    !value.username &&
    !value.hasPassword &&
    !value.password &&
    !value.sshKeyId &&
    !value.sshCertificateId &&
    !value.sshId;
  const inheritedFrom =
    ownEmpty &&
    from &&
    inherited &&
    (inherited.username ||
      inherited.hasPassword ||
      inherited.sshKeyId ||
      inherited.identityId ||
      inherited.sshId)
      ? from
      : null;

  return (
    <>
      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, minHeight: 28 }}>
        <Typography variant="subtitle2" noWrap>
          {usingIdentity || inheritedFrom ? tr("Credentials from") : tr("Credentials")}
        </Typography>
        {inheritedFrom && (
          <Typography
            variant="subtitle2"
            noWrap
            sx={{ minWidth: 0, color: "text.secondary", fontWeight: 400 }}
          >
            {inheritedFrom}
          </Typography>
        )}
        <Button
          variant="text"
          size="small"
          color="inherit"
          startIcon={usingIdentity ? <BadgeOutlinedIcon /> : undefined}
          endIcon={<ExpandMoreRoundedIcon />}
          onClick={(e) => setSourceAnchor(e.currentTarget)}
          sx={{ color: "text.secondary", ml: usingIdentity ? 0 : "auto", px: 0.75, flexShrink: 0 }}
        >
          {sourceLabel ?? tr("Identity")}
        </Button>
      </Box>
      <Menu
        open={sourceAnchor !== null}
        anchorEl={sourceAnchor}
        onClose={() => setSourceAnchor(null)}
        slotProps={{ paper: { sx: { minWidth: 240 } } }}
      >
        <MenuItem
          selected={!usingIdentity}
          onClick={() => {
            onChange({ identityId: null });
            setSourceAnchor(null);
          }}
        >
          {inlineLabel}
        </MenuItem>
        {(identities.data ?? []).map((i) => (
          <MenuItem
            key={i.id}
            selected={i.id === value.identityId}
            onClick={() => {
              onChange({ identityId: i.id });
              setSourceAnchor(null);
            }}
          >
            <BadgeOutlinedIcon fontSize="small" sx={{ mr: 1.25, color: "text.secondary" }} />
            {i.label}
            <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
              {i.username}
            </Typography>
          </MenuItem>
        ))}
        <MenuItem
          onClick={() => {
            setSourceAnchor(null);
            goToSection("keychain");
          }}
          sx={{ color: "primary.main" }}
        >
          <AddRoundedIcon fontSize="small" sx={{ mr: 1.25 }} />
          {tr("Open Keychain…")}
        </MenuItem>
      </Menu>

      {usingIdentity ? (
        <>
          <TextField
            value={identity?.username ?? ""}
            placeholder={identities.data ? tr("No username") : ""}
            disabled
            slotProps={{ input: { startAdornment: adornment(<PersonOutlineRoundedIcon />) } }}
          />
          <TextField
            value={identity?.hasPassword ? "••••••••••••" : ""}
            placeholder={tr("No password")}
            disabled
            slotProps={{ input: { startAdornment: adornment(<PasswordRoundedIcon />) } }}
          />
          {ssh && identity?.sshId && (
            <TextField
              value={tr("SSH ID · {type} first", {
                type: sshIdTypeLabel(identity.sshIdKeyType ?? SSH_ID_DEFAULT_TYPE),
              })}
              disabled
              slotProps={{ input: { startAdornment: adornment(<FingerprintRoundedIcon />) } }}
            />
          )}
          {ssh && identity?.sshKeyLabel && (
            <TextField
              value={identity.sshKeyLabel}
              disabled
              slotProps={{ input: { startAdornment: adornment(<KeyOutlinedIcon />) } }}
            />
          )}
          {ssh && identity?.hasCertificate && (
            <TextField
              value="Certificate"
              disabled
              slotProps={{
                input: { startAdornment: adornment(<WorkspacePremiumOutlinedIcon />) },
              }}
            />
          )}
        </>
      ) : (
        <>
          <TextField
            value={value.username}
            onChange={(e) => onChange({ username: e.target.value })}
            autoComplete="off"
            placeholder={
              inherited?.username
                ? tr("{username} (inherited)", { username: inherited.username })
                : showSshId
                  ? tr("Username (defaults to your SSH ID handle)")
                  : tr("Username")
            }
            helperText={
              !value.username && inherited?.username && from
                ? tr("From {from}", { from })
                : undefined
            }
            slotProps={{
              input: { startAdornment: adornment(<PersonOutlineRoundedIcon />) },
              htmlInput: { "aria-label": tr("Username") },
            }}
          />
          <TextField
            type={showPassword ? "text" : "password"}
            value={value.password ?? ""}
            onChange={(e) => onChange({ password: e.target.value })}
            autoComplete="new-password"
            placeholder={
              value.hasPassword && value.password === null
                ? "••••••••••••"
                : inherited?.hasPassword
                  ? tr("•••••••• (inherited)")
                  : tr("Password")
            }
            helperText={
              value.password && /^(op|bw|pass|env):\/\//.test(value.password)
                ? tr(
                    "Reference: fetched from the external manager when connecting, not stored here.",
                  )
                : value.hasPassword && value.password === null
                  ? tr("A password is stored. Type to replace it or clear it to remove.")
                  : !value.hasPassword && value.password === null && inherited?.hasPassword && from
                    ? tr("From {from}", { from })
                    : undefined
            }
            slotProps={{
              htmlInput: { "aria-label": tr("Password") },
              input: {
                startAdornment: adornment(<PasswordRoundedIcon />),
                endAdornment: (
                  <InputAdornment position="end">
                    {value.hasPassword && value.password === null && (
                      <Button
                        size="small"
                        color="inherit"
                        onClick={() => onChange({ password: "" })}
                      >
                        {tr("Clear")}
                      </Button>
                    )}
                    <IconButton
                      size="small"
                      onClick={() => {
                        if (!showPassword && !requirePerm(vaultId, "secrets.reveal")) return;
                        setShowPassword((v) => !v);
                      }}
                      aria-label={tr("Toggle password visibility")}
                    >
                      {showPassword ? (
                        <VisibilityOffRoundedIcon fontSize="small" />
                      ) : (
                        <VisibilityRoundedIcon fontSize="small" />
                      )}
                    </IconButton>
                  </InputAdornment>
                ),
              },
            }}
          />
          <TextField
            value={value.totpSecret ?? ""}
            onChange={(e) => onChange({ totpSecret: e.target.value })}
            autoComplete="off"
            placeholder={
              value.hasTotp && value.totpSecret === null
                ? "••••••••••••"
                : inherited?.hasTotp
                  ? tr("•••••••• (inherited)")
                  : tr("TOTP secret (optional)")
            }
            helperText={
              value.hasTotp && value.totpSecret === null
                ? tr(
                    "A TOTP secret is stored: one-time codes are typed for you. Type to replace it or clear it to remove.",
                  )
                : tr(
                    "otpauth:// URI or base32 secret from the server's authenticator setup. The current code is typed into the verification-code prompt.",
                  )
            }
            slotProps={{
              htmlInput: { "aria-label": tr("TOTP secret") },
              input: {
                startAdornment: adornment(<PasswordRoundedIcon />),
                endAdornment:
                  value.hasTotp && value.totpSecret === null ? (
                    <InputAdornment position="end">
                      <Button
                        size="small"
                        color="inherit"
                        onClick={() => onChange({ totpSecret: "" })}
                      >
                        {tr("Clear")}
                      </Button>
                    </InputAdornment>
                  ) : undefined,
              },
            }}
          />
          {showSshId && (
            <TextField
              select
              value={value.sshIdKeyType ?? ""}
              onChange={(e) =>
                onChange({
                  sshIdKeyType: e.target.value === "" ? null : (e.target.value as SshIdKeyType),
                })
              }
              helperText={tr(
                "Signs in with this account's passkeys (Settings → SSH ID). Pick which one to offer first.",
              )}
              slotProps={{
                htmlInput: { "aria-label": tr("SSH ID key type") },
                input: {
                  startAdornment: adornment(rowIcon.sshid),
                  endAdornment: (
                    <InputAdornment position="end" sx={{ mr: 2 }}>
                      <IconButton
                        size="small"
                        aria-label={tr("Remove SSH ID")}
                        onClick={() => onChange({ sshId: false, sshIdKeyType: null })}
                      >
                        <CloseRoundedIcon fontSize="small" />
                      </IconButton>
                    </InputAdornment>
                  ),
                },
              }}
            >
              <MenuItem value="">
                {sshIdTypeLabel(SSH_ID_DEFAULT_TYPE)}
                <Typography
                  component="span"
                  variant="caption"
                  color="text.secondary"
                  sx={{ ml: 1 }}
                >
                  {tr("Default")}
                </Typography>
              </MenuItem>
              {SSH_ID_KEY_TYPES.filter((t) => t.value !== SSH_ID_DEFAULT_TYPE).map((t) => (
                <MenuItem key={t.value} value={t.value}>
                  {t.label}
                  <Typography
                    component="span"
                    variant="caption"
                    color="text.secondary"
                    sx={{ ml: 1 }}
                  >
                    {t.hint}
                  </Typography>
                </MenuItem>
              ))}
            </TextField>
          )}
          {shownKeyRow !== null && (
            <TextField
              select
              value={value.sshKeyId ?? ""}
              onChange={(e) => {
                const v = e.target.value;
                if (v === "__new") {
                  goToSection("keychain");
                  return;
                }
                chooseKey(v === "" ? null : v);
              }}
              helperText={
                shownKeyRow === "fido2"
                  ? selectedKey
                    ? tr("The token must be plugged in to connect; you will be asked to touch it.")
                    : allKeys.filter(isHardwareKey).length === 0
                      ? tr("No FIDO2 key in this vault yet — generate one in Keychain → FIDO2.")
                      : undefined
                  : selectedKey?.agentBacked
                    ? tr("Signed by the system SSH agent; it must hold this key when you connect.")
                    : denyLocalKeys && !selectedKey
                      ? tr(
                          "This team allows only keys stored in its vaults — agent-backed keys are hidden.",
                        )
                      : value.sshKeyId === null && inheritedKey && from
                        ? tr("Without a key here “{inheritedKey}” from {from} is used.", {
                            inheritedKey,
                            from,
                          })
                        : undefined
              }
              slotProps={{
                htmlInput: {
                  "aria-label": shownKeyRow === "fido2" ? tr("FIDO2 key") : tr("SSH key"),
                },
                input: {
                  startAdornment: adornment(rowIcon[shownKeyRow]),
                  endAdornment: (
                    <InputAdornment position="end" sx={{ mr: 2 }}>
                      <IconButton
                        size="small"
                        aria-label={
                          shownKeyRow === "fido2" ? tr("Remove FIDO2") : tr("Remove SSH key")
                        }
                        onClick={() => {
                          onChange({ sshKeyId: null, sshCertificateId: null });
                          setKeyRow(null);
                        }}
                      >
                        <CloseRoundedIcon fontSize="small" />
                      </IconButton>
                    </InputAdornment>
                  ),
                },
              }}
            >
              <MenuItem value="">
                <em>{shownKeyRow === "fido2" ? tr("Choose a FIDO2 key") : tr("Choose a key")}</em>
              </MenuItem>
              {!keyKnown && value.sshKeyId && (
                <MenuItem value={value.sshKeyId}>
                  <em>{sshKeys.data ? tr("Unknown key") : tr("Loading…")}</em>
                </MenuItem>
              )}
              {allKeys
                .filter((k) => isHardwareKey(k) === (shownKeyRow === "fido2"))
                .map((k) => (
                  <MenuItem key={k.id} value={k.id}>
                    {k.label}
                    <Typography
                      component="span"
                      variant="caption"
                      color="text.secondary"
                      sx={{ ml: 1 }}
                    >
                      {k.keyType}
                      {k.agentBacked && " · " + tr("SSH agent")}
                    </Typography>
                  </MenuItem>
                ))}
              <MenuItem value="__new" sx={{ color: "primary.main" }}>
                <AddRoundedIcon fontSize="small" sx={{ mr: 1.25 }} />
                {shownKeyRow === "fido2"
                  ? tr("Generate FIDO2 key in Keychain…")
                  : tr("New key in Keychain…")}
              </MenuItem>
            </TextField>
          )}
          {showCert && (
            <TextField
              select
              value={value.sshCertificateId ?? ""}
              onChange={(e) => chooseCert(e.target.value === "" ? null : e.target.value)}
              helperText={
                certKey?.certificate
                  ? certificateSummary(certKey.certificate)
                  : certified.length === 0
                    ? tr("No key has a certificate yet — attach one in Keychain → Edit Key.")
                    : tr("Selecting a certificate also selects its key.")
              }
              slotProps={{
                htmlInput: { "aria-label": tr("Certificate") },
                input: {
                  startAdornment: adornment(rowIcon.certificate),
                  endAdornment: (
                    <InputAdornment position="end" sx={{ mr: 2 }}>
                      <IconButton
                        size="small"
                        aria-label={tr("Remove certificate")}
                        onClick={() => {
                          onChange({ sshCertificateId: null });
                          setCertRow(false);
                        }}
                      >
                        <CloseRoundedIcon fontSize="small" />
                      </IconButton>
                    </InputAdornment>
                  ),
                },
              }}
            >
              <MenuItem value="">
                <em>{tr("Choose a certificate")}</em>
              </MenuItem>
              {certified.map((k) => (
                <MenuItem key={k.id} value={k.certificate?.id ?? ""}>
                  {k.label}
                  <Typography
                    component="span"
                    variant="caption"
                    color="text.secondary"
                    sx={{ ml: 1 }}
                  >
                    {k.certificate ? certificateName(k.certificate) : null}
                  </Typography>
                </MenuItem>
              ))}
            </TextField>
          )}
          {missing.length > 0 && (
            <>
              <Button
                variant="text"
                color="inherit"
                size="small"
                startIcon={<AddRoundedIcon />}
                onClick={(e) => setAddAnchor(e.currentTarget)}
                sx={{ alignSelf: "flex-start", color: "text.secondary", ml: -0.5 }}
              >
                {missing.map((r) => rowTitle[r]).join(", ")}
                {shownKeyRow === null && inheritedKey && from && (
                  <Typography
                    component="span"
                    variant="caption"
                    color="text.disabled"
                    sx={{ ml: 1 }}
                  >
                    {tr("using “{key}” from {from}", { key: inheritedKey, from })}
                  </Typography>
                )}
              </Button>
              <Menu
                anchorEl={addAnchor}
                open={Boolean(addAnchor)}
                onClose={() => setAddAnchor(null)}
              >
                {missing.map((r) => (
                  <MenuItem key={r} onClick={() => addRow(r)}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.25 }}>
                      {rowIcon[r]}
                      {rowTitle[r]}
                    </Box>
                  </MenuItem>
                ))}
              </Menu>
            </>
          )}
        </>
      )}
      {ssh && agentForwarding && (
        <AgentForwardingRow value={value} onChange={onChange} inherited={inherited} />
      )}
    </>
  );
}

export function X11ForwardingRow({
  value,
  onChange,
  inherited,
}: {
  value: Pick<CredentialValues, "forwardX11">;
  onChange: (patch: Pick<CredentialValues, "forwardX11">) => void;
  inherited?: Inherited | null;
}) {
  const from = inherited && inherited.groupPath.length > 0 ? inherited.groupPath.join(" / ") : null;
  return (
    <SettingRow
      label={tr("X11 forwarding")}
      hint={
        !value.forwardX11 && inherited?.forwardX11 && from
          ? tr("Enabled by {from}; turning it on here changes nothing.", { from })
          : tr("Open remote GUI programs on this display (trusted X11, needs a local X server).")
      }
      last
      control={
        <Switch
          checked={value.forwardX11}
          onChange={(e) => onChange({ forwardX11: e.target.checked })}
        />
      }
    />
  );
}

export function AgentForwardingRow({
  value,
  onChange,
  inherited,
}: {
  value: Pick<CredentialValues, "agentForwarding">;
  onChange: (patch: Pick<CredentialValues, "agentForwarding">) => void;
  inherited?: Inherited | null;
}) {
  const from = inherited && inherited.groupPath.length > 0 ? inherited.groupPath.join(" / ") : null;
  return (
    <SettingRow
      label={tr("Agent forwarding")}
      hint={
        !value.agentForwarding && inherited?.agentForwarding && from
          ? tr("Enabled by {from}; turning it on here changes nothing.", { from })
          : tr("Expose the local SSH agent on the remote side.")
      }
      last
      control={
        <Switch
          checked={value.agentForwarding}
          onChange={(e) => onChange({ agentForwarding: e.target.checked })}
        />
      }
    />
  );
}
