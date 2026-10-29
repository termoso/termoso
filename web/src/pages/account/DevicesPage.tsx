import { useState } from "react";
import { tr, trx } from "@/i18n";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Chip,
  IconButton,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Tooltip,
} from "@mui/material";
import ComputerRoundedIcon from "@mui/icons-material/ComputerRounded";
import LanguageRoundedIcon from "@mui/icons-material/LanguageRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import PhoneAndroidRoundedIcon from "@mui/icons-material/PhoneAndroidRounded";
import PhoneIphoneRoundedIcon from "@mui/icons-material/PhoneIphoneRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { UnlockCancelled, withStepUp } from "@/auth/unlock";
import { accountApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { Device, Platform } from "@/api/types";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { PageHeader } from "@/components/PageHeader";
import { Paged } from "@/components/Pager";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { formatDateTime, formatRelative } from "@/components/format";

function platformIcon(p: Platform) {
  switch (p) {
    case "android":
      return <PhoneAndroidRoundedIcon />;
    case "ios":
      return <PhoneIphoneRoundedIcon />;
    case "web":
      return <LanguageRoundedIcon />;
    case "cli":
      return <TerminalRoundedIcon />;
    default:
      return <ComputerRoundedIcon />;
  }
}

const platformLabel: Record<Platform, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
  web: "Web",
  cli: "CLI",
};

export function DevicesPage() {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const devices = useQuery({ queryKey: queryKeys.devices, queryFn: accountApi.devices });
  const [target, setTarget] = useState<Device | null>(null);
  const [revokeOthers, setRevokeOthers] = useState(false);

  const revoke = useMutation({
    mutationFn: (ids: string[]) =>
      withStepUp(() => Promise.all(ids.map((id) => accountApi.revokeDevice(id)))),
    onSuccess: async (_r, ids) => {
      setTarget(null);
      setRevokeOthers(false);
      await qc.invalidateQueries({ queryKey: queryKeys.devices });
      snack.notify(
        ids.length === 1
          ? tr("Device signed out")
          : tr("{length} devices signed out", { length: ids.length }),
      );
    },
    onError: (e) => {
      if (!(e instanceof UnlockCancelled)) snack.error(errorMessage(e));
    },
  });

  if (devices.isPending) return <Loading />;
  if (devices.isError) return <Alert severity="error">{errorMessage(devices.error)}</Alert>;

  const list = [...devices.data.devices].sort((a, b) => Number(b.current) - Number(a.current));
  const others = list.filter((d) => !d.current);

  return (
    <>
      <PageHeader
        title={tr("Devices")}
        subtitle={tr(
          "Every signed-in app and browser. Signing a device out revokes its session immediately.",
        )}
        actions={
          others.length > 0 && (
            <Button
              variant="outlined"
              color="error"
              startIcon={<LogoutRoundedIcon />}
              onClick={() => setRevokeOthers(true)}
            >
              {tr("Sign out all other devices")}
            </Button>
          )
        }
      />
      <Section title={`${list.length} ${list.length === 1 ? "device" : "devices"}`} disablePadding>
        {list.length === 0 ? (
          <EmptyState title={tr("No devices")} />
        ) : (
          <Paged items={list}>
            {(rows) => (
              <List disablePadding>
                {rows.map((d) => (
                  <ListItem
                    key={d.id}
                    divider
                    secondaryAction={
                      !d.current && (
                        <Tooltip title={tr("Sign out this device")}>
                          <IconButton
                            edge="end"
                            onClick={() => setTarget(d)}
                            aria-label={tr("Sign out device")}
                          >
                            <LogoutRoundedIcon />
                          </IconButton>
                        </Tooltip>
                      )
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
                          color: d.current ? "primary.main" : "text.secondary",
                          "& svg": { fontSize: 20 },
                        }}
                      >
                        {platformIcon(d.platform)}
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={
                        <Box
                          sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}
                        >
                          {d.name}
                          {d.current && (
                            <Chip size="small" color="primary" label={tr("This device")} />
                          )}
                        </Box>
                      }
                      secondary={tr("{v1} · v{app_version} · {v2} · Active {v3} · Added {v4}", {
                        v1: platformLabel[d.platform],
                        app_version: d.app_version,
                        v2: d.last_ip ?? tr("unknown IP"),
                        v3: formatRelative(d.last_seen_at),
                        v4: formatDateTime(d.created_at),
                      })}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Paged>
        )}
      </Section>

      <ConfirmDialog
        open={target !== null}
        title={tr("Sign out device?")}
        confirmLabel={tr("Sign out")}
        danger
        busy={revoke.isPending}
        onCancel={() => setTarget(null)}
        onConfirm={() => {
          if (target) revoke.mutate([target.id]);
        }}
      >
        {trx("“{name}” will need to sign in again and unlock with the password.", {
          name: target?.name,
        })}
      </ConfirmDialog>
      <ConfirmDialog
        open={revokeOthers}
        title={tr("Sign out all other devices?")}
        confirmLabel={tr("Sign out all")}
        danger
        busy={revoke.isPending}
        onCancel={() => setRevokeOthers(false)}
        onConfirm={() => revoke.mutate(others.map((d) => d.id))}
      >
        {trx("{length} {v1} will be signed out. This browser stays signed in.", {
          length: others.length,
          v1: others.length === 1 ? "device" : "devices",
        })}
      </ConfirmDialog>
    </>
  );
}
