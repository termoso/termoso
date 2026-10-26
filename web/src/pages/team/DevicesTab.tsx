import { useState } from "react";
import { tr } from "@/i18n";
import {
  Alert,
  Button,
  Chip,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import DevicesOtherRoundedIcon from "@mui/icons-material/DevicesOtherRounded";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/api/client";
import { teamsApi } from "@/api/endpoints";
import { queryKeys } from "@/api/hooks";
import type { Team, TeamDevice } from "@/api/types";
import { Paged } from "@/components/Pager";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { Loading } from "@/components/Loading";
import { Section } from "@/components/Section";
import { useSnackbar } from "@/components/Snackbar";
import { formatRelative } from "@/components/format";

export function DevicesTab({ team }: { team: Team }) {
  const qc = useQueryClient();
  const snack = useSnackbar();
  const q = useQuery({
    queryKey: queryKeys.teamDevices(team.id),
    queryFn: () => teamsApi.devices(team.id),
  });
  const [rejecting, setRejecting] = useState<TeamDevice | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: queryKeys.teamDevices(team.id) });
  const approve = useMutation({
    mutationFn: (d: TeamDevice) => teamsApi.approveDevice(team.id, d.device_id),
    onSuccess: async () => {
      await refresh();
      snack.notify(tr("Device approved"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  const reject = useMutation({
    mutationFn: (d: TeamDevice) => teamsApi.rejectDevice(team.id, d.device_id),
    onSuccess: async () => {
      await refresh();
      setRejecting(null);
      snack.notify(tr("Device rejected and signed out"));
    },
    onError: (e) => snack.error(errorMessage(e)),
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <Alert severity="error">{errorMessage(q.error)}</Alert>;
  const pending = q.data.devices.filter((d) => d.status === "pending");
  const decided = q.data.devices.filter((d) => d.status !== "pending");
  const statusChip = (d: TeamDevice) =>
    d.status === "pending" ? (
      <Chip size="small" color="warning" label={tr("Pending")} />
    ) : d.status === "approved" ? (
      <Chip size="small" color="success" variant="outlined" label={tr("Approved")} />
    ) : (
      <Chip size="small" color="error" variant="outlined" label={tr("Rejected")} />
    );
  const rows = (list: TeamDevice[], actions: boolean) => (
    <Paged items={list}>
      {(page) => (
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>{tr("Member")}</TableCell>
                <TableCell>{tr("Device")}</TableCell>
                <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                  {tr("Last IP")}
                </TableCell>
                <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                  {tr("Last seen")}
                </TableCell>
                <TableCell>{tr("Status")}</TableCell>
                {actions && <TableCell align="right" />}
              </TableRow>
            </TableHead>
            <TableBody>
              {page.map((d) => (
                <TableRow key={d.device_id} hover>
                  <TableCell>{d.user_email}</TableCell>
                  <TableCell>
                    <Typography variant="body2">{d.name}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {d.platform}
                      {d.app_version ? ` · ${d.app_version}` : ""}
                    </Typography>
                  </TableCell>
                  <TableCell
                    sx={{ display: { xs: "none", md: "table-cell" }, fontFamily: "monospace" }}
                  >
                    {d.last_ip ?? "—"}
                  </TableCell>
                  <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>
                    {formatRelative(d.last_seen_at)}
                  </TableCell>
                  <TableCell>{statusChip(d)}</TableCell>
                  {actions && (
                    <TableCell align="right">
                      <Stack direction="row" spacing={1} sx={{ justifyContent: "flex-end" }}>
                        <Button
                          size="small"
                          variant="contained"
                          disabled={approve.isPending}
                          onClick={() => approve.mutate(d)}
                        >
                          {tr("Approve")}
                        </Button>
                        <Button size="small" color="error" onClick={() => setRejecting(d)}>
                          {tr("Reject")}
                        </Button>
                      </Stack>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Paged>
  );
  return (
    <Stack spacing={2}>
      {!q.data.admin_approval && (
        <Alert severity="info">
          {tr(
            "Admin approval for new devices is off in this team's policies; new devices sign in without a review.",
          )}
        </Alert>
      )}
      <Section
        title={tr("Devices awaiting approval")}
        description={tr(
          "New devices of members sign in only after approval. Rejecting ends the device's sessions; it can sign in again later and will wait here once more.",
        )}
      >
        {pending.length === 0 ? (
          <EmptyState
            icon={<DevicesOtherRoundedIcon fontSize="inherit" />}
            title={tr("No pending devices")}
          />
        ) : (
          rows(pending, true)
        )}
      </Section>
      {decided.length > 0 && (
        <Section title={tr("Reviewed devices")}>{rows(decided, false)}</Section>
      )}
      <ConfirmDialog
        open={rejecting !== null}
        title={tr("Reject device?")}
        confirmLabel={tr("Reject")}
        danger
        busy={reject.isPending}
        onCancel={() => setRejecting(null)}
        onConfirm={() => rejecting && reject.mutate(rejecting)}
      >
        {rejecting &&
          tr("{v1} on {v2} will be signed out and blocked until approved again.", {
            v1: rejecting.user_email,
            v2: rejecting.name,
          })}
      </ConfirmDialog>
    </Stack>
  );
}
