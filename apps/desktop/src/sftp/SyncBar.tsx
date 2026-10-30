import { Box, Chip, IconButton, Stack, Tooltip, Typography } from "@mui/material";
import StopRoundedIcon from "@mui/icons-material/StopRounded";
import SyncRoundedIcon from "@mui/icons-material/SyncRounded";
import { useEffect, useState } from "react";
import * as ipc from "@/ipc/commands";
import type { SyncCard, SyncStats } from "@/ipc/types";
import { tr } from "@/i18n";
import { formatSize } from "./format";

/** The folders being watched for this connection set, one row each, with stop. */
export function SyncBar() {
  const [cards, setCards] = useState<Record<string, SyncCard>>({});
  useEffect(() => {
    let stopped = false;
    void ipc
      .syncsList()
      .then((list) => {
        if (!stopped) setCards(Object.fromEntries(list.map((c) => [c.info.id, c])));
      })
      .catch(() => undefined);
    const un = ipc.onSyncEvent((e) => {
      setCards((m) => {
        if (e.type === "started") {
          return { ...m, [e.info.id]: { info: e.info, stats: emptyStats() } };
        }
        if (e.type === "stopped") {
          const { [e.id]: _gone, ...rest } = m;
          return rest;
        }
        const card = m[e.id];
        return card ? { ...m, [e.id]: { ...card, stats: e.stats } } : m;
      });
    });
    return () => {
      stopped = true;
      void un.then((f) => f());
    };
  }, []);
  const list = Object.values(cards);
  if (list.length === 0) return null;
  return (
    <Stack spacing={0.5} sx={{ px: 1.5, py: 0.75, borderTop: 1, borderColor: "border.light" }}>
      {list.map((c) => (
        <Stack
          key={c.info.id}
          direction="row"
          spacing={1}
          sx={{ minWidth: 0, alignItems: "center" }}
        >
          <SyncRoundedIcon
            fontSize="small"
            color={c.stats.lastError ? "error" : c.stats.pending > 0 ? "primary" : "action"}
            sx={
              c.stats.pending > 0
                ? {
                    animation: "spin 1.2s linear infinite",
                    "@keyframes spin": { to: { transform: "rotate(360deg)" } },
                  }
                : undefined
            }
          />
          <Typography
            variant="body2"
            noWrap
            sx={{ flexShrink: 1, minWidth: 0 }}
            title={`${c.info.local} → ${c.info.remote}`}
          >
            {c.info.local} → {c.info.remote}
          </Typography>
          <Box sx={{ flex: 1 }} />
          <Chip
            size="small"
            variant="outlined"
            label={summary(c.stats)}
            color={c.stats.lastError ? "error" : "default"}
            title={c.stats.lastError ?? c.stats.lastPath ?? ""}
          />
          <Tooltip title={tr("Stop watching")}>
            <IconButton
              size="small"
              onClick={() => void ipc.syncStop(c.info.id).catch(() => undefined)}
            >
              <StopRoundedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      ))}
    </Stack>
  );
}

const emptyStats = (): SyncStats => ({
  uploaded: 0,
  downloaded: 0,
  bytes: 0,
  removed: 0,
  failed: 0,
  pending: 0,
  lastPath: null,
  lastAt: null,
  lastError: null,
});

function summary(s: SyncStats): string {
  if (s.pending > 0) return tr("Uploading {n}…", { n: s.pending });
  if (s.lastError) return tr("{n} failed", { n: s.failed });
  if (s.uploaded === 0 && s.removed === 0 && s.downloaded === 0) return tr("Watching for changes");
  const parts = [tr("{n} uploaded ({size})", { n: s.uploaded, size: formatSize(s.bytes) })];
  if (s.downloaded > 0) parts.push(tr("{n} downloaded", { n: s.downloaded }));
  if (s.removed > 0) parts.push(tr("{n} removed", { n: s.removed }));
  if (s.failed > 0) parts.push(tr("{n} failed", { n: s.failed }));
  return parts.join(" · ");
}
