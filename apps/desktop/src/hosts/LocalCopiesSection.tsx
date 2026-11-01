import { Stack, Switch, TextField, Typography } from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Field, SectionCard } from "@/components/ui";
import * as ipc from "@/ipc/commands";
import type { FileCacheSettings, Uuid } from "@/ipc/types";
import { tr } from "@/i18n";

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

const splitPaths = (v: string) =>
  v
    .split(/[,\n]/)
    .map((p) => p.trim())
    .filter(Boolean);

/**
 * Host → Files: keep encrypted local copies of files read over SFTP so the
 * pane can browse them when the host is unreachable. Device-local, saved as
 * soon as a control changes.
 */
export function LocalCopiesSection({ hostId }: { hostId: Uuid }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["fileCacheSettings", hostId],
    queryFn: () => ipc.fileCacheSettings(hostId),
  });
  // Local edits override the stored settings until they are saved.
  const [edited, setEdited] = useState<FileCacheSettings | null>(null);
  const draft = edited ?? q.data ?? null;
  const setDraft = setEdited;
  const save = useMutation({
    mutationFn: (s: FileCacheSettings) => ipc.setFileCacheSettings(hostId, s),
    onSuccess: () => {
      setEdited(null);
      void qc.invalidateQueries({ queryKey: ["fileCacheSettings", hostId] });
      void qc.invalidateQueries({ queryKey: ["fileCacheOverview"] });
    },
  });
  if (!draft?.allowed) return null;
  const commit = (next: FileCacheSettings) => {
    setDraft(next);
    save.mutate(next);
  };
  const num = (label: string, key: "maxFileMib" | "maxTotalMib") => (
    <Field label={label}>
      <TextField
        size="small"
        type="number"
        value={draft[key]}
        onChange={(e) => setDraft({ ...draft, [key]: Math.max(1, Number(e.target.value) || 1) })}
        onBlur={() => save.mutate(draft)}
        slotProps={{ htmlInput: { min: 1 } }}
      />
    </Field>
  );
  return (
    <SectionCard title={tr("Local copies")}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between" }}>
        <Stack>
          <Typography variant="body2">{tr("Keep local copies")}</Typography>
          <Typography variant="caption" color="text.secondary">
            {tr(
              "Files you open are kept encrypted on this device and can be browsed when the host is unreachable.",
            )}
          </Typography>
        </Stack>
        <Switch
          checked={draft.enabled}
          onChange={(e) => commit({ ...draft, enabled: e.target.checked })}
        />
      </Stack>
      {draft.enabled && (
        <>
          {num(tr("Max file size (MiB)"), "maxFileMib")}
          {num(tr("Total size limit (MiB)"), "maxTotalMib")}
          <Field label={tr("Only these paths (comma-separated, empty = all)")}>
            <TextField
              size="small"
              value={draft.includePaths.join(", ")}
              onChange={(e) => setDraft({ ...draft, includePaths: splitPaths(e.target.value) })}
              onBlur={() => save.mutate(draft)}
              placeholder="/var/www, /home/me/docs"
            />
          </Field>
          <Field label={tr("Never these paths")}>
            <TextField
              size="small"
              value={draft.excludePaths.join(", ")}
              onChange={(e) => setDraft({ ...draft, excludePaths: splitPaths(e.target.value) })}
              onBlur={() => save.mutate(draft)}
              placeholder="/home/me/.ssh"
            />
          </Field>
        </>
      )}
    </SectionCard>
  );
}
