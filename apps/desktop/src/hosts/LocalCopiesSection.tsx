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

// One path per line; commas are part of a path, not a separator.
const splitPaths = (v: string) =>
  v
    .split("\n")
    .map((p) => p.trim())
    .filter(Boolean);

/** Multi-line path list that keeps the text as typed until it is saved. */
function PathListField({
  label,
  placeholder,
  paths,
  onChange,
  onBlur,
}: {
  label: string;
  placeholder: string;
  paths: string[];
  onChange: (paths: string[]) => void;
  onBlur: () => void;
}) {
  const [text, setText] = useState<string | null>(null);
  return (
    <Field label={label}>
      <TextField
        size="small"
        multiline
        minRows={1}
        value={text ?? paths.join("\n")}
        onChange={(e) => {
          setText(e.target.value);
          onChange(splitPaths(e.target.value));
        }}
        onBlur={() => {
          setText(null);
          onBlur();
        }}
        placeholder={placeholder}
      />
    </Field>
  );
}

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
          <PathListField
            label={tr("Only these paths (one per line, empty = all)")}
            placeholder={"/var/www\n/home/me/docs"}
            paths={draft.includePaths}
            onChange={(includePaths) => setDraft({ ...draft, includePaths })}
            onBlur={() => save.mutate(draft)}
          />
          <PathListField
            label={tr("Never these paths")}
            placeholder="/home/me/.ssh"
            paths={draft.excludePaths}
            onChange={(excludePaths) => setDraft({ ...draft, excludePaths })}
            onBlur={() => save.mutate(draft)}
          />
        </>
      )}
    </SectionCard>
  );
}
