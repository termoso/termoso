import { useMemo, useState } from "react";
import {
  Autocomplete,
  Box,
  Button,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import { Mono, SectionCard, SettingRow } from "@/components/ui";
import { useAppInfo } from "@/ipc/hooks";
import type { Settings } from "@/ipc/types";
import { appSuggestions } from "@/sftp/OpenWithDialog";
import { tr } from "@/i18n";

interface Props {
  s: Settings;
  update: (patch: Partial<Settings>) => void;
}

const normalizeExt = (raw: string) => raw.trim().replace(/^\.+/, "").toLowerCase();
const validExt = (ext: string) => ext.length <= 32 && !/[/\\.]/.test(ext);

/**
 * Settings → SFTP: which local application opens files of each extension
 * from the remote pane (`Open`), the same table `Open with… → Always use`
 * writes to. An empty extension is the fallback for files without one.
 */
export function SftpPage({ s, update }: Props) {
  const info = useAppInfo();
  const assoc = s.sftpOpenWith;
  const suggestions = useMemo(
    () => appSuggestions(assoc, info.data?.platform),
    [assoc, info.data?.platform],
  );
  const rows = useMemo(
    () => Object.entries(assoc).sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a < b ? -1 : 1)),
    [assoc],
  );
  const [newExt, setNewExt] = useState("");
  const [newApp, setNewApp] = useState("");

  const setApp = (ext: string, app: string) => {
    const chosen = app.trim();
    if (!chosen || chosen === assoc[ext]) return;
    update({ sftpOpenWith: { ...assoc, [ext]: chosen } });
  };
  const remove = (ext: string) => {
    update({ sftpOpenWith: Object.fromEntries(rows.filter(([e]) => e !== ext)) });
  };
  const ext = normalizeExt(newExt);
  const canAdd = validExt(ext) && newApp.trim().length > 0 && !(ext in assoc);
  const add = () => {
    if (!canAdd) return;
    update({ sftpOpenWith: { ...assoc, [ext]: newApp.trim() } });
    setNewExt("");
    setNewApp("");
  };

  return (
    <>
      <SectionCard title={tr("Transfers")}>
        <SettingRow
          label={tr("Transfer speed limit")}
          hint={tr("KiB/s per file, for the queue, watch & upload and edits. 0 is unlimited.")}
          last
          control={
            <TextField
              type="number"
              size="small"
              value={s.sftpRateLimitKib}
              onChange={(e) => {
                const n = Math.max(0, Math.min(1_048_576, Math.floor(Number(e.target.value) || 0)));
                update({ sftpRateLimitKib: n });
              }}
              slotProps={{ htmlInput: { min: 0, max: 1_048_576, step: 64 } }}
              sx={{ width: 140 }}
            />
          }
        />
      </SectionCard>
      <SectionCard title={tr("File associations")}>
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
          {tr(
            "Applications used by Open for files of each extension. Files are downloaded to a private folder and every save is uploaded back. Extensions without an entry open in the system default application.",
          )}
        </Typography>
        <Stack spacing={1}>
          {rows.length === 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
              {tr("No associations yet — add one below or tick “Always use” in Open with….")}
            </Typography>
          )}
          {rows.map(([e, app]) => (
            <AssociationRow
              key={e}
              ext={e}
              app={app}
              suggestions={suggestions}
              onChange={(v) => setApp(e, v)}
              onRemove={() => remove(e)}
            />
          ))}
          <Stack
            component="form"
            direction="row"
            spacing={1}
            sx={{ alignItems: "center", pt: 1 }}
            onSubmit={(ev) => {
              ev.preventDefault();
              add();
            }}
          >
            <TextField
              value={newExt}
              placeholder="ext"
              onChange={(ev) => setNewExt(ev.target.value)}
              error={newExt.length > 0 && (!validExt(ext) || ext in assoc)}
              helperText={
                newExt.length > 0 && ext in assoc
                  ? tr("Already listed")
                  : newExt.length > 0 && !validExt(ext)
                    ? tr("Letters and digits only")
                    : undefined
              }
              sx={{ width: 140 }}
              slotProps={{
                htmlInput: { spellCheck: false, style: { fontFamily: "monospace" } },
                input: { startAdornment: <InputAdornment position="start">.</InputAdornment> },
              }}
            />
            <Autocomplete
              freeSolo
              autoHighlight
              options={suggestions}
              inputValue={newApp}
              onInputChange={(_, v) => setNewApp(v)}
              sx={{ flex: 1 }}
              renderInput={(params) => (
                <TextField {...params} placeholder={tr("Command, path or application name")} />
              )}
            />
            <Button
              type="submit"
              variant="outlined"
              color="inherit"
              disabled={!canAdd}
              startIcon={<AddRoundedIcon />}
              sx={{ flexShrink: 0 }}
            >
              {tr("Add")}
            </Button>
          </Stack>
        </Stack>
      </SectionCard>
    </>
  );
}

function AssociationRow({
  ext,
  app,
  suggestions,
  onChange,
  onRemove,
}: {
  ext: string;
  app: string;
  suggestions: string[];
  onChange: (app: string) => void;
  onRemove: () => void;
}) {
  const [draft, setDraft] = useState(app);
  const commit = () => {
    if (draft.trim()) onChange(draft);
    else setDraft(app);
  };
  return (
    <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
      <Box sx={{ width: 140, flexShrink: 0 }}>
        {ext ? (
          <Mono>.{ext}</Mono>
        ) : (
          <Typography variant="body2" color="text.secondary">
            {tr("No extension")}
          </Typography>
        )}
      </Box>
      <Autocomplete
        freeSolo
        autoHighlight
        options={suggestions}
        inputValue={draft}
        onInputChange={(_, v) => setDraft(v)}
        onBlur={commit}
        sx={{ flex: 1 }}
        renderInput={(params) => (
          <TextField
            {...params}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                commit();
              }
            }}
          />
        )}
      />
      <Tooltip title={tr("Remove")}>
        <IconButton size="small" onClick={onRemove}>
          <DeleteOutlineRoundedIcon fontSize="small" />
        </IconButton>
      </Tooltip>
    </Stack>
  );
}
