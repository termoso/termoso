import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import { open as pickPath } from "@tauri-apps/plugin-dialog";
import { useState } from "react";
import * as ipc from "@/ipc/commands";
import type { Uuid } from "@/ipc/types";
import { errorMessage } from "@/ipc/types";
import { tr } from "@/i18n";

export const DEFAULT_IGNORE = ".git node_modules .DS_Store *.swp *~ .#* *.tmp";

/**
 * Watch & upload: pick a local folder and a remote folder on the open
 * connection; every save under the local one is uploaded to the same place
 * under the remote one until stopped.
 */
export function SyncDialog({
  sftpId,
  defaultLocal,
  defaultRemote,
  onClose,
}: {
  sftpId: Uuid | null;
  defaultLocal: string | null;
  defaultRemote: string | null;
  onClose: () => void;
}) {
  const [local, setLocal] = useState(defaultLocal ?? "");
  const [remote, setRemote] = useState(defaultRemote ?? "");
  const [ignore, setIgnore] = useState(DEFAULT_IGNORE);
  const [deleteRemote, setDeleteRemote] = useState(false);
  const [uploadExisting, setUploadExisting] = useState(true);
  const [twoWay, setTwoWay] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const browse = async () => {
    const picked = await pickPath({ directory: true, multiple: false, title: tr("Local folder") });
    if (typeof picked === "string") setLocal(picked);
  };
  const start = async () => {
    if (!sftpId) return;
    setBusy(true);
    setError(null);
    try {
      await ipc.syncStart({
        sftpId,
        local: local.trim(),
        remote: remote.trim(),
        ignore: ignore.split(/[\s,]+/).filter((s) => s !== ""),
        deleteRemote,
        uploadExisting,
        twoWay,
      });
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={sftpId !== null} onClose={busy ? undefined : onClose} fullWidth maxWidth="sm">
      <DialogTitle>{tr("Watch & upload")}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <Typography variant="body2" color="text.secondary">
            {tr(
              "Every file saved under the local folder is uploaded to the same place under the remote folder, until you stop. Local → server; turn on two-way to also pull what changes on the server.",
            )}
          </Typography>
          <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start" }}>
            <TextField
              label={tr("Local folder")}
              value={local}
              onChange={(e) => setLocal(e.target.value)}
              fullWidth
              size="small"
              autoFocus
            />
            <Button onClick={() => void browse()} sx={{ flexShrink: 0, mt: 0.25 }}>
              {tr("Browse…")}
            </Button>
          </Stack>
          <TextField
            label={tr("Remote folder")}
            value={remote}
            onChange={(e) => setRemote(e.target.value)}
            fullWidth
            size="small"
            placeholder="/srv/app"
          />
          <TextField
            label={tr("Ignore")}
            helperText={tr("Names or globs skipped at any depth, separated by spaces")}
            value={ignore}
            onChange={(e) => setIgnore(e.target.value)}
            fullWidth
            size="small"
          />
          <FormControlLabel
            control={
              <Switch
                checked={uploadExisting}
                onChange={(e) => setUploadExisting(e.target.checked)}
              />
            }
            label={tr("Upload everything in the folder now")}
          />
          <FormControlLabel
            control={
              <Switch checked={deleteRemote} onChange={(e) => setDeleteRemote(e.target.checked)} />
            }
            label={tr("Delete on the server what is deleted locally")}
          />
          <FormControlLabel
            control={<Switch checked={twoWay} onChange={(e) => setTwoWay(e.target.checked)} />}
            label={tr(
              "Two-way: download files that change on the server (checked every 15 s, newest wins, deletions are not pulled)",
            )}
          />
          {error && (
            <Typography variant="body2" color="error">
              {error}
            </Typography>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          {tr("Cancel")}
        </Button>
        <Button
          variant="contained"
          onClick={() => void start()}
          disabled={busy || local.trim() === "" || remote.trim() === ""}
        >
          {tr("Start watching")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
