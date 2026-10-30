import {
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";
import * as ipc from "@/ipc/commands";
import type { DiffResult, DiffSide } from "@/ipc/types";
import { errorMessage } from "@/ipc/types";
import { tr } from "@/i18n";
import { monoFontFamily } from "@/theme/theme";
import { formatSize } from "./format";

export interface CompareRequest {
  name: string;
  left: DiffSide;
  right: DiffSide;
}

const sideLabel = (s: DiffSide) =>
  s.sftpId ? tr("Remote: {path}", { path: s.path }) : tr("Local: {path}", { path: s.path });

/** Line diff of the same file on both panes; hunks with context, folds between.
 *  Mounted with a `key` per request, so state is never reset in place. */
export function DiffDialog({
  request,
  onClose,
}: {
  request: CompareRequest | null;
  onClose: () => void;
}) {
  const [result, setResult] = useState<DiffResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!request) return;
    let alive = true;
    ipc
      .sftpDiff(request.left, request.right)
      .then((r) => {
        if (alive) setResult(r);
      })
      .catch((e: unknown) => {
        if (alive) setError(errorMessage(e));
      });
    return () => {
      alive = false;
    };
  }, [request]);

  return (
    <Dialog open={request !== null} onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>{tr("Compare: {name}", { name: request?.name ?? "" })}</DialogTitle>
      <DialogContent dividers sx={{ p: 0 }}>
        {request && (
          <Stack
            direction="row"
            spacing={2}
            sx={{ px: 2, py: 1, borderBottom: 1, borderColor: "divider" }}
          >
            <Typography variant="caption" sx={{ flex: 1, fontFamily: monoFontFamily }} noWrap>
              − {sideLabel(request.left)}
              {result ? ` (${formatSize(result.leftSize)})` : ""}
            </Typography>
            <Typography variant="caption" sx={{ flex: 1, fontFamily: monoFontFamily }} noWrap>
              + {sideLabel(request.right)}
              {result ? ` (${formatSize(result.rightSize)})` : ""}
            </Typography>
          </Stack>
        )}
        {error && (
          <Typography color="error" variant="body2" sx={{ p: 2 }}>
            {error}
          </Typography>
        )}
        {!error && !result && (
          <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
            <CircularProgress size={24} />
          </Box>
        )}
        {result?.same && (
          <Typography variant="body2" sx={{ p: 2 }}>
            {tr("The files are identical.")}
          </Typography>
        )}
        {result && !result.same && result.binary && (
          <Typography variant="body2" sx={{ p: 2 }}>
            {tr("Binary content differs; sizes {a} and {b}.", {
              a: formatSize(result.leftSize),
              b: formatSize(result.rightSize),
            })}
          </Typography>
        )}
        {result && !result.same && !result.binary && (
          <Box
            component="pre"
            sx={{
              m: 0,
              fontFamily: monoFontFamily,
              fontSize: 12,
              lineHeight: 1.5,
              overflow: "auto",
              maxHeight: "65vh",
            }}
          >
            {result.lines.map((l, i) =>
              l.kind === "skip" ? (
                <Box
                  key={i}
                  sx={{
                    px: 2,
                    color: "text.disabled",
                    bgcolor: "action.hover",
                    userSelect: "none",
                  }}
                >
                  {tr("… {n} unchanged lines", { n: Number(l.text) })}
                </Box>
              ) : (
                <Box
                  key={i}
                  sx={{
                    display: "flex",
                    px: 1,
                    bgcolor:
                      l.kind === "insert"
                        ? "rgba(46, 160, 67, 0.18)"
                        : l.kind === "delete"
                          ? "rgba(248, 81, 73, 0.18)"
                          : undefined,
                  }}
                >
                  <Box
                    component="span"
                    sx={{ width: 44, textAlign: "right", color: "text.disabled", flexShrink: 0 }}
                  >
                    {l.old ?? ""}
                  </Box>
                  <Box
                    component="span"
                    sx={{
                      width: 44,
                      textAlign: "right",
                      color: "text.disabled",
                      flexShrink: 0,
                      mr: 1,
                    }}
                  >
                    {l.new ?? ""}
                  </Box>
                  <Box component="span" sx={{ width: 12, flexShrink: 0, color: "text.secondary" }}>
                    {l.kind === "insert" ? "+" : l.kind === "delete" ? "−" : " "}
                  </Box>
                  <Box component="span" sx={{ whiteSpace: "pre" }}>
                    {l.text}
                  </Box>
                </Box>
              ),
            )}
            {result.truncated && (
              <Box sx={{ px: 2, color: "text.disabled" }}>{tr("… output truncated")}</Box>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{tr("Close")}</Button>
      </DialogActions>
    </Dialog>
  );
}
