import { useRef, useState, type ReactNode } from "react";
import AddPhotoAlternateRoundedIcon from "@mui/icons-material/AddPhotoAlternateRounded";
import {
  Box,
  Button,
  ButtonBase,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Popover,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { IconTile } from "@/components/ui";
import { sizes } from "@/theme/theme";
import { tr } from "@/i18n";
import {
  customIconFromDataUrl,
  customIconFromUrl,
  customIconSource,
  customIconUrl,
  isCustomIcon,
  isSupportedImageMime,
  MAX_CUSTOM_ICON_FILE_BYTES,
} from "./customIcon";
import { CustomIconGlyph, DistroGlyph } from "./HostAvatar";
import { iconSections, pickedIcon } from "./icons";

const sectionTitle = (s: string) =>
  s === "General"
    ? tr("General")
    : s === "Applications"
      ? tr("Applications")
      : tr("Operating systems");

function formatLimit(bytes: number) {
  return `${Math.round(bytes / 1024)} KiB`;
}

function CustomIconDialog({
  open,
  value,
  onChange,
  onClose,
}: {
  open: boolean;
  value: string | null;
  onChange: (id: string | null) => void;
  onClose: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [draft, setDraft] = useState<string | null>(() => (isCustomIcon(value) ? value : null));
  const [url, setUrl] = useState(() => customIconUrl(value) ?? "");
  const [fileName, setFileName] = useState<string | null>(() =>
    value?.startsWith("custom:data:") ? tr("Local image selected") : null,
  );
  const [error, setError] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState(false);

  const chooseFile = () => inputRef.current?.click();
  const onFile = (file: File | undefined) => {
    if (!file) return;
    setError(null);
    setPreviewError(false);
    if (file.size > MAX_CUSTOM_ICON_FILE_BYTES) {
      setError(
        tr("The selected image is too large. Maximum size: {size}.", {
          size: formatLimit(MAX_CUSTOM_ICON_FILE_BYTES),
        }),
      );
      return;
    }
    if (!isSupportedImageMime(file.type)) {
      setError(tr("This image format is not supported."));
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const encoded =
        typeof reader.result === "string" ? customIconFromDataUrl(reader.result) : null;
      if (!encoded) {
        setError(tr("The image could not be read."));
        return;
      }
      setDraft(encoded);
      setUrl("");
      setFileName(file.name);
    };
    reader.onerror = () => setError(tr("The image could not be read."));
    reader.readAsDataURL(file);
  };

  const candidate = draft ?? customIconFromUrl(url);
  const preview = customIconSource(candidate);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{tr("Custom icon")}</DialogTitle>
      <DialogContent>
        <Stack spacing={1.5}>
          <Typography variant="body2" color="text.secondary">
            {tr(
              "Choose an image from your computer or paste an HTTP(S) image URL. Local images are embedded in the vault; remote images load from their URL when shown.",
            )}
          </Typography>
          <Box
            sx={{ display: "flex", justifyContent: "center", minHeight: 72, alignItems: "center" }}
          >
            {preview && !previewError ? (
              <Box
                component="img"
                src={preview}
                alt={tr("Custom icon preview")}
                onError={() => setPreviewError(true)}
                sx={{ width: 72, height: 72, objectFit: "contain", borderRadius: 2 }}
              />
            ) : (
              <IconTile size={72}>
                <AddPhotoAlternateRoundedIcon />
              </IconTile>
            )}
          </Box>
          <Button
            variant="outlined"
            onClick={chooseFile}
            startIcon={<AddPhotoAlternateRoundedIcon />}
          >
            {tr("Choose image…")}
          </Button>
          <input
            ref={inputRef}
            hidden
            type="file"
            accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml,image/x-icon,image/avif"
            onChange={(e) => {
              onFile(e.target.files?.[0]);
              e.currentTarget.value = "";
            }}
          />
          {fileName && (
            <Typography variant="caption" color="text.secondary" noWrap>
              {fileName}
            </Typography>
          )}
          <TextField
            label={tr("Image URL")}
            type="url"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setDraft(null);
              setFileName(null);
              setError(null);
              setPreviewError(false);
            }}
            placeholder="https://example.com/server.png"
            helperText={tr("Use an HTTP or HTTPS URL that points to an image.")}
            fullWidth
          />
          {error && (
            <Typography variant="caption" color="error">
              {error}
            </Typography>
          )}
          {previewError && (
            <Typography variant="caption" color="error">
              {tr("The image preview could not be loaded. You can still save this URL.")}
            </Typography>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        {isCustomIcon(value) && (
          <Button
            color="error"
            onClick={() => {
              onChange(null);
              onClose();
            }}
            sx={{ mr: "auto" }}
          >
            {tr("Remove custom icon")}
          </Button>
        )}
        <Button onClick={onClose}>{tr("Cancel")}</Button>
        <Button
          variant="contained"
          disabled={candidate === null}
          onClick={() => {
            if (candidate) {
              onChange(candidate);
              onClose();
            }
          }}
        >
          {tr("Use this image")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * Tile that opens a gallery of icons. `value` is the stored icon id (`null` =
 * automatic); `fallback` is what the tile shows while nothing is picked.
 */
export function IconPicker({
  value,
  onChange,
  fallback,
  autoLabel,
  disabled,
}: {
  value: string | null;
  onChange: (id: string | null) => void;
  fallback: ReactNode;
  autoLabel: string;
  disabled?: boolean;
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const [customOpen, setCustomOpen] = useState(false);
  const picked = pickedIcon(value);
  const customValue = isCustomIcon(value) ? value : null;
  const custom = customValue !== null;
  return (
    <>
      <Tooltip title={tr("Change icon")}>
        <span>
          <ButtonBase
            disabled={disabled}
            aria-label={tr("Change icon")}
            onClick={(e) => setAnchor(e.currentTarget)}
            sx={{ borderRadius: 2 }}
          >
            <IconTile size={sizes.tile} color={picked?.color}>
              {picked ? (
                <DistroGlyph icon={picked} />
              ) : customValue ? (
                <CustomIconGlyph value={customValue} />
              ) : (
                fallback
              )}
            </IconTile>
          </ButtonBase>
        </span>
      </Tooltip>
      <Popover
        open={!!anchor}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        slotProps={{ paper: { sx: { p: 1.5, width: 340, maxHeight: 480 } } }}
      >
        <ButtonBase
          onClick={() => {
            onChange(null);
            setAnchor(null);
          }}
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1,
            p: 0.75,
            mb: 1,
            width: "100%",
            justifyContent: "flex-start",
            borderRadius: 1.5,
            border: 1,
            borderColor: value === null ? "primary.main" : "divider",
          }}
        >
          <IconTile size={28}>{fallback}</IconTile>
          <Typography variant="body2">{autoLabel}</Typography>
        </ButtonBase>
        <ButtonBase
          onClick={() => {
            setAnchor(null);
            setCustomOpen(true);
          }}
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1,
            p: 0.75,
            mb: 1,
            width: "100%",
            justifyContent: "flex-start",
            borderRadius: 1.5,
            border: 1,
            borderColor: custom ? "primary.main" : "divider",
          }}
        >
          <IconTile size={28}>
            {customValue ? (
              <CustomIconGlyph value={customValue} />
            ) : (
              <AddPhotoAlternateRoundedIcon />
            )}
          </IconTile>
          <Typography variant="body2">{tr("Custom icon…")}</Typography>
        </ButtonBase>
        {iconSections().map((s) => (
          <Box key={s.title} sx={{ mb: 1 }}>
            <Typography variant="caption" color="text.secondary">
              {sectionTitle(s.title)}
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75, mt: 0.5 }}>
              {s.icons.map((i) => (
                <Tooltip key={i.id} title={i.title}>
                  <ButtonBase
                    aria-label={i.title}
                    aria-pressed={value === i.id}
                    onClick={() => {
                      onChange(i.id);
                      setAnchor(null);
                    }}
                    sx={{
                      borderRadius: 1.5,
                      outline: value === i.id ? "2px solid" : "none",
                      outlineColor: "primary.main",
                      outlineOffset: 1,
                    }}
                  >
                    <IconTile size={32} color={i.color}>
                      <DistroGlyph icon={i} />
                    </IconTile>
                  </ButtonBase>
                </Tooltip>
              ))}
            </Box>
          </Box>
        ))}
      </Popover>
      <CustomIconDialog
        key={`${customOpen}-${value ?? ""}`}
        open={customOpen}
        value={value}
        onChange={onChange}
        onClose={() => setCustomOpen(false)}
      />
    </>
  );
}
