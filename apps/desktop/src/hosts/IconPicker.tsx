import { useState, type ReactNode } from "react";
import { Box, ButtonBase, Popover, Tooltip, Typography } from "@mui/material";
import { IconTile } from "@/components/ui";
import { sizes } from "@/theme/theme";
import { tr } from "@/i18n";
import { DistroGlyph } from "./HostAvatar";
import { iconSections, pickedIcon } from "./icons";

const sectionTitle = (s: string) =>
  s === "General"
    ? tr("General")
    : s === "Applications"
      ? tr("Applications")
      : tr("Operating systems");

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
  const picked = pickedIcon(value);
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
              {picked ? <DistroGlyph icon={picked} /> : fallback}
            </IconTile>
          </ButtonBase>
        </span>
      </Tooltip>
      <Popover
        open={!!anchor}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        slotProps={{ paper: { sx: { p: 1.5, width: 340, maxHeight: 420 } } }}
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
    </>
  );
}
