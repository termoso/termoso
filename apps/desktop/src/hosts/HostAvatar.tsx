import { Box } from "@mui/material";
import CloudRoundedIcon from "@mui/icons-material/CloudRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import TerminalRoundedIcon from "@mui/icons-material/TerminalRounded";
import UsbRoundedIcon from "@mui/icons-material/UsbRounded";
import SvgIcon, { type SvgIconProps } from "@mui/material/SvgIcon";
import type { HostCard, SessionInfo } from "@/ipc/types";
import { IconTile } from "@/components/ui";
import { sizes } from "@/theme/theme";
import { distroIcon, type DistroIcon } from "./distroIcons";
import { customIconSource } from "./customIcon";
import { pickedIcon } from "./icons";

/** Renders an image-backed custom icon without treating its contents as markup. */
export function CustomIconGlyph({ value, sx }: { value: string; sx?: SvgIconProps["sx"] }) {
  const src = customIconSource(value);
  if (!src) return null;
  return (
    <Box
      component="img"
      src={src}
      alt=""
      draggable={false}
      style={{ width: "1em", height: "1em", objectFit: "contain", display: "block" }}
      sx={sx}
    />
  );
}

/** Renders a distro glyph as a regular MUI icon (inherits `fontSize` / `color`). */
export function DistroGlyph({ icon, ...props }: { icon: DistroIcon } & SvgIconProps) {
  return (
    <SvgIcon viewBox="0 0 24 24" titleAccess={icon.title} {...props}>
      <path d={icon.path} />
    </SvgIcon>
  );
}

/** The icon a host shows: the user's pick first, otherwise whatever OS detection found. */
export function hostIcon(
  host: Pick<HostCard, "icon" | "osName"> | null | undefined,
): DistroIcon | null {
  if (!host) return null;
  return pickedIcon(host.icon) ?? distroIcon(host.osName);
}

/** Protocols a glyph can stand for: saved-host sections plus the session-only ones. */
export type GlyphProtocol = SessionInfo["protocol"] | "webdav";

/** Glyph for a host's icon (chosen or detected), or the protocol fallback while unknown. */
export function HostGlyph({
  osName,
  icon: iconId,
  protocol,
  ...props
}: {
  osName: string | null | undefined;
  icon?: string | null | undefined;
  protocol: GlyphProtocol;
} & SvgIconProps) {
  const picked = pickedIcon(iconId);
  if (picked) return <DistroGlyph icon={picked} {...props} />;
  const customValue = customIconSource(iconId) ? iconId : null;
  if (customValue) return <CustomIconGlyph value={customValue} sx={props.sx} />;
  const detected = distroIcon(osName);
  if (detected) return <DistroGlyph icon={detected} {...props} />;
  return <ProtocolGlyph protocol={protocol} {...props} />;
}

/** Neutral glyph for a protocol: server, telnet/local terminal or serial plug. */
export function ProtocolGlyph({ protocol, ...props }: { protocol: GlyphProtocol } & SvgIconProps) {
  if (protocol === "telnet" || protocol === "local") return <TerminalRoundedIcon {...props} />;
  if (protocol === "serial") return <UsbRoundedIcon {...props} />;
  if (protocol === "webdav") return <CloudRoundedIcon {...props} />;
  return <DnsRoundedIcon {...props} />;
}

/** Host tile: brand-coloured with the distro logo once the OS is known, neutral before. */
export function HostAvatar({ host, size = sizes.tile }: { host: HostCard; size?: number }) {
  const icon = hostIcon(host);
  return (
    <IconTile size={size} color={icon?.color}>
      <HostGlyph osName={host.osName} icon={host.icon} protocol={host.protocol} />
    </IconTile>
  );
}
