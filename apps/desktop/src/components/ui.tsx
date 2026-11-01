import type { HTMLAttributes } from "react";
import {
  Box,
  Button,
  ButtonGroup,
  CircularProgress,
  IconButton,
  InputAdornment,
  InputBase,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  TextField,
  Tooltip,
  Typography,
  useMediaQuery,
  type ButtonProps,
  type SxProps,
  type Theme,
} from "@mui/material";
import KeyboardArrowDownRoundedIcon from "@mui/icons-material/KeyboardArrowDownRounded";
import ChevronRightRoundedIcon from "@mui/icons-material/ChevronRightRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import CheckRoundedIcon from "@mui/icons-material/CheckRounded";
import RemoveRoundedIcon from "@mui/icons-material/RemoveRounded";
import {
  type DragEvent,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
  createContext,
  useContext,
  useState,
} from "react";
import { monoFontFamily, sizes } from "@/theme/theme";
import { tr } from "@/i18n";

/** Normalises an optional `sx` prop so it can be spread after base styles. */
type SxItem = Exclude<SxProps<Theme>, readonly unknown[]>;
function sxList(sx?: SxProps<Theme>): readonly SxItem[] {
  if (!sx) return [];
  return Array.isArray(sx) ? (sx as readonly SxItem[]) : [sx as SxItem];
}

/* ---------------------------------------------------------------- tiles */

export type TileTone = "accent" | "neutral" | "info" | "warning" | "danger" | "purple";

const toneColor: Record<TileTone, { fg: string; bg: string }> = {
  accent: { fg: "primary.main", bg: "rgba(43,184,132,0.18)" },
  info: { fg: "secondary.main", bg: "rgba(90,169,230,0.18)" },
  warning: { fg: "warning.main", bg: "rgba(248,170,75,0.18)" },
  danger: { fg: "error.main", bg: "rgba(242,94,97,0.18)" },
  purple: { fg: "#B07CF2", bg: "rgba(176,124,242,0.18)" },
  neutral: { fg: "text.secondary", bg: "surface.highest" },
};

/** Square icon tile used on every entity card (host, group, key, rule, package…). */
export function IconTile({
  children,
  tone = "neutral",
  size = sizes.tile,
  color,
  sx,
}: {
  children: ReactNode;
  tone?: TileTone;
  size?: number;
  /** Explicit color (e.g. an OS brand) — overrides `tone`. */
  color?: string;
  sx?: SxProps<Theme>;
}) {
  const t = toneColor[tone];
  return (
    <Box
      sx={[
        {
          width: size,
          height: size,
          borderRadius: size >= 40 ? 2 : 1.5,
          display: "grid",
          placeItems: "center",
          flexShrink: 0,
          bgcolor: color ?? t.bg,
          color: color ? "#fff" : t.fg,
          "& svg": { fontSize: Math.round(size * 0.5) },
          fontWeight: 600,
          fontSize: Math.round(size * 0.42),
        },
        ...sxList(sx),
      ]}
    >
      {children}
    </Box>
  );
}

/**
 * Entity tile that reports selection the Termius way: when checked the whole
 * tile fills with the accent colour under a white check (a dash when only part
 * of a group is picked). `hoverHint` previews a muted check while hovered.
 */
export function CheckTile({
  tile,
  checked,
  partial = false,
  hoverHint = false,
  size = sizes.tile,
  sx,
}: {
  tile: ReactNode;
  checked: boolean;
  partial?: boolean;
  hoverHint?: boolean;
  size?: number;
  sx?: SxProps<Theme>;
}) {
  const radius = size >= 40 ? 2 : 1.5;
  const on = checked || partial;
  return (
    <Box
      className={on ? "tile-checked" : hoverHint ? "tile-hint" : undefined}
      sx={[
        {
          position: "relative",
          width: size,
          height: size,
          flexShrink: 0,
          borderRadius: radius,
          overflow: "hidden",
          "& .tile-icon": { transition: "opacity 120ms" },
          "& .tile-check": {
            position: "absolute",
            inset: 0,
            display: "grid",
            placeItems: "center",
            borderRadius: radius,
            bgcolor: "primary.main",
            color: "#fff",
            opacity: 0,
            transform: "scale(0.85)",
            transition: "opacity 120ms, transform 120ms",
            "& svg": { fontSize: Math.round(size * 0.6) },
          },
          "&.tile-checked .tile-check, &.tile-hint:hover .tile-check": {
            opacity: 1,
            transform: "scale(1)",
          },
          "&.tile-checked .tile-icon, &.tile-hint:hover .tile-icon": { opacity: 0 },
          "&.tile-hint:hover .tile-check": {
            bgcolor: "surface.strong",
            color: "text.secondary",
          },
        },
        ...sxList(sx),
      ]}
    >
      <Box className="tile-icon">{tile}</Box>
      <Box className="tile-check">
        {partial && !checked ? <RemoveRoundedIcon /> : <CheckRoundedIcon />}
      </Box>
    </Box>
  );
}

/* ---------------------------------------------------------------- cards */

/** A list/grid entry: tile + two lines + optional trailing slot. */
export function EntityCard({
  tile,
  title,
  subtitle,
  meta,
  trailing,
  actions,
  selected,
  onClick,
  onDoubleClick,
  onContextMenu,
  dense,
  className,
  sx,
  drag,
  dropping,
  extra,
}: {
  tile: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  /** Third line under the subtitle (tag chips). */
  meta?: ReactNode;
  /** Always visible (status). */
  trailing?: ReactNode;
  /** Revealed on hover / selection (icon buttons). */
  actions?: ReactNode;
  selected?: boolean;
  onClick?: (e: MouseEvent<HTMLElement>) => void;
  onDoubleClick?: () => void;
  onContextMenu?: (e: MouseEvent<HTMLElement>) => void;
  dense?: boolean;
  className?: string;
  sx?: SxProps<Theme>;
  /** HTML5 drag-and-drop wiring (source and/or target). */
  drag?: DragHandlers;
  /** A compatible drag is hovering over this card. */
  dropping?: boolean;
  /** Extra root attributes (data-* markers, keyboard navigation). */
  extra?: HTMLAttributes<HTMLDivElement> & Record<`data-${string}`, string>;
}) {
  return (
    <Box
      role="button"
      tabIndex={0}
      className={className}
      onClick={onClick}
      onDoubleClick={onDoubleClick}
      onContextMenu={onContextMenu}
      {...drag}
      {...extra}
      onKeyDown={(e) => {
        extra?.onKeyDown?.(e);
        if (e.defaultPrevented) return;
        if (e.key === "Enter" && onClick && e.target === e.currentTarget) e.currentTarget.click();
      }}
      sx={[
        {
          display: "flex",
          alignItems: "center",
          gap: 1.5,
          px: dense ? 1.25 : 1.5,
          py: dense ? 0.75 : 1.25,
          minHeight: dense ? 48 : 64,
          borderRadius: 2,
          bgcolor: "surface.high",
          cursor: "default",
          outline: "1px solid transparent",
          outlineOffset: -1,
          transition: "background-color 100ms, outline-color 100ms",
          "&:hover": { bgcolor: "surface.highest" },
          "&:focus-visible": { outlineColor: "primary.main" },
          ...(selected && {
            bgcolor: "surface.strong",
            "&:hover": { bgcolor: "surface.strong" },
            "& .entity-actions": { opacity: 1 },
          }),
          ...(dropping && { outlineColor: "primary.main", bgcolor: "surface.strong" }),
          ...(drag?.draggable && { cursor: "grab", "&:active": { cursor: "grabbing" } }),
          "& .entity-actions": { opacity: 0, transition: "opacity 100ms" },
          "&:hover .entity-actions, &:focus-within .entity-actions": { opacity: 1 },
        },
        ...sxList(sx),
      ]}
    >
      {tile}
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography variant="body1" noWrap sx={{ fontWeight: 500, lineHeight: 1.35 }}>
          {title}
        </Typography>
        {subtitle !== undefined && subtitle !== null && subtitle !== "" && (
          <Typography
            variant="caption"
            color="text.secondary"
            noWrap
            sx={{ display: "block", lineHeight: 1.35, mt: 0.25 }}
          >
            {subtitle}
          </Typography>
        )}
        {meta && (
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 0.75, flexWrap: "wrap" }}>
            {meta}
          </Box>
        )}
      </Box>
      {trailing && (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexShrink: 0 }}>
          {trailing}
        </Box>
      )}
      {actions && (
        <Box
          className="entity-actions"
          sx={{ display: "flex", alignItems: "center", gap: 0.25, flexShrink: 0, mr: -0.5 }}
        >
          {actions}
        </Box>
      )}
    </Box>
  );
}

/** Subset of the native drag events a card may forward to its root element. */
export interface DragHandlers {
  draggable?: boolean;
  onDragStart?: (e: DragEvent<HTMLElement>) => void;
  onDragEnd?: (e: DragEvent<HTMLElement>) => void;
  onDragEnter?: (e: DragEvent<HTMLElement>) => void;
  onDragOver?: (e: DragEvent<HTMLElement>) => void;
  onDragLeave?: (e: DragEvent<HTMLElement>) => void;
  onDrop?: (e: DragEvent<HTMLElement>) => void;
}

/** Responsive card grid. */
export function CardGrid({ children, min = 280 }: { children: ReactNode; min?: number }) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: `repeat(auto-fill, minmax(${min}px, 1fr))`,
        gap: 1.5,
      }}
    >
      {children}
    </Box>
  );
}

/** "Groups" / "Hosts" heading above a card grid. */
export function SectionTitle({
  children,
  trailing,
  sx,
}: {
  children: ReactNode;
  trailing?: ReactNode;
  sx?: SxProps<Theme>;
}) {
  return (
    <Box
      sx={[
        { display: "flex", alignItems: "center", mb: 1.5, mt: 0.5, minHeight: 24 },
        ...sxList(sx),
      ]}
    >
      <Typography variant="subtitle2" sx={{ flex: 1 }}>
        {children}
      </Typography>
      {trailing}
    </Box>
  );
}

/** Grouped form section in a side panel (Termius "Address" / "General" cards). */
export function SectionCard({
  title,
  description,
  action,
  tone,
  children,
  sx,
}: {
  title?: ReactNode;
  /** Muted line under the title. */
  description?: ReactNode;
  action?: ReactNode;
  /** Tinted outline for cards that ask for attention. */
  tone?: "warning";
  children: ReactNode;
  sx?: SxProps<Theme>;
}) {
  return (
    <Box
      sx={[
        {
          bgcolor: "surface.high",
          borderRadius: 2,
          p: 2,
          display: "flex",
          flexDirection: "column",
          gap: 1.5,
        },
        tone === "warning" && {
          outline: "1px solid",
          outlineColor: "warning.main",
          outlineOffset: -1,
        },
        ...sxList(sx),
      ]}
    >
      {(title ?? action ?? description) && (
        <Box
          sx={{
            display: "flex",
            alignItems: description ? "flex-start" : "center",
            minHeight: 24,
            gap: 1,
          }}
        >
          <Box sx={{ flex: 1, minWidth: 0 }}>
            {title && <Typography variant="subtitle2">{title}</Typography>}
            {description && (
              <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                {description}
              </Typography>
            )}
          </Box>
          {action}
        </Box>
      )}
      {children}
    </Box>
  );
}

/* ------------------------------------------------------------- toolbar */

/** Row of actions under the top bar: `+ New X ⌄ | Terminal | Serial …  [right slot]`. */
export function Toolbar({
  children,
  trailing,
  sx,
}: {
  children?: ReactNode;
  trailing?: ReactNode;
  sx?: SxProps<Theme>;
}) {
  return (
    <Box
      sx={[
        {
          display: "flex",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 1,
          px: 2,
          py: 1,
          minHeight: 48,
          borderBottom: 1,
          borderColor: "border.light",
        },
        ...sxList(sx),
      ]}
    >
      {children}
      {trailing && (
        <>
          <Box sx={{ flex: 1 }} />
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>{trailing}</Box>
        </>
      )}
    </Box>
  );
}

/** Compact filter field for a toolbar's right slot. */
export function SearchField({
  value,
  onChange,
  placeholder = "Search",
  width = 240,
  autoFocus,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  width?: number | string;
  autoFocus?: boolean;
}) {
  return (
    <TextField
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      autoFocus={autoFocus}
      fullWidth={false}
      sx={{ width, "& .MuiOutlinedInput-root": { height: sizes.control } }}
      slotProps={{
        input: {
          startAdornment: (
            <InputAdornment position="start">
              <SearchRoundedIcon fontSize="small" />
            </InputAdornment>
          ),
        },
      }}
    />
  );
}

/** Quiet one-line notice above page content ("recording is off", "not synced"). */
export function InfoBar({
  children,
  action,
  icon,
}: {
  children: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "center",
        gap: 1.25,
        px: 1.5,
        py: 1,
        borderRadius: 2,
        bgcolor: "surface.high",
        color: "text.secondary",
        "& > svg": { fontSize: 18, flexShrink: 0 },
      }}
    >
      {icon ?? <InfoOutlinedIcon />}
      <Typography variant="body2" sx={{ flex: 1, minWidth: 0 }}>
        {children}
      </Typography>
      {action}
    </Box>
  );
}

/** Monospace inline text (fingerprints, addresses, commands). */
export function Mono({
  children,
  secondary,
  sx,
}: {
  children: ReactNode;
  secondary?: boolean;
  sx?: SxProps<Theme>;
}) {
  return (
    <Box
      component="span"
      sx={[
        {
          fontFamily: monoFontFamily,
          fontSize: "0.8125em",
          ...(secondary && { color: "text.secondary" }),
        },
        ...sxList(sx),
      ]}
    >
      {children}
    </Box>
  );
}

export interface MenuAction {
  label: ReactNode;
  icon?: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  danger?: boolean;
  divider?: boolean;
  /** Nested actions; the item opens a submenu instead of running `onClick`. */
  items?: MenuAction[];
}

/** `[ + New host ] [⌄]` — primary click + dropdown with alternatives. */
export function SplitButton({
  label,
  icon,
  onClick,
  items,
  variant = "tonal",
  color,
  disabled,
}: {
  label: ReactNode;
  icon?: ReactNode;
  onClick: () => void;
  items: MenuAction[];
  variant?: ButtonProps["variant"];
  color?: ButtonProps["color"];
  disabled?: boolean;
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  return (
    <>
      <ButtonGroup
        variant={variant === "tonal" ? "contained" : variant}
        color={color}
        disabled={disabled}
        disableElevation
        sx={{
          "& .MuiButtonGroup-grouped": { minWidth: 0 },
          "& .MuiButtonGroup-firstButton, & .MuiButtonGroup-middleButton": {
            borderRight: "1px solid rgba(0,0,0,0.25)",
          },
        }}
      >
        <Button variant={variant} startIcon={icon} onClick={onClick}>
          {label}
        </Button>
        <Button
          variant={variant}
          size="small"
          aria-label={tr("More options")}
          onClick={(e) => setAnchor(e.currentTarget)}
          sx={{ px: 0.5, minWidth: 28 }}
        >
          <KeyboardArrowDownRoundedIcon fontSize="small" />
        </Button>
      </ButtonGroup>
      <ActionMenu anchor={anchor} onClose={() => setAnchor(null)} items={items} />
    </>
  );
}

/** Generic anchored menu built from `MenuAction`s. */
export function ActionMenu({
  anchor,
  position,
  onClose,
  items,
}: {
  anchor: HTMLElement | null;
  /** Use for context menus (mouse coordinates). */
  position?: { left: number; top: number } | null;
  onClose: () => void;
  items: MenuAction[];
}) {
  const open = Boolean(anchor) || Boolean(position);
  const [sub, setSub] = useState<number | null>(null);
  const close = () => {
    setSub(null);
    onClose();
  };
  return (
    <Menu
      open={open}
      anchorEl={position ? undefined : anchor}
      anchorReference={position ? "anchorPosition" : "anchorEl"}
      anchorPosition={position ?? undefined}
      onClose={close}
      onClick={(e) => e.stopPropagation()}
    >
      {items.map((it, i) =>
        it.items ? (
          <SubMenuItem
            key={i}
            action={it}
            items={it.items}
            open={sub === i}
            onOpen={() => setSub(i)}
            onClose={close}
          />
        ) : (
          <MenuItem
            key={i}
            disabled={it.disabled}
            divider={it.divider}
            onMouseEnter={() => setSub(null)}
            onClick={() => {
              close();
              it.onClick?.();
            }}
            sx={it.danger ? { color: "error.main" } : undefined}
          >
            {it.icon && (
              <ListItemIcon sx={it.danger ? { color: "error.main" } : undefined}>
                {it.icon}
              </ListItemIcon>
            )}
            <ListItemText primary={it.label} />
          </MenuItem>
        ),
      )}
    </Menu>
  );
}

/**
 * Menu row that opens `items` to its right on hover or click. The parent owns
 * which submenu is open so that hovering a sibling closes this one.
 */
function SubMenuItem({
  action,
  items,
  open,
  onOpen,
  onClose,
}: {
  action: MenuAction;
  items: MenuAction[];
  open: boolean;
  onOpen: () => void;
  onClose: () => void;
}) {
  const [row, setRow] = useState<HTMLElement | null>(null);
  const show = (e: MouseEvent<HTMLElement>) => {
    setRow(e.currentTarget);
    onOpen();
  };
  return (
    <>
      <MenuItem
        disabled={action.disabled}
        divider={action.divider}
        selected={open}
        onClick={show}
        onMouseEnter={show}
        sx={{ pr: 1 }}
      >
        {action.icon && <ListItemIcon>{action.icon}</ListItemIcon>}
        <ListItemText primary={action.label} />
        <ChevronRightRoundedIcon fontSize="small" sx={{ ml: 2, color: "text.secondary" }} />
      </MenuItem>
      <Menu
        open={open && row !== null}
        anchorEl={row}
        anchorOrigin={{ vertical: "top", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "left" }}
        onClose={onClose}
        onClick={(e) => e.stopPropagation()}
        slotProps={{
          root: { sx: { pointerEvents: "none" } },
          paper: { sx: { pointerEvents: "auto", ml: 0.5 } },
        }}
        hideBackdrop
        disableAutoFocus
        disableEnforceFocus
      >
        {items.map((it, i) => (
          <MenuItem
            key={i}
            disabled={it.disabled}
            divider={it.divider}
            onClick={() => {
              onClose();
              it.onClick?.();
            }}
            sx={it.danger ? { color: "error.main" } : undefined}
          >
            {it.icon && (
              <ListItemIcon sx={it.danger ? { color: "error.main" } : undefined}>
                {it.icon}
              </ListItemIcon>
            )}
            <ListItemText primary={it.label} />
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}

/**
 * Single-line name editor: commits on Enter or blur, reverts on Escape.
 * Looks like plain text until focused so it can replace a label in place.
 */
export function InlineName({
  value,
  onCommit,
  onCancel,
  placeholder,
  sx,
}: {
  value: string;
  onCommit: (name: string) => void;
  onCancel: () => void;
  placeholder?: string;
  sx?: SxProps<Theme>;
}) {
  const [draft, setDraft] = useState(value);
  const [done, setDone] = useState(false);
  const finish = (commit: boolean) => {
    if (done) return;
    setDone(true);
    if (commit) onCommit(draft);
    else onCancel();
  };
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    e.stopPropagation();
    if (e.key === "Enter") finish(true);
    if (e.key === "Escape") finish(false);
  };
  return (
    <InputBase
      autoFocus
      value={draft}
      placeholder={placeholder}
      onChange={(e) => setDraft(e.target.value)}
      onFocus={(e) => e.target.select()}
      onBlur={() => finish(true)}
      onKeyDown={onKeyDown}
      onClick={(e) => e.stopPropagation()}
      onMouseDown={(e) => e.stopPropagation()}
      inputProps={{ "aria-label": tr("Name"), maxLength: 120 }}
      sx={[
        {
          font: "inherit",
          fontSize: 13,
          fontWeight: 500,
          height: 24,
          px: 0.75,
          borderRadius: 1,
          bgcolor: "surface.high",
          boxShadow: "0 0 0 1px var(--mui-palette-primary-main)",
          "& input": { p: 0 },
        },
        ...sxList(sx),
      ]}
    />
  );
}

/** Icon button with tooltip, sized to the shared control height. */
export function ToolIconButton({
  title,
  onClick,
  children,
  disabled,
  active,
  color,
}: {
  title: string;
  onClick?: (e: MouseEvent<HTMLButtonElement>) => void;
  children: ReactNode;
  disabled?: boolean;
  active?: boolean;
  color?: "error" | "primary";
}) {
  return (
    <Tooltip title={title}>
      <span>
        <IconButton
          onClick={onClick}
          disabled={disabled}
          aria-label={title}
          color={color}
          sx={active ? { bgcolor: "surface.highest", color: "text.primary" } : undefined}
        >
          {children}
        </IconButton>
      </span>
    </Tooltip>
  );
}

/* ---------------------------------------------------------------- panel */

/** Below this window width a side panel would squeeze the page below usable width, so it overlays instead. */
export const NARROW_WINDOW = `(max-width:${sizes.sidebar + sizes.panel + 520}px)`;

export function useNarrowWindow(): boolean {
  return useMediaQuery(NARROW_WINDOW);
}

/** Right-hand side panel: header (title, subtitle, actions, close) + scrollable body + footer. */
export function SidePanel({
  title,
  subtitle,
  actions,
  onClose,
  onBack,
  children,
  footer,
  width = sizes.panel,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  onClose?: () => void;
  onBack?: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
}) {
  const narrow = useNarrowWindow();
  return (
    <Box
      component="aside"
      sx={{
        width,
        flexShrink: 0,
        display: "flex",
        flexDirection: "column",
        bgcolor: "surface.base",
        borderLeft: 1,
        borderColor: "border.light",
        minHeight: 0,
        ...(narrow && {
          position: "absolute",
          top: 0,
          right: 0,
          bottom: 0,
          zIndex: 3,
          maxWidth: "calc(100% - 48px)",
          boxShadow: 8,
        }),
      }}
    >
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1,
          px: 2,
          minHeight: 56,
          borderBottom: 1,
          borderColor: "border.light",
        }}
      >
        {onBack && (
          <IconButton onClick={onBack} aria-label={tr("Back")} sx={{ ml: -1 }}>
            <ArrowBackRoundedIcon fontSize="small" />
          </IconButton>
        )}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography variant="subtitle1" noWrap>
            {title}
          </Typography>
          {subtitle && (
            <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
              {subtitle}
            </Typography>
          )}
        </Box>
        {actions}
        {onClose && (
          <IconButton onClick={onClose} aria-label={tr("Close panel")} sx={{ mr: -1 }}>
            <CloseRoundedIcon fontSize="small" />
          </IconButton>
        )}
      </Box>
      <Box
        sx={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          p: 1.5,
          display: "flex",
          flexDirection: "column",
          gap: 1.5,
        }}
      >
        {children}
      </Box>
      {footer && (
        <Box
          sx={{
            p: 1.5,
            borderTop: 1,
            borderColor: "border.light",
            display: "flex",
            gap: 1,
            "& > .MuiButton-root": { flex: 1, whiteSpace: "nowrap", minWidth: 0, px: 1 },
          }}
        >
          {footer}
        </Box>
      )}
    </Box>
  );
}

/* ------------------------------------------------------------- settings */

/** One row inside a settings card: label (+ hint) on the left, control on the right. */
export function SettingRow({
  label,
  hint,
  control,
  last,
}: {
  label: ReactNode;
  hint?: ReactNode;
  control: ReactNode;
  last?: boolean;
}) {
  const compact = useContext(CompactFields);
  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        columnGap: 2,
        rowGap: 0.75,
        minHeight: compact ? 36 : sizes.row,
        py: compact ? 0.25 : 0.75,
        borderBottom: last ? 0 : 1,
        borderColor: "border.light",
      }}
    >
      <Box sx={{ flex: "1 1 220px", minWidth: 0 }}>
        <Typography variant={compact ? "body2" : "body1"}>
          {label}
          {compact && hint && <HintIcon hint={hint} />}
        </Typography>
        {hint && !compact && (
          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
            {hint}
          </Typography>
        )}
      </Box>
      <Box sx={{ flexShrink: 0, ml: "auto", display: "flex", alignItems: "center", gap: 1 }}>
        {control}
      </Box>
    </Box>
  );
}

/* --------------------------------------------------------------- states */

export function Loading({ pt = 8 }: { pt?: number }) {
  return (
    <Box sx={{ display: "flex", justifyContent: "center", pt }}>
      <CircularProgress size={22} thickness={4} />
    </Box>
  );
}

/** Field label sitting above a control (no floating labels). */
export function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5, fontWeight: 500 }}>
      {children}
    </Typography>
  );
}

/**
 * Dense forms (the Host Details panel, like Termius) keep hints out of the
 * flow: `Field` / `SettingRow` show them as an info tooltip next to the label.
 */
export const CompactFields = createContext(false);

function HintIcon({ hint }: { hint: ReactNode }) {
  return (
    <Tooltip title={hint} enterDelay={300}>
      <InfoOutlinedIcon
        sx={{ fontSize: 14, color: "text.disabled", ml: 0.5, verticalAlign: "-2px" }}
      />
    </Tooltip>
  );
}

/** Label + control + optional hint, stacked. */
export function Field({
  label,
  hint,
  children,
  sx,
}: {
  label: ReactNode;
  hint?: ReactNode;
  children: ReactNode;
  sx?: SxProps<Theme>;
}) {
  const compact = useContext(CompactFields);
  return (
    <Box sx={[{ minWidth: 0 }, ...sxList(sx)]}>
      <FieldLabel>
        {label}
        {compact && hint && <HintIcon hint={hint} />}
      </FieldLabel>
      {children}
      {hint && !compact && (
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
          {hint}
        </Typography>
      )}
    </Box>
  );
}
