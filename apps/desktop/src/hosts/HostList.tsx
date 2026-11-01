import {
  Box,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import MoreHorizRoundedIcon from "@mui/icons-material/MoreHorizRounded";
import { monoFontFamily, sizes } from "@/theme/theme";
import { hasWebDav, hostProtocols } from "@/ipc/types";
import { PROTOCOL_NAME } from "./ConnectSplit";
import { HostAvatar } from "./HostAvatar";
import { GroupTile, groupSubtitle, SelectableTile, type HostCollectionProps } from "./HostGrid";
import { PresenceStack } from "./PresenceViews";
import { tr } from "@/i18n";

const rowSx = {
  "& td": { py: 0.5 },
  "& .row-actions": { opacity: 0 },
  "&:hover .row-actions, &.Mui-selected .row-actions": { opacity: 1 },
} as const;

const droppingSx = {
  "& td": { bgcolor: "surface.strong" },
  "& td:first-of-type": { boxShadow: "inset 2px 0 0 var(--mui-palette-primary-main)" },
} as const;

/** `2h ago`, `3d ago`, or a short date for anything older. */
export function relativeTime(iso: string | null, now = Date.now()) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return tr("just now");
  const m = Math.round(s / 60);
  if (m < 60) return tr("{m} min ago", { m });
  const h = Math.round(m / 60);
  if (h < 24) return tr("{h} h ago", { h });
  const d = Math.round(h / 24);
  if (d < 14) return tr("{d} d ago", { d });
  return new Date(t).toLocaleDateString();
}

export function HostList(p: HostCollectionProps) {
  return (
    <Table size="small">
      <TableHead>
        <TableRow>
          <TableCell sx={{ width: 48 }} />
          <TableCell>{tr("Name")}</TableCell>
          <TableCell>{tr("Address")}</TableCell>
          <TableCell>{tr("Protocol")}</TableCell>
          <TableCell>{tr("User")}</TableCell>
          <TableCell align="right">{tr("Port")}</TableCell>
          <TableCell>{tr("Tags")}</TableCell>
          <TableCell sx={{ width: 130, whiteSpace: "nowrap" }}>{tr("Last connected")}</TableCell>
          <TableCell sx={{ width: 40 }} />
        </TableRow>
      </TableHead>
      <TableBody>
        {p.groups.map((g) => (
          <TableRow
            key={g.id}
            hover
            sx={[rowSx, p.dnd?.dropping === g.id ? droppingSx : {}]}
            onClick={() => p.onOpenGroup(g.id)}
            onContextMenu={(e) => p.onGroupContext(g, e)}
            {...p.dnd?.dropGroup(g)}
          >
            <TableCell>
              <GroupTile g={g} size={sizes.tileSmall} cloud={p.cloudSynced?.has(g.id)} />
            </TableCell>
            <TableCell>
              <Typography variant="body1" sx={{ fontWeight: 500 }}>
                {g.label}
              </Typography>
            </TableCell>
            <TableCell colSpan={6}>
              <Typography variant="body2" color="text.secondary">
                {groupSubtitle(g)}
              </Typography>
            </TableCell>
            <TableCell align="right">
              <IconButton
                className="row-actions"
                aria-label={tr("Group options")}
                onClick={(e) => {
                  e.stopPropagation();
                  p.onGroupContext(g, e);
                }}
              >
                <MoreHorizRoundedIcon fontSize="small" />
              </IconButton>
            </TableCell>
          </TableRow>
        ))}
        {p.hosts.map((h) => {
          const isChecked = p.checked.has(h.id);
          return (
            <TableRow
              key={h.id}
              hover
              selected={isChecked || h.id === p.selectedId}
              sx={[rowSx, p.dnd?.dragging.has(h.id) ? { opacity: 0.45 } : {}]}
              onClick={(e) => p.onOpenHost(h, e)}
              onDoubleClick={() => p.onConnectHost(h)}
              onContextMenu={(e) => p.onHostContext(h, e)}
              {...p.dnd?.dragHost(h)}
            >
              <TableCell>
                <SelectableTile
                  tile={<HostAvatar host={h} size={sizes.tileSmall} />}
                  checked={isChecked}
                  onToggle={() => p.onToggleHost(h)}
                  size={sizes.tileSmall}
                />
              </TableCell>
              <TableCell>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Typography variant="body1" sx={{ fontWeight: 500 }} noWrap>
                    {h.label || h.address}
                  </Typography>
                  {p.presence?.has(h.id) && (
                    <PresenceStack viewers={p.presence.get(h.id) ?? []} size={18} />
                  )}
                </Box>
                {p.showPath && h.groupPath.length > 0 && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    noWrap
                    sx={{ display: "block" }}
                  >
                    {h.groupPath.join(" / ")}
                  </Typography>
                )}
              </TableCell>
              <TableCell>
                <Typography variant="body2" sx={{ fontFamily: monoFontFamily }} noWrap>
                  {h.address}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {[
                    ...hostProtocols(h).map((x) => PROTOCOL_NAME[x]),
                    ...(hasWebDav(h) ? ["WebDAV"] : []),
                  ].join(", ")}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {h.username || "—"}
                </Typography>
              </TableCell>
              <TableCell align="right">
                <Typography variant="body2" color="text.secondary" noWrap>
                  {h.protocol === "webdav"
                    ? "—"
                    : h.telnetPort !== null && h.protocol === "ssh"
                      ? `${h.port} / ${h.telnetPort}`
                      : h.port}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {h.tags.join(", ") || "—"}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {relativeTime(h.lastConnected)}
                </Typography>
              </TableCell>
              <TableCell align="right">
                <IconButton
                  className="row-actions"
                  aria-label={tr("Host options")}
                  onClick={(e) => {
                    e.stopPropagation();
                    p.onHostContext(h, e);
                  }}
                >
                  <MoreHorizRoundedIcon fontSize="small" />
                </IconButton>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
