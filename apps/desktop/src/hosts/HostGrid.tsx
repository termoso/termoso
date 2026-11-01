import { Box, IconButton, Tooltip } from "@mui/material";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import MoreHorizRoundedIcon from "@mui/icons-material/MoreHorizRounded";
import EditOutlinedIcon from "@mui/icons-material/EditOutlined";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import CloudSyncOutlinedIcon from "@mui/icons-material/CloudSyncOutlined";
import type { MouseEvent, ReactNode } from "react";
import { hasWebDav, hostProtocols, type GroupNode, type HostCard } from "@/ipc/types";
import { CardGrid, CheckTile, EntityCard, IconTile, SectionTitle } from "@/components/ui";
import { DistroGlyph, CustomIconGlyph, HostAvatar } from "./HostAvatar";
import { customIconSource } from "./customIcon";
import { pickedIcon } from "./icons";
import type { HostDnd } from "./dnd";
import type { HostViewer } from "./presence";
import { HOST_ITEM_ATTR, hostItemKeyDown } from "./keyboardNav";
import { PresenceStack } from "./PresenceViews";
import { tr, trn } from "@/i18n";

export interface HostCollectionProps {
  groups: GroupNode[];
  hosts: HostCard[];
  /** Host open in the editor. */
  selectedId: string | null;
  /** Multi-selection (checkboxes / ⌘-click). */
  checked: ReadonlySet<string>;
  showPath: boolean;
  onOpenGroup: (id: string) => void;
  onEditGroup: (g: GroupNode) => void;
  onGroupContext: (g: GroupNode, e: MouseEvent<HTMLElement>) => void;
  /** Plain click: modifier keys turn it into a selection toggle / range. */
  onOpenHost: (h: HostCard, e: MouseEvent<HTMLElement>) => void;
  onToggleHost: (h: HostCard) => void;
  onConnectHost: (h: HostCard) => void;
  onHostContext: (h: HostCard, e: MouseEvent<HTMLElement>) => void;
  /** Drag hosts onto group cards. */
  dnd?: HostDnd;
  /** Teammates connected right now, by host id (team vaults only). */
  presence?: ReadonlyMap<string, HostViewer[]>;
  /** Groups mirrored from a cloud account, by group id. */
  cloudSynced?: ReadonlySet<string>;
}

const CLOUD_SHORT: Record<string, string> = {
  "Amazon AWS": "AWS",
  DigitalOcean: "DigitalOcean",
  azure: "Azure",
};

/** Termius' card line: protocols, then username, then tags, then the cloud it came from. */
export function hostSubtitle(h: HostCard) {
  const parts: string[] = [...hostProtocols(h)];
  if (hasWebDav(h)) parts.push("webdav");
  if (h.username) parts.push(h.username);
  parts.push(...h.tags);
  if (h.cloudProvider) parts.push(CLOUD_SHORT[h.cloudProvider] ?? h.cloudProvider);
  return parts.join(", ");
}

/** `user@address:port` of the given protocol (primary by default), as typed in a terminal. */
export function hostTarget(h: HostCard, protocol: string = h.protocol) {
  if (protocol === "telnet" && h.protocol !== "telnet") {
    return `${h.address}:${h.telnetPort ?? 23}`;
  }
  return `${h.username ? `${h.username}@` : ""}${h.address}:${h.port}`;
}

export function groupSubtitle(g: GroupNode) {
  const parts = [];
  if (g.groupCount > 0) parts.push(trn(g.groupCount, "{count} group", "{count} groups"));
  parts.push(trn(g.hostCount, "{count} host", "{count} hosts"));
  return parts.join(", ");
}

/** Card tile that doubles as the selection toggle (see `CheckTile`). */
export function SelectableTile({
  tile,
  checked,
  onToggle,
  size,
}: {
  tile: ReactNode;
  checked: boolean;
  onToggle: () => void;
  size: number;
}) {
  return (
    <Box
      role="checkbox"
      aria-checked={checked}
      aria-label={tr("Select")}
      tabIndex={-1}
      onClick={(e) => {
        e.stopPropagation();
        onToggle();
      }}
      onDoubleClick={(e) => e.stopPropagation()}
      sx={{ display: "flex", flexShrink: 0, cursor: "pointer" }}
    >
      <CheckTile tile={tile} checked={checked} hoverHint size={size} />
    </Box>
  );
}

export function GroupTile({ g, size, cloud }: { g: GroupNode; size?: number; cloud?: boolean }) {
  const picked = pickedIcon(g.icon);
  const custom = !picked && customIconSource(g.icon) ? g.icon : null;
  return (
    <IconTile size={size} color={picked?.color} sx={{ position: "relative" }}>
      {picked ? (
        <DistroGlyph icon={picked} />
      ) : custom ? (
        <CustomIconGlyph value={custom} />
      ) : (
        <FolderRoundedIcon />
      )}
      {cloud ? (
        <Tooltip title={tr("Synced with a cloud account")}>
          <CloudSyncOutlinedIcon
            sx={{
              position: "absolute",
              right: -3,
              bottom: -3,
              fontSize: "12px !important",
              color: "primary.main",
              bgcolor: "surface.high",
              borderRadius: "50%",
              p: "2px",
            }}
          />
        </Tooltip>
      ) : (
        g.hasConfig && (
          <Tooltip title={tr("Hosts inherit credentials from this group")}>
            <KeyRoundedIcon
              sx={{
                position: "absolute",
                right: -3,
                bottom: -3,
                fontSize: "12px !important",
                color: "primary.main",
                bgcolor: "surface.high",
                borderRadius: "50%",
                p: "2px",
              }}
            />
          </Tooltip>
        )
      )}
    </IconTile>
  );
}

export function HostGrid(p: HostCollectionProps) {
  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
      {p.groups.length > 0 && (
        <Box>
          <SectionTitle>{tr("Groups")}</SectionTitle>
          <CardGrid min={240}>
            {p.groups.map((g) => (
              <EntityCard
                key={g.id}
                dense
                tile={<GroupTile g={g} cloud={p.cloudSynced?.has(g.id)} />}
                title={g.label}
                subtitle={groupSubtitle(g)}
                onClick={() => p.onOpenGroup(g.id)}
                onContextMenu={(e) => p.onGroupContext(g, e)}
                extra={{
                  [HOST_ITEM_ATTR]: "",
                  onKeyDown: (e) => hostItemKeyDown(e, () => p.onOpenGroup(g.id)),
                }}
                drag={p.dnd?.dropGroup(g)}
                dropping={p.dnd?.dropping === g.id}
                actions={
                  <IconButton
                    aria-label={tr("Group options")}
                    onClick={(e) => {
                      e.stopPropagation();
                      p.onGroupContext(g, e);
                    }}
                  >
                    <MoreHorizRoundedIcon fontSize="small" />
                  </IconButton>
                }
              />
            ))}
          </CardGrid>
        </Box>
      )}
      {p.hosts.length > 0 && (
        <Box>
          {p.groups.length > 0 && <SectionTitle>{tr("Hosts")}</SectionTitle>}
          <CardGrid min={280}>
            {p.hosts.map((h) => {
              const isChecked = p.checked.has(h.id);
              return (
                <EntityCard
                  key={h.id}
                  className="entity-card"
                  tile={
                    <SelectableTile
                      tile={<HostAvatar host={h} />}
                      checked={isChecked}
                      onToggle={() => p.onToggleHost(h)}
                      size={40}
                    />
                  }
                  title={h.label}
                  subtitle={
                    p.showPath && h.groupPath.length > 0
                      ? `${hostSubtitle(h)} · ${h.groupPath.join(" / ")}`
                      : hostSubtitle(h)
                  }
                  selected={isChecked || h.id === p.selectedId}
                  onClick={(e) => p.onOpenHost(h, e)}
                  onDoubleClick={() => p.onConnectHost(h)}
                  onContextMenu={(e) => p.onHostContext(h, e)}
                  extra={{
                    [HOST_ITEM_ATTR]: "",
                    onKeyDown: (e) => hostItemKeyDown(e, () => p.onConnectHost(h)),
                  }}
                  drag={p.dnd?.dragHost(h)}
                  sx={p.dnd?.dragging.has(h.id) ? { opacity: 0.45 } : undefined}
                  trailing={
                    p.presence?.has(h.id) && <PresenceStack viewers={p.presence.get(h.id) ?? []} />
                  }
                  actions={
                    <>
                      <Tooltip title={tr("Edit")}>
                        <IconButton
                          aria-label={tr("Edit {label}", { label: h.label })}
                          onClick={(e) => {
                            e.stopPropagation();
                            p.onOpenHost(h, e);
                          }}
                        >
                          <EditOutlinedIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <IconButton
                        aria-label={tr("Host options")}
                        onClick={(e) => {
                          e.stopPropagation();
                          p.onHostContext(h, e);
                        }}
                      >
                        <MoreHorizRoundedIcon fontSize="small" />
                      </IconButton>
                    </>
                  }
                />
              );
            })}
          </CardGrid>
        </Box>
      )}
    </Box>
  );
}
