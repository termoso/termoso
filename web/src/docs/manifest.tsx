import type { ReactNode } from "react";
import RocketLaunchOutlinedIcon from "@mui/icons-material/RocketLaunchOutlined";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import KeyboardOutlinedIcon from "@mui/icons-material/KeyboardOutlined";
import LanOutlinedIcon from "@mui/icons-material/LanOutlined";
import HelpOutlineOutlinedIcon from "@mui/icons-material/HelpOutlineOutlined";
import BuildOutlinedIcon from "@mui/icons-material/BuildOutlined";
import PaletteOutlinedIcon from "@mui/icons-material/PaletteOutlined";
import EditNoteOutlinedIcon from "@mui/icons-material/EditNoteOutlined";
import CompareArrowsOutlinedIcon from "@mui/icons-material/CompareArrowsOutlined";
import DeveloperBoardOutlinedIcon from "@mui/icons-material/DeveloperBoardOutlined";
import DownloadOutlinedIcon from "@mui/icons-material/DownloadOutlined";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import FileUploadOutlinedIcon from "@mui/icons-material/FileUploadOutlined";
import PhoneAndroidOutlinedIcon from "@mui/icons-material/PhoneAndroidOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import UsbOutlinedIcon from "@mui/icons-material/UsbOutlined";
import LabelOutlinedIcon from "@mui/icons-material/LabelOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import ViewQuiltOutlinedIcon from "@mui/icons-material/ViewQuiltOutlined";
import CodeOutlinedIcon from "@mui/icons-material/CodeOutlined";
import TerminalOutlinedIcon from "@mui/icons-material/TerminalOutlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import BadgeOutlinedIcon from "@mui/icons-material/BadgeOutlined";
import FingerprintOutlinedIcon from "@mui/icons-material/FingerprintOutlined";
import AlternateEmailOutlinedIcon from "@mui/icons-material/AlternateEmailOutlined";
import VpnKeyOutlinedIcon from "@mui/icons-material/VpnKeyOutlined";
import GroupsOutlinedIcon from "@mui/icons-material/GroupsOutlined";
import Inventory2OutlinedIcon from "@mui/icons-material/Inventory2Outlined";
import ConnectedTvOutlinedIcon from "@mui/icons-material/ConnectedTvOutlined";
import LockOpenOutlinedIcon from "@mui/icons-material/LockOpenOutlined";
import ScheduleOutlinedIcon from "@mui/icons-material/ScheduleOutlined";
import VerifiedUserOutlinedIcon from "@mui/icons-material/VerifiedUserOutlined";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import VisibilityOffOutlinedIcon from "@mui/icons-material/VisibilityOffOutlined";
import PhonelinkLockOutlinedIcon from "@mui/icons-material/PhonelinkLockOutlined";
import CloudOutlinedIcon from "@mui/icons-material/CloudOutlined";
import TuneOutlinedIcon from "@mui/icons-material/TuneOutlined";
import SettingsBackupRestoreOutlinedIcon from "@mui/icons-material/SettingsBackupRestoreOutlined";
import SystemUpdateAltOutlinedIcon from "@mui/icons-material/SystemUpdateAltOutlined";
import HubOutlinedIcon from "@mui/icons-material/HubOutlined";
import LoginOutlinedIcon from "@mui/icons-material/LoginOutlined";
import { plainText, splitFrontMatter } from "./markdown";

export interface DocPage {
  /** URL below `/docs/`, e.g. `getting-started/quick-start`; `""` is the index. */
  path: string;
  title: string;
  description: string;
  body: string;
  icon: ReactNode;
  section: string;
}

export interface DocSection {
  title: string;
  pages: DocPage[];
}

const files = import.meta.glob("./content/**/*.md", {
  query: "?raw",
  import: "default",
  eager: true,
});

function load(path: string): { title: string; description: string; body: string } {
  const key = `./content/${path || "index"}.md`;
  const src = files[key];
  if (src === undefined) throw new Error(`docs: missing ${key}`);
  const fm = splitFrontMatter(src);
  if (!fm.title) throw new Error(`docs: ${key} has no title`);
  return fm;
}

type Entry = [path: string, icon: ReactNode];

const layout: { title: string; pages: Entry[] }[] = [
  {
    title: "Getting started",
    pages: [
      ["", <InfoOutlinedIcon />],
      ["getting-started/quick-start", <RocketLaunchOutlinedIcon />],
      ["getting-started/download", <DownloadOutlinedIcon />],
      ["getting-started/vaults", <LockOutlinedIcon />],
      ["getting-started/import", <FileUploadOutlinedIcon />],
      ["getting-started/mobile", <PhoneAndroidOutlinedIcon />],
      ["getting-started/migrating-from-termius", <CompareArrowsOutlinedIcon />],
    ],
  },
  {
    title: "Hosts and connections",
    pages: [
      ["hosts/connecting", <DnsOutlinedIcon />],
      ["hosts/groups-and-tags", <LabelOutlinedIcon />],
      ["hosts/sftp", <FolderOutlinedIcon />],
      ["hosts/port-forwarding", <SwapHorizOutlinedIcon />],
      ["hosts/serial", <UsbOutlinedIcon />],
      ["hosts/session-logs", <HistoryOutlinedIcon />],
    ],
  },
  {
    title: "Terminal",
    pages: [
      ["terminal/tabs-and-splits", <ViewQuiltOutlinedIcon />],
      ["terminal/snippets", <CodeOutlinedIcon />],
      ["terminal/autocomplete", <TerminalOutlinedIcon />],
      ["terminal/appearance", <PaletteOutlinedIcon />],
      ["terminal/mobile", <PhoneAndroidOutlinedIcon />],
      ["terminal/compose-and-ai", <EditNoteOutlinedIcon />],
      ["terminal/linux-on-android", <DeveloperBoardOutlinedIcon />],
    ],
  },
  {
    title: "Keychain",
    pages: [
      ["keychain/keys-and-certificates", <KeyOutlinedIcon />],
      ["keychain/identities", <BadgeOutlinedIcon />],
      ["keychain/security-keys", <FingerprintOutlinedIcon />],
      ["keychain/ssh-id", <AlternateEmailOutlinedIcon />],
      ["keychain/ssh-agent", <VpnKeyOutlinedIcon />],
      ["keychain/external-secret-managers", <LockOpenOutlinedIcon />],
    ],
  },
  {
    title: "Teams",
    pages: [
      ["teams/teams-and-roles", <GroupsOutlinedIcon />],
      ["teams/team-vaults", <Inventory2OutlinedIcon />],
      ["teams/terminal-sharing", <ConnectedTvOutlinedIcon />],
      ["teams/ssh-ca", <VerifiedUserOutlinedIcon />],
      ["teams/automations", <ScheduleOutlinedIcon />],
    ],
  },
  {
    title: "Security",
    pages: [
      ["security/encryption", <ShieldOutlinedIcon />],
      ["security/account", <LoginOutlinedIcon />],
      ["security/app-lock", <PhonelinkLockOutlinedIcon />],
      ["security/privacy", <VisibilityOffOutlinedIcon />],
    ],
  },
  {
    title: "Self-hosting",
    pages: [
      ["self-hosting/overview", <CloudOutlinedIcon />],
      ["self-hosting/configuration", <TuneOutlinedIcon />],
      ["self-hosting/upgrading", <SystemUpdateAltOutlinedIcon />],
      ["self-hosting/backups", <SettingsBackupRestoreOutlinedIcon />],
      ["self-hosting/ha", <LanOutlinedIcon />],
      ["self-hosting/api-bridge", <HubOutlinedIcon />],
    ],
  },
  {
    title: "Reference",
    pages: [
      ["reference/keyboard-shortcuts", <KeyboardOutlinedIcon />],
      ["reference/troubleshooting", <BuildOutlinedIcon />],
      ["reference/faq", <HelpOutlineOutlinedIcon />],
    ],
  },
];

export const sections: DocSection[] = layout.map((s) => ({
  title: s.title,
  pages: s.pages.map(([path, icon]) => ({ path, icon, section: s.title, ...load(path) })),
}));

export const pages: DocPage[] = sections.flatMap((s) => s.pages);

export function findPage(path: string): DocPage | undefined {
  return pages.find((p) => p.path === path);
}

export function hrefOf(page: DocPage): string {
  return page.path ? `/docs/${page.path}` : "/docs";
}

export interface SearchHit {
  page: DocPage;
  heading: string | null;
  anchor: string;
  snippet: string;
}

interface IndexEntry {
  page: DocPage;
  heading: string | null;
  anchor: string;
  text: string;
  lower: string;
}

let index: IndexEntry[] | null = null;

function buildIndex(): IndexEntry[] {
  const out: IndexEntry[] = [];
  for (const page of pages) {
    const parts = page.body.split(/^(?=##? )/m);
    for (const part of parts) {
      const m = /^(##?) (.+)\n/.exec(part);
      const heading = m?.[2]?.trim() ?? null;
      const text = plainText(m ? part.slice(m[0].length) : part);
      const anchor = heading
        ? `#${heading
            .toLowerCase()
            .replace(/[^a-z0-9\s-]/g, "")
            .trim()
            .replace(/\s+/g, "-")}`
        : "";
      out.push({
        page,
        heading,
        anchor,
        text,
        lower: `${page.title} ${heading ?? ""} ${text}`.toLowerCase(),
      });
    }
  }
  return out;
}

export function search(query: string, limit = 12): SearchHit[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  index ??= buildIndex();
  const words = q.split(/\s+/);
  const scored: { score: number; e: IndexEntry }[] = [];
  for (const e of index) {
    if (!words.every((w) => e.lower.includes(w))) continue;
    let score = 0;
    if (e.page.title.toLowerCase().includes(q)) score += 10;
    if (e.heading?.toLowerCase().includes(q)) score += 6;
    if (e.page.description.toLowerCase().includes(q)) score += 3;
    score += 1;
    scored.push({ score, e });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map(({ e }) => {
    const i = e.text.toLowerCase().indexOf(words[0] ?? q);
    const start = Math.max(0, i - 60);
    const snippet =
      (start > 0 ? "…" : "") +
      e.text.slice(start, start + 160) +
      (e.text.length > start + 160 ? "…" : "");
    return { page: e.page, heading: e.heading, anchor: e.anchor, snippet };
  });
}
