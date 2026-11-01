// Remote file connections (SFTP, WebDAV) and transfers as seen by the UI.
// Rust owns the transport, file I/O and cancellation; this mirrors its
// events. Names keep the `sftp` prefix because the IPC surface does.

import type { QueryClient } from "@tanstack/react-query";
import * as ipc from "@/ipc/commands";
import type {
  Conflict,
  Direction,
  EditEvent,
  EditInfo,
  RemoteCapabilities,
  SftpEvent,
  SftpInfo,
  SftpTarget,
  TransferEvent,
  TransferInfo,
  Uuid,
} from "@/ipc/types";
import { SFTP_CAPABILITIES, errorMessage } from "@/ipc/types";
import { createStore, omit, useStore } from "@/lib/store";
import { tr } from "@/i18n";
import { requirePerm } from "@/team/perms";

export type ConnStatus = "connecting" | "open" | "error" | "closed";

export interface SftpConn {
  id: Uuid;
  target: SftpTarget;
  title: string;
  hostId: Uuid | null;
  status: ConnStatus;
  message: string | null;
  info: SftpInfo | null;
}

export type TransferStatus = "queued" | "running" | "paused" | "done" | "failed" | "cancelled";

/** Still owned by the engine's queue (can be paused, resumed or cancelled). */
export const isActive = (s: TransferStatus) => s === "queued" || s === "running";

export interface Transfer {
  id: Uuid;
  sftpId: Uuid;
  direction: Direction;
  local: string;
  remote: string;
  conflict: Conflict;
  status: TransferStatus;
  done: number;
  total: number | null;
  filesDone: number;
  filesTotal: number;
  filesSkipped: number;
  current: string;
  message: string | null;
  startedAt: number;
  finishedAt: number | null;
  /** Smoothed throughput in bytes per second; `null` until the first sample. */
  speed: number | null;
  /** Cancel requested but the engine has not confirmed yet. */
  cancelling: boolean;
}

export type EditStatus = "watching" | "uploading" | "failed";

/** A remote file opened in a local application (Open / Open with…). */
export interface Edit {
  info: EditInfo;
  status: EditStatus;
  message: string | null;
  uploadedAt: number | null;
  uploadedBytes: number | null;
}

export interface SftpState {
  conns: Record<Uuid, SftpConn>;
  order: Uuid[];
  /** Connection shown in the right pane. */
  activeId: Uuid | null;
  /** Connection shown in the left pane; `null` = the local file system. */
  leftId: Uuid | null;
  /** Left pane is showing the host picker instead of a file list. */
  leftPicking: boolean;
  transfers: Record<Uuid, Transfer>;
  transferOrder: Uuid[];
  edits: Record<Uuid, Edit>;
  editOrder: Uuid[];
  /** Files copied so far while staging an OS drop; `null` when idle. */
  staging: number | null;
}

export const sftpStore = createStore<SftpState>({
  conns: {},
  order: [],
  activeId: null,
  leftId: null,
  leftPicking: false,
  transfers: {},
  transferOrder: [],
  edits: {},
  editOrder: [],
  staging: null,
});

export const useSftp = <S>(selector: (s: SftpState) => S) => useStore(sftpStore, selector);

const update = (fn: (s: SftpState) => SftpState) => sftpStore.set(fn);

function patchConn(id: Uuid, patch: Partial<SftpConn>) {
  update((s) => {
    const c = s.conns[id];
    return c ? { ...s, conns: { ...s.conns, [id]: { ...c, ...patch } } } : s;
  });
}

function patchTransfer(id: Uuid, patch: Partial<Transfer>) {
  update((s) => {
    const t = s.transfers[id];
    return t ? { ...s, transfers: { ...s.transfers, [id]: { ...t, ...patch } } } : s;
  });
}

export const fsQueryKey = (side: "local" | "remote", sftpId: Uuid | null, path: string | null) =>
  ["fs", side, sftpId, path] as const;

// ───────────────────────────── connections ─────────────────────────────

function connect(id: Uuid, target: SftpTarget) {
  ipc
    .sftpOpen(id, target)
    .then((info) => patchConn(id, { status: "open", info, title: info.title, message: null }))
    .catch((e: unknown) => {
      if (sftpStore.get().conns[id]?.status === "closed") return;
      patchConn(id, { status: "error", message: errorMessage(e) });
    });
}

export type PaneSide = "left" | "right";

export function openSftp(
  target: SftpTarget,
  title: string,
  hostId: Uuid | null,
  side: PaneSide = "right",
): Uuid {
  const s = sftpStore.get();
  if (target.kind === "session") {
    const existing = Object.values(s.conns).find(
      (c) =>
        c.target.kind === "session" &&
        c.target.session_id === target.session_id &&
        c.status !== "closed" &&
        c.status !== "error",
    );
    if (existing) {
      if (side === "left") setLeftSource(existing.id);
      else setActiveSftp(existing.id);
      return existing.id;
    }
  }
  const id = crypto.randomUUID();
  const conn: SftpConn = {
    id,
    target,
    title,
    hostId,
    status: "connecting",
    message: null,
    info: null,
  };
  update((st) => ({
    ...st,
    conns: { ...st.conns, [id]: conn },
    order: [...st.order, id],
    ...(side === "left" ? { leftId: id, leftPicking: false } : { activeId: id }),
  }));
  connect(id, target);
  return id;
}

export const openSftpForHost = (
  hostId: Uuid,
  title: string,
  vaultId: Uuid | null = null,
  side: PaneSide = "right",
) => {
  if (!requirePerm(vaultId, "connect.sftp")) return;
  openSftp({ kind: "host", host_id: hostId, vault_id: vaultId }, title, hostId, side);
};

/** Browse as root: the password is used once to start `sftp-server` under sudo and is never stored. */
export const openSftpForHostAsRoot = (
  hostId: Uuid,
  title: string,
  vaultId: Uuid | null,
  sudoPassword: string,
  side: PaneSide = "right",
) => {
  if (!requirePerm(vaultId, "connect.sftp")) return;
  openSftp(
    { kind: "host", host_id: hostId, vault_id: vaultId, sudo_password: sudoPassword },
    `${title} (root)`,
    hostId,
    side,
  );
};

export const openSftpForSession = (
  sessionId: Uuid,
  title: string,
  hostId: Uuid | null,
  side: PaneSide = "right",
) => openSftp({ kind: "session", session_id: sessionId }, title, hostId, side);

export const openWebDavForHost = (
  hostId: Uuid,
  title: string,
  vaultId: Uuid | null = null,
  side: PaneSide = "right",
) => {
  if (!requirePerm(vaultId, "connect.sftp")) return;
  openSftp({ kind: "webdav", host_id: hostId, vault_id: vaultId }, title, hostId, side);
};

/** Capabilities of a connection; full SFTP until Rust reports otherwise. */
export const connCapabilities = (c: SftpConn | undefined): RemoteCapabilities =>
  c?.info?.capabilities ?? SFTP_CAPABILITIES;

/** Browse a host's offline copies (read-only) instead of connecting. */
export function openSftpOffline(hostId: Uuid, title: string, side: PaneSide = "right"): Uuid {
  return openSftp({ kind: "offline", host_id: hostId }, title, hostId, side);
}

export function reconnectSftp(id: Uuid) {
  const c = sftpStore.get().conns[id];
  if (!c) return;
  patchConn(id, { status: "connecting", message: null, info: null });
  connect(id, c.target);
}

export function setActiveSftp(id: Uuid | null) {
  update((s) => (s.activeId === id ? s : { ...s, activeId: id }));
}

/** Left pane source: a connection, or `null` for the local file system. */
export function setLeftSource(id: Uuid | null) {
  update((s) => ({ ...s, leftId: id, leftPicking: false }));
}

/** Show the host picker in the left pane. */
export function startLeftPick() {
  update((s) => ({ ...s, leftPicking: true }));
}

export async function closeSftp(id: Uuid) {
  update((s) => {
    const conns = omit(s.conns, id);
    const order = s.order.filter((x) => x !== id);
    const activeId = s.activeId === id ? (order[order.length - 1] ?? null) : s.activeId;
    const leftId = s.leftId === id ? null : s.leftId;
    return { ...s, conns, order, activeId, leftId };
  });
  await ipc.sftpClose(id).catch(() => undefined);
}

/** Vault locked: forget every connection locally (Rust closed them already). */
export function dropAllSftp() {
  for (const id of sftpStore.get().order) void closeSftp(id);
}

// ───────────────────────────── transfers ─────────────────────────────

function addTransfer(info: TransferInfo) {
  update((s) => {
    if (s.transfers[info.id]) return s;
    const t: Transfer = {
      id: info.id,
      sftpId: info.sftpId,
      direction: info.direction,
      local: info.local,
      remote: info.remote,
      conflict: info.conflict,
      status: "queued",
      done: 0,
      total: null,
      filesDone: 0,
      filesTotal: 1,
      filesSkipped: 0,
      current: "",
      message: null,
      startedAt: Date.now(),
      finishedAt: null,
      speed: null,
      cancelling: false,
    };
    return {
      ...s,
      transfers: { ...s.transfers, [info.id]: t },
      transferOrder: [info.id, ...s.transferOrder],
    };
  });
}

export async function startTransfer(args: {
  sftpId: Uuid;
  toSftpId?: Uuid | null;
  direction: Direction;
  local: string;
  remote: string;
  conflict?: Conflict;
  temp?: boolean;
}) {
  const info = await ipc.transferStart(args);
  addTransfer(info);
  return info;
}

export function setStaging(count: number | null) {
  update((s) => (s.staging === count ? s : { ...s, staging: count }));
}

export function cancelTransfer(id: Uuid) {
  patchTransfer(id, { cancelling: true });
  return ipc.transferCancel(id);
}

/** Remove a paused or failed transfer from the queue and the list. */
export async function discardTransfer(id: Uuid) {
  update((s) => ({
    ...s,
    transfers: omit(s.transfers, id),
    transferOrder: s.transferOrder.filter((x) => x !== id),
  }));
  samples.delete(id);
  await ipc.transferCancel(id);
}

export function pauseTransfer(id: Uuid) {
  return ipc.transferPause(id);
}

/** Resume a paused transfer or retry a failed one from where it stopped. */
export async function resumeTransfer(id: Uuid) {
  samples.delete(id);
  patchTransfer(id, { status: "queued", message: null, finishedAt: null, speed: null });
  try {
    await ipc.transferResume(id);
  } catch (e) {
    patchTransfer(id, { status: "failed", message: errorMessage(e), finishedAt: Date.now() });
    throw e;
  }
}

/** Last progress sample per transfer, for the throughput estimate. */
const samples = new Map<Uuid, { at: number; done: number }>();

function sampleSpeed(t: Transfer, done: number): number | null {
  const now = Date.now();
  const prev = samples.get(t.id) ?? { at: t.startedAt, done: 0 };
  const dt = now - prev.at;
  if (dt < 400) return t.speed;
  samples.set(t.id, { at: now, done });
  const inst = ((done - prev.done) * 1000) / dt;
  return t.speed === null ? inst : t.speed * 0.7 + inst * 0.3;
}

/** Drop everything that is not queued, running or paused. */
export function clearFinishedTransfers() {
  const dropped: Uuid[] = [];
  update((s) => {
    const transfers: Record<Uuid, Transfer> = {};
    const transferOrder = s.transferOrder.filter((id) => {
      const t = s.transfers[id];
      if (t && (isActive(t.status) || t.status === "paused")) {
        transfers[id] = t;
        return true;
      }
      dropped.push(id);
      return false;
    });
    return { ...s, transfers, transferOrder };
  });
  for (const id of dropped) void ipc.transferForget(id).catch(() => undefined);
}

// ───────────────────────────── edits ─────────────────────────────

function addEdit(info: EditInfo) {
  update((s) => {
    if (s.edits[info.id]) return s;
    const e: Edit = {
      info,
      status: "watching",
      message: null,
      uploadedAt: null,
      uploadedBytes: null,
    };
    return { ...s, edits: { ...s.edits, [info.id]: e }, editOrder: [info.id, ...s.editOrder] };
  });
}

function patchEdit(id: Uuid, patch: Partial<Edit>) {
  update((s) => {
    const e = s.edits[id];
    return e ? { ...s, edits: { ...s.edits, [id]: { ...e, ...patch } } } : s;
  });
}

export async function openEdit(sftpId: Uuid, remote: string, withApp: string | null) {
  const info = await ipc.editOpen(sftpId, remote, withApp);
  addEdit(info);
  return info;
}

export const uploadEditNow = (id: Uuid) => ipc.editUploadNow(id);

export async function closeEdit(id: Uuid) {
  update((s) => ({
    ...s,
    edits: omit(s.edits, id),
    editOrder: s.editOrder.filter((x) => x !== id),
  }));
  await ipc.editClose(id).catch(() => undefined);
}

/** Remote paths currently open for editing on `sftpId`. */
export function editingPaths(edits: Edit[], sftpId: Uuid): Set<string> {
  return new Set(edits.filter((e) => e.info.sftpId === sftpId).map((e) => e.info.remote));
}

function onEditEvent(ev: EditEvent, queryClient: QueryClient) {
  switch (ev.type) {
    case "opened":
      addEdit(ev.info);
      break;
    case "uploading":
      patchEdit(ev.id, { status: "uploading", message: null });
      break;
    case "uploaded":
      patchEdit(ev.id, {
        status: "watching",
        message: null,
        uploadedAt: Date.parse(ev.at) || Date.now(),
        uploadedBytes: ev.bytes,
      });
      void queryClient.invalidateQueries({ queryKey: ["fs", "remote"] });
      break;
    case "failed":
      patchEdit(ev.id, { status: "failed", message: ev.message });
      break;
    case "closed":
      update((s) => ({
        ...s,
        edits: omit(s.edits, ev.id),
        editOrder: s.editOrder.filter((x) => x !== ev.id),
      }));
      break;
  }
}

// ───────────────────────────── events ─────────────────────────────

function onSftpEvent(ev: SftpEvent) {
  switch (ev.type) {
    case "opened":
      if (sftpStore.get().conns[ev.id]) {
        patchConn(ev.id, { status: "open", info: ev.info, title: ev.info.title });
      }
      break;
    case "closed": {
      const c = sftpStore.get().conns[ev.id];
      if (c && c.status !== "closed") {
        patchConn(ev.id, { status: "closed", message: tr("Connection closed") });
      }
      break;
    }
  }
}

type TransferDoneListener = (transfer: Transfer) => void;
const transferDoneListeners = new Set<TransferDoneListener>();

/** A transfer reached `done` or `failed` (cancellations are not reported). */
export function onTransferDone(listener: TransferDoneListener): () => void {
  transferDoneListeners.add(listener);
  return () => {
    transferDoneListeners.delete(listener);
  };
}

function onTransferEvent(ev: TransferEvent, queryClient: QueryClient) {
  switch (ev.type) {
    case "started":
      addTransfer(ev.info);
      break;
    case "queued":
      patchTransfer(ev.id, { status: "queued", message: null, finishedAt: null });
      break;
    case "running": {
      const now = Date.now();
      samples.set(ev.id, { at: now, done: sftpStore.get().transfers[ev.id]?.done ?? 0 });
      patchTransfer(ev.id, { status: "running", speed: null, startedAt: now });
      break;
    }
    case "paused": {
      const t = sftpStore.get().transfers[ev.id];
      samples.delete(ev.id);
      patchTransfer(ev.id, { status: "paused", speed: null, cancelling: false });
      void queryClient.invalidateQueries({
        queryKey: ["fs", t?.direction === "download" ? "local" : "remote"],
      });
      break;
    }
    case "progress": {
      const t = sftpStore.get().transfers[ev.id];
      if (!t) break;
      patchTransfer(ev.id, {
        done: ev.done,
        total: ev.total,
        filesDone: ev.files_done,
        filesTotal: ev.files_total,
        filesSkipped: ev.files_skipped,
        current: ev.current,
        speed: sampleSpeed(t, ev.done),
      });
      break;
    }
    case "finished":
    case "failed":
    case "cancelled": {
      const t = sftpStore.get().transfers[ev.id];
      samples.delete(ev.id);
      patchTransfer(ev.id, {
        status: ev.type === "finished" ? "done" : ev.type,
        message: ev.type === "failed" ? ev.message : null,
        done: ev.type === "finished" ? ev.bytes : (t?.done ?? 0),
        filesSkipped: ev.type === "finished" ? ev.files_skipped : (t?.filesSkipped ?? 0),
        filesDone: ev.type === "finished" ? (t?.filesTotal ?? 1) : (t?.filesDone ?? 0),
        finishedAt: Date.now(),
        cancelling: false,
      });
      const side = t?.direction === "download" ? "local" : "remote";
      void queryClient.invalidateQueries({ queryKey: ["fs", side] });
      const done = sftpStore.get().transfers[ev.id];
      if (done && ev.type !== "cancelled") {
        for (const l of transferDoneListeners) l(done);
      }
      break;
    }
  }
}

let started = false;
export function startSftpEvents(queryClient: QueryClient) {
  if (started) return;
  started = true;
  void ipc.onSftpEvent(onSftpEvent);
  void ipc.onTransferEvent((ev) => onTransferEvent(ev, queryClient));
  void ipc.onEditEvent((ev) => onEditEvent(ev, queryClient));
  ipc
    .editsList()
    .then((list) => list.forEach(addEdit))
    .catch(() => undefined);
}
