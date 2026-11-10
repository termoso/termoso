import type { Uuid } from "@/ipc/types";

/** Tab title for a session: the host's label when it has one, else the host name. */
export function sessionTitle(info: { title: string; target: string; hostId: Uuid | null }): string {
  const label = info.title.trim();
  if (label || !info.hostId) return info.title;
  // `user@host:port`, `host:port` or `user@[::1]:22` → the bare host name.
  const rest = info.target.replace(/ · .*$/, "").replace(/^.*@/, "");
  const v6 = /^\[([^\]]+)\]/.exec(rest);
  const host = v6 ? v6[1] : rest.replace(/:\d+$/, "");
  return host === undefined || host === "" ? info.target : host;
}
