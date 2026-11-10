import { describe, expect, it } from "vitest";
import { sessionTitle } from "./sessionTitle";

const ID = "3f2b7c9e-1d4a-4e8b-9c6f-0a1b2c3d4e5f";
const saved = (title: string, target: string) => sessionTitle({ title, target, hostId: ID });

describe("sessionTitle", () => {
  it("shows the label when the host has one", () => {
    expect(saved("Zabbix main", "root@172.20.8.12:22")).toBe("Zabbix main");
  });
  it("falls back to the bare host name without a label", () => {
    expect(saved("", "root@172.20.8.12:22")).toBe("172.20.8.12");
    expect(saved("  ", "web1.example.com:2222")).toBe("web1.example.com");
  });
  it("handles IPv6 and Mosh targets", () => {
    expect(saved("", "root@[::1]:22")).toBe("::1");
    expect(saved("", "deploy@edge:22 · mosh udp/60001")).toBe("edge");
  });
  it("leaves sessions without a saved host alone", () => {
    expect(sessionTitle({ title: "", target: "root@h:22", hostId: null })).toBe("");
    expect(sessionTitle({ title: "Local", target: "local shell", hostId: null })).toBe("Local");
  });
});
