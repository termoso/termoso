import { describe, expect, it } from "vitest";
import { activeLocale, setLanguage, tr, trn, trx } from "./index";
import { ru } from "./ru";

const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe("ru table", () => {
  it("keeps every placeholder of the English source", () => {
    for (const [en, value] of Object.entries(ru)) {
      const want = placeholders(en);
      for (const form of value.split("|")) {
        expect(placeholders(form), en).toEqual(want);
      }
    }
  });

  it("lists one|few|many for plural entries and nothing else uses |", () => {
    for (const [en, value] of Object.entries(ru)) {
      if (value.includes("|")) {
        expect(en, en).toContain("{count}");
        expect(value.split("|"), en).toHaveLength(3);
      }
    }
  });

  // Brand names, acronyms, file names and placeholder-only strings read the
  // same in Russian; they still get an entry so Weblate counts them as done.
  const sameInRussian = new Set([
    "Aa",
    "Access Key ID",
    "Ansible inventory",
    "Authorization: Bearer",
    "Big5",
    "CSV",
    "Client Secret",
    "Datadog Logs",
    "Elasticsearch / OpenSearch",
    "ID {keyId}",
    "IP",
    "IPv4",
    "IPv6",
    "IdP",
    "JSONL",
    "Lightsail",
    "MFA",
    "Mosh",
    "Okta production",
    "OpenSSH 5.7+",
    "PIN",
    "Regex",
    "SCIM",
    "SFTP",
    "SFTP ({sftpCount})",
    "SSH ID",
    "SSO",
    "Secret Access Key",
    "Shift_JIS",
    "Splunk HEC",
    "TERMOSO_BRIDGE_API_KEY",
    "Telnet",
    "Tenant ID",
    "Termius / CSV",
    "Termoso",
    "Termoso Cloud",
    "URL (https://…)",
    "WebDAV",
    "WinSCP.ini…",
    "YubiKey 5C",
    "ZMODEM: {error}",
    "ZOC Terminal",
    "ansible-prod",
    "config.yaml…",
    "example.com, corp.example.com",
    "member., vault.deleted, policy.updated",
    "termoso-bridge",
    "vault. / member.removed",
    "{vault} · {role}",
  ]);

  it("has no identity entries", () => {
    for (const [en, value] of Object.entries(ru)) {
      if (sameInRussian.has(en)) continue;
      expect(value, en).not.toBe(en);
    }
  });
});

describe("tr / trn / trx", () => {
  it("falls back to English and interpolates", () => {
    setLanguage("en");
    expect(activeLocale()).toBe("en");
    expect(tr("Saved to {path}", { path: "/tmp/x" })).toBe("Saved to /tmp/x");
    expect(tr("not a key {n}", { n: 1 })).toBe("not a key 1");
    expect(trn(1, "{count} host", "{count} hosts")).toBe("1 host");
    expect(trn(2, "{count} host", "{count} hosts")).toBe("2 hosts");
  });

  it("picks Russian plural forms by CLDR category", () => {
    setLanguage("ru");
    expect(activeLocale()).toBe("ru");
    expect(tr("Saved to {path}", { path: "/tmp/x" })).toBe("Сохранено в /tmp/x");
    const one = trn(1, "{count} host", "{count} hosts");
    const few = trn(3, "{count} host", "{count} hosts");
    const many = trn(11, "{count} host", "{count} hosts");
    const twentyOne = trn(21, "{count} host", "{count} hosts");
    expect(one).toBe("1 хост");
    expect(few).toBe("3 хоста");
    expect(many).toBe("11 хостов");
    expect(twentyOne).toBe("21 хост");
    expect(trn(5, "{count} widget", "{count} widgets")).toBe("5 widgets");
    setLanguage("en");
  });

  it("splits rich placeholders into renderable pieces", () => {
    setLanguage("en");
    const parts = trx("Saved to {path}", { path: "X" });
    expect(parts).toHaveLength(2);
    expect(parts[0]).toBe("Saved to ");
    expect(trx("{a} and {b}", { a: 1 })).toEqual([expect.anything(), " and ", "{b}"]);
  });
});
