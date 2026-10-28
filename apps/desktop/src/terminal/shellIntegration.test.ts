import { describe, expect, it } from "vitest";

import { looksLikeShellPrompt } from "./shellIntegration";

const at = (line: string, extra: Partial<Parameters<typeof looksLikeShellPrompt>[0]> = {}) =>
  looksLikeShellPrompt({
    line,
    cursorX: line.length,
    alternateScreen: false,
    ...extra,
  });

describe("looksLikeShellPrompt", () => {
  it("accepts the usual shell prompts", () => {
    for (const p of ["user@host:~$ ", "root@box:/# ", "host% ", "❯ ", "~ › ", "λ "]) {
      expect(at(p), p).toBe(true);
    }
  });

  it("rejects REPL and CLI prompts that end in >", () => {
    for (const p of [">>> ", "mysql> ", "[admin@MikroTik] > ", "> ", "psql=> ", "PS C:\\> "]) {
      expect(at(p), p).toBe(false);
    }
  });

  it("rejects an empty row and text still printing past the cursor", () => {
    expect(at("")).toBe(false);
    expect(at("Last login: Mon$ ", { cursorX: 3 })).toBe(false);
  });

  it("never fires inside a TUI on the alternate screen", () => {
    expect(at("user@host:~$ ", { alternateScreen: true })).toBe(false);
  });
});
