import { describe, expect, it } from "vitest";
import { iconSections, pickedIcon } from "./icons";

describe("pickedIcon", () => {
  it("resolves generic, product and OS ids", () => {
    expect(pickedIcon("server")?.title).toBe("Server");
    expect(pickedIcon("zabbix")?.title).toBe("Zabbix");
    expect(pickedIcon("debian")?.title).toBe("Debian");
  });
  it("is case-insensitive and ignores blanks / unknown ids", () => {
    expect(pickedIcon(" Zabbix ")?.id).toBe("zabbix");
    expect(pickedIcon("")).toBeNull();
    expect(pickedIcon(null)).toBeNull();
    expect(pickedIcon("no-such-icon")).toBeNull();
  });
  it("has unique ids across the sections", () => {
    const ids = iconSections().flatMap((s) => s.icons.map((i) => i.id));
    expect(new Set(ids).size).toBe(ids.length);
  });
});
