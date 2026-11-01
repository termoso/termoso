import { describe, expect, it } from "vitest";
import {
  customIconFromDataUrl,
  customIconFromUrl,
  customIconSource,
  customIconUrl,
  isCustomIcon,
  MAX_CUSTOM_ICON_DATA_URL_LENGTH,
} from "./customIcon";

describe("custom icons", () => {
  it("stores and reads supported embedded image data", () => {
    const stored = customIconFromDataUrl("data:image/png;base64,AAECAw==");
    expect(stored).toBe("custom:data:data:image/png;base64,AAECAw==");
    expect(customIconSource(stored)).toBe("data:image/png;base64,AAECAw==");
    expect(isCustomIcon(stored)).toBe(true);
  });

  it("rejects non-image data and oversized data URLs", () => {
    expect(customIconFromDataUrl("data:text/html;base64,PGh0bWw+")).toBeNull();
    expect(
      customIconFromDataUrl(`data:image/png;base64,${"A".repeat(MAX_CUSTOM_ICON_DATA_URL_LENGTH)}`),
    ).toBeNull();
    expect(customIconSource("custom:data:data:image/png;base64,not valid")).toBeNull();
  });

  it("accepts HTTP(S) image URLs and rejects local or credentialed URLs", () => {
    const stored = customIconFromUrl(" https://example.com/server.png ");
    expect(stored).toBe("custom:url:https://example.com/server.png");
    expect(customIconSource(stored)).toBe("https://example.com/server.png");
    expect(customIconUrl(stored)).toBe("https://example.com/server.png");
    expect(customIconFromUrl("file:///C:/server.png")).toBeNull();
    expect(customIconFromUrl("https://user:password@example.com/server.png")).toBeNull();
  });
});
