import { afterEach, describe, expect, it, vi } from "vitest";
import {
  customIconFromDataUrl,
  customIconSource,
  isCustomIcon,
  MAX_CUSTOM_ICON_DATA_URL_LENGTH,
  resizeCustomIconFile,
} from "./customIcon";

afterEach(() => {
  vi.unstubAllGlobals();
});

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

  it("resizes an oversized raster image to a 64x64 PNG", async () => {
    const context = {
      clearRect: vi.fn(),
      drawImage: vi.fn(),
    };
    const canvas = {
      width: 0,
      height: 0,
      getContext: vi.fn(() => context),
      toDataURL: vi.fn(() => "data:image/png;base64,AA=="),
    };
    class MockImage {
      naturalWidth = 128;
      naturalHeight = 64;
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      set src(_value: string) {
        queueMicrotask(() => this.onload?.());
      }
    }
    vi.stubGlobal("document", { createElement: vi.fn(() => canvas) });
    vi.stubGlobal("Image", MockImage);
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn(() => "blob:custom-icon"),
      revokeObjectURL: vi.fn(),
    });

    const file = new File([new Uint8Array(100_000)], "wide.png", { type: "image/png" });
    const stored = await resizeCustomIconFile(file);

    expect(stored).toBe("custom:data:data:image/png;base64,AA==");
    expect(canvas.width).toBe(64);
    expect(canvas.height).toBe(64);
    expect(context.drawImage).toHaveBeenCalledWith(expect.any(MockImage), 0, 16, 64, 32);
  });

  it("keeps SVG data intact while accepting only supported files", async () => {
    class MockFileReader {
      result = "data:image/svg+xml;base64,PHN2Zy8+";
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      readAsDataURL() {
        queueMicrotask(() => this.onload?.());
      }
    }
    vi.stubGlobal("FileReader", MockFileReader);

    const svg = new File(['<svg xmlns="http://www.w3.org/2000/svg" />'], "icon.svg", {
      type: "image/svg+xml",
    });
    const stored = await resizeCustomIconFile(svg);
    expect(stored).toMatch(/^custom:data:data:image\/svg\+xml;base64,/);

    const text = new File(["not an image"], "icon.txt", { type: "text/plain" });
    expect(await resizeCustomIconFile(text)).toBeNull();
  });
});
