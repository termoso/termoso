const CUSTOM_DATA_PREFIX = "custom:data:";

/** Maximum size of the source file accepted by the desktop picker. */
export const MAX_CUSTOM_ICON_FILE_BYTES = 8 * 1024 * 1024;
/** SVG files are kept in their original form, but remain small. */
export const MAX_CUSTOM_ICON_SVG_BYTES = 16 * 1024;
/** TypeScript and Rust use the same limit for the stored data URL. */
export const MAX_CUSTOM_ICON_DATA_URL_LENGTH = 32 * 1024;
export const CUSTOM_ICON_SIZE = 64;

const IMAGE_MIME = /^image\/(?:png|jpeg|gif|webp|svg\+xml|x-icon|avif)$/i;
const DATA_URL =
  /^data:(image\/(?:png|jpeg|gif|webp|svg\+xml|x-icon|avif));base64,([a-z0-9+/]+={0,2})$/i;

function validDataUrl(value: string): boolean {
  if (value.length > MAX_CUSTOM_ICON_DATA_URL_LENGTH) return false;
  const match = DATA_URL.exec(value);
  return match !== null && (match[2]?.length ?? 0) > 0;
}

/** Turn a FileReader data URL into the value stored in a host/group icon field. */
export function customIconFromDataUrl(dataUrl: string): string | null {
  const value = dataUrl.trim();
  return validDataUrl(value) ? `${CUSTOM_DATA_PREFIX}${value}` : null;
}

/** Return a stored custom icon's image source, or null for built-in/invalid ids. */
export function customIconSource(value: string | null | undefined): string | null {
  if (!value?.startsWith(CUSTOM_DATA_PREFIX)) return null;
  const dataUrl = value.slice(CUSTOM_DATA_PREFIX.length);
  return validDataUrl(dataUrl) ? dataUrl : null;
}

export function isSupportedImageMime(mime: string): boolean {
  return IMAGE_MIME.test(mime.trim());
}

export function isCustomIcon(value: string | null | undefined): boolean {
  return customIconSource(value) !== null;
}

function readFileAsDataUrl(file: File): Promise<string | null> {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : null);
    reader.onerror = () => resolve(null);
    reader.readAsDataURL(file);
  });
}

function loadImage(source: string): Promise<HTMLImageElement | null> {
  return new Promise((resolve) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => resolve(null);
    image.src = source;
  });
}

/**
 * Resize raster images to a transparent 64×64 PNG before storing them. SVG is
 * intentionally kept as SVG so vector icons remain crisp at any display size.
 */
export async function resizeCustomIconFile(file: File): Promise<string | null> {
  if (!isSupportedImageMime(file.type) || file.size > MAX_CUSTOM_ICON_FILE_BYTES) {
    return null;
  }
  if (file.type.toLowerCase() === "image/svg+xml") {
    if (file.size > MAX_CUSTOM_ICON_SVG_BYTES) return null;
    const dataUrl = await readFileAsDataUrl(file);
    return dataUrl ? customIconFromDataUrl(dataUrl) : null;
  }

  const objectUrl = URL.createObjectURL(file);
  try {
    const image = await loadImage(objectUrl);
    if (!image || image.naturalWidth <= 0 || image.naturalHeight <= 0) return null;
    const canvas = document.createElement("canvas");
    canvas.width = CUSTOM_ICON_SIZE;
    canvas.height = CUSTOM_ICON_SIZE;
    const context = canvas.getContext("2d");
    if (!context) return null;
    context.clearRect(0, 0, CUSTOM_ICON_SIZE, CUSTOM_ICON_SIZE);
    const scale = Math.min(
      CUSTOM_ICON_SIZE / image.naturalWidth,
      CUSTOM_ICON_SIZE / image.naturalHeight,
    );
    const width = image.naturalWidth * scale;
    const height = image.naturalHeight * scale;
    context.drawImage(
      image,
      (CUSTOM_ICON_SIZE - width) / 2,
      (CUSTOM_ICON_SIZE - height) / 2,
      width,
      height,
    );
    return customIconFromDataUrl(canvas.toDataURL("image/png"));
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}
