const CUSTOM_DATA_PREFIX = "custom:data:";
const CUSTOM_URL_PREFIX = "custom:url:";

/** Maximum size of a local image before it is embedded in the vault. */
export const MAX_CUSTOM_ICON_FILE_BYTES = 512 * 1024;
/** Keep remote references small enough to fit comfortably in synced entity data. */
export const MAX_CUSTOM_ICON_URL_LENGTH = 2048;
/** Base64 expands a file by roughly one third, plus the data URL header. */
export const MAX_CUSTOM_ICON_DATA_URL_LENGTH = 768 * 1024;

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
  if (!value) return null;
  if (value.startsWith(CUSTOM_DATA_PREFIX)) {
    const dataUrl = value.slice(CUSTOM_DATA_PREFIX.length);
    return validDataUrl(dataUrl) ? dataUrl : null;
  }
  if (value.startsWith(CUSTOM_URL_PREFIX)) {
    const url = value.slice(CUSTOM_URL_PREFIX.length);
    return customIconFromUrl(url) === value ? url : null;
  }
  return null;
}

/** Validate and encode an HTTP(S) image URL for storage. */
export function customIconFromUrl(raw: string): string | null {
  const value = raw.trim();
  if (!value || value.length > MAX_CUSTOM_ICON_URL_LENGTH) return null;
  try {
    const url = new URL(value);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname) return null;
    if (url.username || url.password) return null;
    return `${CUSTOM_URL_PREFIX}${url.href}`;
  } catch {
    return null;
  }
}

export function isSupportedImageMime(mime: string): boolean {
  return IMAGE_MIME.test(mime.trim());
}

export function isCustomIcon(value: string | null | undefined): boolean {
  return customIconSource(value) !== null;
}

/** The URL part of a stored remote icon, used to re-open the editor. */
export function customIconUrl(value: string | null | undefined): string | null {
  const source = customIconSource(value);
  return value?.startsWith(CUSTOM_URL_PREFIX) && source ? source : null;
}
