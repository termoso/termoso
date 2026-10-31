import { distroIcon, distroIcons, type DistroIcon } from "./distroIcons";
import { brandIcons, genericIcons } from "./iconCatalog";

export type { DistroIcon };

const catalog = new Map<string, DistroIcon>(
  [...genericIcons, ...brandIcons].map((i) => [i.id, i]),
);

/**
 * Icon for an explicit pick (`Host.icon` / `Group.icon`): the generic and
 * product catalog first, then the OS logos. Unknown ids resolve to `null`, so
 * a pick made by a newer client degrades to the default instead of breaking.
 */
export function pickedIcon(id: string | null | undefined): DistroIcon | null {
  const key = id?.trim().toLowerCase();
  if (!key) return null;
  return catalog.get(key) ?? distroIcon(key);
}

/** Sections of the picker, in display order. */
export function iconSections(): { title: string; icons: DistroIcon[] }[] {
  return [
    { title: "General", icons: genericIcons },
    { title: "Applications", icons: brandIcons },
    { title: "Operating systems", icons: Object.values(distroIcons) },
  ];
}
