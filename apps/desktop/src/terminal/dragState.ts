// What the user is dragging between tabs and panes right now. HTML5 drag events
// cannot read `dataTransfer` data while hovering, so drop targets (tabs, pane
// overlays) consult this instead.

import { createStore, useStore } from "@/lib/store";
import type { Uuid } from "@/ipc/types";

export interface DockPreview {
  /** Viewport rectangle the docked session will take. */
  rect: { left: number; top: number; width: number; height: number };
  /** The window is full: shown in the error colour. */
  full: boolean;
}

interface DockPreviewState {
  /** The preview being shown; `null` while hidden. */
  preview: DockPreview | null;
  /** Last preview shown, kept so it can fade out in place. */
  last: DockPreview | null;
  /** Already visible, so a move should glide rather than appear. */
  slide: boolean;
}

export const dockPreviewStore = createStore<DockPreviewState>({
  preview: null,
  last: null,
  slide: false,
});
export const useDockPreview = () => useStore(dockPreviewStore, (s) => s);

let clearTimer: ReturnType<typeof setTimeout> | undefined;

/** Show (or move) the single docking preview. */
export function showDockPreview(preview: DockPreview) {
  clearTimeout(clearTimer);
  dockPreviewStore.set((s) => ({ preview, last: preview, slide: s.preview !== null }));
}

/**
 * Hide the preview shortly: moving between two panes fires leave then enter,
 * and the next `showDockPreview` cancels this so the preview glides instead of blinking.
 */
export function hideDockPreview() {
  clearTimeout(clearTimer);
  clearTimer = setTimeout(
    () => dockPreviewStore.set((s) => ({ ...s, preview: null, slide: false })),
    80,
  );
}

export type SessionDrag = { kind: "tab"; id: string } | { kind: "pane"; id: Uuid };

export const dragStore = createStore<{ drag: SessionDrag | null }>({ drag: null });

export const useSessionDrag = () => useStore(dragStore, (s) => s.drag);

export function setSessionDrag(drag: SessionDrag | null) {
  dragStore.set({ drag });
}

// A drop can unmount the element that started the drag, so `dragend` may never
// reach it; clear the state at the window instead (after the target's own handler).
if (typeof window !== "undefined") {
  const end = () => {
    setSessionDrag(null);
    hideDockPreview();
  };
  window.addEventListener("dragend", end);
  window.addEventListener("drop", end);
}
