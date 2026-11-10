// Split layout of one tab: a binary tree whose leaves are panes. Pure
// functions only; the store owns the tree and React renders it.

import type { Uuid } from "@/ipc/types";

export type SplitDirection = "row" | "column";

export type SplitNode =
  | { kind: "leaf"; paneId: Uuid }
  | {
      kind: "split";
      id: string;
      direction: SplitDirection;
      /** Share of the first child, 0–1. */
      ratio: number;
      first: SplitNode;
      second: SplitNode;
    };

export const MAX_PANES = 16;
export const MIN_RATIO = 0.1;

export const leaf = (paneId: Uuid): SplitNode => ({ kind: "leaf", paneId });

/** Pane ids in reading order (first child before second, depth first). */
export function leaves(node: SplitNode): Uuid[] {
  if (node.kind === "leaf") return [node.paneId];
  return [...leaves(node.first), ...leaves(node.second)];
}

export const clampRatio = (r: number) => Math.min(1 - MIN_RATIO, Math.max(MIN_RATIO, r));

/**
 * Replace the leaf `paneId` with a split of it and `newPaneId`; the new pane
 * takes the second half. Returns the tree unchanged when the leaf is absent.
 */
export function splitLeaf(
  node: SplitNode,
  paneId: Uuid,
  newPaneId: Uuid,
  direction: SplitDirection,
  splitId: string,
): SplitNode {
  if (node.kind === "leaf") {
    if (node.paneId !== paneId) return node;
    return {
      kind: "split",
      id: splitId,
      direction,
      ratio: 0.5,
      first: node,
      second: leaf(newPaneId),
    };
  }
  const first = splitLeaf(node.first, paneId, newPaneId, direction, splitId);
  const second = splitLeaf(node.second, paneId, newPaneId, direction, splitId);
  return first === node.first && second === node.second ? node : { ...node, first, second };
}

/** Drop a leaf; its sibling takes the parent's place. `null` when the tree becomes empty. */
export function removeLeaf(node: SplitNode, paneId: Uuid): SplitNode | null {
  if (node.kind === "leaf") return node.paneId === paneId ? null : node;
  const first = removeLeaf(node.first, paneId);
  const second = removeLeaf(node.second, paneId);
  if (first === null) return second;
  if (second === null) return first;
  return first === node.first && second === node.second ? node : { ...node, first, second };
}

export type DropSide = "left" | "right" | "up" | "down";

/**
 * Put `piece` (a pane or a whole sub-tree) next to the leaf `targetId`, on the
 * given side of it. Returns the tree unchanged when the leaf is absent.
 */
export function insertBeside(
  node: SplitNode,
  targetId: Uuid,
  piece: SplitNode,
  side: DropSide,
  splitId: string,
): SplitNode {
  if (node.kind === "leaf") {
    if (node.paneId !== targetId) return node;
    const before = side === "left" || side === "up";
    return {
      kind: "split",
      id: splitId,
      direction: side === "left" || side === "right" ? "row" : "column",
      ratio: 0.5,
      first: before ? piece : node,
      second: before ? node : piece,
    };
  }
  const first = insertBeside(node.first, targetId, piece, side, splitId);
  const second = insertBeside(node.second, targetId, piece, side, splitId);
  return first === node.first && second === node.second ? node : { ...node, first, second };
}

/** Put `piece` along one whole side of the window, next to everything already in it. */
export function wrapRoot(
  node: SplitNode,
  piece: SplitNode,
  side: DropSide,
  splitId: string,
): SplitNode {
  const before = side === "left" || side === "up";
  return {
    kind: "split",
    id: splitId,
    direction: side === "left" || side === "right" ? "row" : "column",
    ratio: 0.5,
    first: before ? piece : node,
    second: before ? node : piece,
  };
}

/** Which edge of a box a point is nearest to; `x` and `y` are 0–1 within it. */
export function nearestSide(x: number, y: number): DropSide {
  const d = { left: x, right: 1 - x, up: y, down: 1 - y };
  return (Object.keys(d) as DropSide[]).reduce((a, b) => (d[b] < d[a] ? b : a));
}

export function replaceLeaf(node: SplitNode, paneId: Uuid, newPaneId: Uuid): SplitNode {
  if (node.kind === "leaf") return node.paneId === paneId ? leaf(newPaneId) : node;
  const first = replaceLeaf(node.first, paneId, newPaneId);
  const second = replaceLeaf(node.second, paneId, newPaneId);
  return first === node.first && second === node.second ? node : { ...node, first, second };
}

export function setRatio(node: SplitNode, splitId: string, ratio: number): SplitNode {
  if (node.kind === "leaf") return node;
  if (node.id === splitId) return { ...node, ratio: clampRatio(ratio) };
  const first = setRatio(node.first, splitId, ratio);
  const second = setRatio(node.second, splitId, ratio);
  return first === node.first && second === node.second ? node : { ...node, first, second };
}

/** Reset every split in the tree to an even share. */
export function equalize(node: SplitNode): SplitNode {
  if (node.kind === "leaf") return node;
  return { ...node, ratio: 0.5, first: equalize(node.first), second: equalize(node.second) };
}

export interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

export type Side = "left" | "right" | "up" | "down";

/**
 * The pane geometrically next to `from` in `side`, judged by rectangles:
 * candidates must start past the edge of `from`, the one with the smallest
 * gap along the axis (then the least perpendicular offset) wins.
 */
export function neighbor(from: Rect, others: Map<Uuid, Rect>, side: Side): Uuid | null {
  const fromCx = from.left + from.width / 2;
  const fromCy = from.top + from.height / 2;
  let best: { id: Uuid; gap: number; off: number } | null = null;
  for (const [id, r] of others) {
    let gap: number;
    let off: number;
    switch (side) {
      case "left":
        gap = from.left - (r.left + r.width);
        off = Math.abs(r.top + r.height / 2 - fromCy);
        break;
      case "right":
        gap = r.left - (from.left + from.width);
        off = Math.abs(r.top + r.height / 2 - fromCy);
        break;
      case "up":
        gap = from.top - (r.top + r.height);
        off = Math.abs(r.left + r.width / 2 - fromCx);
        break;
      case "down":
        gap = r.top - (from.top + from.height);
        off = Math.abs(r.left + r.width / 2 - fromCx);
        break;
    }
    if (gap < -1) continue;
    if (!best || gap < best.gap - 1 || (Math.abs(gap - best.gap) <= 1 && off < best.off)) {
      best = { id, gap, off };
    }
  }
  return best?.id ?? null;
}
