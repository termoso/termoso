import { memo, useEffect, useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { Box } from "@mui/material";
import type { Uuid } from "@/ipc/types";
import { TerminalPane } from "./TerminalPane";
import { useTerminal } from "./store";

// Every session's pane is rendered exactly once, into a DOM node of its own that
// outlives layout changes. The layout (`SplitView`, tabs) only provides empty
// slots and moves the node into the right one. Docking, detaching or reshaping
// a split therefore re-parents an existing element instead of tearing down and
// rebuilding the whole terminal UI.

const nodes = new Map<Uuid, HTMLDivElement>();

function nodeFor(paneId: Uuid): HTMLDivElement {
  let node = nodes.get(paneId);
  if (!node) {
    node = document.createElement("div");
    node.dataset.paneNode = paneId;
    Object.assign(node.style, {
      display: "flex",
      flex: "1",
      minWidth: "0",
      minHeight: "0",
      width: "100%",
      height: "100%",
    });
    nodes.set(paneId, node);
  }
  return node;
}

const PanePortal = memo(function PanePortal({ paneId }: { paneId: Uuid }) {
  return createPortal(<TerminalPane paneId={paneId} />, nodeFor(paneId));
});

/** Renders every pane's terminal; mount once, outside the tab layouts. */
export function PaneLayer() {
  const panes = useTerminal((s) => s.panes);
  const ids = Object.keys(panes);
  useEffect(() => {
    for (const [id, node] of nodes) {
      if (!(id in panes)) {
        node.remove();
        nodes.delete(id);
      }
    }
  }, [panes]);
  return (
    <>
      {ids.map((id) => (
        <PanePortal key={id} paneId={id} />
      ))}
    </>
  );
}

/** A place in the layout where pane `paneId` is shown. */
export function PaneSlot({ paneId }: { paneId: Uuid }) {
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const slot = ref.current;
    if (!slot) return;
    const node = nodeFor(paneId);
    slot.appendChild(node);
    return () => {
      // Another slot may already have taken the node during the same commit.
      if (node.parentElement === slot) slot.removeChild(node);
    };
  }, [paneId]);
  return (
    <Box
      ref={ref}
      sx={{ flex: 1, minWidth: 0, minHeight: 0, width: "100%", height: "100%", display: "flex" }}
    />
  );
}
