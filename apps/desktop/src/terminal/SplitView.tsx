import { useRef } from "react";
import { Box } from "@mui/material";
import { PaneSlot } from "./PaneHost";
import { clampRatio, type SplitNode } from "./layout";
import { setSplitRatio } from "./store";
import type { Uuid } from "@/ipc/types";

const DIVIDER = 6;

interface Props {
  tabId: string;
  node: SplitNode;
  activePaneId: Uuid;
  showFrame: boolean;
}

/** Renders a split tree; every inner node is two children with a draggable divider. */
export function SplitView({ tabId, node, activePaneId, showFrame }: Props) {
  if (node.kind === "leaf") return <PaneSlot paneId={node.paneId} />;
  return (
    <SplitBranch tabId={tabId} node={node} activePaneId={activePaneId} showFrame={showFrame} />
  );
}

function SplitBranch({
  tabId,
  node,
  activePaneId,
  showFrame,
}: Props & { node: Extract<SplitNode, { kind: "split" }> }) {
  const ref = useRef<HTMLDivElement>(null);
  const horizontal = node.direction === "row";

  const onPointerDown = (ev: React.PointerEvent<HTMLDivElement>) => {
    const box = ref.current;
    if (!box || ev.button !== 0) return;
    ev.preventDefault();
    const handle = ev.currentTarget;
    handle.setPointerCapture(ev.pointerId);
    const rect = box.getBoundingClientRect();
    const start = horizontal ? rect.left : rect.top;
    const size = (horizontal ? rect.width : rect.height) - DIVIDER;
    const move = (e: PointerEvent) => {
      const pos = (horizontal ? e.clientX : e.clientY) - start - DIVIDER / 2;
      setSplitRatio(tabId, node.id, clampRatio(pos / Math.max(1, size)));
    };
    const up = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
      handle.removeEventListener("pointercancel", up);
      document.body.style.cursor = "";
    };
    document.body.style.cursor = horizontal ? "col-resize" : "row-resize";
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
    handle.addEventListener("pointercancel", up);
  };

  return (
    <Box
      ref={ref}
      sx={{
        flex: 1,
        minWidth: 0,
        minHeight: 0,
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: node.direction,
      }}
    >
      <Box
        sx={{
          flex: `${node.ratio} 1 0px`,
          minWidth: 0,
          minHeight: 0,
          display: "flex",
        }}
      >
        <SplitView
          tabId={tabId}
          node={node.first}
          activePaneId={activePaneId}
          showFrame={showFrame}
        />
      </Box>
      <Box
        onPointerDown={onPointerDown}
        onDoubleClick={() => setSplitRatio(tabId, node.id, 0.5)}
        sx={{
          flex: `0 0 ${DIVIDER}px`,
          cursor: horizontal ? "col-resize" : "row-resize",
          touchAction: "none",
          borderRadius: 1,
          transition: "background-color 120ms",
          "&:hover, &:active": { bgcolor: "divider" },
        }}
      />
      <Box
        sx={{
          flex: `${1 - node.ratio} 1 0px`,
          minWidth: 0,
          minHeight: 0,
          display: "flex",
        }}
      >
        <SplitView
          tabId={tabId}
          node={node.second}
          activePaneId={activePaneId}
          showFrame={showFrame}
        />
      </Box>
    </Box>
  );
}
