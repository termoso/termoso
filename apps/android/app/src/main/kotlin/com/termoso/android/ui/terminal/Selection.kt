package com.termoso.android.ui.terminal

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import com.termoso.android.R
import kotlin.math.roundToInt

/**
 * A run of screen cells from [anchor] to [focus] (inclusive, either order),
 * in viewport rows. Rows may fall outside the viewport after scrolling; the
 * grid clamps them when it draws or extracts text.
 */
data class TermSelection(val anchor: CellPoint, val focus: CellPoint) {
    val start: CellPoint get() = if (anchor <= focus) anchor else focus
    val end: CellPoint get() = if (anchor <= focus) focus else anchor

    fun shiftedRows(delta: Int) = TermSelection(
        CellPoint(anchor.row + delta, anchor.col),
        CellPoint(focus.row + delta, focus.col),
    )
}

private operator fun CellPoint.compareTo(o: CellPoint): Int =
    if (row != o.row) row.compareTo(o.row) else col.compareTo(o.col)

private const val WORD_SEPARATORS = " \t\"'`()[]{}<>,;|&"

private fun CellGrid.isSeparator(row: Int, col: Int): Boolean {
    if (isSpacer(row, col)) return false
    val cp = if (isHidden(row, col)) 0 else codepoint(row, col)
    return cp == 0 || (cp < 0x80 && WORD_SEPARATORS.indexOf(cp.toChar()) >= 0)
}

/** The whitespace/punctuation-delimited word under [at], or the cell itself. */
fun CellGrid.wordAt(at: CellPoint): TermSelection? {
    if (at.row !in 0 until rows || at.col !in 0 until cols) return null
    if (isSeparator(at.row, at.col)) return TermSelection(at, at)
    var a = at.col
    while (a > 0 && !isSeparator(at.row, a - 1)) a--
    var b = at.col
    while (b + 1 < cols && !isSeparator(at.row, b + 1)) b++
    return TermSelection(CellPoint(at.row, a), CellPoint(at.row, b))
}

fun CellGrid.all(): TermSelection = TermSelection(CellPoint(0, 0), CellPoint(rows - 1, cols - 1))

/**
 * Selected text including rows scrolled out of the viewport: the selection is
 * mapped to scrollback-absolute lines (0 = oldest history row) and read back
 * through [textRange] (the emulator). Falls back to [textIn] on the alternate
 * screen, which has no history.
 */
fun CellGrid.textAcross(sel: TermSelection, textRange: (Long, UInt, Long, UInt) -> String): String {
    if (frame.altScreen) return textIn(sel)
    val top = frame.history.toLong() - frame.displayOffset.toLong()
    val (s, e) = sel.start to sel.end
    return textRange(top + s.row, s.col.coerceAtLeast(0).toUInt(), top + e.row, e.col.coerceAtLeast(0).toUInt())
}

/** Selected text; rows outside the viewport are skipped, trailing blanks trimmed per line. */
fun CellGrid.textIn(sel: TermSelection): String {
    val (s, e) = sel.start to sel.end
    val out = StringBuilder()
    for (row in maxOf(0, s.row)..minOf(rows - 1, e.row)) {
        val from = if (row == s.row) s.col.coerceIn(0, cols - 1) else 0
        val to = if (row == e.row) e.col.coerceIn(0, cols - 1) else cols - 1
        val line = StringBuilder()
        for (col in from..to) {
            if (isSpacer(row, col)) continue
            val cp = if (isHidden(row, col)) 0 else codepoint(row, col)
            if (cp == 0) line.append(' ') else line.appendCodePoint(cp)
        }
        if (out.isNotEmpty()) out.append('\n')
        out.append(line.toString().trimEnd())
    }
    return out.toString()
}

/** Cell under a pixel, clamped to the grid. */
internal fun CellMetrics.cellAt(p: Offset, grid: CellGrid) = CellPoint(
    row = (p.y / height).toInt().coerceIn(0, grid.rows - 1),
    col = (p.x / width).toInt().coerceIn(0, grid.cols - 1),
)

internal fun DrawScope.drawSelection(sel: TermSelection, grid: CellGrid, m: CellMetrics, color: Color) {
    val (s, e) = sel.start to sel.end
    for (row in maxOf(0, s.row)..minOf(grid.rows - 1, e.row)) {
        val from = if (row == s.row) s.col.coerceIn(0, grid.cols - 1) else 0
        val to = if (row == e.row) e.col.coerceIn(0, grid.cols - 1) else grid.cols - 1
        drawRect(color, Offset(from * m.width, row * m.height), Size((to - from + 1) * m.width, m.height))
    }
}

/** Drag handles at both ends of the selection plus the floating action bar. */
@Composable
internal fun SelectionOverlay(
    selection: TermSelection,
    grid: CellGrid,
    metrics: CellMetrics,
    viewport: IntSize,
    onChange: (TermSelection) -> Unit,
    onDragAt: (Offset) -> Unit,
    onCopy: () -> Unit,
    onPaste: () -> Unit,
    onSelectAll: () -> Unit,
    more: @Composable (dismiss: () -> Unit) -> Unit,
) {
    val density = LocalDensity.current
    val handle = with(density) { 24.dp.roundToPx() }
    val gap = with(density) { 8.dp.roundToPx() }
    val color = MaterialTheme.colorScheme.primary
    val (s, e) = selection.start to selection.end
    val cw = metrics.width
    val ch = metrics.height

    fun px(c: CellPoint, right: Boolean) =
        Offset((c.col + if (right) 1 else 0) * cw, (c.row + 1).coerceIn(0, grid.rows) * ch)

    SelectionHandle(
        at = px(s, right = false),
        size = handle,
        viewport = viewport,
        color = color,
        left = true,
        visible = s.row in 0 until grid.rows,
        onDrag = { p ->
            onDragAt(p)
            onChange(TermSelection(anchor = e, focus = metrics.cellAt(p - Offset(0f, ch / 2), grid)))
        },
    )
    SelectionHandle(
        at = px(e, right = true),
        size = handle,
        viewport = viewport,
        color = color,
        left = false,
        visible = e.row in 0 until grid.rows,
        onDrag = { p ->
            onDragAt(p)
            onChange(TermSelection(anchor = s, focus = metrics.cellAt(p - Offset(0f, ch / 2), grid)))
        },
    )

    var bar by remember { mutableStateOf(IntSize.Zero) }
    var moreOpen by remember { mutableStateOf(false) }
    val top = (s.row.coerceIn(0, grid.rows - 1) * ch).roundToInt()
    val bottom = ((e.row.coerceIn(0, grid.rows - 1) + 1) * ch).roundToInt() + handle
    val y = if (top - bar.height - gap >= 0) top - bar.height - gap else minOf(bottom + gap, viewport.height - bar.height)
    val mid = if (s.row == e.row) ((s.col + e.col + 1) * cw / 2).roundToInt() else viewport.width / 2
    val x = (mid - bar.width / 2).coerceIn(0, maxOf(0, viewport.width - bar.width))
    Box(Modifier.offset { IntOffset(x, y) }.onSizeChanged { bar = it }) {
        Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 6.dp, shadowElevation = 4.dp) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 4.dp)) {
                TextButton(onClick = onCopy) { Text(stringResource(R.string.copy)) }
                TextButton(onClick = onPaste) { Text(stringResource(R.string.paste_2)) }
                TextButton(onClick = onSelectAll) { Text(stringResource(R.string.select_all)) }
                Box {
                    IconButton(onClick = { moreOpen = true }) {
                        Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more))
                    }
                    if (moreOpen) more { moreOpen = false }
                }
            }
        }
    }
}

@Composable
private fun SelectionHandle(
    at: Offset,
    size: Int,
    viewport: IntSize,
    color: Color,
    left: Boolean,
    visible: Boolean,
    onDrag: (Offset) -> Unit,
) {
    if (!visible) return
    val x = (if (left) at.x - size else at.x).coerceIn(0f, maxOf(0, viewport.width - size).toFloat())
    val y = at.y.coerceIn(0f, maxOf(0, viewport.height - size).toFloat())
    val anchor by rememberUpdatedState(at)
    // The gesture outlives recompositions; always call the latest callback so the
    // fixed end of the selection follows the text while the view auto-scrolls.
    val currentOnDrag by rememberUpdatedState(onDrag)
    var finger by remember { mutableStateOf(Offset.Zero) }
    Canvas(
        Modifier
            .offset { IntOffset(x.roundToInt(), y.roundToInt()) }
            .size(with(LocalDensity.current) { size.toDp() })
            .pointerInput(left) {
                detectDragGestures(
                    onDragStart = { finger = anchor },
                    onDrag = { change, delta ->
                        change.consume()
                        finger += delta
                        currentOnDrag(finger)
                    },
                )
            },
    ) {
        val r = this.size.width / 2
        drawCircle(color, r, Offset(r, r))
        drawRect(color, Offset(if (left) r else 0f, 0f), Size(r, r))
    }
}
