package com.termoso.android.ui.terminal

import android.net.Uri
import android.view.HapticFeedbackConstants
import android.view.inputmethod.InputMethodManager
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.getSystemService
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termoso.android.data.TerminalSession
import com.termoso.core.CursorStyle
import com.termoso.core.KeyMods
import com.termoso.core.SpecialKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.math.abs
import androidx.compose.animation.core.AnimationState
import androidx.compose.animation.core.animateDecay
import androidx.compose.animation.core.exponentialDecay
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.input.pointer.util.VelocityTracker
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Position of a cell under a touch. */
data class CellPoint(val row: Int, val col: Int)

/**
 * Terminal surface: a Compose [Canvas] fed by packed frames from Rust, plus a
 * hidden [TerminalInputView] that owns the soft keyboard. The Rust grid is
 * resized to whatever number of whole cells fits the measured size, so the
 * remote always sees the true geometry.
 */
@Composable
fun TerminalView(
    session: TerminalSession,
    controller: TerminalController,
    fontSizeSp: Int,
    fontFamily: String,
    cursorBlink: Boolean,
    cursorStyle: String,
    modifier: Modifier = Modifier,
    onFrame: (CellGrid) -> Unit = {},
    onTap: () -> Unit = {},
    /** Text copied from a selection; the caller puts it on the clipboard. */
    onCopy: (String) -> Unit = {},
    onPaste: () -> Unit = {},
    /** Extra entries of the selection bar's overflow menu. */
    selectionMenu: @Composable (cell: CellPoint, dismiss: () -> Unit) -> Unit = { _, _ -> },
    onZoom: (Int) -> Unit = {},
    gestures: TerminalGestures = TerminalGestures(),
    /** Two-finger horizontal swipe; `true` = towards the next session. */
    onSwipeSession: (Boolean) -> Unit = {},
    /** Image/file inserted by the keyboard or pasted; the caller uploads it. */
    onContent: (Uri) -> Unit = {},
    /** Tap on an OSC 8 hyperlink or a printed URL; the caller offers to open it. */
    onLink: (String) -> Unit = {},
    /** Search hits on the visible rows, drawn like a selection in the tertiary colour. */
    highlights: List<TermSelection> = emptyList(),
    /** Long-press arrow gesture state for an on-screen hint; `null` when it ends. */
    onArrowGesture: (ArrowHint?) -> Unit = {},
    /** Small badge drawn just above the cursor cell (multiplayer: who is typing). */
    cursorBadge: (@Composable () -> Unit)? = null,
) {
    val density = LocalDensity.current
    val context = LocalContext.current
    val metrics = remember(fontSizeSp, fontFamily, density) {
        CellMetrics(with(density) { fontSizeSp.sp.toPx() }, terminalTypefaces(context, fontFamily))
    }
    val renderer = remember { TerminalRenderer() }

    var grid by remember(session) { mutableStateOf<CellGrid?>(null) }
    var size by remember { mutableStateOf(IntSize.Zero) }
    var focused by remember { mutableStateOf(false) }
    var blinkOn by remember { mutableStateOf(true) }

    var selection by remember(session) { mutableStateOf<TermSelection?>(null) }
    var dragSelecting by remember { mutableStateOf(false) }
    var dragPos by remember { mutableStateOf<Offset?>(null) }

    /** Scroll one line when [p] is within a cell of the top/bottom edge; true when it did. */
    fun autoScrollAt(p: Offset, m: CellMetrics, viewport: IntSize): Boolean {
        val alt = grid?.frame?.altScreen == true
        if (alt || viewport.height == 0) return false
        val lines = when {
            p.y < m.height -> 1
            p.y > viewport.height - m.height -> -1
            else -> return false
        }
        controller.scrollBy(lines, altScreen = false)
        return true
    }
    // Momentum after a vertical swipe through scrollback.
    val flingScope = rememberCoroutineScope()
    var flingJob by remember { mutableStateOf<Job?>(null) }
    // Long-press arrow mode: set by the tap detector, consumed by the drag loop below.
    var arrowGesture by remember { mutableStateOf<ArrowGesture?>(null) }
    var arrowOrigin by remember { mutableStateOf(Offset.Zero) }
    val view = LocalView.current

    val tick by session.frameTick.collectAsStateWithLifecycle()

    LaunchedEffect(session, tick) {
        val frame = withContext(Dispatchers.Default) { session.rust.frame() }
        val next = CellGrid(frame)
        val prev = grid
        if (prev != null && (prev.cols != next.cols || prev.rows != next.rows || prev.frame.altScreen != next.frame.altScreen)) {
            selection = null
        } else {
            // Keep the selection on the same text while the viewport scrolls through history.
            val delta = next.frame.displayOffset.toInt() - (prev?.frame?.displayOffset?.toInt() ?: 0)
            if (delta != 0) selection = selection?.shiftedRows(delta)
        }
        grid = next
        blinkOn = true
        onFrame(next)
    }

    LaunchedEffect(size, metrics) {
        if (size == IntSize.Zero) return@LaunchedEffect
        val cols = (size.width / metrics.width).toInt().coerceIn(2, 500)
        val rows = (size.height / metrics.height).toInt().coerceIn(1, 300)
        val current = grid
        if (current == null || current.cols != cols || current.rows != rows) {
            withContext(Dispatchers.Default) { session.rust.resize(cols.toUShort(), rows.toUShort()) }
        }
    }

    LaunchedEffect(cursorBlink, focused) {
        if (!cursorBlink || !focused) {
            blinkOn = true
            return@LaunchedEffect
        }
        var last = 0L
        while (true) {
            withFrameNanos { now ->
                if (now - last > 530_000_000L) {
                    blinkOn = !blinkOn
                    last = now
                }
            }
        }
    }

    val override = when (cursorStyle) {
        "underline" -> CursorStyle.UNDERLINE
        "beam" -> CursorStyle.BEAM
        else -> null
    }
    val background = grid?.frame?.background?.toInt()?.let { Color(it or (0xFF shl 24)) } ?: Color(0xFF0D1117)

    val currentTap by rememberUpdatedState(onTap)
    val currentZoom by rememberUpdatedState(onZoom)
    val currentSwipe by rememberUpdatedState(onSwipeSession)
    val currentGestures by rememberUpdatedState(gestures)
    val currentOnArrowGesture by rememberUpdatedState(onArrowGesture)
    val currentMetrics by rememberUpdatedState(metrics)
    val currentGrid by rememberUpdatedState(grid)
    val slop = with(density) { 12.dp.toPx() }
    val selectionColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.35f)
    val highlightColor = MaterialTheme.colorScheme.tertiary.copy(alpha = 0.45f)

    fun selectWordAt(offset: Offset) {
        val g = currentGrid ?: return
        selection = g.wordAt(currentMetrics.cellAt(offset, g))
    }

    Box(
        modifier
            .background(background)
            // Breathing room like Termius: the grid never touches the screen edge.
            .padding(start = 6.dp, end = 6.dp, top = 4.dp)
            .onSizeChanged { size = it }
            .pointerInput(session) {
                detectTapGestures(
                    onTap = { offset ->
                        if (selection != null) {
                            selection = null
                            return@detectTapGestures
                        }
                        currentGrid?.let { g ->
                            val cell = currentMetrics.cellAt(offset, g)
                            (g.linkAt(cell.row, cell.col) ?: g.urlAt(cell.row, cell.col))?.let { uri ->
                                onLink(uri)
                                return@detectTapGestures
                            }
                        }
                        controller.inputView?.let { v ->
                            v.requestFocus()
                            context.getSystemService<InputMethodManager>()?.showSoftInput(v, 0)
                        }
                        currentTap()
                    },
                    onDoubleTap = { offset ->
                        if (currentGestures.doubleTapTab) controller.sendKey(SpecialKey.TAB) else selectWordAt(offset)
                    },
                    onLongPress = { offset ->
                        if (currentGestures.longPressArrows && selection == null) {
                            val m = currentMetrics
                            arrowGesture = ArrowGesture(m.width, m.height, currentGestures.cursorSpeed)
                            arrowOrigin = offset
                            currentOnArrowGesture(ArrowHint(null, 1))
                            view.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
                        } else {
                            selectWordAt(offset)
                            dragSelecting = selection != null
                        }
                    },
                )
            }
            .pointerInput(session) {
                awaitEachGesture {
                    awaitFirstDown(requireUnconsumed = false)
                    flingJob?.cancel()
                    val velocity = VelocityTracker()
                    val g = currentGestures
                    var scrollAcc = 0f
                    var arrowAcc = 0f
                    var zoomAcc = 1f
                    var panAcc = Offset.Zero
                    var multi = false
                    var swiped = false
                    var axis = Axis.NONE
                    while (true) {
                        // Short timeout so a finger held still in arrow mode keeps repeating.
                        val event = withTimeoutOrNull(ArrowGesture.REPEAT_MS) { awaitPointerEvent() }
                        if (event == null) {
                            arrowGesture?.let { a ->
                                a.repeatTick()?.let { controller.arrowKeys(it) }
                                currentOnArrowGesture(ArrowHint(a.direction, a.gear))
                            }
                            if (dragSelecting) {
                                dragPos?.let { p ->
                                    if (autoScrollAt(p, currentMetrics, size)) {
                                        val sel = selection
                                        val grid = currentGrid
                                        if (sel != null && grid != null) selection = TermSelection(sel.anchor, currentMetrics.cellAt(p, grid))
                                    }
                                }
                            }
                            continue
                        }
                        val pressed = event.changes.count { it.pressed }
                        val arrows = arrowGesture
                        if (arrows != null) {
                            val pan = event.calculatePan()
                            arrows.move(pan.x, pan.y)?.let { controller.arrowKeys(it) }
                            currentOnArrowGesture(ArrowHint(arrows.direction, arrows.gear))
                            event.changes.forEach { it.consume() }
                        } else if (!dragSelecting && event.changes.all { it.isConsumed }) {
                            // A selection handle or the action bar owns this gesture.
                        } else if (dragSelecting) {
                            // Long press keeps selecting while the finger moves; at the top or
                            // bottom edge the view scrolls so the selection can run on into
                            // scrollback (the frame tick shifts the selection with the text).
                            val p = event.changes.firstOrNull { it.pressed }?.position
                            val sel = selection
                            val grid = currentGrid
                            if (p != null && sel != null && grid != null) {
                                dragPos = p
                                selection = TermSelection(sel.anchor, currentMetrics.cellAt(p, grid))
                                autoScrollAt(p, currentMetrics, size)
                            }
                            event.changes.forEach { it.consume() }
                        } else if (pressed >= 2) {
                            multi = true
                            panAcc += event.calculatePan()
                            if (g.pinchZoom) {
                                zoomAcc *= event.calculateZoom()
                                if (zoomAcc > 1.12f) {
                                    currentZoom(1)
                                    zoomAcc = 1f
                                } else if (zoomAcc < 0.89f) {
                                    currentZoom(-1)
                                    zoomAcc = 1f
                                }
                            }
                            // A steady sideways drag with two fingers (not a pinch) changes session.
                            if (g.swipeSessions && !swiped && zoomAcc in 0.95f..1.05f &&
                                abs(panAcc.x) > slop * 5 && abs(panAcc.x) > abs(panAcc.y) * 2
                            ) {
                                swiped = true
                                currentSwipe(panAcc.x < 0)
                            }
                            event.changes.forEach { it.consume() }
                        } else if (!multi) {
                            event.changes.firstOrNull { it.pressed }?.let { velocity.addPosition(it.uptimeMillis, it.position) }
                            val pan = event.calculatePan()
                            scrollAcc += pan.y
                            arrowAcc += pan.x
                            if (axis == Axis.NONE) {
                                axis = when {
                                    abs(scrollAcc) > slop -> Axis.VERTICAL
                                    g.swipeArrows && abs(arrowAcc) > slop -> Axis.HORIZONTAL
                                    else -> Axis.NONE
                                }
                                if (axis == Axis.HORIZONTAL) arrowAcc = 0f
                            }
                            if (axis == Axis.VERTICAL) {
                                val cellH = currentMetrics.height
                                val lines = (scrollAcc / cellH).toInt()
                                if (lines != 0) {
                                    scrollAcc -= lines * cellH
                                    controller.scrollBy(lines, currentGrid?.frame?.altScreen == true)
                                    event.changes.forEach { it.consume() }
                                }
                            } else if (axis == Axis.HORIZONTAL) {
                                val cellW = currentMetrics.width
                                val cells = (arrowAcc / cellW).toInt()
                                if (cells != 0) {
                                    arrowAcc -= cells * cellW
                                    controller.arrows(cells)
                                    event.changes.forEach { it.consume() }
                                }
                            }
                        }
                        if (event.changes.none { it.pressed }) break
                    }
                    // A plain vertical swipe keeps going with momentum, one line per cell height.
                    if (axis == Axis.VERTICAL && !multi && !dragSelecting && arrowGesture == null &&
                        currentGrid?.frame?.altScreen != true
                    ) {
                        val v = velocity.calculateVelocity().y
                        val cellH = currentMetrics.height
                        if (abs(v) > FLING_MIN_VELOCITY && cellH > 0f) {
                            flingJob = flingScope.launch {
                                var last = 0f
                                var acc = 0f
                                AnimationState(initialValue = 0f, initialVelocity = v)
                                    .animateDecay(exponentialDecay(frictionMultiplier = 1.4f)) {
                                        acc += value - last
                                        last = value
                                        val lines = (acc / cellH).toInt()
                                        if (lines != 0) {
                                            acc -= lines * cellH
                                            controller.scrollBy(lines, altScreen = false)
                                        }
                                    }
                            }
                        }
                    }
                    // A long-press released without dragging still selects the word under it.
                    arrowGesture?.let {
                        if (!it.moved) selectWordAt(arrowOrigin)
                        currentOnArrowGesture(null)
                    }
                    arrowGesture = null
                    dragSelecting = false
                    dragPos = null
                }
            },
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val g = grid ?: return@Canvas
            // A grid pinned by somebody else (multiplayer: the host's or the
            // controller's size) is scaled down to fit instead of being clipped.
            val fit = minOf(
                1f,
                this.size.width / (g.cols * metrics.width),
                this.size.height / (g.rows * metrics.height),
            )
            withTransform({ if (fit < 0.999f) scale(fit, fit, Offset.Zero) }) {
                renderer.draw(
                    canvas = drawContext.canvas.nativeCanvas,
                    grid = g,
                    metrics = metrics,
                    cursorVisible = blinkOn,
                    cursorOverride = override,
                    focused = focused,
                )
                for (h in highlights) drawSelection(h, g, metrics, highlightColor)
                selection?.let { drawSelection(it, g, metrics, selectionColor) }
            }
        }
        val sel = selection
        val g = grid
        if (cursorBadge != null && g != null) {
            val badge = with(density) { 22.dp.roundToPx() }
            val col = g.frame.cursorCol.toInt()
            val row = g.frame.cursorRow.toInt()
            Box(
                Modifier.offset {
                    IntOffset(
                        (col * metrics.width).toInt().coerceAtMost((size.width - badge).coerceAtLeast(0)),
                        ((row * metrics.height).toInt() - badge).coerceAtLeast(0),
                    )
                },
            ) { cursorBadge() }
        }
        if (sel != null && g != null) {
            SelectionOverlay(
                selection = sel,
                grid = g,
                metrics = metrics,
                viewport = size,
                onChange = { selection = it },
                onDragAt = { p -> autoScrollAt(p, metrics, size) },
                onCopy = {
                    onCopy(g.textAcross(sel) { a, b, c, d -> session.rust.textRange(a, b, c, d) })
                    selection = null
                },
                onPaste = {
                    selection = null
                    onPaste()
                },
                onSelectAll = { selection = g.all() },
                more = { dismiss -> selectionMenu(sel.start) { dismiss(); selection = null } },
            )
        }
        AndroidView(
            factory = { ctx ->
                TerminalInputView(ctx).also { v ->
                    v.setOnFocusChangeListener { _, has -> focused = has }
                    controller.inputView = v
                }
            },
            update = { v ->
                v.onText = { text -> controller.sendText(text) }
                v.onTextWithMods = { text, mods -> controller.sendText(text, mods) }
                v.onKey = { key, mods -> controller.sendKey(key, mods) }
                v.onContent = onContent
            },
            modifier = Modifier.size(1.dp),
        )
    }
}

/** Which touch gestures the terminal surface reacts to, from settings. */
data class TerminalGestures(
    val pinchZoom: Boolean = true,
    val swipeArrows: Boolean = true,
    val swipeSessions: Boolean = true,
    /** Long-press, then drag in any direction for ← ↑ ↓ →; hold to repeat. */
    val longPressArrows: Boolean = true,
    /** Double-tap sends Tab (otherwise it selects the word under the finger). */
    val doubleTapTab: Boolean = true,
    /** Travel multiplier for arrow gestures, see [ArrowGesture.speedOf]. */
    val cursorSpeed: Float = 1f,
)

private enum class Axis { NONE, VERTICAL, HORIZONTAL }

/** Scroll-position helper for the scroll-to-bottom affordance. */
fun CellGrid.scrolledLines(): Int = frame.displayOffset.toInt()

/**
 * Input funnel for one session: applies the sticky modifiers from the key
 * panel and forwards everything to Rust, which does the actual key encoding.
 */
class TerminalController(private val session: TerminalSession) {
    var inputView: TerminalInputView? = null

    var ctrl by mutableStateOf(false)
    var alt by mutableStateOf(false)
    var shift by mutableStateOf(false)

    private fun takeMods(extra: KeyMods): KeyMods {
        val m = KeyMods(ctrl = ctrl || extra.ctrl, alt = alt || extra.alt, shift = shift || extra.shift)
        ctrl = false
        alt = false
        shift = false
        return m
    }

    fun sendText(text: String, extra: KeyMods = NONE) {
        val mods = takeMods(extra)
        session.rust.sendText(text, KeyMods(ctrl = mods.ctrl, alt = mods.alt, shift = false))
        session.rust.scrollToBottom()
    }

    fun sendKey(key: SpecialKey, extra: KeyMods = NONE) {
        session.rust.sendKey(key, takeMods(extra))
        session.rust.scrollToBottom()
    }

    /** Text that bypasses sticky modifiers (hidden input, snippets). */
    fun sendRaw(text: String, enter: Boolean) {
        session.rust.sendText(text, NONE)
        if (enter) session.rust.sendKey(SpecialKey.ENTER, NONE)
        session.rust.scrollToBottom()
    }

    fun paste(text: String) {
        session.rust.paste(text)
        session.rust.scrollToBottom()
    }

    /** Paste [command] (bracketed when the shell asks for it) and press Enter. */
    fun runCommand(command: String) {
        session.rust.runCommand(command)
        session.rust.scrollToBottom()
    }

    /** Positive = towards history. On the alternate screen it becomes arrow keys. */
    fun scrollBy(lines: Int, altScreen: Boolean) {
        if (altScreen) {
            val key = if (lines > 0) SpecialKey.UP else SpecialKey.DOWN
            repeat(abs(lines)) { session.rust.sendKey(key, NONE) }
        } else {
            session.rust.scroll(lines)
        }
    }

    fun scrollToBottom() = session.rust.scrollToBottom()

    fun altScreen(): Boolean = session.rust.frame().altScreen

    /** One step of a long-press arrow gesture. */
    fun arrowKeys(step: ArrowStep) {
        repeat(step.count.coerceAtMost(50)) { session.rust.sendKey(step.key, NONE) }
    }

    /** Horizontal swipe: positive = →, negative = ←, one key per cell travelled. */
    fun arrows(cells: Int) {
        val key = if (cells > 0) SpecialKey.RIGHT else SpecialKey.LEFT
        repeat(abs(cells).coerceAtMost(200)) { session.rust.sendKey(key, NONE) }
    }

    fun visibleText(): String = session.rust.visibleText().joinToString("\n").trimEnd()

    private companion object {
        val NONE = KeyMods(ctrl = false, alt = false, shift = false)
    }
}

/** px/s below which a release is a stop, not a fling. */
private const val FLING_MIN_VELOCITY = 250f
