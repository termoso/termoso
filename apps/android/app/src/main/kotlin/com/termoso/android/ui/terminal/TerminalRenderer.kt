package com.termoso.android.ui.terminal

import android.graphics.Canvas
import android.graphics.Paint
import com.termoso.core.CursorStyle
import com.termoso.core.GridFrame
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.ceil

private const val CELL_BYTES = 12

private const val FLAG_BOLD = 1
private const val FLAG_ITALIC = 1 shl 1
private const val FLAG_UNDERLINE = 1 shl 2
private const val FLAG_STRIKEOUT = 1 shl 3
private const val FLAG_WIDE = 1 shl 5
private const val FLAG_WIDE_SPACER = 1 shl 6
private const val FLAG_HIDDEN = 1 shl 7
private val URL_RE = Regex("(?:https?|ftp)://[^\\s<>\"'`\\u00A0]+")

/** Read-only view over the packed cell buffer of a [GridFrame]. */
class CellGrid(val frame: GridFrame) {
    private val buf: ByteBuffer = ByteBuffer.wrap(frame.cells).order(ByteOrder.LITTLE_ENDIAN)
    val cols: Int = frame.cols.toInt()
    val rows: Int = frame.rows.toInt()

    fun codepoint(row: Int, col: Int): Int = buf.getInt((row * cols + col) * CELL_BYTES)

    /** `0xRRGGBB`. */
    fun fg(row: Int, col: Int): Int = buf.getInt((row * cols + col) * CELL_BYTES + 4) and 0xFFFFFF

    fun bg(row: Int, col: Int): Int = buf.getInt((row * cols + col) * CELL_BYTES + 8) and 0xFFFFFF

    /** OSC 8 hyperlink target of the cell, if any (index rides in the top byte of `bg`). */
    fun linkAt(row: Int, col: Int): String? {
        if (row !in 0 until rows || col !in 0 until cols) return null
        val id = (buf.getInt((row * cols + col) * CELL_BYTES + 8) ushr 24) and 0xFF
        return if (id == 0) null else frame.links.getOrNull(id - 1)
    }

    fun hasLink(row: Int, col: Int): Boolean = (buf.getInt((row * cols + col) * CELL_BYTES + 8) ushr 24) and 0xFF != 0

    fun flags(row: Int, col: Int): Int = (buf.getInt((row * cols + col) * CELL_BYTES + 4) ushr 24) and 0xFF

    /** Second half of a double-width character. */
    fun isSpacer(row: Int, col: Int): Boolean = flags(row, col) and FLAG_WIDE_SPACER != 0

    /** Concealed (SGR 8) text; never leaves the grid as plain text. */
    fun isHidden(row: Int, col: Int): Boolean = flags(row, col) and FLAG_HIDDEN != 0

    /**
     * A plain-text URL (`http(s)://`, `ftp://`) printed across [col] of [row],
     * for taps on links that are not OSC 8 hyperlinks. Single row only.
     */
    fun urlAt(row: Int, col: Int): String? {
        if (row !in 0 until rows || col !in 0 until cols) return null
        val sb = StringBuilder(cols)
        val colOf = IntArray(cols + 1)
        var n = 0
        for (c in 0 until cols) {
            val cp = codepoint(row, c)
            if (cp == 0 || isSpacer(row, c)) continue
            colOf[n++] = c
            sb.appendCodePoint(cp)
        }
        val text = sb.toString()
        for (m in URL_RE.findAll(text)) {
            var end = m.range.last + 1
            while (end > m.range.first && text[end - 1] in ".,;:!?)]}'\"") end--
            if (end <= m.range.first) continue
            val startCol = colOf[m.range.first]
            val endCol = colOf[end - 1]
            if (col in startCol..endCol) return text.substring(m.range.first, end)
        }
        return null
    }

    /** Text of one row with trailing blanks trimmed. */
    fun lineText(row: Int): String {
        val sb = StringBuilder(cols)
        for (c in 0 until cols) {
            val cp = codepoint(row, c)
            if (cp == 0) continue
            sb.appendCodePoint(cp)
        }
        return sb.toString().trimEnd()
    }
}

/**
 * Cell metrics for a monospace font at [textSizePx]; every glyph is placed on
 * this grid regardless of its natural advance.
 */
class CellMetrics(
    textSizePx: Float,
    val typefaces: TerminalTypefaces = TerminalTypefaces.system,
    lineSpacing: Float = 1.0f,
) {
    val paint = Paint(Paint.ANTI_ALIAS_FLAG or Paint.SUBPIXEL_TEXT_FLAG).apply {
        typeface = typefaces[0]
        textSize = textSizePx
    }
    val width: Float = paint.measureText("M")
    private val fontMetrics = paint.fontMetrics
    val height: Float = ceil((fontMetrics.descent - fontMetrics.ascent) * lineSpacing)
    /** Baseline offset from the top of a cell. */
    val baseline: Float = -fontMetrics.ascent + (height - (fontMetrics.descent - fontMetrics.ascent)) / 2f
    val underlineY: Float = baseline + fontMetrics.descent * 0.6f
    val strikeY: Float = baseline + fontMetrics.ascent * 0.35f
}

/**
 * Draws a [CellGrid] with plain `android.graphics` calls. Backgrounds are drawn
 * as runs of equal colour, text as runs of equal (colour, style) so a line of
 * prose is one `drawText`, not eighty.
 */
class TerminalRenderer {
    private val fill = Paint()
    private val line = Paint().apply { style = Paint.Style.STROKE }
    private val text = Paint(Paint.ANTI_ALIAS_FLAG or Paint.SUBPIXEL_TEXT_FLAG)
    private val sb = StringBuilder(256)

    fun draw(
        canvas: Canvas,
        grid: CellGrid,
        metrics: CellMetrics,
        cursorVisible: Boolean,
        cursorOverride: CursorStyle?,
        focused: Boolean,
    ) {
        val cw = metrics.width
        val ch = metrics.height
        val defaultBg = grid.frame.background.toInt() and 0xFFFFFF
        text.textSize = metrics.paint.textSize
        line.strokeWidth = maxOf(1f, metrics.paint.textSize / 14f)

        for (row in 0 until grid.rows) {
            val top = row * ch
            var runStart = 0
            var runBg = -1
            for (col in 0..grid.cols) {
                val bg = if (col < grid.cols) grid.bg(row, col) else -2
                if (bg != runBg) {
                    if (runBg >= 0 && runBg != defaultBg) {
                        fill.color = opaque(runBg)
                        canvas.drawRect(runStart * cw, top, col * cw, top + ch, fill)
                    }
                    runStart = col
                    runBg = bg
                }
            }
        }

        for (row in 0 until grid.rows) {
            val top = row * ch
            val baseline = top + metrics.baseline
            var col = 0
            while (col < grid.cols) {
                // OSC 8 links are drawn underlined so there is something to tap.
                val flags = grid.flags(row, col) or (if (grid.hasLink(row, col)) FLAG_UNDERLINE else 0)
                val cp = grid.codepoint(row, col)
                if (cp == 0 || cp == ' '.code || flags and (FLAG_WIDE_SPACER or FLAG_HIDDEN) != 0) {
                    col++
                    continue
                }
                val fg = grid.fg(row, col)
                val style = flags and (FLAG_BOLD or FLAG_ITALIC or FLAG_UNDERLINE or FLAG_STRIKEOUT)
                if (flags and FLAG_WIDE != 0) {
                    text.typeface = metrics.typefaces[style]
                    text.color = opaque(fg)
                    sb.setLength(0)
                    sb.appendCodePoint(cp)
                    val w = text.measureText(sb, 0, sb.length)
                    canvas.drawText(sb, 0, sb.length, col * cw + (2 * cw - w) / 2f, baseline, text)
                    decorate(canvas, style, fg, col * cw, (col + 2) * cw, top, metrics)
                    col += 2
                    continue
                }
                sb.setLength(0)
                val start = col
                while (col < grid.cols) {
                    val f = grid.flags(row, col) or (if (grid.hasLink(row, col)) FLAG_UNDERLINE else 0)
                    val c = grid.codepoint(row, col)
                    if (f and FLAG_WIDE != 0 || grid.fg(row, col) != fg ||
                        (f and (FLAG_BOLD or FLAG_ITALIC or FLAG_UNDERLINE or FLAG_STRIKEOUT)) != style
                    ) {
                        break
                    }
                    if (c == 0 || f and (FLAG_WIDE_SPACER or FLAG_HIDDEN) != 0) sb.append(' ') else sb.appendCodePoint(c)
                    col++
                }
                text.typeface = metrics.typefaces[style]
                text.color = opaque(fg)
                drawRun(canvas, sb, start * cw, baseline, cw)
                decorate(canvas, style, fg, start * cw, col * cw, top, metrics)
            }
        }

        val shape = when (val s = grid.frame.cursor) {
            CursorStyle.HIDDEN -> null
            CursorStyle.BLOCK -> cursorOverride ?: s
            else -> s
        }
        if (shape != null && cursorVisible) {
            val cc = grid.frame.cursorCol.toInt()
            val cr = grid.frame.cursorRow.toInt()
            if (cc < grid.cols && cr < grid.rows) {
                val x = cc * cw
                val y = cr * ch
                val wide = grid.flags(cr, cc) and FLAG_WIDE != 0
                val w = if (wide) 2 * cw else cw
                val cursorColor = opaque(grid.fg(cr, cc))
                when {
                    !focused || shape == CursorStyle.HOLLOW_BLOCK -> {
                        line.color = cursorColor
                        canvas.drawRect(x + 0.5f, y + 0.5f, x + w - 0.5f, y + ch - 0.5f, line)
                    }
                    shape == CursorStyle.BLOCK -> {
                        fill.color = cursorColor
                        canvas.drawRect(x, y, x + w, y + ch, fill)
                        val cp = grid.codepoint(cr, cc)
                        if (cp != 0 && cp != ' '.code) {
                            text.color = opaque(grid.bg(cr, cc))
                            text.typeface = metrics.typefaces[grid.flags(cr, cc)]
                            sb.setLength(0)
                            sb.appendCodePoint(cp)
                            canvas.drawText(sb, 0, sb.length, x, y + metrics.baseline, text)
                        }
                    }
                    shape == CursorStyle.UNDERLINE -> {
                        fill.color = cursorColor
                        canvas.drawRect(x, y + ch - line.strokeWidth * 2, x + w, y + ch, fill)
                    }
                    shape == CursorStyle.BEAM -> {
                        fill.color = cursorColor
                        canvas.drawRect(x, y, x + line.strokeWidth * 2, y + ch, fill)
                    }
                    else -> Unit
                }
            }
        }
    }

    /** Glyphs whose advance differs from the cell (Nerd icons, fallbacks) are placed one by one. */
    private fun drawRun(canvas: Canvas, run: StringBuilder, x: Float, baseline: Float, cw: Float) {
        val natural = text.measureText(run, 0, run.length)
        val expected = cw * run.codePointCount(0, run.length)
        if (kotlin.math.abs(natural - expected) < 0.5f) {
            canvas.drawText(run, 0, run.length, x, baseline, text)
            return
        }
        var i = 0
        var cell = 0
        while (i < run.length) {
            val next = run.offsetByCodePoints(i, 1)
            canvas.drawText(run, i, next, x + cell * cw, baseline, text)
            i = next
            cell++
        }
    }

    private fun decorate(canvas: Canvas, style: Int, fg: Int, x0: Float, x1: Float, top: Float, m: CellMetrics) {
        if (style and (FLAG_UNDERLINE or FLAG_STRIKEOUT) == 0) return
        line.color = opaque(fg)
        if (style and FLAG_UNDERLINE != 0) {
            val y = top + m.underlineY
            canvas.drawLine(x0, y, x1, y, line)
        }
        if (style and FLAG_STRIKEOUT != 0) {
            val y = top + m.strikeY
            canvas.drawLine(x0, y, x1, y, line)
        }
    }

    private fun opaque(rgb: Int): Int = rgb or (0xFF shl 24)
}
