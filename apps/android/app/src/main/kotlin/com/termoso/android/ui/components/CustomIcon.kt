package com.termoso.android.ui.components

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.RectF
import android.util.Base64
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.core.graphics.createBitmap
import com.caverock.androidsvg.PreserveAspectRatio
import com.caverock.androidsvg.SVG

/**
 * Custom host/group icons picked on the desktop: `Host.icon` / `Group.icon`
 * hold `custom:data:<data URL>` — a 64 px PNG (or any raster the desktop
 * accepted) or an SVG of at most 16 KiB, the whole value at most 32 KiB.
 * Same validation as `apps/desktop/src/hosts/customIcon.ts`; anything else
 * falls back to the built-in icon / folder tile.
 */
object CustomIcon {
    private const val PREFIX = "custom:data:"
    private const val MAX_LENGTH = 32 * 1024
    /** Raster size for SVGs; desktop stores rasters at 64 px as well. */
    private const val SVG_SIDE = 128
    private val DATA_URL = Regex(
        "^data:(image/(?:png|jpeg|gif|webp|svg\\+xml|x-icon|avif));base64,([a-z0-9+/]+={0,2})$",
        RegexOption.IGNORE_CASE,
    )

    private class Parsed(val mime: String, val bytes: ByteArray)

    private val cache = LruCache<String, ImageBitmap>(64)

    /** True for a well-formed custom icon value. */
    fun isCustom(value: String?): Boolean = parse(value) != null

    private fun parse(value: String?): Parsed? {
        if (value == null || !value.startsWith(PREFIX) || value.length > MAX_LENGTH + PREFIX.length) return null
        val m = DATA_URL.matchEntire(value.substring(PREFIX.length)) ?: return null
        val payload = m.groupValues[2]
        if (payload.isEmpty()) return null
        val bytes = try {
            Base64.decode(payload, Base64.DEFAULT)
        } catch (_: IllegalArgumentException) {
            return null
        }
        return Parsed(m.groupValues[1].lowercase(), bytes)
    }

    /** Decoded bitmap for [value], or null when it is not a usable custom icon. */
    fun bitmap(value: String?): ImageBitmap? {
        val parsed = parse(value) ?: return null
        cache.get(value)?.let { return it }
        val bitmap = try {
            if (parsed.mime == "image/svg+xml") decodeSvg(parsed.bytes) else BitmapFactory.decodeByteArray(parsed.bytes, 0, parsed.bytes.size)
        } catch (_: Exception) {
            null
        } ?: return null
        return bitmap.asImageBitmap().also { cache.put(value, it) }
    }

    private fun decodeSvg(bytes: ByteArray): Bitmap? {
        val svg = SVG.getFromString(String(bytes, Charsets.UTF_8))
        if (svg.documentWidth <= 0f || svg.documentHeight <= 0f) {
            svg.setDocumentWidth("100%")
            svg.setDocumentHeight("100%")
        }
        val bitmap = createBitmap(SVG_SIDE, SVG_SIDE)
        svg.setDocumentPreserveAspectRatio(PreserveAspectRatio.LETTERBOX)
        svg.renderToCanvas(Canvas(bitmap), RectF(0f, 0f, SVG_SIDE.toFloat(), SVG_SIDE.toFloat()))
        return bitmap
    }
}

/** Rounded tile showing a custom icon image on a neutral background. */
@Composable
fun CustomIconTile(bitmap: ImageBitmap, modifier: Modifier = Modifier, size: Int = 40) {
    Box(
        modifier = modifier
            .size(size.dp)
            .clip(RoundedCornerShape((size * 0.25f).dp))
            .background(MaterialTheme.colorScheme.surfaceContainerHighest),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            modifier = Modifier.size((size * 0.7f).dp).padding(1.dp),
        )
    }
}

/** Decoded custom icon for [value], remembered per value; null for built-in ids. */
@Composable
fun rememberCustomIcon(value: String?): ImageBitmap? = remember(value) { CustomIcon.bitmap(value) }
