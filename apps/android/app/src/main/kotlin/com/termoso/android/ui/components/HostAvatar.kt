package com.termoso.android.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.termoso.android.R

private val vectorCache = HashMap<String, ImageVector>()

/** White glyph of a distro icon, built once per id from its SVG path. */
fun distroVector(icon: DistroIcon): ImageVector = vectorCache.getOrPut(icon.id) {
    ImageVector.Builder(
        name = icon.id,
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).addPath(pathData = addPathNodes(SvgPath.normalize(icon.path)), fill = SolidColor(Color.White)).build()
}

/**
 * Host tile: the icon the user picked (`Host.icon`, see [IconCatalog]) or,
 * failing that, the brand-coloured distro glyph when the OS is known, and a
 * neutral terminal tile otherwise; green check while selected.
 */
@Composable
fun HostAvatar(osName: String?, modifier: Modifier = Modifier, selected: Boolean = false, size: Int = 40, icon: String? = null) {
    val icon = remember(osName, icon) { IconCatalog.picked(icon) ?: DistroIcons.forOs(osName) }
    Box(
        modifier = modifier
            .size(size.dp)
            .clip(RoundedCornerShape((size * 0.25f).dp))
            .background(
                when {
                    selected -> MaterialTheme.colorScheme.primary
                    icon != null -> icon.color
                    else -> MaterialTheme.colorScheme.surfaceContainerHighest
                },
            ),
        contentAlignment = Alignment.Center,
    ) {
        when {
            selected -> Icon(Icons.Filled.Check, contentDescription = stringResource(R.string.selected), tint = Color.White)
            icon != null -> Image(
                painter = rememberVectorPainter(distroVector(icon)),
                contentDescription = icon.title,
                modifier = Modifier.size((size * 0.6).dp),
            )
            else -> Icon(
                Icons.Filled.Terminal,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.size((size * 0.55).dp),
            )
        }
    }
}
