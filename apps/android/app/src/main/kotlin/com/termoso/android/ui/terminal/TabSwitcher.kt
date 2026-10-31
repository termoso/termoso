package com.termoso.android.ui.terminal

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import kotlinx.coroutines.launch
import kotlin.math.abs
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termoso.android.R
import com.termoso.android.data.TerminalSession
import com.termoso.android.ui.components.HostAvatar
import com.termoso.core.SessionState

private val PillShape = RoundedCornerShape(8.dp)
private val CardShape = RoundedCornerShape(14.dp)

/**
 * The one pill of the session bar, browser style: the active session's icon
 * and name, a tab counter, and the close button. Tap opens the tab switcher,
 * long press opens the session menu.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun TabSwitcherButton(
    session: TerminalSession,
    count: Int,
    onOpen: () -> Unit,
    onLongClick: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by session.state.collectAsStateWithLifecycle()
    val detected by session.detectedOs.collectAsStateWithLifecycle()
    val accent = MaterialTheme.colorScheme.primary
    val fg = when (state) {
        is SessionState.Failed -> MaterialTheme.colorScheme.error
        else -> accent
    }
    Row(
        modifier
            .height(36.dp)
            .clip(PillShape)
            .background(accent.copy(alpha = 0.18f))
            .focusProperties { canFocus = false }
            .combinedClickable(onClick = onOpen, onLongClick = onLongClick, onLongClickLabel = stringResource(R.string.session_actions))
            .padding(start = 12.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        when {
            state is SessionState.Connecting -> CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = fg)
            session.isView -> Icon(Icons.Filled.Groups, contentDescription = null, tint = fg, modifier = Modifier.size(18.dp))
            else -> HostAvatar(detected ?: session.savedOsName, size = 20)
        }
        Text(
            session.label,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
            color = fg,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        // Tab counter as in a mobile browser: a small rounded square with the number.
        Box(
            Modifier
                .size(22.dp)
                .border(2.dp, fg, RoundedCornerShape(5.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                if (count > 99) ":)" else count.toString(),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = fg,
                textAlign = TextAlign.Center,
            )
        }
        Icon(
            Icons.Filled.Close,
            contentDescription = stringResource(R.string.close_session),
            tint = fg,
            modifier = Modifier
                .size(26.dp)
                .clip(RoundedCornerShape(13.dp))
                .clickable(onClick = onClose)
                .padding(5.dp),
        )
    }
}

/**
 * Full-screen tab switcher over the terminal, like the tab grid of a mobile
 * browser: one card per session with a live thumbnail of its screen, the name
 * and a close button underneath; the last card opens a new connection. Tap switches, long press opens the session
 * menu, the last card opens a new connection.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun TabSwitcher(
    sessions: List<TerminalSession>,
    activeId: String?,
    fontFamily: String,
    onSelect: (String) -> Unit,
    onClose: (String) -> Unit,
    onMenu: (String) -> Unit,
    onNew: () -> Unit,
    onDismiss: () -> Unit,
) {
    BackHandler(onBack = onDismiss)
    Column(
        Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .statusBarsPadding(),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 6.dp, top = 6.dp, bottom = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.tabs_count, sessions.size),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = onDismiss) {
                Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.close))
            }
        }
        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 8.dp, bottom = 24.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize(),
        ) {
            items(sessions, key = { it.id }) { s ->
                TabCard(
                    session = s,
                    active = s.id == activeId,
                    fontFamily = fontFamily,
                    onClick = { onSelect(s.id); onDismiss() },
                    onLongClick = { onMenu(s.id) },
                    onClose = { onClose(s.id) },
                )
            }
            item(key = "new") { NewTabCard(onNew) }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun TabCard(
    session: TerminalSession,
    active: Boolean,
    fontFamily: String,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    onClose: () -> Unit,
) {
    val state by session.state.collectAsStateWithLifecycle()
    val detected by session.detectedOs.collectAsStateWithLifecycle()
    val accent = MaterialTheme.colorScheme.primary
    val outline = if (active) accent else MaterialTheme.colorScheme.outlineVariant
    val fg = when {
        state is SessionState.Failed -> MaterialTheme.colorScheme.error
        active -> accent
        else -> MaterialTheme.colorScheme.onSurface
    }
    // Swipe the card sideways to close it, as in a browser's tab grid.
    val scope = rememberCoroutineScope()
    val offsetX = remember { Animatable(0f) }
    var widthPx by remember { mutableIntStateOf(0) }
    Column(
        Modifier
            .onSizeChanged { widthPx = it.width }
            .graphicsLayer {
                translationX = offsetX.value
                alpha = if (widthPx == 0) 1f else (1f - (abs(offsetX.value) / widthPx) * 0.9f).coerceIn(0.1f, 1f)
            }
            .pointerInput(session.id) {
                detectHorizontalDragGestures(
                    onHorizontalDrag = { change, delta ->
                        change.consume()
                        scope.launch { offsetX.snapTo(offsetX.value + delta) }
                    },
                    onDragEnd = {
                        val threshold = widthPx * 0.4f
                        if (widthPx > 0 && abs(offsetX.value) > threshold) {
                            val target = if (offsetX.value > 0) widthPx * 1.5f else -widthPx * 1.5f
                            scope.launch {
                                offsetX.animateTo(target, tween(160))
                                onClose()
                            }
                        } else {
                            scope.launch { offsetX.animateTo(0f, spring(stiffness = Spring.StiffnessMediumLow)) }
                        }
                    },
                    onDragCancel = { scope.launch { offsetX.animateTo(0f) } },
                )
            }
            .clip(CardShape)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .border(if (active) 2.dp else 1.dp, outline, CardShape)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick, onLongClickLabel = stringResource(R.string.session_actions)),
    ) {
        Box(
            Modifier
                .fillMaxWidth()
                .aspectRatio(1.1f)
                .padding(start = 6.dp, end = 6.dp, top = 6.dp)
                .clip(RoundedCornerShape(10.dp)),
        ) {
            if (state is SessionState.Connected) {
                TerminalPreview(session = session, fontFamily = fontFamily, modifier = Modifier.fillMaxSize(), fontSizeSp = 5)
            } else {
                val note = when (val s = state) {
                    is SessionState.Connecting -> stringResource(R.string.connecting)
                    is SessionState.Closed -> stringResource(R.string.closed)
                    is SessionState.Failed -> s.message
                    else -> ""
                }
                Box(Modifier.fillMaxSize().background(Color(0xFF0D1117)), contentAlignment = Alignment.Center) {
                    if (state is SessionState.Connecting) {
                        CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = accent)
                    } else {
                        Text(
                            note,
                            style = MaterialTheme.typography.bodySmall,
                            color = fg.copy(alpha = 0.8f),
                            textAlign = TextAlign.Center,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(start = 10.dp, end = 2.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (session.isView) Icon(Icons.Filled.Groups, contentDescription = null, tint = fg, modifier = Modifier.size(16.dp))
            else HostAvatar(detected ?: session.savedOsName, size = 18)
            Text(
                session.label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = fg,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = onClose, modifier = Modifier.size(32.dp)) {
                Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.close_session), tint = fg, modifier = Modifier.size(18.dp))
            }
        }
    }
}

@Composable
private fun NewTabCard(onNew: () -> Unit) {
    val accent = MaterialTheme.colorScheme.primary
    Column(
        Modifier
            .clip(CardShape)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, CardShape)
            .clickable(onClick = onNew),
    ) {
        Box(Modifier.fillMaxWidth().aspectRatio(1.1f).padding(start = 6.dp, end = 6.dp, top = 6.dp), contentAlignment = Alignment.Center) {
            Icon(Icons.Filled.Add, contentDescription = null, tint = accent, modifier = Modifier.size(40.dp))
        }
        // Same footer as a session card so the grid rows line up.
        Row(
            Modifier.fillMaxWidth().padding(start = 10.dp, end = 10.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Filled.Add, contentDescription = null, tint = accent, modifier = Modifier.size(18.dp))
            Text(
                stringResource(R.string.new_session),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = accent,
                maxLines = 1,
                modifier = Modifier.weight(1f),
            )
            // Mirrors the 32 dp close button of a session card.
            Box(Modifier.size(32.dp))
        }
    }
}
