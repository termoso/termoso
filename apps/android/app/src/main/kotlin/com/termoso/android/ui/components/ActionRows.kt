package com.termoso.android.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudQueue
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termoso.android.R
import com.termoso.android.data.SftpConnection
import com.termoso.android.data.TerminalSession
import com.termoso.android.str
import com.termoso.core.FileProtocol
import com.termoso.core.SessionState
import com.termoso.core.Transport

/** One tappable action inside a bottom-sheet [SectionCard]: icon + label, tinted for destructive ones. */
@Composable
fun ActionRow(icon: ImageVector, title: String, tint: Color? = null, enabled: Boolean = true, onClick: () -> Unit) {
    val base = tint ?: MaterialTheme.colorScheme.onSurface
    val color = if (enabled) base else base.copy(alpha = 0.38f)
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(16.dp))
        Text(title, style = MaterialTheme.typography.bodyLarge, color = color)
    }
}

/** An open terminal tab: tap opens it, the trailing button closes just that one. */
@Composable
fun OpenTerminalRow(session: TerminalSession, onOpen: () -> Unit, onClose: () -> Unit) {
    val state by session.state.collectAsStateWithLifecycle()
    val title by session.title.collectAsStateWithLifecycle()
    OpenRow(
        icon = Icons.Filled.Terminal,
        title = title ?: session.label,
        subtitle = transportLabel(session.transport) + " · " + stateLabel(state),
        failed = state is SessionState.Failed,
        onOpen = onOpen,
        onClose = onClose,
    )
}

/** An open SFTP connection: tap opens the browser, the trailing button closes it. */
@Composable
fun OpenSftpRow(conn: SftpConnection, onOpen: () -> Unit, onClose: () -> Unit) {
    val state by conn.state.collectAsStateWithLifecycle()
    OpenRow(
        icon = when (conn.protocol) {
            FileProtocol.WEBDAV, FileProtocol.S3 -> Icons.Filled.CloudQueue
            FileProtocol.LOCAL -> Icons.Filled.PhoneAndroid
            FileProtocol.SFTP -> Icons.Filled.FolderOpen
        },
        title = when (conn.protocol) {
            FileProtocol.WEBDAV -> "WebDAV"
            FileProtocol.S3 -> "S3"
            FileProtocol.LOCAL -> stringResource(R.string.local_shell_files)
            FileProtocol.SFTP -> "SFTP"
        },
        subtitle = stateLabel(state),
        failed = state is SessionState.Failed,
        onOpen = onOpen,
        onClose = onClose,
    )
}

@Composable
private fun OpenRow(
    icon: ImageVector,
    title: String,
    subtitle: String,
    failed: Boolean,
    onOpen: () -> Unit,
    onClose: () -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .heightIn(min = 56.dp)
            .padding(start = 16.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.bodyLarge,
                color = if (failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        IconButton(onClick = onClose) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.close_connection)) }
    }
}

/** Label for the host-scoped close action: the row itself plus its siblings. */
fun closeHostLabel(total: Int): String = str(R.string.close_all_to_this_host, total)

fun transportLabel(t: Transport): String = when (t) {
    Transport.MOSH -> "Mosh"
    Transport.TELNET -> "Telnet"
    else -> "SSH"
}

fun stateLabel(state: SessionState): String = when (state) {
    is SessionState.Connecting -> connectingLabel(state)
    is SessionState.Connected -> str(R.string.connected)
    is SessionState.Closed -> str(R.string.closed) + (state.reason?.let { " · $it" } ?: "")
    is SessionState.Failed -> state.message
}
