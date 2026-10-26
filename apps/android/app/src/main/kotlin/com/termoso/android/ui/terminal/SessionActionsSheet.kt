package com.termoso.android.ui.terminal

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.material3.TextButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.AlertDialog
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termoso.android.R
import com.termoso.android.data.TerminalSession
import com.termoso.android.str
import com.termoso.android.ui.components.ActionRow
import com.termoso.android.ui.components.HostAvatar
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.SectionLabel
import com.termoso.android.ui.components.closeHostLabel
import com.termoso.android.ui.components.stateLabel
import com.termoso.android.ui.components.transportLabel
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.core.QuickTarget
import com.termoso.core.SessionState

/** `user@host[:port]` / `telnet://host[:port]` — what quick connect accepts back. */
fun quickTargetText(q: QuickTarget): String {
    val telnet = q.protocol.equals("telnet", true)
    val default = if (telnet) 23 else 22
    val port = if (q.port.toInt() == default) "" else ":${q.port}"
    return if (telnet) "telnet://${q.host}$port" else if (q.username.isBlank()) "${q.host}$port" else "${q.username}@${q.host}$port"
}

/** How many of [sessions] besides [session] point at the same saved host. */
fun siblingsOf(session: TerminalSession, sessions: List<TerminalSession>): List<TerminalSession> {
    val hostId = session.hostId ?: return emptyList()
    return sessions.filter { it.hostId == hostId && it.id != session.id }
}

/**
 * The `⋯` menu of a terminal tab: what else to open for this target (another
 * tab, SFTP, port forwarding), where its host lives (edit / add to hosts), the
 * panel and key customisation shortcuts, and the ways to close it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SessionActionsSheet(
    shell: ShellViewModel,
    session: TerminalSession,
    sessions: List<TerminalSession>,
    onLive: () -> Unit,
    onPanel: () -> Unit,
    onCustomizeKeys: () -> Unit,
    onNewSession: () -> Unit,
    onOpenSftp: (String) -> Unit,
    onForward: (String) -> Unit,
    onEditHost: (String) -> Unit,
    onAddHost: (String) -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val state by session.state.collectAsStateWithLifecycle()
    val title by session.title.collectAsStateWithLifecycle()
    val detected by session.detectedOs.collectAsStateWithLifecycle()
    val shared by session.share.collectAsStateWithLifecycle()
    val hostId = session.hostId
    val quick = session.quick
    val siblings = siblingsOf(session, sessions)
    val ssh = !session.isView && session.local == null && (quick?.protocol?.equals("ssh", true) ?: (hostId != null))

    fun then(action: () -> Unit): () -> Unit = { onClose(); action() }

    var saveWorkspace by remember { mutableStateOf(false) }
    if (saveWorkspace) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { saveWorkspace = false },
            title = { Text(stringResource(R.string.save_as_workspace)) },
            text = {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.name)) },
                    supportingText = { Text(pluralStringResource(R.plurals.n_tabs, sessions.size, sessions.size)) },
                )
            },
            confirmButton = {
                TextButton(enabled = name.isNotBlank(), onClick = {
                    saveWorkspace = false
                    shell.saveWorkspace(name)
                    onClose()
                }) { Text(stringResource(R.string.save)) }
            },
            dismissButton = { TextButton(onClick = { saveWorkspace = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }

    ModalBottomSheet(onDismissRequest = onClose) {
        Column(
            Modifier
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                HostAvatar(detected ?: session.savedOsName)
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        title ?: session.label,
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        session.target + " · " + transportLabel(session.transport) + " · " + stateLabel(state),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (state is SessionState.Failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            SectionLabel(stringResource(R.string.session))
            SectionCard {
                if (!session.isView) {
                    ActionRow(
                        Icons.Filled.ContentCopy,
                        stringResource(R.string.duplicate),
                        onClick = then { shell.launch { shell.duplicateSession(session.id) } },
                    )
                    RowDivider()
                }
                if (session.reconnectable) {
                    ActionRow(
                        Icons.Filled.Refresh,
                        stringResource(R.string.reconnect),
                        onClick = then { shell.launch { shell.sessions.reconnect(session.id) } },
                    )
                    RowDivider()
                }
                if (ssh) {
                    ActionRow(
                        Icons.Filled.FolderOpen,
                        stringResource(R.string.open_sftp),
                        onClick = then {
                            shell.launch { shell.openSftpSession(session)?.let { onOpenSftp(it.id) } }
                        },
                    )
                    RowDivider()
                    if (hostId != null) {
                        ActionRow(Icons.Filled.SwapHoriz, stringResource(R.string.port_forwarding_2), onClick = then { onForward(hostId) })
                        RowDivider()
                    }
                }
                if (!session.isView && session.local != null) {
                    ActionRow(
                        Icons.Filled.FolderOpen,
                        stringResource(R.string.open_local_files),
                        onClick = then { shell.launch { shell.openLocalFiles()?.let { onOpenSftp(it.id) } } },
                    )
                    RowDivider()
                }
                ActionRow(
                    Icons.Filled.Groups,
                    when {
                        session.isView -> stringResource(R.string.shared_terminal)
                        shared != null -> stringResource(R.string.terminal_sharing_live)
                        else -> stringResource(R.string.terminal_sharing)
                    },
                    onClick = then(onLive),
                )
                if (!session.isView && session.local == null) {
                    RowDivider()
                    ActionRow(
                        Icons.Filled.Link,
                        stringResource(R.string.copy_address),
                        onClick = then {
                            copyToClipboard(context, session.target)
                            shell.notify(str(R.string.address_copied))
                        },
                    )
                }
            }

            if (hostId != null || quick != null) {
                SectionLabel(stringResource(R.string.host))
                SectionCard {
                    if (hostId != null) {
                        ActionRow(Icons.Filled.Edit, stringResource(R.string.edit_host), onClick = then { onEditHost(hostId) })
                    } else if (quick != null) {
                        ActionRow(Icons.Filled.Add, stringResource(R.string.add_to_hosts), onClick = then { onAddHost(quickTargetText(quick)) })
                    }
                }
            }

            SectionLabel(stringResource(R.string.terminal))
            SectionCard {
                ActionRow(Icons.Filled.History, stringResource(R.string.history_themes), onClick = then(onPanel))
                RowDivider()
                ActionRow(Icons.Filled.Keyboard, stringResource(R.string.customize_keys), onClick = then(onCustomizeKeys))
                RowDivider()
                ActionRow(Icons.Filled.Add, stringResource(R.string.new_session), onClick = then(onNewSession))
                if (shell.sessions.workspaces != null && sessions.any { !it.isView }) {
                    RowDivider()
                    ActionRow(Icons.Filled.Dashboard, stringResource(R.string.save_as_workspace), onClick = { saveWorkspace = true })
                }
            }

            SectionLabel(stringResource(R.string.close))
            SectionCard {
                ActionRow(
                    Icons.Filled.Close,
                    stringResource(R.string.close_session),
                    tint = MaterialTheme.colorScheme.error,
                    onClick = then { shell.launch { shell.sessions.close(session.id) } },
                )
                if (siblings.isNotEmpty()) {
                    RowDivider()
                    ActionRow(
                        Icons.Filled.PowerSettingsNew,
                        closeHostLabel(siblings.size + 1),
                        tint = MaterialTheme.colorScheme.error,
                        onClick = then { shell.launch { shell.sessions.closeMany(siblings.map { it.id } + session.id) } },
                    )
                }
                if (sessions.size > 1) {
                    RowDivider()
                    ActionRow(
                        Icons.Filled.PowerSettingsNew,
                        stringResource(R.string.close_all_sessions, sessions.size),
                        tint = MaterialTheme.colorScheme.error,
                        onClick = then { shell.launch { shell.sessions.closeAll() } },
                    )
                }
            }
        }
    }
}
