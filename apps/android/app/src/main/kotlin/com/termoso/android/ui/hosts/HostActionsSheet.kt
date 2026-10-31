package com.termoso.android.ui.hosts

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudQueue
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termoso.android.R
import com.termoso.android.str
import com.termoso.android.ui.components.ActionRow
import com.termoso.android.ui.components.HostAvatar
import com.termoso.android.ui.components.OpenSftpRow
import com.termoso.android.ui.components.OpenTerminalRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.SectionLabel
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.android.ui.terminal.copyToClipboard
import com.termoso.core.HostItem
import com.termoso.core.Transport

/** `user@address` plus protocol/port when they are not the SSH defaults, with Mosh/Telnet/WebDAV flags. */
fun hostSubtitle(h: HostItem): String {
    val target = if (h.username.isNotBlank()) "${h.username}@${h.address}" else h.address
    val ssh = h.protocol.equals("ssh", true)
    val webdavOnly = h.protocol.equals("webdav", true)
    val base = when {
        webdavOnly -> "$target · WebDAV"
        ssh && h.port == 22.toUShort() -> target
        else -> "$target · ${h.protocol.uppercase()} ${h.port}"
    }
    val mosh = if (ssh && h.useMosh) " · Mosh" else ""
    val telnet = if (ssh && h.telnetPort != null) " · Telnet" else ""
    val webdav = if (!webdavOnly && h.webdavUrl != null) " · WebDAV" else ""
    return base + mosh + telnet + webdav
}

/** `ssh://user@host[:port]` (or `telnet://…`; the share URL for WebDAV-only hosts) for the clipboard; the default port is left out. */
fun hostLink(h: HostItem): String =
    if (h.protocol.equals("webdav", true)) h.webdavUrl ?: h.address else hostLink(h.protocol, h.username, h.address, h.port.toInt())

fun hostLink(protocol: String, username: String, address: String, port: Int): String {
    val ssh = protocol.equals("ssh", true)
    val scheme = if (ssh) "ssh" else protocol.lowercase()
    val default = if (ssh) 22 else 23
    val user = if (ssh && username.isNotBlank()) "$username@" else ""
    val suffix = if (port == default) "" else ":$port"
    return "$scheme://$user$address$suffix"
}

/** Termius wording: one connection closes as such, several as "Close all". */
fun closeConnectionsLabel(count: Int): String = if (count <= 1) str(R.string.close_connection) else str(R.string.close_all_2, count)

/**
 * Everything one can do with a host, reached by long-pressing it or tapping its
 * Active badge: the open terminals/SFTP to it (open one, close one, close all),
 * then the connect variants and the housekeeping actions. Bulk selection is a
 * step away through "Select".
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostActionsSheet(
    shell: ShellViewModel,
    host: HostItem,
    canCopyToVault: Boolean,
    onConnect: (Transport) -> Unit,
    onSftp: () -> Unit,
    onWebdav: () -> Unit,
    onOpenSftp: (String) -> Unit,
    onOpenTerminal: () -> Unit,
    onForward: () -> Unit,
    onEdit: () -> Unit,
    onAddKey: () -> Unit,
    onDuplicate: () -> Unit,
    onMove: () -> Unit,
    onMoveVault: () -> Unit,
    onCopy: () -> Unit,
    onSelect: () -> Unit,
    onDelete: () -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val allSessions by shell.sessions.sessions.collectAsStateWithLifecycle()
    val allSftp by shell.sftp.connections.collectAsStateWithLifecycle()
    val sessions = allSessions.filter { it.hostId == host.id }
    val sftp = allSftp.filter { it.hostId == host.id }
    val open = sessions.size + sftp.size
    val ssh = host.protocol.equals("ssh", true)
    val telnet = ssh && host.telnetPort != null
    val webdav = host.webdavUrl != null
    val terminal = !host.protocol.equals("webdav", true)

    fun then(action: () -> Unit): () -> Unit = { onClose(); action() }

    ModalBottomSheet(onDismissRequest = onClose) {
        Column(
            Modifier
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                HostAvatar(host.osName, icon = host.icon)
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        host.label.ifBlank { host.address },
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        hostSubtitle(host),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            if (open > 0) {
                SectionLabel(if (open == 1) stringResource(R.string.active_connection) else stringResource(R.string.active_connections, open))
                SectionCard {
                    sessions.forEachIndexed { i, s ->
                        if (i > 0) RowDivider()
                        OpenTerminalRow(
                            session = s,
                            onOpen = then { shell.sessions.setActive(s.id); onOpenTerminal() },
                            onClose = { shell.launch { shell.sessions.close(s.id) } },
                        )
                    }
                    sftp.forEachIndexed { i, c ->
                        if (i > 0 || sessions.isNotEmpty()) RowDivider()
                        OpenSftpRow(
                            conn = c,
                            onOpen = then { onOpenSftp(c.id) },
                            onClose = { shell.launch { shell.sftp.close(c.id) } },
                        )
                    }
                    RowDivider()
                    ActionRow(
                        Icons.Filled.PowerSettingsNew,
                        closeConnectionsLabel(open),
                        tint = MaterialTheme.colorScheme.error,
                        onClick = then {
                            shell.launch {
                                shell.sessions.closeMany(sessions.map { it.id })
                                shell.sftp.closeMany(sftp.map { it.id })
                            }
                        },
                    )
                }
            }

            SectionLabel(stringResource(R.string.connect))
            SectionCard {
                if (terminal) {
                    ActionRow(Icons.Filled.Terminal, if (ssh) stringResource(R.string.connect) else stringResource(R.string.connect_with_telnet), onClick = then { onConnect(Transport.AUTO) })
                }
                if (ssh) {
                    RowDivider()
                    ActionRow(Icons.Filled.Bolt, stringResource(R.string.connect_with_mosh), onClick = then { onConnect(Transport.MOSH) })
                    if (telnet) {
                        RowDivider()
                        ActionRow(Icons.Filled.Terminal, stringResource(R.string.connect_with_telnet), onClick = then { onConnect(Transport.TELNET) })
                    }
                    RowDivider()
                    ActionRow(Icons.Filled.FolderOpen, "SFTP", onClick = then(onSftp))
                }
                if (webdav) {
                    if (terminal) RowDivider()
                    ActionRow(Icons.Filled.CloudQueue, stringResource(R.string.webdav_files), onClick = then(onWebdav))
                }
                if (ssh) {
                    RowDivider()
                    ActionRow(Icons.Filled.SwapHoriz, stringResource(R.string.port_forwarding_2), onClick = then(onForward))
                }
            }

            SectionLabel(stringResource(R.string.host))
            SectionCard {
                ActionRow(Icons.Filled.Edit, stringResource(R.string.edit), onClick = then(onEdit))
                if (ssh) {
                    RowDivider()
                    ActionRow(Icons.Filled.VpnKey, stringResource(R.string.add_ssh_key_to_host), onClick = then(onAddKey))
                }
                RowDivider()
                ActionRow(Icons.Filled.ContentCopy, stringResource(R.string.duplicate), onClick = then(onDuplicate))
                RowDivider()
                ActionRow(Icons.AutoMirrored.Filled.DriveFileMove, stringResource(R.string.move_to_group), onClick = then(onMove))
                if (canCopyToVault) {
                    RowDivider()
                    ActionRow(Icons.AutoMirrored.Filled.DriveFileMove, stringResource(R.string.move_to_vault), onClick = then(onMoveVault))
                    RowDivider()
                    ActionRow(Icons.Filled.ContentCopy, stringResource(R.string.copy_to_vault), onClick = then(onCopy))
                }
                RowDivider()
                ActionRow(
                    Icons.Filled.Link,
                    stringResource(R.string.copy_link),
                    onClick = then {
                        copyToClipboard(context, hostLink(host))
                        shell.notify(str(R.string.link_copied))
                    },
                )
                RowDivider()
                ActionRow(Icons.Filled.CheckCircle, stringResource(R.string.select), onClick = then(onSelect))
                RowDivider()
                ActionRow(Icons.Filled.Delete, stringResource(R.string.remove_2), tint = MaterialTheme.colorScheme.error, onClick = then(onDelete))
            }
        }
    }
}
