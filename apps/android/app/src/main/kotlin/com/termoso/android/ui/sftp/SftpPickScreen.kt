package com.termoso.android.ui.sftp

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termoso.android.R
import com.termoso.android.data.SftpManager
import com.termoso.android.data.userMessage
import com.termoso.android.ui.components.EmptyState
import com.termoso.android.ui.components.HostAvatar
import com.termoso.android.ui.components.ListRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.SectionLabel
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.core.FileProtocol
import com.termoso.core.HostItem
import com.termoso.core.MobileException
import com.termoso.core.parseTarget
import kotlinx.coroutines.launch

/** One row of the saved-hosts list: a host over one of its file protocols. */
private data class FileTarget(val host: HostItem, val protocol: FileProtocol)

/** "New SFTP connection": pick a saved host of the selected vault (SFTP for SSH ones, WebDAV for shares) or type a target. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SftpPickScreen(shell: ShellViewModel, onBack: () -> Unit, onOpened: (String) -> Unit) {
    val revision by shell.repo.revision.collectAsStateWithLifecycle()
    val vaultId by shell.selectedVaultId.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var hosts by remember { mutableStateOf<List<FileTarget>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }
    var target by remember { mutableStateOf("") }
    var query by remember { mutableStateOf("") }
    LaunchedEffect(revision, vaultId) {
        val id = vaultId
        hosts = if (id == null) emptyList() else runCatching { shell.repo.read { hosts(id) } }.getOrDefault(emptyList())
            .filter { SftpManager.hasFiles(it) }
            .sortedBy { it.label.ifBlank { it.address }.lowercase() }
            .flatMap { h ->
                buildList {
                    if (h.protocol.equals("ssh", ignoreCase = true)) add(FileTarget(h, FileProtocol.SFTP))
                    if (h.webdavUrl != null) add(FileTarget(h, FileProtocol.WEBDAV))
                }
            }
        loaded = true
    }

    fun connectQuick() {
        val parsed = try {
            parseTarget(target)
        } catch (e: MobileException) {
            shell.notify(e.userMessage())
            return
        }
        scope.launch { shell.openSftpQuick(parsed)?.let { onOpened(it.id) } }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.new_sftp_connection)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            OutlinedTextField(
                value = target,
                onValueChange = { target = it },
                placeholder = { Text("user@host:port") },
                label = { Text(stringResource(R.string.quick_connect)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    capitalization = KeyboardCapitalization.None,
                    imeAction = ImeAction.Go,
                    autoCorrectEnabled = false,
                ),
                keyboardActions = KeyboardActions(onGo = { connectQuick() }),
                trailingIcon = {
                    IconButton(onClick = ::connectQuick, enabled = target.isNotBlank()) {
                        Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = stringResource(R.string.connect))
                    }
                },
            )
            SectionLabel(stringResource(R.string.saved_hosts))
            if (hosts.size > 8) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text(stringResource(R.string.search_hosts)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
                )
            }
            val shown = hosts.filter { (h, _) ->
                query.isBlank() || h.label.contains(query, true) || h.address.contains(query, true) || h.username.contains(query, true)
            }
            if (loaded && shown.isEmpty()) {
                EmptyState(
                    title = if (hosts.isEmpty()) stringResource(R.string.no_ssh_hosts_yet) else stringResource(R.string.nothing_found),
                    hint = if (hosts.isEmpty()) stringResource(R.string.add_a_host_in_vaults_or_type_user) else stringResource(R.string.try_another_name_or_address),
                )
            } else {
                SectionCard {
                    shown.forEachIndexed { i, (h, protocol) ->
                        if (i > 0) RowDivider()
                        ListRow(
                            title = h.label.ifBlank { h.address },
                            subtitle = if (protocol == FileProtocol.WEBDAV) {
                                stringResource(R.string.webdav_target, h.webdavUrl ?: h.address)
                            } else {
                                listOf(h.username, h.address).filter { it.isNotBlank() }.joinToString("@")
                            },
                            leading = { HostAvatar(h.osName, icon = h.icon) },
                            modifier = Modifier.clickable {
                                scope.launch { shell.openSftpHost(h.id, protocol)?.let { onOpened(it.id) } }
                            },
                        )
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
