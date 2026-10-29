package com.termoso.android.ui.hosts

import androidx.compose.runtime.SideEffect
import com.termoso.android.data.userMessage
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudQueue
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.termoso.android.R
import com.termoso.android.data.VaultRepository
import com.termoso.android.saf.FilesIntegration
import com.termoso.android.str
import com.termoso.android.ui.components.ChevronRow
import com.termoso.android.ui.components.FormField
import com.termoso.android.ui.components.ListRow
import com.termoso.android.ui.components.PickerRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.SectionLabel
import com.termoso.android.ui.components.SegmentedLabel
import com.termoso.android.ui.components.SwitchRow
import com.termoso.android.ui.keychain.KeyTextArea
import com.termoso.android.ui.keychain.SshIdRows
import com.termoso.android.ui.keychain.pasteText
import com.termoso.android.ui.keychain.readTextFile
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.android.ui.terminal.copyToClipboard
import com.termoso.android.ui.vault.vaultLabel
import com.termoso.core.HostDraft
import com.termoso.core.HostKeyPinItem
import com.termoso.core.IdentityItem
import com.termoso.core.InheritedInfo
import com.termoso.core.QuickTarget
import com.termoso.core.TagItem
import com.termoso.core.TelnetDraft
import com.termoso.core.VaultAccess
import com.termoso.core.VaultInfo
import com.termoso.core.VaultKind
import com.termoso.core.WebDavDraft
import com.termoso.core.moshDefaultServerCommand
import kotlinx.coroutines.launch

/**
 * New / edit host form. The `⋯` menu saves pending edits before it connects,
 * so what the terminal dials is what the form shows.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostEditorScreen(
    shell: ShellViewModel,
    hostId: String?,
    groupId: String?,
    onClose: () -> Unit,
    prefill: QuickTarget? = null,
    files: FilesIntegration? = null,
    onConnect: (String) -> Unit = {},
    onSftp: (String) -> Unit = {},
    onWebdav: (String) -> Unit = {},
    onForward: (String) -> Unit = {},
) {
    val initialVault by shell.selectedVaultId.collectAsStateWithLifecycle()
    val vm: HostEditorViewModel = viewModel(key = "host/${hostId ?: "new"}") {
        HostEditorViewModel(shell.repo, hostId, initialVault, groupId, prefill)
    }
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var menu by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }
    // What to do with the saved host once the write lands ("Connect" from the menu).
    var afterSave by remember { mutableStateOf<((String) -> Unit)?>(null) }

    LaunchedEffect(state.error) {
        state.error?.let { shell.notify(it); vm.errorShown() }
    }
    LaunchedEffect(state.saved) {
        if (!state.saved) return@LaunchedEffect
        onClose()
        val id = state.savedId
        val next = afterSave
        if (id != null && next != null) next(id)
    }

    fun saveThen(action: (String) -> Unit) {
        if (!state.canSave) return
        afterSave = action
        vm.save()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (hostId == null) stringResource(R.string.new_host) else state.draft?.label?.ifBlank { null } ?: stringResource(R.string.edit_host)) },
                navigationIcon = {
                    IconButton(onClick = onClose) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.close)) }
                },
                actions = {
                    IconButton(onClick = vm::save, enabled = state.canSave) {
                        if (state.saving) {
                            CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.Filled.Check, contentDescription = stringResource(R.string.save))
                        }
                    }
                    val draft = state.draft
                    val savedId = draft?.id
                    if (draft != null) {
                        Box {
                            IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more)) }
                            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                                if (draft.ssh || draft.telnet != null) {
                                    DropdownMenuItem(
                                        text = { Text(if (savedId == null) stringResource(R.string.save_and_connect) else stringResource(R.string.connect)) },
                                        leadingIcon = { Icon(Icons.Filled.Terminal, null) },
                                        enabled = state.canSave,
                                        onClick = { menu = false; saveThen(onConnect) },
                                    )
                                }
                                if (draft.webdav != null) {
                                    DropdownMenuItem(
                                        text = { Text(if (savedId == null) stringResource(R.string.save_and_open_webdav) else stringResource(R.string.webdav_files)) },
                                        leadingIcon = { Icon(Icons.Filled.CloudQueue, null) },
                                        enabled = state.canSave,
                                        onClick = { menu = false; saveThen(onWebdav) },
                                    )
                                }
                                if (draft.ssh) {
                                    DropdownMenuItem(
                                        text = { Text(if (savedId == null) stringResource(R.string.save_and_open_sftp) else "SFTP") },
                                        leadingIcon = { Icon(Icons.Filled.FolderOpen, null) },
                                        enabled = state.canSave,
                                        onClick = { menu = false; saveThen(onSftp) },
                                    )
                                    if (savedId != null) {
                                        DropdownMenuItem(
                                            text = { Text(stringResource(R.string.port_forwarding_2)) },
                                            leadingIcon = { Icon(Icons.Filled.SwapHoriz, null) },
                                            onClick = { menu = false; onForward(savedId) },
                                        )
                                    }
                                }
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.copy_link)) },
                                    leadingIcon = { Icon(Icons.Filled.Link, null) },
                                    enabled = draft.address.isNotBlank(),
                                    onClick = {
                                        menu = false
                                        copyToClipboard(context, draftLink(draft))
                                        shell.notify(str(R.string.link_copied))
                                    },
                                )
                                if (savedId != null) {
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.duplicate)) },
                                        leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                                        enabled = !state.saving,
                                        onClick = { menu = false; vm.duplicate() },
                                    )
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.remove_2), color = MaterialTheme.colorScheme.error) },
                                        leadingIcon = { Icon(Icons.Filled.Delete, null, tint = MaterialTheme.colorScheme.error) },
                                        enabled = !state.saving,
                                        onClick = { menu = false; confirmRemove = true },
                                    )
                                }
                            }
                        }
                    }
                },
            )
        },
    ) { padding ->
        val draft = state.draft
        if (state.loading || draft == null) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                if (state.loading) CircularProgressIndicator()
            }
            return@Scaffold
        }
        val vault = state.vaults.firstOrNull { it.id == draft.vaultId }
    val revealAllowed: suspend () -> Boolean = {
        runCatching { shell.repo.perms.require(draft.vaultId, "secrets.reveal") }
            .onFailure { shell.notify(it.userMessage()) }
            .isSuccess
    }
    SideEffect { revealCheck = revealAllowed }
        val presence = rememberVaultPresence(shell, vault)
        val viewers = remember(presence, draft.id) { draft.id?.let { viewersByHost(presence)[it] } ?: emptyList() }
        HostForm(
            repo = shell.repo,
            state = state,
            draft = draft,
            vm = vm,
            viewers = viewers,
            files = files,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        )
    }

    if (confirmRemove) {
        ConfirmDialog(
            title = stringResource(R.string.remove_host),
            text = stringResource(R.string.the_host_is_removed_from_this_vault_keys),
            confirm = stringResource(R.string.remove_2),
            onConfirm = { confirmRemove = false; vm.delete() },
            onDismiss = { confirmRemove = false },
        )
    }
}

/** `ssh://user@host[:port]` from the form as it stands (Telnet-only hosts give `telnet://`, WebDAV-only the share URL). */
fun draftLink(d: HostDraft): String {
    val telnet = d.telnet
    val webdav = d.webdav
    return when {
        d.ssh -> hostLink("ssh", d.username, d.address.trim(), d.port?.toInt() ?: 22)
        telnet != null -> hostLink("telnet", "", d.address.trim(), telnet.port?.toInt() ?: 23)
        webdav != null -> webdavLink(d.address.trim(), webdav)
        else -> hostLink("ssh", d.username, d.address.trim(), d.port?.toInt() ?: 22)
    }
}

@Composable
private fun HostForm(
    repo: VaultRepository,
    state: HostEditorState,
    draft: HostDraft,
    vm: HostEditorViewModel,
    viewers: List<HostViewer>,
    files: FilesIntegration?,
    modifier: Modifier,
) {
    var groupPicker by remember { mutableStateOf(false) }
    var tagPicker by remember { mutableStateOf(false) }
    var more by remember { mutableStateOf(hasAdvanced(draft)) }
    val inherited = state.inherited
    val groupPaths = remember(state.groups) { groupPaths(state.groups) }
    val identity = state.identities.firstOrNull { it.id == draft.identityId }

    Column(modifier) {
        if (draft.id == null && state.vaults.size > 1) {
            VaultRow(state.vaults, draft.vaultId, onSelect = vm::setVault)
        } else {
            Spacer(Modifier.height(12.dp))
        }

        if (viewers.isNotEmpty()) {
            ConnectedNowSection(repo, viewers)
            Spacer(Modifier.height(12.dp))
        }

        SectionCard {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                FormField(draft.label, { v -> vm.update { it.copy(label = v) } }, stringResource(R.string.alias))
                FormField(
                    draft.address,
                    { v -> vm.update { it.copy(address = v) } },
                    stringResource(R.string.hostname_or_ip_address),
                    keyboard = KeyboardType.Uri,
                )
            }
            RowDivider()
            ChevronRow(
                title = stringResource(R.string.group),
                badge = draft.groupId?.let { groupPaths[it] } ?: stringResource(R.string.none),
                modifier = Modifier.clickable { groupPicker = true },
            )
            RowDivider()
            ChevronRow(
                title = stringResource(R.string.tags),
                badge = tagSummary(draft, state.tags),
                modifier = Modifier.clickable { tagPicker = true },
            )
        }

        val telnet = draft.telnet
        val webdav = draft.webdav
        val sections = (if (draft.ssh) 1 else 0) + (if (telnet != null) 1 else 0) + (if (webdav != null) 1 else 0)
        if (draft.ssh) {
            ProtocolHeader("SSH", removable = sections > 1) { vm.update { it.copy(ssh = false) } }
            SshSection(state, draft, vm, inherited, identity)
        }

        if (telnet != null) {
            ProtocolHeader("Telnet", removable = sections > 1) { vm.update { it.copy(telnet = null) } }
            SectionCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    FormField(
                        telnet.port?.toString() ?: "",
                        { v -> vm.updateTelnet { it.copy(port = v.filter(Char::isDigit).take(5).toUIntOrNull()?.takeIf { p -> p in 1u..65535u }?.toUShort()) } },
                        stringResource(R.string.port),
                        placeholder = "23",
                        keyboard = KeyboardType.Number,
                    )
                    FormField(telnet.username, { v -> vm.updateTelnet { it.copy(username = v) } }, stringResource(R.string.username))
                    PasswordField(
                                                password = telnet.password,
                        hasPassword = telnet.hasPassword,
                        inheritedHint = false,
                        onChange = { v -> vm.updateTelnet { it.copy(password = v) } },
                    )
                    Text(
                        stringResource(R.string.telnet_is_not_encrypted_anything_typed_including_the),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (webdav != null) {
            ProtocolHeader("WebDAV", removable = sections > 1) { vm.update { it.copy(webdav = null) } }
            SectionCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    FormField(
                        webdav.port?.toString() ?: "",
                        { v -> vm.updateWebdav { it.copy(port = v.filter(Char::isDigit).take(5).toIntOrNull()?.takeIf { p -> p in 1..65535 }?.toUShort()) } },
                        stringResource(R.string.webdav_port),
                        placeholder = if (webdav.http) "80" else "443",
                        keyboard = KeyboardType.Number,
                    )
                    FormField(
                        webdav.path,
                        { v -> vm.updateWebdav { it.copy(path = v) } },
                        stringResource(R.string.webdav_path),
                        placeholder = "/remote.php/dav/files/user/",
                        keyboard = KeyboardType.Uri,
                    )
                    Text(
                        stringResource(R.string.webdav_path_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    WebDavAuthRow(webdav.auth) { mode -> vm.updateWebdav { it.copy(auth = mode) } }
                    if (webdav.auth == WEBDAV_AUTH_TOKEN) {
                        PasswordField(
                                                        password = webdav.bearerToken,
                            hasPassword = webdav.hasBearerToken,
                            inheritedHint = false,
                            onChange = { v -> vm.updateWebdav { it.copy(bearerToken = v) } },
                            label = stringResource(R.string.webdav_token),
                            savedLabel = stringResource(R.string.webdav_token_saved),
                        )
                        Text(
                            stringResource(R.string.webdav_token_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        FormField(webdav.username, { v -> vm.updateWebdav { it.copy(username = v) } }, stringResource(R.string.username))
                        PasswordField(
                                                        password = webdav.password,
                            hasPassword = webdav.hasPassword,
                            inheritedHint = false,
                            onChange = { v -> vm.updateWebdav { it.copy(password = v) } },
                        )
                    }
                    Text(
                        stringResource(R.string.webdav_credentials_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.webdav_plain_http),
                    checked = webdav.http,
                    onCheckedChange = { on -> vm.updateWebdav { it.copy(http = on) } },
                )
                if (!webdav.http) {
                    RowDivider()
                    TlsBlock(vm, webdav)
                    RowDivider()
                    ClientCertificateBlock(vm, state, webdav)
                }
            }
        }

        if (!draft.ssh || telnet == null || webdav == null) {
            Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!draft.ssh) {
                    TextButton(onClick = { vm.update { it.copy(ssh = true) } }) {
                        Icon(Icons.Filled.Add, contentDescription = null)
                        Text(stringResource(R.string.add_ssh))
                    }
                }
                if (telnet == null) {
                    TextButton(onClick = { vm.update { it.copy(telnet = TelnetDraft(port = null, username = "", password = null, identityId = null, hasPassword = false)) } }) {
                        Icon(Icons.Filled.Add, contentDescription = null)
                        Text(stringResource(R.string.add_telnet))
                    }
                }
                if (webdav == null) {
                    TextButton(onClick = { vm.update { it.copy(webdav = emptyWebDavDraft()) } }) {
                        Icon(Icons.Filled.Add, contentDescription = null)
                        Text(stringResource(R.string.add_webdav))
                    }
                }
            }
        }

        if (draft.ssh || webdav != null) {
            Spacer(Modifier.height(12.dp))
            FilesSection(draft, vm, files)
        }

        if (draft.ssh || draft.telnet != null || draft.webdav != null) {
            Spacer(Modifier.height(12.dp))
            SectionCard { ConnectionSection(state, draft, vm) }
        }

        Row(
            Modifier
                .fillMaxWidth()
                .clickable { more = !more }
                .padding(vertical = 16.dp, horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(if (more) stringResource(R.string.hide_advanced) else stringResource(R.string.show_advanced), color = MaterialTheme.colorScheme.primary)
            Icon(
                if (more) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
        }

        if (more) {
            SectionCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    IpVersionRow(draft.ipVersion) { v -> vm.update { it.copy(ipVersion = v) } }
                    FormField(
                        draft.keepAliveInterval?.toString() ?: "",
                        { v -> vm.update { it.copy(keepAliveInterval = v.filter(Char::isDigit).take(5).toUIntOrNull()) } },
                        stringResource(R.string.keep_alive_interval_seconds),
                        placeholder = stringResource(R.string.app_default),
                        keyboard = KeyboardType.Number,
                    )
                    FormField(
                        draft.timeout?.toString() ?: "",
                        { v -> vm.update { it.copy(timeout = v.filter(Char::isDigit).take(4).toUIntOrNull()) } },
                        stringResource(R.string.connection_timeout_seconds),
                        placeholder = stringResource(R.string.app_default),
                        keyboard = KeyboardType.Number,
                    )
                }
                RowDivider()
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.environment_variables), style = MaterialTheme.typography.labelLarge)
                    draft.envVariables.forEachIndexed { i, env ->
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = env.name,
                                onValueChange = { vm.setEnv(i, it, env.value) },
                                label = { Text(stringResource(R.string.name)) },
                                singleLine = true,
                                modifier = Modifier.weight(1f),
                                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
                            )
                            OutlinedTextField(
                                value = env.value,
                                onValueChange = { vm.setEnv(i, env.name, it) },
                                label = { Text(stringResource(R.string.value_)) },
                                singleLine = true,
                                modifier = Modifier.weight(1f),
                                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                            )
                            IconButton(onClick = { vm.removeEnv(i) }) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.remove_2)) }
                        }
                    }
                    TextButton(onClick = vm::addEnv) {
                        Icon(Icons.Filled.Add, contentDescription = null)
                        Text(stringResource(R.string.add_variable))
                    }
                }
                RowDivider()
                Column(Modifier.padding(16.dp)) {
                    OutlinedTextField(
                        value = draft.notes,
                        onValueChange = { v -> vm.update { it.copy(notes = v) } },
                        label = { Text(stringResource(R.string.notes)) },
                        minLines = 3,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }
        Spacer(Modifier.height(32.dp))
    }

    if (groupPicker) {
        GroupPickerDialog(
            title = stringResource(R.string.group),
            groups = state.groups,
            current = draft.groupId,
            onPick = { vm.setGroup(it); groupPicker = false },
            onDismiss = { groupPicker = false },
        )
    }
    if (tagPicker) {
        TagPickerDialog(
            tags = state.tags,
            selected = draft.tagIds.toSet(),
            onToggle = vm::toggleTag,
            onCreate = vm::createTag,
            onDismiss = { tagPicker = false },
        )
    }
}

@Composable
private fun SshSection(
    state: HostEditorState,
    draft: HostDraft,
    vm: HostEditorViewModel,
    inherited: InheritedInfo?,
    identity: IdentityItem?,
) {
    SectionCard {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            FormField(
                draft.port?.toString() ?: "",
                { v -> vm.update { it.copy(port = v.filter(Char::isDigit).take(5).toUIntOrNull()?.takeIf { p -> p in 1u..65535u }?.toUShort()) } },
                stringResource(R.string.port),
                placeholder = inherited?.port?.toString() ?: "22",
                keyboard = KeyboardType.Number,
            )
            IdentityRow(state, draft, onPick = { id -> vm.update { it.copy(identityId = id) } })
            if (identity == null) {
                FormField(
                    draft.username,
                    { v -> vm.update { it.copy(username = v) } },
                    stringResource(R.string.username),
                    placeholder = inherited?.username ?: if (draft.sshId || inherited?.sshId == true) stringResource(R.string.ssh_id_handle) else stringResource(R.string.asked_on_connect),
                )
                PasswordField(
                                        password = draft.password,
                    hasPassword = draft.hasPassword,
                    inheritedHint = inherited?.hasPassword == true,
                    onChange = { v -> vm.update { it.copy(password = v) } },
                )
                PasswordField(
                    password = draft.totpSecret,
                    hasPassword = draft.hasTotp,
                    inheritedHint = inherited?.hasTotp == true,
                    onChange = { v -> vm.update { it.copy(totpSecret = v) } },
                    label = stringResource(R.string.totp_secret),
                    savedLabel = stringResource(R.string.totp_secret_saved),
                )
                KeyRow(state, draft, onPick = { id -> vm.update { it.copy(sshKeyId = id) } })
                SshIdRows(
                    sshId = draft.sshId,
                    keyType = draft.sshIdKeyType,
                    onSshId = { v -> vm.update { it.copy(sshId = v) } },
                    onKeyType = { v -> vm.update { it.copy(sshIdKeyType = v) } },
                    usernameHint = draft.username.isBlank() && inherited?.username.isNullOrBlank(),
                )
            } else {
                Text(
                    if (identity.sshId) {
                        stringResource(R.string.username_password_key_and_ssh_id_come_from, identity.label)
                    } else {
                        stringResource(R.string.username_password_and_key_come_from_the_identity, identity.label)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        RowDivider()
        SwitchRow(
            title = stringResource(R.string.agent_forwarding),
            checked = draft.agentForwarding,
            onCheckedChange = { v -> vm.update { it.copy(agentForwarding = v) } },
        )
        RowDivider()
        SwitchRow(
            title = stringResource(R.string.forward_x11),
            subtitle = stringResource(R.string.forward_x11_mobile_hint),
            checked = draft.forwardX11,
            onCheckedChange = { v -> vm.update { it.copy(forwardX11 = v) } },
        )
        RowDivider()
        SwitchRow(
            title = "Mosh",
            subtitle = stringResource(R.string.roaming_udp_session_ssh_only_starts_mosh_server),
            checked = draft.useMosh,
            onCheckedChange = { v -> vm.update { it.copy(useMosh = v) } },
        )
        if (draft.useMosh) {
            Box(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)) {
                FormField(
                    draft.moshServerCommand ?: "",
                    { v -> vm.update { it.copy(moshServerCommand = v.takeIf { c -> c.isNotBlank() }) } },
                    stringResource(R.string.mosh_server_command),
                    placeholder = remember { moshDefaultServerCommand() },
                )
            }
        }
        RowDivider()
        Box(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            CodingAgentRow(state, draft, onPick = vm::setCodingAgent)
        }
        if (state.snippets.isNotEmpty() || draft.startupSnippetId != null) {
            RowDivider()
            Box(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                StartupSnippetRow(state, draft, onPick = { id -> vm.update { it.copy(startupSnippetId = id) } })
            }
        }
        RowDivider()
        Box(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            ShellIntegrationRow(draft.shellIntegration) { v -> vm.update { it.copy(shellIntegration = v) } }
        }
        RowDivider()
        ServerKeySection(state, draft, vm, inherited)
    }
}

/**
 * Server keys pinned for `address:port`, grouped by the vault holding them.
 * Team-vault pins sync to every member, so an admin can hand out the trusted
 * fingerprint before anyone connects; a key contradicting any pin is refused.
 */
@Composable
private fun ServerKeySection(state: HostEditorState, draft: HostDraft, vm: HostEditorViewModel, inherited: InheritedInfo?) {
    val host = draft.address.trim()
    val port = draft.port ?: inherited?.port ?: 22u
    val vault = state.vaults.firstOrNull { it.id == draft.vaultId }
    val isTeam = vault?.kind == VaultKind.TEAM
    val canWrite = vault?.access != VaultAccess.VIEW
    var paste by remember { mutableStateOf(false) }
    var line by remember { mutableStateOf("") }
    LaunchedEffect(host, port) { vm.loadHostKeyPins(host, port) }

    val here = state.hostKeyPins.filter { it.vaultId == draft.vaultId }
    val elsewhere = state.hostKeyPins.filter { it.vaultId != draft.vaultId }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.server_key), style = MaterialTheme.typography.labelLarge)
        Text(
            when {
                host.isEmpty() -> stringResource(R.string.server_key_enter_address)
                state.hostKeyPins.isEmpty() -> stringResource(R.string.server_key_not_pinned)
                isTeam -> stringResource(R.string.server_key_team_hint)
                else -> stringResource(R.string.server_key_local_hint)
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        here.forEach { p ->
            PinRow(
                pin = p,
                where = if (isTeam) stringResource(R.string.server_key_where_team) else null,
                onRemove = if (canWrite) ({ vm.unpinHostKey(p.id, host, port) }) else null,
                enabled = !state.hostKeyPinsBusy,
            )
        }
        elsewhere.forEach { p ->
            val other = state.vaults.firstOrNull { it.id == p.vaultId }
            PinRow(
                pin = p,
                where = when (other?.kind) {
                    null -> stringResource(R.string.server_key_where_other)
                    VaultKind.LOCAL -> stringResource(R.string.server_key_where_device)
                    else -> other.name
                },
                onRemove = null,
                enabled = !state.hostKeyPinsBusy,
            )
        }
        state.hostKeyPinError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        if (canWrite && host.isNotEmpty()) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                if (elsewhere.isNotEmpty()) {
                    TextButton(enabled = !state.hostKeyPinsBusy, onClick = { vm.pinHostKey(host, port, null) }) {
                        Text(if (isTeam) stringResource(R.string.server_key_pin_for_team) else stringResource(R.string.server_key_pin_here))
                    }
                }
                TextButton(enabled = !state.hostKeyPinsBusy, onClick = { paste = !paste }) {
                    Text(if (paste) stringResource(R.string.cancel) else stringResource(R.string.server_key_paste))
                }
            }
        }
        if (paste) {
            OutlinedTextField(
                value = line,
                onValueChange = { line = it },
                label = { Text(stringResource(R.string.server_key_public_key)) },
                placeholder = { Text("ssh-ed25519 AAAA…") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace),
            )
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(
                    enabled = !state.hostKeyPinsBusy && line.isNotBlank(),
                    onClick = {
                        vm.pinHostKey(host, port, line)
                        paste = false
                        line = ""
                    },
                ) { Text(stringResource(R.string.server_key_pin)) }
            }
        }
    }
}

@Composable
private fun PinRow(pin: HostKeyPinItem, where: String?, onRemove: (() -> Unit)?, enabled: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Column(Modifier.weight(1f)) {
            Text(
                pin.fingerprint,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                listOfNotNull(pin.keyType, where).joinToString(" · "),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (onRemove != null) {
            IconButton(onClick = onRemove, enabled = enabled) {
                Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.server_key_unpin))
            }
        }
    }
}

/**
 * Per-host opt-in for the system file picker. The Settings switch stays the
 * master: a host is listed only when both are on.
 */
@Composable
private fun FilesSection(draft: HostDraft, vm: HostEditorViewModel, files: FilesIntegration?) {
    val filesEnabled = files?.enabled?.collectAsStateWithLifecycle()?.value ?: true
    SectionCard {
        SwitchRow(
            title = stringResource(R.string.show_in_files),
            subtitle = if (filesEnabled) {
                stringResource(R.string.show_in_files_summary)
            } else {
                stringResource(R.string.show_in_files_disabled_summary)
            },
            checked = draft.filesProvider,
            onCheckedChange = { v -> vm.update { it.copy(filesProvider = v) } },
        )
    }
}

@Composable
private fun CodingAgentRow(state: HostEditorState, draft: HostDraft, onPick: (String?) -> Unit) {
    val current = CodingAgents.selected(state.snippets, draft.startupSnippetId)
    PickerRow(
        label = stringResource(R.string.ai_coding_agent),
        value = current?.name ?: stringResource(R.string.none),
        options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) + CodingAgents.presets.map { it.id to it.name },
        selected = current?.id,
        onPick = onPick,
        empty = null,
    )
}

@Composable
private fun StartupSnippetRow(state: HostEditorState, draft: HostDraft, onPick: (String?) -> Unit) {
    val snippet = state.snippets.firstOrNull { it.id == draft.startupSnippetId }
    PickerRow(
        label = stringResource(R.string.startup_snippet),
        value = snippet?.label ?: if (draft.startupSnippetId != null) stringResource(R.string.unknown_snippet) else stringResource(R.string.none),
        options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) + state.snippets.map { it.id to it.label },
        selected = draft.startupSnippetId,
        onPick = onPick,
        empty = null,
    )
}

/** `http(s)://address[:port]/path/` the way the core builds it from the section. */
private fun webdavLink(address: String, w: WebDavDraft): String {
    val scheme = if (w.http) "http" else "https"
    val port = w.port?.let { ":$it" } ?: ""
    val path = "/" + w.path.trim().trim('/')
    return "$scheme://$address$port${if (path == "/") "/" else "$path/"}"
}

private fun hasAdvanced(d: HostDraft) =
    d.envVariables.isNotEmpty() || d.keepAliveInterval != null || d.timeout != null || d.notes.isNotBlank() || d.ipVersion != "auto" ||
        d.hostChainId != null || d.proxyId != null || d.colorScheme != null || d.charset != null || d.backspace != null ||
        d.shellIntegration != null

private fun tagSummary(draft: HostDraft, tags: List<TagItem>): String {
    val labels = draft.tagIds.mapNotNull { id -> tags.firstOrNull { it.id == id }?.label }
    return when {
        labels.isEmpty() -> str(R.string.none)
        labels.size <= 2 -> labels.joinToString(", ")
        else -> "${labels.take(2).joinToString(", ")} +${labels.size - 2}"
    }
}

/** Section title with an optional "Remove" for the protocol it heads. */
@Composable
private fun ProtocolHeader(title: String, removable: Boolean, onRemove: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.weight(1f)) { SectionLabel(title) }
        if (removable) {
            TextButton(onClick = onRemove) { Text(stringResource(R.string.remove_2)) }
        }
    }
}

/**
 * Password editor over the draft convention: `null` keeps the stored secret
 * ([hasPassword]), `""` clears it, anything else replaces it.
 */
/** Set by the open editor so every [PasswordField] asks the team policy before revealing. */
private var revealCheck: suspend () -> Boolean = { true }

@Composable
private fun PasswordField(
    password: String?,
    hasPassword: Boolean,
    inheritedHint: Boolean,
    onChange: (String?) -> Unit,
    label: String = stringResource(R.string.password),
    savedLabel: String = stringResource(R.string.password_saved),
    /** Team permission check before the secret is shown (client-enforced `secrets.reveal`). */
    reveal: suspend () -> Boolean = { revealCheck() },
) {
    var visible by remember { mutableStateOf(false) }
    val revealScope = rememberCoroutineScope()
    val stored = password == null && hasPassword
    FormField(
        value = password ?: "",
        onChange = { onChange(it) },
        label = if (stored) savedLabel else label,
        placeholder = when {
            stored -> "••••••••"
            inheritedHint -> stringResource(R.string.inherited_from_group)
            else -> null
        },
        keyboard = KeyboardType.Password,
        visual = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailing = {
            Row {
                if (hasPassword) {
                    TextButton(onClick = { onChange(if (stored) "" else null) }) {
                        Text(if (stored) stringResource(R.string.clear) else stringResource(R.string.keep_saved))
                    }
                }
                IconButton(onClick = {
                    if (visible) visible = false
                    else revealScope.launch { if (reveal()) visible = true }
                }) {
                    Icon(
                        if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = if (visible) stringResource(R.string.hide_password) else stringResource(R.string.show_password),
                    )
                }
            }
        },
    )
}

@Composable
private fun WebDavAuthRow(auth: String, onPick: (String) -> Unit) {
    val modes = listOf(
        WEBDAV_AUTH_PASSWORD to stringResource(R.string.webdav_auth_password),
        WEBDAV_AUTH_TOKEN to stringResource(R.string.webdav_auth_token),
    )
    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
        modes.forEachIndexed { i, (mode, title) ->
            SegmentedButton(
                selected = auth == mode,
                onClick = { onPick(mode) },
                shape = SegmentedButtonDefaults.itemShape(index = i, count = modes.size),
            ) { SegmentedLabel(title) }
        }
    }
}

/**
 * mTLS client certificate of a WebDAV section. Follows the draft convention:
 * `clientCertificate == null` keeps the stored pair ([WebDavDraft.clientCertificateFingerprint]
 * says whether there is one), `""` removes it, PEM text replaces it.
 */
@Composable
private fun TlsBlock(vm: HostEditorViewModel, webdav: WebDavDraft) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val pickPem = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch {
            runCatching { readTextFile(context, uri) }
                .onSuccess { text -> vm.updateWebdav { it.copy(caCertificate = text.trim().ifEmpty { null }) } }
                .onFailure { vm.showError(it.message ?: str(R.string.could_not_read_the_file)) }
        }
    }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.webdav_tls), style = MaterialTheme.typography.titleSmall)
        FormField(
            webdav.tlsServerName ?: "",
            { v -> vm.updateWebdav { it.copy(tlsServerName = v.trim().ifEmpty { null }) } },
            stringResource(R.string.webdav_tls_server_name),
            placeholder = "dav.internal",
            keyboard = KeyboardType.Uri,
        )
        Text(
            stringResource(R.string.webdav_tls_server_name_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(stringResource(R.string.webdav_ca_certificate), style = MaterialTheme.typography.bodyMedium)
        KeyTextArea(
            value = webdav.caCertificate ?: "",
            onChange = { v -> vm.updateWebdav { it.copy(caCertificate = v.ifBlank { null }) } },
            placeholder = stringResource(R.string.begin_certificate_placeholder),
            minLines = 3,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = {
                pasteText(context)?.let { text -> vm.updateWebdav { it.copy(caCertificate = text.trim().ifEmpty { null }) } }
                    ?: vm.showError(str(R.string.clipboard_is_empty))
            }) {
                Icon(Icons.Filled.ContentPaste, contentDescription = null, Modifier.height(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.paste))
            }
            TextButton(onClick = { pickPem.launch(arrayOf("*/*")) }) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null, Modifier.height(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.open_pem_file))
            }
        }
        Text(
            stringResource(R.string.webdav_ca_certificate_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FormField(
            webdav.certificateFingerprint ?: "",
            { v -> vm.updateWebdav { it.copy(certificateFingerprint = v.ifBlank { null }) } },
            stringResource(R.string.certificate_fingerprint_sha_256),
            placeholder = stringResource(R.string.system_trust_roots),
            keyboard = KeyboardType.Ascii,
        )
        Text(
            stringResource(R.string.webdav_fingerprint_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ClientCertificateBlock(vm: HostEditorViewModel, state: HostEditorState, webdav: WebDavDraft) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val saved = webdav.clientCertificateFingerprint
    val editing = webdav.clientCertificate != null
    val pickPem = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch {
            runCatching { readTextFile(context, uri) }
                .onSuccess(vm::importClientPem)
                .onFailure { vm.showError(it.message ?: str(R.string.could_not_read_the_file)) }
        }
    }

    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.webdav_client_certificate), style = MaterialTheme.typography.titleSmall)
        when {
            !editing && saved != null -> {
                Text(stringResource(R.string.webdav_client_certificate_saved), style = MaterialTheme.typography.bodyMedium)
                Text(saved, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { vm.updateWebdav { it.copy(clientCertificate = "", clientKey = null) } }) { Text(stringResource(R.string.replace)) }
                    TextButton(onClick = { vm.updateWebdav { it.copy(clientCertificate = "", clientKey = "") } }) { Text(stringResource(R.string.remove_2)) }
                }
            }
            !editing -> {
                Text(
                    stringResource(R.string.webdav_client_certificate_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(onClick = { vm.updateWebdav { it.copy(clientCertificate = "", clientKey = "") } }) {
                    Icon(Icons.Filled.Add, contentDescription = null)
                    Text(stringResource(R.string.add_client_certificate))
                }
            }
            else -> {
                KeyTextArea(
                    value = webdav.clientCertificate ?: "",
                    onChange = { v -> vm.updateWebdav { it.copy(clientCertificate = v) } },
                    placeholder = stringResource(R.string.begin_certificate_placeholder),
                    minLines = 3,
                )
                KeyTextArea(
                    value = webdav.clientKey ?: "",
                    onChange = { v -> vm.updateWebdav { it.copy(clientKey = v) } },
                    placeholder = if (saved != null && webdav.clientKey == null) stringResource(R.string.webdav_client_key_kept) else stringResource(R.string.begin_private_key_placeholder),
                    minLines = 3,
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { pasteText(context)?.let(vm::importClientPem) ?: vm.showError(str(R.string.clipboard_is_empty)) }) {
                        Icon(Icons.Filled.ContentPaste, contentDescription = null, Modifier.height(18.dp))
                        Text(stringResource(R.string.paste))
                    }
                    TextButton(onClick = { pickPem.launch(arrayOf("*/*")) }) {
                        Icon(Icons.Filled.FolderOpen, contentDescription = null, Modifier.height(18.dp))
                        Text(stringResource(R.string.open_file))
                    }
                    TextButton(onClick = { vm.updateWebdav { it.copy(clientCertificate = null, clientKey = null) } }) {
                        Text(if (saved != null) stringResource(R.string.keep_saved) else stringResource(R.string.cancel))
                    }
                }
                val fingerprint = state.clientCertificateFingerprint
                val error = state.clientCertificateError
                when {
                    fingerprint != null -> Text(
                        stringResource(R.string.webdav_client_certificate_ok, fingerprint),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    error != null -> Text(error, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    webdav.clientCertificate.isNullOrBlank() && saved != null -> Text(
                        stringResource(R.string.webdav_client_certificate_will_be_removed),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    stringResource(R.string.webdav_client_certificate_storage_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun KeyRow(state: HostEditorState, draft: HostDraft, onPick: (String?) -> Unit) {
    val key = state.keys.firstOrNull { it.id == draft.sshKeyId }
    PickerRow(
        label = stringResource(R.string.key),
        value = key?.label ?: state.inherited?.sshKeyLabel?.let { stringResource(R.string.inherited, it) } ?: stringResource(R.string.none),
        options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) + state.keys.map { it.id to "${it.label} · ${it.keyType}" },
        selected = draft.sshKeyId,
        onPick = onPick,
        empty = stringResource(R.string.no_keys_in_this_vault_yet_add_one),
    )
}

@Composable
private fun IdentityRow(state: HostEditorState, draft: HostDraft, onPick: (String?) -> Unit) {
    if (state.identities.isEmpty() && draft.identityId == null) return
    val identity = state.identities.firstOrNull { it.id == draft.identityId }
    PickerRow(
        label = stringResource(R.string.identity),
        value = identity?.label ?: state.inherited?.identityLabel?.let { stringResource(R.string.inherited, it) } ?: stringResource(R.string.none),
        options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) + state.identities.map { it.id to "${it.label} · ${it.username}" },
        selected = draft.identityId,
        onPick = onPick,
        empty = null,
    )
}

@Composable
private fun IpVersionRow(value: String, onPick: (String) -> Unit) {
    val options = listOf("auto" to stringResource(R.string.auto), "ipv4" to stringResource(R.string.ipv4_only), "ipv6" to stringResource(R.string.ipv6_only))
    PickerRow(
        label = stringResource(R.string.ip_version),
        value = options.firstOrNull { it.first == value }?.second ?: value,
        options = options.map { it.first to it.second },
        selected = value,
        onPick = { onPick(it ?: "auto") },
        empty = null,
    )
}

/**
 * Per-host override of the desktop's shell integration (OSC 133 hooks typed
 * after login): follow the app setting, always on, or off for routers, jump
 * hosts and hosts whose session is a program rather than a shell.
 */
@Composable
private fun ShellIntegrationRow(value: Boolean?, onPick: (Boolean?) -> Unit) {
    val options = listOf(
        "follow" to stringResource(R.string.host_shell_integration_follow),
        "on" to stringResource(R.string.host_shell_integration_on),
        "off" to stringResource(R.string.host_shell_integration_off),
    )
    val key = when (value) { null -> "follow"; true -> "on"; false -> "off" }
    PickerRow(
        label = stringResource(R.string.host_shell_integration),
        value = options.first { it.first == key }.second,
        options = options,
        selected = key,
        onPick = { onPick(when (it) { "on" -> true; "off" -> false; else -> null }) },
        empty = null,
    )
}

@Composable
private fun VaultRow(vaults: List<VaultInfo>, selected: String, onSelect: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxWidth()) {
        ListRow(
            title = vaults.firstOrNull { it.id == selected }?.let { vaultLabel(it) } ?: stringResource(R.string.vault),
            subtitle = stringResource(R.string.vault),
            modifier = Modifier.clickable { open = true },
        ) { Icon(Icons.Filled.ArrowDropDown, contentDescription = stringResource(R.string.choose_vault)) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            vaults.forEach { v ->
                DropdownMenuItem(text = { Text(vaultLabel(v)) }, onClick = { onSelect(v.id); open = false })
            }
        }
    }
}

@Composable
private fun TagPickerDialog(
    tags: List<TagItem>,
    selected: Set<String>,
    onToggle: (String) -> Unit,
    onCreate: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var newTag by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.tags)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                if (tags.isEmpty()) {
                    Text(stringResource(R.string.no_tags_yet), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                tags.sortedBy { it.label.lowercase() }.forEach { tag ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onToggle(tag.id) },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = tag.id in selected, onCheckedChange = { onToggle(tag.id) })
                        Text(tag.label, Modifier.weight(1f))
                        Text("${tag.hosts}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = newTag,
                    onValueChange = { newTag = it },
                    label = { Text(stringResource(R.string.new_tag)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    trailingIcon = {
                        IconButton(
                            onClick = { onCreate(newTag); newTag = "" },
                            enabled = newTag.isNotBlank(),
                        ) { Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.add_tag)) }
                    },
                )
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.done)) } },
    )
}
