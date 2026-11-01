package com.termoso.android.ui.hosts

import com.termoso.android.ui.keychain.AddKeyToHostFlow
import com.termoso.android.ui.components.distroVector
import com.termoso.android.ui.components.IconCatalog
import androidx.compose.ui.graphics.Color
import com.termoso.android.plural
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudQueue
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SortByAlpha
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import com.termoso.android.R
import com.termoso.android.data.VaultRepository
import com.termoso.android.ui.components.EmptyState
import com.termoso.android.ui.components.HostAvatar
import com.termoso.android.ui.components.CustomIconTile
import com.termoso.android.ui.components.IconTile
import com.termoso.android.ui.components.rememberCustomIcon
import com.termoso.android.ui.components.ListRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.SectionLabel
import com.termoso.android.ui.components.TermosoSwitch
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.android.ui.vault.VaultPickerTitle
import com.termoso.android.ui.vault.vaultLabel
import com.termoso.core.GroupItem
import com.termoso.core.HostItem
import com.termoso.core.Transport
import com.termoso.core.VaultInfo

/** Host list for a vault root or a group: search, sort, per-host actions (long-press / ⋯), multi-select, FAB. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun HostsScreen(
    shell: ShellViewModel,
    groupId: String?,
    onBack: () -> Unit,
    onOpenGroup: (String) -> Unit,
    onNewHost: () -> Unit,
    /** New-host form prefilled with an address typed into the empty state. */
    onNewHostFrom: (String) -> Unit = {},
    onEditHost: (String) -> Unit,
    onConnect: (String) -> Unit,
    /** Connect over an explicit transport (Mosh, the Telnet section). */
    onConnectWith: (String, Transport) -> Unit,
    onSftp: (String) -> Unit,
    onWebdav: (String) -> Unit,
    onOpenSftp: (String) -> Unit,
    onOpenTerminal: () -> Unit,
    onForward: (String) -> Unit,
) {
    val vm: HostsViewModel = viewModel(key = "hosts/${groupId ?: "root"}") {
        HostsViewModel(shell.repo, shell.selectedVaultId, groupId)
    }
    val state by vm.state.collectAsStateWithLifecycle()
    val vaults by shell.vaults.collectAsStateWithLifecycle()
    val selectedVaultId by shell.selectedVaultId.collectAsStateWithLifecycle()
    val vault = vaults.firstOrNull { it.id == selectedVaultId }
    val sessions by shell.sessions.sessions.collectAsStateWithLifecycle()
    val sftp by shell.sftp.connections.collectAsStateWithLifecycle()
    val openByHost = (sessions.mapNotNull { it.hostId } + sftp.mapNotNull { it.hostId }).groupingBy { it }.eachCount()
    val presence = rememberVaultPresence(shell, vault)
    val viewersByHost = remember(presence) { viewersByHost(presence) }
    val online = remember(viewersByHost) { viewersByHost.values.flatten().sortedBy { it.since } }

    LaunchedEffect(state.error) {
        state.error?.let { shell.notify(it); vm.errorShown() }
    }
    BackHandler(enabled = state.selecting) { vm.clearSelection() }

    var searching by remember { mutableStateOf(false) }
    var fabMenu by remember { mutableStateOf(false) }
    var dialog by remember { mutableStateOf<HostsDialog?>(null) }
    val otherVaults = vaults.filter { it.id != selectedVaultId && !it.locked }

    Scaffold(
        topBar = {
            if (state.selecting) {
                SelectionBar(
                    state = state,
                    vaults = otherVaults,
                    onClose = vm::clearSelection,
                    onSelectAll = vm::selectAll,
                    onEdit = { onEditHost(state.selected.first()) },
                    onSftp = {
                        val id = state.selected.first()
                        vm.clearSelection()
                        onSftp(id)
                    },
                    onWebdav = {
                        val id = state.selected.first()
                        vm.clearSelection()
                        onWebdav(id)
                    },
                    onConnectWith = { transport ->
                        val id = state.selected.first()
                        vm.clearSelection()
                        onConnectWith(id, transport)
                    },
                    onForward = {
                        val id = state.selected.first()
                        vm.clearSelection()
                        onForward(id)
                    },
                    onDuplicate = vm::duplicateSelected,
                    onMove = { dialog = HostsDialog.Move(state.selected.toList()) },
                    onCopy = { dialog = HostsDialog.Copy(state.selected.toList()) },
                    onDelete = { dialog = HostsDialog.Delete(state.selected.toList()) },
                )
            } else {
                val navigationIcon: @Composable () -> Unit = {
                    IconButton(onClick = { if (searching) { searching = false; vm.setQuery("") } else onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
                val actions: @Composable RowScope.() -> Unit = {
                    if (!searching) {
                        IconButton(onClick = { searching = true }) {
                            Icon(Icons.Filled.Search, contentDescription = stringResource(R.string.search))
                        }
                    }
                    SortMenu(state.sort, vm::setSort)
                }
                when {
                    searching -> TopAppBar(
                        title = { SearchField(state.query, vm::setQuery) },
                        navigationIcon = navigationIcon,
                        actions = actions,
                    )
                    // Vault root: the vault itself is the title and switches vaults, like Termius.
                    groupId == null -> CenterAlignedTopAppBar(
                        title = { VaultPickerTitle(vaults, selectedVaultId, shell::selectVault) },
                        navigationIcon = navigationIcon,
                        actions = actions,
                    )
                    else -> TopAppBar(
                        title = {
                            Column {
                                Text(state.group?.label ?: stringResource(R.string.hosts))
                                if (vault != null && vaults.size > 1) {
                                    Text(
                                        vaultLabel(vault),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                            }
                        },
                        navigationIcon = navigationIcon,
                        actions = actions,
                    )
                }
            }
        },
        floatingActionButton = {
            if (!state.selecting) {
                Box {
                    FloatingActionButton(onClick = { fabMenu = true }) {
                        Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.add))
                    }
                    DropdownMenu(expanded = fabMenu, onDismissRequest = { fabMenu = false }) {
                        // Create first, then "bring hosts in from somewhere".
                        DropdownMenuItem(text = { Text(stringResource(R.string.new_host)) }, onClick = { fabMenu = false; onNewHost() })
                        DropdownMenuItem(text = { Text(stringResource(R.string.new_group)) }, onClick = { fabMenu = false; dialog = HostsDialog.NewGroup })
                        HorizontalDivider()
                        DropdownMenuItem(text = { Text(stringResource(R.string.import_hosts)) }, onClick = { fabMenu = false; dialog = HostsDialog.QuickImport })
                        DropdownMenuItem(text = { Text(stringResource(R.string.discover_on_local_network)) }, onClick = { fabMenu = false; dialog = HostsDialog.Discover })
                    }
                }
            }
        },
    ) { padding ->
        when {
            state.loading -> Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            state.visibleGroups.isEmpty() && state.visibleHosts.isEmpty() -> Box(
                Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center,
            ) {
                if (state.query.isBlank()) {
                    // Termius-style first host: type the address right here, the form opens prefilled.
                    var address by rememberSaveable { mutableStateOf("") }
                    val go = { if (address.isNotBlank()) onNewHostFrom(address.trim()) }
                    EmptyState(
                        title = if (state.group == null) stringResource(R.string.no_hosts_yet) else stringResource(R.string.empty_group),
                        hint = stringResource(R.string.save_a_server_with_its_credentials_to_connect),
                        icon = Icons.Filled.Dns,
                        action = {
                            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                OutlinedTextField(
                                    value = address,
                                    onValueChange = { address = it },
                                    singleLine = true,
                                    placeholder = { Text(stringResource(R.string.type_ip_address_or_hostname)) },
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, capitalization = KeyboardCapitalization.None, imeAction = ImeAction.Go, autoCorrectEnabled = false),
                                    keyboardActions = KeyboardActions(onGo = { go() }),
                                    modifier = Modifier.fillMaxWidth(0.85f),
                                )
                                Button(onClick = go, enabled = address.isNotBlank(), modifier = Modifier.fillMaxWidth(0.85f)) { Text(stringResource(R.string.continue_)) }
                                TextButton(onClick = onNewHost) { Text(stringResource(R.string.add_host)) }
                            }
                        },
                    )
                } else {
                    EmptyState(
                        title = stringResource(R.string.nothing_found),
                        hint = stringResource(R.string.try_another_name_address_user_or_tag),
                        icon = Icons.Filled.Search,
                    )
                }
            }
            else -> HostList(
                repo = shell.repo,
                state = state,
                openByHost = openByHost,
                viewersByHost = viewersByHost,
                online = online,
                onOnline = { dialog = HostsDialog.Online },
                padding = padding,
                onOpenGroup = onOpenGroup,
                onGroupLongPress = { dialog = HostsDialog.GroupMenu(it) },
                onHostTap = { host ->
                    if (state.selecting) vm.toggle(host.id) else onConnect(host.id)
                },
                onHostLongPress = { host ->
                    if (state.selecting) vm.toggle(host.id) else dialog = HostsDialog.HostMenu(host)
                },
                onHostMenu = { dialog = HostsDialog.HostMenu(it) },
            )
        }
    }

    when (val d = dialog) {
        null -> Unit
        is HostsDialog.HostMenu -> HostActionsSheet(
            shell = shell,
            host = d.host,
            canCopyToVault = otherVaults.isNotEmpty(),
            onConnect = { transport -> if (transport == Transport.AUTO) onConnect(d.host.id) else onConnectWith(d.host.id, transport) },
            onSftp = { onSftp(d.host.id) },
            onWebdav = { onWebdav(d.host.id) },
            onOpenSftp = onOpenSftp,
            onOpenTerminal = onOpenTerminal,
            onForward = { onForward(d.host.id) },
            onEdit = { onEditHost(d.host.id) },
            onAddKey = { dialog = HostsDialog.AddKey(d.host) },
            onDuplicate = { vm.duplicate(listOf(d.host.id)) },
            onMove = { dialog = HostsDialog.Move(listOf(d.host.id)) },
            onMoveVault = { dialog = HostsDialog.MoveVault(listOf(d.host.id)) },
            onCopy = { dialog = HostsDialog.Copy(listOf(d.host.id)) },
            onSelect = { vm.toggle(d.host.id) },
            onDelete = { dialog = HostsDialog.Delete(listOf(d.host.id)) },
            onClose = { dialog = null },
        )
        is HostsDialog.AddKey -> AddKeyToHostFlow(shell.repo, d.host, onNotify = shell::notify, onDismiss = { dialog = null })
        is HostsDialog.Delete -> ConfirmDialog(
            title = if (d.ids.size == 1) stringResource(R.string.remove_host) else stringResource(R.string.remove_hosts, d.ids.size),
            text = stringResource(R.string.hosts_are_removed_from_this_vault_keys_in),
            confirm = stringResource(R.string.remove_2),
            onConfirm = { vm.delete(d.ids); dialog = null },
            onDismiss = { dialog = null },
        )
        is HostsDialog.Move -> GroupPickerDialog(
            title = stringResource(R.string.move_to),
            groups = state.allGroups,
            current = groupId,
            onPick = { vm.move(d.ids, it); dialog = null },
            onDismiss = { dialog = null },
        )
        is HostsDialog.Copy -> CopyToVaultDialog(
            vaults = otherVaults,
            onCopy = { v, creds -> vm.copy(d.ids, v, creds); dialog = null },
            onDismiss = { dialog = null },
        )
        is HostsDialog.MoveVault -> CopyToVaultDialog(
            vaults = otherVaults,
            move = true,
            onCopy = { v, creds -> vm.moveToVault(d.ids, v, creds); dialog = null },
            onDismiss = { dialog = null },
        )
        HostsDialog.NewGroup -> NameDialog(
            title = stringResource(R.string.new_group),
            initial = "",
            onConfirm = { vm.createGroup(it); dialog = null },
            onDismiss = { dialog = null },
        )
        is HostsDialog.GroupMenu -> GroupMenuDialog(
            group = d.group,
            onRename = { dialog = HostsDialog.RenameGroup(d.group) },
            onDelete = { vm.deleteGroup(d.group); dialog = null },
            onDismiss = { dialog = null },
        )
        is HostsDialog.RenameGroup -> NameDialog(
            title = stringResource(R.string.rename_group),
            initial = d.group.label,
            onConfirm = { vm.renameGroup(d.group, it); dialog = null },
            onDismiss = { dialog = null },
        )
        HostsDialog.QuickImport -> QuickImportSheet(parse = vm::parseImport, onImport = { items -> dialog = null; vm.importHosts(items) }, onDismiss = { dialog = null })
        HostsDialog.Discover -> DiscoverSheet(onPick = { t -> dialog = null; onNewHostFrom(t) }, onDismiss = { dialog = null })
        HostsDialog.Online -> {
            var labels by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
            LaunchedEffect(selectedVaultId) {
                val id = selectedVaultId ?: return@LaunchedEffect
                labels = runCatching { shell.repo.read { hosts(id) } }.getOrDefault(emptyList())
                    .associate { it.id to it.label.ifBlank { it.address } }
            }
            TeamOnlineSheet(
                repo = shell.repo,
                viewersByHost = viewersByHost,
                hostLabel = { labels[it] },
                onClose = { dialog = null },
            )
        }
    }
}

private sealed interface HostsDialog {
    data class HostMenu(val host: HostItem) : HostsDialog
    data class AddKey(val host: HostItem) : HostsDialog
    data class Delete(val ids: List<String>) : HostsDialog
    data class Move(val ids: List<String>) : HostsDialog
    data class Copy(val ids: List<String>) : HostsDialog
    data class MoveVault(val ids: List<String>) : HostsDialog
    data object NewGroup : HostsDialog
    data class GroupMenu(val group: GroupItem) : HostsDialog
    data class RenameGroup(val group: GroupItem) : HostsDialog
    data object Online : HostsDialog
    data object Discover : HostsDialog
    data object QuickImport : HostsDialog
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun HostList(
    repo: VaultRepository,
    state: HostsUiState,
    openByHost: Map<String, Int>,
    viewersByHost: Map<String, List<HostViewer>>,
    /** Teammates connected anywhere in the vault; empty outside team vaults. */
    online: List<HostViewer>,
    onOnline: () -> Unit,
    padding: PaddingValues,
    onOpenGroup: (String) -> Unit,
    onGroupLongPress: (GroupItem) -> Unit,
    onHostTap: (HostItem) -> Unit,
    onHostLongPress: (HostItem) -> Unit,
    onHostMenu: (HostItem) -> Unit,
) {
    val groups = state.visibleGroups
    val hosts = state.visibleHosts
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 96.dp),
    ) {
        if (groups.isNotEmpty()) {
            item { LabelWithOnline(stringResource(R.string.groups), repo, online, onOnline) }
            item {
                SectionCard {
                    groups.forEachIndexed { i, g ->
                        if (i > 0) RowDivider()
                        ListRow(
                            title = g.label,
                            subtitle = groupSubtitle(g),
                            leading = {
                                val picked = remember(g.icon) { IconCatalog.picked(g.icon) }
                                val custom = rememberCustomIcon(g.icon)
                                when {
                                    picked != null -> IconTile(distroVector(picked), tint = Color.White, container = picked.color)
                                    custom != null -> CustomIconTile(custom)
                                    else -> IconTile(Icons.Filled.Folder)
                                }
                            },
                            modifier = Modifier.combinedClickable(
                                onClick = { onOpenGroup(g.id) },
                                onLongClick = { onGroupLongPress(g) },
                            ),
                        )
                    }
                }
            }
        }
        if (hosts.isNotEmpty()) {
            item {
                if (groups.isEmpty()) {
                    LabelWithOnline(stringResource(R.string.hosts), repo, online, onOnline)
                } else {
                    SectionLabel(stringResource(R.string.hosts))
                }
            }
            item {
                SectionCard {
                    hosts.forEachIndexed { i, h ->
                        if (i > 0) RowDivider()
                        val selected = h.id in state.selected
                        ListRow(
                            title = h.label.ifBlank { h.address },
                            subtitle = hostSubtitle(h),
                            leading = { HostAvatar(h.osName, selected = selected, icon = h.icon) },
                            modifier = Modifier.combinedClickable(
                                onClick = { onHostTap(h) },
                                onLongClick = { onHostLongPress(h) },
                            ),
                        ) {
                            if (h.tags.isNotEmpty()) {
                                Text(
                                    h.tags.take(2).joinToString(" · "),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                            viewersByHost[h.id]?.let { PresenceStack(repo, it) }
                            openByHost[h.id]?.let { OpenSessionsBadge(it, onClick = { onHostMenu(h) }) }
                            if (!state.selecting) {
                                IconButton(onClick = { onHostMenu(h) }, modifier = Modifier.size(32.dp)) {
                                    Icon(
                                        Icons.Filled.MoreVert,
                                        contentDescription = stringResource(R.string.host_actions),
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** Section label with the team’s online avatars on the right (team vaults only). */
@Composable
private fun LabelWithOnline(text: String, repo: VaultRepository, online: List<HostViewer>, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        SectionLabel(text, Modifier.weight(1f))
        TeamOnlineStack(repo, online, onClick, Modifier.padding(top = 8.dp))
    }
}

/** “N open” pill on a host card while it has terminal sessions, like the Active badge in Termius. */
@Composable
private fun OpenSessionsBadge(count: Int, onClick: () -> Unit) {
    Row(
        Modifier
            .padding(start = 8.dp)
            .clip(RoundedCornerShape(999.dp))
            .background(MaterialTheme.colorScheme.primaryContainer)
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Box(Modifier.size(6.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary))
        Text(
            if (count == 1) stringResource(R.string.active) else stringResource(R.string.active_2, count),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
        )
    }
}

private fun groupSubtitle(g: GroupItem): String? {
    val parts = buildList {
        if (g.hostCount > 0u) add(plural(R.plurals.n_hosts, g.hostCount.toInt(), g.hostCount.toInt()))
        if (g.groupCount > 0u) add(plural(R.plurals.n_groups, g.groupCount.toInt(), g.groupCount.toInt()))
    }
    return parts.joinToString(" · ").ifEmpty { null }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SelectionBar(
    state: HostsUiState,
    vaults: List<VaultInfo>,
    onClose: () -> Unit,
    onSelectAll: () -> Unit,
    onEdit: () -> Unit,
    onSftp: () -> Unit,
    onWebdav: () -> Unit,
    onConnectWith: (Transport) -> Unit,
    onForward: () -> Unit,
    onDuplicate: () -> Unit,
    onMove: () -> Unit,
    onCopy: () -> Unit,
    onDelete: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    val single = state.visibleHosts.firstOrNull { it.id in state.selected }.takeIf { state.selected.size == 1 }
    val singleSsh = single?.protocol.equals("ssh", ignoreCase = true)
    val singleTelnet = singleSsh && single?.telnetPort != null
    val singleWebdav = single?.webdavUrl != null
    TopAppBar(
        title = { Text(stringResource(R.string.selected_2, state.selected.size)) },
        navigationIcon = {
            IconButton(onClick = onClose) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.cancel_selection)) }
        },
        actions = {
            if (state.selected.size == 1) {
                IconButton(onClick = onEdit) { Icon(Icons.Filled.Edit, contentDescription = stringResource(R.string.edit)) }
                if (singleSsh) {
                    IconButton(onClick = onSftp) { Icon(Icons.Filled.FolderOpen, contentDescription = "SFTP") }
                }
                if (singleWebdav) {
                    IconButton(onClick = onWebdav) { Icon(Icons.Filled.CloudQueue, contentDescription = stringResource(R.string.webdav_files)) }
                }
            }
            IconButton(onClick = onDelete) { Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.remove_2)) }
            Box {
                IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more)) }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.select_all)) },
                        leadingIcon = { Icon(Icons.Filled.Check, null) },
                        onClick = { menu = false; onSelectAll() },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.duplicate)) },
                        leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                        onClick = { menu = false; onDuplicate() },
                    )
                    if (singleSsh) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.connect_with_mosh)) },
                            leadingIcon = { Icon(Icons.Filled.Bolt, null) },
                            onClick = { menu = false; onConnectWith(Transport.MOSH) },
                        )
                        if (singleTelnet) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.connect_with_telnet)) },
                                leadingIcon = { Icon(Icons.Filled.Terminal, null) },
                                onClick = { menu = false; onConnectWith(Transport.TELNET) },
                            )
                        }
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.port_forwarding_2)) },
                            leadingIcon = { Icon(Icons.Filled.SwapHoriz, null) },
                            onClick = { menu = false; onForward() },
                        )
                    }
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.move_to_group)) },
                        leadingIcon = { Icon(Icons.AutoMirrored.Filled.DriveFileMove, null) },
                        onClick = { menu = false; onMove() },
                    )
                    if (vaults.isNotEmpty()) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.copy_to_vault)) },
                            leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                            onClick = { menu = false; onCopy() },
                        )
                    }
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
    )
}

@Composable
private fun SearchField(query: String, onChange: (String) -> Unit) {
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    OutlinedTextField(
        value = query,
        onValueChange = onChange,
        placeholder = { Text(stringResource(R.string.search_hosts)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().focusRequester(focus),
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
    )
}

@Composable
private fun SortMenu(sort: HostSort, onSort: (HostSort) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }) { Icon(Icons.Filled.SortByAlpha, contentDescription = stringResource(R.string.sort)) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            HostSort.entries.forEach { s ->
                DropdownMenuItem(
                    text = { Text(stringResource(s.label)) },
                    trailingIcon = if (s == sort) {
                        { Icon(Icons.Filled.Check, contentDescription = null) }
                    } else {
                        null
                    },
                    onClick = { onSort(s); open = false },
                )
            }
        }
    }
}

@Composable
fun ConfirmDialog(title: String, text: String, confirm: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(confirm, color = MaterialTheme.colorScheme.error) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun NameDialog(title: String, initial: String, onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                label = { Text(stringResource(R.string.name)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(value) }, enabled = value.isNotBlank()) { Text(stringResource(R.string.save)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun GroupMenuDialog(group: GroupItem, onRename: () -> Unit, onDelete: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(group.label) },
        text = {
            Column {
                Text(
                    stringResource(R.string.deleting_a_group_moves_its_hosts_and_sub),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            Row {
                TextButton(onClick = onRename) { Text(stringResource(R.string.rename)) }
                TextButton(onClick = onDelete) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** Flat list of groups with their path, plus “No group” at the top. */
@Composable
fun GroupPickerDialog(
    title: String,
    groups: List<GroupItem>,
    current: String?,
    onPick: (String?) -> Unit,
    onDismiss: () -> Unit,
) {
    val paths = remember(groups) { groupPaths(groups) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            LazyColumn(modifier = Modifier.fillMaxWidth().height(320.dp)) {
                item {
                    PickRow(stringResource(R.string.no_group), selected = current == null, onClick = { onPick(null) })
                }
                items(groups.sortedBy { paths[it.id] }, key = { it.id }) { g ->
                    PickRow(paths[g.id] ?: g.label, selected = g.id == current, onClick = { onPick(g.id) })
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

fun groupPaths(groups: List<GroupItem>): Map<String, String> {
    val byId = groups.associateBy { it.id }
    fun path(g: GroupItem): String {
        val parent = g.parentId?.let { byId[it] }
        return if (parent == null) g.label else "${path(parent)} / ${g.label}"
    }
    return groups.associate { it.id to path(it) }
}

@Composable
private fun PickRow(label: String, selected: Boolean, onClick: () -> Unit) {
    ListRow(
        title = label,
        modifier = Modifier.combinedClickable(onClick = onClick),
        titleColor = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
    ) {
        if (selected) Icon(Icons.Filled.Check, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun CopyToVaultDialog(vaults: List<VaultInfo>, onCopy: (String, Boolean) -> Unit, onDismiss: () -> Unit, move: Boolean = false) {
    var target by remember { mutableStateOf(vaults.firstOrNull()?.id) }
    var withCredentials by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (move) stringResource(R.string.move_to_vault) else stringResource(R.string.copy_to_vault_2)) },
        text = {
            Column {
                vaults.forEach { v ->
                    Row(
                        Modifier.fillMaxWidth().combinedClickable(onClick = { target = v.id }).padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = target == v.id, onClick = { target = v.id })
                        Text(vaultLabel(v))
                    }
                }
                Spacer(Modifier.height(12.dp))
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.include_credentials), fontWeight = FontWeight.Medium)
                        Text(
                            if (withCredentials) {
                                stringResource(R.string.passwords_and_keys_are_copied_into_the_target)
                            } else {
                                stringResource(R.string.only_host_details_are_copied_members_use_their)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TermosoSwitch(checked = withCredentials, onCheckedChange = { withCredentials = it })
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { target?.let { onCopy(it, withCredentials) } }, enabled = target != null) {
                Text(if (move) stringResource(R.string.move) else stringResource(R.string.copy))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
