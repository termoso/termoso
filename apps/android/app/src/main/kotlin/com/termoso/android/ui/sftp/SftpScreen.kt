package com.termoso.android.ui.sftp

import android.content.ActivityNotFoundException
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.termoso.android.R
import com.termoso.android.data.SftpConnection
import com.termoso.android.str
import com.termoso.android.ui.components.EmptyState
import com.termoso.android.ui.components.IconTile
import com.termoso.android.ui.components.ListRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.connectingLabel
import com.termoso.android.ui.components.groupRow
import com.termoso.android.ui.hosts.ConfirmDialog
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.android.ui.terminal.PromptDialog
import com.termoso.core.EntryKind
import com.termoso.core.FileProtocol
import com.termoso.core.SessionState
import com.termoso.core.SftpEntry
import com.termoso.core.TransferStatus
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch

/**
 * Remote file browser for one file connection (SFTP or WebDAV): breadcrumbs,
 * upload, long-press actions, "Open with" on tap, transfers sheet. Actions a
 * protocol lacks (permissions, edit in terminal, server-side copy) are hidden
 * per [SftpConnection.capabilities].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SftpScreen(
    shell: ShellViewModel,
    connectionId: String,
    onBack: () -> Unit,
    /** Open a terminal to the same host and run an editor on [path]. */
    onEdit: (SftpConnection, String) -> Unit,
) {
    val connections by shell.sftp.connections.collectAsStateWithLifecycle()
    var currentId by remember { mutableStateOf(connectionId) }
    val conn = connections.firstOrNull { it.id == currentId }
    // Leave the screen at most once: closing the connection also removes it from the list.
    var left by remember { mutableStateOf(false) }
    val leave: () -> Unit = { if (!left) { left = true; onBack() } }
    if (conn == null) {
        LaunchedEffect(Unit) { leave() }
        return
    }
    val context = LocalContext.current
    val vm: SftpViewModel = viewModel(key = "sftp/${conn.id}") { SftpViewModel(context.applicationContext, conn) }
    val state by vm.state.collectAsStateWithLifecycle()
    val connState by conn.state.collectAsStateWithLifecycle()
    val prompt by conn.prompt.collectAsStateWithLifecycle()
    val transfers by conn.transfers.collectAsStateWithLifecycle()
    val conflict by vm.conflict.collectAsStateWithLifecycle()
    val preview by vm.preview.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current

    var searching by remember { mutableStateOf(false) }
    var showTransfers by remember { mutableStateOf(false) }
    var dialog by remember { mutableStateOf<SftpDialog?>(null) }
    var pendingDownload by remember { mutableStateOf<List<SftpEntry>>(emptyList()) }

    val pickFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        vm.uploadDocuments(uris)
    }
    val pickFolder = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        uri?.let(vm::uploadTree)
    }
    val pickDownloadFolder = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) vm.downloadFolderChosen(uri, pendingDownload)
        pendingDownload = emptyList()
    }

    LaunchedEffect(vm) {
        vm.events.collect { ev ->
            when (ev) {
                is SftpUiEvent.Notice -> scope.launch { snackbar.showSnackbar(ev.text) }
                is SftpUiEvent.NeedDownloadFolder -> {
                    pendingDownload = ev.pending
                    scope.launch { snackbar.showSnackbar(str(R.string.choose_a_folder_for_downloads)) }
                    pickDownloadFolder.launch(null)
                }
                is SftpUiEvent.OpenFile -> try {
                    context.startActivity(LocalFiles.openWithIntent(context, ev.file))
                } catch (_: ActivityNotFoundException) {
                    scope.launch { snackbar.showSnackbar(str(R.string.no_app_can_open_use_download_to_save, ev.file.name)) }
                }
            }
        }
    }

    BackHandler(enabled = preview == null && (state.selecting || searching)) {
        if (state.selecting) vm.clearSelection() else { searching = false; vm.setQuery("") }
    }

    preview?.let { p ->
        FileViewer(
            preview = p,
            snackbar = snackbar,
            onEdit = vm::startEditing,
            onDraft = vm::editDraft,
            onSave = vm::saveEdits,
            onDiscard = vm::discardEdits,
            onOpenWith = { vm.openWith(p.entry) },
            onClose = vm::closePreview,
        )
        prompt?.let { pr -> PromptDialog(pr) { answer -> scope.launch { conn.answer(pr, answer) } } }
        return
    }

    fun copyPath(paths: List<String>) {
        clipboard.setText(AnnotatedString(paths.joinToString("\n")))
        scope.launch { snackbar.showSnackbar(if (paths.size == 1) str(R.string.path_copied) else str(R.string.paths_copied, paths.size)) }
        vm.clearSelection()
    }

    val active = transfers.count { it.status is TransferStatus.Running || it.status is TransferStatus.Queued }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            if (state.selecting) {
                SelectionBar(
                    state = state,
                    onClose = vm::clearSelection,
                    onSelectAll = vm::selectAll,
                    onDownload = { vm.download(state.selectedEntries) },
                    onCopyTo = { state.selectedEntries.singleOrNull()?.let { dialog = SftpDialog.CopyTo(it) } },
                    onRelay = { dialog = SftpDialog.RelayTo(state.selectedEntries) },
                    canRelay = connections.any { it.id != conn.id && it.state.value is SessionState.Connected },
                    onRename = { dialog = SftpDialog.Rename(state.selectedEntries.first()) },
                    onEdit = { onEdit(conn, state.selectedEntries.first().path); vm.clearSelection() },
                    onOpenWith = { vm.openWith(state.selectedEntries.first()) },
                    onPermissions = { dialog = SftpDialog.Permissions(state.selectedEntries.first()) },
                    onDuplicate = { vm.duplicate(state.selectedEntries.first()) },
                    onCopyPath = { copyPath(state.selectedEntries.map { it.path }) },
                    onRemove = { dialog = SftpDialog.Remove(state.selectedEntries) },
                    canChmod = conn.capabilities.permissions,
                    canEditInTerminal = conn.protocol == FileProtocol.SFTP,
                    canDuplicate = conn.capabilities.serverCopy,
                )
            } else {
                TopAppBar(
                    title = {
                        if (searching) {
                            SearchField(state.query, vm::setQuery)
                        } else {
                            Column {
                                Text(conn.label, maxLines = 1)
                                Text(
                                    when (conn.protocol) {
                                        FileProtocol.WEBDAV -> stringResource(R.string.webdav_target, conn.target)
                                        FileProtocol.LOCAL -> conn.target
                                        FileProtocol.SFTP -> conn.target
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                )
                            }
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = { if (searching) { searching = false; vm.setQuery("") } else leave() }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                        }
                    },
                    actions = {
                        if (!searching) {
                            IconButton(onClick = { searching = true }) { Icon(Icons.Filled.Search, contentDescription = stringResource(R.string.search)) }
                        }
                        IconButton(onClick = { showTransfers = true }) {
                            BadgedBox(badge = { if (active > 0) Badge { Text("$active") } }) {
                                Icon(Icons.Filled.SwapVert, contentDescription = stringResource(R.string.transfers))
                            }
                        }
                        OverflowMenu(
                            state = state,
                            downloadFolder = LocalFiles.downloadTreeLabel(context),
                            onNewFolder = { dialog = SftpDialog.NewFolder },
                            onSort = vm::setSort,
                            onToggleHidden = vm::toggleHidden,
                            onRefresh = vm::refresh,
                            onDownloadFolder = { pendingDownload = emptyList(); pickDownloadFolder.launch(null) },
                            onCopyPath = { copyPath(listOf(state.path)) },
                            onDisconnect = { scope.launch { shell.sftp.close(conn.id); leave() } },
                        )
                    },
                )
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            Column(Modifier.fillMaxSize()) {
                Breadcrumbs(path = state.path, onNavigate = vm::navigate)
                if (state.offline) {
                    Text(
                        stringResource(R.string.files_offline_read_only),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    )
                }
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    UploadButton(
                        enabled = connState is SessionState.Connected,
                        onFiles = { pickFiles.launch(arrayOf("*/*")) },
                        onFolder = { pickFolder.launch(null) },
                    )
                    Spacer(Modifier.weight(1f))
                    Text(
                        pluralStringResource(R.plurals.n_items, state.visible.size, state.visible.size),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                when {
                    state.loading && state.entries.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        if (connState is SessionState.Connected) CircularProgressIndicator()
                    }
                    state.visible.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        EmptyState(
                            title = if (state.query.isBlank()) stringResource(R.string.empty_folder) else stringResource(R.string.nothing_found),
                            hint = if (state.query.isBlank()) stringResource(R.string.upload_files_here_or_create_a_folder_from) else stringResource(R.string.try_another_name),
                            icon = if (state.query.isBlank()) Icons.Filled.FolderOpen else Icons.Filled.Search,
                        )
                    }
                    else -> EntryList(
                        state = state,
                        onTap = { e -> if (state.selecting) vm.toggle(e) else vm.open(e) },
                        onLongPress = vm::toggle,
                    )
                }
            }
            if (!state.offline) {
                StateOverlay(
                    state = connState,
                    target = conn.target,
                    onRetry = { scope.launch { shell.sftp.reconnect(conn.id)?.let { currentId = it.id } } },
                    onClose = { scope.launch { shell.sftp.close(conn.id); leave() } },
                    onBrowseOffline = if (state.offlineAvailable) vm::browseOffline else null,
                )
            }
        }
    }

    prompt?.let { p -> PromptDialog(p) { answer -> scope.launch { conn.answer(p, answer) } } }

    if (showTransfers) {
        TransfersSheet(
            transfers = transfers,
            onPause = vm::pauseTransfer,
            onResume = vm::resumeTransfer,
            onCancel = vm::cancelTransfer,
            onDismissCard = vm::dismissTransfer,
            onClearFinished = vm::clearFinishedTransfers,
            onClose = { showTransfers = false },
        )
    }

    conflict?.let { c ->
        AlertDialog(
            onDismissRequest = { vm.resolveConflict(ConflictChoice.Skip) },
            title = { Text(if (c.conflicting.size == 1) stringResource(R.string.file_already_exists) else stringResource(R.string.files_already_exist, c.conflicting.size)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    c.conflicting.take(5).forEach { Text(it.name, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
                    if (c.conflicting.size > 5) Text(stringResource(R.string.and_more, c.conflicting.size - 5), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(4.dp))
                    Text(stringResource(R.string.replace_the_remote_copy_keep_both_new_name), style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { vm.resolveConflict(ConflictChoice.KeepBoth) }) { Text(stringResource(R.string.keep_both)) }
                    Button(onClick = { vm.resolveConflict(ConflictChoice.Replace) }) { Text(stringResource(R.string.replace)) }
                }
            },
            dismissButton = { TextButton(onClick = { vm.resolveConflict(ConflictChoice.Skip) }) { Text(stringResource(R.string.skip)) } },
        )
    }

    when (val d = dialog) {
        null -> Unit
        SftpDialog.NewFolder -> NameDialog(
            title = stringResource(R.string.new_folder),
            initial = "",
            confirm = stringResource(R.string.create),
            onConfirm = { vm.mkdir(it); dialog = null },
            onDismiss = { dialog = null },
        )
        is SftpDialog.Rename -> NameDialog(
            title = stringResource(R.string.rename),
            initial = d.entry.name,
            confirm = stringResource(R.string.rename),
            onConfirm = { vm.rename(d.entry, it); vm.clearSelection(); dialog = null },
            onDismiss = { dialog = null },
        )
        is SftpDialog.CopyTo -> NameDialog(
            title = stringResource(R.string.copy_to),
            initial = d.entry.path,
            confirm = stringResource(R.string.copy_to),
            onConfirm = { vm.copyTo(d.entry, it); vm.clearSelection(); dialog = null },
            onDismiss = { dialog = null },
        )
        is SftpDialog.RelayTo -> RelayDialog(
            targets = connections.filter { it.id != conn.id && it.state.value is SessionState.Connected },
            count = d.entries.count { !it.isDir },
            onConfirm = { target, dir -> vm.relayTo(d.entries, target, dir); dialog = null },
            onDismiss = { dialog = null },
        )
        is SftpDialog.Remove -> ConfirmDialog(
            title = if (d.entries.size == 1) stringResource(R.string.remove, d.entries.first().name) else stringResource(R.string.remove_items, d.entries.size),
            text = if (d.entries.any { it.isDir }) {
                stringResource(R.string.folders_are_removed_with_everything_inside_this_cannot)
            } else {
                stringResource(R.string.this_cannot_be_undone)
            },
            confirm = stringResource(R.string.remove_2),
            onConfirm = { vm.remove(d.entries); vm.clearSelection(); dialog = null },
            onDismiss = { dialog = null },
        )
        is SftpDialog.Permissions -> PermissionsDialog(
            entry = d.entry,
            onConfirm = { mode -> vm.chmod(d.entry, mode); vm.clearSelection(); dialog = null },
            onDismiss = { dialog = null },
        )
    }
}

private sealed interface SftpDialog {
    data object NewFolder : SftpDialog
    data class Rename(val entry: SftpEntry) : SftpDialog
    data class CopyTo(val entry: SftpEntry) : SftpDialog
    data class RelayTo(val entries: List<SftpEntry>) : SftpDialog
    data class Remove(val entries: List<SftpEntry>) : SftpDialog
    data class Permissions(val entry: SftpEntry) : SftpDialog
}

/** Pick an open connection and a folder on it for a phone-relayed copy. */
@Composable
private fun RelayDialog(
    targets: List<SftpConnection>,
    count: Int,
    onConfirm: (SftpConnection, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var target by remember { mutableStateOf(targets.firstOrNull()) }
    var dir by remember(target) { mutableStateOf(target?.rust?.home()?.ifBlank { "/" } ?: "/") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.copy_to_another_server)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(pluralStringResource(R.plurals.n_files_will_be_copied_through_this_device, count, count), style = MaterialTheme.typography.bodySmall)
                targets.forEach { t ->
                    Row(
                        Modifier.fillMaxWidth().clickable { target = t }.padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = t.id == target?.id, onClick = { target = t })
                        Column(Modifier.padding(start = 4.dp)) {
                            Text(t.label, style = MaterialTheme.typography.bodyLarge)
                            Text(t.target, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
                OutlinedTextField(
                    value = dir,
                    onValueChange = { dir = it },
                    label = { Text(stringResource(R.string.destination_folder)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            Button(onClick = { target?.let { onConfirm(it, dir) } }, enabled = target != null && dir.isNotBlank()) {
                Text(stringResource(R.string.copy_action))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun Breadcrumbs(path: String, onNavigate: (String) -> Unit) {
    val segments = path.split('/').filter { it.isNotEmpty() }
    val listState = rememberLazyListState()
    LaunchedEffect(segments.size) { if (segments.isNotEmpty()) listState.animateScrollToItem(segments.size) }
    LazyRow(
        state = listState,
        modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceContainerLow),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        itemsIndexed(listOf("/") + segments) { i, seg ->
            if (i > 0) {
                Icon(
                    Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val target = if (i == 0) "/" else "/" + segments.take(i).joinToString("/")
            val last = i == segments.size
            AssistChip(
                onClick = { if (!last) onNavigate(target) },
                label = { Text(seg, style = MaterialTheme.typography.labelLarge) },
                leadingIcon = if (i == 0) {
                    { Icon(Icons.Filled.Folder, contentDescription = null, Modifier.width(16.dp)) }
                } else {
                    null
                },
            )
        }
    }
}

@Composable
private fun UploadButton(enabled: Boolean, onFiles: () -> Unit, onFolder: () -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        FilledTonalButton(onClick = { open = true }, enabled = enabled) {
            Icon(Icons.Filled.Upload, contentDescription = null, Modifier.width(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.upload))
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.upload_files)) },
                leadingIcon = { Icon(Icons.Filled.InsertDriveFile, null) },
                onClick = { open = false; onFiles() },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.upload_folder)) },
                leadingIcon = { Icon(Icons.Filled.Folder, null) },
                onClick = { open = false; onFolder() },
            )
        }
    }
}

/**
 * One lazy item per entry (keyed by path) so a directory with thousands of
 * files only composes the rows on screen; the grouped-card look is kept by
 * rounding the first/last row.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun EntryList(state: SftpUiState, onTap: (SftpEntry) -> Unit, onLongPress: (SftpEntry) -> Unit) {
    val entries = state.visible
    val listState = rememberLazyListState()
    LaunchedEffect(state.path) { listState.scrollToItem(0) }
    val dates = remember { DateFormat.getDateInstance(DateFormat.SHORT) }
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 32.dp),
    ) {
        itemsIndexed(entries, key = { _, e -> e.path }, contentType = { _, _ -> "entry" }) { i, e ->
            val selected = e.path in state.selected
            Column(Modifier.groupRow(top = i == 0, bottom = i == entries.lastIndex)) {
                if (i > 0) RowDivider()
                ListRow(
                    title = e.name,
                    subtitle = listOfNotNull(e.permissions, e.owner).joinToString(" · "),
                    leading = { IconTile(iconFor(e), selected = selected, tint = tintFor(e)) },
                    trailing = {
                        Column(horizontalAlignment = Alignment.End) {
                            Text(
                                if (e.isDir) "—" else formatSize(e.size),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.End,
                            )
                            Text(
                                e.modifiedMs?.let { dates.format(Date(it)) } ?: "",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.End,
                            )
                        }
                    },
                    modifier = Modifier.combinedClickable(onClick = { onTap(e) }, onLongClick = { onLongPress(e) }),
                )
            }
        }
    }
}

@Composable
private fun iconFor(e: SftpEntry) = when {
    e.kind == EntryKind.SYMLINK -> Icons.Filled.Link
    e.isDir -> Icons.Filled.Folder
    e.kind == EntryKind.OTHER -> Icons.Filled.Lock
    else -> Icons.Filled.InsertDriveFile
}

@Composable
private fun tintFor(e: SftpEntry) = if (e.isDir) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SelectionBar(
    state: SftpUiState,
    onClose: () -> Unit,
    onSelectAll: () -> Unit,
    onDownload: () -> Unit,
    onRename: () -> Unit,
    onCopyTo: () -> Unit,
    onRelay: () -> Unit,
    canRelay: Boolean,
    onEdit: () -> Unit,
    onOpenWith: () -> Unit,
    onPermissions: () -> Unit,
    onDuplicate: () -> Unit,
    onCopyPath: () -> Unit,
    onRemove: () -> Unit,
    canChmod: Boolean,
    canEditInTerminal: Boolean,
    canDuplicate: Boolean,
) {
    var menu by remember { mutableStateOf(false) }
    val one = state.selected.size == 1
    val single = state.selectedEntries.singleOrNull()
    TopAppBar(
        title = { Text(stringResource(R.string.selected_2, state.selected.size)) },
        navigationIcon = { IconButton(onClick = onClose) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.cancel_selection)) } },
        actions = {
            if (state.selectedEntries.any { !it.isDir }) {
                IconButton(onClick = onDownload) { Icon(Icons.Filled.Download, contentDescription = stringResource(R.string.download)) }
            }
            IconButton(onClick = onRemove) { Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.remove_2)) }
            Box {
                IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more)) }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    if (one) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.rename)) },
                            leadingIcon = { Icon(Icons.Filled.DriveFileRenameOutline, null) },
                            onClick = { menu = false; onRename() },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.copy_to)) },
                            leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                            onClick = { menu = false; onCopyTo() },
                        )
                    }
                    if (canRelay && state.selectedEntries.any { !it.isDir }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.copy_to_another_server)) },
                            leadingIcon = { Icon(Icons.Filled.SwapHoriz, null) },
                            onClick = { menu = false; onRelay() },
                        )
                    }
                    if (one) {
                        if (single != null && !single.isDir) {
                            if (canEditInTerminal) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.edit_in_terminal)) },
                                    leadingIcon = { Icon(Icons.Filled.Edit, null) },
                                    onClick = { menu = false; onEdit() },
                                )
                            }
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.open_with_2)) },
                                leadingIcon = { Icon(Icons.Filled.OpenInNew, null) },
                                onClick = { menu = false; onOpenWith() },
                            )
                        }
                        if (canDuplicate) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.duplicate)) },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                                onClick = { menu = false; onDuplicate() },
                            )
                        }
                        if (canChmod) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.change_permissions)) },
                                leadingIcon = { Icon(Icons.Filled.Lock, null) },
                                onClick = { menu = false; onPermissions() },
                            )
                        }
                    }
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.copy_path)) },
                        leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                        onClick = { menu = false; onCopyPath() },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.select_all)) },
                        leadingIcon = { Icon(Icons.Filled.Check, null) },
                        onClick = { menu = false; onSelectAll() },
                    )
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
    )
}

@Composable
private fun OverflowMenu(
    state: SftpUiState,
    downloadFolder: String?,
    onNewFolder: () -> Unit,
    onSort: (SftpSort) -> Unit,
    onToggleHidden: () -> Unit,
    onRefresh: () -> Unit,
    onDownloadFolder: () -> Unit,
    onCopyPath: () -> Unit,
    onDisconnect: () -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    var sortOpen by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }) { Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more)) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.new_folder)) },
                leadingIcon = { Icon(Icons.Filled.CreateNewFolder, null) },
                onClick = { open = false; onNewFolder() },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.sort_by, stringResource(state.sort.label))) },
                leadingIcon = { Icon(Icons.Filled.SwapVert, null) },
                onClick = { open = false; sortOpen = true },
            )
            DropdownMenuItem(
                text = { Text(if (state.showHidden) stringResource(R.string.hide_hidden_files) else stringResource(R.string.show_hidden_files)) },
                leadingIcon = { Icon(if (state.showHidden) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, null) },
                onClick = { open = false; onToggleHidden() },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.refresh)) },
                leadingIcon = { Icon(Icons.Filled.Refresh, null) },
                onClick = { open = false; onRefresh() },
            )
            DropdownMenuItem(
                text = {
                    Column {
                        Text(stringResource(R.string.download_folder))
                        Text(
                            downloadFolder ?: stringResource(R.string.not_chosen),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                leadingIcon = { Icon(Icons.Filled.FolderOpen, null) },
                onClick = { open = false; onDownloadFolder() },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.copy_path)) },
                leadingIcon = { Icon(Icons.Filled.ContentCopy, null) },
                onClick = { open = false; onCopyPath() },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.disconnect)) },
                leadingIcon = { Icon(Icons.Filled.OpenInNew, null) },
                onClick = { open = false; onDisconnect() },
            )
        }
        DropdownMenu(expanded = sortOpen, onDismissRequest = { sortOpen = false }) {
            SftpSort.entries.forEach { s ->
                DropdownMenuItem(
                    text = { Text(stringResource(s.label)) },
                    trailingIcon = if (s == state.sort) {
                        { Icon(Icons.Filled.Check, contentDescription = null) }
                    } else {
                        null
                    },
                    onClick = { sortOpen = false; onSort(s) },
                )
            }
        }
    }
}

@Composable
private fun SearchField(query: String, onChange: (String) -> Unit) {
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    OutlinedTextField(
        value = query,
        onValueChange = onChange,
        placeholder = { Text(stringResource(R.string.search_in_folder)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().focusRequester(focus),
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
    )
}

@Composable
private fun NameDialog(title: String, initial: String, confirm: String, onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var value by remember { mutableStateOf(initial) }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    val valid = value.isNotBlank() && !value.contains('/') && value != "." && value != ".."
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                label = { Text(stringResource(R.string.name)) },
                singleLine = true,
                isError = value.isNotEmpty() && !valid,
                modifier = Modifier.fillMaxWidth().focusRequester(focus),
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
            )
        },
        confirmButton = { TextButton(onClick = { onConfirm(value.trim()) }, enabled = valid) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun StateOverlay(
    state: SessionState,
    target: String,
    onRetry: () -> Unit,
    onClose: () -> Unit,
    onBrowseOffline: (() -> Unit)? = null,
) {
    val card: (@Composable () -> Unit)? = when (val s = state) {
        is SessionState.Connected -> null
        is SessionState.Connecting -> {
            {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.width(20.dp).height(20.dp), strokeWidth = 2.dp)
                    Column {
                        Text(target, style = MaterialTheme.typography.titleSmall)
                        Text(connectingLabel(s), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
        is SessionState.Closed -> {
            {
                Text(stringResource(R.string.connection_closed_2), style = MaterialTheme.typography.titleSmall)
                s.reason?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
                    Button(onClick = onRetry) { Text(stringResource(R.string.reconnect)) }
                }
            }
        }
        is SessionState.Failed -> {
            {
                Text(stringResource(R.string.connection_failed), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.error)
                Text(s.message, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
                    Button(onClick = onRetry) { Text(stringResource(R.string.retry)) }
                }
                if (onBrowseOffline != null) {
                    TextButton(onClick = onBrowseOffline) { Text(stringResource(R.string.files_browse_local_copies)) }
                }
            }
        }
    }
    if (card != null) {
        Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
            SectionCard { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) { card() } }
        }
    }
}

fun formatSize(size: ULong?): String {
    val b = size?.toDouble() ?: return "—"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var v = b
    var i = 0
    while (v >= 1024 && i < units.lastIndex) { v /= 1024; i++ }
    return if (i == 0) "${b.toLong()} B" else String.format(java.util.Locale.US, if (v < 10) "%.1f %s" else "%.0f %s", v, units[i])
}


