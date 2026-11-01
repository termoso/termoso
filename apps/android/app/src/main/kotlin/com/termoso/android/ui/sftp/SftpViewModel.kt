package com.termoso.android.ui.sftp

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.termoso.android.R
import com.termoso.android.data.SftpConnection
import com.termoso.android.data.userMessage
import com.termoso.android.saf.uniqueName
import com.termoso.android.str
import com.termoso.core.MobileException
import com.termoso.core.SessionState
import com.termoso.core.SftpEntry
import com.termoso.core.TransferCard
import com.termoso.core.TransferDirection
import com.termoso.core.TransferStatus
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class SftpSort(@StringRes val label: Int) {
    Name(R.string.name),
    Date(R.string.date),
    Size(R.string.size),
    Kind(R.string.kind),
}

data class SftpUiState(
    val path: String = "",
    val entries: List<SftpEntry> = emptyList(),
    val loading: Boolean = true,
    val showHidden: Boolean = false,
    val sort: SftpSort = SftpSort.Name,
    val query: String = "",
    /** Selected entry paths (long-press mode). */
    val selected: Set<String> = emptySet(),
    /** The host is unreachable and the cache has copies to browse. */
    val offlineAvailable: Boolean = false,
    /** Browsing offline copies: read-only, listings and files come from the cache. */
    val offline: Boolean = false,
) {
    val selecting: Boolean get() = selected.isNotEmpty()
    /** Filtered + sorted view of [entries]; computed once per state instance. */
    val visible: List<SftpEntry> by lazy {
        val filtered = entries.filter { (showHidden || !it.hidden) && (query.isBlank() || it.name.contains(query, ignoreCase = true)) }
        val byName = compareBy<SftpEntry> { it.name.lowercase() }
        val cmp: Comparator<SftpEntry> = when (sort) {
            SftpSort.Name -> byName
            SftpSort.Date -> compareByDescending<SftpEntry> { it.modifiedMs ?: 0L }.then(byName)
            SftpSort.Size -> compareByDescending<SftpEntry> { it.size ?: 0uL }.then(byName)
            SftpSort.Kind -> compareBy<SftpEntry> { it.name.substringAfterLast('.', "").lowercase() }.then(byName)
        }
        filtered.sortedWith(compareByDescending<SftpEntry> { it.isDir }.then(cmp))
    }
    val selectedEntries: List<SftpEntry> get() = entries.filter { it.path in selected }
}

/** Things the screen has to do with an Activity: open a file, show a notice. */
sealed interface SftpUiEvent {
    data class Notice(val text: String) : SftpUiEvent

    /** Launch Android "Open with" for this downloaded file. */
    data class OpenFile(val file: File) : SftpUiEvent

    /** No download folder chosen yet: ask the user to pick one, then retry [pending]. */
    data class NeedDownloadFolder(val pending: List<SftpEntry>) : SftpUiEvent
}

/** Uploads whose name already exists remotely; the user picks what to do with all of them. */
data class UploadConflict(val conflicting: List<PickedDocument>, val fresh: List<PickedDocument>)

enum class ConflictChoice { Replace, KeepBoth, Skip }

/** What to do with a download once Rust has finished writing the scratch file. */
private sealed interface Sink {
    data class SaveToTree(val tree: Uri) : Sink
    data object OpenWith : Sink
}

/** One remote directory browser bound to one connection. */
class SftpViewModel(private val appContext: Context, val conn: SftpConnection) : ViewModel() {
    private val _state = MutableStateFlow(SftpUiState())
    val state: StateFlow<SftpUiState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<SftpUiEvent>(extraBufferCapacity = 8)
    val events: SharedFlow<SftpUiEvent> = _events.asSharedFlow()

    private val _conflict = MutableStateFlow<UploadConflict?>(null)
    val conflict: StateFlow<UploadConflict?> = _conflict.asStateFlow()

    private val _preview = MutableStateFlow<PreviewState?>(null)
    /** File open in the in-app viewer/editor; survives list navigation until closed. */
    val preview: StateFlow<PreviewState?> = _preview.asStateFlow()

    private val sinks = HashMap<ULong, Sink>()
    private val scratchOf = HashMap<ULong, File>()
    /** Failures already announced, so re-emitted cards don't repeat the notice. */
    private val failed = HashSet<ULong>()
    private var scratchSeq = 0
    private var started = false

    init {
        viewModelScope.launch {
            conn.state.collect { s ->
                if (s is SessionState.Connected && !started) {
                    started = true
                    _state.update { it.copy(offline = false, offlineAvailable = false) }
                    navigate(conn.io { home() })
                }
                if (s is SessionState.Failed) {
                    val available = runCatching { conn.io { offlineCopiesAvailable() } }.getOrDefault(false)
                    _state.update { it.copy(offlineAvailable = available) }
                }
            }
        }
        viewModelScope.launch {
            conn.transfers.collect { cards -> cards.forEach { settle(it) } }
        }
    }

    // ───────────────────────────── navigation ─────────────────────────────

    /** Switch to the offline copies of this host (read-only); starts at the folder of the newest copy. */
    fun browseOffline() {
        viewModelScope.launch {
            val start = runCatching { conn.io { offlineCopies() } }.getOrDefault(emptyList())
                .firstOrNull()?.path?.substringBeforeLast('/')?.ifBlank { "/" } ?: "/"
            _state.update { it.copy(offline = true) }
            navigate(start)
        }
    }

    fun navigate(path: String) {
        viewModelScope.launch {
            _state.update { it.copy(loading = true, selected = emptySet(), query = "") }
            val offline = _state.value.offline
            val result = runCatching {
                val canonical = if (offline) path.trimEnd('/').ifBlank { "/" } else conn.io { canonicalize(path) }
                canonical to conn.io { list(canonical) }
            }
            result.onSuccess { (p, entries) -> _state.update { it.copy(path = p, entries = entries, loading = false) } }
                .onFailure { e ->
                    _state.update { it.copy(loading = false) }
                    notice(e.userMessage())
                }
        }
    }

    fun refresh() = navigate(_state.value.path.ifBlank { "~" })

    fun up() {
        val p = _state.value.path
        if (p.isBlank() || p == "/") return
        navigate(p.trimEnd('/').substringBeforeLast('/').ifBlank { "/" })
    }

    fun open(entry: SftpEntry) {
        if (entry.isDir) navigate(entry.path) else preview(entry)
    }

    // ───────────────────────────── viewer / editor ─────────────────────────────

    /** Text and images open in-app; anything else falls back to "Open with". */
    fun preview(entry: SftpEntry) {
        if (entry.isDir) return
        clearSelection()
        val kind = FilePreview.classify(entry.name, entry.size?.toLong())
        if (kind is PreviewKind.Unsupported) {
            notice(kind.reason)
            openWith(entry)
            return
        }
        _preview.value = PreviewState(entry)
        viewModelScope.launch {
            val loaded = runCatching {
                val bytes = conn.io { read(entry.path) }
                withContext(Dispatchers.Default) { decode(entry, kind, bytes) }
            }
            // The user may have closed the viewer (or opened another file) meanwhile.
            if (_preview.value?.entry?.path != entry.path) return@launch
            loaded.onSuccess { state ->
                if (state == null) {
                    _preview.value = null
                    notice(str(R.string.not_a_text_or_image_file))
                    openWith(entry)
                } else {
                    _preview.value = state
                }
            }.onFailure { e -> _preview.update { it?.copy(loading = false, error = e.userMessage()) } }
        }
    }

    private fun decode(entry: SftpEntry, kind: PreviewKind, bytes: ByteArray): PreviewState? =
        when (kind) {
            PreviewKind.Image -> FilePreview.decodeImage(bytes)?.let { PreviewState(entry, loading = false, image = it) }
            PreviewKind.Text, PreviewKind.Sniff -> {
                if (bytes.size > FilePreview.TEXT_LIMIT) return null
                FilePreview.decodeText(bytes)?.let { PreviewState(entry, loading = false, text = it) }
            }
            is PreviewKind.Unsupported -> null
        }

    fun startEditing() = _preview.update { p -> if (p?.text != null && p.draft == null) p.copy(draft = p.text) else p }

    fun editDraft(text: String) = _preview.update { p -> if (p?.editing == true) p.copy(draft = text) else p }

    /** Drop the buffer, back to read-only view. */
    fun discardEdits() = _preview.update { it?.copy(draft = null, error = null) }

    /** Upload the buffer over the same SFTP session; mode of the remote file is preserved by core. */
    fun saveEdits() {
        val p = _preview.value ?: return
        val draft = p.draft ?: return
        if (p.saving) return
        _preview.update { it?.copy(saving = true, error = null) }
        viewModelScope.launch {
            runCatching { conn.io { write(p.entry.path, draft.toByteArray(Charsets.UTF_8)) } }
                .onSuccess {
                    _preview.update { cur ->
                        if (cur?.entry?.path == p.entry.path) cur.copy(text = draft, draft = null, saving = false) else cur
                    }
                    notice(str(R.string.saved_2, p.entry.name))
                    if (p.entry.path.substringBeforeLast('/', "/").ifBlank { "/" } == _state.value.path) refresh()
                }
                .onFailure { e -> _preview.update { it?.copy(saving = false, error = e.userMessage()) } }
        }
    }

    fun closePreview() {
        _preview.value = null
    }

    fun toggle(entry: SftpEntry) = _state.update { s ->
        s.copy(selected = if (entry.path in s.selected) s.selected - entry.path else s.selected + entry.path)
    }

    fun clearSelection() = _state.update { it.copy(selected = emptySet()) }

    fun selectAll() = _state.update { s -> s.copy(selected = s.visible.map { it.path }.toSet()) }

    fun setQuery(q: String) = _state.update { it.copy(query = q) }

    fun setSort(sort: SftpSort) = _state.update { it.copy(sort = sort) }

    fun toggleHidden() = _state.update { it.copy(showHidden = !it.showHidden) }

    // ───────────────────────────── mutations ─────────────────────────────

    fun mkdir(name: String) = mutate(str(R.string.folder_created)) { mkdir(join(_state.value.path, name.trim())) }

    fun rename(entry: SftpEntry, newName: String) = mutate(null) {
        val parent = entry.path.substringBeforeLast('/', "")
        rename(entry.path, join(parent.ifBlank { "/" }, newName.trim()))
    }

    /** Server-side copy of [entry] to [target] (a full path, or a directory to copy into). */
    fun copyTo(entry: SftpEntry, target: String) = mutate(str(R.string.copied_2)) {
        val t = target.trim().ifBlank { entry.path }
        val dest = if (t.endsWith("/")) join(t, entry.name) else t
        copy(entry.path, dest)
    }

    fun remove(entries: List<SftpEntry>) = mutate(if (entries.size == 1) str(R.string.removed_2) else str(R.string.removed_items, entries.size)) {
        entries.forEach { remove(it.path) }
    }

    fun chmod(entry: SftpEntry, mode: UInt) = mutate(str(R.string.permissions_changed)) { chmod(entry.path, mode) }

    /** Server-side copy next to the original as `name (1)`, `name (2)`… (protocols with `serverCopy` only). */
    fun duplicate(entry: SftpEntry) {
        clearSelection()
        val parent = entry.path.substringBeforeLast('/', "").ifBlank { "/" }
        val taken = _state.value.entries.map { it.name }.toSet()
        val target = join(parent, uniqueName(entry.name, taken))
        mutate(str(R.string.copied_as, target.substringAfterLast('/'))) { copy(entry.path, target) }
    }

    private fun mutate(done: String?, block: com.termoso.core.SftpSession.() -> Unit) {
        viewModelScope.launch {
            runCatching { conn.io(block) }
                .onSuccess { done?.let(::notice); refresh() }
                .onFailure { notice(it.userMessage()) }
        }
    }

    // ───────────────────────────── downloads ─────────────────────────────

    /** Download into the chosen folder; asks for one first if none is set. */
    /**
     * Copy [entries] (files only) to [dir] on [target], streamed through the
     * phone without touching its storage; folders are skipped with a notice.
     */
    fun relayTo(entries: List<SftpEntry>, target: SftpConnection, dir: String) {
        val files = entries.filter { !it.isDir }
        if (files.size < entries.size) notice(str(R.string.folders_are_not_copied_between_servers))
        viewModelScope.launch(Dispatchers.IO) {
            for (e in files) conn.rust.relay(e.path, target.rust, join(dir.trim().ifBlank { "/" }, e.name))
            if (files.isNotEmpty()) notice(str(R.string.copying_to, files.size, target.label))
        }
        clearSelection()
    }

    fun download(entries: List<SftpEntry>) {
        val files = entries.filter { !it.isDir }
        if (files.size < entries.size) notice(str(R.string.folders_are_skipped_download_files_inside_them))
        if (files.isEmpty()) return
        val tree = LocalFiles.downloadTree(appContext)
        if (tree == null) {
            _events.tryEmit(SftpUiEvent.NeedDownloadFolder(files))
            return
        }
        clearSelection()
        viewModelScope.launch { files.forEach { start(it, Sink.SaveToTree(tree)) } }
    }

    fun downloadFolderChosen(tree: Uri, pending: List<SftpEntry>) {
        LocalFiles.setDownloadTree(appContext, tree)
        if (pending.isNotEmpty()) download(pending)
    }

    fun openWith(entry: SftpEntry) {
        if (entry.isDir) return
        clearSelection()
        viewModelScope.launch { start(entry, Sink.OpenWith) }
    }

    private suspend fun start(entry: SftpEntry, sink: Sink) {
        val scratch = conn.scratch("dl-${++scratchSeq}", entry.name)
        withContext(Dispatchers.IO) { scratch.parentFile?.mkdirs(); scratch.delete() }
        val id = conn.io { download(entry.path, scratch.absolutePath) }
        synchronized(sinks) {
            sinks[id] = sink
            scratchOf[id] = scratch
        }
        settleIfFinished(id)
    }

    // A tiny transfer can finish before its id comes back; the card is then already settled-looking.
    private fun settleIfFinished(id: ULong) {
        conn.transfers.value.firstOrNull { it.id == id && it.status.isFinished }?.let { settle(it) }
    }

    // ───────────────────────────── uploads ─────────────────────────────

    /** Files from the system picker; names that already exist remotely go through the conflict dialog. */
    fun uploadDocuments(uris: List<Uri>) {
        if (uris.isEmpty()) return
        viewModelScope.launch {
            val resolver = appContext.contentResolver
            val docs = withContext(Dispatchers.IO) { uris.map { LocalFiles.describe(resolver, it) } }
            val dir = _state.value.path
            val existing = _state.value.entries.map { it.name }.toSet()
            val (clash, fresh) = docs.partition { it.name in existing }
            if (clash.isEmpty()) {
                fresh.forEach { enqueueUpload(it, join(dir, it.name)) }
            } else {
                _conflict.value = UploadConflict(clash, fresh)
            }
        }
    }

    fun resolveConflict(choice: ConflictChoice) {
        val c = _conflict.value ?: return
        _conflict.value = null
        val dir = _state.value.path
        val taken = _state.value.entries.map { it.name }.toMutableSet()
        viewModelScope.launch {
            c.fresh.forEach { enqueueUpload(it, join(dir, it.name)) }
            when (choice) {
                ConflictChoice.Skip -> Unit
                ConflictChoice.Replace -> c.conflicting.forEach { enqueueUpload(it, join(dir, it.name)) }
                ConflictChoice.KeepBoth -> c.conflicting.forEach { doc ->
                    val name = uniqueName(doc.name, taken).also(taken::add)
                    enqueueUpload(doc, join(dir, name))
                }
            }
        }
    }

    /** A whole folder from the system picker: remote directories are created, files uploaded one by one. */
    fun uploadTree(tree: Uri) {
        viewModelScope.launch {
            val resolver = appContext.contentResolver
            val root = _state.value.path
            val result = runCatching {
                val name = withContext(Dispatchers.IO) { LocalFiles.treeName(resolver, tree) }
                val target = join(root, name)
                ensureRemoteDir(target)
                var count = 0
                suspend fun walk(documentId: String, remoteDir: String) {
                    val kids = withContext(Dispatchers.IO) { LocalFiles.children(resolver, tree, documentId) }
                    for (kid in kids) {
                        val remote = join(remoteDir, kid.name)
                        if (kid.isDir) {
                            ensureRemoteDir(remote)
                            walk(DocumentsContract.getDocumentId(kid.uri), remote)
                        } else {
                            enqueueUpload(PickedDocument(kid.uri, kid.name, kid.size), remote)
                            count++
                        }
                    }
                }
                walk(DocumentsContract.getTreeDocumentId(tree), target)
                count
            }
            result.onSuccess { n -> notice(if (n == 0) str(R.string.folder_created_no_files_inside) else str(R.string.uploading_files, n)); refresh() }
                .onFailure { notice(it.userMessage()) }
        }
    }

    private suspend fun ensureRemoteDir(path: String) {
        try {
            conn.io { mkdir(path) }
        } catch (e: MobileException) {
            val exists = runCatching { conn.io { stat(path) }.isDir }.getOrDefault(false)
            if (!exists) throw e
        }
    }

    private suspend fun enqueueUpload(doc: PickedDocument, remote: String) {
        val scratch = conn.scratch("ul-${++scratchSeq}", doc.name)
        val copied = runCatching {
            withContext(Dispatchers.IO) { LocalFiles.copyIn(appContext.contentResolver, doc.uri, scratch) }
        }
        if (copied.isFailure) {
            notice(str(R.string.cannot_read, doc.name, copied.exceptionOrNull()?.userMessage()))
            return
        }
        val id = conn.io { upload(scratch.absolutePath, remote) }
        synchronized(sinks) { scratchOf[id] = scratch }
        settleIfFinished(id)
    }

    // ───────────────────────────── transfers ─────────────────────────────

    fun pauseTransfer(id: ULong) {
        viewModelScope.launch { runCatching { conn.io { pauseTransfer(id) } } }
    }

    /** Paused or failed: continue from the bytes already on the destination. */
    fun resumeTransfer(id: ULong) {
        viewModelScope.launch { runCatching { conn.io { resumeTransfer(id) } } }
    }

    fun cancelTransfer(id: ULong) {
        viewModelScope.launch { runCatching { conn.io { cancelTransfer(id) } } }
    }

    fun dismissTransfer(id: ULong) {
        viewModelScope.launch { dismiss(id) }
    }

    fun clearFinishedTransfers() {
        val finished = conn.transfers.value.filter { it.status.isFinished }
        viewModelScope.launch { finished.forEach { dismiss(it.id) } }
    }

    private suspend fun dismiss(id: ULong) {
        if (runCatching { conn.dismissTransfer(id) }.getOrDefault(false).not()) return
        // A failed card keeps its partial file for Retry until it is dismissed.
        val scratch = synchronized(sinks) {
            failed.remove(id)
            sinks.remove(id)
            scratchOf.remove(id)
        }
        if (scratch != null) withContext(Dispatchers.IO) { scratch.delete() }
    }

    /** Runs once per settled card: move the scratch file where it was meant to go, then forget it. */
    private fun settle(card: TransferCard) {
        when (val st = card.status) {
            is TransferStatus.Failed -> {
                if (synchronized(sinks) { failed.add(card.id) }) notice("${card.name}: ${st.message}")
                return
            }
            is TransferStatus.Done, is TransferStatus.Cancelled -> Unit
            else -> {
                synchronized(sinks) { failed.remove(card.id) }
                return
            }
        }
        val (sink, scratch) = synchronized(sinks) {
            failed.remove(card.id)
            val s = sinks.remove(card.id)
            val f = scratchOf.remove(card.id)
            if (s == null && f == null) return
            s to f
        }
        viewModelScope.launch {
            when (card.status) {
                is TransferStatus.Done -> when (sink) {
                    is Sink.SaveToTree -> if (scratch != null) {
                        runCatching { withContext(Dispatchers.IO) { LocalFiles.saveToTree(appContext, sink.tree, scratch) } }
                            .onSuccess { notice(str(R.string.saved_to, card.name, LocalFiles.downloadTreeLabel(appContext) ?: str(R.string.download_folder))) }
                            .onFailure { notice(it.userMessage()) }
                        withContext(Dispatchers.IO) { scratch.delete() }
                    }
                    Sink.OpenWith -> if (scratch != null) _events.tryEmit(SftpUiEvent.OpenFile(scratch))
                    null -> {
                        if (scratch != null) withContext(Dispatchers.IO) { scratch.delete() }
                        if (card.remotePath.substringBeforeLast('/', "/").ifBlank { "/" } == _state.value.path) refresh()
                    }
                }
                else -> {
                    if (scratch != null) withContext(Dispatchers.IO) { scratch.delete() }
                    // Rust removed the remote partial of a cancelled upload.
                    if (card.direction == TransferDirection.UPLOAD &&
                        card.remotePath.substringBeforeLast('/', "/").ifBlank { "/" } == _state.value.path
                    ) {
                        refresh()
                    }
                }
            }
        }
    }

    fun notice(text: String) {
        _events.tryEmit(SftpUiEvent.Notice(text))
    }

    companion object {
        fun join(dir: String, name: String): String = if (dir.endsWith("/")) "$dir$name" else "$dir/$name"

        /** `report.pdf` → `report (1).pdf`, first free number. */
        fun uniqueName(name: String, taken: Set<String>): String {
            val dot = name.lastIndexOf('.')
            val (stem, ext) = if (dot > 0) name.substring(0, dot) to name.substring(dot) else name to ""
            var n = 1
            while (true) {
                val candidate = "$stem ($n)$ext"
                if (candidate !in taken) return candidate
                n++
            }
        }
    }
}
