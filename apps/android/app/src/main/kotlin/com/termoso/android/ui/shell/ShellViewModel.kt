package com.termoso.android.ui.shell

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.termoso.android.R
import com.termoso.android.data.AiManager
import com.termoso.android.data.SessionManager
import com.termoso.android.data.Workspace
import com.termoso.android.data.WorkspaceTarget
import com.termoso.android.data.ForwardManager
import com.termoso.android.data.PresenceManager
import com.termoso.android.data.SftpConnection
import com.termoso.android.data.SftpManager
import com.termoso.android.data.TerminalSession
import com.termoso.android.data.VaultRepository
import com.termoso.android.data.userMessage
import com.termoso.android.str
import com.termoso.core.LocalShell
import com.termoso.core.FileProtocol
import com.termoso.core.MobileException
import com.termoso.core.QuickTarget
import com.termoso.core.SessionState
import com.termoso.core.SnippetRun
import com.termoso.core.Transport
import com.termoso.core.VaultInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import com.termoso.core.VaultKind
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/** Time for the shell to print its prompt before a snippet is typed into a fresh session. */
private const val SHELL_READY_DELAY_MS = 400L

/** Time for the last line to reach the server before a close-after-run snippet drops the session. */
private const val CLOSE_AFTER_RUN_DELAY_MS = 1_000L

/** Cross-tab state: the vault currently shown in Vaults → Hosts, open terminals, one-shot notices. */
class ShellViewModel(
    val repo: VaultRepository,
    val sessions: SessionManager,
    val sftp: SftpManager,
    val forwards: ForwardManager,
    val presence: PresenceManager,
    val ai: AiManager,
) : ViewModel() {
    private val _vaults = MutableStateFlow<List<VaultInfo>>(emptyList())
    /** Corporate mode (`/server/info` personal_vaults=false): the personal vault is not offered. */
    val hidePersonalVaults = MutableStateFlow(false)
    val vaults: StateFlow<List<VaultInfo>> =
        combine(_vaults, hidePersonalVaults) { list, hide ->
            if (hide) list.filter { it.kind != VaultKind.PERSONAL } else list
        }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _selectedVaultId = MutableStateFlow(repo.settings.value.selectedVaultId)
    val selectedVaultId: StateFlow<String?> = _selectedVaultId.asStateFlow()

    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice.asStateFlow()

    init {
        viewModelScope.launch {
            repo.revision.collect { reload() }
        }
    }

    /**
     * Refresh the vault list. The selection only moves when the list is
     * known and the vault is really gone (left the team, signed out); a
     * failed read keeps whatever the user had picked.
     */
    private suspend fun reload() {
        val list = runCatching { repo.read { vaults() } }.getOrNull() ?: return
        _vaults.value = list
        if (list.isNotEmpty() && list.none { it.id == _selectedVaultId.value }) {
            _selectedVaultId.value = list.first().id
        }
    }

    fun selectVault(id: String) {
        if (_selectedVaultId.value == id) return
        _selectedVaultId.value = id
        viewModelScope.launch {
            runCatching { repo.updateSettings { it.copy(selectedVaultId = id) } }
        }
    }

    fun notify(message: String) {
        _notice.value = message
    }

    /** Work started from a menu that dismisses itself first, so a composition scope would cancel it. */
    fun launch(block: suspend CoroutineScope.() -> Unit): Job = viewModelScope.launch(block = block)

    /**
     * Open a terminal to a saved host of the selected vault. Returns null
     * (after a notice) when Rust refuses to even start — the host is missing
     * or belongs to another vault; connection errors themselves arrive later
     * through the session state.
     */
    suspend fun connectHost(hostId: String, transport: Transport = Transport.AUTO): TerminalSession? =
        runCatching { connectHost(hostId, requireVault(), transport) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** Same, for a host of an explicit vault — the one an open connection to it was made from. */
    suspend fun connectHost(hostId: String, vaultId: String, transport: Transport = Transport.AUTO): TerminalSession? =
        runCatching { sessions.connectHost(hostId, vaultId, transport) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    private fun requireVault(): String =
        selectedVaultId.value ?: throw MobileException.NotFound(str(R.string.no_vault_selected))

    suspend fun connectQuick(target: QuickTarget): TerminalSession? =
        runCatching { sessions.connectQuick(target) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** Another tab to the same target as an open session. */
    suspend fun duplicateSession(id: String): TerminalSession? =
        runCatching { sessions.duplicate(id) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** Reopen every tab of a saved workspace or the previous session; returns how many opened. */
    suspend fun openWorkspace(targets: List<WorkspaceTarget>): Int =
        sessions.openWorkspace(targets) { notify(it.userMessage()) }

    /** Save the open tabs under [name]; null when nothing is worth saving. */
    fun saveWorkspace(name: String): Workspace? {
        val ws = sessions.workspaces?.save(name, sessions.sessions.value)
        if (ws == null) notify(str(R.string.workspace_nothing_to_save)) else notify(str(R.string.workspace_saved, ws.name))
        return ws
    }

    /** A shell on this device. */
    suspend fun connectLocal(): TerminalSession? =
        runCatching { sessions.connectLocal() }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** The plain Android shell, even when a Linux system is installed. */
    suspend fun connectAndroidShell(): TerminalSession? =
        runCatching { sessions.connectLocal(LocalShell(argv = listOf("/system/bin/sh"), home = "", env = emptyList())) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** A serial console over a USB-UART adapter. */
    suspend fun connectSerial(adapterKey: String, line: com.termoso.core.SerialLine): TerminalSession? =
        runCatching { sessions.connectSerial(adapterKey, line) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** Join a `termoso://join/…` share as a viewer; the link is validated in Rust. */
    suspend fun joinLive(link: String): TerminalSession? =
        runCatching { sessions.joinLive(link.trim()) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** Files browser for a saved host; `protocol` picks SFTP or WebDAV, `null` = the host's primary one. */
    suspend fun openSftpHost(hostId: String, protocol: FileProtocol? = null): SftpConnection? =
        runCatching { openSftpHost(hostId, requireVault(), protocol) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** Same, for a host of an explicit vault — the one an open session to it was made from. */
    suspend fun openSftpHost(hostId: String, vaultId: String, protocol: FileProtocol? = null): SftpConnection? =
        runCatching { sftp.openHost(hostId, vaultId, protocol) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /**
     * Whether the saved host lives in the vault the UI is showing. Lists built
     * from device-wide data (connection history) must check this before
     * connecting: a host of another vault must not be reachable from here.
     */
    suspend fun inSelectedVault(hostId: String): Boolean {
        val vaultId = selectedVaultId.value ?: return false
        return runCatching { repo.read { host(hostId) } }
            .map { it.vaultId == vaultId }
            .getOrDefault(false)
    }

    /** Whether "Connect" on this host means a terminal (false for WebDAV-only hosts, which open Files). */
    suspend fun hasTerminal(hostId: String): Boolean =
        runCatching { repo.read { host(hostId) } }
            .map { !it.protocol.equals("webdav", true) }
            .getOrDefault(true)

    /**
     * SFTP for an open terminal: reuses its SSH login (no prompts); a terminal
     * without one to reuse (Mosh, after a disconnect) falls back to a fresh
     * connection to the same host.
     */
    suspend fun openSftpSession(session: TerminalSession): SftpConnection? {
        val reused = runCatching { sftp.openSession(session) }.getOrNull()
        if (reused != null) return reused
        val hostId = session.hostId
        val vaultId = session.vaultId
        return when {
            hostId != null && vaultId != null -> openSftpHost(hostId, vaultId)
            session.quick != null -> openSftpQuick(session.quick)
            else -> null
        }
    }

    suspend fun openSftpQuick(target: QuickTarget): SftpConnection? =
        runCatching { sftp.openQuick(target) }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /** Files browser for the local shell's home directory; reuses the open one if there is any. */
    suspend fun openLocalFiles(): SftpConnection? =
        sftp.findLocal() ?: runCatching { sftp.openLocal() }
            .onFailure { notify(it.userMessage()) }
            .getOrNull()

    /**
     * Expand the snippet in Rust and type it into the given open terminals.
     * `paste` leaves out the trailing newline. Sessions the snippet asks to
     * close are dropped shortly after the text went out.
     */
    suspend fun runSnippet(
        snippetId: String,
        targets: List<TerminalSession>,
        vars: Map<String, String>,
        paste: Boolean,
    ): SnippetRun? {
        val run = runCatching { repo.read { runSnippet(snippetId, targets.map { it.rust }, vars, paste) } }
            .onFailure { notify(it.userMessage()) }
            .getOrNull() ?: return null
        if (run.closeAfterRun) {
            viewModelScope.launch {
                delay(CLOSE_AFTER_RUN_DELAY_MS)
                run.sessionIds.forEach { sessions.close(it) }
            }
        }
        return run
    }

    /** Open a terminal to a saved host and run the snippet once its shell is up. */
    suspend fun connectAndRunSnippet(
        hostId: String,
        snippetId: String,
        vars: Map<String, String>,
        paste: Boolean,
    ): TerminalSession? {
        val session = connectHost(hostId) ?: return null
        viewModelScope.launch {
            val state = session.state.first { it !is SessionState.Connecting }
            if (state is SessionState.Connected && sessions.find(session.id) != null) {
                delay(SHELL_READY_DELAY_MS)
                runSnippet(snippetId, listOf(session), vars, paste)
            }
        }
        return session
    }

    fun noticeShown() {
        _notice.value = null
    }
}
