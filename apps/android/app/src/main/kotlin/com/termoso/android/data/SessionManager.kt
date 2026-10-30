package com.termoso.android.data

import android.net.ConnectivityManager
import android.net.Network
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import com.termoso.android.R
import com.termoso.android.str
import com.termoso.android.ui.components.initialConnecting
import com.termoso.core.HostItem
import com.termoso.core.LiveEndReason
import com.termoso.core.LiveListener
import com.termoso.core.LiveParticipantCard
import com.termoso.core.LiveShare
import com.termoso.core.LocalShell
import com.termoso.core.SerialLine
import com.termoso.core.SerialLink
import com.termoso.core.SerialPipe
import com.termoso.android.data.serial.UsbSerial
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import com.termoso.core.PromptAnswer
import com.termoso.core.PromptRequest
import com.termoso.core.QuickTarget
import com.termoso.core.SessionListener
import com.termoso.core.SessionState
import com.termoso.core.SshSession
import com.termoso.core.TerminalOptions
import com.termoso.core.TerminalPalette
import com.termoso.core.TerminalTheme
import com.termoso.core.Transport
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/** Which adapter and line settings a serial console was opened with. */
data class SerialTarget(val adapterKey: String, val line: SerialLine)

@Suppress("DEPRECATION")
private inline fun <reified T : android.os.Parcelable> Intent.parcelable(key: String): T? =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) getParcelableExtra(key, T::class.java)
    else getParcelableExtra(key) as? T

/** A prompt the user has to answer before the connection can continue. */
data class PendingPrompt(val id: ULong, val request: PromptRequest)

/** One-shot signals from the remote that the UI reacts to once. */
sealed interface SessionEvent {
    data object Bell : SessionEvent

    /** OSC 52: the remote asked to place [text] on the clipboard. */
    data class Clipboard(val text: String) : SessionEvent
}

/**
 * Receives Rust callbacks (from tokio threads) and republishes them as flows the
 * UI collects on the main thread. Renders are conflated: the UI pulls one fresh
 * frame per tick it observes, no matter how many arrived in between.
 */
class SessionBridge : SessionListener {
    private val _state = MutableStateFlow<SessionState>(initialConnecting())
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val _frameTick = MutableStateFlow(0L)
    val frameTick: StateFlow<Long> = _frameTick.asStateFlow()

    private val _title = MutableStateFlow<String?>(null)
    val title: StateFlow<String?> = _title.asStateFlow()

    private val _prompt = MutableStateFlow<PendingPrompt?>(null)
    val prompt: StateFlow<PendingPrompt?> = _prompt.asStateFlow()

    private val _osName = MutableStateFlow<String?>(null)
    val osName: StateFlow<String?> = _osName.asStateFlow()

    private val _events = MutableSharedFlow<SessionEvent>(extraBufferCapacity = 16)
    val events: SharedFlow<SessionEvent> = _events.asSharedFlow()

    override fun onState(state: SessionState) {
        _state.value = state
        if (state !is SessionState.Connecting) _prompt.value = null
    }

    override fun onRender() {
        _frameTick.update { it + 1 }
    }

    override fun onPrompt(promptId: ULong, request: PromptRequest) {
        _prompt.value = PendingPrompt(promptId, request)
    }

    override fun onTitle(title: String?) {
        _title.value = title?.takeIf { it.isNotBlank() }
    }

    override fun onBell() {
        _events.tryEmit(SessionEvent.Bell)
    }

    override fun onClipboard(text: String) {
        _events.tryEmit(SessionEvent.Clipboard(text))
    }

    override fun onOsDetected(osName: String) {
        _osName.value = osName
    }

    /** Drop [id] from the UI; a newer prompt Rust already raised stays untouched. */
    fun promptAnswered(id: ULong) {
        _prompt.update { if (it?.id == id) null else it }
    }
}

/** One-shot multiplayer signals (host and viewer side). */
sealed interface LiveEvent {
    /** Viewer: the host granted ([canWrite]) or took back control. */
    data class Control(val canWrite: Boolean) : LiveEvent

    /** The share is over; the viewer's terminal closes right after. */
    data class Ended(val reason: LiveEndReason, val message: String) : LiveEvent
}

/**
 * Multiplayer state of one terminal: who is connected, whether we may type
 * (always true for the host) and the host's share handle while sharing. Rust
 * calls in from tokio threads; the UI collects the flows.
 */
class LiveBridge(viewer: Boolean = false) : LiveListener {
    private val _participants = MutableStateFlow<List<LiveParticipantCard>>(emptyList())
    val participants: StateFlow<List<LiveParticipantCard>> = _participants.asStateFlow()

    private val _canWrite = MutableStateFlow(!viewer)
    val canWrite: StateFlow<Boolean> = _canWrite.asStateFlow()

    private val _share = MutableStateFlow<LiveShare?>(null)
    val share: StateFlow<LiveShare?> = _share.asStateFlow()

    private val _ended = MutableStateFlow<LiveEvent.Ended?>(null)
    val ended: StateFlow<LiveEvent.Ended?> = _ended.asStateFlow()

    private val _events = MutableSharedFlow<LiveEvent>(extraBufferCapacity = 16)
    val events: SharedFlow<LiveEvent> = _events.asSharedFlow()

    /** User id of whoever typed last; emitted about once a second while they keep typing. */
    private val _typing = MutableSharedFlow<String>(extraBufferCapacity = 16)
    val typing: SharedFlow<String> = _typing.asSharedFlow()

    override fun onParticipants(participants: List<LiveParticipantCard>) {
        _participants.value = participants
    }

    override fun onControl(canWrite: Boolean) {
        _canWrite.value = canWrite
        _events.tryEmit(LiveEvent.Control(canWrite))
    }

    override fun onTyping(userId: String) {
        _typing.tryEmit(userId)
    }

    override fun onEnded(reason: LiveEndReason, message: String) {
        val ev = LiveEvent.Ended(reason, message)
        _ended.value = ev
        _share.value = null
        _participants.value = emptyList()
        _events.tryEmit(ev)
    }

    internal fun started(share: LiveShare) {
        _share.value = share
        _participants.value = share.participants()
    }

    internal fun stopped() {
        _share.value = null
        _participants.value = emptyList()
    }
}

/** A live terminal: the Rust session plus everything the UI needs to show it. */
class TerminalSession(
    val id: String,
    val label: String,
    val target: String,
    val hostId: String?,
    /** Vault of [hostId]; a reconnect must find the host there again. */
    val vaultId: String?,
    /** Set for quick-connect sessions (no saved host). */
    val quick: QuickTarget?,
    /** How the shell was opened; a reconnect keeps it. */
    val transport: Transport,
    /** OS saved on the host; [detectedOs] supersedes it once the shell opens. */
    val savedOsName: String?,
    val rust: SshSession,
    private val bridge: SessionBridge,
    /** True for a terminal joined from somebody's share: read-only until granted. */
    val isView: Boolean = false,
    /** Set for a shell running on this device. */
    val local: LocalShell? = null,
    /** Set for a USB-UART console; a reconnect reopens the same adapter. */
    val serial: SerialTarget? = null,
    private val live: LiveBridge = LiveBridge(),
) {
    val state: StateFlow<SessionState> get() = bridge.state
    val frameTick: StateFlow<Long> get() = bridge.frameTick
    val title: StateFlow<String?> get() = bridge.title
    val prompt: StateFlow<PendingPrompt?> get() = bridge.prompt
    val events: SharedFlow<SessionEvent> get() = bridge.events
    val detectedOs: StateFlow<String?> get() = bridge.osName

    val participants: StateFlow<List<LiveParticipantCard>> get() = live.participants
    val canWrite: StateFlow<Boolean> get() = live.canWrite
    val share: StateFlow<LiveShare?> get() = live.share
    val liveEnded: StateFlow<LiveEvent.Ended?> get() = live.ended
    val liveEvents: SharedFlow<LiveEvent> get() = live.events
    /** User id of the participant who just typed (host included, this device too). */
    val typing: SharedFlow<String> get() = live.typing

    /** Theme picked for this terminal only from the side panel; `null` follows the global setting. */
    val themeOverride = MutableStateFlow<String?>(null)

    /** Can be reconnected by us (not a view, has a target). */
    val reconnectable: Boolean get() = !isView && (hostId != null || quick != null || local != null || serial != null)

    internal val liveListener: LiveBridge get() = live

    suspend fun answer(prompt: PendingPrompt, answer: PromptAnswer): Boolean {
        bridge.promptAnswered(prompt.id)
        return withContext(Dispatchers.IO) { rust.answer(prompt.id, answer) }
    }
}

/**
 * Owns every open terminal for one unlocked vault. Connecting runs the Rust
 * connect on the IO dispatcher; the returned session drives itself from tokio.
 * The foreground service mirrors the session count so Android keeps the process
 * (and the sockets) alive while the user is in another app.
 */
/** Lines of the old screen shown above a reconnected shell. */
private const val CARRY_LINES = 300u

class SessionManager(
    private val context: Context,
    private val repo: VaultRepository,
    /** `HOME` and working directory of local shells; created on first use. */
    private val localHome: File,
    /** The optional Linux userland the default local shell runs in. */
    val linux: LinuxManager,
    /** Saved workspaces; told about every change so the last session can be restored. */
    val workspaces: Workspaces? = null,
) {
    private val _sessions = MutableStateFlow<List<TerminalSession>>(emptyList())
    val sessions: StateFlow<List<TerminalSession>> = _sessions.asStateFlow()

    private val _activeId = MutableStateFlow<String?>(null)
    val activeId: StateFlow<String?> = _activeId.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var reconnectJob: Job? = null

    init {
        watchNetwork()
    }

    /**
     * Auto-reconnect: when the device gets a (new) network, every remote session
     * that dropped on its own comes back. A session closed by the user is gone
     * from the list, so anything still here in Closed/Failed is an unexpected drop.
     */
    private fun watchNetwork() {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        var first = true
        runCatching {
            cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (first) {
                        first = false
                        return
                    }
                    reconnectDropped()
                }
            })
        }
    }

    private fun reconnectDropped() {
        if (!repo.settings.value.autoReconnect) return
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            // Let routes settle; a captive portal or DNS that is not up yet fails anyway.
            delay(1500)
            val dropped = _sessions.value.filter { s ->
                s.reconnectable && (s.hostId != null || s.quick != null) &&
                    s.state.value.let { it is SessionState.Closed || it is SessionState.Failed }
            }
            for (s in dropped) runCatching { reconnect(s.id) }
        }
    }

    val active: TerminalSession? get() = _sessions.value.firstOrNull { it.id == _activeId.value }

    fun find(id: String): TerminalSession? = _sessions.value.firstOrNull { it.id == id }

    fun setActive(id: String) {
        if (_sessions.value.any { it.id == id }) _activeId.value = id
    }

    /**
     * Connect a saved host. [vaultId] is the vault the caller took the host
     * from; Rust refuses a host of any other vault before reading credentials.
     */
    suspend fun connectHost(hostId: String, vaultId: String, transport: Transport = Transport.AUTO): TerminalSession {
        val host: HostItem = repo.read { host(hostId) }
        repo.perms.require(
            vaultId,
            when {
                transport == Transport.TELNET || host.protocol == "telnet" -> "connect.telnet"
                transport == Transport.MOSH || (transport == Transport.AUTO && host.useMosh) -> "connect.mosh"
                else -> "connect.ssh"
            },
        )
        val bridge = SessionBridge()
        val rust = repo.read { connectHost(hostId, vaultId, options(transport), bridge) }
        val telnet = transport == Transport.TELNET || host.protocol == "telnet"
        val user = host.username.takeIf { it.isNotBlank() && !telnet }?.let { "$it@" } ?: ""
        val mosh = !telnet && (transport == Transport.MOSH || (transport == Transport.AUTO && host.useMosh))
        val suffix = when {
            telnet -> " · Telnet"
            mosh -> " · Mosh"
            else -> ""
        }
        val target = "$user${host.address}:${if (telnet) host.telnetPort ?: host.port else host.port}$suffix"
        return register(
            TerminalSession(
                rust.id(),
                host.label.ifBlank { host.address },
                target,
                hostId,
                vaultId,
                null,
                if (telnet) Transport.TELNET else transport,
                host.osName,
                rust,
                bridge,
            ),
        )
    }

    suspend fun connectQuick(target: QuickTarget): TerminalSession {
        val bridge = SessionBridge()
        val telnet = target.protocol == "telnet"
        val transport = if (telnet) Transport.TELNET else Transport.SSH
        val rust = repo.read { connectQuick(target, options(transport), bridge) }
        val text = if (telnet) "${target.host}:${target.port} · Telnet" else listOf(target.username, "${target.host}:${target.port}").filter { it.isNotBlank() }.joinToString("@")
        return register(TerminalSession(rust.id(), target.host, text, null, null, target, transport, null, rust, bridge))
    }

    /**
     * A serial console over a USB-UART adapter. The adapter is opened here and
     * its bytes are pumped into the Rust terminal; the far side is whatever is
     * on the wire, so nothing is saved except the connection history.
     */
    suspend fun connectSerial(adapterKey: String, line: SerialLine): TerminalSession {
        repo.perms.requireAnywhere("connect.serial")
        val adapter = UsbSerial.find(context, adapterKey)
            ?: throw IllegalStateException(str(R.string.usb_adapter_not_found))
        if (!UsbSerial.requestPermission(context, adapter.device)) {
            throw IllegalStateException(str(R.string.usb_permission_denied))
        }
        val port = withContext(Dispatchers.IO) { UsbSerial.open(context, adapter, line) }
        val bridge = SessionBridge()
        lateinit var pipe: SerialPipe
        val link = object : SerialLink {
            override fun write(data: ByteArray) {
                runCatching { port.write(data) }
                    .onFailure { pipe.closed(it.message ?: str(R.string.usb_write_failed)) }
            }

            override fun release() {
                port.close()
            }
        }
        val opened = repo.read { connectSerial(adapter.key, adapter.name, line, link, options(Transport.SSH), bridge) }
        pipe = opened.pipe
        val reader = Thread({
            val buffer = ByteArray(4096)
            try {
                while (port.isOpen) {
                    val chunk = port.read(buffer) ?: break
                    if (chunk.isNotEmpty()) pipe.feed(chunk)
                }
                pipe.closed(null)
            } catch (e: Throwable) {
                pipe.closed(e.message ?: str(R.string.usb_read_failed))
            }
        }, "usb-serial-${adapter.key}")
        reader.isDaemon = true
        reader.start()
        val detach = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val gone = intent.parcelable<UsbDevice>(UsbManager.EXTRA_DEVICE) ?: return
                if (gone.deviceName != adapter.device.deviceName) return
                runCatching { ctx.unregisterReceiver(this) }
                port.close()
                pipe.closed(str(R.string.usb_adapter_unplugged))
            }
        }
        val filter = IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(detach, filter, Context.RECEIVER_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(detach, filter)
        }
        return register(
            TerminalSession(
                id = opened.session.id(),
                label = adapter.name,
                target = str(R.string.serial_target, line.baudRate.toLong(), adapter.driver.label),
                hostId = null,
                vaultId = null,
                quick = null,
                transport = Transport.SSH,
                savedOsName = null,
                rust = opened.session,
                bridge = bridge,
                serial = SerialTarget(adapter.key, line),
            ),
        )
    }

    /** A shell on this device (`/system/bin/sh` in [localHome] unless [shell] says otherwise). */
    suspend fun connectLocal(
        shell: LocalShell = LocalShell(argv = emptyList(), home = "", env = emptyList()),
        title: String? = null,
    ): TerminalSession {
        repo.perms.requireAnywhere("connect.local_terminal")
        // No program named: the installed Linux system when there is one, else the Android shell.
        val linuxShell = if (shell.argv.isEmpty()) linux.shell() else null
        val shell = linuxShell?.shell ?: shell
        val bridge = SessionBridge()
        val home = shell.home.ifBlank {
            withContext(Dispatchers.IO) { localHome.mkdirs() }
            localHome.absolutePath
        }
        val rust = repo.read { connectLocal(shell.copy(home = home), options(Transport.SSH), bridge) }
        val program = shell.argv.firstOrNull()?.substringAfterLast('/') ?: "sh"
        val target = title ?: linuxShell?.title ?: str(R.string.on_this_device, program)
        return register(
            TerminalSession(
                id = rust.id(),
                label = str(R.string.local),
                target = target,
                hostId = null,
                vaultId = null,
                quick = null,
                transport = Transport.SSH,
                savedOsName = "android",
                rust = rust,
                bridge = bridge,
                local = shell,
            ),
        )
    }

    /**
     * Join a `termoso://join/…` link as a viewer. The link is parsed in Rust;
     * Kotlin never sees the secret in its fragment separately.
     */
    suspend fun joinLive(link: String): TerminalSession {
        repo.perms.requireAnywhere("live.join")
        val bridge = SessionBridge()
        val live = LiveBridge(viewer = true)
        val rust = repo.read { joinLive(link, options(Transport.SSH), bridge, live) }
        return register(
            TerminalSession(
                id = rust.id(),
                label = str(R.string.shared_terminal),
                target = str(R.string.multiplayer),
                hostId = null,
                vaultId = null,
                quick = null,
                transport = Transport.SSH,
                savedOsName = null,
                rust = rust,
                bridge = bridge,
                isView = true,
                live = live,
            ),
        )
    }

    /** Start sharing [id]; returns the opaque join link. */
    suspend fun share(id: String): String {
        val session = find(id) ?: throw IllegalStateException("no such session")
        val share = repo.read { shareSession(session.rust, session.label, session.liveListener) }
        session.liveListener.started(share)
        return share.link()
    }

    suspend fun stopShare(id: String) {
        val session = find(id) ?: return
        val share = session.share.value ?: return
        session.liveListener.stopped()
        withContext(Dispatchers.IO) { runCatching { share.stop() } }
    }

    suspend fun setControl(id: String, userId: String, enabled: Boolean) {
        val share = find(id)?.share?.value ?: return
        withContext(Dispatchers.IO) { share.setControl(userId, enabled) }
    }

    /** Account went away: stop every share we host and leave every view. */
    suspend fun endLive() {
        val list = _sessions.value
        list.filter { it.share.value != null }.forEach { stopShare(it.id) }
        list.filter { it.isView }.forEach { close(it.id) }
    }

    /** A second tab to the same target as [id]; shared views cannot be duplicated. */
    suspend fun duplicate(id: String): TerminalSession? {
        val old = find(id) ?: return null
        return when {
            old.isView -> null
            old.hostId != null && old.vaultId != null -> connectHost(old.hostId, old.vaultId, old.transport)
            old.quick != null -> connectQuick(old.quick)
            old.local != null -> connectLocal(old.local, old.target)
            old.serial != null -> connectSerial(old.serial.adapterKey, old.serial.line)
            else -> null
        }
    }

    /** Replace a closed/failed session with a fresh connection to the same target. */
    suspend fun reconnect(id: String): TerminalSession? {
        val old = find(id) ?: return null
        // Carry the old screen over so the user keeps their context above the new prompt.
        val carried = withContext(Dispatchers.IO) { runCatching { old.rust.dumpText(CARRY_LINES) }.getOrDefault("") }
        val fresh = when {
            old.hostId != null && old.vaultId != null -> connectHost(old.hostId, old.vaultId, old.transport)
            old.quick != null -> connectQuick(old.quick)
            old.local != null -> connectLocal(old.local, old.target)
            old.serial != null -> connectSerial(old.serial.adapterKey, old.serial.line)
            else -> return null
        }
        _sessions.update { list -> list.filterNot { it.id == fresh.id }.map { if (it.id == id) fresh else it } }
        withContext(Dispatchers.IO) {
            runCatching { old.rust.disconnect() }
            if (carried.isNotBlank()) {
                runCatching { fresh.rust.preload(carried + "\r\n\u001b[2m" + "─".repeat(24) + " reconnected \u001b[0m\r\n") }
            }
        }
        return fresh
    }

    /** Recolour every open terminal after the scheme changed in Settings. */
    suspend fun applyPalette(palette: TerminalPalette) = withContext(Dispatchers.IO) {
        _sessions.value.filter { it.themeOverride.value == null }.forEach { runCatching { it.rust.setPalette(palette) } }
    }

    /** Recolour one terminal; a `null` theme reverts it to [fallback] (the global theme). */
    suspend fun applySessionTheme(session: TerminalSession, theme: TerminalTheme?, fallback: TerminalPalette) =
        withContext(Dispatchers.IO) {
            session.themeOverride.value = theme?.id
            runCatching { session.rust.setPalette(theme?.palette ?: fallback) }
        }

    private fun options(transport: Transport) = TerminalOptions(
        cols = 80u,
        rows = 24u,
        termType = "",
        palette = null,
        transport = transport,
    )

    private fun register(session: TerminalSession): TerminalSession {
        _sessions.update { it + session }
        _activeId.value = session.id
        workspaces?.record(_sessions.value)
        return session
    }

    /** Open every target of a workspace (or the previous session); failures are reported, not fatal. */
    suspend fun openWorkspace(targets: List<WorkspaceTarget>, onError: (Throwable) -> Unit): Int {
        var opened = 0
        for (t in targets) {
            runCatching {
                when (t) {
                    is WorkspaceTarget.Host -> connectHost(t.hostId, t.vaultId, t.transport)
                    is WorkspaceTarget.Quick -> connectQuick(t.target)
                    is WorkspaceTarget.Local -> connectLocal(t.shell, t.title)
                }
            }.onSuccess { opened++ }.onFailure(onError)
        }
        return opened
    }

    /** Disconnect and drop the tab. */
    suspend fun close(id: String) {
        val session = find(id) ?: return
        _sessions.update { list -> list.filterNot { it.id == id } }
        if (_activeId.value == id) _activeId.value = _sessions.value.lastOrNull()?.id
        workspaces?.record(_sessions.value)
        withContext(Dispatchers.IO) { runCatching { session.rust.disconnect() } }
    }

    /** Disconnect and drop several tabs at once; unknown ids are skipped. */
    suspend fun closeMany(ids: Collection<String>) {
        val wanted = ids.toSet()
        val closing = _sessions.value.filter { it.id in wanted }
        if (closing.isEmpty()) return
        _sessions.update { list -> list.filterNot { it.id in wanted } }
        if (_activeId.value in wanted) _activeId.value = _sessions.value.lastOrNull()?.id
        workspaces?.record(_sessions.value)
        withContext(Dispatchers.IO) { closing.forEach { runCatching { it.rust.disconnect() } } }
    }

    /** Every open tab to a saved host. */
    fun forHost(hostId: String): List<TerminalSession> = _sessions.value.filter { it.hostId == hostId }

    suspend fun closeAll() {
        val list = _sessions.value
        _sessions.value = emptyList()
        _activeId.value = null
        workspaces?.record(emptyList())
        withContext(Dispatchers.IO) { list.forEach { runCatching { it.rust.disconnect() } } }
    }
}
