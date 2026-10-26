package com.termoso.android.data

import android.content.Context
import com.termoso.core.LocalShell
import com.termoso.core.QuickTarget
import com.termoso.core.Transport
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject

/**
 * What a tab was opened to, enough to open it again. Mirrors the desktop
 * workspace templates: only targets are kept — never terminal contents,
 * credentials or the serial adapter (it has to be plugged in anyway).
 */
sealed interface WorkspaceTarget {
    data class Host(val hostId: String, val vaultId: String, val transport: Transport) : WorkspaceTarget
    data class Quick(val target: QuickTarget) : WorkspaceTarget
    data class Local(val shell: LocalShell, val title: String) : WorkspaceTarget
}

/** A named set of tabs the user saved to reopen together. */
data class Workspace(val id: String, val name: String, val targets: List<WorkspaceTarget>, val createdAt: Long)

/** The tabs open when the app last ran, offered for restore on the next start. */
data class LastSession(val savedAt: Long, val targets: List<WorkspaceTarget>)

/**
 * Named workspaces and the previous-session snapshot, in app-private
 * preferences (plain JSON: nothing here is secret, hosts are only referenced
 * by id and resolve against the encrypted store when opened).
 */
class Workspaces(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("workspaces", Context.MODE_PRIVATE)

    private val _templates = MutableStateFlow(loadTemplates())
    val templates: StateFlow<List<Workspace>> = _templates.asStateFlow()

    private val _previous = MutableStateFlow(loadPrevious())
    /** Non-null until restored or dismissed; cleared once any tab is open. */
    val previous: StateFlow<LastSession?> = _previous.asStateFlow()

    private var seenOpen = false

    fun save(name: String, sessions: List<TerminalSession>): Workspace? {
        val targets = sessions.mapNotNull(::targetOf)
        if (targets.isEmpty()) return null
        val ws = Workspace(UUID.randomUUID().toString(), name.trim(), targets, System.currentTimeMillis())
        _templates.value = _templates.value + ws
        persistTemplates()
        return ws
    }

    fun rename(id: String, name: String) {
        _templates.value = _templates.value.map { if (it.id == id) it.copy(name = name.trim()) else it }
        persistTemplates()
    }

    fun delete(id: String) {
        _templates.value = _templates.value.filterNot { it.id == id }
        persistTemplates()
    }

    /**
     * Called by [SessionManager] after every change. The first non-empty list
     * drops the restore offer (the user is working); an empty list is only
     * written once tabs were open, so a fresh start never wipes the snapshot.
     */
    fun record(sessions: List<TerminalSession>) {
        val targets = sessions.filterNot { it.isView }.mapNotNull(::targetOf)
        if (targets.isNotEmpty()) {
            seenOpen = true
            _previous.value = null
        }
        if (!seenOpen) return
        prefs.edit().putString(PREVIOUS, JSONObject().put("saved_at", System.currentTimeMillis()).put("targets", encodeAll(targets)).toString()).apply()
    }

    fun dismissPrevious() {
        _previous.value = null
        prefs.edit().remove(PREVIOUS).apply()
    }

    private fun persistTemplates() {
        val arr = JSONArray()
        for (w in _templates.value) {
            arr.put(JSONObject().put("id", w.id).put("name", w.name).put("created_at", w.createdAt).put("targets", encodeAll(w.targets)))
        }
        prefs.edit().putString(TEMPLATES, arr.toString()).apply()
    }

    private fun loadTemplates(): List<Workspace> = runCatching {
        val arr = JSONArray(prefs.getString(TEMPLATES, null) ?: return emptyList())
        (0 until arr.length()).mapNotNull { i ->
            val o = arr.getJSONObject(i)
            val targets = decodeAll(o.getJSONArray("targets"))
            if (targets.isEmpty()) null else Workspace(o.getString("id"), o.getString("name"), targets, o.optLong("created_at"))
        }
    }.getOrDefault(emptyList())

    private fun loadPrevious(): LastSession? = runCatching {
        val o = JSONObject(prefs.getString(PREVIOUS, null) ?: return null)
        val targets = decodeAll(o.getJSONArray("targets"))
        if (targets.isEmpty()) null else LastSession(o.optLong("saved_at"), targets)
    }.getOrNull()

    private fun encodeAll(targets: List<WorkspaceTarget>): JSONArray {
        val arr = JSONArray()
        for (t in targets) arr.put(encode(t))
        return arr
    }

    private fun encode(t: WorkspaceTarget): JSONObject = when (t) {
        is WorkspaceTarget.Host -> JSONObject().put("kind", "host").put("host_id", t.hostId).put("vault_id", t.vaultId).put("transport", t.transport.name)
        is WorkspaceTarget.Quick -> JSONObject().put("kind", "quick").put("host", t.target.host).put("port", t.target.port.toInt())
            .put("username", t.target.username).put("protocol", t.target.protocol)
        is WorkspaceTarget.Local -> JSONObject().put("kind", "local").put("argv", JSONArray(t.shell.argv)).put("home", t.shell.home)
            .put("env", JSONArray(t.shell.env)).put("title", t.title)
    }

    private fun decodeAll(arr: JSONArray): List<WorkspaceTarget> =
        (0 until arr.length()).mapNotNull { i -> runCatching { decode(arr.getJSONObject(i)) }.getOrNull() }

    private fun decode(o: JSONObject): WorkspaceTarget? = when (o.getString("kind")) {
        "host" -> WorkspaceTarget.Host(
            o.getString("host_id"),
            o.getString("vault_id"),
            runCatching { Transport.valueOf(o.optString("transport", "AUTO")) }.getOrDefault(Transport.AUTO),
        )
        "quick" -> WorkspaceTarget.Quick(
            QuickTarget(
                host = o.getString("host"),
                port = o.getInt("port").toUShort(),
                username = o.optString("username"),
                protocol = o.optString("protocol", "ssh"),
            ),
        )
        "local" -> WorkspaceTarget.Local(
            LocalShell(argv = o.getJSONArray("argv").strings(), home = o.optString("home"), env = o.getJSONArray("env").strings()),
            o.optString("title"),
        )
        else -> null
    }

    private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }

    private companion object {
        const val TEMPLATES = "templates"
        const val PREVIOUS = "previous"

        fun targetOf(s: TerminalSession): WorkspaceTarget? = when {
            s.isView -> null
            s.hostId != null && s.vaultId != null -> WorkspaceTarget.Host(s.hostId, s.vaultId, s.transport)
            s.quick != null -> WorkspaceTarget.Quick(s.quick)
            s.local != null -> WorkspaceTarget.Local(s.local, s.target)
            else -> null
        }
    }
}
