package com.termoso.android.ui.hosts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.termoso.android.data.userMessage
import com.termoso.android.data.VaultRepository
import com.termoso.core.EnvVar
import com.termoso.core.GatewayCard
import com.termoso.core.GroupItem
import com.termoso.core.HostChainDraft
import com.termoso.core.HostChainItem
import com.termoso.core.HostDraft
import com.termoso.core.HostItem
import com.termoso.core.ProxyDraft
import com.termoso.core.SnippetDraft
import com.termoso.core.ProxyItem
import com.termoso.core.HostKeyPinItem
import com.termoso.core.IdentityItem
import com.termoso.core.InheritedInfo
import com.termoso.core.KeyItem
import com.termoso.core.QuickTarget
import com.termoso.core.SnippetItem
import com.termoso.core.TagItem
import com.termoso.core.TelnetDraft
import com.termoso.core.VaultInfo
import com.termoso.core.WebDavDraft
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import com.termoso.core.terminalThemes
import com.termoso.core.FileCacheSettings

/** [WebDavDraft.auth] values, as the store spells them. */
const val WEBDAV_AUTH_PASSWORD = "password"
const val WEBDAV_AUTH_TOKEN = "token"

/** A blank WebDAV section for "+ Add WebDAV". */
fun emptyWebDavDraft() = WebDavDraft(
    port = null,
    path = "",
    http = false,
    tlsServerName = null,
    caCertificate = null,
    username = "",
    password = null,
    identityId = null,
    certificateFingerprint = null,
    hasPassword = false,
    auth = WEBDAV_AUTH_PASSWORD,
    bearerToken = null,
    hasBearerToken = false,
    clientCertificate = null,
    clientKey = null,
    clientCertificateFingerprint = null,
)

/**
 * A fresh draft started from a quick-connect target ("Add to hosts" on an ad-hoc
 * terminal): address, user and port land in the matching protocol section; a
 * Telnet target gets a Telnet section instead of the SSH one.
 */
fun HostDraft.prefilled(target: QuickTarget?): HostDraft {
    if (target == null) return this
    return if (target.protocol.equals("telnet", true)) {
        copy(
            address = target.host,
            ssh = false,
            telnet = TelnetDraft(
                port = target.port.takeIf { it != 23.toUShort() },
                username = target.username,
                password = null,
                identityId = null,
                hasPassword = false,
            ),
        )
    } else {
        copy(
            address = target.host,
            username = target.username,
            port = target.port.takeIf { it != 22.toUShort() },
        )
    }
}

data class HostEditorState(
    val loading: Boolean = true,
    val draft: HostDraft? = null,
    val vaults: List<VaultInfo> = emptyList(),
    val groups: List<GroupItem> = emptyList(),
    val tags: List<TagItem> = emptyList(),
    val keys: List<KeyItem> = emptyList(),
    val identities: List<IdentityItem> = emptyList(),
    val snippets: List<SnippetItem> = emptyList(),
    val proxies: List<ProxyItem> = emptyList(),
    val chains: List<HostChainItem> = emptyList(),
    /** Team gateways the signed-in account can use; empty when offline or personal. */
    val gateways: List<GatewayCard> = emptyList(),
    /** One-line feedback under the connection block (Wake-on-LAN result). */
    val notice: String? = null,
    /** Hosts of the draft's vault, candidates for a jump chain. */
    val hosts: List<HostItem> = emptyList(),
    val inherited: InheritedInfo? = null,
    val saving: Boolean = false,
    /** The form is finished (saved, duplicated or removed) and should close. */
    val saved: Boolean = false,
    /** Id of the host just written by [HostEditorViewModel.save], for "save, then connect" flows. */
    val savedId: String? = null,
    /** Offline-copy settings (device-local, saved with the host); null until loaded. */
    val fileCache: FileCacheSettings? = null,
    val error: String? = null,
    /** Leaf SHA-256 of the WebDAV client certificate typed into the form, once it validated. */
    val clientCertificateFingerprint: String? = null,
    /** Why the typed WebDAV client certificate / key pair does not validate. */
    val clientCertificateError: String? = null,
    /** Server keys pinned for the draft's `address:port`, across all unlocked vaults. */
    val hostKeyPins: List<HostKeyPinItem> = emptyList(),
    val hostKeyPinsBusy: Boolean = false,
    val hostKeyPinError: String? = null,
) {
    val canSave: Boolean
        get() {
            val d = draft ?: return false
            if (saving) return false
            // Every section, WebDAV included, lives at the host's address.
            return d.address.isNotBlank()
        }
}

/**
 * New/edit host form over [HostDraft]. The draft is the only thing that holds a
 * password, and only when the user typed one; `null` keeps the stored secret.
 */
private val DEFAULT_FILE_CACHE = FileCacheSettings(
    allowed = true,
    enabled = false,
    maxFileMib = 32u,
    maxTotalMib = 512u,
    includePaths = emptyList(),
    excludePaths = emptyList(),
    serveOfflineWithoutAsking = false,
)

class HostEditorViewModel(
    private val repo: VaultRepository,
    private val hostId: String?,
    private val initialVault: String?,
    private val groupId: String?,
    /** For a new host: the quick-connect target (`user@host:port`, `telnet://host`) to start the form from. */
    private val prefill: QuickTarget? = null,
) : ViewModel() {
    /** Built-in colour schemes plus the user's own from the vault. */
    suspend fun allThemes() = runCatching { repo.read { terminalThemesAll(null) } }.getOrDefault(terminalThemes())

    private val _state = MutableStateFlow(HostEditorState())
    val state: StateFlow<HostEditorState> = _state.asStateFlow()

    init {
        viewModelScope.launch { load() }
    }

    private suspend fun load() {
        runCatching {
            repo.read {
                val vaults = vaults().filter { !it.locked }
                val draft = if (hostId != null) {
                    hostDraft(hostId)
                } else {
                    val vault = initialVault ?: vaults.first().id
                    newHostDraft(vault, groupId).prefilled(prefill)
                }
                HostEditorState(
                    loading = false,
                    draft = draft,
                    vaults = vaults,
                    groups = groups(draft.vaultId),
                    tags = tags(draft.vaultId),
                    keys = keys(draft.vaultId),
                    identities = identities(draft.vaultId),
                    snippets = snippets(draft.vaultId),
                    proxies = proxies(draft.vaultId),
                    chains = hostChains(draft.vaultId),
                    hosts = hosts(draft.vaultId),
                    inherited = inherited(draft.groupId),
                    fileCache = if (hostId != null) fileCacheSettings(hostId) else DEFAULT_FILE_CACHE,
                )
            }
        }.onSuccess { s -> _state.value = s }
            .onFailure { e -> _state.update { it.copy(loading = false, error = e.userMessage()) } }
    }

    fun updateFileCache(transform: (FileCacheSettings) -> FileCacheSettings) {
        _state.update { s -> s.copy(fileCache = s.fileCache?.let(transform)) }
    }

    fun update(transform: (HostDraft) -> HostDraft) {
        _state.update { s -> s.draft?.let { s.copy(draft = transform(it)) } ?: s }
    }

    private fun reloadConnection(vaultId: String) {
        viewModelScope.launch {
            runCatching { repo.read { Triple(proxies(vaultId), hostChains(vaultId), hosts(vaultId)) } }
                .onSuccess { (p, c, h) -> _state.update { it.copy(proxies = p, chains = c, hosts = h) } }
            runCatching { repo.read { gateways() } }
                .onSuccess { g -> _state.update { it.copy(gateways = g.filter { gw -> vaultId in gw.vaultIds }) } }
        }
    }

    /** Wake-on-LAN: broadcast a magic packet for the draft's MAC on the local network. */
    fun wake(mac: String, sent: String) {
        viewModelScope.launch {
            runCatching { repo.read { wakeHost(mac, null) } }
                .onSuccess { _state.update { it.copy(notice = sent) } }
                .onFailure { e -> _state.update { it.copy(notice = e.userMessage()) } }
        }
    }

    /** Pick a CLI coding agent to start on connect: reuse or create its startup snippet. */
    fun setCodingAgent(agentId: String?) {
        val s = _state.value
        val draft = s.draft ?: return
        val agent = CodingAgents.byId(agentId)
        if (agent == null) {
            if (CodingAgents.selected(s.snippets, draft.startupSnippetId) != null) update { it.copy(startupSnippetId = null) }
            return
        }
        s.snippets.firstOrNull { CodingAgents.of(it)?.id == agent.id }?.let { existing ->
            update { it.copy(startupSnippetId = existing.id) }
            return
        }
        viewModelScope.launch {
            runCatching {
                repo.write {
                    saveSnippet(
                        SnippetDraft(
                            id = null,
                            vaultId = draft.vaultId,
                            label = CodingAgents.snippetLabel(agent),
                            script = agent.command,
                            packageId = null,
                            closeAfterRun = false,
                            targetHostIds = emptyList(),
                        ),
                    )
                }
            }.onSuccess { created ->
                val list = runCatching { repo.read { snippets(draft.vaultId) } }.getOrDefault(s.snippets + created)
                _state.update { st -> st.copy(snippets = list, draft = st.draft?.copy(startupSnippetId = created.id)) }
            }.onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    fun saveProxy(draft: ProxyDraft, onSaved: (String) -> Unit) {
        viewModelScope.launch {
            runCatching { repo.write { saveProxy(draft) } }
                .onSuccess { id -> reloadConnection(draft.vaultId); onSaved(id) }
                .onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    fun deleteProxy(id: String) {
        val vaultId = _state.value.draft?.vaultId ?: return
        viewModelScope.launch {
            runCatching { repo.write { deleteProxy(id) } }
                .onSuccess { reloadConnection(vaultId) }
                .onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    fun saveChain(draft: HostChainDraft, onSaved: (String) -> Unit) {
        viewModelScope.launch {
            runCatching { repo.write { saveHostChain(draft) } }
                .onSuccess { id -> reloadConnection(draft.vaultId); onSaved(id) }
                .onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    fun deleteChain(id: String) {
        val vaultId = _state.value.draft?.vaultId ?: return
        viewModelScope.launch {
            runCatching { repo.write { deleteHostChain(id) } }
                .onSuccess { reloadConnection(vaultId) }
                .onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    fun loadHostKeyPins(host: String, port: UShort) {
        if (host.isBlank()) {
            _state.update { it.copy(hostKeyPins = emptyList(), hostKeyPinError = null) }
            return
        }
        viewModelScope.launch {
            runCatching { repo.read { hostKeyPins(host.trim(), port) } }
                .onSuccess { pins -> _state.update { it.copy(hostKeyPins = pins) } }
                .onFailure { e -> _state.update { it.copy(hostKeyPinError = e.userMessage()) } }
        }
    }

    /** Pin a pasted OpenSSH public key (or, with `null`, the keys trusted in other vaults) into the draft's vault. */
    fun pinHostKey(host: String, port: UShort, publicKey: String?) {
        val vaultId = _state.value.draft?.vaultId ?: return
        _state.update { it.copy(hostKeyPinsBusy = true, hostKeyPinError = null) }
        viewModelScope.launch {
            runCatching { repo.write { pinHostKey(vaultId, host.trim(), port, publicKey) } }
                .onSuccess { pins -> _state.update { it.copy(hostKeyPins = pins, hostKeyPinsBusy = false) } }
                .onFailure { e -> _state.update { it.copy(hostKeyPinsBusy = false, hostKeyPinError = e.userMessage()) } }
        }
    }

    fun unpinHostKey(id: String, host: String, port: UShort) {
        _state.update { it.copy(hostKeyPinsBusy = true, hostKeyPinError = null) }
        viewModelScope.launch {
            runCatching {
                repo.write { unpinHostKey(id) }
                repo.read { hostKeyPins(host.trim(), port) }
            }
                .onSuccess { pins -> _state.update { it.copy(hostKeyPins = pins, hostKeyPinsBusy = false) } }
                .onFailure { e -> _state.update { it.copy(hostKeyPinsBusy = false, hostKeyPinError = e.userMessage()) } }
        }
    }

    /** Edit the Telnet section; no-op while the host has none. */
    fun updateTelnet(transform: (TelnetDraft) -> TelnetDraft) = update { d ->
        d.telnet?.let { d.copy(telnet = transform(it)) } ?: d
    }

    /** Edit the WebDAV section; no-op while the host has none. */
    fun updateWebdav(transform: (WebDavDraft) -> WebDavDraft) {
        update { d -> d.webdav?.let { d.copy(webdav = transform(it)) } ?: d }
        validateClientCertificate()
    }

    /**
     * Split a pasted / picked PEM file into the client certificate and key
     * fields; a part the file does not contain leaves the field alone.
     */
    fun importClientPem(text: String) {
        viewModelScope.launch {
            runCatching { repo.read { splitClientPem(text) } }
                .onSuccess { parts ->
                    updateWebdav {
                        it.copy(
                            clientCertificate = parts.certificate.ifBlank { it.clientCertificate ?: "" },
                            clientKey = parts.privateKey.ifBlank { it.clientKey ?: "" },
                        )
                    }
                }
                .onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    private var certificateCheck: Job? = null

    private fun validateClientCertificate() {
        val w = _state.value.draft?.webdav
        val cert = w?.clientCertificate?.trim().orEmpty()
        val key = w?.clientKey?.trim().orEmpty()
        certificateCheck?.cancel()
        if (cert.isEmpty() || key.isEmpty()) {
            _state.update { it.copy(clientCertificateFingerprint = null, clientCertificateError = null) }
            return
        }
        certificateCheck = viewModelScope.launch {
            val result = runCatching { repo.read { inspectClientCertificate(cert, key) } }
            _state.update {
                it.copy(
                    clientCertificateFingerprint = result.getOrNull(),
                    clientCertificateError = result.exceptionOrNull()?.userMessage(),
                )
            }
        }
    }

    /** Switching vault (new hosts only) resets group/tags/key/identity, which are per-vault. */
    fun setVault(vaultId: String) {
        val current = _state.value.draft ?: return
        if (current.vaultId == vaultId || current.id != null) return
        viewModelScope.launch {
            runCatching {
                repo.read {
                    _state.value.copy(
                        draft = current.copy(
                            vaultId = vaultId,
                            groupId = null,
                            tagIds = emptyList(),
                            sshKeyId = null,
                            identityId = null,
                            startupSnippetId = null,
                        ),
                        groups = groups(vaultId),
                        tags = tags(vaultId),
                        keys = keys(vaultId),
                        identities = identities(vaultId),
                        snippets = snippets(vaultId),
                        proxies = proxies(vaultId),
                        chains = hostChains(vaultId),
                        hosts = hosts(vaultId),
                        inherited = inherited(null),
                    )
                }
            }.onSuccess { _state.value = it }
                .onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    fun setGroup(groupId: String?) {
        update { it.copy(groupId = groupId) }
        viewModelScope.launch {
            runCatching { repo.read { inherited(groupId) } }
                .onSuccess { inh -> _state.update { it.copy(inherited = inh) } }
        }
    }

    fun toggleTag(tagId: String) = update {
        it.copy(tagIds = if (tagId in it.tagIds) it.tagIds - tagId else it.tagIds + tagId)
    }

    fun createTag(label: String) {
        val draft = _state.value.draft ?: return
        viewModelScope.launch {
            runCatching { repo.write { createTag(draft.vaultId, label.trim()) } }
                .onSuccess { tag ->
                    _state.update { s ->
                        s.copy(
                            tags = (s.tags + tag).distinctBy { it.id },
                            draft = s.draft?.copy(tagIds = s.draft.tagIds + tag.id),
                        )
                    }
                }
                .onFailure { e -> _state.update { it.copy(error = e.userMessage()) } }
        }
    }

    fun setEnv(index: Int, name: String, value: String) = update {
        it.copy(envVariables = it.envVariables.toMutableList().apply { this[index] = EnvVar(name, value) })
    }

    fun addEnv() = update { it.copy(envVariables = it.envVariables + EnvVar("", "")) }

    fun removeEnv(index: Int) = update {
        it.copy(envVariables = it.envVariables.toMutableList().apply { removeAt(index) })
    }

    fun save() {
        val draft = _state.value.draft ?: return
        if (!_state.value.canSave) return
        _state.update { it.copy(saving = true) }
        viewModelScope.launch {
            val clean = draft.copy(
                label = draft.label.trim().ifBlank { draft.address.trim() },
                address = draft.address.trim(),
                username = draft.username.trim(),
                telnet = draft.telnet?.let { it.copy(username = it.username.trim()) },
                webdav = draft.webdav?.let {
                    val tokenMode = it.auth == WEBDAV_AUTH_TOKEN
                    it.copy(
                        path = it.path.trim(),
                        tlsServerName = it.tlsServerName?.trim()?.ifEmpty { null },
                        caCertificate = it.caCertificate?.trim()?.ifEmpty { null },
                        username = if (tokenMode) "" else it.username.trim(),
                        // Switching modes drops the other mode's secret.
                        password = if (tokenMode) "" else it.password,
                        bearerToken = if (tokenMode) it.bearerToken else "",
                        certificateFingerprint = it.certificateFingerprint?.trim()?.ifEmpty { null },
                        // A new certificate with an empty key field keeps the stored key (renewal).
                        clientKey = if (it.clientCertificateFingerprint != null) it.clientKey?.ifBlank { null } else it.clientKey,
                    )
                },
                envVariables = draft.envVariables.filter { it.name.isNotBlank() },
            )
            val fileCache = _state.value.fileCache
            runCatching {
                repo.write {
                    val host = saveHost(clean)
                    if (fileCache != null && (fileCache.enabled || hostId != null)) {
                        runCatching { setFileCacheSettings(host.id, fileCache) }
                    }
                    host
                }
            }
                .onSuccess { host -> _state.update { it.copy(saving = false, saved = true, savedId = host.id) } }
                .onFailure { e -> _state.update { it.copy(saving = false, error = e.userMessage()) } }
        }
    }

    /** Existing hosts only: a copy next to the original, then the form closes. */
    fun duplicate() = finishWith { id -> repo.write { duplicateHost(id) } }

    /** Existing hosts only: remove the host, then the form closes. */
    fun delete() = finishWith { id -> repo.write { deleteHosts(listOf(id)) } }

    private fun finishWith(block: suspend (String) -> Unit) {
        val id = _state.value.draft?.id ?: return
        _state.update { it.copy(saving = true) }
        viewModelScope.launch {
            runCatching { block(id) }
                .onSuccess { _state.update { it.copy(saving = false, saved = true) } }
                .onFailure { e -> _state.update { it.copy(saving = false, error = e.userMessage()) } }
        }
    }

    fun errorShown() = _state.update { it.copy(error = null) }

    fun showError(message: String) = _state.update { it.copy(error = message) }
}
