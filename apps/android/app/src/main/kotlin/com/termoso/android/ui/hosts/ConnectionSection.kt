package com.termoso.android.ui.hosts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.termoso.android.R
import com.termoso.android.ui.components.FormField
import com.termoso.android.ui.components.PickerRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SwitchRow
import com.termoso.core.HostChainDraft
import com.termoso.core.HostDraft
import com.termoso.core.GatewayCard
import com.termoso.core.ProxyDraft
import com.termoso.core.terminalThemes
import androidx.compose.runtime.produceState

/** Picker sentinel: "create a new one" entry. */
private const val NEW = "__new__"

/** Charsets offered per host, like Termius' "Select charset"; `null` is UTF-8. */
private val CHARSETS = listOf(
    "ISO-8859-1", "ISO-8859-2", "ISO-8859-5", "ISO-8859-15",
    "Windows-1250", "Windows-1251", "Windows-1252",
    "KOI8-R", "KOI8-U", "GBK", "GB18030", "Big5", "Shift_JIS", "EUC-JP", "EUC-KR",
)

private val PROXY_KINDS = listOf("socks5" to "SOCKS5", "socks4" to "SOCKS4", "http" to "HTTP")

/**
 * Termius-style "Connection" block of the host editor: jump chain, proxy,
 * colour scheme, charset and the Backspace mode — the SSH options that live in
 * the vault model but had no mobile UI.
 */
@Composable
fun ConnectionSection(state: HostEditorState, draft: HostDraft, vm: HostEditorViewModel) {
    var proxyEditor by remember { mutableStateOf<ProxyDraft?>(null) }
    var chainEditor by remember { mutableStateOf<HostChainDraft?>(null) }
    val themes by produceState(initialValue = terminalThemes()) { value = vm.allThemes() }

    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.connection), style = MaterialTheme.typography.labelLarge)

        val chain = state.chains.firstOrNull { it.id == draft.hostChainId }
        if (draft.ssh) PickerRow(
            label = stringResource(R.string.host_chaining),
            value = chain?.let { it.label.ifBlank { it.hostLabels.joinToString(" → ") } } ?: stringResource(R.string.none),
            options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) +
                state.chains.map { it.id to it.label.ifBlank { it.hostLabels.joinToString(" → ") } } +
                (NEW to stringResource(R.string.new_chain)),
            selected = draft.hostChainId,
            onPick = { id ->
                if (id == NEW) chainEditor = HostChainDraft(null, draft.vaultId, "", emptyList())
                else vm.update { it.copy(hostChainId = id) }
            },
            empty = null,
        )
        if (draft.ssh && chain != null) {
            EditLink { chainEditor = HostChainDraft(chain.id, chain.vaultId, chain.label, chain.hostIds) }
        }

        val proxy = state.proxies.firstOrNull { it.id == draft.proxyId }
        PickerRow(
            label = stringResource(R.string.proxy),
            value = proxy?.let { "${it.kind.uppercase()} ${it.host}:${it.port}" } ?: stringResource(R.string.none),
            options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) +
                state.proxies.map { it.id to "${it.kind.uppercase()} ${it.host}:${it.port}" } +
                (NEW to stringResource(R.string.new_proxy)),
            selected = draft.proxyId,
            onPick = { id ->
                if (id == NEW) proxyEditor = ProxyDraft(null, draft.vaultId, "socks5", "", 1080u, null, null, null)
                else vm.update { it.copy(proxyId = id) }
            },
            empty = null,
        )
        if (proxy != null) {
            EditLink { proxyEditor = ProxyDraft(proxy.id, proxy.vaultId, proxy.kind, proxy.host, proxy.port, proxy.identityId, proxy.username, proxy.password) }
        }

        if (draft.ssh && state.gateways.isNotEmpty()) {
            val online = stringResource(R.string.gateway_online)
            val offline = stringResource(R.string.gateway_offline)
            fun gwLabel(g: GatewayCard) = "${g.name} · ${if (g.online) online else offline}"
            val gw = state.gateways.firstOrNull { it.id == draft.gatewayId }
            PickerRow(
                label = stringResource(R.string.gateway),
                value = gw?.let { gwLabel(it) } ?: stringResource(R.string.none),
                options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) + state.gateways.map { it.id to gwLabel(it) },
                selected = draft.gatewayId,
                onPick = { id -> vm.update { it.copy(gatewayId = id) } },
                empty = null,
            )
        }
        if (draft.ssh) {
            val sent = stringResource(R.string.magic_packet_sent)
            val mac = draft.macAddress.orEmpty()
            FormField(
                mac,
                { v -> vm.update { it.copy(macAddress = v.ifBlank { null }) } },
                stringResource(R.string.mac_address),
                placeholder = "aa:bb:cc:dd:ee:ff",
                trailing = if (mac.isBlank()) null else {
                    { TextButton(onClick = { vm.wake(mac, sent) }) { Text(stringResource(R.string.wake)) } }
                },
            )
            state.notice?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (draft.ssh) PickerRow(
            label = stringResource(R.string.color_scheme),
            value = themes.firstOrNull { it.id == draft.colorScheme || it.name == draft.colorScheme }?.name
                ?: draft.colorScheme ?: stringResource(R.string.app_default),
            options = listOf<Pair<String?, String>>(null to stringResource(R.string.app_default)) + themes.map { it.id to it.name },
            selected = draft.colorScheme,
            onPick = { id -> vm.update { it.copy(colorScheme = id) } },
            empty = null,
        )
        if (draft.ssh) PickerRow(
            label = stringResource(R.string.charset),
            value = draft.charset ?: "UTF-8",
            options = listOf<Pair<String?, String>>(null to "UTF-8") + CHARSETS.map { it to it },
            selected = draft.charset,
            onPick = { id -> vm.update { it.copy(charset = id) } },
            empty = null,
        )
    }
    if (draft.ssh) RowDivider()
    if (draft.ssh) SwitchRow(
        title = stringResource(R.string.backspace_sends_ctrl_h),
        subtitle = stringResource(R.string.for_hosts_whose_shell_expects_h_instead_of_del),
        checked = draft.backspace == "ctrl-h",
        onCheckedChange = { v -> vm.update { it.copy(backspace = if (v) "ctrl-h" else null) } },
    )

    proxyEditor?.let { initial ->
        ProxyEditorDialog(
            initial = initial,
            state = state,
            onSave = { d -> vm.saveProxy(d) { id -> vm.update { it.copy(proxyId = id) } }; proxyEditor = null },
            onDelete = initial.id?.let { id -> { vm.deleteProxy(id); vm.update { it.copy(proxyId = null) }; proxyEditor = null } },
            onDismiss = { proxyEditor = null },
        )
    }
    chainEditor?.let { initial ->
        ChainEditorDialog(
            initial = initial,
            state = state,
            onSave = { d -> vm.saveChain(d) { id -> vm.update { it.copy(hostChainId = id) } }; chainEditor = null },
            onDelete = initial.id?.let { id -> { vm.deleteChain(id); vm.update { it.copy(hostChainId = null) }; chainEditor = null } },
            onDismiss = { chainEditor = null },
        )
    }
}

@Composable
private fun EditLink(onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        TextButton(onClick = onClick) { Text(stringResource(R.string.edit)) }
    }
}

@Composable
private fun ProxyEditorDialog(
    initial: ProxyDraft,
    state: HostEditorState,
    onSave: (ProxyDraft) -> Unit,
    onDelete: (() -> Unit)?,
    onDismiss: () -> Unit,
) {
    var kind by remember { mutableStateOf(initial.kind) }
    var host by remember { mutableStateOf(initial.host) }
    var port by remember { mutableStateOf(initial.port.toString()) }
    var identityId by remember { mutableStateOf(initial.identityId) }
    var username by remember { mutableStateOf(initial.username ?: "") }
    var password by remember { mutableStateOf(initial.password ?: "") }
    val valid = host.isNotBlank() && (port.toIntOrNull() ?: 0) in 1..65535
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial.id == null) stringResource(R.string.new_proxy) else stringResource(R.string.proxy)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                PickerRow(
                    label = stringResource(R.string.proxy_type),
                    value = PROXY_KINDS.firstOrNull { it.first == kind }?.second ?: kind,
                    options = PROXY_KINDS.map { it.first to it.second },
                    selected = kind,
                    onPick = { it?.let { k -> kind = k } },
                    empty = null,
                )
                FormField(host, { host = it }, stringResource(R.string.hostname_or_ip_address), keyboard = KeyboardType.Uri)
                FormField(port, { port = it.filter(Char::isDigit).take(5) }, stringResource(R.string.port), keyboard = KeyboardType.Number)
                val identity = state.identities.firstOrNull { it.id == identityId }
                PickerRow(
                    label = stringResource(R.string.identity),
                    value = identity?.label ?: stringResource(R.string.none),
                    options = listOf<Pair<String?, String>>(null to stringResource(R.string.none)) + state.identities.map { it.id to it.label },
                    selected = identityId,
                    onPick = { identityId = it },
                    empty = null,
                )
                if (identityId == null) {
                    FormField(username, { username = it }, stringResource(R.string.username))
                    if (kind != "socks4") {
                        FormField(password, { password = it }, stringResource(R.string.password), keyboard = KeyboardType.Password, visual = PasswordVisualTransformation())
                    }
                    Text(
                        stringResource(R.string.proxy_credentials_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                enabled = valid,
                onClick = {
                    onSave(
                        ProxyDraft(
                            initial.id, initial.vaultId, kind, host.trim(), port.toInt().toUShort(), identityId,
                            username.trim().ifEmpty { null }.takeIf { identityId == null },
                            password.ifEmpty { null }.takeIf { identityId == null && kind != "socks4" },
                        ),
                    )
                },
            ) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            Row {
                if (onDelete != null) {
                    TextButton(onClick = onDelete) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
            }
        },
    )
}

@Composable
private fun ChainEditorDialog(
    initial: HostChainDraft,
    state: HostEditorState,
    onSave: (HostChainDraft) -> Unit,
    onDelete: (() -> Unit)?,
    onDismiss: () -> Unit,
) {
    var label by remember { mutableStateOf(initial.label) }
    var hostIds by remember { mutableStateOf(initial.hostIds) }
    val candidates = state.hosts.filter { it.id !in hostIds && it.id != state.draft?.id }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial.id == null) stringResource(R.string.new_chain) else stringResource(R.string.host_chaining)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                FormField(label, { label = it }, stringResource(R.string.name))
                Text(stringResource(R.string.jump_hosts_in_order), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                hostIds.forEachIndexed { i, id ->
                    val h = state.hosts.firstOrNull { it.id == id }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("${i + 1}. ${h?.label ?: id}", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        IconButton(enabled = i > 0, onClick = { hostIds = hostIds.toMutableList().also { l -> l.add(i - 1, l.removeAt(i)) } }) {
                            Icon(Icons.Filled.ArrowUpward, contentDescription = stringResource(R.string.move_up))
                        }
                        IconButton(onClick = { hostIds = hostIds - id }) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.remove_2)) }
                    }
                }
                PickerRow(
                    label = stringResource(R.string.add_host),
                    value = "",
                    options = candidates.map { it.id to it.label },
                    selected = null,
                    onPick = { id -> id?.let { hostIds = hostIds + it } },
                    empty = stringResource(R.string.no_hosts_yet),
                )
            }
        },
        confirmButton = {
            Button(enabled = hostIds.isNotEmpty(), onClick = { onSave(HostChainDraft(initial.id, initial.vaultId, label, hostIds)) }) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            Row {
                if (onDelete != null) {
                    TextButton(onClick = onDelete) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
            }
        },
    )
}
