package com.termoso.android.ui.hosts

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.clickable
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.style.TextOverflow
import com.termoso.android.R
import com.termoso.core.ImportPreviewItem
import com.termoso.core.ImportedHostItem
import kotlinx.coroutines.launch

/** A host parsed out of pasted text or an `ssh_config` file. */
data class ImportedHost(val label: String, val address: String, val port: Int?, val username: String)

/**
 * Parses OpenSSH `~/.ssh/config` blocks and loose `user@host:port` / `ssh user@host -p N`
 * lines (Termius "Quick Import"). Wildcard `Host *` blocks are skipped.
 */
fun parseQuickImport(text: String): List<ImportedHost> {
    val out = LinkedHashMap<String, ImportedHost>()
    var cur: ImportedHost? = null
    fun flush() {
        cur?.takeIf { it.address.isNotBlank() && !it.address.contains('*') && !it.address.contains('?') }?.let { out[it.address + ":" + it.port + "@" + it.username] = it }
        cur = null
    }
    val loose = Regex("""^(?:ssh\s+)?(?:(?<user>[\w.\-]+)@)?(?<host>[\w.\-]+|\[[0-9a-fA-F:]+])(?::(?<port>\d{1,5}))?(?:\s+-p\s*(?<port2>\d{1,5}))?\s*$""")
    for (raw in text.lines()) {
        val line = raw.substringBefore('#').trim()
        if (line.isEmpty()) continue
        val kv = Regex("""^(\w+)\s*[=\s]\s*(.+)$""").find(line)
        val key = kv?.groupValues?.get(1)?.lowercase()
        when (key) {
            "host" -> {
                flush()
                val alias = kv.groupValues[2].trim().split(Regex("\\s+")).first()
                cur = ImportedHost(alias, alias, null, "")
            }
            "hostname" -> cur = cur?.copy(address = kv.groupValues[2].trim())
            "user" -> cur = cur?.copy(username = kv.groupValues[2].trim())
            "port" -> cur = cur?.copy(port = kv.groupValues[2].trim().toIntOrNull())
            "match" -> flush()
            else -> if (cur == null || !line.contains(' ')) {
                loose.find(line)?.let { m ->
                    flush()
                    val host = m.groups["host"]!!.value.trim('[', ']')
                    val port = (m.groups["port"] ?: m.groups["port2"])?.value?.toIntOrNull()
                    val h = ImportedHost(host, host, port, m.groups["user"]?.value.orEmpty())
                    out[h.address + ":" + h.port + "@" + h.username] = h
                }
            }
        }
    }
    flush()
    return out.values.toList()
}

@OptIn(ExperimentalMaterial3Api::class)
/** Loose `user@host:port` lines → the shared record, for pastes the shared parsers do not cover. */
private fun looseToItems(items: List<ImportedHost>): List<ImportedHostItem> =
    items.map { ImportedHostItem(label = it.label, address = it.address, protocol = "ssh", port = it.port?.toUShort(), username = it.username, password = null, groupPath = emptyList(), tags = emptyList(), notes = "", warnings = emptyList()) }

/**
 * Import hosts from pasted text, a QR code or a file: ssh_config, PuTTY `.reg`,
 * MobaXterm bookmarks, SecureCRT settings, ZOC host directory, CSV. The shared
 * Rust parsers detect the format; loose `user@host:port` lines are handled here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QuickImportSheet(
    parse: suspend (text: String, fileName: String) -> ImportPreviewItem,
    onImport: (List<ImportedHostItem>) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var fileName by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var preview by remember { mutableStateOf<ImportPreviewItem?>(null) }
    var selected by remember { mutableStateOf<Set<Int>>(emptySet()) }
    var parsing by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    if (scanning) {
        QrScanDialog(
            onResult = { code ->
                text = if (text.isBlank()) code else text + "\n" + code
                scanning = false
            },
            onDismiss = { scanning = false },
        )
    }
    fun runParse(t: String, name: String) {
        if (t.isBlank()) { preview = null; selected = emptySet(); return }
        parsing = true
        error = null
        scope.launch {
            val fromCore = runCatching { parse(t, name) }
            val loose = looseToItems(parseQuickImport(t))
            val p = fromCore.getOrNull()
            val merged = when {
                p != null && p.hosts.isNotEmpty() -> p
                loose.isNotEmpty() -> ImportPreviewItem(source = "ssh_config", hosts = loose, warnings = p?.warnings ?: emptyList())
                else -> p
            }
            if (merged == null) error = fromCore.exceptionOrNull()?.message
            preview = merged
            selected = merged?.hosts?.indices?.toSet() ?: emptySet()
            parsing = false
        }
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        val name = runCatching {
            context.contentResolver.query(uri, null, null, null, null)?.use { c ->
                val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (c.moveToFirst() && i >= 0) c.getString(i) else null
            }
        }.getOrNull() ?: uri.lastPathSegment.orEmpty()
        runCatching { context.contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) } }
            .getOrNull()?.let { t ->
                text = t
                fileName = name
                runParse(t, name)
            }
    }
    val chosen = preview?.hosts?.filterIndexed { i, _ -> i in selected } ?: emptyList()
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 24.dp)) {
            Text(stringResource(R.string.import_hosts), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.import_hosts_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = text,
                onValueChange = { text = it; fileName = ""; runParse(it, "") },
                modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp, max = 180.dp),
                placeholder = { Text("Host web\n  HostName 203.0.113.5\n  User deploy\n\nroot@10.0.0.2:2222", fontFamily = FontFamily.Monospace) },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { pick.launch(arrayOf("*/*")) }) { Text(stringResource(R.string.choose_file)) }
                OutlinedButton(onClick = { scanning = true }) { Text(stringResource(R.string.scan_qr)) }
            }
            preview?.let { p ->
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        stringResource(R.string.import_detected_format, importSourceLabel(p.source)) + (if (fileName.isNotBlank()) " · $fileName" else ""),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (parsing) CircularProgressIndicator(Modifier.height(16.dp).padding(0.dp), strokeWidth = 2.dp)
                }
                LazyColumn(Modifier.fillMaxWidth().heightIn(max = 260.dp)) {
                    items(p.hosts.indices.toList()) { i ->
                        val h = p.hosts[i]
                        Row(
                            Modifier.fillMaxWidth().clickable { selected = if (i in selected) selected - i else selected + i },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(checked = i in selected, onCheckedChange = { selected = if (it) selected + i else selected - i })
                            Column(Modifier.weight(1f)) {
                                Text(h.label.ifBlank { h.address }, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                val target = buildString {
                                    if (h.protocol == "telnet") append("telnet ")
                                    if (h.username.isNotBlank()) append(h.username).append('@')
                                    append(h.address)
                                    h.port?.let { append(':').append(it.toString()) }
                                    if (h.groupPath.isNotEmpty()) append(" · ").append(h.groupPath.joinToString(" / "))
                                }
                                Text(target, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                if (h.warnings.isNotEmpty()) {
                                    Text(h.warnings.joinToString("; "), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                }
                            }
                        }
                    }
                }
                if (p.warnings.isNotEmpty()) {
                    Text(p.warnings.joinToString("\n"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary, maxLines = 4, overflow = TextOverflow.Ellipsis)
                }
            }
            error?.let { Spacer(Modifier.height(8.dp)); Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(8.dp))
            Row {
                Button(modifier = Modifier.fillMaxWidth(), enabled = chosen.isNotEmpty() && !parsing, onClick = { onImport(chosen) }) {
                    Text(pluralStringResource(R.plurals.import_n_hosts, chosen.size, chosen.size))
                }
            }
        }
    }
}

@Composable
private fun importSourceLabel(source: String): String = when (source) {
    "putty" -> "PuTTY"
    "csv" -> "CSV"
    "mobaxterm" -> "MobaXterm"
    "securecrt" -> "SecureCRT"
    "zoc" -> "ZOC"
    "winscp" -> "WinSCP"
    "royalts" -> "Royal TS"
    "iterm2" -> "iTerm2"
    "tabby" -> "Tabby"
    "xshell" -> "Xshell"
    else -> "ssh_config"
}
