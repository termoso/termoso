package com.termoso.android.ui.team

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.termoso.android.R
import com.termoso.android.data.userMessage
import com.termoso.android.ui.components.SubScreen
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.core.AutomationCard
import com.termoso.core.AutomationRunCard
import com.termoso.core.HostRunCard
import kotlinx.coroutines.launch

/**
 * Team automations, read-only plus "Run now": the list, and per automation
 * the run history with per-host output (opened with the vault key when the
 * vault is unlocked on this device). Creating and editing stay on the desktop.
 */
@Composable
fun TeamAutomationsScreen(shell: ShellViewModel, teamId: String, canRun: Boolean, onBack: () -> Unit) {
    var list by remember { mutableStateOf<List<AutomationCard>?>(null) }
    var openId by remember { mutableStateOf<String?>(null) }
    var runs by remember { mutableStateOf<List<AutomationRunCard>?>(null) }
    var expanded by remember { mutableStateOf<String?>(null) }
    var reload by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(teamId, reload) {
        runCatching { shell.repo.read { teamAutomations(teamId) } }
            .onSuccess { list = it }
            .onFailure { shell.notify(it.userMessage()) }
    }
    LaunchedEffect(openId, reload) {
        val id = openId ?: run { runs = null; return@LaunchedEffect }
        runCatching { shell.repo.read { teamAutomationRuns(teamId, id) } }
            .onSuccess { runs = it }
            .onFailure { shell.notify(it.userMessage()) }
    }
    val queuedMsg = stringResource(R.string.run_queued)
    val current = list?.firstOrNull { it.id == openId }
    SubScreen(
        title = current?.name ?: stringResource(R.string.automations),
        onBack = { if (openId != null) openId = null else onBack() },
        actions = {
            if (current != null && canRun && current.enabled) {
                TextButton(onClick = {
                    scope.launch {
                        runCatching { shell.repo.read { teamRunAutomationNow(teamId, current.id) } }
                            .onSuccess { reload++; shell.notify(queuedMsg) }
                            .onFailure { shell.notify(it.userMessage()) }
                    }
                }) { Text(stringResource(R.string.run_now)) }
            }
        },
    ) { padding ->
        val l = list
        if (l == null || (openId != null && runs == null)) {
            Column(Modifier.fillMaxSize().padding(padding), horizontalAlignment = Alignment.CenterHorizontally) {
                Spacer(Modifier.height(48.dp)); CircularProgressIndicator()
            }
            return@SubScreen
        }
        if (current == null) {
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                item {
                    Text(
                        stringResource(R.string.automations_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp),
                    )
                }
                if (l.isEmpty()) item { Text(stringResource(R.string.no_automations), modifier = Modifier.padding(16.dp)) }
                items(l, key = { it.id }) { a ->
                    Column(Modifier.fillMaxWidth().clickable { openId = a.id }.padding(horizontal = 16.dp, vertical = 10.dp)) {
                        Text(a.name, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            listOfNotNull(
                                if (a.enabled) "${a.schedule} ${a.timezone}" else stringResource(R.string.automation_paused),
                                a.lastStatus?.let { runStatus(it) },
                                a.nextRunAt?.takeIf { a.enabled }?.let { stringResource(R.string.next_run_at, it.take(16).replace('T', ' ')) },
                            ).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    HorizontalDivider(Modifier.padding(start = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        } else {
            val rs = runs.orEmpty()
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                if (rs.isEmpty()) item { Text(stringResource(R.string.no_runs_yet), modifier = Modifier.padding(16.dp)) }
                items(rs, key = { it.id }) { r ->
                    val open = expanded == r.id
                    val expandable = r.results.isNotEmpty() || r.error != null || r.locked
                    Column(
                        Modifier.fillMaxWidth()
                            .clickable(enabled = expandable) { expanded = if (open) null else r.id }
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                    ) {
                        Text(
                            r.scheduledFor.take(16).replace('T', ' ') + if (r.manual) " · " + stringResource(R.string.manual_run) else "",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            listOfNotNull(
                                runStatus(r.status),
                                if (r.hostsTotal > 0) {
                                    if (r.hostsFailed > 0) stringResource(R.string.hosts_failed_of, r.hostsFailed, r.hostsTotal)
                                    else stringResource(R.string.hosts_ok, r.hostsTotal)
                                } else null,
                                r.claimedByName,
                            ).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (open) {
                            Spacer(Modifier.height(6.dp))
                            r.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                            if (r.locked) {
                                Text(stringResource(R.string.run_locked_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            r.results.forEach { h -> HostRunRow(h) }
                        }
                    }
                    HorizontalDivider(Modifier.padding(start = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
                }
                item { Spacer(Modifier.height(24.dp)) }
            }
        }
    }
}

@Composable
private fun HostRunRow(h: HostRunCard) {
    val ok = h.error == null && h.exitCode == 0u
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(h.label, style = MaterialTheme.typography.bodySmall)
            Text(
                h.error?.let { stringResource(R.string.run_status_failed) } ?: stringResource(R.string.exit_code, h.exitCode?.toLong() ?: -1L),
                style = MaterialTheme.typography.labelSmall,
                color = if (ok) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
            )
        }
        if (h.target.isNotBlank()) Text("${h.target} · ${"%.1f".format(h.ms.toDouble() / 1000.0)}s", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        h.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (h.stdout.isNotBlank()) Text(h.stdout.trimEnd(), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        if (h.stderr.isNotBlank()) Text(h.stderr.trimEnd(), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.error)
    }
}

@Composable
private fun runStatus(s: String): String = when (s) {
    "pending" -> stringResource(R.string.run_status_pending)
    "running" -> stringResource(R.string.run_status_running)
    "done" -> stringResource(R.string.run_status_done)
    "failed" -> stringResource(R.string.run_status_failed)
    "missed" -> stringResource(R.string.run_status_missed)
    "cancelled" -> stringResource(R.string.run_status_cancelled)
    else -> s
}
