package com.termoso.android.ui.team

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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.termoso.android.R
import com.termoso.android.data.AccountManager
import com.termoso.android.data.userMessage
import com.termoso.android.ui.components.SubScreen
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.core.AccessReviewCard
import com.termoso.core.AccessReviewDetailCard
import com.termoso.core.BreakGlassCard
import kotlinx.coroutines.launch

/**
 * The on-the-go half of the desktop Compliance tab: use/end break-glass and
 * decide access reviews. Configuring break-glass and verifying the audit
 * chain stay on the desktop.
 */
@Composable
fun TeamComplianceScreen(
    shell: ShellViewModel,
    account: AccountManager,
    teamId: String,
    canDecide: Boolean,
    onBack: () -> Unit,
) {
    var reviews by remember { mutableStateOf<List<AccessReviewCard>?>(null) }
    var glass by remember { mutableStateOf<BreakGlassCard?>(null) }
    var detail by remember { mutableStateOf<AccessReviewDetailCard?>(null) }
    var using by remember { mutableStateOf(false) }
    var reload by remember { mutableIntStateOf(0) }
    val status by account.status.collectAsState()
    val myId = status.account?.userId
    val scope = rememberCoroutineScope()
    LaunchedEffect(teamId, reload) {
        runCatching { shell.repo.read { teamAccessReviews(teamId) } }
            .onSuccess { reviews = it }
            .onFailure { shell.notify(it.userMessage()) }
        runCatching { shell.repo.read { teamBreakGlass(teamId) } }.onSuccess { glass = it }
    }
    fun mutate(done: String?, block: suspend () -> Unit) {
        scope.launch {
            runCatching { block() }
                .onSuccess { reload++; done?.let { shell.notify(it) } }
                .onFailure { shell.notify(it.userMessage()) }
        }
    }
    val endedMsg = stringResource(R.string.break_glass_ended)
    val usedMsg = stringResource(R.string.break_glass_used)
    SubScreen(title = stringResource(R.string.compliance), onBack = onBack) { padding ->
        val list = reviews
        if (list == null) {
            Column(Modifier.fillMaxSize().padding(padding), horizontalAlignment = Alignment.CenterHorizontally) {
                Spacer(Modifier.height(48.dp)); CircularProgressIndicator()
            }
            return@SubScreen
        }
        LazyColumn(Modifier.fillMaxSize().padding(padding)) {
            item { SectionTitle(stringResource(R.string.break_glass)) }
            item {
                val g = glass
                Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (g == null) {
                        Text(stringResource(R.string.break_glass_not_configured), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        Text(g.email ?: g.userId, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            listOfNotNull(
                                glassStatus(g.status),
                                stringResource(R.string.hours_short, g.duration_hours()),
                                g.expiresAt?.takeIf { g.status == "active" }?.let { stringResource(R.string.until_when, it.take(16).replace('T', ' ')) },
                            ).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            if (g.status == "active" && (canDecide || g.userId == myId)) {
                                TextButton(onClick = { mutate(endedMsg) { shell.repo.read { teamEndBreakGlass(teamId) } } }) {
                                    Text(stringResource(R.string.break_glass_end), color = MaterialTheme.colorScheme.error)
                                }
                            }
                            if (g.status != "active" && g.userId == myId) {
                                Button(onClick = { using = true }) { Text(stringResource(R.string.break_glass_use)) }
                            }
                        }
                    }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            item { SectionTitle(stringResource(R.string.access_reviews)) }
            if (list.isEmpty()) item {
                Text(stringResource(R.string.no_reviews), modifier = Modifier.padding(16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            items(list, key = { it.id }) { r ->
                Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp)) {
                    Text(
                        stringResource(R.string.review_opened_on, r.openedAt.take(10)),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        listOf(
                            reviewStatus(r.status),
                            if (r.status == "open") stringResource(R.string.review_progress, r.decided, r.items)
                            else stringResource(R.string.review_outcome, r.kept, r.removed),
                            stringResource(R.string.review_due, r.dueAt.take(10)),
                        ).joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        TextButton(onClick = {
                            scope.launch {
                                runCatching { shell.repo.read { teamAccessReview(teamId, r.id) } }
                                    .onSuccess { detail = it }
                                    .onFailure { shell.notify(it.userMessage()) }
                            }
                        }) { Text(stringResource(R.string.open)) }
                    }
                }
                HorizontalDivider(Modifier.padding(start = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
            }
            item { Spacer(Modifier.height(24.dp)) }
        }
    }
    detail?.let { d ->
        ReviewDialog(
            detail = d,
            canDecide = canDecide && d.review.status == "open",
            onDismiss = { detail = null },
            onDecide = { itemId, decision ->
                scope.launch {
                    runCatching { shell.repo.read { teamDecideAccessReviewItem(teamId, d.review.id, itemId, decision, null) } }
                        .onSuccess { updated -> detail = d.copy(items = d.items.map { if (it.id == updated.id) updated else it }) }
                        .onFailure { shell.notify(it.userMessage()) }
                }
            },
            onComplete = {
                detail = null
                mutate(null) { shell.repo.read { teamCompleteAccessReview(teamId, d.review.id) } }
            },
        )
    }
    if (using) {
        UseBreakGlassDialog(
            onDismiss = { using = false },
            onSubmit = { secret, reason ->
                using = false
                mutate(usedMsg) { shell.repo.read { teamUseBreakGlass(teamId, secret, reason) } }
            },
        )
    }
}

private fun BreakGlassCard.duration_hours(): Int = durationHours

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(start = 16.dp, top = 16.dp, end = 16.dp, bottom = 4.dp))
}

@Composable
private fun glassStatus(s: String): String = when (s) {
    "active" -> stringResource(R.string.break_glass_status_active)
    "locked" -> stringResource(R.string.break_glass_status_locked)
    "used" -> stringResource(R.string.break_glass_status_used)
    else -> stringResource(R.string.break_glass_status_armed)
}

@Composable
private fun reviewStatus(s: String): String = when (s) {
    "completed" -> stringResource(R.string.review_status_completed)
    "cancelled" -> stringResource(R.string.review_status_cancelled)
    else -> stringResource(R.string.review_status_open)
}

@Composable
private fun ReviewDialog(
    detail: AccessReviewDetailCard,
    canDecide: Boolean,
    onDismiss: () -> Unit,
    onDecide: (String, String) -> Unit,
    onComplete: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.access_review)) },
        text = {
            LazyColumn(Modifier.fillMaxWidth()) {
                item {
                    Text(stringResource(R.string.access_review_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(8.dp))
                }
                items(detail.items, key = { it.id }) { i ->
                    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                        Text(i.displayName ?: i.email ?: i.userId, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            listOfNotNull(
                                i.vaultName?.let { "→ $it" },
                                i.role,
                                i.lastSeenAt?.let { stringResource(R.string.last_seen_on, it.take(10)) },
                            ).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            if (canDecide) {
                                TextButton(onClick = { onDecide(i.id, "remove") }, enabled = i.decision != "remove") {
                                    Text(stringResource(R.string.remove), color = MaterialTheme.colorScheme.error)
                                }
                                TextButton(onClick = { onDecide(i.id, "keep") }, enabled = i.decision != "keep") {
                                    Text(stringResource(R.string.keep))
                                }
                            } else if (i.decision != null) {
                                Text(if (i.decision == "keep") stringResource(R.string.keep) else stringResource(R.string.remove), style = MaterialTheme.typography.labelMedium)
                            }
                        }
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        },
        confirmButton = {
            if (canDecide) Button(onClick = onComplete) { Text(stringResource(R.string.complete_review)) }
            else TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
        },
        dismissButton = { if (canDecide) TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun UseBreakGlassDialog(onDismiss: () -> Unit, onSubmit: (String, String) -> Unit) {
    var secret by remember { mutableStateOf("") }
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.break_glass_use)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.break_glass_use_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedTextField(secret, { secret = it }, label = { Text(stringResource(R.string.break_glass_secret)) }, singleLine = true, visualTransformation = PasswordVisualTransformation())
                OutlinedTextField(reason, { reason = it }, label = { Text(stringResource(R.string.reason)) }, minLines = 2)
            }
        },
        confirmButton = {
            Button(onClick = { onSubmit(secret.trim(), reason.trim()) }, enabled = secret.isNotBlank() && reason.trim().length >= 4) {
                Text(stringResource(R.string.break_glass_use))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
