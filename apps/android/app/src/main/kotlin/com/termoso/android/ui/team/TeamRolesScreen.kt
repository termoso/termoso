package com.termoso.android.ui.team

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.termoso.android.R
import com.termoso.android.data.userMessage
import com.termoso.android.ui.components.SubScreen
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.core.PermissionCard
import com.termoso.core.TeamPoliciesCard
import com.termoso.core.TeamRoleCard

/** Read-only view of the team's roles (with their permissions) and policies.
 *  Editing lives in the web cabinet and the desktop app. */
@Composable
fun TeamRolesScreen(shell: ShellViewModel, teamId: String, onBack: () -> Unit) {
    var roles by remember { mutableStateOf<List<TeamRoleCard>?>(null) }
    var catalog by remember { mutableStateOf<Map<String, PermissionCard>>(emptyMap()) }
    var policies by remember { mutableStateOf<TeamPoliciesCard?>(null) }
    var expanded by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(teamId) {
        runCatching { shell.repo.read { teamPermissions(teamId) } }
            .onSuccess { list -> catalog = list.associateBy { it.key } }
        runCatching { shell.repo.read { teamPolicies(teamId) } }.onSuccess { policies = it }
        runCatching { shell.repo.read { teamRoles(teamId) } }
            .onSuccess { roles = it }
            .onFailure { shell.notify(it.userMessage()); roles = emptyList() }
    }

    SubScreen(title = stringResource(R.string.roles_and_policies), onBack = onBack) { padding ->
        val list = roles
        if (list == null) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            }
            return@SubScreen
        }
        LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(top = padding.calculateTopPadding(), bottom = 24.dp)) {
            item { SectionLabel(stringResource(R.string.roles)) }
            items(list, key = { it.id }) { r ->
                RoleRow(r, catalog, expanded == r.id) { expanded = if (expanded == r.id) null else r.id }
                HorizontalDivider(Modifier.padding(start = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
            }
            policies?.let { p ->
                item { Spacer(Modifier.height(12.dp)); SectionLabel(stringResource(R.string.team_policies)) }
                item { PolicyRows(p) }
            }
            item {
                Text(
                    stringResource(R.string.roles_edit_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                )
            }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

@Composable
private fun RoleRow(r: TeamRoleCard, catalog: Map<String, PermissionCard>, open: Boolean, onToggle: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(r.name, style = MaterialTheme.typography.bodyLarge)
            if (r.isDefault) Tag(stringResource(R.string.default_role))
            if (!r.builtin) Tag(stringResource(R.string.custom))
            Spacer(Modifier.weight(1f))
            Text(
                pluralStringResource(R.plurals.members_count, r.memberCount.toInt(), r.memberCount.toInt()),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (r.description.isNotBlank()) {
            Text(r.description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        val all = r.permissions.contains("*")
        val shown = if (all) catalog.values.toList() else r.permissions.mapNotNull { catalog[it] }
        val summary = if (all) stringResource(R.string.all_permissions) else
            pluralStringResource(R.plurals.permissions_count, shown.size, shown.size)
        androidx.compose.material3.TextButton(onClick = onToggle, contentPadding = PaddingValues(0.dp)) {
            Text(if (open) stringResource(R.string.hide_permissions) else summary)
        }
        if (open) {
            shown.groupBy { it.group }.forEach { (group, perms) ->
                Text(group, style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 6.dp))
                perms.forEach { p ->
                    val flags = buildList {
                        if (p.sensitive) add(stringResource(R.string.sensitive_flag))
                        if (p.clientEnforced) add(stringResource(R.string.client_flag))
                    }
                    Text(
                        if (flags.isEmpty()) p.title else "${p.title} · ${flags.joinToString(", ")}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun Tag(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.primary,
    )
}

@Composable
private fun PolicyRows(p: TeamPoliciesCard) {
    val rows = listOf(
        stringResource(R.string.two_factor) to when (p.mfa) {
            "any" -> stringResource(R.string.mfa_any)
            "passkey" -> stringResource(R.string.mfa_passkey_only)
            else -> stringResource(R.string.not_required)
        },
        stringResource(R.string.keys_only_in_team_vaults) to onOff(p.localKeys == "deny"),
        stringResource(R.string.session_lifetime) to (
            p.sessionTtlHours?.let { stringResource(R.string.hours_n, it) } ?: stringResource(R.string.server_default)
            ),
        stringResource(R.string.sign_in_only_through_sso) to onOff(p.ssoOnly),
        stringResource(R.string.allowed_email_domains) to (p.ssoDomains.joinToString(", ").ifEmpty { stringResource(R.string.any_domain) }),
        stringResource(R.string.approve_new_devices) to onOff(p.deviceApproval),
        stringResource(R.string.audit_log_retention) to stringResource(R.string.days_n, p.auditRetentionDays),
        stringResource(R.string.session_recording) to stringResource(
            if (p.sessionRecording == "required") R.string.required else R.string.optional,
        ),
        stringResource(R.string.recording_retention) to (
            if (p.logRetentionDays == 0) stringResource(R.string.forever) else stringResource(R.string.days_n, p.logRetentionDays)
            ),
        stringResource(R.string.key_rotation_age) to (
            if (p.keyMaxAgeDays == 0) stringResource(R.string.off) else stringResource(R.string.days_n, p.keyMaxAgeDays)
            ),
        stringResource(R.string.password_rotation_age) to (
            if (p.passwordMaxAgeDays == 0) stringResource(R.string.off) else stringResource(R.string.days_n, p.passwordMaxAgeDays)
            ),
        stringResource(R.string.ip_allow_list) to (p.ipAllowlist.joinToString(", ").ifEmpty { stringResource(R.string.everywhere) }),
        stringResource(R.string.admin_approval_new_devices) to onOff(p.deviceAdminApproval),
        stringResource(R.string.policy_keys_only) to onOff(p.auth == "keys_only"),
        stringResource(R.string.policy_jump_host_required) to onOff(p.jumpHostRequired),
        stringResource(R.string.policy_no_export) to onOff(p.export == "deny"),
        stringResource(R.string.policy_no_offline_cache) to onOff(p.offlineCache == "deny"),
        stringResource(R.string.policy_forwarded_ports) to (p.forwardPorts.joinToString(", ").ifEmpty { stringResource(R.string.any_port) }),
        stringResource(R.string.policy_require_disk_encryption) to onOff(p.postureDiskEncryption),
        stringResource(R.string.policy_require_screen_lock) to onOff(p.postureScreenLock),
        stringResource(R.string.policy_require_secure_key) to onOff(p.postureSecureKey),
    )
    Column(Modifier.fillMaxWidth()) {
        rows.forEach { (k, v) ->
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                Text(k, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                Text(v, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            HorizontalDivider(Modifier.padding(start = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}

@Composable
private fun onOff(v: Boolean) = stringResource(if (v) R.string.on else R.string.off)
