package com.termoso.android.ui.team

import androidx.compose.ui.res.pluralStringResource
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.termoso.android.R
import com.termoso.android.data.PermissionDenied
import com.termoso.android.data.can
import com.termoso.android.data.AccountManager
import com.termoso.android.data.VaultRepository
import com.termoso.android.data.userMessage
import com.termoso.android.str
import com.termoso.android.ui.components.ChevronRow
import com.termoso.android.ui.components.IconTile
import com.termoso.android.ui.components.ListRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.SectionLabel
import com.termoso.android.ui.components.SubScreen
import com.termoso.android.ui.components.SwitchRow
import com.termoso.android.ui.components.UserAvatar
import com.termoso.android.ui.hosts.ConfirmDialog
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.android.ui.theme.Warning
import com.termoso.core.InviteCard
import com.termoso.core.PendingKeyCard
import com.termoso.core.TeamMemberCard
import com.termoso.core.TeamRole
import com.termoso.core.VaultAccess
import com.termoso.core.VaultInfo
import kotlinx.coroutines.launch

/**
 * One team, like Termius' Team screen: members with roles, pending invitations,
 * team vaults, keys waiting to be granted, security switches, activity log.
 * What you can change follows your role; the server enforces it too.
 */
@Composable
fun TeamScreen(
    shell: ShellViewModel,
    account: AccountManager,
    teamId: String,
    onBack: () -> Unit,
    onOpenVault: (String) -> Unit,
    onActivity: () -> Unit,
    onOpenAccount: () -> Unit = {},
    onRoles: () -> Unit = {},
    onDevices: () -> Unit = {},
    onAccess: () -> Unit = {},
    onRecordings: () -> Unit = {},
    onData: () -> Unit = {},
    onCompliance: () -> Unit = {},
    onAutomations: () -> Unit = {},
) {
    val vm: TeamViewModel = viewModel(key = "team-$teamId") { TeamViewModel(shell.repo, account, teamId) }
    val state by vm.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf(false) }
    var inviting by remember { mutableStateOf(false) }
    var newVault by remember { mutableStateOf(false) }
    var memberMenu by remember { mutableStateOf<TeamMemberCard?>(null) }
    var removing by remember { mutableStateOf<TeamMemberCard?>(null) }
    var transferring by remember { mutableStateOf<TeamMemberCard?>(null) }
    var revoking by remember { mutableStateOf<InviteCard?>(null) }
    var leaving by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { vm.reload() }
    LaunchedEffect(state.error) {
        state.error?.let {
            shell.notify(it)
            vm.errorShown()
        }
    }

    val team = state.team
    SubScreen(
        title = team?.name ?: stringResource(R.string.team),
        onBack = onBack,
        actions = {
            if (team != null) {
                Box {
                    IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more)) }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        if (state.isAdmin) {
                            DropdownMenuItem(text = { Text(stringResource(R.string.rename_team)) }, onClick = { menu = false; renaming = true })
                            DropdownMenuItem(text = { Text(stringResource(R.string.activity_log)) }, onClick = { menu = false; onActivity() })
                        }
                        if (state.isOwner) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.delete_team), color = MaterialTheme.colorScheme.error) },
                                onClick = { menu = false; deleting = true },
                            )
                        } else {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.leave_team), color = MaterialTheme.colorScheme.error) },
                                onClick = { menu = false; leaving = true },
                            )
                        }
                    }
                }
            }
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            Spacer(Modifier.height(8.dp))
            if (state.mfaRequired) {
                SectionCard {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(stringResource(R.string.team_requires_two_factor), style = MaterialTheme.typography.bodyMedium)
                        Button(onClick = onOpenAccount) { Text(stringResource(R.string.set_up_two_factor)) }
                    }
                }
                if (team == null) return@SubScreen
            }
            if (team == null) {
                Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    if (state.loading) CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                }
                return@SubScreen
            }

            SectionCard {
                ListRow(
                    title = team.name,
                    subtitle = stringResource(R.string.you_are, team.myRoleName ?: team.myRole.label().lowercase(), members(team.memberCount)),
                    leading = { IconTile(Icons.Filled.Group) },
                    trailing = if (state.isAdmin) {
                        { IconButton(onClick = { renaming = true }) { Icon(Icons.Filled.Edit, contentDescription = stringResource(R.string.rename)) } }
                    } else {
                        null
                    },
                )
            }

            if (state.pendingKeys.isNotEmpty()) {
                SectionLabel(stringResource(R.string.waiting_for_a_key))
                SectionCard {
                    state.pendingKeys.forEachIndexed { i, p ->
                        if (i > 0) RowDivider()
                        PendingKeyRow(p, onGrant = { vm.grantKey(p) })
                    }
                    Text(
                        stringResource(R.string.these_members_joined_after_being_given_access_granting),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                }
            }

            SectionLabel(stringResource(R.string.members))
            SectionCard {
                state.members.forEachIndexed { i, m ->
                    if (i > 0) RowDivider()
                    MemberRow(
                        shell.repo,
                        m,
                        mfaRequired = state.team?.requireMfa == true,
                        canManage = state.isAdmin && !m.me && (m.role != TeamRole.OWNER),
                        onMenu = { memberMenu = m },
                    )
                }
                if (state.isAdmin) {
                    RowDivider()
                    ListRow(
                        title = stringResource(R.string.invite_people),
                        titleColor = MaterialTheme.colorScheme.primary,
                        leading = { IconTile(Icons.Filled.Person, tint = MaterialTheme.colorScheme.primary) },
                        modifier = Modifier.clickable { inviting = true },
                    )
                }
            }

            if (state.isAdmin && state.invites.isNotEmpty()) {
                SectionLabel(stringResource(R.string.pending_invitations))
                SectionCard {
                    state.invites.forEachIndexed { i, inv ->
                        if (i > 0) RowDivider()
                        ListRow(
                            title = inv.email,
                            subtitle = stringResource(R.string.expires, inv.role.label(), inv.expiresAt.take(10)),
                            trailing = {
                                IconButton(onClick = { revoking = inv }) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.revoke)) }
                            },
                        )
                    }
                }
            }

            SectionLabel(stringResource(R.string.vaults))
            SectionCard {
                state.vaults.forEachIndexed { i, v ->
                    if (i > 0) RowDivider()
                    VaultRow(v, Modifier.clickable { onOpenVault(v.id) })
                }
                if (state.vaults.isEmpty()) {
                    Text(
                        if (state.isAdmin) stringResource(R.string.no_team_vault_yet) else stringResource(R.string.you_have_not_been_given_access_to_any),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp),
                    )
                }
                if (state.isAdmin) {
                    RowDivider()
                    ListRow(
                        title = stringResource(R.string.new_team_vault),
                        titleColor = MaterialTheme.colorScheme.primary,
                        leading = { IconTile(Icons.Filled.Lock, tint = MaterialTheme.colorScheme.primary) },
                        modifier = Modifier.clickable { newVault = true },
                    )
                }
            }

            if (state.isAdmin) {
                SectionLabel(stringResource(R.string.security))
                SectionCard {
                    SwitchRow(
                        title = stringResource(R.string.terminal_sharing),
                        subtitle = stringResource(R.string.members_may_share_a_live_terminal_with_each),
                        checked = team.multiplayerEnabled,
                        onCheckedChange = { vm.setMultiplayer(it) },
                    )
                    RowDivider()
                    val noMfa = state.members.count { it.mfaEnabled == false }
                    SwitchRow(
                        title = stringResource(R.string.require_two_factor_authentication),
                        subtitle = stringResource(R.string.members_without_2fa_cannot_open_team_vaults) +
                            when (noMfa) {
                                0 -> ""
                                else -> pluralStringResource(R.plurals.sep_members_no_2fa, noMfa, noMfa)
                            },
                        checked = team.requireMfa,
                        onCheckedChange = { vm.setRequireMfa(it) },
                    )
                    RowDivider()
                    SwitchRow(
                        title = stringResource(R.string.show_who_is_connected),
                        subtitle = stringResource(R.string.members_see_who_is_on_which_team_vault),
                        checked = team.presenceEnabled,
                        onCheckedChange = { vm.setPresence(it) },
                    )
                    RowDivider()
                    ChevronRow(
                        title = stringResource(R.string.activity_log),
                        subtitle = stringResource(R.string.who_joined_invited_granted_access_rotated_keys),
                        leading = { IconTile(Icons.Filled.History) },
                        modifier = Modifier.clickable(onClick = onActivity),
                    )
                    if (team.can("roles.manage") || team.can("policies.manage")) {
                        RowDivider()
                        ChevronRow(
                            title = stringResource(R.string.roles_and_policies),
                            subtitle = stringResource(R.string.roles_and_policies_hint),
                            leading = { IconTile(Icons.Filled.Lock) },
                            modifier = Modifier.clickable(onClick = onRoles),
                        )
                    }
                    RowDivider()
                    ChevronRow(
                        title = stringResource(R.string.access_requests),
                        subtitle = stringResource(R.string.access_requests_hint),
                        leading = { IconTile(Icons.Filled.Lock) },
                        modifier = Modifier.clickable(onClick = onAccess),
                    )
                    RowDivider()
                    ChevronRow(
                        title = stringResource(R.string.compliance),
                        subtitle = stringResource(R.string.compliance_hint),
                        leading = { IconTile(Icons.Filled.Lock) },
                        modifier = Modifier.clickable(onClick = onCompliance),
                    )
                    if (team.can("automations.view")) {
                        RowDivider()
                        ChevronRow(
                            title = stringResource(R.string.automations),
                            subtitle = stringResource(R.string.automations_hint),
                            leading = { IconTile(Icons.Filled.History) },
                            modifier = Modifier.clickable(onClick = onAutomations),
                        )
                    }
                    RowDivider()
                    ChevronRow(
                        title = stringResource(R.string.team_recordings),
                        subtitle = stringResource(R.string.team_recordings_hint),
                        leading = { IconTile(Icons.Filled.Lock) },
                        modifier = Modifier.clickable(onClick = onRecordings),
                    )
                    RowDivider()
                    ChevronRow(
                        title = stringResource(R.string.team_data),
                        subtitle = stringResource(R.string.team_data_tile_hint),
                        leading = { IconTile(Icons.Filled.Lock) },
                        modifier = Modifier.clickable(onClick = onData),
                    )
                    if (team.can("devices.approve")) {
                        RowDivider()
                        ChevronRow(
                            title = stringResource(R.string.devices_awaiting_approval),
                            subtitle = stringResource(R.string.devices_hint),
                            leading = { IconTile(Icons.Filled.Lock) },
                            modifier = Modifier.clickable(onClick = onDevices),
                        )
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    if (renaming && team != null) {
        NameDialog(
            title = stringResource(R.string.rename_team),
            label = stringResource(R.string.team_name),
            initial = team.name,
            onDismiss = { renaming = false },
            onConfirm = { renaming = false; vm.rename(it) },
        )
    }
    if (inviting && team != null) {
        InviteDialog(
            vaults = state.vaults,
            canMakeAdmin = state.isAdmin,
            onDismiss = { inviting = false },
            onSend = { emails, role, vaults -> vm.invite(emails, role, vaults) },
        )
    }
    if (newVault) {
        NewTeamVaultDialog(
            members = state.members,
            onDismiss = { newVault = false },
            onCreate = { name, access ->
                runCatching { vm.createVault(name, access) }
                    .onSuccess { shell.notify(str(R.string.vault_created, name)) }
                    .onFailure { shell.notify(it.userMessage()) }
                    .isSuccess
            },
        )
    }
    memberMenu?.let { m ->
        MemberMenuDialog(
            member = m,
            isOwner = state.isOwner,
            onRole = { role -> memberMenu = null; vm.setRole(m.userId, role) },
            onTransfer = { memberMenu = null; transferring = m },
            onRemove = { memberMenu = null; removing = m },
            onDismiss = { memberMenu = null },
        )
    }
    removing?.let { m ->
        ConfirmDialog(
            title = stringResource(R.string.remove, m.displayName ?: m.email),
            text = stringResource(R.string.they_lose_access_to_every_vault_of_this),
            confirm = stringResource(R.string.remove_2),
            onConfirm = { removing = null; vm.removeMember(m.userId) },
            onDismiss = { removing = null },
        )
    }
    transferring?.let { m ->
        ConfirmDialog(
            title = stringResource(R.string.make_the_owner, m.displayName ?: m.email),
            text = stringResource(R.string.you_become_an_admin_only_the_owner_can),
            confirm = stringResource(R.string.transfer),
            onConfirm = { transferring = null; vm.setRole(m.userId, TeamRole.OWNER) },
            onDismiss = { transferring = null },
        )
    }
    revoking?.let { inv ->
        ConfirmDialog(
            title = stringResource(R.string.revoke_invitation),
            text = stringResource(R.string.the_link_sent_to_stops_working, inv.email),
            confirm = stringResource(R.string.revoke),
            onConfirm = { revoking = null; vm.revokeInvite(inv.id) },
            onDismiss = { revoking = null },
        )
    }
    if (leaving && team != null) {
        ConfirmDialog(
            title = stringResource(R.string.leave, team.name),
            text = stringResource(R.string.its_vaults_disappear_from_this_device_an_admin),
            confirm = stringResource(R.string.leave_2),
            onConfirm = {
                leaving = false
                scope.launch {
                    runCatching { vm.leave() }
                        .onSuccess { shell.notify(str(R.string.left, team.name)); onBack() }
                        .onFailure { shell.notify(it.userMessage()) }
                }
            },
            onDismiss = { leaving = false },
        )
    }
    if (deleting && team != null) {
        ConfirmDialog(
            title = stringResource(R.string.delete_3, team.name),
            text = stringResource(R.string.all_team_vaults_and_their_hosts_keys_and),
            confirm = stringResource(R.string.delete),
            onConfirm = {
                deleting = false
                scope.launch {
                    runCatching {
                        if (!team.can("team.delete")) throw PermissionDenied("team.delete", team.name)
                        vm.delete()
                    }
                        .onSuccess { shell.notify(str(R.string.team_deleted)); onBack() }
                        .onFailure { shell.notify(it.userMessage()) }
                }
            },
            onDismiss = { deleting = false },
        )
    }
}

@Composable
private fun MemberRow(repo: VaultRepository, m: TeamMemberCard, mfaRequired: Boolean, canManage: Boolean, onMenu: () -> Unit) {
    ListRow(
        title = (m.displayName ?: m.email) + if (m.me) stringResource(R.string.you_3) else "",
        subtitle = if (m.displayName != null) "${m.email} · ${m.role.label()}" else m.role.label(),
        leading = { UserAvatar(repo, m.userId, m.avatar, m.displayName ?: m.email) },
        trailing = if (canManage || m.mfaEnabled != null) {
            {
                MfaBadge(m.mfaEnabled, mfaRequired)
                if (canManage) {
                    IconButton(onClick = onMenu) { Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.manage)) }
                }
            }
        } else {
            null
        },
    )
}

/**
 * Second-factor state of a team member as the server discloses it: admins see everyone, members
 * only themselves ([enabled] is null otherwise and nothing is drawn).
 */
@Composable
fun MfaBadge(enabled: Boolean?, required: Boolean) {
    when (enabled) {
        true -> Icon(
            Icons.Filled.VerifiedUser,
            contentDescription = stringResource(R.string.two_factor_authentication_enabled),
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(18.dp),
        )
        false -> {
            val tint = if (required) MaterialTheme.colorScheme.error else Warning
            Row(
                Modifier
                    .border(1.dp, tint, RoundedCornerShape(6.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.GppMaybe, contentDescription = null, tint = tint, modifier = Modifier.size(12.dp))
                Spacer(Modifier.width(4.dp))
                Text(
                    stringResource(R.string.no_2fa),
                    color = tint,
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
        null -> Unit
    }
}

@Composable
private fun PendingKeyRow(p: PendingKeyCard, onGrant: () -> Unit) {
    ListRow(
        title = p.displayName ?: p.email,
        subtitle = "${p.vaultName} · ${p.access.label()}",
        leading = { IconTile(Icons.Filled.LockOpen) },
        trailing = { TextButton(onClick = onGrant) { Text(stringResource(R.string.grant)) } },
    )
}

@Composable
fun VaultRow(v: VaultInfo, modifier: Modifier = Modifier) {
    ChevronRow(
        title = v.name,
        subtitle = if (v.locked) stringResource(R.string.key_not_received_yet) else stringResource(R.string.you_4, v.access.label()),
        leading = { IconTile(if (v.locked) Icons.Filled.Lock else Icons.Filled.LockOpen) },
        modifier = modifier,
    )
}

@Composable
private fun MemberMenuDialog(
    member: TeamMemberCard,
    isOwner: Boolean,
    onRole: (TeamRole) -> Unit,
    onTransfer: () -> Unit,
    onRemove: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(member.displayName ?: member.email) },
        text = {
            Column {
                if (member.displayName != null) {
                    Text(member.email, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(8.dp))
                }
                listOf(TeamRole.MEMBER, TeamRole.ADMIN).forEach { role ->
                    val current = member.role == role
                    ListRow(
                        title = role.label() + if (current) stringResource(R.string.sep_current) else "",
                        subtitle = role.hint(),
                        titleColor = if (current) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.clickable(enabled = !current) { onRole(role) },
                    )
                }
                if (isOwner) {
                    ListRow(title = stringResource(R.string.make_owner), subtitle = TeamRole.OWNER.hint(), modifier = Modifier.clickable(onClick = onTransfer))
                }
                ListRow(
                    title = stringResource(R.string.remove_from_team),
                    titleColor = MaterialTheme.colorScheme.error,
                    modifier = Modifier.clickable(onClick = onRemove),
                )
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
internal fun NameDialog(
    title: String,
    label: String,
    initial: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                label = { Text(label) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(value.trim()) }, enabled = value.isNotBlank() && value.trim() != initial) { Text(stringResource(R.string.save)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** Access level picker used by invitations, new vaults and vault members; `null` = no access. */
@Composable
internal fun AccessMenu(
    current: VaultAccess?,
    allowNone: Boolean,
    onPick: (VaultAccess?) -> Unit,
    content: @Composable (open: () -> Unit) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    Box {
        content { open = true }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            if (allowNone) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.no_access)) },
                    onClick = { open = false; onPick(null) },
                    enabled = current != null,
                )
            }
            listOf(VaultAccess.VIEW, VaultAccess.EDIT, VaultAccess.MANAGE).forEach { a ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(a.label())
                            Text(a.hint(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    },
                    onClick = { open = false; onPick(a) },
                    enabled = current != a,
                )
            }
        }
    }
}

@Composable
internal fun AccessChip(current: VaultAccess?, onClick: () -> Unit) {
    TextButton(onClick = onClick) { Text(current?.label() ?: stringResource(R.string.no_access)) }
}
