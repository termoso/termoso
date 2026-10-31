package com.termoso.android.ui.settings

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SyncProblem
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termoso.android.AppLanguage
import com.termoso.android.BuildConfig
import com.termoso.android.data.AppPin
import com.termoso.android.ui.security.PinSetupDialog
import com.termoso.android.R
import com.termoso.android.data.AccountManager
import com.termoso.android.data.AppContainer
import com.termoso.android.str
import com.termoso.android.ui.components.ChevronRow
import com.termoso.android.ui.components.ChoiceSheet
import com.termoso.android.ui.components.IconTile
import com.termoso.android.ui.components.ListRow
import com.termoso.android.ui.components.RowDivider
import com.termoso.android.ui.components.SectionCard
import com.termoso.android.ui.components.SectionLabel
import com.termoso.android.ui.components.SwitchRow
import com.termoso.android.ui.security.AuthResult
import com.termoso.android.ui.security.authenticateDevice
import com.termoso.android.ui.security.deviceAuthProblem
import com.termoso.android.ui.security.findFragmentActivity
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.android.ui.theme.supportsDynamicColor
import com.termoso.core.MobileSettings
import com.termoso.core.SyncState
import com.termoso.core.coreVersion
import com.termoso.core.terminalTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val themes = listOf("system" to R.string.system, "dark" to R.string.dark, "light" to R.string.light)

private val lockDelays = listOf(
    0u to R.string.immediately,
    30u to R.string.after_30_seconds,
    60u to R.string.after_1_minute,
    300u to R.string.after_5_minutes,
    900u to R.string.after_15_minutes,
    3600u to R.string.after_1_hour,
)

private val languages = listOf(
    AppLanguage.SYSTEM to R.string.system_default,
    "en" to R.string.language_english,
    "ru" to R.string.language_russian,
)

private const val SOURCE_URL = "https://github.com/termoso/termoso"

/** Settings tab: account/sync, appearance, terminal, security (app lock), about. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    shell: ShellViewModel,
    container: AppContainer,
    account: AccountManager,
    onAccount: () -> Unit,
    onSignIn: () -> Unit,
    onLock: () -> Unit,
    onTerminalAppearance: () -> Unit,
    onTerminalInput: () -> Unit,
    onLinux: () -> Unit,
) {
    val settings by shell.repo.settings.collectAsStateWithLifecycle()
    val accountStatus by account.status.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    fun set(transform: (MobileSettings) -> MobileSettings) {
        scope.launch { shell.repo.updateSettings(transform) }
    }
    var themePicker by remember { mutableStateOf(false) }
    var languagePicker by remember { mutableStateOf(false) }
    val language = remember { AppLanguage.current(context) }
    var delayPicker by remember { mutableStateOf(false) }
    var termTypePicker by remember { mutableStateOf(false) }
    var scrollbackPicker by remember { mutableStateOf(false) }
    var keepAlivePicker by remember { mutableStateOf(false) }
    var privacy by remember { mutableStateOf(false) }
    var licenses by remember { mutableStateOf(false) }
    val appLock by container.appLock.collectAsStateWithLifecycle()
    var pinSet by remember { mutableStateOf(container.appPin.isSet) }
    var pinMenu by remember { mutableStateOf(false) }
    var pinSetup by remember { mutableStateOf(false) }
    if (pinSetup) PinSetupDialog(container.appPin) { pinSetup = false; pinSet = container.appPin.isSet }
    if (pinMenu) {
        AlertDialog(
            onDismissRequest = { pinMenu = false },
            title = { Text(stringResource(R.string.app_pin_or_pattern)) },
            text = { Text(stringResource(R.string.app_pin_hint)) },
            confirmButton = { TextButton(onClick = { pinMenu = false; pinSetup = true }) { Text(stringResource(if (pinSet) R.string.change else R.string.set_up)) } },
            dismissButton = {
                if (pinSet) TextButton(onClick = { container.appPin.clear(); pinSet = false; pinMenu = false }) { Text(stringResource(R.string.remove)) }
                else TextButton(onClick = { pinMenu = false }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }
    var lockBusy by remember { mutableStateOf(false) }
    val filesEnabled by container.files.enabled.collectAsStateWithLifecycle()

    /**
     * Toggle the Keystore-gated master key. Both directions require passing the
     * system prompt first so the vault can never end up behind an unusable lock.
     */
    fun setAppLock(enable: Boolean) {
        if (lockBusy) return
        if (enable) {
            deviceAuthProblem(context)?.let { shell.notify(it); return }
        }
        val activity = context.findFragmentActivity() ?: return
        lockBusy = true
        scope.launch {
            try {
                val title = if (enable) str(R.string.turn_on_app_lock) else str(R.string.turn_off_app_lock)
                when (val r = authenticateDevice(activity, title, str(R.string.confirm_its_you))) {
                    AuthResult.Success -> {
                        runCatching { withContext(Dispatchers.IO) { container.setAppLock(enable) } }
                            .onSuccess { shell.notify(if (enable) str(R.string.app_lock_is_on) else str(R.string.app_lock_is_off)) }
                            .onFailure { shell.notify(it.message ?: str(R.string.could_not_change_app_lock)) }
                    }
                    AuthResult.Cancelled -> {}
                    is AuthResult.Failed -> shell.notify(r.message)
                }
            } finally {
                lockBusy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text(stringResource(R.string.settings)) }) }) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            Spacer(Modifier.height(8.dp))
            SectionCard {
                val card = accountStatus.account
                if (card == null) {
                    ChevronRow(
                        title = "Termoso Cloud",
                        subtitle = stringResource(R.string.free_forever_e2e_encrypted_sync_or_your_own),
                        leading = { IconTile(Icons.Filled.Cloud) },
                        modifier = Modifier.clickable(onClick = onSignIn),
                    )
                } else {
                    val sync = accountStatus.sync
                    ChevronRow(
                        title = card.displayName ?: card.email,
                        subtitle = card.serverUrl.removePrefix("https://").removePrefix("http://") + " · " +
                            when (sync.state) {
                                SyncState.IDLE -> if (sync.realtime) stringResource(R.string.synced_live) else stringResource(R.string.synced)
                                SyncState.SYNCING -> stringResource(R.string.syncing_2)
                                SyncState.OFFLINE -> stringResource(R.string.offline_2)
                                SyncState.ERROR -> stringResource(R.string.sync_failed_2)
                            },
                        leading = {
                            IconTile(
                                when (sync.state) {
                                    SyncState.OFFLINE -> Icons.Filled.CloudOff
                                    SyncState.ERROR -> Icons.Filled.SyncProblem
                                    else -> Icons.Filled.Cloud
                                },
                                tint = when (sync.state) {
                                    SyncState.ERROR -> MaterialTheme.colorScheme.error
                                    else -> MaterialTheme.colorScheme.primary
                                },
                            )
                        },
                        modifier = Modifier.clickable(onClick = onAccount),
                    )
                }
            }

            SectionLabel(stringResource(R.string.appearance))
            SectionCard {
                ChevronRow(
                    title = stringResource(R.string.app_theme),
                    badge = themes.firstOrNull { it.first == settings.appTheme }?.let { stringResource(it.second) } ?: settings.appTheme,
                    modifier = Modifier.clickable { themePicker = true },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.language),
                    badge = stringResource((languages.firstOrNull { it.first == language } ?: languages.first()).second),
                    modifier = Modifier.clickable { languagePicker = true },
                )
                if (supportsDynamicColor) {
                    RowDivider()
                    SwitchRow(
                        title = stringResource(R.string.dynamic_colors),
                        subtitle = stringResource(R.string.follow_the_wallpaper_palette_material_you),
                        checked = settings.dynamicColor,
                        onCheckedChange = { on -> set { it.copy(dynamicColor = on) } },
                    )
                }
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.terminal),
                    subtitle = "${terminalTheme(settings.terminalTheme)?.name ?: settings.terminalTheme} · " +
                        "${settings.terminalFontFamily} ${settings.terminalFontSize}",
                    leading = { IconTile(Icons.Filled.Palette) },
                    modifier = Modifier.clickable(onClick = onTerminalAppearance),
                )
            }

            SectionLabel(stringResource(R.string.terminal))
            SectionCard {
                ChevronRow(
                    title = stringResource(R.string.keyboard_gestures),
                    subtitle = stringResource(R.string.key_panel_rows_volume_buttons_physical_keyboard_swipes),
                    leading = { IconTile(Icons.Filled.Keyboard) },
                    modifier = Modifier.clickable(onClick = onTerminalInput),
                )
                RowDivider()
                val linux by container.linux.installed.collectAsStateWithLifecycle()
                ChevronRow(
                    title = stringResource(R.string.linux_environment),
                    subtitle = linux?.let { "${it.name} ${it.version}" } ?: stringResource(R.string.linux_environment_subtitle),
                    leading = { IconTile(Icons.Filled.Terminal) },
                    modifier = Modifier.clickable(onClick = onLinux),
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.detect_os),
                    subtitle = stringResource(R.string.read_the_remote_os_after_connecting_to_show),
                    checked = settings.detectOs,
                    onCheckedChange = { v -> set { it.copy(detectOs = v) } },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.import_shell_history),
                    subtitle = stringResource(R.string.show_the_host_s_own_command_history_in),
                    checked = settings.importShellHistory,
                    onCheckedChange = { v -> set { it.copy(importShellHistory = v) } },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.post_quantum_key_exchange),
                    subtitle = stringResource(R.string.prefer_ml_kem_hybrid_kex_when_the_server),
                    checked = settings.postQuantumKex,
                    onCheckedChange = { v -> set { it.copy(postQuantumKex = v) } },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.terminal_type),
                    badge = settings.termType,
                    modifier = Modifier.clickable { termTypePicker = true },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.scrollback),
                    badge = stringResource(R.string.n_lines, settings.scrollbackLines.toInt()),
                    modifier = Modifier.clickable { scrollbackPicker = true },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.keep_alive_interval),
                    subtitle = stringResource(R.string.default_for_hosts_without_their_own_interval),
                    badge = if (settings.keepAliveSeconds == 0u) stringResource(R.string.off) else stringResource(R.string.n_seconds_short, settings.keepAliveSeconds.toInt()),
                    modifier = Modifier.clickable { keepAlivePicker = true },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.auto_reconnect),
                    subtitle = stringResource(R.string.auto_reconnect_summary),
                    checked = settings.autoReconnect,
                    onCheckedChange = { v -> set { it.copy(autoReconnect = v) } },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.keep_screen_on),
                    subtitle = stringResource(R.string.while_a_terminal_is_in_the_foreground),
                    checked = settings.keepScreenOn,
                    onCheckedChange = { v -> set { it.copy(keepScreenOn = v) } },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.haptic_feedback),
                    checked = settings.hapticFeedback,
                    onCheckedChange = { v -> set { it.copy(hapticFeedback = v) } },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.terminal_bell),
                    subtitle = stringResource(R.string.vibrate_on_bel),
                    checked = settings.terminalBell,
                    onCheckedChange = { v -> set { it.copy(terminalBell = v) } },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.record_sessions),
                    subtitle = stringResource(R.string.keep_what_the_remote_side_prints_in_the),
                    checked = settings.recordSessions,
                    onCheckedChange = { v -> set { it.copy(recordSessions = v) } },
                )
            }

            SectionLabel(stringResource(R.string.security))
            SectionCard {
                SwitchRow(
                    title = stringResource(R.string.app_lock),
                    subtitle = if (appLock) {
                        stringResource(R.string.fingerprint_or_screen_lock_required_to_open_the)
                    } else {
                        stringResource(R.string.protect_the_vault_with_your_fingerprint_or_screen)
                    },
                    checked = appLock,
                    enabled = !lockBusy,
                    onCheckedChange = ::setAppLock,
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.lock_when_in_background),
                    subtitle = stringResource(R.string.ask_again_after_leaving_the_app_sessions_keep),
                    checked = settings.lockOnBackground,
                    enabled = appLock || pinSet,
                    onCheckedChange = { v -> set { it.copy(lockOnBackground = v) } },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.lock_after),
                    badge = lockDelays.firstOrNull { it.first == settings.lockAfterSeconds }?.let { stringResource(it.second) } ?: stringResource(R.string.n_seconds_short, settings.lockAfterSeconds.toLong()),
                    modifier = Modifier.clickable(enabled = (appLock || pinSet) && settings.lockOnBackground) { delayPicker = true },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.app_pin_or_pattern),
                    badge = when (container.appPin.kind?.takeIf { pinSet }) {
                        AppPin.Kind.PIN -> stringResource(R.string.pin)
                        AppPin.Kind.PATTERN -> stringResource(R.string.pattern)
                        null -> stringResource(R.string.off)
                    },
                    modifier = Modifier.clickable { pinMenu = true },
                )
                RowDivider()
                SwitchRow(
                    title = stringResource(R.string.remember_key_passphrases_in_memory),
                    subtitle = stringResource(R.string.key_passphrases_kept_in_ram_until_vault_locked),
                    checked = settings.cachePassphrases,
                    onCheckedChange = { v -> set { it.copy(cachePassphrases = v) } },
                )
                RowDivider()
                if (appLock) {
                    ChevronRow(
                        title = stringResource(R.string.lock_now),
                        subtitle = stringResource(R.string.cover_the_app_until_you_authenticate_sessions_stay),
                        leading = { IconTile(Icons.Filled.Fingerprint) },
                        modifier = Modifier.clickable(onClick = container::gate),
                    )
                    RowDivider()
                }
                ChevronRow(
                    title = stringResource(R.string.lock_vault_now),
                    subtitle = stringResource(R.string.disconnects_every_session_and_closes_the_encrypted_database),
                    leading = { IconTile(Icons.Filled.Lock) },
                    modifier = Modifier.clickable(onClick = onLock),
                )
            }

            SectionLabel(stringResource(R.string.files_integration))
            SectionCard {
                SwitchRow(
                    title = stringResource(R.string.files_show_sftp_hosts_in_files),
                    subtitle = stringResource(R.string.files_show_sftp_hosts_in_files_summary),
                    checked = filesEnabled,
                    onCheckedChange = container.files::setEnabled,
                )
            }

            SectionLabel(stringResource(R.string.about))
            SectionCard {
                ListRow(
                    title = stringResource(R.string.termoso_for_android),
                    subtitle = stringResource(R.string.core, BuildConfig.VERSION_NAME, coreVersion()),
                    leading = { IconTile(Icons.Filled.Info) },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.privacy),
                    subtitle = stringResource(R.string.no_telemetry_no_analytics_no_accounts_required),
                    leading = { IconTile(Icons.Filled.Shield) },
                    modifier = Modifier.clickable { privacy = true },
                )
                RowDivider()
                ChevronRow(
                    title = stringResource(R.string.source_code),
                    subtitle = stringResource(R.string.agpl_licensed_on_github),
                    leading = { IconTile(Icons.Filled.Code) },
                    modifier = Modifier.clickable {
                        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, SOURCE_URL.toUri())) }
                            .onFailure { shell.notify(SOURCE_URL) }
                    },
                )
                RowDivider()
                ChevronRow(title = stringResource(R.string.open_source_licenses), modifier = Modifier.clickable { licenses = true })
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    if (themePicker) {
        ChoiceSheet(stringResource(R.string.app_theme), themes.map { it.first to stringResource(it.second) }, settings.appTheme, onPick = { set { s -> s.copy(appTheme = it) } }) { themePicker = false }
    }
    if (languagePicker) {
        ChoiceSheet(
            stringResource(R.string.language),
            languages.map { it.first to stringResource(it.second) },
            language,
            onPick = { tag ->
                if (tag != language && AppLanguage.set(context, tag)) context.findFragmentActivity()?.recreate()
            },
        ) { languagePicker = false }
    }
    if (delayPicker) {
        ChoiceSheet(stringResource(R.string.lock_after), lockDelays.map { it.first to stringResource(it.second) }, settings.lockAfterSeconds, onPick = { set { s -> s.copy(lockAfterSeconds = it) } }) { delayPicker = false }
    }
    if (termTypePicker) {
        ChoiceSheet(
            stringResource(R.string.terminal_type),
            TERM_TYPES.map { it to it },
            settings.termType,
            onPick = { set { s -> s.copy(termType = it) } },
        ) { termTypePicker = false }
    }
    if (scrollbackPicker) {
        ChoiceSheet(
            stringResource(R.string.scrollback),
            SCROLLBACKS.map { it to stringResource(R.string.n_lines, it.toInt()) },
            settings.scrollbackLines,
            onPick = { set { s -> s.copy(scrollbackLines = it) } },
        ) { scrollbackPicker = false }
    }
    if (keepAlivePicker) {
        ChoiceSheet(
            stringResource(R.string.keep_alive_interval),
            KEEP_ALIVES.map { it to if (it == 0u) stringResource(R.string.off) else stringResource(R.string.n_seconds_short, it.toInt()) },
            settings.keepAliveSeconds,
            onPick = { set { s -> s.copy(keepAliveSeconds = it) } },
        ) { keepAlivePicker = false }
    }
    if (privacy) {
        AlertDialog(
            onDismissRequest = { privacy = false },
            title = { Text(stringResource(R.string.privacy)) },
            text = {
                Text(
                    stringResource(R.string.termoso_reports_to_you_not_on_you_no),
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = { TextButton(onClick = { privacy = false }) { Text(stringResource(R.string.close)) } },
        )
    }
    if (licenses) {
        AlertDialog(
            onDismissRequest = { licenses = false },
            title = { Text(stringResource(R.string.open_source_licenses)) },
            text = {
                Text(
                    stringResource(R.string.termoso_agpl_3_0_bundled_terminal_fonts_jetbrains),
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = { TextButton(onClick = { licenses = false }) { Text(stringResource(R.string.close)) } },
        )
    }
}

/** `TERM` values a shell is likely to have terminfo for. */
private val TERM_TYPES = listOf("xterm-256color", "xterm", "screen-256color", "tmux-256color", "linux", "vt100")
private val SCROLLBACKS = listOf(500u, 1000u, 2000u, 5000u, 10000u, 50000u)
private val KEEP_ALIVES = listOf(0u, 15u, 30u, 60u, 120u, 300u)
