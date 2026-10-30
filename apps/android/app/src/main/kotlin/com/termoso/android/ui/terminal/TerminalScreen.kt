package com.termoso.android.ui.terminal

import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import com.termoso.core.SearchHit
import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.content.ActivityNotFoundException
import android.content.Intent
import android.speech.RecognizerIntent
import android.view.HapticFeedbackConstants
import android.view.KeyEvent
import android.view.inputmethod.InputMethodManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBackIosNew
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.KeyboardDoubleArrowDown
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SmallFloatingActionButton
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.MutableState
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.PopupProperties
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import com.termoso.android.R
import com.termoso.android.data.LiveEvent
import com.termoso.android.data.SessionEvent
import com.termoso.android.data.TerminalSession
import com.termoso.android.data.userMessage
import com.termoso.android.str
import com.termoso.android.ui.components.EmptyState
import com.termoso.android.ui.components.HostAvatar
import com.termoso.android.ui.components.connectingLabel
import com.termoso.android.ui.shell.ShellViewModel
import com.termoso.android.ui.snippets.SnippetPickerSheet
import com.termoso.core.ConnectStage
import com.termoso.core.LiveEndReason
import com.termoso.core.MobileSettings
import com.termoso.core.SessionState
import com.termoso.core.SpecialKey
import com.termoso.core.SuggestionItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import androidx.compose.foundation.shape.CircleShape
import com.termoso.android.ui.components.UserAvatar
import com.termoso.core.LiveParticipantCard

/** Lines one volume press scrolls through the history. */
private const val VOLUME_SCROLL_LINES = 3

/**
 * Terminal tab host, laid out like Termius: the terminal fills the screen, the
 * session bar (back, one pill per session, menu, new) sits at the bottom right
 * above the key panel and the soft keyboard. Sessions keep running when the
 * user navigates away; this screen only shows them.
 */
@Composable
fun TerminalScreen(
    shell: ShellViewModel,
    onBack: () -> Unit,
    onNewSession: () -> Unit,
    onOpenSnippets: () -> Unit,
    onOpenAccount: () -> Unit,
    /** Opens Settings → Customize keys from the key panel. */
    onCustomizeKeys: () -> Unit,
    /** Files shared into the app, offered to the active terminal once; `null` when none. */
    pendingShare: List<Uri>? = null,
    onShareConsumed: () -> Unit = {},
    /** Installs (or, with `null`, removes) the activity-level hardware-key hook while a terminal is shown. */
    onHardwareKeyHook: (((KeyEvent) -> Boolean)?) -> Unit = {},
    /** Session-menu targets: SFTP / port forwarding / editor for a saved host, new-host form for a quick target. */
    /** Show an SFTP connection that is already open (quick targets connect first, then navigate). */
    onOpenSftp: (String) -> Unit = {},
    onForward: (String) -> Unit = {},
    onEditHost: (String) -> Unit = {},
    onAddHost: (String) -> Unit = {},
) {
    val sessions by shell.sessions.sessions.collectAsStateWithLifecycle()
    val activeId by shell.sessions.activeId.collectAsStateWithLifecycle()
    val settings by shell.repo.settings.collectAsStateWithLifecycle()
    val active = sessions.firstOrNull { it.id == activeId } ?: sessions.lastOrNull()
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val view = LocalView.current
    val context = LocalContext.current

    // The foreground-service notification is invisible until the user grants
    // POST_NOTIFICATIONS on Android 13+; ask once, the first time a terminal is shown.
    val askNotifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    var askedNotifications by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(active != null) {
        if (active == null || askedNotifications || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return@LaunchedEffect
        askedNotifications = true
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    DisposableEffect(settings.keepScreenOn, active) {
        view.keepScreenOn = settings.keepScreenOn && active != null
        onDispose { view.keepScreenOn = false }
    }

    LaunchedEffect(sessions.isEmpty()) {
        if (sessions.isEmpty()) onBack()
    }

    var liveSheet by remember { mutableStateOf(false) }
    // Session whose `⋯` menu is open; it is also made active so the menu's shortcuts target it.
    var menuFor by remember { mutableStateOf<String?>(null) }
    // Bumped by the session menu to open the History & themes panel, which lives with the terminal.
    var panelRequest by remember { mutableStateOf(0) }
    // Key grid shown instead of the keyboard; toggled from the session bar like Termius.
    val gridShown = rememberSaveable { mutableStateOf(false) }
    // Bumped by the session bar's keyboard button to bring the soft keyboard back.
    var imeRequest by remember { mutableStateOf(0) }
    var searchRequest by remember { mutableStateOf(0) }
    // Background of the active terminal's theme: the session bar sits on it, as in Termius.
    val terminalBackground = remember { mutableStateOf<Color?>(null) }
    // The sharing sheet is per session: switching chips or losing the session closes it.
    LaunchedEffect(active?.id) { liveSheet = false }

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        snackbarHost = { SnackbarHost(snackbar, Modifier.windowInsetsPadding(WindowInsets.ime.union(WindowInsets.navigationBars))) },
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .statusBarsPadding()
                .windowInsetsPadding(WindowInsets.ime.union(WindowInsets.navigationBars)),
        ) {
            val bar: @Composable () -> Unit = {
                SessionBar(
                    sessions = sessions,
                    active = active,
                    onBack = onBack,
                    onSelect = { shell.sessions.setActive(it) },
                    onClose = { id -> scope.launch { shell.sessions.close(id) } },
                    onLive = { liveSheet = true },
                    onMenu = { id -> shell.sessions.setActive(id); menuFor = id },
                    onNew = onNewSession,
                    gridShown = gridShown.value,
                    onToggleGrid = {
                        if (gridShown.value) imeRequest++ else gridShown.value = true
                    },
                    onSearch = { searchRequest++ },
                    background = terminalBackground.value ?: MaterialTheme.colorScheme.surfaceContainer,
                )
            }
            if (active == null) {
                Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    EmptyState(
                        title = stringResource(R.string.no_sessions),
                        hint = stringResource(R.string.connect_to_a_host_to_open_a_terminal),
                        icon = Icons.Filled.Terminal,
                        action = { Button(onClick = onNewSession) { Text(stringResource(R.string.new_connection)) } },
                    )
                }
                bar()
            } else {
                ActiveSession(
                    session = active,
                    sessions = sessions,
                    shell = shell,
                    snackbar = snackbar,
                    settings = settings,
                    searchRequest = searchRequest,
                    onOpenSnippets = onOpenSnippets,
                    onOpenAccount = onOpenAccount,
                    onCustomizeKeys = onCustomizeKeys,
                    onNewSession = onNewSession,
                    pendingShare = pendingShare,
                    onShareConsumed = onShareConsumed,
                    onHardwareKeyHook = onHardwareKeyHook,
                    panelRequest = panelRequest,
                    gridShown = gridShown,
                    imeRequest = imeRequest,
                    terminalBackground = terminalBackground,
                    bar = bar,
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                )
            }
        }
    }
    if (liveSheet && active != null) {
        LiveSheet(session = active, shell = shell, onClose = { liveSheet = false })
    }
    val menuSession = menuFor?.let { id -> sessions.firstOrNull { it.id == id } }
    if (menuSession != null) {
        SessionActionsSheet(
            shell = shell,
            session = menuSession,
            sessions = sessions,
            onLive = { liveSheet = true },
            onPanel = { panelRequest++ },
            onCustomizeKeys = onCustomizeKeys,
            onNewSession = onNewSession,
            onOpenSftp = onOpenSftp,
            onForward = onForward,
            onEditHost = onEditHost,
            onAddHost = onAddHost,
            onClose = { menuFor = null },
        )
    }
}

private val ChipShape = RoundedCornerShape(8.dp)

/** Square 40dp chrome button of the session bar (back, sharing, menu, new). */
@Composable
private fun HeaderButton(icon: ImageVector, description: String, tint: Color? = null, onClick: () -> Unit) {
    Box(
        Modifier
            .size(36.dp)
            .clip(ChipShape)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = description, tint = tint ?: MaterialTheme.colorScheme.onSurface, modifier = Modifier.size(20.dp))
    }
}

/**
 * Session bar above the key panel: back, one pill per session (the active one
 * tinted with the accent and carrying its close button; long-press opens its
 * menu), sharing while a terminal is live, the `⋯` session menu and the
 * new-session button.
 */
@Composable
private fun SessionBar(
    sessions: List<TerminalSession>,
    active: TerminalSession?,
    onBack: () -> Unit,
    onSelect: (String) -> Unit,
    onClose: (String) -> Unit,
    onLive: () -> Unit,
    onMenu: (String) -> Unit,
    onNew: () -> Unit,
    gridShown: Boolean = false,
    onToggleGrid: (() -> Unit)? = null,
    onSearch: (() -> Unit)? = null,
    background: Color = MaterialTheme.colorScheme.surfaceContainer,
) {
    val activeId = active?.id
    // Termius: 30 dp tiles and pill, 10 dp apart, 10 dp from the edges, 10 dp above the strip.
    Row(
        Modifier
            .fillMaxWidth()
            .height(56.dp)
            .background(background)
            .padding(horizontal = 10.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        HeaderButton(Icons.Filled.ArrowBackIosNew, stringResource(R.string.back), onClick = onBack)
        val listState = rememberLazyListState()
        // Bring the active chip into view when the selection changes and again
        // whenever the row is re-measured to a new width (dialogs, IME), which
        // resets the scroll offset; manual scrolling in between is left alone.
        LaunchedEffect(activeId, sessions.size) {
            val index = sessions.indexOfFirst { it.id == activeId }
            if (index < 0) return@LaunchedEffect
            snapshotFlow {
                val info = listState.layoutInfo
                if (info.totalItemsCount > index) info.viewportEndOffset - info.viewportStartOffset else null
            }.filterNotNull().distinctUntilChanged().collect {
                listState.animateScrollToItem(index)
            }
        }
        LazyRow(
            Modifier.weight(1f),
            state = listState,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(sessions, key = { it.id }) { s ->
                SessionChip(
                    s,
                    s.id == activeId,
                    onClick = { onSelect(s.id) },
                    onLongClick = { onMenu(s.id) },
                    onClose = { onClose(s.id) },
                    // A lone session stretches across the row like the Termius pill.
                    fillWidth = sessions.size == 1,
                    modifier = if (sessions.size == 1) Modifier.fillParentMaxWidth() else Modifier,
                )
            }
        }
        if (active != null) {
            val shared by active.share.collectAsStateWithLifecycle()
            // Sharing has its own button only while it is on; otherwise it lives in the menu.
            if (active.isView || shared != null) {
                HeaderButton(
                    Icons.Filled.Groups,
                    if (active.isView) stringResource(R.string.shared_terminal) else stringResource(R.string.terminal_sharing),
                    tint = MaterialTheme.colorScheme.primary,
                    onClick = onLive,
                )
            }
            if (onSearch != null) HeaderButton(Icons.Filled.Search, stringResource(R.string.search_in_terminal), onClick = onSearch)
            HeaderButton(Icons.Filled.MoreVert, stringResource(R.string.session_actions), onClick = { onMenu(active.id) })
        }
        HeaderButton(Icons.Filled.Add, stringResource(R.string.new_session), tint = MaterialTheme.colorScheme.primary, onClick = onNew)
        if (onToggleGrid != null && active != null) {
            HeaderButton(
                if (gridShown) Icons.Filled.Keyboard else Icons.Filled.GridView,
                if (gridShown) stringResource(R.string.toggle_keyboard) else stringResource(R.string.more_keys),
                onClick = onToggleGrid,
            )
        }
    }
}

/**
 * One session pill: distro icon (a spinner while connecting), the name, and —
 * on the active pill — the close button. State shows through colour: accent
 * for the active session, error red for a failed one, muted for a closed one.
 */
@Composable
private fun SessionChip(
    session: TerminalSession,
    active: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    onClose: () -> Unit,
    /** Stretched pill: the name takes the free width so the close button sits at the edge. */
    fillWidth: Boolean = false,
    modifier: Modifier = Modifier,
) {
    val state by session.state.collectAsStateWithLifecycle()
    val detected by session.detectedOs.collectAsStateWithLifecycle()
    val accent = MaterialTheme.colorScheme.primary
    val bg = if (active) accent.copy(alpha = 0.18f) else MaterialTheme.colorScheme.surfaceContainerHigh
    val fg = when {
        state is SessionState.Failed -> MaterialTheme.colorScheme.error
        active -> accent
        state is SessionState.Closed -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> MaterialTheme.colorScheme.onSurface
    }
    Row(
        modifier
            .height(36.dp)
            .clip(ChipShape)
            .background(bg)
            // Not focusable: a focus grab (e.g. after a dialog closes) would
            // otherwise scroll the row back to the first chip.
            .focusProperties { canFocus = false }
            .combinedClickable(onClick = onClick, onLongClick = onLongClick, onLongClickLabel = stringResource(R.string.session_actions))
            .padding(start = 12.dp, end = if (active) 4.dp else 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        when {
            state is SessionState.Connecting -> CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = fg)
            session.isView -> Icon(Icons.Filled.Groups, contentDescription = null, tint = fg, modifier = Modifier.size(18.dp))
            else -> HostAvatar(detected ?: session.savedOsName, size = 20)
        }
        Text(
            session.label,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
            color = fg,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            // Weight only in a stretched pill: in an unbounded LazyRow item it would collapse to zero.
            modifier = if (fillWidth) Modifier.weight(1f) else Modifier.widthIn(max = 180.dp),
        )
        if (active) {
            Icon(
                Icons.Filled.Close,
                contentDescription = stringResource(R.string.close_session),
                tint = fg,
                modifier = Modifier
                    .size(26.dp)
                    .clip(RoundedCornerShape(13.dp))
                    .clickable(onClick = onClose)
                    .padding(5.dp),
            )
        }
    }
}

@Composable
private fun ActiveSession(
    session: TerminalSession,
    sessions: List<TerminalSession>,
    shell: ShellViewModel,
    snackbar: SnackbarHostState,
    settings: MobileSettings,
    onOpenSnippets: () -> Unit,
    onOpenAccount: () -> Unit,
    onCustomizeKeys: () -> Unit,
    onNewSession: () -> Unit,
    pendingShare: List<Uri>?,
    onShareConsumed: () -> Unit,
    onHardwareKeyHook: (((KeyEvent) -> Boolean)?) -> Unit,
    /** Incremented by the caller to open the History & themes sheet. */
    panelRequest: Int = 0,
    /** Incremented by the caller to open the scrollback search bar. */
    searchRequest: Int = 0,
    /** Whether the key grid stands in for the keyboard (owned by the screen so the session bar can toggle it). */
    gridShown: MutableState<Boolean> = mutableStateOf(false),
    /** Incremented by the caller to show the soft keyboard (closing the grid). */
    imeRequest: Int = 0,
    /** Receives the terminal theme's background colour from each frame. */
    terminalBackground: MutableState<Color?> = mutableStateOf(null),
    /** The session bar, drawn between the terminal and the key panel. */
    bar: @Composable () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val view = LocalView.current
    val configuration = LocalConfiguration.current
    val scope = rememberCoroutineScope()
    val controller = remember(session) { TerminalController(session) }
    val state by session.state.collectAsStateWithLifecycle()
    // Scrollback search: hits live in scrollback-absolute lines; the frame says which are on screen.
    var searchOpen by remember(session.id) { mutableStateOf(false) }
    var query by remember(session.id) { mutableStateOf("") }
    var hits by remember(session.id) { mutableStateOf<List<SearchHit>>(emptyList()) }
    var hitIndex by remember(session.id) { mutableIntStateOf(0) }
    var frameInfo by remember(session.id) { mutableStateOf(Triple(0L, 0L, 0)) }
    val frameTick by session.frameTick.collectAsStateWithLifecycle()
    LaunchedEffect(searchRequest) {
        if (searchRequest > 0) searchOpen = true
    }
    BackHandler(enabled = searchOpen) { searchOpen = false }
    LaunchedEffect(searchOpen) {
        if (!searchOpen) {
            query = ""
            hits = emptyList()
        }
    }
    var lastQuery by remember(session.id) { mutableStateOf("") }
    LaunchedEffect(searchOpen, query, frameTick) {
        if (!searchOpen || query.isBlank()) {
            hits = emptyList()
            lastQuery = query
            return@LaunchedEffect
        }
        delay(150)
        val found = withContext(Dispatchers.IO) { runCatching { session.rust.search(query) }.getOrDefault(emptyList()) }
        val fresh = query != lastQuery
        lastQuery = query
        hits = found
        if (found.isEmpty()) return@LaunchedEffect
        if (fresh || hitIndex >= found.size) {
            hitIndex = found.lastIndex
            withContext(Dispatchers.IO) { runCatching { session.rust.scrollToLine(found.last().line) } }
        }
    }
    val goHit: (Int) -> Unit = { delta ->
        if (hits.isNotEmpty()) {
            hitIndex = Math.floorMod(hitIndex + delta, hits.size)
            val line = hits[hitIndex].line
            scope.launch(Dispatchers.IO) { runCatching { session.rust.scrollToLine(line) } }
        }
    }
    val searchHighlights = remember(hits, frameInfo) {
        val (history, offset, rows) = frameInfo
        hits.mapNotNull { h ->
            val row = (h.line - (history - offset)).toInt()
            if (row in 0 until rows) {
                val c = h.col.toInt()
                TermSelection(CellPoint(row, c), CellPoint(row, c + h.len.toInt() - 1))
            } else {
                null
            }
        }
    }
    val prompt by session.prompt.collectAsStateWithLifecycle()
    val canWrite by session.canWrite.collectAsStateWithLifecycle()
    // Multiplayer: whoever typed last gets a small avatar above the cursor for a moment.
    var typingBy by remember(session) { mutableStateOf<LiveParticipantCard?>(null) }
    LaunchedEffect(session) {
        var clear: Job? = null
        session.typing.collect { id ->
            val card = session.participants.value.firstOrNull { it.userId == id && !it.me } ?: return@collect
            typingBy = card
            clear?.cancel()
            clear = launch {
                delay(2_500)
                typingBy = null
            }
        }
    }

    val fontSize = settings.terminalFontSize.toInt()
    val haptics = settings.hapticFeedback
    val bell = settings.terminalBell
    val keyRows = remember(settings.keyGroups) { KeyGroups.rows(settings.keyGroups) }
    val hardwareKeyboard = configuration.keyboard == Configuration.KEYBOARD_QWERTY &&
        configuration.hardKeyboardHidden == Configuration.HARDKEYBOARDHIDDEN_NO
    // The user can pull the panel back while a keyboard is attached; detaching resets that.
    var panelForced by remember(hardwareKeyboard) { mutableStateOf(false) }
    val panelCollapsed = settings.hidePanelWithKeyboard && hardwareKeyboard && !panelForced

    var panelExpanded by gridShown
    var imeShown by remember { mutableStateOf(false) }
    // The real keyboard state from the window insets; `imeShown` is our intent and follows it.
    @OptIn(ExperimentalLayoutApi::class)
    val imeVisible = WindowInsets.isImeVisible
    var hiddenInput by remember { mutableStateOf(false) }
    var snippetPicker by remember { mutableStateOf(false) }
    var askAi by remember { mutableStateOf(false) }
    var panelSheet by remember { mutableStateOf(false) }
    var panelTab by remember { mutableIntStateOf(0) }
    // Cursor mode (grid ✢): swipes on the terminal move the cursor with arrow keys.
    var cursorMode by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(panelRequest) { if (panelRequest > 0) panelSheet = true }
    var dropping by remember { mutableStateOf<DropProgress?>(null) }
    var confirmDrop by remember { mutableStateOf<List<Uri>?>(null) }
    var zoomDelta by rememberSaveable { mutableStateOf(0) }
    var scrolled by remember { mutableStateOf(false) }
    var arrowHint by remember { mutableStateOf<ArrowHint?>(null) }

    val autocompleteOn = autocompleteAllowed(settings.autocomplete, state, canWrite, session.isView)
    val completions = remember(session) { AutocompleteTracker() }
    var suggestions by remember(session) { mutableStateOf<List<SuggestionItem>>(emptyList()) }
    // Re-keyed by every rendered frame; the delay collapses output bursts.
    LaunchedEffect(session, frameTick, autocompleteOn) {
        if (!autocompleteOn) {
            completions.reset()
            suggestions = emptyList()
            return@LaunchedEffect
        }
        delay(AUTOCOMPLETE_DEBOUNCE_MS)
        val next = withContext(Dispatchers.IO) {
            completions.next(session.rust.typedLine()) { session.rust.suggestions() }
        }
        if (next != null) suggestions = next
    }

    LaunchedEffect(session) {
        session.events.collect { ev ->
            when (ev) {
                SessionEvent.Bell -> if (bell) {
                    view.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
                }
                is SessionEvent.Clipboard -> {
                    val result = snackbar.showSnackbar(
                        message = str(R.string.the_remote_wants_to_put_text_on_your),
                        actionLabel = str(R.string.copy),
                        duration = SnackbarDuration.Long,
                    )
                    if (result == SnackbarResult.ActionPerformed) copyToClipboard(context, ev.text)
                }
            }
        }
    }
    LaunchedEffect(session) {
        session.liveEvents.collect { ev ->
            val text = when (ev) {
                is LiveEvent.Control ->
                    if (ev.canWrite) str(R.string.the_host_let_you_type) else str(R.string.the_host_took_back_control_view_only)
                is LiveEvent.Ended -> when {
                    session.isView && ev.reason == LiveEndReason.STOPPED -> str(R.string.the_host_stopped_sharing)
                    session.isView -> str(R.string.shared_terminal_ended, ev.message)
                    ev.reason == LiveEndReason.STOPPED -> null
                    else -> str(R.string.sharing_ended, ev.message)
                }
            } ?: return@collect
            snackbar.showSnackbar(text)
        }
    }

    fun tap() {
        if (haptics) view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
    }

    fun zoom(delta: Int) {
        zoomDelta = (zoomDelta + delta).coerceIn(6 - fontSize, 40 - fontSize)
    }

    fun hideIme() {
        context.getSystemService<InputMethodManager>()?.hideSoftInputFromWindow(view.windowToken, 0)
        imeShown = false
    }

    fun toggleIme() {
        val imm = context.getSystemService<InputMethodManager>()
        val input = controller.inputView
        // Decide by what is on screen, not by our flag: a keyboard the system took away
        // (app switch, home and back) left `imeShown` true and the tap used to hide nothing.
        if (imeVisible) {
            hideIme()
        } else if (input != null) {
            input.requestFocus()
            if (imm?.showSoftInput(input, 0) != true) {
                imm?.showSoftInput(input, InputMethodManager.SHOW_IMPLICIT)
            }
            imeShown = true
            panelExpanded = false
        }
    }
    LaunchedEffect(imeRequest) {
        if (imeRequest > 0) {
            panelExpanded = false
            if (!imeShown) toggleIme()
        }
    }
    LaunchedEffect(panelExpanded) {
        // The grid stands in for the keyboard, as in Termius: one or the other.
        if (panelExpanded && imeShown) hideIme()
    }

    fun switchSession(forward: Boolean) {
        val index = sessions.indexOfFirst { it.id == session.id }
        val next = HardwareKeys.neighbour(sessions.size, index, forward) ?: return
        shell.sessions.setActive(sessions[next].id)
    }

    fun dropFiles(uris: List<Uri>) {
        if (uris.isEmpty() || dropping != null) return
        FileDrop.blocker(session)?.let { why ->
            scope.launch { snackbar.showSnackbar(why) }
            return
        }
        scope.launch {
            dropping = DropProgress("", 0, uris.size, 0, null)
            runCatching { FileDrop.send(context, session, uris) { dropping = it } }
                .onSuccess { paths ->
                    snackbar.showSnackbar(if (paths.size == 1) str(R.string.uploaded_to, paths.single()) else str(R.string.uploaded_files_to_tmp, paths.size))
                }
                .onFailure { snackbar.showSnackbar(str(R.string.upload_failed, it.userMessage())) }
            dropping = null
        }
    }

    // Shared files arrive while another screen may be up; offer them once this terminal is showing.
    // The share stays pending until the user answers, so a recomposition of
    // this screen (navigation, rotation) re-offers rather than drops it.
    LaunchedEffect(pendingShare) {
        val uris = pendingShare ?: return@LaunchedEffect
        session.state.first { it !is SessionState.Connecting }
        FileDrop.blocker(session)?.let { why ->
            // Consuming re-keys this effect, so the snackbar runs on the screen scope.
            scope.launch { snackbar.showSnackbar(why) }
            onShareConsumed()
            return@LaunchedEffect
        }
        confirmDrop = uris
    }

    val pickFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        dropFiles(uris)
    }

    // Compose box (long prompts for coding agents, dictation); text only leaves on Send/Paste.
    var composeOpen by rememberSaveable { mutableStateOf(false) }
    var composeText by rememberSaveable { mutableStateOf("") }
    val speech = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val heard = result.data?.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS)?.firstOrNull()?.trim()
        if (!heard.isNullOrEmpty()) {
            composeText = if (composeText.isBlank()) heard else composeText.trimEnd() + " " + heard
            composeOpen = true
        }
    }

    fun voiceInput() {
        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH)
            .putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            .putExtra(RecognizerIntent.EXTRA_PREFER_OFFLINE, true)
            .putExtra(RecognizerIntent.EXTRA_PROMPT, str(R.string.compose_message))
        try {
            speech.launch(intent)
        } catch (_: ActivityNotFoundException) {
            scope.launch { snackbar.showSnackbar(str(R.string.speech_not_available)) }
        }
    }

    fun paste() {
        val clip = context.getSystemService<ClipboardManager>()?.primaryClip
        val item = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)
        val text = item?.coerceToText(context)?.toString()
        val uri = item?.uri?.takeIf { it.scheme == "content" }
        when {
            !text.isNullOrEmpty() && (uri == null || text != uri.toString()) -> controller.paste(text)
            // An image or file on the clipboard (gallery "copy", keyboard sticker): upload it instead.
            uri != null -> dropFiles(listOf(uri))
            else -> scope.launch { snackbar.showSnackbar(str(R.string.clipboard_is_empty)) }
        }
    }

    fun run(action: InputAction) {
        when (action) {
            InputAction.Disabled -> Unit
            is InputAction.Key -> {
                tap()
                controller.press(action.key)
            }
            is InputAction.Ui -> when (action.action) {
                UiAction.FONT_UP -> zoom(1)
                UiAction.FONT_DOWN -> zoom(-1)
                UiAction.SCROLL_UP -> controller.scrollBy(VOLUME_SCROLL_LINES, controller.altScreen())
                UiAction.SCROLL_DOWN -> controller.scrollBy(-VOLUME_SCROLL_LINES, controller.altScreen())
                UiAction.NEXT_SESSION -> switchSession(forward = true)
                UiAction.PREV_SESSION -> switchSession(forward = false)
                UiAction.TOGGLE_KEYBOARD -> toggleIme()
                UiAction.CLOSE_SESSION -> scope.launch { shell.sessions.close(session.id) }
                UiAction.SEND_FILE -> if (FileDrop.blocker(session) == null) pickFiles.launch(arrayOf("*/*"))
                UiAction.COMPOSE -> composeOpen = true
                UiAction.VOICE_INPUT -> voiceInput()
            }
        }
    }

    fun run(hotkey: Hotkey) {
        when (hotkey) {
            Hotkey.PREV_SESSION -> switchSession(forward = false)
            Hotkey.NEXT_SESSION -> switchSession(forward = true)
            Hotkey.CLOSE_SESSION -> scope.launch { shell.sessions.close(session.id) }
            Hotkey.NEW_SESSION -> onNewSession()
            Hotkey.CLONE_SESSION -> scope.launch {
                when {
                    session.hostId != null && session.vaultId != null -> shell.connectHost(session.hostId, session.vaultId, session.transport)
                    session.quick != null -> shell.connectQuick(session.quick)
                    session.local != null -> shell.connectLocal()
                    else -> snackbar.showSnackbar(str(R.string.this_session_cannot_be_cloned))
                }
            }
            Hotkey.FONT_UP -> zoom(1)
            Hotkey.FONT_DOWN -> zoom(-1)
            Hotkey.FONT_RESET -> zoomDelta = 0
            Hotkey.PASTE -> paste()
            Hotkey.TOGGLE_PANEL -> if (panelCollapsed) panelForced = true else panelExpanded = !panelExpanded
        }
        hotkey.toast?.let { scope.launch { snackbar.showSnackbar(str(it)) } }
    }

    // Activity-level hook: volume bindings and Ctrl(+Shift) hotkeys never reach the
    // shell. Both DOWN and UP of a bound key are swallowed so the system does not
    // see half a press; anything unbound falls through untouched.
    val hook: (KeyEvent) -> Boolean = { ev ->
        val volume = HardwareKeys.volumeAction(ev.keyCode, settings.volumeUpAction, settings.volumeDownAction)
        val hotkey = if (volume == null) {
            HardwareKeys.hotkey(ev.keyCode, ev.isCtrlPressed, ev.isShiftPressed, ev.isAltPressed, settings.hardwareHotkeys)
        } else {
            null
        }
        when {
            volume != null -> {
                if (ev.action == KeyEvent.ACTION_DOWN) run(volume)
                true
            }
            hotkey != null -> {
                if (ev.action == KeyEvent.ACTION_DOWN && ev.repeatCount == 0) run(hotkey)
                true
            }
            else -> false
        }
    }

    // Shake gesture (Termius "shake action"): accelerometer only while a terminal is
    // in front and the action is bound; nothing is recorded.
    val shakeAction = remember(settings.shakeAction) { InputAction.parse(settings.shakeAction).takeIf { it != InputAction.Disabled } }
    DisposableEffect(shakeAction) {
        val action = shakeAction ?: return@DisposableEffect onDispose {}
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        val sensor = sm?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        if (sm == null || sensor == null) return@DisposableEffect onDispose {}
        var last = 0L
        val listener = object : SensorEventListener {
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
            override fun onSensorChanged(event: SensorEvent) {
                val (x, y, z) = event.values
                val g = kotlin.math.sqrt(x * x + y * y + z * z) / SensorManager.GRAVITY_EARTH
                val now = System.currentTimeMillis()
                if (g > 2.4f && now - last > 1000) {
                    last = now
                    run(action)
                }
            }
        }
        sm.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_GAME)
        onDispose { sm.unregisterListener(listener) }
    }
    val currentHook by rememberUpdatedState(hook)
    DisposableEffect(onHardwareKeyHook) {
        onHardwareKeyHook { currentHook(it) }
        onDispose { onHardwareKeyHook(null) }
    }

    // Like Termius: the first Back only puts the keyboard (or the key grid) away
    // so the terminal fills the screen; the next one leaves to Connections.
    // Last measured keyboard height: the key grid takes exactly this much room
    // when it replaces the keyboard, so the terminal does not jump between the two.
    // The screen already pads the navigation bar, and the IME inset includes it, so the
    // grid gets the keyboard height minus that bar.
    val density = LocalDensity.current
    val imeBottomPx = WindowInsets.ime.getBottom(density)
    val navBottomPx = WindowInsets.navigationBars.getBottom(density)
    var keyboardHeight by rememberSaveable { mutableStateOf(0f) }
    LaunchedEffect(imeBottomPx, imeVisible) {
        if (imeVisible && imeBottomPx > navBottomPx) {
            keyboardHeight = maxOf(keyboardHeight, with(density) { (imeBottomPx - navBottomPx).toDp().value })
        }
    }
    // The keyboard also comes up on its own (a tap on the terminal, the system restoring
    // it after a rotation or an app switch): follow the real inset so the flag stays honest
    // and the key grid never stands on top of the keyboard.
    LaunchedEffect(imeVisible) {
        if (imeVisible) {
            imeShown = true
            panelExpanded = false
        } else {
            imeShown = false
        }
    }
    BackHandler(enabled = imeVisible || panelExpanded) {
        when {
            panelExpanded -> panelExpanded = false
            else -> hideIme()
        }
    }

    Box(modifier) {
        Column(Modifier.fillMaxSize()) {
            if (session.isView) ViewBanner(canWrite)
            if (searchOpen) {
                TerminalSearchBar(
                    query = query,
                    onQuery = { query = it },
                    count = hits.size,
                    index = hitIndex,
                    onPrev = { goHit(-1) },
                    onNext = { goHit(1) },
                    onClose = { searchOpen = false },
                )
            }
            Box(Modifier.weight(1f).fillMaxWidth()) {
                TerminalView(
                    session = session,
                    controller = controller,
                    fontSizeSp = (fontSize + zoomDelta).coerceIn(6, 40),
                    fontFamily = settings.terminalFontFamily,
                    cursorBlink = settings.cursorBlink,
                    cursorStyle = settings.cursorStyle,
                    modifier = Modifier.fillMaxSize(),
                    onFrame = {
                        scrolled = it.frame.displayOffset > 0u
                        terminalBackground.value = it.frame.background?.toInt()?.let { c -> Color(c or (0xFF shl 24)) }
                        frameInfo = Triple(it.frame.history.toLong(), it.frame.displayOffset.toLong(), it.rows)
                    },
                    highlights = searchHighlights,
                    cursorBadge = typingBy?.let { card ->
                        {
                            UserAvatar(
                                shell.repo,
                                userId = card.userId,
                                tag = card.avatar,
                                name = card.displayName ?: card.email,
                                size = 22,
                                shape = CircleShape,
                            )
                        }
                    },
                    onTap = {
                        imeShown = true
                        panelExpanded = false
                    },
                    onCopy = { text ->
                        copyToClipboard(context, text)
                        scope.launch { snackbar.showSnackbar(str(R.string.selection_copied)) }
                    },
                    onPaste = ::paste,
                    selectionMenu = { cell, dismiss ->
                        // Non-focusable: a focusable popup would hide the IME and resize the grid.
                        DropdownMenu(
                            expanded = true,
                            onDismissRequest = dismiss,
                            properties = PopupProperties(focusable = false),
                        ) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.copy_line)) },
                                onClick = {
                                    dismiss()
                                    val line = CellGrid(session.rust.frame()).let { g ->
                                        if (cell.row in 0 until g.rows) g.lineText(cell.row) else ""
                                    }
                                    copyToClipboard(context, line)
                                    scope.launch { snackbar.showSnackbar(str(R.string.line_copied)) }
                                },
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.copy_screen)) },
                                onClick = {
                                    dismiss()
                                    copyToClipboard(context, controller.visibleText())
                                    scope.launch { snackbar.showSnackbar(str(R.string.screen_copied)) }
                                },
                            )
                            if (FileDrop.blocker(session) == null) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.send_file)) },
                                    onClick = { dismiss(); pickFiles.launch(arrayOf("*/*")) },
                                )
                            }
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.history_themes)) },
                                onClick = { dismiss(); panelSheet = true },
                            )
                        }
                    },
                    onZoom = ::zoom,
                    gestures = TerminalGestures(
                        pinchZoom = settings.pinchZoom,
                        swipeArrows = settings.swipeArrows || cursorMode,
                        swipeSessions = settings.swipeSessions,
                        longPressArrows = settings.longPressArrows,
                        doubleTapTab = settings.doubleTapTab,
                        cursorSpeed = ArrowGesture.speedOf(settings.cursorSpeed),
                    ),
                    onSwipeSession = ::switchSession,
                    onContent = { dropFiles(listOf(it)) },
                    onLink = { uri ->
                        scope.launch {
                            val r = snackbar.showSnackbar(uri, actionLabel = str(R.string.open_link), withDismissAction = true)
                            if (r == SnackbarResult.ActionPerformed) openLink(context, uri)
                        }
                    },
                    onArrowGesture = { arrowHint = it },
                )
                arrowHint?.let { ArrowGestureOverlay(it, Modifier.align(Alignment.Center)) }
                if (scrolled) {
                    SmallFloatingActionButton(
                        onClick = { controller.scrollToBottom() },
                        modifier = Modifier.align(Alignment.BottomEnd).padding(12.dp),
                    ) {
                        Icon(Icons.Filled.KeyboardDoubleArrowDown, contentDescription = stringResource(R.string.scroll_to_bottom))
                    }
                }
                StateOverlay(
                    state = state,
                    target = session.target,
                    onRetry = if (session.reconnectable) {
                        { scope.launch { shell.sessions.reconnect(session.id) } }
                    } else {
                        null
                    },
                    onClose = { scope.launch { shell.sessions.close(session.id) } },
                )
            }
            bar()
            AutocompleteStrip(
                items = suggestions,
                onPick = { item ->
                    suggestionInsert(item)?.let {
                        tap()
                        controller.sendText(it)
                    }
                },
            )
            KeyPanel(
                controller = controller,
                rows = keyRows,
                expanded = panelExpanded,
                collapsed = panelCollapsed,
                imeShown = imeShown,
                onToggleExpanded = {
                    panelExpanded = !panelExpanded
                    // The grid stands in for the keyboard, as on iOS: one or the other.
                    if (panelExpanded && imeShown) toggleIme()
                },
                onToggleCollapsed = { panelForced = true },
                onToggleIme = ::toggleIme,
                onHiddenInput = { hiddenInput = true },
                onSnippets = { snippetPicker = true },
                onAskAi = { askAi = true },
                onPanel = { panelTab = 0; panelSheet = true },
                onThemes = { panelTab = 1; panelSheet = true },
                cursorMode = cursorMode,
                onToggleCursorMode = { cursorMode = !cursorMode },
                onPaste = ::paste,
                canAttach = FileDrop.blocker(session) == null,
                onAttach = { pickFiles.launch(arrayOf("*/*")) },
                onCustomize = onCustomizeKeys,
                onCompose = { composeOpen = true },
                onVoice = ::voiceInput,
                onKeyPressed = ::tap,
                gridHeight = if (keyboardHeight > 0f) keyboardHeight.dp else null,
            )
        }
    }

    prompt?.let { pending ->
        PromptDialog(pending) { answer -> scope.launch { session.answer(pending, answer) } }
    }
    if (composeOpen) {
        ComposeSheet(
            text = composeText,
            onTextChange = { composeText = it },
            onVoice = ::voiceInput,
            onPaste = { t -> controller.paste(t); composeText = ""; composeOpen = false },
            onSend = { t ->
                controller.paste(t)
                controller.sendKey(SpecialKey.ENTER)
                composeText = ""
                composeOpen = false
            },
            onClose = { composeOpen = false },
        )
    }
    if (snippetPicker) {
        SnippetPickerSheet(
            shell = shell,
            sessionId = session.id,
            onOpenSnippets = onOpenSnippets,
            onClose = { snippetPicker = false },
        )
    }
    if (askAi) {
        AskAiSheet(
            shell = shell,
            session = session,
            connected = state is SessionState.Connected && canWrite,
            onInsert = { controller.paste(it) },
            onOpenAccount = onOpenAccount,
            onClose = { askAi = false },
        )
    }
    if (panelSheet) {
        TerminalPanelSheet(initialTab = panelTab, shell = shell, session = session, controller = controller, onClose = { panelSheet = false })
    }
    confirmDrop?.let { uris ->
        fun answer(send: Boolean) {
            confirmDrop = null
            onShareConsumed()
            if (send) dropFiles(uris)
        }
        AlertDialog(
            onDismissRequest = { answer(false) },
            title = { Text(if (uris.size == 1) stringResource(R.string.send_file_to, session.label) else stringResource(R.string.send_files_to, uris.size, session.label)) },
            text = { Text(stringResource(R.string.copied_to_tmp_on_the_remote_over_this)) },
            confirmButton = { TextButton(onClick = { answer(true) }) { Text(stringResource(R.string.send)) } },
            dismissButton = { TextButton(onClick = { answer(false) }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    dropping?.let { p ->
        AlertDialog(
            onDismissRequest = {},
            title = { Text(if (p.count > 1) stringResource(R.string.sending_of, p.index + 1, p.count) else stringResource(R.string.sending_file)) },
            text = {
                Column {
                    Text(p.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Spacer(Modifier.height(12.dp))
                    p.fraction?.let { LinearProgressIndicator(progress = { it }, modifier = Modifier.fillMaxWidth()) }
                        ?: LinearProgressIndicator(Modifier.fillMaxWidth())
                }
            },
            confirmButton = {},
        )
    }
    if (hiddenInput) {
        HiddenInputDialog(
            onSend = { text, enter ->
                hiddenInput = false
                controller.sendRaw(text, enter)
            },
            onDismiss = { hiddenInput = false },
        )
    }
}

/** Viewer strip: read-only until the host grants control; Rust drops input either way. */
@Composable
private fun ViewBanner(canWrite: Boolean) {
    val bg = if (canWrite) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh
    val fg = if (canWrite) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
    Row(
        Modifier.fillMaxWidth().background(bg).padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(Icons.Filled.Visibility, contentDescription = null, tint = fg, modifier = Modifier.size(16.dp))
        Text(
            if (canWrite) stringResource(R.string.shared_terminal_you_can_type) else stringResource(R.string.shared_terminal_view_only),
            style = MaterialTheme.typography.labelMedium,
            color = fg,
        )
    }
}

@Composable
private fun StateOverlay(state: SessionState, target: String, onRetry: (() -> Unit)?, onClose: () -> Unit) {
    when (val s = state) {
        is SessionState.Connected -> Unit
        is SessionState.Connecting -> OverlayCard {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                if (s.stage is ConnectStage.SecurityKeyTouch) {
                    Icon(Icons.Filled.TouchApp, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                } else {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                }
                Column {
                    Text(target, style = MaterialTheme.typography.titleSmall)
                    Text(connectingLabel(s), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        is SessionState.Closed -> OverlayCard {
            Text(stringResource(R.string.session_closed), style = MaterialTheme.typography.titleSmall)
            s.reason?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onClose) { Text(stringResource(R.string.close)) }
                if (onRetry != null) Button(onClick = onRetry) { Text(stringResource(R.string.reconnect)) }
            }
        }
        is SessionState.Failed -> OverlayCard {
            Text(failureTitle(s.kind), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.error)
            if (!s.message.equals(s.kind, ignoreCase = true)) {
                Text(s.message, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
                if (onRetry != null) Button(onClick = onRetry) { Text(stringResource(R.string.retry)) }
            }
        }
    }
}

private fun failureTitle(kind: String): String = when (kind) {
    "auth_failed" -> str(R.string.authentication_failed_2)
    "host_key_rejected" -> str(R.string.host_key_rejected)
    "io", "network" -> str(R.string.could_not_connect)
    "ssh" -> str(R.string.ssh_error)
    "cancelled" -> str(R.string.cancelled_2)
    "not_found" -> str(R.string.not_found)
    else -> str(R.string.connection_failed)
}

@Composable
private fun OverlayCard(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            tonalElevation = 3.dp,
        ) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) { content() }
        }
    }
}

internal fun copyToClipboard(context: android.content.Context, text: String) {
    context.getSystemService<ClipboardManager>()?.setPrimaryClip(ClipData.newPlainText("Termoso", text))
}

/** Open a hyperlink from the terminal: web and mail go to the system, anything else is copied. */
private fun openLink(context: Context, uri: String) {
    val scheme = uri.substringBefore(':', "").lowercase()
    if (scheme == "http" || scheme == "https" || scheme == "mailto") {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(uri)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
            .onFailure { copyToClipboard(context, uri) }
    } else {
        copyToClipboard(context, uri)
    }
}

@Composable
private fun TerminalSearchBar(
    query: String,
    onQuery: (String) -> Unit,
    count: Int,
    index: Int,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onClose: () -> Unit,
) {
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    Row(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TextField(
            value = query,
            onValueChange = onQuery,
            modifier = Modifier.weight(1f).focusRequester(focus),
            singleLine = true,
            placeholder = { Text(stringResource(R.string.search_terminal_hint)) },
            colors = TextFieldDefaults.colors(
                focusedContainerColor = Color.Transparent,
                unfocusedContainerColor = Color.Transparent,
                focusedIndicatorColor = Color.Transparent,
                unfocusedIndicatorColor = Color.Transparent,
            ),
        )
        Text(
            when {
                query.isBlank() -> ""
                count == 0 -> stringResource(R.string.no_matches)
                else -> stringResource(R.string.match_n_of_m, index + 1, count)
            },
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        IconButton(onClick = onPrev, enabled = count > 0) {
            Icon(Icons.Filled.KeyboardArrowUp, contentDescription = stringResource(R.string.previous_match))
        }
        IconButton(onClick = onNext, enabled = count > 0) {
            Icon(Icons.Filled.KeyboardArrowDown, contentDescription = stringResource(R.string.next_match))
        }
        IconButton(onClick = onClose) {
            Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.close))
        }
    }
}
