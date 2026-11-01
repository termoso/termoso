package com.termoso.android

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.KeyEvent
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.termoso.android.data.AppContainer
import com.termoso.android.data.OpenTarget
import com.termoso.android.data.VaultState
import com.termoso.android.service.SessionService
import com.termoso.android.ui.TermosoRoot
import com.termoso.android.ui.keychain.LocalFido2
import com.termoso.android.ui.theme.TermosoTheme
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/** [FragmentActivity] rather than ComponentActivity because BiometricPrompt hosts a fragment. */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class MainActivity : FragmentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLanguage.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val container = (application as TermosoApplication).container
        // With app lock on, keep terminal contents out of Recents thumbnails and
        // screen capture unless Settings → Security → Allow screenshots says otherwise.
        lifecycleScope.launch {
            val allowScreenshots = container.vault.flatMapLatest { state ->
                (state as? VaultState.Open)?.repo?.settings?.map { it.allowScreenshots } ?: flowOf(false)
            }
            combine(container.appLock, allowScreenshots) { lock, allow -> lock && !allow }.distinctUntilChanged().collect { secure ->
                if (secure) {
                    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(!secure)
            }
        }
        handleLink(intent, container)
        setContent { App(container) }
    }

    override fun onStart() {
        super.onStart()
        SessionService.ensureRunning(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLink(intent, (application as TermosoApplication).container)
    }

    /**
     * Terminal-installed hook first (volume bindings, app hotkeys); everything else as usual.
     * ComponentActivity marks this override as restricted although it is the only place that
     * sees volume keys and chords before the focused view consumes them.
     */
    @SuppressLint("RestrictedApi")
    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        val hook = (application as TermosoApplication).container.hardwareKeyHook
        if (hook != null && hook(event)) return true
        return super.dispatchKeyEvent(event)
    }

    private fun handleLink(intent: Intent?, container: AppContainer) {
        when (intent?.action) {
            android.hardware.usb.UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                container.offerSerial()
                intent.action = Intent.ACTION_MAIN
                return
            }
            Intent.ACTION_SEND, Intent.ACTION_SEND_MULTIPLE -> {
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                val uris = sharedUris(intent)
                // Text shared from another app is typed into the terminal, like Termius' "share to terminal".
                if (uris.isEmpty() && !text.isNullOrEmpty()) container.offerShareText(text) else container.offerShare(uris)
                // Consumed: a rotation must not re-offer the same files.
                intent.action = Intent.ACTION_MAIN
                return
            }
            SessionService.ACTION_OPEN_TERMINAL, SessionService.ACTION_OPEN_CONNECTIONS,
            SessionService.ACTION_OPEN_FORWARDING, SessionService.ACTION_OPEN_FILES,
            -> {
                val id = intent.getStringExtra(SessionService.EXTRA_ID)
                container.offerOpen(
                    when (intent.action) {
                        SessionService.ACTION_OPEN_TERMINAL -> id?.let { OpenTarget.Terminal(it) } ?: OpenTarget.Connections
                        SessionService.ACTION_OPEN_FORWARDING -> OpenTarget.Forwarding
                        SessionService.ACTION_OPEN_FILES -> OpenTarget.Files(id)
                        else -> OpenTarget.Connections
                    },
                )
                intent.action = Intent.ACTION_MAIN
                return
            }
            Intent.ACTION_VIEW -> Unit
            else -> return
        }
        val link = intent.dataString ?: return
        parseSsoLink(link)?.let {
            container.offerSso(it)
            // Consumed: a rotation must not replay the callback.
            intent.action = Intent.ACTION_MAIN
            return
        }
        when (classifyLink(link)) {
            LinkKind.Invite -> container.offerInvite(link)
            LinkKind.Join -> container.offerJoin(link)
            LinkKind.Host -> hostLinkId(link)?.let(container::offerHost)
            LinkKind.Action -> quickAction(link)?.let(container::offerAction)
            LinkKind.Other -> Unit
        }
    }
}

/** Content URIs of a share intent: `EXTRA_STREAM` first, then the clip items (keyboard image paste, some galleries). */
internal fun sharedUris(intent: Intent): List<Uri> {
    val out = LinkedHashSet<Uri>()
    if (intent.action == Intent.ACTION_SEND_MULTIPLE) {
        val list = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
        }
        list?.forEach { out += it }
    } else {
        val one = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }
        one?.let { out += it }
    }
    intent.clipData?.let { clip ->
        for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let { out += it }
    }
    return out.filter { it.scheme == "content" }
}

@Composable
private fun App(container: AppContainer) {
    val vault by container.vault.collectAsStateWithLifecycle()
    var theme by rememberSaveable { mutableStateOf("system") }
    var dynamic by rememberSaveable { mutableStateOf(true) }
    val openSettings = (vault as? VaultState.Open)
        ?.repo?.settings?.collectAsStateWithLifecycle()?.value
    LaunchedEffect(openSettings?.appTheme, openSettings?.dynamicColor) {
        if (openSettings != null) {
            theme = openSettings.appTheme
            dynamic = openSettings.dynamicColor
        }
    }
    TermosoTheme(appTheme = theme, dynamicColor = dynamic) {
        CompositionLocalProvider(LocalFido2 provides container.fido2) {
            TermosoRoot(container = container, vault = vault)
        }
    }
}
