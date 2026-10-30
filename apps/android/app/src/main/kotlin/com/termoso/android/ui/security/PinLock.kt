package com.termoso.android.ui.security

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.termoso.android.R
import com.termoso.android.data.AppPin
import com.termoso.android.ui.components.IconTile
import kotlinx.coroutines.delay

/** Full-screen gate asking for the configured PIN or pattern. */
@Composable
fun PinLockScreen(pin: AppPin, onUnlocked: () -> Unit) {
    var error by remember { mutableStateOf<String?>(null) }
    var retry by remember { mutableStateOf(pin.retryIn()) }
    LaunchedEffect(retry) { if (retry > 0) { delay(1000); retry = pin.retryIn() } }
    val wait = stringResource(R.string.try_again_in_n_seconds, retry)
    val wrong = stringResource(R.string.wrong_code)
    fun submit(code: String) {
        if (pin.verify(code)) onUnlocked() else { retry = pin.retryIn(); error = if (retry > 0) wait else wrong }
    }
    Scaffold { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            IconTile(Icons.Filled.Lock, size = 56, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(12.dp))
            Text(stringResource(R.string.termoso_is_locked), style = MaterialTheme.typography.titleMedium)
            Text(
                error ?: if (retry > 0) wait else stringResource(if (pin.kind == AppPin.Kind.PATTERN) R.string.draw_your_pattern else R.string.enter_your_pin),
                style = MaterialTheme.typography.bodyMedium,
                color = if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(24.dp))
            CodeEntry(kind = pin.kind ?: AppPin.Kind.PIN, enabled = retry == 0L, onSubmit = { submit(it); error?.let { } })
        }
    }
}

/** Set up or change the app PIN / pattern: pick a kind, enter twice. */
@Composable
fun PinSetupDialog(pin: AppPin, onDone: () -> Unit) {
    var kind by remember { mutableStateOf(pin.kind ?: AppPin.Kind.PIN) }
    var first by remember { mutableStateOf<String?>(null) }
    var mismatch by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(stringResource(if (first == null) R.string.set_app_pin else R.string.confirm_code)) },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (first == null) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(selected = kind == AppPin.Kind.PIN, onClick = { kind = AppPin.Kind.PIN }, label = { Text(stringResource(R.string.pin)) })
                        FilterChip(selected = kind == AppPin.Kind.PATTERN, onClick = { kind = AppPin.Kind.PATTERN }, label = { Text(stringResource(R.string.pattern)) })
                    }
                    Spacer(Modifier.height(12.dp))
                }
                if (mismatch) Text(stringResource(R.string.codes_do_not_match), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                CodeEntry(kind = kind, enabled = true) { code ->
                    val f = first
                    when {
                        f == null -> { first = code; mismatch = false }
                        f == code -> { pin.set(code, kind); onDone() }
                        else -> { first = null; mismatch = true }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDone) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun CodeEntry(kind: AppPin.Kind, enabled: Boolean, onSubmit: (String) -> Unit) {
    when (kind) {
        AppPin.Kind.PIN -> PinPad(enabled, onSubmit)
        AppPin.Kind.PATTERN -> PatternGrid(enabled, onSubmit)
    }
}

@Composable
private fun PinPad(enabled: Boolean, onSubmit: (String) -> Unit) {
    var code by remember { mutableStateOf("") }
    LaunchedEffect(code) { if (code.length == 6) { onSubmit(code); code = "" } }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            repeat(6) { i ->
                Box(
                    Modifier.size(12.dp).clip(CircleShape)
                        .background(if (i < code.length) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant),
                )
            }
        }
        Spacer(Modifier.height(20.dp))
        val rows = listOf("123", "456", "789", " 0<")
        rows.forEach { r ->
            Row {
                r.forEach { ch ->
                    when (ch) {
                        ' ' -> Spacer(Modifier.size(72.dp))
                        '<' -> IconButton(onClick = { code = code.dropLast(1) }, enabled = enabled, modifier = Modifier.size(72.dp)) {
                            Icon(Icons.AutoMirrored.Filled.Backspace, contentDescription = stringResource(R.string.backspace))
                        }
                        else -> TextButton(onClick = { if (code.length < 6) code += ch }, enabled = enabled, modifier = Modifier.size(72.dp)) {
                            Text(ch.toString(), style = MaterialTheme.typography.headlineSmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PatternGrid(enabled: Boolean, onSubmit: (String) -> Unit) {
    val path = remember { mutableStateOf<List<Int>>(emptyList()) }
    var finger by remember { mutableStateOf<Offset?>(null) }
    val primary = MaterialTheme.colorScheme.primary
    val dot = MaterialTheme.colorScheme.onSurfaceVariant
    Canvas(
        Modifier.fillMaxWidth(0.7f).aspectRatio(1f).pointerInput(enabled) {
            if (!enabled) return@pointerInput
            val cell = size.width / 3f
            fun hit(p: Offset): Int? {
                val c = (p.x / cell).toInt().coerceIn(0, 2)
                val r = (p.y / cell).toInt().coerceIn(0, 2)
                val centre = Offset((c + 0.5f) * cell, (r + 0.5f) * cell)
                return if ((p - centre).getDistance() < cell * 0.35f) r * 3 + c else null
            }
            detectDragGestures(
                onDragStart = { p -> path.value = listOfNotNull(hit(p)); finger = p },
                onDrag = { change, _ ->
                    finger = change.position
                    hit(change.position)?.let { if (it !in path.value) path.value = path.value + it }
                },
                onDragEnd = {
                    finger = null
                    val p = path.value
                    path.value = emptyList()
                    if (p.size >= 4) onSubmit(p.joinToString(""))
                },
                onDragCancel = { finger = null; path.value = emptyList() },
            )
        },
    ) {
        val cell = size.width / 3f
        fun centre(i: Int) = Offset((i % 3 + 0.5f) * cell, (i / 3 + 0.5f) * cell)
        val pts = path.value.map(::centre)
        for (i in 1 until pts.size) drawLine(primary, pts[i - 1], pts[i], strokeWidth = 10f, cap = StrokeCap.Round)
        if (pts.isNotEmpty()) finger?.let { drawLine(primary.copy(alpha = 0.5f), pts.last(), it, strokeWidth = 10f, cap = StrokeCap.Round) }
        for (i in 0 until 9) {
            val on = i in path.value
            drawCircle(if (on) primary else dot, radius = if (on) cell * 0.14f else cell * 0.09f, center = centre(i))
            if (on) drawCircle(Color.White, radius = cell * 0.05f, center = centre(i))
        }
    }
}
