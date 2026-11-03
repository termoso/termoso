package com.termoso.android.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.sp
import com.termoso.android.R

/** Label inside a segmented button: always one line, shrinks before it ellipsizes. */
@Composable
fun SegmentedLabel(text: String) {
    Text(
        text,
        maxLines = 1,
        softWrap = false,
        overflow = TextOverflow.Ellipsis,
        autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 14.sp, stepSize = 0.5.sp),
    )
}

/** Scaffold with a back arrow, used by every pushed sub-screen. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SubScreen(
    title: String,
    onBack: () -> Unit,
    actions: @Composable () -> Unit = {},
    floating: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back)) }
                },
                actions = { actions() },
            )
        },
        floatingActionButton = floating,
    ) { content(it) }
}

/** Single-line outlined field without autocorrect/capitalisation (aliases, hosts, usernames). */
@Composable
fun FormField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    placeholder: String? = null,
    keyboard: KeyboardType = KeyboardType.Text,
    visual: VisualTransformation = VisualTransformation.None,
    trailing: (@Composable () -> Unit)? = null,
    enabled: Boolean = true,
    singleLine: Boolean = true,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        singleLine = singleLine,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(
            keyboardType = keyboard,
            capitalization = KeyboardCapitalization.None,
            autoCorrectEnabled = false,
        ),
        visualTransformation = visual,
        trailingIcon = trailing,
        colors = OutlinedTextFieldDefaults.colors(),
    )
}

/** Password/passphrase field with a show–hide eye. */
@Composable
fun SecretField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    placeholder: String? = null,
    enabled: Boolean = true,
    leadingActions: (@Composable () -> Unit)? = null,
) {
    var visible by remember { mutableStateOf(false) }
    FormField(
        value = value,
        onChange = onChange,
        label = label,
        placeholder = placeholder,
        keyboard = KeyboardType.Password,
        visual = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        enabled = enabled,
        trailing = {
            androidx.compose.foundation.layout.Row {
                leadingActions?.invoke()
                IconButton(onClick = { visible = !visible }) {
                    Icon(
                        if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = if (visible) stringResource(R.string.hide) else stringResource(R.string.show),
                    )
                }
            }
        },
    )
}

/** Read-only outlined field that opens a dropdown of `(id, label)` options; `null` id = none. */
@Composable
fun PickerRow(
    label: String,
    value: String,
    options: List<Pair<String?, String>>,
    selected: String?,
    onPick: (String?) -> Unit,
    empty: String?,
) {
    var open by remember { mutableStateOf(false) }
    Box {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            singleLine = true,
            trailingIcon = { Icon(Icons.Filled.ArrowDropDown, contentDescription = null) },
            modifier = Modifier.fillMaxWidth(),
        )
        Box(Modifier.matchParentSize().clickable { open = true })
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { (id, text) ->
                DropdownMenuItem(
                    text = { Text(text) },
                    trailingIcon = if (id == selected) {
                        { Icon(Icons.Filled.Check, contentDescription = null) }
                    } else {
                        null
                    },
                    onClick = { onPick(id); open = false },
                )
            }
            if (options.size == 1 && empty != null) {
                DropdownMenuItem(text = { Text(empty, color = MaterialTheme.colorScheme.onSurfaceVariant) }, onClick = { open = false })
            }
        }
    }
}
