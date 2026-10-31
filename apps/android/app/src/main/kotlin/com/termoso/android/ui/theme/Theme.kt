package com.termoso.android.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val DarkScheme = darkColorScheme(
    primary = Emerald,
    onPrimary = Color.White,
    primaryContainer = EmeraldDark,
    onPrimaryContainer = Color.White,
    secondary = Sky,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFF1E4A3C),
    onSecondaryContainer = EmeraldLight,
    tertiary = Sky,
    background = DarkLayers.base,
    onBackground = DarkLayers.text,
    surface = DarkLayers.base,
    onSurface = DarkLayers.text,
    surfaceVariant = DarkLayers.high,
    onSurfaceVariant = DarkLayers.secondary,
    surfaceContainerLowest = DarkLayers.lowest,
    surfaceContainerLow = DarkLayers.base,
    surfaceContainer = DarkLayers.high,
    surfaceContainerHigh = DarkLayers.highest,
    surfaceContainerHighest = DarkLayers.strong,
    outline = DarkLayers.disabled,
    outlineVariant = DarkLayers.high,
    error = Danger,
    onError = Color.White,
)

private val LightScheme = lightColorScheme(
    primary = EmeraldDark,
    onPrimary = Color.White,
    primaryContainer = EmeraldLight,
    onPrimaryContainer = LightLayers.text,
    secondary = Sky,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCFF0E3),
    onSecondaryContainer = Color(0xFF0F5C42),
    tertiary = Sky,
    background = LightLayers.base,
    onBackground = LightLayers.text,
    surface = LightLayers.base,
    onSurface = LightLayers.text,
    surfaceVariant = LightLayers.highest,
    onSurfaceVariant = LightLayers.secondary,
    surfaceContainerLowest = LightLayers.lowest,
    surfaceContainerLow = LightLayers.base,
    surfaceContainer = LightLayers.high,
    surfaceContainerHigh = LightLayers.highest,
    surfaceContainerHighest = LightLayers.strong,
    outline = LightLayers.disabled,
    outlineVariant = LightLayers.highest,
    error = Danger,
    onError = Color.White,
)

/** Material You is available from Android 12. */
val supportsDynamicColor: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

/**
 * `appTheme` is `system` / `dark` / `light` — same values as
 * `MobileSettings.appTheme`. With [dynamicColor] the palette follows the
 * wallpaper on Android 12+; older devices and the setting off use the fixed
 * emerald scheme.
 */
@Composable
fun TermosoTheme(
    appTheme: String = "system",
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val dark = when (appTheme) {
        "dark" -> true
        "light" -> false
        else -> isSystemInDarkTheme()
    }
    val context = LocalContext.current
    val scheme = when {
        dynamicColor && supportsDynamicColor ->
            (if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context))
                // Row dividers use outlineVariant; the Material You palette makes it a
                // visible line, while the Termoso schemes keep it one surface layer away
                // (barely there). Match that so sections look the same in both modes.
                .let { it.copy(outlineVariant = it.surfaceContainer) }
        dark -> DarkScheme
        else -> LightScheme
    }
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
        }
    }
    MaterialTheme(colorScheme = scheme, typography = TermosoTypography, content = content)
}
