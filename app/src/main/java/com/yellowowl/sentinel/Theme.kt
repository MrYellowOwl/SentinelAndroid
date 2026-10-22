package com.yellowowl.sentinel

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.Color

/**
 * All color tokens the UI draws with. Two palettes ship: Cyber Contrast (default,
 * true-black OLED with cyan + magenta) and Light & Crisp (daytime light mode).
 * The user swaps between them from Settings; the choice persists in [SentinelSettings].
 */
internal data class SentinelPalette(
    val isLight: Boolean,
    val bg: Color,
    val surface: Color,
    val surfaceRaised: Color,
    val accent: Color,
    val accentAlt: Color,
    val onAccent: Color,
    val textMain: Color,
    val textMuted: Color,
    val border: Color,
    val navIndicator: Color,
    val high: Color,
    val medium: Color,
    val low: Color
)

/** Default: true-black background, cyan primary, magenta secondary — high contrast. */
internal val CyberDark = SentinelPalette(
    isLight = false,
    bg = Color(0xFF000000),
    surface = Color(0xFF0A0F14),
    surfaceRaised = Color(0xFF121A22),
    accent = Color(0xFF22D3EE),
    accentAlt = Color(0xFFE879F9),
    onAccent = Color(0xFF001016),
    textMain = Color(0xFFEAFBFF),
    textMuted = Color(0xFF7E97A5),
    border = Color(0xFF1E2A33),
    navIndicator = Color(0xFF0E2A33),
    high = Color(0xFFFF4D74),
    medium = Color(0xFFFFB020),
    low = Color(0xFF38BDF8)
)

/** Light mode: soft off-white surfaces, indigo primary, pink secondary. */
internal val LightCrisp = SentinelPalette(
    isLight = true,
    bg = Color(0xFFF4F6FA),
    surface = Color(0xFFFFFFFF),
    surfaceRaised = Color(0xFFFFFFFF),
    accent = Color(0xFF4F46E5),
    accentAlt = Color(0xFFDB2777),
    onAccent = Color(0xFFFFFFFF),
    textMain = Color(0xFF0F172A),
    textMuted = Color(0xFF64748B),
    border = Color(0xFFE2E8F0),
    navIndicator = Color(0xFFE0E7FF),
    high = Color(0xFFDC2626),
    medium = Color(0xFFD97706),
    low = Color(0xFF2563EB)
)

/**
 * The live palette. It is a snapshot state, so every token getter below subscribes the
 * composition that reads it — flipping this value re-themes the whole app instantly.
 */
internal val paletteState = mutableStateOf(CyberDark)

/** Point the app at a palette (called on startup from the saved setting and by the toggle). */
internal fun applyTheme(light: Boolean) {
    paletteState.value = if (light) LightCrisp else CyberDark
}

// Token accessors — same names the screens already use, now backed by the live palette.
internal val Bg: Color get() = paletteState.value.bg
internal val SurfaceColor: Color get() = paletteState.value.surface
internal val SurfaceRaised: Color get() = paletteState.value.surfaceRaised
internal val Accent: Color get() = paletteState.value.accent
internal val AccentAlt: Color get() = paletteState.value.accentAlt
internal val OnAccent: Color get() = paletteState.value.onAccent
internal val TextMain: Color get() = paletteState.value.textMain
internal val TextMuted: Color get() = paletteState.value.textMuted
internal val Border: Color get() = paletteState.value.border
internal val NavIndicator: Color get() = paletteState.value.navIndicator
internal val HighColor: Color get() = paletteState.value.high
internal val MediumColor: Color get() = paletteState.value.medium
internal val LowColor: Color get() = paletteState.value.low

internal fun Severity.color(): Color = when (this) {
    Severity.HIGH -> HighColor
    Severity.MEDIUM -> MediumColor
    Severity.LOW -> LowColor
    Severity.INFO -> Accent
}

/** Wraps content in a MaterialTheme whose color scheme tracks the live palette. */
@Composable
internal fun SentinelTheme(content: @Composable () -> Unit) {
    val p = paletteState.value
    val base = if (p.isLight) lightColorScheme() else darkColorScheme()
    MaterialTheme(
        colorScheme = base.copy(
            primary = p.accent,
            onPrimary = p.onAccent,
            secondary = p.accentAlt,
            background = p.bg,
            surface = p.surface,
            surfaceVariant = p.surfaceRaised,
            onSurface = p.textMain,
            onSurfaceVariant = p.textMuted,
            onBackground = p.textMain,
            outline = p.border,
            error = p.high
        ),
        content = content
    )
}
