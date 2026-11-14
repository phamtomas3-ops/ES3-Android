package dev.es3.editor.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.dp

private val Dark = darkColorScheme(
    primary = Color(0xFF5EEAD4), onPrimary = Color(0xFF00201B),
    secondary = Color(0xFF8AB4F8), background = Color(0xFF0B0F14), onBackground = Color(0xFFE6EAF0),
    surface = Color(0xFF0B0F14), onSurface = Color(0xFFE6EAF0),
    surfaceContainer = Color(0xFF141B24), surfaceContainerHigh = Color(0xFF1B2430),
    onSurfaceVariant = Color(0xFF9AA7B8), error = Color(0xFFFFB4AB)
)
private val Light = lightColorScheme(
    primary = Color(0xFF00796B), secondary = Color(0xFF1A56C4),
    background = Color(0xFFF7F9FB), surface = Color(0xFFF7F9FB),
    surfaceContainer = Color(0xFFEAEFF4), surfaceContainerHigh = Color(0xFFDDE4EC)
)
private val Shapes = Shapes(
    small = RoundedCornerShape(12.dp), medium = RoundedCornerShape(18.dp), large = RoundedCornerShape(24.dp)
)

/** Dark by default (spec §5); Stage 7 adds a user theme setting. */
@Composable
fun ES3Theme(darkTheme: Boolean = true, content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (darkTheme) Dark else Light, shapes = Shapes, content = content)
}
