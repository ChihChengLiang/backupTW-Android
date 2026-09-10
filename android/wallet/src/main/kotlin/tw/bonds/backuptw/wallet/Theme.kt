package tw.bonds.backuptw.wallet

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * Light pink theme, chosen over `/design`
 * (https://claude.ai/code/artifact/257e1d0b-88f8-4687-a37b-ed6488cffe4f)
 * - deliberately not the iOS app's dark/teal-purple card-stack look, so
 * the two apps don't read as one team's work with matching features.
 * `HomeScreen`'s card stack uses its own fixed palette (front-to-back:
 * [CardStackFront], [CardStackMiddle], [CardStackBack]) rather than
 * deriving from [PrimaryPink] - those three tones are a set, picked
 * together, not implied by one color role.
 */
private val PrimaryPink = Color(0xFFD6336C)
private val OnPrimaryWhite = Color(0xFFFFFFFF)
private val BackgroundPinkTint = Color(0xFFFBF6F7)
private val SurfaceWhite = Color(0xFFFFFFFF)
private val OnSurfaceDark = Color(0xFF241419)
private val OnSurfaceMutedMauve = Color(0xFF8C6B73)

val CardStackFront = Color(0xFFE0527A)
val CardStackMiddle = Color(0xFFB5567A)
val CardStackBack = Color(0xFF8C3D63)

private val BackupTWLightColors =
    lightColorScheme(
        primary = PrimaryPink,
        onPrimary = OnPrimaryWhite,
        background = BackgroundPinkTint,
        onBackground = OnSurfaceDark,
        surface = SurfaceWhite,
        onSurface = OnSurfaceDark,
        surfaceVariant = BackgroundPinkTint,
        onSurfaceVariant = OnSurfaceMutedMauve,
        outline = PrimaryPink,
    )

/**
 * Always the light scheme, regardless of system theme - the user chose
 * light theme explicitly (see the plan this shipped under); no dark
 * variant has been designed yet.
 */
@Composable
fun BackupTWTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = BackupTWLightColors, content = content)
}
