package tw.bonds.backuptw.wallet

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

/**
 * Display names for the telecom credential types this app can hold -
 * matched to `core::twdiw::convenience_store_pickup::TELECOM_CREDENTIAL_TYPES`
 * (the source of truth for which type strings these are), kept here by
 * hand since there is no FFI-exported display name for a bare type
 * string. Presentation-only: nothing here makes a trust decision.
 * Not `private` - `ApplyForCardScreen`/`CredentialHistoryScreen` reuse
 * it too, rather than keeping their own copies.
 */
val TELECOM_CARD_DISPLAY_NAMES =
    mapOf(
        "96979933_name_phonel5_phonel3" to "中華電信門號電子卡",
        "97179430_fet_vc_prod" to "遠傳電信門號電子卡",
        "97176270_twmdiwvc_postpaid" to "台灣大哥大門號電子卡",
    )

/** Short issuer label per card, for the card stack's subtitle line - also reused by `CredentialHistoryScreen`. */
val TELECOM_CARD_ISSUER_NAMES =
    mapOf(
        "96979933_name_phonel5_phonel3" to "中華電信",
        "97179430_fet_vc_prod" to "遠傳電信",
        "97176270_twmdiwvc_postpaid" to "台灣大哥大",
    )

/**
 * Fixed display order, matching `TELECOM_CARD_DISPLAY_NAMES`'s declared
 * order (itself matching core's `TELECOM_CREDENTIAL_TYPES`) - so the
 * card stack's front-to-back order is stable across restarts rather
 * than following `CredentialStore.allIds()`'s filesystem-listing order.
 */
private val TELECOM_CARD_ORDER = TELECOM_CARD_DISPLAY_NAMES.keys.toList()

/** Front-to-back card colors, picked as a set - see `Theme.kt`. */
private val CARD_STACK_COLORS = listOf(CardStackBack, CardStackMiddle, CardStackFront)

private val CARD_HEIGHT = 172.dp
private val CARD_PEEK = 64.dp

@Composable
fun HomeScreen(onOpenDeveloperTools: () -> Unit, onOpenCredential: (String) -> Unit) {
    val context = LocalContext.current
    val credentialStore = remember { CredentialStore(context) }
    val storedIds by remember { mutableStateOf(credentialStore.allIds()) }
    val orderedIds = remember(storedIds) { storedIds.sortedBy { TELECOM_CARD_ORDER.indexOf(it) } }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("有備而來", style = MaterialTheme.typography.headlineMedium)
        Text(
            "A digital wallet for Taiwan's TWDIW credentials.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                "Stored credentials",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (orderedIds.isEmpty()) {
                Text("None yet - use the Add tab to apply for a card.", style = MaterialTheme.typography.bodyMedium)
            } else {
                CredentialCardStack(orderedIds, onOpenCard = onOpenCredential)
            }
        }

        HorizontalDivider()
        TextButton(onClick = onOpenDeveloperTools) { Text("Developer tools") }
    }
}

/**
 * The stored credentials as an overlapping stack (mock:
 * https://claude.ai/code/artifact/257e1d0b-88f8-4687-a37b-ed6488cffe4f)
 * - each card peeks [CARD_PEEK] above the one drawn after it, so only
 * the frontmost (last, fully visible) card gets the full verified-
 * badge treatment; cards further back show just their name in their
 * visible strip. `ids` is already in stable front-to-back order.
 */
@Composable
private fun CredentialCardStack(ids: List<String>, onOpenCard: (String) -> Unit) {
    val stackHeight = CARD_HEIGHT + CARD_PEEK * (ids.size - 1)
    Box(modifier = Modifier.fillMaxWidth().height(stackHeight)) {
        ids.forEachIndexed { index, id ->
            val color = CARD_STACK_COLORS[index.coerceAtMost(CARD_STACK_COLORS.size - 1)]
            val isFrontmost = index == ids.lastIndex
            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .offset(y = CARD_PEEK * index)
                        .height(CARD_HEIGHT)
                        .background(color, RoundedCornerShape(18.dp))
                        .clickable { onOpenCard(id) }
                        .padding(20.dp),
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        TELECOM_CARD_DISPLAY_NAMES[id] ?: id,
                        style = MaterialTheme.typography.titleMedium,
                        color = Color.White,
                    )
                    Text(
                        TELECOM_CARD_ISSUER_NAMES[id] ?: "",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color.White.copy(alpha = 0.7f),
                    )
                }
                if (isFrontmost) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkmark(color = Color.White)
                        Text(
                            "已驗證 · 數位發展部信任清單",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.8f),
                        )
                    }
                }
            }
        }
    }
}

/** A small stroke-based checkmark, matching the mock's SVG icon - no icon library dependency for one glyph. */
@Composable
private fun Checkmark(color: Color) {
    Canvas(modifier = Modifier.size(14.dp).padding(end = 8.dp)) {
        val stroke = Stroke(width = 2.2.dp.toPx(), cap = StrokeCap.Round)
        val path =
            Path().apply {
                moveTo(size.width * 0.05f, size.height * 0.55f)
                lineTo(size.width * 0.4f, size.height * 0.9f)
                lineTo(size.width * 0.95f, size.height * 0.15f)
            }
        drawPath(path, color = color, style = stroke)
    }
}
