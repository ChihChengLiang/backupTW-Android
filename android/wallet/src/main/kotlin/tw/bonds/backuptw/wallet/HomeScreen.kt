package tw.bonds.backuptw.wallet

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

/**
 * Display names for the telecom credential types this app can hold -
 * matched to `core::twdiw::convenience_store_pickup::TELECOM_CREDENTIAL_TYPES`
 * (the source of truth for which type strings these are), kept here by
 * hand since there is no FFI-exported display name for a bare type
 * string. Presentation-only: nothing here makes a trust decision.
 */
private val TELECOM_CARD_DISPLAY_NAMES =
    mapOf(
        "96979933_name_phonel5_phonel3" to "中華電信門號電子卡",
        "97179430_fet_vc_prod" to "遠傳電信門號電子卡",
        "97176270_twmdiwvc_postpaid" to "台灣大哥大門號電子卡",
    )

@Composable
fun HomeScreen(onNavigate: (Screen) -> Unit) {
    val context = LocalContext.current
    val credentialStore = remember { CredentialStore(context) }
    val storedIds by remember { mutableStateOf(credentialStore.allIds()) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("有備而來", style = MaterialTheme.typography.headlineMedium)
        Text(
            "A digital wallet for Taiwan's TWDIW credentials.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Stored credentials", style = MaterialTheme.typography.titleMedium)
            if (storedIds.isEmpty()) {
                Text("None yet - apply for a card below.", style = MaterialTheme.typography.bodyMedium)
            } else {
                storedIds.forEach { id ->
                    Text("• ${TELECOM_CARD_DISPLAY_NAMES[id] ?: id}", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        HorizontalDivider()
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { onNavigate(Screen.ApplyForCard) }) { Text("Apply for a telecom card") }
            Button(onClick = { onNavigate(Screen.PickupCatalog) }) { Text("7-Eleven package pickup") }
        }

        HorizontalDivider()
        TextButton(onClick = { onNavigate(Screen.DeveloperTools) }) { Text("Developer tools") }
    }
}
