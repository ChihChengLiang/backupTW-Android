package tw.bonds.backuptw.wallet

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm")

private fun formatTimestamp(unixMillis: Long): String =
    Instant.ofEpochMilli(unixMillis).atZone(ZoneId.systemDefault()).format(TIMESTAMP_FORMAT)

/**
 * One credential's own activity log - matches the official TWDIW app's
 * "Credential History" screen. Reached by tapping a card in `HomeScreen`'s
 * stack; the primary screen for that tap (not a picker).
 */
@Composable
fun CredentialHistoryScreen(credentialId: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val events =
        remember(credentialId) {
            CredentialHistoryStore(context).load(credentialId).sortedByDescending { it.timestampUnixMillis }
        }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Text("Credential History", style = MaterialTheme.typography.headlineSmall)

        Card(
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(TELECOM_CARD_ISSUER_NAMES[credentialId] ?: credentialId, style = MaterialTheme.typography.titleMedium)
                Text(
                    TELECOM_CARD_DISPLAY_NAMES[credentialId] ?: credentialId,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Data", style = MaterialTheme.typography.titleMedium)
                Text("Newest First", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (events.isEmpty()) {
                Text("No activity yet.", style = MaterialTheme.typography.bodyMedium)
            } else {
                events.forEachIndexed { index, event ->
                    HistoryEventCard(event, startExpanded = index == 0)
                }
            }
        }

        TextButton(onClick = onBack) { Text("Back") }
    }
}

@Composable
private fun HistoryEventCard(event: CredentialHistoryEvent, startExpanded: Boolean) {
    var expanded by remember(event) { mutableStateOf(startExpanded) }

    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            when (event) {
                is CredentialHistoryEvent.Added -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            "Add Credential",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            formatTimestamp(event.timestampUnixMillis),
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 1,
                        )
                    }
                    Text("\"${event.credentialDisplayName}\" added.", style = MaterialTheme.typography.bodyMedium)
                }
                is CredentialHistoryEvent.Authorized -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            "Authorization Credentials",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            formatTimestamp(event.timestampUnixMillis),
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 1,
                        )
                    }
                    TextButton(onClick = { expanded = !expanded }) {
                        Text(event.purpose + if (expanded) " ▴" else " ▾", style = MaterialTheme.typography.bodyMedium)
                    }
                    if (expanded) {
                        HorizontalDivider()
                        DetailLine("Organization", event.organisationName)
                        DetailLine("Purpose", event.purpose)
                        event.vcNo?.let { DetailLine("VC No.", it) }
                        DetailLine("Data", event.disclosedFieldsLabel)
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Text(
        "$label  $value",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
