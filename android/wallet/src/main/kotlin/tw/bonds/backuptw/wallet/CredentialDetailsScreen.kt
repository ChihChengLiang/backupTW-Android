package tw.bonds.backuptw.wallet

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import uniffi.backuptw_core.FfiTwdiwCredential
import uniffi.backuptw_core.credentialSerial
import uniffi.backuptw_core.readTwdiwCredential

private val EXPIRY_FORMAT = DateTimeFormatter.ofPattern("yyyy/MM/dd")

/** Friendly labels for the claims a TWDIW telecom credential discloses - the fixed set `PickupClient.matchAndDisclose` and the official app both work with. */
private val CLAIM_DISPLAY_LABELS =
    mapOf(
        "name" to "Name",
        "phonel3" to "Last 3 digits of phone number",
        "phonel5" to "Last 5 digits of phone number",
    )

private const val MASKED_VALUE = "••••••"

/**
 * The fields a stored credential actually holds - matches the official
 * TWDIW app's "Credential Details" screen. Reached from
 * [CredentialHistoryScreen]'s "Credential Details" link, not directly
 * from a card tap (History is the primary screen for that).
 *
 * Deliberately not carried over from the official screenshot: an
 * "Identity Assurance Level" row (this app doesn't compute or verify
 * one anywhere in `core` - showing a number would be fabricated) and
 * "Update" links next to each field (there's nothing to update to -
 * `PickupClient.matchAndDisclose` always picks the one matching stored
 * credential automatically).
 */
@Composable
fun CredentialDetailsScreen(credentialId: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val credential =
        remember(credentialId) {
            runCatching {
                val serialized = CredentialStore(context).load(credentialId) ?: error("credential not found")
                readTwdiwCredential(serialized, System.currentTimeMillis() / 1000)
            }
        }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Text("Credential Details", style = MaterialTheme.typography.headlineSmall)

        credential.fold(
            onSuccess = { CredentialDetailsCard(credentialId, it) },
            onFailure = { Text("Could not load this credential: ${it.message}", style = MaterialTheme.typography.bodyMedium) },
        )

        TextButton(onClick = onBack) { Text("Back") }
    }
}

@Composable
private fun CredentialDetailsCard(credentialId: String, credential: FfiTwdiwCredential) {
    val vcNo = credentialSerial(credential.credentialId ?: credentialId)
    val expiry = Instant.ofEpochSecond(credential.expires).atZone(ZoneId.systemDefault()).format(EXPIRY_FORMAT)

    Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
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
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                vcNo?.let {
                    Text("VC No.  $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text(
                    "Expiry Date: $expiry",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Credential Details", style = MaterialTheme.typography.titleMedium)
            credential.disclosedClaims.forEach { claim ->
                ClaimRow(CLAIM_DISPLAY_LABELS[claim.name] ?: claim.name, claim.value)
            }
        }
    }
}

@Composable
private fun ClaimRow(label: String, value: String) {
    var revealed by remember(label) { mutableStateOf(false) }

    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(if (revealed) value else MASKED_VALUE, style = MaterialTheme.typography.bodyMedium)
            }
            EyeToggle(revealed = revealed, onClick = { revealed = !revealed })
        }
    }
}

/** A hand-drawn reveal/hide toggle - no icon library dependency in this module. */
@Composable
private fun EyeToggle(revealed: Boolean, onClick: () -> Unit) {
    val color = MaterialTheme.colorScheme.onSurfaceVariant
    Canvas(modifier = Modifier.size(22.dp).clickable(onClick = onClick)) {
        val stroke = Stroke(width = 1.4.dp.toPx(), cap = StrokeCap.Round)
        val w = size.width
        val h = size.height
        val eye =
            Path().apply {
                moveTo(w * 0.05f, h * 0.5f)
                quadraticTo(w * 0.5f, h * 0.05f, w * 0.95f, h * 0.5f)
                quadraticTo(w * 0.5f, h * 0.95f, w * 0.05f, h * 0.5f)
                close()
            }
        drawPath(eye, color = color, style = stroke)
        if (revealed) {
            drawCircle(color = color, radius = h * 0.14f, center = Offset(w / 2f, h / 2f))
        } else {
            drawLine(color, Offset(w * 0.08f, h * 0.18f), Offset(w * 0.92f, h * 0.82f), strokeWidth = stroke.width, cap = StrokeCap.Round)
        }
    }
}
