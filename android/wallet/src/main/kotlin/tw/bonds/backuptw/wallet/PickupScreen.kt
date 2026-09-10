package tw.bonds.backuptw.wallet

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import uniffi.backuptw_core.ConvenienceStorePickupScenario
import uniffi.backuptw_core.convenienceStorePickupCountdownRemainingSeconds

/** Drives [PickupScreen] end to end - each variant is one composition branch, so entering it runs its `LaunchedEffect` exactly once. */
private sealed interface PickupStage {
    data object LoadingCatalog : PickupStage
    data class CatalogError(val message: String) : PickupStage
    data class Ready(val scenario: ConvenienceStorePickupScenario) : PickupStage
    data class Starting(val scenario: ConvenienceStorePickupScenario) : PickupStage
    data class PreviewingDisclosure(val context: PickupContext) : PickupStage
    data class Consent(val context: PickupContext, val preview: PickupDisclosurePreview) : PickupStage
    data class Generating(val context: PickupContext) : PickupStage
    data class Barcode(val session: PickupBarcodeSession) : PickupStage
    data class Regenerating(val session: PickupBarcodeSession) : PickupStage
    data class Failed(val message: String, val retry: PickupStage) : PickupStage
}

/**
 * Milestone 4: the live 7-Eleven package-pickup flow, built on the card
 * [ApplyForCardScreen]'s [ReceiveFlow] already collected. Fetches the live
 * pickup catalog, runs [PickupClient]'s trust checks against the verifier
 * module, presents exactly `name`/`phonel5`, and displays the verifier's
 * own barcode with a live countdown.
 *
 * No biometric gate before signing (iOS requires device-owner
 * authentication here) - out of scope for this milestone; the on-screen
 * disclosure text is the informed-consent step this build has.
 */
@Composable
fun PickupScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val credentialStore = remember { CredentialStore(context) }

    var stage by remember { mutableStateOf<PickupStage>(PickupStage.LoadingCatalog) }
    var statusLines by remember { mutableStateOf<List<String>>(emptyList()) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        PickupHeader(onBack)

        when (val current = stage) {
            PickupStage.LoadingCatalog -> ProgressStage("Loading the live catalog…") {
                LaunchedEffect(Unit) {
                    runCatching { PickupClient.fetchScenarios() }
                        .fold(
                            onSuccess = { scenarios ->
                                val scenario = scenarios.firstOrNull { it.vpUid == SEVEN_ELEVEN_VP_UID }
                                stage =
                                    if (scenario != null) {
                                        PickupStage.Ready(scenario)
                                    } else {
                                        PickupStage.CatalogError("7-Eleven pickup is not in today's catalog.")
                                    }
                            },
                            onFailure = { stage = PickupStage.CatalogError("Failed to load the catalog: ${it.message}") },
                        )
                }
            }

            is PickupStage.CatalogError -> ErrorCard(current.message)

            is PickupStage.Ready ->
                Card(
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(current.scenario.name, style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Scan a 7-Eleven POS to pick up your package with this digital card.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Button(
                            onClick = {
                                statusLines = emptyList()
                                stage = PickupStage.Starting(current.scenario)
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Start pickup") }
                    }
                }

            is PickupStage.Starting -> ProgressStage("Verifying the pickup service…") {
                LaunchedEffect(Unit) {
                    PickupClient.begin(current.scenario) { statusLines = statusLines + it }
                        .fold(
                            onSuccess = { stage = PickupStage.PreviewingDisclosure(it) },
                            onFailure = { stage = PickupStage.Failed(it.message ?: "failed", PickupStage.Ready(current.scenario)) },
                        )
                }
            }

            is PickupStage.PreviewingDisclosure -> ProgressStage("Matching a stored card to the request…") {
                LaunchedEffect(Unit) {
                    PickupClient.previewDisclosure(current.context, credentialStore)
                        .fold(
                            onSuccess = { stage = PickupStage.Consent(current.context, it) },
                            onFailure = { stage = PickupStage.Failed(it.message ?: "failed", PickupStage.Ready(current.context.scenario)) },
                        )
                }
            }

            is PickupStage.Consent ->
                ConsentSection(current.context, current.preview, onConfirm = {
                    statusLines = emptyList()
                    stage = PickupStage.Generating(current.context)
                })

            is PickupStage.Generating -> ProgressStage("Building the presentation…") {
                LaunchedEffect(Unit) {
                    PickupClient.presentAndGenerate(current.context, credentialStore) { statusLines = statusLines + it }
                        .fold(
                            onSuccess = { stage = PickupStage.Barcode(it) },
                            onFailure = {
                                stage = PickupStage.Failed(it.message ?: "failed", PickupStage.PreviewingDisclosure(current.context))
                            },
                        )
                }
            }

            is PickupStage.Barcode ->
                BarcodeSection(current.session, onRegenerate = { stage = PickupStage.Regenerating(current.session) })

            is PickupStage.Regenerating -> ProgressStage("Requesting a new barcode…") {
                LaunchedEffect(Unit) {
                    PickupClient.regenerate(current.session) { statusLines = statusLines + it }
                        .fold(
                            onSuccess = { stage = PickupStage.Barcode(it) },
                            onFailure = { stage = PickupStage.Failed(it.message ?: "failed", PickupStage.Barcode(current.session)) },
                        )
                }
            }

            is PickupStage.Failed ->
                ErrorCard(current.message) {
                    Button(onClick = { stage = current.retry }, modifier = Modifier.fillMaxWidth()) { Text("Try again") }
                }
        }

        if (statusLines.isNotEmpty()) {
            TechnicalLog(statusLines)
        }
    }
}

@Composable
private fun PickupHeader(onBack: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            "←",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.clickable(onClick = onBack).padding(4.dp),
        )
        Text("7-Eleven package pickup", style = MaterialTheme.typography.headlineSmall)
    }
}

/** Centered spinner + label, shared by every transient/in-flight stage. `content` supplies that stage's one-shot `LaunchedEffect`. */
@Composable
private fun ProgressStage(label: String, content: @Composable () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    content()
}

@Composable
private fun ErrorCard(message: String, actions: @Composable () -> Unit = {}) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(message, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onErrorContainer)
            actions()
        }
    }
}

/** The status log passed to [PickupClient] calls - technical/debug-facing, so it's tucked away by default rather than shown inline. */
@Composable
private fun TechnicalLog(statusLines: List<String>) {
    var expanded by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        HorizontalDivider()
        TextButton(onClick = { expanded = !expanded }) {
            Text(if (expanded) "Hide technical log ▴" else "Show technical log ▾", style = MaterialTheme.typography.bodySmall)
        }
        if (expanded) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                statusLines.forEach {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun ConsentSection(context: PickupContext, preview: PickupDisclosurePreview, onConfirm: () -> Unit) {
    var showTrustDetails by remember { mutableStateOf(false) }

    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "DATA BEING PROVIDED",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(preview.holderName, style = MaterialTheme.typography.titleMedium)
                Text(
                    "Last 5 digits of phone number: ${preview.phoneLastFive}",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            HorizontalDivider()

            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "FROM CREDENTIAL",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text("${preview.credentialName} · ${preview.issuerName}", style = MaterialTheme.typography.bodySmall)
            }

            TextButton(onClick = { showTrustDetails = !showTrustDetails }) {
                Text(
                    if (showTrustDetails) "Hide service trust details ▴" else "Show service trust details ▾",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (showTrustDetails) {
                Text(
                    "Trust-list API: ${context.trustEvidence.organisationName}\n" +
                        "Arbitrum block: ${context.trustEvidence.blockNumber}\n" +
                        "Transaction: ${context.trustEvidence.transactionHash}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            HorizontalDivider()

            Text(
                "By tapping \"Create barcode\", you agree to provide the name and phone-number " +
                    "digits above to 7-ELEVEN for this parcel pickup check.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = onConfirm, modifier = Modifier.fillMaxWidth()) { Text("Create barcode") }
        }
    }
}

@Composable
private fun BarcodeSection(session: PickupBarcodeSession, onRegenerate: () -> Unit) {
    var remainingSeconds by remember(session) { mutableLongStateOf(0L) }

    LaunchedEffect(session) {
        while (true) {
            remainingSeconds =
                convenienceStorePickupCountdownRemainingSeconds(session.expiresAtUnixMillis, System.currentTimeMillis() / 1000)
            if (remainingSeconds <= 0) break
            delay(1000)
        }
    }

    val bitmap =
        remember(session.barcode.imageData) {
            val bytes = session.barcode.imageData
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        }
    val expiringSoon = remainingSeconds in 1..30

    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            "Show this barcode to the scanner",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.fillMaxWidth(),
        )
        // A plain white backing regardless of theme - a scanner needs real
        // black-on-white contrast and a clean quiet zone, not the app's
        // pink surface tint.
        Card(
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = "7-Eleven pickup barcode",
                modifier = Modifier.fillMaxWidth().aspectRatio(1f).padding(20.dp),
            )
        }
        if (remainingSeconds > 0) {
            Text(
                "Expires in %02d:%02d".format(remainingSeconds / 60, remainingSeconds % 60),
                style = MaterialTheme.typography.titleMedium,
                color = if (expiringSoon) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.fillMaxWidth(),
            )
        } else {
            Text(
                "This barcode has expired.",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        OutlinedButton(
            onClick = onRegenerate,
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.primary),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Create a new barcode") }
    }
}
