package tw.bonds.backuptw.wallet

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
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
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("7-Eleven package pickup", style = MaterialTheme.typography.headlineSmall)
        Button(onClick = onBack) { Text("Back") }

        when (val current = stage) {
            PickupStage.LoadingCatalog -> {
                Text("Loading the live catalog…", style = MaterialTheme.typography.bodyMedium)
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

            is PickupStage.CatalogError -> Text(current.message, style = MaterialTheme.typography.bodyMedium)

            is PickupStage.Ready -> {
                Text(current.scenario.name, style = MaterialTheme.typography.titleMedium)
                Button(onClick = {
                    statusLines = emptyList()
                    stage = PickupStage.Starting(current.scenario)
                }) {
                    Text("Start pickup")
                }
            }

            is PickupStage.Starting -> {
                Text("Verifying the pickup service…", style = MaterialTheme.typography.bodyMedium)
                LaunchedEffect(Unit) {
                    PickupClient.begin(current.scenario) { statusLines = statusLines + it }
                        .fold(
                            onSuccess = { stage = PickupStage.PreviewingDisclosure(it) },
                            onFailure = { stage = PickupStage.Failed(it.message ?: "failed", PickupStage.Ready(current.scenario)) },
                        )
                }
            }

            is PickupStage.PreviewingDisclosure -> {
                Text("Matching a stored card to the request…", style = MaterialTheme.typography.bodyMedium)
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

            is PickupStage.Generating -> {
                Text("Building the presentation…", style = MaterialTheme.typography.bodyMedium)
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

            is PickupStage.Regenerating -> {
                Text("Requesting a new barcode…", style = MaterialTheme.typography.bodyMedium)
                LaunchedEffect(Unit) {
                    PickupClient.regenerate(current.session) { statusLines = statusLines + it }
                        .fold(
                            onSuccess = { stage = PickupStage.Barcode(it) },
                            onFailure = { stage = PickupStage.Failed(it.message ?: "failed", PickupStage.Barcode(current.session)) },
                        )
                }
            }

            is PickupStage.Failed -> {
                Text("Failed: ${current.message}", style = MaterialTheme.typography.bodyMedium)
                Button(onClick = { stage = current.retry }) { Text("Try again") }
            }
        }

        if (statusLines.isNotEmpty()) {
            HorizontalDivider()
            Text("Progress", style = MaterialTheme.typography.titleMedium)
            statusLines.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
private fun ConsentSection(context: PickupContext, preview: PickupDisclosurePreview, onConfirm: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Service trust verified", style = MaterialTheme.typography.titleMedium)
        Text(
            "Trust-list API: ${context.trustEvidence.organisationName}\n" +
                "Arbitrum block: ${context.trustEvidence.blockNumber}\n" +
                "Transaction: ${context.trustEvidence.transactionHash}",
            style = MaterialTheme.typography.bodySmall,
        )
        HorizontalDivider()
        Text("Data being provided", style = MaterialTheme.typography.titleMedium)
        Text(
            "${preview.credentialName} (${preview.issuerName})" +
                (preview.credentialSerial?.let { "\nCredential ID: $it" } ?: ""),
            style = MaterialTheme.typography.bodySmall,
        )
        Text("Name: ${preview.holderName}", style = MaterialTheme.typography.bodyMedium)
        Text("Last 5 digits of phone number: ${preview.phoneLastFive}", style = MaterialTheme.typography.bodyMedium)
        HorizontalDivider()
        Text(
            "By tapping \"Create barcode\", you agree to provide the name and phone-number " +
                "digits above to 7-ELEVEN for this parcel pickup check.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = onConfirm) { Text("Create barcode") }
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

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Show this barcode to the scanner", style = MaterialTheme.typography.titleMedium)
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "7-Eleven pickup barcode",
            modifier = Modifier.fillMaxWidth().aspectRatio(1f),
        )
        if (remainingSeconds > 0) {
            Text(
                "Expires in %02d:%02d".format(remainingSeconds / 60, remainingSeconds % 60),
                style = MaterialTheme.typography.bodyMedium,
            )
        } else {
            Text("This barcode has expired.", style = MaterialTheme.typography.bodyMedium)
        }
        Button(onClick = onRegenerate) { Text("Create a new barcode") }
    }
}
