package tw.bonds.backuptw.wallet

import android.content.Intent
import android.net.Uri
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.backuptw_core.TelecomCard
import uniffi.backuptw_core.telecomCardsFromVcListJson

private const val CATALOG_URL =
    "https://frontend.wallet.gov.tw/api/moda/dwapp/apply/vcList?name=&page=0&size=50"

/**
 * Milestone 3: the live "apply for a telecom card" flow. Browses the real
 * catalog, opens a card's own `issuerServiceUrl` externally for the user
 * to complete real carrier phone-verification, then - once the carrier
 * hands back a `modadigitalwallet://credential_offer` deep link - runs
 * [ReceiveFlow] against it and stores the result.
 *
 * `pendingOfferLink`/`onOfferConsumed` come from [WalletApp]'s deep-link
 * handling; which card the link answers is read back from
 * [PendingCardApplicationStore] rather than kept only in this
 * composable's state, since the carrier's page runs in an external
 * browser/app and this process may not survive the trip.
 */
@Composable
fun ApplyForCardScreen(pendingOfferLink: String?, onOfferConsumed: () -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    val credentialStore = remember { CredentialStore(context) }

    var cards by remember { mutableStateOf<List<TelecomCard>>(emptyList()) }
    var catalogError by remember { mutableStateOf<String?>(null) }
    var pending by remember { mutableStateOf(PendingCardApplicationStore.load(context)) }
    var statusLines by remember { mutableStateOf<List<String>>(emptyList()) }
    var resultMessage by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        runCatching {
            val body = withContext(Dispatchers.IO) { TwdiwClient.get(CATALOG_URL) }
            telecomCardsFromVcListJson(body)
        }.fold(
            onSuccess = { cards = it },
            onFailure = { catalogError = "Failed to load the catalog: ${it.message}" },
        )
    }

    LaunchedEffect(pendingOfferLink) {
        val offerLink = pendingOfferLink ?: return@LaunchedEffect
        val application = pending
        if (application == null) {
            resultMessage = "Received a credential offer, but no card application was pending."
            onOfferConsumed()
            return@LaunchedEffect
        }
        statusLines = emptyList()
        resultMessage = null
        val holderKey = KeystoreHolderKey.load(application.alias) ?: KeystoreHolderKey.generate(application.alias)
        ReceiveFlow.receive(offerLink, holderKey) { message -> statusLines = statusLines + message }
            .fold(
                onSuccess = { (credential, configurationId) ->
                    credentialStore.save(configurationId, credential.serialized)
                    PendingCardApplicationStore.clear(context)
                    pending = null
                    resultMessage = "Received and stored: ${credential.credentialType}"
                },
                onFailure = { resultMessage = "Failed: ${it.message}" },
            )
        onOfferConsumed()
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Apply for a telecom card", style = MaterialTheme.typography.headlineSmall)
        Button(onClick = onBack) { Text("Back") }

        pending?.let {
            Text(
                "Waiting on verification for ${it.vcUid}. Complete it in the browser/carrier app, " +
                    "then return here.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        catalogError?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

        cards.forEach { card ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(card.name, style = MaterialTheme.typography.titleMedium)
                Button(onClick = {
                    val alias = "telecom-${card.vcUid}"
                    KeystoreHolderKey.load(alias) ?: KeystoreHolderKey.generate(alias)
                    val application = PendingCardApplication(card.vcUid, alias)
                    PendingCardApplicationStore.save(context, application)
                    pending = application
                    resultMessage = null
                    statusLines = emptyList()
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(card.issuerServiceUrl)))
                }) {
                    Text("Apply")
                }
            }
        }

        if (statusLines.isNotEmpty()) {
            HorizontalDivider()
            Text("Progress", style = MaterialTheme.typography.titleMedium)
            statusLines.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        resultMessage?.let {
            HorizontalDivider()
            Text(it, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
