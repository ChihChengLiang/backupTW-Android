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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.backuptw_core.parseIssuerTrustListPage

private const val TRUST_LIST_URL = "https://frontend.wallet.gov.tw/api/did?size=20&page=0&orgType=1&status=1"

/**
 * Not part of the demo path - the M1 infrastructure smoke tests (real
 * Keystore signing, real encrypted storage, one real network call) and
 * the M0/PR #22 fixture-only regression demo, kept reachable for
 * debugging but off [HomeScreen]'s primary buttons.
 */
@Composable
fun DeveloperToolsScreen(onNavigate: (Screen) -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    val credentialStore = remember { CredentialStore(context) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Developer tools", style = MaterialTheme.typography.headlineSmall)
        Button(onClick = onBack) { Text("Back") }

        Button(onClick = { onNavigate(Screen.FixtureDemo) }) { Text("Fixture demo (no network)") }

        HorizontalDivider()
        Text("Infrastructure smoke tests", style = MaterialTheme.typography.titleMedium)
        Text(
            "Real Keystore signing, real encrypted storage, one real network " +
                "call - proving the pieces the receive/pickup flows build on.",
            style = MaterialTheme.typography.bodyMedium,
        )
        KeystoreSmokeTest()
        StorageSmokeTest(credentialStore)
        TrustListSmokeTest()
    }
}

@Composable
private fun KeystoreSmokeTest() {
    var result by remember { mutableStateOf<String?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Button(onClick = {
            result = runCatching {
                val key = KeystoreHolderKey.generate("smoke-test")
                val signature = key.signRaw("smoke test".toByteArray())
                "Keystore key generated; public key ${key.publicKeyX963().size} bytes, " +
                    "signature ${signature.size} bytes."
            }.fold(onSuccess = { it }, onFailure = { "Failed: ${it.message}" })
        }) {
            Text("Generate Keystore key + sign")
        }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun StorageSmokeTest(credentialStore: CredentialStore) {
    var result by remember { mutableStateOf<String?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Button(onClick = {
            result = runCatching {
                val id = "smoke-test"
                val value = "encrypted-at-${System.currentTimeMillis()}"
                credentialStore.save(id, value)
                val reloaded = credentialStore.load(id)
                credentialStore.delete(id)
                if (reloaded == value) "Saved and reloaded from an encrypted file: matched." else "Mismatch: got $reloaded"
            }.fold(onSuccess = { it }, onFailure = { "Failed: ${it.message}" })
        }) {
            Text("Save + reload an encrypted file")
        }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun TrustListSmokeTest() {
    var result by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Button(onClick = {
            scope.launch {
                result = "Fetching…"
                result = runCatching {
                    val body = withContext(Dispatchers.IO) { TwdiwClient.get(TRUST_LIST_URL) }
                    val issuers = parseIssuerTrustListPage(body)
                    "Live trust list: ${issuers.size} issuer(s) on this page. " +
                        "First: ${issuers.firstOrNull()?.displayName ?: "(none)"}"
                }.fold(onSuccess = { it }, onFailure = { "Failed: ${it.message}" })
            }
        }) {
            Text("Fetch live trust list (page 0)")
        }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}
