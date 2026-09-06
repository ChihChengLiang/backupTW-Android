package tw.bonds.backuptw.wallet

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * The real 7-Eleven pickup build (`docs/2026-09-05-*` field notes; see
 * the session's plan for the full four-milestone sequence). M1 supplied
 * native infrastructure - real HTTP (`TwdiwClient`), real Android
 * Keystore signing (`KeystoreHolderKey`), real encrypted storage
 * (`CredentialStore`/`TrustSnapshotStore`) - and the
 * `modadigitalwallet://` deep-link registration a carrier's app or a
 * verifier's request needs to hand control back to this app. M3 wires the
 * `credential_offer` form of that link into [ApplyForCardScreen]'s live
 * receive flow; `PickupCatalog` stays a placeholder until M4. The
 * original fixture-only demo (`FixtureDemoScreen`) stays reachable from
 * Home, unchanged.
 */
class MainActivity : ComponentActivity() {
    private var pendingDeepLink by mutableStateOf<Uri?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingDeepLink = intent?.data
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    WalletApp(
                        deepLink = pendingDeepLink,
                        onDeepLinkConsumed = { pendingDeepLink = null },
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        pendingDeepLink = intent.data
    }
}

sealed interface Screen {
    data object Home : Screen
    data object FixtureDemo : Screen
    data object ApplyForCard : Screen
    data object PickupCatalog : Screen
}

@Composable
fun WalletApp(deepLink: Uri?, onDeepLinkConsumed: () -> Unit) {
    var screen by remember { mutableStateOf<Screen>(Screen.Home) }
    var pendingOfferLink by remember { mutableStateOf<String?>(null) }
    var deepLinkNotice by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(deepLink) {
        if (deepLink != null) {
            when (deepLink.host) {
                // The carrier's app hands this back once phone verification
                // is done - route straight into the screen that started it,
                // which reads back which application it answers.
                "credential_offer" -> {
                    pendingOfferLink = deepLink.toString()
                    screen = Screen.ApplyForCard
                }
                "authorize" ->
                    deepLinkNotice = "Received a pickup/authorize link (handling arrives in Milestone 4):\n$deepLink"
                else -> deepLinkNotice = "Received an unrecognised link: $deepLink"
            }
            onDeepLinkConsumed()
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        deepLinkNotice?.let {
            Text(
                it,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        when (screen) {
            Screen.Home -> HomeScreen(onNavigate = { screen = it })
            Screen.FixtureDemo -> FixtureDemoScreen(onBack = { screen = Screen.Home })
            Screen.ApplyForCard ->
                ApplyForCardScreen(
                    pendingOfferLink = pendingOfferLink,
                    onOfferConsumed = { pendingOfferLink = null },
                    onBack = { screen = Screen.Home },
                )
            Screen.PickupCatalog ->
                PlaceholderScreen(
                    title = "7-Eleven package pickup",
                    body = "The live pickup flow (catalog, on-chain check, OID4VP " +
                        "presentation, barcode) lands in Milestone 4.",
                    onBack = { screen = Screen.Home },
                )
        }
    }
}

@Composable
private fun PlaceholderScreen(title: String, body: String, onBack: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Text(body, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 8.dp))
        Button(onClick = onBack, modifier = Modifier.padding(top = 16.dp)) {
            Text("Back")
        }
    }
}
