package tw.bonds.backuptw.wallet

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
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
 * receive flow; M4 wires up [PickupScreen]'s live 7-Eleven pickup, whose
 * own `authorize` deep link is generated and consumed in-process rather
 * than through this OS-level handler. Demo polish: the M1 smoke tests and
 * the fixture-only regression demo (`FixtureDemoScreen`, PR #22) moved off
 * Home's primary buttons into [DeveloperToolsScreen], so the two real
 * flows are what a demo actually shows first.
 */
class MainActivity : ComponentActivity() {
    private var pendingDeepLink by mutableStateOf<Uri?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingDeepLink = intent?.data
        setContent {
            BackupTWTheme {
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

/** The three bottom-nav destinations - one per real feature this app has (see the session's design discussion for why Scan/Personal aren't tabs yet: no feature exists behind either). */
enum class NavTab(val label: String) {
    Credentials("Credentials"),
    Add("Add"),
    Present("Present"),
}

/** Screens reached from within a tab, layered above it without their own nav-bar entry - not part of the tab set, so the bottom bar hides while one is open. */
private sealed interface Overlay {
    data object DeveloperTools : Overlay
    data object FixtureDemo : Overlay
    data class CredentialHistory(val credentialId: String) : Overlay
}

@Composable
fun WalletApp(deepLink: Uri?, onDeepLinkConsumed: () -> Unit) {
    var currentTab by remember { mutableStateOf(NavTab.Credentials) }
    var overlay by remember { mutableStateOf<Overlay?>(null) }
    var pendingOfferLink by remember { mutableStateOf<String?>(null) }
    var deepLinkNotice by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(deepLink) {
        if (deepLink != null) {
            when (deepLink.host) {
                // The carrier's app hands this back once phone verification
                // is done - route straight into the tab that started it,
                // which reads back which application it answers.
                "credential_offer" -> {
                    pendingOfferLink = deepLink.toString()
                    overlay = null
                    currentTab = NavTab.Add
                }
                // A verifier's own QR/NFC `authorize` link, scanned in
                // person - distinct from PickupScreen's flow, which starts
                // from the catalog and gets its own deep link in-process
                // from the transaction-start reply. Not implemented: this
                // build's pickup entry point is the Present tab.
                "authorize" -> deepLinkNotice = "Received a pickup/authorize link (not yet handled):\n$deepLink"
                else -> deepLinkNotice = "Received an unrecognised link: $deepLink"
            }
            onDeepLinkConsumed()
        }
    }

    Scaffold(
        bottomBar = {
            if (overlay == null) {
                NavigationBar {
                    NavTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = currentTab == tab,
                            onClick = { currentTab = tab },
                            icon = { NavTabIcon(tab, selected = currentTab == tab) },
                            label = { Text(tab.label) },
                        )
                    }
                }
            }
        },
    ) { innerPadding ->
        Column(modifier = Modifier.fillMaxSize().padding(innerPadding)) {
            deepLinkNotice?.let {
                Text(
                    it,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            when (val current = overlay) {
                Overlay.DeveloperTools ->
                    DeveloperToolsScreen(
                        onOpenFixtureDemo = { overlay = Overlay.FixtureDemo },
                        onBack = { overlay = null },
                    )
                Overlay.FixtureDemo -> FixtureDemoScreen(onBack = { overlay = null })
                is Overlay.CredentialHistory ->
                    CredentialHistoryScreen(credentialId = current.credentialId, onBack = { overlay = null })
                null ->
                    when (currentTab) {
                        NavTab.Credentials ->
                            HomeScreen(
                                onOpenDeveloperTools = { overlay = Overlay.DeveloperTools },
                                onOpenCredential = { overlay = Overlay.CredentialHistory(it) },
                            )
                        NavTab.Add ->
                            ApplyForCardScreen(
                                pendingOfferLink = pendingOfferLink,
                                onOfferConsumed = { pendingOfferLink = null },
                            )
                        NavTab.Present -> PickupScreen()
                    }
            }
        }
    }
}

@Composable
private fun NavTabIcon(tab: NavTab, selected: Boolean) {
    val color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
    Canvas(modifier = Modifier.size(22.dp)) {
        val stroke = Stroke(width = 1.6.dp.toPx(), cap = StrokeCap.Round)
        when (tab) {
            NavTab.Credentials -> {
                val inset = size.width * 0.08f
                drawRoundRect(
                    color = color,
                    topLeft = Offset(inset, size.height * 0.2f),
                    size = Size(size.width - inset * 2, size.height * 0.6f),
                    cornerRadius = CornerRadius(size.width * 0.12f),
                    style = stroke,
                )
            }
            NavTab.Add -> {
                val mid = size.width / 2f
                val midY = size.height / 2f
                val half = size.width * 0.38f
                drawLine(color, Offset(mid - half, midY), Offset(mid + half, midY), strokeWidth = stroke.width, cap = StrokeCap.Round)
                drawLine(color, Offset(mid, midY - half), Offset(mid, midY + half), strokeWidth = stroke.width, cap = StrokeCap.Round)
            }
            // A share/present arrow (out of a corner bracket) - deliberately
            // not the official app's QR-grid glyph for this tab, matching
            // this session's general "don't look too close to a reference
            // design" rule.
            NavTab.Present -> {
                val path =
                    Path().apply {
                        moveTo(size.width * 0.22f, size.height * 0.78f)
                        lineTo(size.width * 0.78f, size.height * 0.22f)
                        moveTo(size.width * 0.4f, size.height * 0.22f)
                        lineTo(size.width * 0.78f, size.height * 0.22f)
                        lineTo(size.width * 0.78f, size.height * 0.6f)
                    }
                drawPath(path, color = color, style = stroke)
            }
        }
    }
}
