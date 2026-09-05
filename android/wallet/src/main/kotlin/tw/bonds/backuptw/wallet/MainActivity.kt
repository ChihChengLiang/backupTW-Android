package tw.bonds.backuptw.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.backuptw_core.WalletIdentity
import uniffi.backuptw_core.generateEphemeralWalletIdentity

/**
 * Phase 4's first vertical-slice step, and nothing past it: generate a
 * did:key identity via core/'s (real, tested) Rust logic through UniFFI,
 * show it on screen. No storage, no navigation, no network - see
 * core/src/ffi.rs's doc comment on why the key itself is ephemeral.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    WalletIdentityScreen()
                }
            }
        }
    }
}

@Composable
fun WalletIdentityScreen() {
    var identity by remember { mutableStateOf<WalletIdentity?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("有備而來 — dev build", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Generates a fresh did:key identity via core/'s Rust logic. " +
                "Ephemeral only - see core/src/ffi.rs.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = { identity = generateEphemeralWalletIdentity() }) {
            Text("Generate identity")
        }
        identity?.let { id ->
            Text("p256-pub:", style = MaterialTheme.typography.labelLarge)
            Text(id.did, style = MaterialTheme.typography.bodySmall)
            Text("jwk_jcs-pub:", style = MaterialTheme.typography.labelLarge)
            Text(id.jwkDid, style = MaterialTheme.typography.bodySmall)
        }
    }
}
