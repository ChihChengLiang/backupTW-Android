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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.backuptw_core.CredentialOffer
import uniffi.backuptw_core.FfiTwdiwCredential
import uniffi.backuptw_core.TwdiwIssuer
import uniffi.backuptw_core.TwdiwOnChainVerification
import uniffi.backuptw_core.Verdict
import uniffi.backuptw_core.WalletIdentity
import uniffi.backuptw_core.assembleProofJwt
import uniffi.backuptw_core.authoriseFetchUrl
import uniffi.backuptw_core.canonicalIssuerIdentifier
import uniffi.backuptw_core.confirmOrganisation
import uniffi.backuptw_core.confirmRegistryEvidence
import uniffi.backuptw_core.generateEphemeralWalletIdentity
import uniffi.backuptw_core.parseCredentialOffer
import uniffi.backuptw_core.parseIssuerTrustListPage
import uniffi.backuptw_core.proofSigningInput
import uniffi.backuptw_core.readTwdiwCredential
import uniffi.backuptw_core.walletIdentityFromPublicKey

/**
 * PR #22's original fixture-only proof that `core/`'s UniFFI surface
 * works end to end - identity generation, offer/trust-list evaluation,
 * proof-JWT building and signing, and reading a received credential.
 * Kept unchanged and reachable from Home as a no-network regression
 * check; the live equivalents of these steps are what Milestones 3/4
 * build against real infrastructure instead of `Fixtures.kt`.
 */
@Composable
fun FixtureDemoScreen(onBack: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Fixture demo (dev)", style = MaterialTheme.typography.headlineSmall)
        Button(onClick = onBack) { Text("Back") }

        IdentitySection()
        HorizontalDivider()
        OfferGatesSection()
        HorizontalDivider()
        ProofJwtSection()
        HorizontalDivider()
        ReadCredentialSection()
    }
}

@Composable
private fun IdentitySection() {
    var identity by remember { mutableStateOf<WalletIdentity?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("1. Generate an identity", style = MaterialTheme.typography.titleMedium)
        Text(
            "Generates a fresh did:key identity via core/'s Rust logic. Ephemeral only.",
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

@Composable
private fun OfferGatesSection() {
    var result by remember { mutableStateOf<String?>(null) }
    var matchedIssuer by remember { mutableStateOf<TwdiwIssuer?>(null) }
    var issuerIdentifier by remember { mutableStateOf<String?>(null) }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("2. Evaluate a fixture offer", style = MaterialTheme.typography.titleMedium)
        Text(
            "Parses a bundled fixture credential offer and trust-list page, " +
                "not a live issuer, and runs the three issuer-authorization gates.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = {
            result = runCatching {
                val offer: CredentialOffer = parseCredentialOffer(Fixtures.OFFER_JSON.toByteArray())
                val list = parseIssuerTrustListPage(Fixtures.TRUST_LIST_PAGE_JSON.toByteArray())

                val matched = when (val verdict = authoriseFetchUrl(offer.credentialIssuer, list)) {
                    is Verdict.Allowed -> verdict.issuers
                    is Verdict.Refused -> throw verdict.v1
                }

                val verification = mapOf(matched[0].did to TwdiwOnChainVerification.DevelopmentSandbox)
                confirmRegistryEvidence(matched, verification)

                val confirmed = confirmOrganisation(offer.credentialIssuer, matched)
                matchedIssuer = confirmed
                issuerIdentifier = canonicalIssuerIdentifier(offer.credentialIssuer)

                "Gate 1 (host trusted): pass\n" +
                    "Gate 1b (registry evidence): pass (development sandbox)\n" +
                    "Gate 2 (organisation match): pass — ${confirmed.displayName}"
            }.fold(
                onSuccess = { it },
                onFailure = { "Refused: ${it.message}" },
            )
        }) {
            Text("Evaluate fixture offer")
        }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun ProofJwtSection() {
    var holderKey by remember { mutableStateOf<HolderKey?>(null) }
    var result by remember { mutableStateOf<String?>(null) }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("3. Build a signed proof JWT", style = MaterialTheme.typography.titleMedium)
        Text(
            "Generates an in-memory P-256 key (real signing, not a live " +
                "Keystore) and signs an OID4VCI proof JWT for the fixture issuer.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = {
            result = runCatching {
                val key = holderKey ?: HolderKey.generate().also { holderKey = it }
                val x963 = key.publicKeyX963()
                val issuerIdentifier = canonicalIssuerIdentifier(
                    parseCredentialOffer(Fixtures.OFFER_JSON.toByteArray()).credentialIssuer,
                ) ?: throw IllegalStateException("no issuer identifier")

                // The proof's `kid`/`iss` must be this key's own did:key, in
                // the jwk_jcs-pub spelling TWDIW expects - derived from this
                // key's own public point, not a fresh unrelated identity.
                val clientId = walletIdentityFromPublicKey(x963).jwkDid
                val input = proofSigningInput(clientId, issuerIdentifier, clientId, Fixtures.DEMO_NONCE, System.currentTimeMillis() / 1000)
                val signature = key.signRaw(input.toByteArray())
                val jwt = assembleProofJwt(input, signature)
                "client_id (this key's did:key):\n$clientId\n\nProof JWT (${jwt.split(".").size} segments, ${jwt.length} chars):\n$jwt"
            }.fold(
                onSuccess = { it },
                onFailure = { "Failed: ${it.message}" },
            )
        }) {
            Text("Build signed proof JWT")
        }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun ReadCredentialSection() {
    var result by remember { mutableStateOf<String?>(null) }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("4. Read a fixture credential", style = MaterialTheme.typography.titleMedium)
        Text(
            "Reads and cryptographically verifies a bundled fixture TWDIW " +
                "SD-JWT credential (real signature check, not a live issuer).",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = {
            result = runCatching {
                val credential: FfiTwdiwCredential =
                    readTwdiwCredential(Fixtures.CREDENTIAL, System.currentTimeMillis() / 1000)
                val claims = credential.disclosedClaims.joinToString("\n") { "  ${it.name}: ${it.value}" }
                "type: ${credential.credentialType}\n" +
                    "issuer: ${credential.issuerDid}\n" +
                    "subject: ${credential.subjectDid}\n" +
                    "disclosed claims:\n$claims"
            }.fold(
                onSuccess = { it },
                onFailure = { "Failed: ${it.message}" },
            )
        }) {
            Text("Read fixture credential")
        }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}
