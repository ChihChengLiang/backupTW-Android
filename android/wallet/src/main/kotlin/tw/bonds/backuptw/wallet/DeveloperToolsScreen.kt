package tw.bonds.backuptw.wallet

import android.content.Context
import android.util.Base64
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
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uniffi.backuptw_core.PresentationCredentialSource
import uniffi.backuptw_core.assembleAgePredicateProofPackage
import uniffi.backuptw_core.agePredicateProofRequestCutoffValue
import uniffi.backuptw_core.decodeAgePredicateProofPackage
import uniffi.backuptw_core.encodeAgePredicateProofPackage
import uniffi.backuptw_core.generateAgePredicateProofRequest
import uniffi.backuptw_core.parseIssuerTrustListPage
import uniffi.backuptw_core.walletIdentityFromPublicKey
import uniffi.mopro.createAgePrepareInput
import uniffi.mopro.createAgeShowInput
import uniffi.mopro.generateSharedBlinds
import uniffi.mopro.proveJwt
import uniffi.mopro.proveShow
import uniffi.mopro.reblindJwt
import uniffi.mopro.reblindShow
import uniffi.mopro.setupJwtKeys
import uniffi.mopro.setupShowKeys
import uniffi.mopro.verifyAgePresentation

private const val TRUST_LIST_URL = "https://frontend.wallet.gov.tw/api/did?size=20&page=0&orgType=1&status=1"

/**
 * Not part of the demo path - the M1 infrastructure smoke tests (real
 * Keystore signing, real encrypted storage, one real network call) and
 * the M0/PR #22 fixture-only regression demo, kept reachable for
 * debugging but off [HomeScreen]'s primary buttons.
 */
@Composable
fun DeveloperToolsScreen(onOpenFixtureDemo: () -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    val credentialStore = remember { CredentialStore(context) }
    val credentialHistoryStore = remember { CredentialHistoryStore(context) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Developer tools", style = MaterialTheme.typography.headlineSmall)
        Button(onClick = onBack) { Text("Back") }

        Button(onClick = onOpenFixtureDemo) { Text("Fixture demo (no network)") }

        HorizontalDivider()
        Text("Infrastructure smoke tests", style = MaterialTheme.typography.titleMedium)
        Text(
            "Real Keystore signing, real encrypted storage, one real network " +
                "call - proving the pieces the receive/pickup flows build on.",
            style = MaterialTheme.typography.bodyMedium,
        )
        KeystoreSmokeTest()
        StorageSmokeTest(credentialStore)
        CredentialHistorySmokeTest(credentialHistoryStore)
        TrustListSmokeTest()

        HorizontalDivider()
        Text("ZK age-predicate proof", style = MaterialTheme.typography.titleMedium)
        Text(
            "Real Mopro/Spartan2 proving inside this app's own build - not " +
                "the separate zkharness POC. No real MOICA/national-ID " +
                "credential exists to prove over yet, so the issuer and " +
                "SD-JWT are still a known-good fixture; the holder key, the " +
                "native proving/verification, and the age_predicate_proof " +
                "request/package assembly are all real.",
            style = MaterialTheme.typography.bodyMedium,
        )
        AgeProofSmokeTest()
    }
}

@Composable
private fun AgeProofSmokeTest() {
    var result by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Button(onClick = {
            result = "Proving… (Prepare setup can take several seconds)"
            scope.launch {
                val outcome = withContext(Dispatchers.Default) {
                    runCatching { runAgeProofSmokeTest(context) }
                }
                result = outcome.fold(onSuccess = { it }, onFailure = { "Failed: ${it.message}" })
            }
        }) {
            Text("Run real ZK age-predicate proof (Mopro)")
        }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

/**
 * The same fixed-vector shape `zkharness`'s harness uses (fabricated
 * issuer + a single `birthdate` disclosure) - see `android/README.md` -
 * but run inside `wallet`'s own process against a real Keystore-backed
 * holder key, and routed through the real `age_predicate_proof`
 * request/package FFI instead of a bare boolean check. Proves the native
 * libraries and both UniFFI bindings (`backuptw_core`, `mopro`) coexist
 * in one process, and that `age_predicate_proof`'s package assembly
 * actually validates real Mopro-produced proof bytes, not just the
 * fixture bytes its own unit tests use.
 */
private fun runAgeProofSmokeTest(context: Context): String {
    val documentsPath = File(context.filesDir, "circom").absolutePath
    setupJwtKeys(documentsPath)
    setupShowKeys(documentsPath)

    val issuer = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    val issuerPublic = issuer.public as ECPublicKey
    val issuerX = b64url(EcdsaCodec.unsignedBytes32(issuerPublic.w.affineX))
    val issuerY = b64url(EcdsaCodec.unsignedBytes32(issuerPublic.w.affineY))
    val issuerX963 = EcdsaCodec.x963(issuerPublic.w.affineX, issuerPublic.w.affineY)
    val issuerDid = walletIdentityFromPublicKey(issuerX963).did

    KeystoreHolderKey.delete("age-proof-smoke-test")
    val holderKey = KeystoreHolderKey.generate("age-proof-smoke-test")
    val holderX963 = holderKey.publicKeyX963()
    val holderX = b64url(holderX963.copyOfRange(1, 33))
    val holderY = b64url(holderX963.copyOfRange(33, 65))

    val disclosure = b64url("[\"fixed-test-salt\",\"birthdate\",\"1990-01-01\"]".toByteArray())
    val digest = b64url(MessageDigest.getInstance("SHA-256").digest(disclosure.toByteArray()))
    val header = b64url(
        JSONObject().put("alg", "ES256").put("typ", "vc+sd-jwt").toString().toByteArray(),
    )
    val payload = b64url(
        JSONObject()
            .put("iss", issuerDid)
            .put("nbf", 1)
            .put("exp", 4_102_444_800L)
            .put(
                "cnf",
                JSONObject().put(
                    "jwk",
                    JSONObject()
                        .put("kty", "EC")
                        .put("crv", "P-256")
                        .put("x", holderX)
                        .put("y", holderY),
                ),
            )
            .put(
                "vc",
                JSONObject().put(
                    "credentialSubject",
                    JSONObject().put("_sd_alg", "sha-256").put("_sd", JSONArray().put(digest)),
                ),
            )
            .toString()
            .toByteArray(),
    )
    val signingInput = "$header.$payload"
    val issuerSig = b64url(signWithSoftwareKey(issuer.private, signingInput.toByteArray()))
    val sdJwt = "$signingInput.$issuerSig~$disclosure~"

    val prepared = createAgePrepareInput(documentsPath, sdJwt, issuerX, issuerY)
    val jwtTiming = proveJwt(documentsPath)

    val request = generateAgePredicateProofRequest(
        "ZK proof smoke test",
        PresentationCredentialSource.SELF_ISSUED,
        18,
        null,
        System.currentTimeMillis() / 1000,
    )
    val cutoff = agePredicateProofRequestCutoffValue(request, prepared.claimFormat)

    val holderSig = b64url(holderKey.signRaw(request.nonce.toByteArray()))
    createAgeShowInput(
        documentsPath, request.nonce, holderSig, prepared.claimName, prepared.claimFormat, cutoff,
    )
    val showTiming = proveShow(documentsPath)

    generateSharedBlinds(documentsPath)
    reblindJwt(documentsPath)
    reblindShow(documentsPath)

    val accepted = verifyAgePresentation(
        documentsPath, request.nonce, prepared.claimName, prepared.claimFormat, cutoff, issuerX, issuerY,
    )
    check(accepted) { "linked age proof rejected its own fixed vector" }

    // The Kotlin bindings return only timings/sizes - the actual proof
    // artifacts stay on disk, written by prove_jwt/prove_show and
    // rewritten in place by reblind, matching the iOS engine's own
    // "read the .bin files only after reblind" order.
    val prepareProofBytes = File(documentsPath, "keys/prepare_proof.bin").readBytes()
    val showProofBytes = File(documentsPath, "keys/show_proof.bin").readBytes()
    val pkg = assembleAgePredicateProofPackage(
        request,
        prepared.claimName,
        prepared.claimFormat,
        issuerDid,
        prepareProofBytes,
        showProofBytes,
        jwtTiming.totalMs,
        showTiming.totalMs,
        System.currentTimeMillis(),
    )
    val roundTripped = decodeAgePredicateProofPackage(encodeAgePredicateProofPackage(pkg))
    check(roundTripped == pkg) { "package did not round-trip through encode/decode" }

    return "Real Mopro proof verified and packaged: prepare=${jwtTiming.totalMs}ms " +
        "show=${showTiming.totalMs}ms, package ${pkg.prepareProof.size + pkg.showProof.size} bytes."
}

/** Base64url, no padding - matches Rust's URL_SAFE_NO_PAD. */
private fun b64url(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

/**
 * SHA256withECDSA via the default provider yields a DER-encoded signature;
 * the circuit expects the raw 64-byte `r ‖ s` form - same conversion
 * [KeystoreHolderKey.signRaw] does for the Keystore-backed key, needed
 * here too since the fixture issuer is a plain (non-Keystore) software key.
 */
private fun signWithSoftwareKey(key: PrivateKey, message: ByteArray): ByteArray {
    val der = Signature.getInstance("SHA256withECDSA").apply {
        initSign(key)
        update(message)
    }.sign()
    return EcdsaCodec.derToRaw(der)
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

/** A dedicated test id, isolated from any real telecom card's history file - never shown on `HomeScreen`'s card stack. */
private const val HISTORY_SMOKE_TEST_ID = "history-smoke-test"

@Composable
private fun CredentialHistorySmokeTest(credentialHistoryStore: CredentialHistoryStore) {
    var result by remember { mutableStateOf<String?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Button(onClick = {
            result = runCatching {
                val now = System.currentTimeMillis()
                credentialHistoryStore.append(HISTORY_SMOKE_TEST_ID, CredentialHistoryEvent.Added(now, "Smoke-test card"))
                credentialHistoryStore.append(
                    HISTORY_SMOKE_TEST_ID,
                    CredentialHistoryEvent.Authorized(now + 1, "Smoke-test org", "Smoke test", "vc-123", "Name"),
                )
                val events = credentialHistoryStore.load(HISTORY_SMOKE_TEST_ID)
                check(events.size == 2) { "expected 2 events, got ${events.size}" }
                check(events[0] is CredentialHistoryEvent.Added) { "event 0 should be Added" }
                check(events[1] is CredentialHistoryEvent.Authorized) { "event 1 should be Authorized" }
                "Appended and reloaded 2 events from an encrypted file: round-trip matched."
            }.fold(onSuccess = { it }, onFailure = { "Failed: ${it.message}" })
        }) {
            Text("Append + reload credential history events")
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
