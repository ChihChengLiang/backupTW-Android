package tw.bonds.backuptw.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uniffi.backuptw_core.ConvenienceStorePickupScenario
import uniffi.backuptw_core.CredentialOfferLink
import uniffi.backuptw_core.FfiConvenienceStorePickupBarcode
import uniffi.backuptw_core.FfiFormField
import uniffi.backuptw_core.FfiTwdiwCredential
import uniffi.backuptw_core.Oid4VpAuthorizeLink
import uniffi.backuptw_core.Oid4VpRequest
import uniffi.backuptw_core.TwdiwIssuer
import uniffi.backuptw_core.TwdiwOnChainVerification
import uniffi.backuptw_core.Verdict
import uniffi.backuptw_core.assembleVpToken
import uniffi.backuptw_core.authoriseFetchUrl
import uniffi.backuptw_core.convenienceStorePickupCountdownExpiresAt
import uniffi.backuptw_core.convenienceStorePickupScenarios
import uniffi.backuptw_core.formEncode
import uniffi.backuptw_core.parseAuthorizeLink
import uniffi.backuptw_core.parseConvenienceStorePickupBarcode
import uniffi.backuptw_core.parseConvenienceStorePickupStart
import uniffi.backuptw_core.presentationSubmissionForDescriptorIds
import uniffi.backuptw_core.readTwdiwCredential
import uniffi.backuptw_core.reserialiseTwdiwCredential
import uniffi.backuptw_core.verifyOid4vpRequest
import uniffi.backuptw_core.vpTokenSigningInput
import uniffi.backuptw_core.walletIdentityFromPublicKey

private const val PICKUP_CATALOG_URL = "https://frontend.wallet.gov.tw/api/moda/dwapp/offline/vpList?name=&page=0&size=100"

/** `core::twdiw::convenience_store_pickup::SEVEN_ELEVEN_VP_UID` - not FFI-exported (a plain const), kept in sync by hand. */
const val SEVEN_ELEVEN_VP_UID = "22555003_711pickup"

data class PickupTrustEvidence(val organisationName: String, val blockNumber: String, val transactionHash: String)

data class PickupContext(
    val scenario: ConvenienceStorePickupScenario,
    val transactionId: String,
    val request: Oid4VpRequest,
    val trustEvidence: PickupTrustEvidence,
)

data class PickupReceipt(val holderDid: String, val holderKeyAlias: String)

data class PickupBarcodeSession(
    val context: PickupContext,
    val receipt: PickupReceipt,
    val barcode: FfiConvenienceStorePickupBarcode,
    val expiresAtUnixMillis: Long,
)

/**
 * Orchestrates the four official operations without ever inventing a
 * barcode: catalogue -> transaction/deep-link (401) -> OID4VP response ->
 * encrypted image (402). Ported from
 * `backupTW-iOS/backupTW/TWDIW/ConvenienceStorePickup.swift`'s
 * `ConvenienceStorePickupClient` - matching its trust-evidence algorithm
 * (the first matched issuer with a *verified* on-chain record, not "every
 * matched issuer agrees" the way the receive flow's gate 1b works) and its
 * extra same-module host checks on top of `core`'s general trust-list
 * gates.
 *
 * Which stored card answers a request and what it discloses is the one
 * piece of `OID4VPResponder` deliberately never ported to `core` (it needs
 * the credential store, native by design) - written directly here, calling
 * `reserialiseTwdiwCredential`/`vpTokenSigningInput`/`assembleVpToken` for
 * the actual crypto.
 */
object PickupClient {
    suspend fun fetchScenarios(): List<ConvenienceStorePickupScenario> =
        withContext(Dispatchers.IO) {
            convenienceStorePickupScenarios(TwdiwClient.get(PICKUP_CATALOG_URL))
        }

    suspend fun begin(
        scenario: ConvenienceStorePickupScenario,
        onStatus: (String) -> Unit,
    ): Result<PickupContext> =
        withContext(Dispatchers.IO) {
            runCatching {
                val moduleUri = java.net.URI(scenario.verifierModuleUrl)
                val moduleHost =
                    moduleUri.host?.lowercase()?.takeIf { moduleUri.scheme?.lowercase() == "https" }
                        ?: error("verifier module is not a trusted service")

                onStatus("Fetching the live trust list…")
                val trustList = IssuerTrustList.fetchAll()
                val trustedHosts = verifierHosts(trustList)
                if (moduleHost !in trustedHosts) error("verifier module is not a trusted service")

                onStatus("Gate 1: matching the verifier's organisation…")
                val matched =
                    when (val verdict = authoriseFetchUrl(scenario.verifierModuleUrl, trustList)) {
                        is Verdict.Allowed -> verdict.issuers
                        is Verdict.Refused -> throw verdict.v1
                    }

                onStatus("Verifying the verifier's on-chain standing…")
                val trustEvidence = firstOnChainEvidence(matched)

                onStatus("Starting the pickup transaction…")
                val startUrl = "${scenario.verifierModuleUrl.trimEnd('/')}/api/ext/offline/qrcode/${scenario.vpUid}"
                val start = parseConvenienceStorePickupStart(TwdiwClient.get(startUrl))

                onStatus("Reading the verifier's request…")
                val link = parseAuthorizeLink(start.deepLink)
                val requestUri = (link as? Oid4VpAuthorizeLink.ByReference)?.requestUri
                if (requestUri != null) {
                    val requestHost = runCatching { java.net.URI(requestUri).host?.lowercase() }.getOrNull()
                    if (requestHost != moduleHost) error("unexpected request: not this verifier's own host")
                }
                val compactJws =
                    when (link) {
                        is Oid4VpAuthorizeLink.ByReference -> TwdiwClient.getText(link.requestUri).trim()
                        is Oid4VpAuthorizeLink.ByValue -> link.requestObject
                    }
                val clientId =
                    when (link) {
                        is Oid4VpAuthorizeLink.ByReference -> link.clientId
                        is Oid4VpAuthorizeLink.ByValue -> link.clientId
                    }

                onStatus("Verifying the request's signature…")
                val request = verifyOid4vpRequest(compactJws, clientId, trustedHosts.toList())
                val responseHost = runCatching { java.net.URI(request.responseUri).host?.lowercase() }.getOrNull()
                if (responseHost != moduleHost || request.definitionId != scenario.vpUid) {
                    error("unexpected request: does not match this transaction")
                }
                val claims = request.inputDescriptors.flatMap { it.requestedFields }.mapNotNull { it.claimName() }.toSet()
                if ("name" !in claims || "phonel5" !in claims) {
                    error("unexpected request: does not ask for name/phonel5")
                }

                PickupContext(scenario, start.transactionId, request, trustEvidence)
            }
        }

    /** Ported from `ConvenienceStorePickupClient.begin`: the first matched issuer with a verified record, not "all agree". */
    private suspend fun firstOnChainEvidence(matched: List<TwdiwIssuer>): PickupTrustEvidence {
        val results = matched.associateWith { OnChainVerifier.verify(it) }
        for (issuer in matched) {
            val result = results[issuer]
            if (result is TwdiwOnChainVerification.Verified) {
                return PickupTrustEvidence(issuer.displayName, result.blockNumber, result.transactionHash)
            }
        }
        if (results.values.any { it == TwdiwOnChainVerification.Unavailable }) {
            error("on-chain trust evidence is unavailable right now")
        }
        error("verifier module is not a trusted service")
    }

    suspend fun presentAndGenerate(
        context: PickupContext,
        credentialStore: CredentialStore,
        onStatus: (String) -> Unit,
    ): Result<PickupBarcodeSession> =
        withContext(Dispatchers.IO) {
            runCatching {
                onStatus("Matching a stored card to the request…")
                val (credentialId, credential, presented, descriptorIds) = matchAndDisclose(context.request, credentialStore)
                val alias = "telecom-${credential.credentialType}"
                val holderKey =
                    KeystoreHolderKey.load(alias)
                        ?: error("no Keystore key for the matched card ($credentialId)")

                onStatus("Signing the presentation…")
                val nowSeconds = System.currentTimeMillis() / 1000
                val signingInput =
                    vpTokenSigningInput(context.request, presented, holderKey.publicKeyX963(), nowSeconds)
                        ?: error("could not build the vp_token signing input")
                val vpToken = assembleVpToken(signingInput, holderKey.signRaw(signingInput.toByteArray()))
                val submission = presentationSubmissionForDescriptorIds(context.request, descriptorIds)

                onStatus("Posting the presentation…")
                val body =
                    formEncode(
                        listOf(
                            FfiFormField("vp_token", vpToken),
                            FfiFormField("presentation_submission", submission),
                            FfiFormField("state", context.request.state),
                        ),
                    )
                TwdiwClient.postFormEncoded(context.request.responseUri, body)

                val holderDid = walletIdentityFromPublicKey(holderKey.publicKeyX963()).jwkDid
                val receipt = PickupReceipt(holderDid, alias)

                onStatus("Requesting the barcode…")
                val barcode = requestBarcode(context, receipt)
                val expiresAt =
                    convenienceStorePickupCountdownExpiresAt(barcode.lifetimeSeconds, barcode.generatedAtUnixSeconds)
                        ?: error("could not compute the barcode's countdown")

                PickupBarcodeSession(context, receipt, barcode, expiresAt)
            }
        }

    suspend fun regenerate(session: PickupBarcodeSession, onStatus: (String) -> Unit): Result<PickupBarcodeSession> =
        withContext(Dispatchers.IO) {
            runCatching {
                onStatus("Requesting a new barcode…")
                val barcode = requestBarcode(session.context, session.receipt)
                val expiresAt =
                    convenienceStorePickupCountdownExpiresAt(barcode.lifetimeSeconds, barcode.generatedAtUnixSeconds)
                        ?: error("could not compute the barcode's countdown")
                session.copy(barcode = barcode, expiresAtUnixMillis = expiresAt)
            }
        }

    private fun requestBarcode(context: PickupContext, receipt: PickupReceipt): FfiConvenienceStorePickupBarcode {
        val holderKey =
            KeystoreHolderKey.load(receipt.holderKeyAlias) ?: error("no Keystore key for ${receipt.holderKeyAlias}")
        val header = JSONObject().put("typ", "JWT").put("alg", "ES256").put("kid", receipt.holderDid)
        val payload = JSONObject().put("transactionId", context.transactionId)
        val signingInput = "${base64url(header.toString())}.${base64url(payload.toString())}"
        val jwt = "$signingInput.${base64url(holderKey.signRaw(signingInput.toByteArray()))}"

        val url = "${context.scenario.verifierModuleUrl.trimEnd('/')}/api/ext/offline/getEncryptionData"
        val response = TwdiwClient.postJson(url, JSONObject().put("jwt", jwt).toString())
        return parseConvenienceStorePickupBarcode(response, System.currentTimeMillis() / 1000)
    }

    private fun base64url(text: String): String = base64url(text.toByteArray())

    private fun base64url(bytes: ByteArray): String =
        android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)

    private data class Match(
        val credentialId: String,
        val credential: FfiTwdiwCredential,
        val presented: List<String>,
        val descriptorIds: List<String>,
    )

    /**
     * Ported from `OID4VPResponder.presentationMaterial`: finds one stored
     * card that can answer every requested group and serialises it once per
     * selected descriptor, disclosing exactly `name`/`phonel5`.
     */
    private fun matchAndDisclose(request: Oid4VpRequest, credentialStore: CredentialStore): Match {
        val chosenClaims = setOf("name", "phonel5")
        for (id in credentialStore.allIds()) {
            val serialized = credentialStore.load(id) ?: continue
            val credential = runCatching { readTwdiwCredential(serialized, System.currentTimeMillis() / 1000) }.getOrNull() ?: continue

            val available = credential.disclosedClaims.map { it.name }.toSet()
            if (!chosenClaims.all { it in available }) continue

            val matchingDescriptors =
                request.inputDescriptors.filter { it.credentialType == null || it.credentialType == credential.credentialType }

            val selected =
                if (request.submissionRequirements.isEmpty()) {
                    matchingDescriptors
                        .firstOrNull { descriptor ->
                            val claims = descriptor.requestedFields.mapNotNull { it.claimName() }.toSet()
                            claims.isEmpty() || claims.intersect(chosenClaims).isNotEmpty()
                        }
                        ?.let { listOf(it) } ?: emptyList()
                } else {
                    request.submissionRequirements.mapNotNull { requirement ->
                        val inGroup = matchingDescriptors.filter { requirement.from in it.groups }
                        val groupClaims = inGroup.flatMap { it.requestedFields.mapNotNull { f -> f.claimName() } }.toSet()
                        if (groupClaims.intersect(chosenClaims).isEmpty()) return@mapNotNull null
                        inGroup.firstOrNull { descriptor ->
                            descriptor.requestedFields.mapNotNull { it.claimName() }.toSet().intersect(chosenClaims).isNotEmpty()
                        }
                    }
                }

            val covered = selected.flatMap { it.requestedFields.mapNotNull { f -> f.claimName() } }.toSet()
            if (selected.isEmpty() || !chosenClaims.all { it in covered }) continue

            val presented =
                selected.map { descriptor ->
                    val descriptorClaims = descriptor.requestedFields.mapNotNull { it.claimName() }.toSet()
                    reserialiseTwdiwCredential(credential, chosenClaims.intersect(descriptorClaims).toList())
                }
            return Match(id, credential, presented, selected.map { it.id })
        }
        error("no stored card can answer this request")
    }

    private fun verifierHosts(trustList: List<TwdiwIssuer>): Set<String> =
        trustList
            .flatMap { listOfNotNull(it.issuerMetadataBaseUrl, it.serviceBaseUrl) }
            .mapNotNull { runCatching { java.net.URI(it).host?.lowercase() }.getOrNull() }
            .toSet()
}

/** Mirrors `Oid4VpRequestedField::claim_name` (core doesn't export it as a standalone function). */
private fun uniffi.backuptw_core.Oid4VpRequestedField.claimName(): String? {
    val prefix = "$.credentialSubject."
    if (!path.startsWith(prefix)) return null
    val rest = path.removePrefix(prefix)
    return if ('.' in rest) null else rest
}
