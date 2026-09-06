package tw.bonds.backuptw.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uniffi.backuptw_core.CredentialOfferLink
import uniffi.backuptw_core.FfiFormField
import uniffi.backuptw_core.FfiTwdiwCredential
import uniffi.backuptw_core.Verdict
import uniffi.backuptw_core.assembleProofJwt
import uniffi.backuptw_core.authoriseFetchUrl
import uniffi.backuptw_core.canonicalIssuerIdentifier
import uniffi.backuptw_core.confirmOrganisation
import uniffi.backuptw_core.confirmRegistryEvidence
import uniffi.backuptw_core.credentialBoundTo
import uniffi.backuptw_core.formEncode
import uniffi.backuptw_core.parseCredentialOffer
import uniffi.backuptw_core.parseCredentialOfferLink
import uniffi.backuptw_core.proofSigningInput
import uniffi.backuptw_core.readTwdiwCredential
import uniffi.backuptw_core.walletIdentityFromPublicKey

/**
 * Orchestrates receiving one real TWDIW credential end to end: reads the
 * offer link, runs the three issuer-authorization gates against the live
 * trust list and live on-chain state, exchanges the pre-authorized code
 * for an access token, signs and submits an OID4VCI proof, and verifies
 * the credential that comes back is bound to `holderKey`.
 *
 * `client_id` in the token request and the proof's `iss` is the literal
 * string `moda_dw` - this project's established policy is to replicate
 * the official app's own client_id exactly (the token endpoint looks up
 * the pre-authorized code by the pair `(code, "moda_dw")`), not to "fix"
 * it. The proof's `kid`/holder identity is still this device's own key.
 *
 * Everything here is native orchestration around `core`'s pure logic -
 * network calls and Keystore signing stay on this side of the FFI
 * boundary by design (`docs/2026-09-05-decisions-and-roadmap.md`).
 */
object ReceiveFlow {
    private const val TOKEN_CLIENT_ID = "moda_dw"

    /** On success: the verified credential and the configuration id it was requested under. */
    suspend fun receive(
        offerLink: String,
        holderKey: SigningKeyHandle,
        onStatus: (String) -> Unit,
    ): Result<Pair<FfiTwdiwCredential, String>> =
        withContext(Dispatchers.IO) {
            runCatching {
                onStatus("Reading offer link…")
                val link = parseCredentialOfferLink(offerLink)
                val offerJson =
                    when (link) {
                        is CredentialOfferLink.ByReference -> TwdiwClient.get(link.fetchUrl)
                        is CredentialOfferLink.ByValue -> link.json.toByteArray()
                    }
                val offer = parseCredentialOffer(offerJson)

                onStatus("Fetching the live trust list…")
                val trustList = IssuerTrustList.fetchAll()

                onStatus("Gate 1: checking the issuer host…")
                val matched =
                    when (val verdict = authoriseFetchUrl(offer.credentialIssuer, trustList)) {
                        is Verdict.Allowed -> verdict.issuers
                        is Verdict.Refused -> throw verdict.v1
                    }

                onStatus("Gate 1b: verifying the on-chain registry…")
                val verification = matched.associate { it.did to OnChainVerifier.verify(it) }
                confirmRegistryEvidence(matched, verification)

                onStatus("Gate 2: confirming the organisation…")
                confirmOrganisation(offer.credentialIssuer, matched)
                val issuerIdentifier =
                    canonicalIssuerIdentifier(offer.credentialIssuer)
                        ?: error("no canonical issuer identifier for ${offer.credentialIssuer}")

                onStatus("Fetching issuer metadata…")
                val credentialEndpoint = fetchCredentialEndpoint(issuerIdentifier)

                onStatus("Requesting an access token…")
                val tokenBody =
                    formEncode(
                        listOf(
                            FfiFormField(
                                "grant_type",
                                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                            ),
                            FfiFormField("pre-authorized_code", offer.preAuthorizedCode),
                            FfiFormField("client_id", TOKEN_CLIENT_ID),
                        ),
                    )
                val tokenResponse =
                    JSONObject(String(TwdiwClient.postFormEncoded("$issuerIdentifier/token", tokenBody), Charsets.UTF_8))
                val accessToken = tokenResponse.getString("access_token")
                val nonce = tokenResponse.getString("c_nonce")

                onStatus("Signing the proof…")
                val configurationId = offer.configurationIds.first()
                val holderDid = walletIdentityFromPublicKey(holderKey.publicKeyX963()).jwkDid
                val proofInput =
                    proofSigningInput(
                        TOKEN_CLIENT_ID,
                        issuerIdentifier,
                        holderDid,
                        nonce,
                        System.currentTimeMillis() / 1000,
                    )
                val proofJwt = assembleProofJwt(proofInput, holderKey.signRaw(proofInput.toByteArray()))

                onStatus("Requesting the credential…")
                val credentialRequestBody =
                    JSONObject()
                        .put("credential_identifier", configurationId)
                        .put("proofs", JSONObject().put("jwt", JSONArray().put(proofJwt)))
                val credentialResponse =
                    JSONObject(
                        String(
                            TwdiwClient.postJson(credentialEndpoint, credentialRequestBody.toString(), accessToken),
                            Charsets.UTF_8,
                        ),
                    )
                val serializedCredential = extractCredential(credentialResponse)

                onStatus("Verifying the credential…")
                if (!credentialBoundTo(serializedCredential, holderKey.publicKeyX963())) {
                    error("received credential is not bound to this device's key")
                }
                val credential = readTwdiwCredential(serializedCredential, System.currentTimeMillis() / 1000)

                credential to configurationId
            }
        }

    /** Host must match `issuerIdentifier`'s - fail closed, same discipline as every other gate here. */
    private fun fetchCredentialEndpoint(issuerIdentifier: String): String {
        val metadata =
            JSONObject(
                String(TwdiwClient.get("$issuerIdentifier/.well-known/openid-credential-issuer"), Charsets.UTF_8),
            )
        val endpoint = metadata.getString("credential_endpoint")
        val issuerHost = java.net.URI(issuerIdentifier).host?.lowercase()
        val endpointHost = java.net.URI(endpoint).host?.lowercase()
        check(issuerHost != null && issuerHost == endpointHost) {
            "credential_endpoint host does not match the issuer: $endpoint"
        }
        return endpoint
    }

    /** Both `{credentials:[{credential}]}` and `{credential}` are live shapes. */
    private fun extractCredential(response: JSONObject): String {
        response.optJSONArray("credentials")?.let { credentials ->
            if (credentials.length() > 0) return credentials.getJSONObject(0).getString("credential")
        }
        return response.getString("credential")
    }
}
