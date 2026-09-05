package tw.bonds.backuptw.wallet

/**
 * Fixed test data for the fixture-driven demo screens - the exact same
 * strings `core/src/ffi.rs`'s own `#[cfg(test)]` module uses to exercise
 * these FFI wrappers, so this file and that test never drift apart
 * silently. No live TWDIW endpoint is contacted; see `MainActivity.kt`
 * and `android/README.md` for why.
 */
object Fixtures {
    /** A well-formed offer naming the fixture sandbox issuer below. */
    const val OFFER_JSON =
        """{"credential_issuer":"https://issuer-sandbox.wallet.gov.tw/api/issuer/00000000","credential_configuration_ids":["00000000_demo_drivinglicense_202504251418"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"CODE-1"}}}"""

    /**
     * One trust-list page entry whose `issuerMetadataBaseURL` host
     * matches [OFFER_JSON]'s `credential_issuer`, so all three
     * issuer-authorization gates pass - paired with
     * `TwdiwOnChainVerification.DevelopmentSandbox` for the on-chain gate,
     * the same way the real app treats its own DEBUG-only sandbox
     * demo issuer (no production Arbitrum record exists for it either).
     */
    const val TRUST_LIST_PAGE_JSON =
        """{"msg":"執行成功","code":"0","data":{"count":1,"dids":[
      {"id":"did:key:zSandboxDemoIssuer","orgType":1,"orgGroupDetail":{"name":"政府部門"},
       "org":{"name":"數位憑證皮夾沙盒","name_en":"Taiwan Digital Identity Wallet Sandbox",
              "taxId":"00000000","issuerMetadataBaseURL":"https://issuer-sandbox.wallet.gov.tw"},
       "onChainHistory":[]}
    ]}}"""

    /**
     * A complete, real, independently-verifiable TWDIW SD-JWT credential:
     * a fixed (not random) P-256 issuer/holder key pair, built the same
     * way `core/src/twdiw/credential.rs`'s own `Fixture` test helper
     * builds one. Its ES256 signature genuinely verifies and its three
     * disclosures genuinely match their committed digests - this is not
     * a fake string, just one whose keys are fixed instead of freshly
     * generated, so the same bytes work on every run.
     */
    const val CREDENTIAL =
        "eyJhbGciOiJFUzI1NiIsImprdSI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL2tleXMiLCJraWQiOiJrZXktMSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiMWxxVGwzeXFQUnNJR0ZMX1Y2ZWVSbDhXWUZkekJMcnExUVhkT2toWW5QTSIsInkiOiJVQmhlaVZOeTMySWg2am9UZFZma2NfM2JaMVh3VzlVSHc4VXpfT25KRW9VIn19LCJleHAiOjIwNzUzNTY1NjEsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtib2lzUW1hOEUxMjM5Y2lEWjhEODZQa0w1UkcyWEs5SGRKaFNKRkxoNlZSckM4b3VUQ1VSdTlaWGdSRTlEcTNSbmc3WTkxMmo0NFlGeDRYZ0xLa21yVDVVbkN5OGlDODR4dVRrMTFCS291VHVtdWh3dnlqenRNQXdRQ1g3S0JjU3UyVSIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL2NyZWRlbnRpYWwvMzlkNjA3MTUtZTkwYy00MDJhLTk4YWEtdGVzdCIsIm5iZiI6MTc1OTgyMzc2MSwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JuVVdyaG9LSExIMURaS1lVTGNKaG9VYTRxTE15VjYzVmZLeEZZV0FkY1BQN2tmVEVCTlNZbXViM0pOdHNOTkFGWHZWTHk4SHZrQTlwR3FjNmt6Nk5wNHV1Nm5UNmc2RWNyVTJCTGE3cjI1WUV4NDM2ZFJwZ3NXZnI3Y2h3ZnRkbW5DIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW8vVjEvYjY1M2FkNGIiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvMDAwMDAwMDBfZGVtb19kcml2aW5nbGljZW5zZV8yMDI1MDQyNTE0MTgvcjAjMzUiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIiwic3RhdHVzTGlzdEluZGV4IjoiMzUiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiIsInR5cGUiOiJTdGF0dXNMaXN0MjAyMUVudHJ5In0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyI0YTBnWVFiZkVLMDBCUTBpRnNmR0JqVUR6bG5EdlJRYjZwTmFUZEY2OTNBIiwiUzNrS1hCZDZsU3NqVERVV0lJRjRlWVV0QnFkdm9ZLWtGdEVkeFpxQ0dnYyIsIlloVjZFeWFXZk1ueWlxWEFnQ3dJdDVRTjN4OGR6SnlxQ05KZnJRaVAtZlEiXSwiX3NkX2FsZyI6InNoYS0yNTYifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4Il19fQ.Xi2bDyU5b-OHZ82oG63oNNt6Kv42lYx9Mb9tCEve2P886uGi7HcAFxj1o4Cbp65QpIhqCRNyR-QJ6SwhP3oicg~WyJWU3dybVpBRE91VUlfdDFiVkh3NVF3IiwibmFtZSIsIumZs-etseeOsiJd~WyJ6WEZ3U3JPV0kyd3RBQlZManRwVXl3IiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd~WyJ6WVFTd1dGcDVGTG5FazBvMElMaXhBIiwicm9jX2JpcnRoZGF5IiwiMDU3MDYwNSJd~"

    /** A stand-in for the nonce a real token response would carry. */
    const val DEMO_NONCE = "DEMO-NONCE-1"
}
