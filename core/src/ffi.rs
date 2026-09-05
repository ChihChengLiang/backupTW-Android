//! The UniFFI-exported surface of this crate.
//!
//! Kept as one place so the FFI boundary's *entry points* are easy to
//! audit: every `#[uniffi::export]` function lives here, not scattered
//! across `identity`/`credential`/`trust`/`twdiw`'s own modules. The
//! `#[derive(uniffi::Record/Enum/Error)]` attributes those functions'
//! parameter and return types need live on the domain types themselves,
//! in their home modules — duplicating each as a hand-written mirror
//! struct here would be a second copy to keep in sync for no benefit,
//! since every field on them is already a UniFFI-builtin-compatible
//! shape. The one exception is [`FfiTwdiwCredential`]: `TwdiwCredential`'s
//! `disclosed_claims` is `Vec<(String, String)>`, and tuples aren't a
//! UniFFI type, so that one field gets a small mirror record instead of
//! changing the tuple shape everywhere else in the crate that uses it.

use std::collections::HashMap;

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;

use crate::identity::{did_key, jwk_did_key};
use crate::twdiw::collection;
use crate::twdiw::credential::{self as twdiw_credential, TwdiwCredential, TwdiwStatusListEntry};
use crate::twdiw::credential_offer::{CredentialOffer, CredentialOfferError, CredentialOfferLink};
use crate::twdiw::issuer_authorization::{
    self, Refusal, TwdiwIssuer, TwdiwOnChainVerification, Verdict,
};

#[derive(uniffi::Record)]
pub struct WalletIdentity {
    /// This app's own `did:key` spelling (`p256-pub`, multicodec `0x1200`).
    pub did: String,
    /// The `jwk_jcs-pub` spelling (multicodec `0xEB51`) the TWDIW ecosystem
    /// uses — the same key, the other identifier.
    pub jwk_did: String,
}

/// Generates a fresh P-256 wallet identity.
///
/// **Ephemeral and in-memory only — a placeholder, not the real design.**
/// The architecture decision
/// (`docs/2026-09-05-decisions-and-roadmap.md`) is that key storage stays
/// native (Android Keystore), reaching the core only through a
/// trait/callback boundary that doesn't exist yet. This function exists to
/// prove the UniFFI plumbing end-to-end for Phase 4's first vertical-slice
/// step (did:key generation) — the key is thrown away the moment the
/// process exits, and calling this twice gives two unrelated identities.
/// Do not build anything that needs a *stable* identity on top of this
/// until Keystore-backed generation replaces it.
#[uniffi::export]
pub fn generate_ephemeral_wallet_identity() -> WalletIdentity {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key: p256::ecdsa::VerifyingKey = *signing_key.verifying_key();
    let x963 = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    WalletIdentity {
        did: did_key::did_from_p256_x963(&x963).expect("freshly generated key is always valid"),
        jwk_did: jwk_did_key::did_from_p256_x963(&x963)
            .expect("freshly generated key is always valid"),
    }
}

/// Both `did:key` spellings for a caller-supplied P-256 public key
/// (X9.63 uncompressed, 65 bytes) - the same derivation
/// [`generate_ephemeral_wallet_identity`] runs on a freshly generated
/// one, exposed separately for a key a caller already holds (e.g. a
/// signing key it generated itself, in-memory or Keystore-backed).
#[uniffi::export]
pub fn wallet_identity_from_public_key(
    public_key_x963: Vec<u8>,
) -> Result<WalletIdentity, FfiError> {
    Ok(WalletIdentity {
        did: did_key::did_from_p256_x963(&public_key_x963)
            .map_err(|e| FfiError::Failed(e.to_string()))?,
        jwk_did: jwk_did_key::did_from_p256_x963(&public_key_x963)
            .map_err(|e| FfiError::Failed(e.to_string()))?,
    })
}

// MARK: - Errors that cannot cross the FFI boundary as themselves

/// A catch-all for FFI functions whose underlying Rust error type cannot
/// cross the UniFFI boundary as-is (e.g. it carries `&'static str`
/// fields, which have no UniFFI representation). Carries the original
/// error's `Display` text rather than losing the reason entirely.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    #[error("{0}")]
    Failed(String),
}

// MARK: - Receiving a credential (TWDIW OID4VCI)
//
// Network calls (fetching the trust list, the offer, the token, the
// credential) and Keystore-backed signing stay native
// (`docs/2026-09-05-decisions-and-roadmap.md`); everything below is the
// pure parsing/decision logic an orchestrator on the Kotlin side calls
// into at each step.

/// Reads a scanned/pasted credential-offer link - which form it is
/// (`byReference`/`byValue`), not yet fetched or trusted.
#[uniffi::export]
pub fn parse_credential_offer_link(
    scanned: String,
) -> Result<CredentialOfferLink, CredentialOfferError> {
    CredentialOfferLink::parse_scanned(&scanned)
}

/// Parses the offer document itself (inline, or fetched from a
/// `byReference` link's `fetch_url`).
#[uniffi::export]
pub fn parse_credential_offer(json: Vec<u8>) -> Result<CredentialOffer, CredentialOfferError> {
    CredentialOffer::parse(&json)
}

/// Parses one page of the TWDIW trust-list API (`GET /api/did`).
#[uniffi::export]
pub fn parse_issuer_trust_list_page(json: Vec<u8>) -> Result<Vec<TwdiwIssuer>, FfiError> {
    TwdiwIssuer::page(&json).map_err(|e| FfiError::Failed(e.to_string()))
}

/// Gate 1: may `fetch_url`'s host be contacted at all?
#[uniffi::export]
pub fn authorise_fetch_url(fetch_url: String, list: Vec<TwdiwIssuer>) -> Verdict {
    issuer_authorization::authorise(&fetch_url, &list)
}

/// Gate 1b: does the current on-chain state agree with the API's claim,
/// for every row gate 1 matched?
#[uniffi::export]
pub fn confirm_registry_evidence(
    matched: Vec<TwdiwIssuer>,
    verification: HashMap<String, TwdiwOnChainVerification>,
) -> Result<(), Refusal> {
    issuer_authorization::confirm_registry_evidence(&matched, &verification)
}

/// Gate 2: does the offer that came back name an issuer from the same
/// organisation as the URL it was fetched from?
#[uniffi::export]
pub fn confirm_organisation(
    credential_issuer: String,
    matched: Vec<TwdiwIssuer>,
) -> Result<TwdiwIssuer, Refusal> {
    issuer_authorization::confirm(&credential_issuer, &matched)
}

/// The issuer identifier to build OID4VCI requests against - scheme,
/// host and path from the gate's canonical spelling, never the offer's
/// own bytes.
#[uniffi::export]
pub fn canonical_issuer_identifier(credential_issuer: String) -> Option<String> {
    collection::canonical_issuer_identifier(&credential_issuer)
}

/// The bytes an OID4VCI proof JWT signature covers. Sign the result
/// externally (Keystore) and hand the raw `r ‖ s` signature to
/// [`assemble_proof_jwt`].
#[uniffi::export]
pub fn proof_signing_input(
    client_id: String,
    issuer_identifier: String,
    holder_did: String,
    nonce: String,
    issued_at: i64,
) -> String {
    collection::proof_signing_input(&collection::ProofClaims {
        client_id: &client_id,
        issuer_identifier: &issuer_identifier,
        holder_did: &holder_did,
        nonce: &nonce,
        issued_at,
    })
}

/// Combines a `signing_input` (from [`proof_signing_input`]) with its raw
/// `r ‖ s` ECDSA signature into the compact proof JWT. `signature` must
/// be exactly 64 bytes.
#[uniffi::export]
pub fn assemble_proof_jwt(signing_input: String, signature: Vec<u8>) -> Result<String, FfiError> {
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| FfiError::Failed("signature must be 64 bytes".to_string()))?;
    Ok(collection::assemble_proof_jwt(&signing_input, &signature))
}

/// Whether the credential's `cnf.jwk` is exactly the public key named by
/// `public_key_x963` (X9.63 uncompressed, 65 bytes).
#[uniffi::export]
pub fn credential_bound_to(serialized: String, public_key_x963: Vec<u8>) -> bool {
    collection::credential_bound_to(&serialized, &public_key_x963)
}

/// One claim a TWDIW credential disclosed. A small mirror of one field of
/// `TwdiwCredential` - see this module's doc comment for why.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDisclosedClaim {
    pub name: String,
    pub value: String,
}

/// A verified TWDIW credential, ready to display. Mirrors
/// `twdiw::TwdiwCredential` field-for-field except `disclosed_claims`,
/// which becomes `Vec<FfiDisclosedClaim>` in place of `Vec<(String,
/// String)>` - see this module's doc comment.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTwdiwCredential {
    pub serialized: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub credential_id: Option<String>,
    pub credential_type: String,
    pub not_before: i64,
    pub expires: i64,
    pub holder_key_x963: Vec<u8>,
    pub status: Option<TwdiwStatusListEntry>,
    pub schema_url: Option<String>,
    pub declared_key_source_url: Option<String>,
    pub declared_key_id: Option<String>,
    pub commitments: Vec<String>,
    pub disclosed_claims: Vec<FfiDisclosedClaim>,
}

impl From<TwdiwCredential> for FfiTwdiwCredential {
    fn from(credential: TwdiwCredential) -> Self {
        Self {
            serialized: credential.serialized,
            issuer_did: credential.issuer_did,
            subject_did: credential.subject_did,
            credential_id: credential.credential_id,
            credential_type: credential.credential_type,
            not_before: credential.not_before,
            expires: credential.expires,
            holder_key_x963: credential.holder_key_x963,
            status: credential.status,
            schema_url: credential.schema_url,
            declared_key_source_url: credential.declared_key_source_url,
            declared_key_id: credential.declared_key_id,
            commitments: credential.commitments,
            disclosed_claims: credential
                .disclosed_claims
                .into_iter()
                .map(|(name, value)| FfiDisclosedClaim { name, value })
                .collect(),
        }
    }
}

/// Reads and cryptographically verifies a received TWDIW SD-JWT
/// credential. `now`: Unix seconds, for the `nbf`/`exp` window.
#[uniffi::export]
pub fn read_twdiw_credential(serialized: String, now: i64) -> Result<FfiTwdiwCredential, FfiError> {
    twdiw_credential::read(&serialized, now)
        .map(FfiTwdiwCredential::from)
        .map_err(|e| FfiError::Failed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_two_valid_did_key_spellings_of_one_key() {
        let identity = generate_ephemeral_wallet_identity();
        assert!(identity.did.starts_with("did:key:zDnae"));
        assert!(identity.jwk_did.starts_with("did:key:z"));

        // Round-trips through this crate's own decoders.
        let from_p256 = did_key::p256_public_key_from_did(&identity.did).unwrap();
        let from_jwk = jwk_did_key::p256_public_key_from_did(&identity.jwk_did).unwrap();
        assert_eq!(
            p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&from_p256, false)
                .as_bytes(),
            p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&from_jwk, false)
                .as_bytes(),
        );
    }

    #[test]
    fn two_calls_give_different_identities() {
        let a = generate_ephemeral_wallet_identity();
        let b = generate_ephemeral_wallet_identity();
        assert_ne!(a.did, b.did);
    }

    #[test]
    fn wallet_identity_from_public_key_matches_the_ephemeral_generator() {
        // A key generated outside this crate (as HolderKey.kt does)
        // derives the same two DIDs the all-in-one generator would have
        // produced for the same key.
        let key = SigningKey::random(&mut OsRng);
        let vk: p256::ecdsa::VerifyingKey = *key.verifying_key();
        let x963 = vk.to_encoded_point(false).as_bytes().to_vec();

        let identity = wallet_identity_from_public_key(x963.clone()).unwrap();
        assert_eq!(identity.did, did_key::did_from_p256_x963(&x963).unwrap());
        assert_eq!(
            identity.jwk_did,
            jwk_did_key::did_from_p256_x963(&x963).unwrap()
        );
    }

    #[test]
    fn wallet_identity_from_public_key_rejects_a_malformed_key() {
        assert!(wallet_identity_from_public_key(vec![1, 2, 3]).is_err());
    }

    // The same fixtures the `wallet` app's fixture-driven demo screen
    // uses (see android/wallet's Fixtures.kt) - kept here too so the
    // FFI-facing wrappers are covered by this crate's own test suite,
    // not only by tapping through the app.

    const FIXTURE_OFFER_JSON: &str = r#"{"credential_issuer":"https://issuer-sandbox.wallet.gov.tw/api/issuer/00000000","credential_configuration_ids":["00000000_demo_drivinglicense_202504251418"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"CODE-1"}}}"#;

    const FIXTURE_TRUST_LIST_PAGE_JSON: &str = r#"{"msg":"執行成功","code":"0","data":{"count":1,"dids":[
      {"id":"did:key:zSandboxDemoIssuer","orgType":1,"orgGroupDetail":{"name":"政府部門"},
       "org":{"name":"數位憑證皮夾沙盒","name_en":"Taiwan Digital Identity Wallet Sandbox",
              "taxId":"00000000","issuerMetadataBaseURL":"https://issuer-sandbox.wallet.gov.tw"},
       "onChainHistory":[]}
    ]}}"#;

    #[test]
    fn a_fixture_offer_passes_all_three_gates() {
        let offer = parse_credential_offer(FIXTURE_OFFER_JSON.as_bytes().to_vec()).unwrap();
        let list =
            parse_issuer_trust_list_page(FIXTURE_TRUST_LIST_PAGE_JSON.as_bytes().to_vec()).unwrap();
        assert_eq!(list.len(), 1);

        let matched = match authorise_fetch_url(offer.credential_issuer.clone(), list) {
            Verdict::Allowed { issuers, .. } => issuers,
            Verdict::Refused(refusal) => panic!("gate 1 refused: {refusal}"),
        };
        assert_eq!(matched.len(), 1);

        let mut verification = HashMap::new();
        verification.insert(
            matched[0].did.clone(),
            TwdiwOnChainVerification::DevelopmentSandbox,
        );
        confirm_registry_evidence(matched.clone(), verification).unwrap();

        let confirmed = confirm_organisation(offer.credential_issuer.clone(), matched).unwrap();
        assert_eq!(confirmed.did, "did:key:zSandboxDemoIssuer");

        let issuer_identifier = canonical_issuer_identifier(offer.credential_issuer).unwrap();
        assert_eq!(
            issuer_identifier,
            "https://issuer-sandbox.wallet.gov.tw/api/issuer/00000000"
        );
    }

    #[test]
    fn a_proof_jwt_round_trips_through_the_ffi_split() {
        use p256::ecdsa::signature::Signer;
        let key = SigningKey::random(&mut OsRng);
        let vk: p256::ecdsa::VerifyingKey = *key.verifying_key();
        let x963 = vk.to_encoded_point(false).as_bytes().to_vec();
        let holder_did = jwk_did_key::did_from_p256_x963(&x963).unwrap();

        let input = proof_signing_input(
            holder_did.clone(),
            "https://issuer-sandbox.wallet.gov.tw/api/issuer/00000000".to_string(),
            holder_did,
            "DEMO-NONCE-1".to_string(),
            1_754_400_000,
        );
        let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
        let jwt = assemble_proof_jwt(input, signature.to_bytes().to_vec()).unwrap();
        assert_eq!(jwt.split('.').count(), 3);

        assert_eq!(
            assemble_proof_jwt("x.y".to_string(), vec![0u8; 10]),
            Err(FfiError::Failed("signature must be 64 bytes".to_string()))
        );
    }

    /// A fixed (not random) issuer/holder key pair's credential, built the
    /// same way `twdiw::credential::tests::Fixture` builds one, so it's a
    /// real, independently-verifiable SD-JWT rather than an invented
    /// string. See `android/wallet`'s Fixtures.kt for the same constant.
    const FIXTURE_CREDENTIAL: &str = "eyJhbGciOiJFUzI1NiIsImprdSI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL2tleXMiLCJraWQiOiJrZXktMSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiMWxxVGwzeXFQUnNJR0ZMX1Y2ZWVSbDhXWUZkekJMcnExUVhkT2toWW5QTSIsInkiOiJVQmhlaVZOeTMySWg2am9UZFZma2NfM2JaMVh3VzlVSHc4VXpfT25KRW9VIn19LCJleHAiOjIwNzUzNTY1NjEsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtib2lzUW1hOEUxMjM5Y2lEWjhEODZQa0w1UkcyWEs5SGRKaFNKRkxoNlZSckM4b3VUQ1VSdTlaWGdSRTlEcTNSbmc3WTkxMmo0NFlGeDRYZ0xLa21yVDVVbkN5OGlDODR4dVRrMTFCS291VHVtdWh3dnlqenRNQXdRQ1g3S0JjU3UyVSIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL2NyZWRlbnRpYWwvMzlkNjA3MTUtZTkwYy00MDJhLTk4YWEtdGVzdCIsIm5iZiI6MTc1OTgyMzc2MSwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JuVVdyaG9LSExIMURaS1lVTGNKaG9VYTRxTE15VjYzVmZLeEZZV0FkY1BQN2tmVEVCTlNZbXViM0pOdHNOTkFGWHZWTHk4SHZrQTlwR3FjNmt6Nk5wNHV1Nm5UNmc2RWNyVTJCTGE3cjI1WUV4NDM2ZFJwZ3NXZnI3Y2h3ZnRkbW5DIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW8vVjEvYjY1M2FkNGIiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvMDAwMDAwMDBfZGVtb19kcml2aW5nbGljZW5zZV8yMDI1MDQyNTE0MTgvcjAjMzUiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIiwic3RhdHVzTGlzdEluZGV4IjoiMzUiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiIsInR5cGUiOiJTdGF0dXNMaXN0MjAyMUVudHJ5In0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyI0YTBnWVFiZkVLMDBCUTBpRnNmR0JqVUR6bG5EdlJRYjZwTmFUZEY2OTNBIiwiUzNrS1hCZDZsU3NqVERVV0lJRjRlWVV0QnFkdm9ZLWtGdEVkeFpxQ0dnYyIsIlloVjZFeWFXZk1ueWlxWEFnQ3dJdDVRTjN4OGR6SnlxQ05KZnJRaVAtZlEiXSwiX3NkX2FsZyI6InNoYS0yNTYifSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4Il19fQ.Xi2bDyU5b-OHZ82oG63oNNt6Kv42lYx9Mb9tCEve2P886uGi7HcAFxj1o4Cbp65QpIhqCRNyR-QJ6SwhP3oicg~WyJWU3dybVpBRE91VUlfdDFiVkh3NVF3IiwibmFtZSIsIumZs-etseeOsiJd~WyJ6WEZ3U3JPV0kyd3RBQlZManRwVXl3IiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd~WyJ6WVFTd1dGcDVGTG5FazBvMElMaXhBIiwicm9jX2JpcnRoZGF5IiwiMDU3MDYwNSJd~";

    #[test]
    fn a_fixture_credential_reads_and_verifies() {
        let credential =
            read_twdiw_credential(FIXTURE_CREDENTIAL.to_string(), 1_754_400_000).unwrap();
        assert_eq!(
            credential.credential_type,
            "00000000_demo_drivinglicense_202504251418"
        );
        assert_eq!(credential.disclosed_claims.len(), 3);
        assert!(credential
            .disclosed_claims
            .iter()
            .any(|c| c.name == "name" && c.value == "陳筱玲"));
    }
}
