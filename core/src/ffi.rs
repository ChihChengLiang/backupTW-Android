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

use std::collections::{HashMap, HashSet};

use chrono::{TimeZone, Utc};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;

use crate::identity::{did_key, jwk_did_key};
use crate::twdiw::collection;
use crate::twdiw::convenience_store_pickup::{
    self, ConvenienceStorePickupBarcode, ConvenienceStorePickupCountdown,
    ConvenienceStorePickupError, ConvenienceStorePickupScenario,
};
use crate::twdiw::credential::{self as twdiw_credential, TwdiwCredential, TwdiwStatusListEntry};
use crate::twdiw::credential_offer::{CredentialOffer, CredentialOfferError, CredentialOfferLink};
use crate::twdiw::issuer_authorization::{
    self, Refusal, TwdiwIssuer, TwdiwOnChainRecord, TwdiwOnChainVerification, Verdict,
};
use crate::twdiw::moda_card_application::{self, DwModa201iResponse, DwModa201iResponseError};
use crate::twdiw::oid4vp_request::{Oid4VpAuthorizeLink, Oid4VpRequest};
use crate::twdiw::oid4vp_response;
use crate::twdiw::onchain::{self, CurrentRegistryRecord};
use crate::twdiw::telecom_card_catalog::{self, TelecomCard, TelecomCardCatalogError};

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

// MARK: - Presenting a credential (TWDIW OID4VP) and the convenience-store
// pickup scenario built on top of it.
//
// Same boundary as the receive path above: network calls (the verifier
// module's catalogue/transaction/barcode endpoints, fetching the request
// object) and Keystore-backed signing stay native.

/// Reads a scanned/pasted `openid4vp` / `modadigitalwallet://authorize`
/// link - which form it is (`byReference`/`byValue`), not yet fetched or
/// verified.
#[uniffi::export]
pub fn parse_authorize_link(scanned: String) -> Result<Oid4VpAuthorizeLink, FfiError> {
    Oid4VpAuthorizeLink::parse(&scanned).map_err(|e| FfiError::Failed(e.to_string()))
}

/// Verifies a fetched OID4VP request object and reduces it to what
/// building a response needs. `trusted_response_hosts`: hosts this wallet
/// will post a signed token to - the request's `response_uri` must be one
/// of them, the same "gate before the first request" discipline the
/// issuer offer's gates use.
#[uniffi::export]
pub fn verify_oid4vp_request(
    compact_jws: String,
    client_id: String,
    trusted_response_hosts: Vec<String>,
) -> Result<Oid4VpRequest, FfiError> {
    let hosts: HashSet<String> = trusted_response_hosts.into_iter().collect();
    Oid4VpRequest::verify(&compact_jws, &client_id, &hosts)
        .map_err(|e| FfiError::Failed(e.to_string()))
}

/// Rebuilds a received TWDIW SD-JWT keeping only the chosen disclosures -
/// the wire form a `vp_token` presents. `credential`: as returned by
/// [`read_twdiw_credential`].
#[uniffi::export]
pub fn reserialise_twdiw_credential(
    credential: FfiTwdiwCredential,
    chosen_claims: Vec<String>,
) -> String {
    let chosen: HashSet<String> = chosen_claims.into_iter().collect();
    let full = TwdiwCredential {
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
            .map(|c| (c.name, c.value))
            .collect(),
    };
    oid4vp_response::reserialise(&full, &chosen)
}

/// The DIF presentation submission for the legacy one-descriptor request,
/// as compact JSON.
#[uniffi::export]
pub fn presentation_submission_for_request(request: Oid4VpRequest) -> String {
    oid4vp_response::presentation_submission_for_request(&request).to_string()
}

/// The DIF presentation submission for a grouped (carrier-alternative)
/// request - one `jwt_vc`-formatted entry per descriptor id, in order - as
/// compact JSON.
#[uniffi::export]
pub fn presentation_submission_for_descriptor_ids(
    request: Oid4VpRequest,
    descriptor_ids: Vec<String>,
) -> String {
    oid4vp_response::presentation_submission_for_descriptor_ids(&request, &descriptor_ids)
        .to_string()
}

/// The bytes a `vp_token` JWT signature covers. Sign the result externally
/// (Keystore) and hand the raw `r ‖ s` signature to [`assemble_vp_token`].
/// `now_unix_seconds`: Unix seconds; `None` if it cannot be represented as
/// a valid instant.
#[uniffi::export]
pub fn vp_token_signing_input(
    request: Oid4VpRequest,
    presented: Vec<String>,
    holder_public_key_x963: Vec<u8>,
    now_unix_seconds: i64,
) -> Option<String> {
    let now = Utc.timestamp_opt(now_unix_seconds, 0).single()?;
    oid4vp_response::vp_token_signing_input(&request, &presented, &holder_public_key_x963, now)
}

/// Combines a `signing_input` (from [`vp_token_signing_input`]) with its
/// raw `r ‖ s` ECDSA signature into the compact `vp_token` JWT. `signature`
/// must be exactly 64 bytes.
#[uniffi::export]
pub fn assemble_vp_token(signing_input: String, signature: Vec<u8>) -> Result<String, FfiError> {
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| FfiError::Failed("signature must be 64 bytes".to_string()))?;
    Ok(oid4vp_response::assemble_vp_token(
        &signing_input,
        &signature,
    ))
}

/// ABI-encodes `getDocById(bytes)` for a current-state on-chain registry
/// lookup (the `eth_call` leg of the on-chain verification batch).
#[uniffi::export]
pub fn current_record_call_data(did: String) -> Option<String> {
    onchain::current_record_call_data(&did)
}

/// Decodes the live registry contract's current-record return value.
#[uniffi::export]
pub fn decode_current_record(value: String) -> Option<CurrentRegistryRecord> {
    onchain::decode_current_record(&value)
}

/// Whether a JSON-RPC reply names an infrastructure failure (the
/// independent source could not be checked) rather than a contract
/// execution revert (Arbitrum answered; the claimed current record simply
/// does not exist). A reply that is not even valid JSON is treated as an
/// infrastructure error too - fail closed.
#[uniffi::export]
pub fn is_infrastructure_error(reply_json: String) -> bool {
    serde_json::from_str::<serde_json::Value>(&reply_json)
        .map(|value| onchain::is_infrastructure_error(&value))
        .unwrap_or(true)
}

/// Checks that the successful Arbitrum transaction named by the API
/// actually wrote this issuer's own record, *and* that the registry's
/// current state (from [`decode_current_record`]) still agrees.
/// `transaction_json`/`receipt_json`: the raw `result` objects of
/// `eth_getTransactionByHash`/`eth_getTransactionReceipt`, as JSON text.
#[uniffi::export]
pub fn check_on_chain_record(
    issuer: TwdiwIssuer,
    record: TwdiwOnChainRecord,
    transaction_json: Option<String>,
    receipt_json: Option<String>,
    current: Option<CurrentRegistryRecord>,
) -> TwdiwOnChainVerification {
    let transaction: Option<serde_json::Value> =
        transaction_json.and_then(|s| serde_json::from_str(&s).ok());
    let receipt: Option<serde_json::Value> =
        receipt_json.and_then(|s| serde_json::from_str(&s).ok());
    onchain::check(
        &issuer,
        &record,
        transaction.as_ref(),
        receipt.as_ref(),
        current.as_ref(),
    )
}

/// Parses the 「申請新卡」 directory (`GET
/// {frontendBase}/api/moda/dwapp/apply/vcList?...`), reduced to the
/// telecom 門號電子卡 a holder can start.
#[uniffi::export]
pub fn telecom_cards_from_vc_list_json(
    json: Vec<u8>,
) -> Result<Vec<TelecomCard>, TelecomCardCatalogError> {
    telecom_card_catalog::telecom_cards_from_vc_list_json(&json)
}

/// Parses the 201i response naming the issuer page a card application
/// finishes on (`GET
/// {frontendBase}/api/moda/dwapp/serviceUrl/{vcUid}?mode={mode}`).
#[uniffi::export]
pub fn parse_dw_modal_201i_response(
    json: Vec<u8>,
) -> Result<DwModa201iResponse, DwModa201iResponseError> {
    moda_card_application::parse_dw_modal_201i_response(&json)
}

/// Parses the offline-verifier catalogue (`GET
/// {frontendBase}/api/moda/dwapp/offline/vpList?...`).
#[uniffi::export]
pub fn convenience_store_pickup_scenarios(
    json: Vec<u8>,
) -> Result<Vec<ConvenienceStorePickupScenario>, ConvenienceStorePickupError> {
    convenience_store_pickup::scenarios(&json)
}

/// A convenience-store pickup's started transaction: its id and the
/// verifier's own `modadigitalwallet://authorize` deep link. A small
/// mirror record - see this module's doc comment - since a tuple has no
/// UniFFI representation.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiConvenienceStorePickupStart {
    pub transaction_id: String,
    pub deep_link: String,
}

/// Reads the pickup-transaction start reply.
#[uniffi::export]
pub fn parse_convenience_store_pickup_start(
    json: Vec<u8>,
) -> Result<FfiConvenienceStorePickupStart, ConvenienceStorePickupError> {
    convenience_store_pickup::parse_start(&json).map(|(transaction_id, deep_link)| {
        FfiConvenienceStorePickupStart {
            transaction_id,
            deep_link,
        }
    })
}

/// A verifier-issued pickup barcode, ready to display. `image_data` is the
/// verifier's own PNG bytes, kept exactly - never re-encoded.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiConvenienceStorePickupBarcode {
    pub image_data: Vec<u8>,
    pub lifetime_seconds: f64,
    /// Echoes back the `now_unix_seconds` this barcode was received at -
    /// hand it straight to [`convenience_store_pickup_countdown_expires_at`].
    pub generated_at_unix_seconds: i64,
}

/// Reads the encrypted-barcode reply. `now_unix_seconds`: Unix seconds
/// this reply was received - the countdown's absolute deadline is computed
/// from this instant, never decremented locally, so time spent
/// backgrounded cannot make an expired store token look current.
#[uniffi::export]
pub fn parse_convenience_store_pickup_barcode(
    json: Vec<u8>,
    now_unix_seconds: i64,
) -> Result<FfiConvenienceStorePickupBarcode, ConvenienceStorePickupError> {
    let now = Utc
        .timestamp_opt(now_unix_seconds, 0)
        .single()
        .ok_or(ConvenienceStorePickupError::MalformedResponse)?;
    convenience_store_pickup::parse_barcode(&json, now).map(|barcode| {
        FfiConvenienceStorePickupBarcode {
            image_data: barcode.image_data,
            lifetime_seconds: barcode.lifetime_seconds,
            generated_at_unix_seconds: now_unix_seconds,
        }
    })
}

/// The absolute deadline (Unix milliseconds) a pickup barcode expires at,
/// from its verifier-stated lifetime - see
/// [`parse_convenience_store_pickup_barcode`]. `None` only if
/// `generated_at_unix_seconds` cannot be represented as a valid instant.
#[uniffi::export]
pub fn convenience_store_pickup_countdown_expires_at(
    lifetime_seconds: f64,
    generated_at_unix_seconds: i64,
) -> Option<i64> {
    let generated_at = Utc.timestamp_opt(generated_at_unix_seconds, 0).single()?;
    let barcode = ConvenienceStorePickupBarcode {
        image_data: Vec::new(),
        lifetime_seconds,
        generated_at,
    };
    Some(
        ConvenienceStorePickupCountdown::new(&barcode)
            .expires_at
            .timestamp_millis(),
    )
}

/// Seconds remaining until `expires_at_unix_millis`, floored at zero.
/// Always asks the deadline again rather than decrementing a counter, so
/// time spent backgrounded cannot make an expired store token look
/// current. `0` if either timestamp cannot be represented as a valid
/// instant - fail closed to "expired", never to "still valid".
#[uniffi::export]
pub fn convenience_store_pickup_countdown_remaining_seconds(
    expires_at_unix_millis: i64,
    now_unix_seconds: i64,
) -> i64 {
    let (Some(expires_at), Some(now)) = (
        chrono::DateTime::<Utc>::from_timestamp_millis(expires_at_unix_millis),
        Utc.timestamp_opt(now_unix_seconds, 0).single(),
    ) else {
        return 0;
    };
    ConvenienceStorePickupCountdown { expires_at }.remaining_seconds(now)
}

/// The display serial for a signed-credential identifier URL: its last
/// path component.
#[uniffi::export]
pub fn credential_serial(identifier: String) -> Option<String> {
    convenience_store_pickup::credential_serial(&identifier)
}

/// One `application/x-www-form-urlencoded` field. A small mirror record -
/// see this module's doc comment - since `Vec<(String, String)>` has no
/// UniFFI representation.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFormField {
    pub name: String,
    pub value: String,
}

/// `application/x-www-form-urlencoded` encoding for a token/form POST
/// body - e.g. the OID4VCI token request.
#[uniffi::export]
pub fn form_encode(fields: Vec<FfiFormField>) -> String {
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|f| (f.name.as_str(), f.value.as_str()))
        .collect();
    collection::form_encode(&pairs)
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

    // MARK: - Milestone 2: presenting a credential / convenience-store pickup

    use crate::twdiw::oid4vp_request::{Oid4VpInputDescriptor, Oid4VpRequestedField};

    fn base64url(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn sample_oid4vp_request(client_id: &str) -> Oid4VpRequest {
        Oid4VpRequest {
            response_uri: "https://verifier.example/response".to_string(),
            client_id: client_id.to_string(),
            nonce: "N-1".to_string(),
            state: "S-1".to_string(),
            input_descriptors: vec![Oid4VpInputDescriptor {
                id: "desc-1".to_string(),
                credential_format: None,
                credential_type: Some("twm-card".to_string()),
                requested_fields: vec![Oid4VpRequestedField {
                    path: "$.credentialSubject.name".to_string(),
                }],
                groups: vec![],
                credential_name: None,
                issuer_name: None,
            }],
            submission_requirements: vec![],
            definition_id: "def-1".to_string(),
        }
    }

    #[test]
    fn parse_authorize_link_reads_the_official_scheme() {
        let link = parse_authorize_link(
            "modadigitalwallet://authorize?client_id=did:key:zABC&request_uri=https%3A%2F%2Fverifier.example%2Frequest%2Fx"
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            link,
            Oid4VpAuthorizeLink::ByReference {
                client_id: "did:key:zABC".to_string(),
                request_uri: "https://verifier.example/request/x".to_string(),
            }
        );
    }

    #[test]
    fn verify_oid4vp_request_round_trips_through_the_ffi_split() {
        use p256::ecdsa::signature::Signer;
        let key = SigningKey::random(&mut OsRng);
        let vk: p256::ecdsa::VerifyingKey = *key.verifying_key();
        let x963 = vk.to_encoded_point(false).as_bytes().to_vec();
        let client_id = jwk_did_key::did_from_p256_x963(&x963).unwrap();

        let header = serde_json::json!({"kid": "verifier-did", "typ": "oauth-authz-req+jwt", "alg": "ES256"});
        let payload = serde_json::json!({
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example/response",
            "client_id": client_id,
            "nonce": "N-1",
            "state": "S-1",
            "presentation_definition": {
                "id": "def-1",
                "input_descriptors": [{
                    "id": "desc-1",
                    "constraints": {"fields": [
                        {"path": ["$.type"], "filter": {"type": "array", "contains": {"const": "twm-card"}}},
                        {"path": ["$.credentialSubject.name"]},
                    ]},
                }],
            },
        });
        let h = base64url(&serde_json::to_vec(&header).unwrap());
        let p = base64url(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let signature: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", base64url(&signature.to_bytes()));

        let request =
            verify_oid4vp_request(jwt, client_id, vec!["verifier.example".to_string()]).unwrap();
        assert_eq!(request.nonce, "N-1");
        assert_eq!(request.input_descriptors[0].id, "desc-1");
    }

    #[test]
    fn reserialise_twdiw_credential_keeps_only_chosen_claims() {
        let credential =
            read_twdiw_credential(FIXTURE_CREDENTIAL.to_string(), 1_754_400_000).unwrap();
        let presented = reserialise_twdiw_credential(credential, vec!["name".to_string()]);
        // jwt, exactly one kept disclosure, and the trailing empty segment.
        let segments: Vec<&str> = presented.split('~').collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[2], "");
    }

    #[test]
    fn presentation_submission_for_request_is_valid_json_naming_the_definition() {
        let request = sample_oid4vp_request("did:key:zVerifier");
        let submission = presentation_submission_for_request(request);
        let value: serde_json::Value = serde_json::from_str(&submission).unwrap();
        assert_eq!(value["definition_id"], "def-1");
        assert_eq!(value["descriptor_map"][0]["id"], "desc-1");
    }

    #[test]
    fn presentation_submission_for_descriptor_ids_names_every_descriptor() {
        let request = sample_oid4vp_request("did:key:zVerifier");
        let submission = presentation_submission_for_descriptor_ids(
            request,
            vec!["twm-name".to_string(), "twm-last5".to_string()],
        );
        let value: serde_json::Value = serde_json::from_str(&submission).unwrap();
        let map = value["descriptor_map"].as_array().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[0]["id"], "twm-name");
        assert_eq!(map[1]["id"], "twm-last5");
    }

    #[test]
    fn vp_token_signing_input_and_assemble_round_trip() {
        use p256::ecdsa::signature::Signer;
        let holder_key = SigningKey::random(&mut OsRng);
        let holder_x963 = holder_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let request = sample_oid4vp_request("did:key:zVerifier");

        let input = vp_token_signing_input(
            request,
            vec!["presented-jws".to_string()],
            holder_x963,
            1_754_400_000,
        )
        .unwrap();
        let signature: p256::ecdsa::Signature = holder_key.sign(input.as_bytes());
        let token = assemble_vp_token(input, signature.to_bytes().to_vec()).unwrap();
        assert_eq!(token.split('.').count(), 3);

        assert_eq!(
            assemble_vp_token("x.y".to_string(), vec![0u8; 10]),
            Err(FfiError::Failed("signature must be 64 bytes".to_string()))
        );
    }

    #[test]
    fn current_record_call_data_via_ffi() {
        let call = current_record_call_data("did:key:zA".to_string()).unwrap();
        assert!(call.starts_with("0xfba6fe49"));
        assert_eq!(current_record_call_data("".to_string()), None);
    }

    #[test]
    fn is_infrastructure_error_distinguishes_infra_from_a_revert_and_fails_closed_on_garbage() {
        assert!(is_infrastructure_error(
            r#"{"error":{"code":-32000,"message":"upstream unavailable"}}"#.to_string()
        ));
        assert!(!is_infrastructure_error(
            r#"{"error":{"code":3,"message":"execution reverted"}}"#.to_string()
        ));
        assert!(is_infrastructure_error("not json".to_string()));
    }

    #[test]
    fn check_on_chain_record_reports_a_mismatch_with_no_transaction_data() {
        let issuer = TwdiwIssuer::default();
        let record = TwdiwOnChainRecord::default();
        assert_eq!(
            check_on_chain_record(issuer, record, None, None, None),
            TwdiwOnChainVerification::Mismatch
        );
    }

    const SAMPLE_TELECOM_VC_LIST: &str = r#"{"data":{"vcItems":[
        {"vcUid":"97176270_twmdiwvc_postpaid","name":"台灣大哥大門號電子卡","type":1,"issuerServiceUrl":"https://twm5g.com/8fk2j"}
    ]}}"#;

    #[test]
    fn telecom_cards_from_vc_list_json_via_ffi() {
        let cards =
            telecom_cards_from_vc_list_json(SAMPLE_TELECOM_VC_LIST.as_bytes().to_vec()).unwrap();
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].vc_uid, "97176270_twmdiwvc_postpaid");
    }

    #[test]
    fn parse_dw_modal_201i_response_via_ffi() {
        let body = r#"{"type":1,"name":"台灣大哥大門號電子卡","issuerServiceUrl":"https://twm5g.com/8fk2j"}"#;
        let parsed = parse_dw_modal_201i_response(body.as_bytes().to_vec()).unwrap();
        assert_eq!(parsed.card_type, Some(1));
        assert_eq!(
            parsed.issuer_service_url,
            Some("https://twm5g.com/8fk2j".to_string())
        );
    }

    const SAMPLE_PICKUP_CATALOGUE: &str = r#"{"code":"0","data":{"vpItems":[
        {"vpUid":"22555003_711pickup","name":"統一超商包裹取貨","verifierModuleUrl":"https://22555003.wallet.gov.tw/oid4vp"}
    ]}}"#;

    #[test]
    fn convenience_store_pickup_scenarios_via_ffi() {
        let scenarios =
            convenience_store_pickup_scenarios(SAMPLE_PICKUP_CATALOGUE.as_bytes().to_vec())
                .unwrap();
        assert_eq!(scenarios[0].vp_uid, "22555003_711pickup");
    }

    #[test]
    fn parse_convenience_store_pickup_start_via_ffi() {
        let link =
            "modadigitalwallet://authorize?client_id=did:key:zTest&request_uri=https%3A%2F%2Fx%2Fy";
        let body = serde_json::json!({
            "code": "0",
            "data": {"transactionId": "txn-1", "deepLink": link},
        });
        let start =
            parse_convenience_store_pickup_start(serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(start.transaction_id, "txn-1");
        assert_eq!(start.deep_link, link);
    }

    #[test]
    fn parse_convenience_store_pickup_barcode_and_countdown_via_ffi() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        const ONE_BY_ONE_PNG_BASE64: &str =
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
        let png = STANDARD.decode(ONE_BY_ONE_PNG_BASE64).unwrap();
        let body = serde_json::json!({
            "code": "0",
            "data": {
                "qrcode": format!("data:image/png;base64,{}", STANDARD.encode(&png)),
                "totptimeout": "300",
            },
        });
        let generated_at = 1_800_000_000i64;
        let barcode = parse_convenience_store_pickup_barcode(
            serde_json::to_vec(&body).unwrap(),
            generated_at,
        )
        .unwrap();
        assert_eq!(barcode.image_data, png);
        assert_eq!(barcode.lifetime_seconds, 300.0);

        let expires_at =
            convenience_store_pickup_countdown_expires_at(barcode.lifetime_seconds, generated_at)
                .unwrap();
        assert_eq!(expires_at, generated_at * 1000 + 300_000);
        assert_eq!(
            convenience_store_pickup_countdown_remaining_seconds(expires_at, generated_at),
            300
        );
        assert_eq!(
            convenience_store_pickup_countdown_remaining_seconds(expires_at, generated_at + 301),
            0
        );
    }

    #[test]
    fn credential_serial_via_ffi() {
        assert_eq!(
            credential_serial(
                "https://issuer-vc.wallet.gov.tw/api/credential/39d60715-e90c-402a-98aa-test"
                    .to_string()
            ),
            Some("39d60715-e90c-402a-98aa-test".to_string())
        );
    }

    #[test]
    fn form_encode_via_ffi() {
        let body = form_encode(vec![
            FfiFormField {
                name: "grant_type".to_string(),
                value: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            },
            FfiFormField {
                name: "client_id".to_string(),
                value: "moda_dw".to_string(),
            },
        ]);
        assert!(body.contains("client_id=moda_dw"));
        assert!(body
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"));
    }
}
