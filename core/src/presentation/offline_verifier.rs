//! Checks a `VerifiablePresentation` entirely on this device.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/OfflineVerifier.swift` -
//! see that file for the extensive rationale: what a verified result
//! actually proves (「本人可驗」, not 「資料可驗」), why revocation cannot be
//! checked for a self-issued credential, why replay defence is split
//! between this pure function and a caller-owned pending-challenge store,
//! and the relay `PresentationRequest`/`VerificationCaveat::VerifierNotAuthenticated`
//! document but cannot close.
//!
//! **Scoped to two of the three credential-securing mechanisms.** Swift's
//! `envelopedCredential` dispatches on the envelope's media type to one of
//! three checkers: a device-signed JWS, a card-signed (`MOICASignedCredential`,
//! X.509/自然人憑證) envelope, or a TWDIW SD-JWT. `MOICASignedCredential` is
//! not yet ported (see `presentation::verifiable_presentation`'s module
//! docs for the same boundary on the presenting side), so this reads only
//! the device-signed and TWDIW SD-JWT paths - both fully, including the
//! shared holder-binding/freshness/validity orchestration every path goes
//! through. A card-signed envelope is still *recognised* by its media type
//! (never sniffed from other bytes - that would be the type-confusion bug
//! this file's own Swift test suite is named after), and refused with
//! `VerificationFailure::CredentialUnreadable`. That is not a new failure
//! mode invented for this gap: it is exactly what Swift's own
//! `envelopedCredential` throws when `MOICASignedCredential.parse` fails,
//! which is the only outcome available here since no parser exists yet.
//!
//! **Revocation checking is out of scope**, tracked separately
//! (`RevocationSnapshot.swift`'s SMT-proof machinery, tied to the
//! card-signed path this module does not yet handle). Every verified
//! result in this module reports `RevocationStatus::NotChecked { reason:
//! NoCertificateToCheck }`, which is what Swift itself always produces for
//! a device-signed or SD-JWT credential too - neither carries a
//! certificate serial number to look up. [`caveat_for_revocation_status`]
//! is still implemented in full (all three `RevocationStatus` branches),
//! so the one piece a future card-signed PR needs to add is a serial
//! number and a snapshot lookup, not this function.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use crate::credential::{
    timestamp, verification_method_id, VerifiableCredential, BASE_TYPE as CREDENTIAL_BASE_TYPE,
    CREDENTIALS_V2_CONTEXT,
};
use crate::identity::{did_key, jwk_did_key};
use crate::presentation::request::{PresentationCredentialSource, PresentationRequest};
use crate::presentation::verifiable_presentation::{self as vp, EnvelopedVerifiableCredential};
use crate::twdiw::credential::{self as twdiw_credential, TwdiwCredentialError};
use crate::twdiw::onchain;

// MARK: - What the verifier can say

/// Something true about a verified presentation that a green tick does not
/// say on its own. Every one is attached to a presentation that passed
/// every check - these exist because a bare 「驗證通過」 lets a verifier
/// read guarantees into the result that this design does not provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationCaveat {
    NoNetworkQuery,
    RevocationNotChecked,
    RevocationCheckedInLocalSnapshotOnly,
    RevocationCheckedInStaleSnapshot,
    SelfIssuedByTheHolder,
    AssertedByCardholder,
    GovernmentIssuerMatchedStoredTrust,
    IdentifierIsLinkable,
    GovernmentCardIdentifierIsLinkable,
    VerifierNotAuthenticated,
    NoExpiryAsserted,
    NotBoundToThisVerifier,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum VerificationFailure {
    // Structure
    #[error("presentation is not a JWS")]
    PresentationIsNotAJws,
    #[error("presentation unreadable")]
    PresentationUnreadable,
    #[error("presentation fields disagree: {field}")]
    PresentationFieldsDisagree { field: String },
    #[error("presentation field is not text: {field}")]
    PresentationFieldIsNotText { field: String },
    #[error("presentation is not a presentation (declared type {declared_type:?})")]
    PresentationIsNotAPresentation { declared_type: Option<String> },
    #[error("unsupported signature algorithm (declared {declared:?})")]
    UnsupportedSignatureAlgorithm { declared: Option<String> },

    // Holder
    #[error("holder identifier unusable")]
    HolderIdentifierUnusable,
    #[error("presentation key id mismatch")]
    PresentationKeyIdMismatch,
    #[error("presentation signature invalid")]
    PresentationSignatureInvalid,

    // Credential
    #[error("credential missing")]
    CredentialMissing,
    #[error("presentation carries multiple credentials: {count}")]
    PresentationCarriesMultipleCredentials { count: usize },
    #[error("credential not enveloped")]
    CredentialNotEnveloped,
    #[error("credential is not a JWS")]
    CredentialIsNotAJws,
    #[error("credential is not a credential (declared type {declared_type:?})")]
    CredentialIsNotACredential { declared_type: Option<String> },
    #[error("issuer identifier unusable")]
    IssuerIdentifierUnusable,
    #[error("credential key id mismatch")]
    CredentialKeyIdMismatch,
    #[error("credential signature invalid")]
    CredentialSignatureInvalid,
    #[error("credential unreadable")]
    CredentialUnreadable,
    #[error("credential not bound to presenter")]
    CredentialNotBoundToPresenter,
    #[error("credential issuer is not the subject")]
    CredentialIssuerIsNotTheSubject,
    #[error("credential source mismatch")]
    CredentialSourceMismatch,
    #[error("issuer not in offline trust store")]
    IssuerNotInOfflineTrustStore,

    // Freshness
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("purpose mismatch")]
    PurposeMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("presentation timestamp unreadable")]
    PresentationTimestampUnreadable,
    #[error("presentation too old: {age}s")]
    PresentationTooOld { age: f64 },
    #[error("presentation dated in the future: {skew}s")]
    PresentationDatedInTheFuture { skew: f64 },

    // Validity
    #[error("credential validity unreadable")]
    CredentialValidityUnreadable,
    #[error("credential not yet valid")]
    CredentialNotYetValid,
    #[error("credential expired")]
    CredentialExpired,

    // Card-signed credentials - not yet reachable; see module docs.
    #[error("card signature invalid")]
    CardSignatureInvalid,
    #[error("cardholder is not the subject")]
    CardholderIsNotTheSubject,
    #[error("cardholder certificate unusable")]
    CardholderCertificateUnusable,
    #[error("cardholder certificate revoked")]
    CardholderCertificateRevoked,
    #[error("trust anchor unavailable")]
    TrustAnchorUnavailable,
    #[error("device clock precedes certificate valid-from {valid_from}")]
    DeviceClockPrecedesCertificate { valid_from: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedClaim {
    pub term: String,
    pub value: String,
}

/// Everything a verifier learned, including what they did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPresentation {
    pub holder: String,
    /// The name on the certificate that signed the credential's fields, or
    /// `None` for a device-signed or TWDIW credential - always `None`
    /// here, since neither path this module reads carries one.
    pub cardholder_name: Option<String>,
    pub cardholder_name_was_checked: bool,
    pub withheld_claim_count: i64,
    pub credential_types: Vec<String>,
    /// Ordered for reading, not in claim-serialization order.
    pub claims: Vec<DisclosedClaim>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub presented_at: DateTime<Utc>,
    pub caveats: Vec<VerificationCaveat>,
    pub revocation: RevocationStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerificationOutcome {
    Verified(VerifiedPresentation),
    Rejected(VerificationFailure),
}

impl VerificationOutcome {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }

    pub fn verified(&self) -> Option<&VerifiedPresentation> {
        match self {
            Self::Verified(v) => Some(v),
            Self::Rejected(_) => None,
        }
    }

    pub fn failure(&self) -> Option<&VerificationFailure> {
        match self {
            Self::Verified(_) => None,
            Self::Rejected(f) => Some(f),
        }
    }
}

// MARK: - Revocation (shape only - see module docs)

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    Revoked { snapshot: RevocationSnapshotInfo },
    NotRevokedInThisSnapshot { snapshot: RevocationSnapshotInfo },
    NotChecked { reason: NotCheckedReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCheckedReason {
    SnapshotUnavailable,
    SnapshotUnusable,
    ProofDidNotVerify,
    NoCertificateToCheck,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationSnapshotInfo {
    pub root: String,
    /// `YYYYMMDDHH`.
    pub crl_number: i64,
    pub entry_count: i64,
}

impl RevocationSnapshotInfo {
    /// `crl_number` read as a moment in Taipei local time (UTC+8, no DST),
    /// or `None` if it is not in the documented `YYYYMMDDHH` shape or
    /// names a calendar date/hour that does not exist.
    pub fn generated_at(&self) -> Option<DateTime<Utc>> {
        let text = self.crl_number.to_string();
        if text.len() != 10 {
            return None;
        }
        let year: i32 = text[0..4].parse().ok()?;
        let month: u32 = text[4..6].parse().ok()?;
        let day: u32 = text[6..8].parse().ok()?;
        let hour: u32 = text[8..10].parse().ok()?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 {
            return None;
        }
        let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, 0, 0)?;
        // Taipei is a fixed UTC+8 offset year-round.
        Some(DateTime::from_naive_utc_and_offset(
            naive - chrono::Duration::hours(8),
            Utc,
        ))
    }
}

pub const MAXIMUM_SNAPSHOT_FRESHNESS_SECONDS: i64 = 72 * 60 * 60;

/// Turns a revocation result into the one caveat the screen may say about
/// it - or refuses the presentation outright.
pub fn caveat_for_revocation_status(
    status: &RevocationStatus,
    now: DateTime<Utc>,
) -> Result<VerificationCaveat, VerificationFailure> {
    match status {
        RevocationStatus::NotRevokedInThisSnapshot { snapshot } => match snapshot.generated_at() {
            Some(generated_at)
                if (now - generated_at).num_seconds() <= MAXIMUM_SNAPSHOT_FRESHNESS_SECONDS =>
            {
                Ok(VerificationCaveat::RevocationCheckedInLocalSnapshotOnly)
            }
            _ => Ok(VerificationCaveat::RevocationCheckedInStaleSnapshot),
        },
        RevocationStatus::NotChecked { .. } => Ok(VerificationCaveat::RevocationNotChecked),
        // Never demoted by age: an old list can miss a revocation that
        // came after it, but it cannot invent one that never happened.
        RevocationStatus::Revoked { .. } => Err(VerificationFailure::CardholderCertificateRevoked),
    }
}

// MARK: - Offline issuer trust (data shape only - the file-backed store stays native)

/// The minimum evidence an offline verifier needs to decide that a TWDIW
/// issuer was accepted previously by both independent trust channels.
/// Reading/writing this snapshot to disk stays native
/// (`docs/2026-09-05-decisions-and-roadmap.md`); this module only compares
/// one already-looked-up snapshot against a credential's issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineIssuerTrustSnapshot {
    pub issuer_did: String,
    pub display_name: String,
    pub tax_id: String,
    pub api_updated_at: Option<i64>,
    pub verified_at: i64,
    pub network: String,
    pub contract_address: String,
    pub block_number: String,
    pub transaction_hash: String,
}

// MARK: - The verifier

pub const MAXIMUM_PRESENTATION_AGE_SECONDS: f64 = 5.0 * 60.0;
pub const MAXIMUM_CLOCK_SKEW_SECONDS: f64 = 2.0 * 60.0;

const PRESENTATION_MEDIA_TYPE: &str = "vp+jwt";
const CREDENTIAL_MEDIA_TYPE: &str = "vc+jwt";

/// Checks `presentation_jws` against the request this verifier issued.
///
/// Never fails loudly: every way this can go wrong is a
/// [`VerificationFailure`] inside the returned outcome.
///
/// `issuer_trust`: the offline trust snapshot for the TWDIW credential's
/// issuer, if this device's (native-owned) store has one - looked up by
/// the caller before calling this function, since file storage stays
/// native. Irrelevant for a device-signed presentation.
///
/// Replay protection is only half this function's job: it compares the
/// presented challenge against `request` and remembers nothing, so the
/// *same* presentation verifies every time it is checked. Consuming each
/// challenge exactly once - on failure as well as success - belongs to
/// the caller that owns the pending-challenge store.
pub fn verify(
    presentation_jws: &str,
    request: &PresentationRequest,
    now: DateTime<Utc>,
    issuer_trust: Option<&OfflineIssuerTrustSnapshot>,
) -> VerificationOutcome {
    match check(presentation_jws, request, now, issuer_trust) {
        Ok(verified) => VerificationOutcome::Verified(verified),
        Err(failure) => VerificationOutcome::Rejected(failure),
    }
}

/// The order is load-bearing: signatures are checked before anything is
/// believed about the contents, holder binding comes next, and only then
/// do freshness and validity run - see the Swift source for the full
/// rationale.
fn check(
    presentation_jws: &str,
    request: &PresentationRequest,
    now: DateTime<Utc>,
    issuer_trust: Option<&OfflineIssuerTrustSnapshot>,
) -> Result<VerifiedPresentation, VerificationFailure> {
    // 1. Structure, and the domain separation that stops a stored
    //    credential passing as a live presentation.
    let presentation = CompactJws::parse(
        presentation_jws,
        VerificationFailure::PresentationIsNotAJws,
        VerificationFailure::PresentationUnreadable,
    )?;
    let declared_type = presentation.header.get("typ").and_then(Value::as_str);
    if declared_type != Some(PRESENTATION_MEDIA_TYPE) {
        return Err(VerificationFailure::PresentationIsNotAPresentation {
            declared_type: declared_type.map(str::to_owned),
        });
    }
    let body_types = type_list(presentation.payload.get("type"));
    if !body_types.iter().any(|t| t == vp::BASE_TYPE) {
        return Err(VerificationFailure::PresentationIsNotAPresentation {
            declared_type: body_types.first().cloned(),
        });
    }
    require_es256(&presentation)?;

    // 2. The holder's key comes from the signed body, never from `kid`.
    let holder = presentation
        .payload
        .get("holder")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(VerificationFailure::PresentationUnreadable)?
        .to_string();
    let holder_key =
        resolve_public_key(&holder).ok_or(VerificationFailure::HolderIdentifierUnusable)?;
    require_key_id(
        &presentation.header,
        &holder,
        VerificationFailure::PresentationKeyIdMismatch,
    )?;
    require_signature(
        &presentation,
        &holder_key,
        VerificationFailure::PresentationSignatureInvalid,
    )?;

    // 3. The credential, checked under whichever mechanism secured it,
    //    over the bytes that arrived. Which mechanism is decided by the
    //    envelope's media type, never by looking at the bytes.
    let credential = match enveloped_credential(&presentation.payload)? {
        RawEnvelopedCredential::DeviceSigned(jws) => {
            if request.credential_source != PresentationCredentialSource::SelfIssued {
                return Err(VerificationFailure::CredentialSourceMismatch);
            }
            check_device_signed(&jws)?
        }
        RawEnvelopedCredential::GovernmentSdJwt(serialized) => {
            if request.credential_source != PresentationCredentialSource::Twdiw {
                return Err(VerificationFailure::CredentialSourceMismatch);
            }
            check_government_sd_jwt(&serialized, now, issuer_trust)?
        }
    };
    let issuer = credential.issuer.clone();

    // 4. Holder binding.
    let subject = credential
        .payload
        .get("credentialSubject")
        .and_then(Value::as_object)
        .and_then(|o| o.get("id"))
        .and_then(Value::as_str)
        .ok_or(VerificationFailure::CredentialUnreadable)?;
    if subject != holder {
        return Err(VerificationFailure::CredentialNotBoundToPresenter);
    }
    if credential.issuer_trust_snapshot.is_none() && issuer != subject {
        return Err(VerificationFailure::CredentialIssuerIsNotTheSubject);
    }

    // 5. Freshness.
    if signed_field("challenge", &presentation)?.as_deref() != Some(request.challenge.as_str()) {
        throw_challenge_mismatch()?;
    }
    if signed_field("purpose", &presentation)?.as_deref() != Some(request.purpose.as_str()) {
        return Err(VerificationFailure::PurposeMismatch);
    }

    let presented_audience = signed_field("audience", &presentation)?;
    let mut audience_is_bound = false;
    if let Some(expected) = &request.audience {
        if presented_audience.as_deref() != Some(expected.as_str()) {
            return Err(VerificationFailure::AudienceMismatch);
        }
        audience_is_bound = true;
    }

    let created_text = signed_field("created", &presentation)?
        .ok_or(VerificationFailure::PresentationTimestampUnreadable)?;
    let presented_at =
        parse_date(&created_text).ok_or(VerificationFailure::PresentationTimestampUnreadable)?;
    let age = (now - presented_at).num_milliseconds() as f64 / 1000.0;
    if age > MAXIMUM_PRESENTATION_AGE_SECONDS {
        return Err(VerificationFailure::PresentationTooOld { age });
    }
    if -age > MAXIMUM_CLOCK_SKEW_SECONDS {
        return Err(VerificationFailure::PresentationDatedInTheFuture { skew: -age });
    }

    // 6. Only now decode for display.
    let decoded: VerifiableCredential = serde_json::from_slice(&credential.payload_data)
        .map_err(|_| VerificationFailure::CredentialUnreadable)?;

    let valid_from =
        parse_date(&decoded.valid_from).ok_or(VerificationFailure::CredentialValidityUnreadable)?;
    if (valid_from - now).num_milliseconds() as f64 / 1000.0 > MAXIMUM_CLOCK_SKEW_SECONDS {
        return Err(VerificationFailure::CredentialNotYetValid);
    }

    let mut valid_until: Option<DateTime<Utc>> = None;
    if let Some(text) = text_field(
        &credential.payload,
        "validUntil",
        VerificationFailure::CredentialValidityUnreadable,
    )? {
        let parsed = parse_date(&text).ok_or(VerificationFailure::CredentialValidityUnreadable)?;
        if (now - parsed).num_milliseconds() as f64 / 1000.0 > MAXIMUM_CLOCK_SKEW_SECONDS {
            return Err(VerificationFailure::CredentialExpired);
        }
        valid_until = Some(parsed);
    }

    // Revocation runs only once signature, holder binding and validity
    // have all passed. Neither path this module reads carries a
    // certificate serial number to look up - see module docs.
    let revocation_status = RevocationStatus::NotChecked {
        reason: NotCheckedReason::NoCertificateToCheck,
    };
    let revocation_caveat = caveat_for_revocation_status(&revocation_status, now)?;

    let mut caveats = vec![VerificationCaveat::NoNetworkQuery, revocation_caveat];
    if credential.issuer_trust_snapshot.is_some() {
        caveats.push(VerificationCaveat::GovernmentIssuerMatchedStoredTrust);
        caveats.push(VerificationCaveat::GovernmentCardIdentifierIsLinkable);
    } else {
        caveats.push(if credential.cardholder_name.is_none() {
            VerificationCaveat::SelfIssuedByTheHolder
        } else {
            VerificationCaveat::AssertedByCardholder
        });
        caveats.push(VerificationCaveat::IdentifierIsLinkable);
    }
    caveats.push(VerificationCaveat::VerifierNotAuthenticated);
    if valid_until.is_none() {
        caveats.push(VerificationCaveat::NoExpiryAsserted);
    }
    if !audience_is_bound {
        caveats.push(VerificationCaveat::NotBoundToThisVerifier);
    }

    let disclosed_subject = if credential.cardholder_name.is_none() {
        decoded.credential_subject.clone()
    } else {
        credential.claims.clone()
    };

    Ok(VerifiedPresentation {
        holder,
        cardholder_name: credential.cardholder_name,
        cardholder_name_was_checked: credential.cardholder_name_was_checked,
        withheld_claim_count: credential.withheld_claim_count,
        credential_types: decoded.types,
        claims: disclosed_claims(&disclosed_subject),
        valid_from,
        valid_until,
        presented_at,
        caveats,
        revocation: revocation_status,
    })
}

/// A `?`-friendly spelling for a plain `return Err(...)` inside `check`,
/// used once at the challenge check so that line reads the same shape as
/// every other guard in this function.
fn throw_challenge_mismatch() -> Result<(), VerificationFailure> {
    Err(VerificationFailure::ChallengeMismatch)
}

// MARK: - Steps

fn require_es256(jws: &CompactJws) -> Result<(), VerificationFailure> {
    let declared = jws.header.get("alg").and_then(Value::as_str);
    if declared != Some("ES256") {
        return Err(VerificationFailure::UnsupportedSignatureAlgorithm {
            declared: declared.map(str::to_owned),
        });
    }
    Ok(())
}

fn resolve_public_key(did: &str) -> Option<p256::PublicKey> {
    did_key::p256_public_key_from_did(did)
        .ok()
        .or_else(|| jwk_did_key::p256_public_key_from_did(did).ok())
}

/// An absent `kid` is allowed; a *wrong* one is refused.
fn require_key_id(
    header: &serde_json::Map<String, Value>,
    did: &str,
    when_mismatched: VerificationFailure,
) -> Result<(), VerificationFailure> {
    let Some(key_id) = text_field(header, "kid", when_mismatched.clone())? else {
        return Ok(());
    };
    let expected = verification_method_id(did).ok();
    if expected.as_deref() != Some(key_id.as_str()) {
        return Err(when_mismatched);
    }
    Ok(())
}

fn require_signature(
    jws: &CompactJws,
    key: &p256::PublicKey,
    when_invalid: VerificationFailure,
) -> Result<(), VerificationFailure> {
    use p256::ecdsa::signature::Verifier;
    if jws.signature.len() != 64 {
        return Err(when_invalid);
    }
    let signature =
        p256::ecdsa::Signature::from_slice(&jws.signature).map_err(|_| when_invalid.clone())?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(key);
    verifying_key
        .verify(&jws.signing_input, &signature)
        .map_err(|_| when_invalid)
}

enum RawEnvelopedCredential {
    DeviceSigned(String),
    GovernmentSdJwt(String),
}

/// Pulls the credential out of the presentation without re-encoding it.
/// Decided from the envelope's media type and nowhere else - sniffing the
/// bytes would let a document be steered into whichever verifier is
/// weaker for it.
fn enveloped_credential(
    payload: &serde_json::Map<String, Value>,
) -> Result<RawEnvelopedCredential, VerificationFailure> {
    let entries: Vec<Value> = match payload.get("verifiableCredential") {
        Some(Value::Array(array)) => array.clone(),
        Some(single) => vec![single.clone()],
        None => return Err(VerificationFailure::CredentialMissing),
    };
    let first = entries
        .first()
        .cloned()
        .ok_or(VerificationFailure::CredentialMissing)?;
    if entries.len() != 1 {
        return Err(
            VerificationFailure::PresentationCarriesMultipleCredentials {
                count: entries.len(),
            },
        );
    }
    let envelope = first
        .as_object()
        .ok_or(VerificationFailure::CredentialNotEnveloped)?;
    let types = type_list(envelope.get("type"));
    let identifier = envelope.get("id").and_then(Value::as_str);
    if !types
        .iter()
        .any(|t| t == EnvelopedVerifiableCredential::TYPE_NAME)
        || identifier.is_none()
    {
        return Err(VerificationFailure::CredentialNotEnveloped);
    }
    let identifier = identifier.unwrap();

    if let Some(jws) = identifier.strip_prefix(EnvelopedVerifiableCredential::COMPACT_JWS_PREFIX) {
        return Ok(RawEnvelopedCredential::DeviceSigned(jws.to_string()));
    }
    if identifier.starts_with(EnvelopedVerifiableCredential::MOICA_SIGNED_PREFIX) {
        // Recognised, not parsed - see this module's docs. Swift itself
        // throws exactly this failure when MOICASignedCredential.parse
        // fails, which is the only outcome available with no parser at
        // all.
        return Err(VerificationFailure::CredentialUnreadable);
    }
    if let Some(serialized) = identifier.strip_prefix(EnvelopedVerifiableCredential::SD_JWT_PREFIX)
    {
        if serialized.is_empty() {
            return Err(VerificationFailure::CredentialUnreadable);
        }
        return Ok(RawEnvelopedCredential::GovernmentSdJwt(
            serialized.to_string(),
        ));
    }
    // An envelope carrying a media type this build does not know - a ZK
    // proof, one day - is refused here rather than fed to the wrong
    // parser.
    Err(VerificationFailure::CredentialNotEnveloped)
}

/// What a credential turned out to be, once its own signature was
/// checked. Both branches produce this so everything downstream - holder
/// binding, validity windows, display - is written once.
struct CheckedCredential {
    payload: serde_json::Map<String, Value>,
    payload_data: Vec<u8>,
    issuer: String,
    cardholder_name: Option<String>,
    claims: BTreeMap<String, String>,
    withheld_claim_count: i64,
    cardholder_name_was_checked: bool,
    issuer_trust_snapshot: Option<OfflineIssuerTrustSnapshot>,
}

/// The device-signed path: a credential secured by the device's own ES256
/// key.
fn check_device_signed(jws: &str) -> Result<CheckedCredential, VerificationFailure> {
    let credential = CompactJws::parse(
        jws,
        VerificationFailure::CredentialIsNotAJws,
        VerificationFailure::CredentialUnreadable,
    )?;
    let credential_type = credential.header.get("typ").and_then(Value::as_str);
    if credential_type != Some(CREDENTIAL_MEDIA_TYPE) {
        return Err(VerificationFailure::CredentialIsNotACredential {
            declared_type: credential_type.map(str::to_owned),
        });
    }
    require_es256(&credential)?;

    let issuer = credential
        .payload
        .get("issuer")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(VerificationFailure::CredentialUnreadable)?
        .to_string();
    let issuer_key =
        resolve_public_key(&issuer).ok_or(VerificationFailure::IssuerIdentifierUnusable)?;
    require_key_id(
        &credential.header,
        &issuer,
        VerificationFailure::CredentialKeyIdMismatch,
    )?;
    require_signature(
        &credential,
        &issuer_key,
        VerificationFailure::CredentialSignatureInvalid,
    )?;

    Ok(CheckedCredential {
        payload: credential.payload,
        payload_data: credential.payload_data,
        issuer,
        cardholder_name: None,
        claims: BTreeMap::new(),
        withheld_claim_count: 0,
        cardholder_name_was_checked: false,
        issuer_trust_snapshot: None,
    })
}

/// The government-wallet SD-JWT path. `twdiw::credential::read` verifies
/// the issuer's ES256 signature, each disclosure commitment and
/// `cnf.jwk`; the outer presentation signature is checked separately
/// above, and the shared subject/holder equality in `check` binds the two
/// layers together.
fn check_government_sd_jwt(
    serialized: &str,
    now: DateTime<Utc>,
    issuer_trust: Option<&OfflineIssuerTrustSnapshot>,
) -> Result<CheckedCredential, VerificationFailure> {
    let credential =
        twdiw_credential::read(serialized, now.timestamp()).map_err(|error| match error {
            TwdiwCredentialError::UnresolvableIssuer
            | TwdiwCredentialError::SignatureInvalid
            | TwdiwCredentialError::UndisclosedDigest(_) => {
                VerificationFailure::CredentialSignatureInvalid
            }
            _ => VerificationFailure::CredentialUnreadable,
        })?;

    let snapshot = issuer_trust.ok_or(VerificationFailure::IssuerNotInOfflineTrustStore)?;
    if snapshot.issuer_did != credential.issuer_did
        || snapshot.network != onchain::NETWORK
        || snapshot.contract_address.to_lowercase() != onchain::REGISTRY_CONTRACT
    {
        return Err(VerificationFailure::IssuerNotInOfflineTrustStore);
    }

    let mut subject = serde_json::Map::new();
    subject.insert(
        "id".to_string(),
        Value::String(credential.subject_did.clone()),
    );
    for (name, value) in &credential.disclosed_claims {
        subject.insert(name.clone(), Value::String(value.clone()));
    }

    let not_before = Utc
        .timestamp_opt(credential.not_before, 0)
        .single()
        .ok_or(VerificationFailure::CredentialUnreadable)?;

    let mut payload_value = serde_json::json!({
        "@context": [CREDENTIALS_V2_CONTEXT],
        "type": [CREDENTIAL_BASE_TYPE, credential.credential_type],
        "issuer": credential.issuer_did,
        "validFrom": timestamp(not_before),
        "credentialSubject": Value::Object(subject),
    });
    if credential.expires != i64::MAX {
        let expires = Utc
            .timestamp_opt(credential.expires, 0)
            .single()
            .ok_or(VerificationFailure::CredentialUnreadable)?;
        payload_value["validUntil"] = Value::String(timestamp(expires));
    }
    let payload_object = payload_value
        .as_object()
        .cloned()
        .ok_or(VerificationFailure::CredentialUnreadable)?;
    let payload_data = serde_json::to_vec(&payload_value)
        .map_err(|_| VerificationFailure::CredentialUnreadable)?;

    let disclosed: BTreeMap<String, String> = credential.disclosed_claims.iter().cloned().collect();
    let withheld =
        (credential.commitments.len() as i64 - credential.disclosed_claims.len() as i64).max(0);

    Ok(CheckedCredential {
        payload: payload_object,
        payload_data,
        issuer: credential.issuer_did,
        cardholder_name: None,
        claims: disclosed,
        withheld_claim_count: withheld,
        cardholder_name_was_checked: false,
        issuer_trust_snapshot: Some(snapshot.clone()),
    })
}

/// Reads a field from the body, falling back to the protected header.
/// Both are covered by the signature, so this is tolerance for where a
/// presenter put a value, not a trust decision. Disagreement between the
/// two is refused rather than resolved.
fn signed_field(name: &str, jws: &CompactJws) -> Result<Option<String>, VerificationFailure> {
    let not_text = VerificationFailure::PresentationFieldIsNotText {
        field: name.to_string(),
    };
    let from_body = text_field(&jws.payload, name, not_text.clone())?;
    let from_header = text_field(&jws.header, name, not_text)?;
    if let (Some(body), Some(header)) = (&from_body, &from_header) {
        if body != header {
            return Err(VerificationFailure::PresentationFieldsDisagree {
                field: name.to_string(),
            });
        }
    }
    Ok(from_body.or(from_header))
}

/// Reads a JSON member that can only be text, distinguishing *absent*
/// from *present and not text* (including `null`) - see the Swift source
/// for why the distinction matters.
fn text_field(
    object: &serde_json::Map<String, Value>,
    name: &str,
    when_not_text: VerificationFailure,
) -> Result<Option<String>, VerificationFailure> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(when_not_text),
    }
}

// MARK: - Display

const CLAIM_DISPLAY_ORDER: [&str; 5] = [
    "name",
    "birthdate",
    "unifiedNo",
    "addressOfHousehold",
    "nationality",
];

/// The order a person reads an ID card in, not the order the credential
/// serializes in.
fn disclosed_claims(subject: &BTreeMap<String, String>) -> Vec<DisclosedClaim> {
    let mut remaining = subject.clone();
    // The holder's DID, already reported as `holder`.
    remaining.remove("id");

    let mut claims: Vec<DisclosedClaim> = CLAIM_DISPLAY_ORDER
        .iter()
        .filter_map(|term| {
            remaining.remove(*term).map(|value| DisclosedClaim {
                term: term.to_string(),
                value,
            })
        })
        .collect();
    // `remaining` is a BTreeMap, so this is already sorted by key.
    claims.extend(
        remaining
            .into_iter()
            .map(|(term, value)| DisclosedClaim { term, value }),
    );
    claims
}

// MARK: - Primitives

/// JSON-LD allows a single string wherever a list of types is expected.
fn type_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(single)) => vec![single.clone()],
        Some(Value::Array(many)) => many
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

/// XSD 1.1 `dateTimeStamp`, the format `credential::timestamp` writes.
/// Fractional seconds and any RFC 3339 offset are accepted, although this
/// crate only ever emits whole-second UTC.
fn parse_date(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

// MARK: - Compact JWS

/// A parsed compact JWS that keeps the bytes which were actually signed.
/// Header and payload stay as raw JSON rather than becoming modelled
/// types: this is a document from another device, and the verifier has
/// to be able to say "the signature is fine but I do not understand the
/// contents" instead of failing to parse and reporting something that
/// sounds like an accusation.
struct CompactJws {
    header: serde_json::Map<String, Value>,
    payload: serde_json::Map<String, Value>,
    /// The undecoded body, for a typed decode once the signature has been
    /// checked.
    payload_data: Vec<u8>,
    /// `BASE64URL(header) || "." || BASE64URL(payload)`, exactly as
    /// received - never rebuilt by re-encoding the decoded JSON.
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

impl CompactJws {
    fn parse(
        serialization: &str,
        structure_failure: VerificationFailure,
        content_failure: VerificationFailure,
    ) -> Result<Self, VerificationFailure> {
        let trimmed = serialization.trim();
        let segments: Vec<&str> = trimmed.split('.').collect();
        let [header_segment, payload_segment, signature_segment] = segments.as_slice() else {
            return Err(structure_failure);
        };
        let header_data =
            base64url_decode_strict(header_segment).ok_or_else(|| structure_failure.clone())?;
        let payload_data =
            base64url_decode_strict(payload_segment).ok_or_else(|| structure_failure.clone())?;
        let signature =
            base64url_decode_strict(signature_segment).ok_or_else(|| structure_failure.clone())?;

        let header: Value =
            serde_json::from_slice(&header_data).map_err(|_| content_failure.clone())?;
        let payload: Value =
            serde_json::from_slice(&payload_data).map_err(|_| content_failure.clone())?;
        let header = header
            .as_object()
            .cloned()
            .ok_or_else(|| content_failure.clone())?;
        let payload = payload.as_object().cloned().ok_or(content_failure)?;

        let signing_input = format!("{header_segment}.{payload_segment}").into_bytes();
        Ok(Self {
            header,
            payload,
            payload_data,
            signing_input,
            signature,
        })
    }
}

/// base64url, unpadded, strict: `+`, `/` and `=` cannot appear in a
/// compact JWS, and a decoder that takes them anyway carries a mangled
/// serialization far enough to fail later as "signature invalid" - the
/// least informative refusal available.
fn base64url_decode_strict(segment: &str) -> Option<Vec<u8>> {
    if segment.is_empty() || segment.contains(['+', '/', '=']) {
        return None;
    }
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(segment).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{assemble_jws, jws_signing_input, national_id, NationalIdModel};
    use crate::presentation::verifiable_presentation::{
        assemble_presentation_jws, presentation_signing_input,
    };
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;

    fn issued_at() -> DateTime<Utc> {
        Utc.timestamp_opt(1_754_400_000, 0).unwrap()
    }

    fn presented_at() -> DateTime<Utc> {
        issued_at() + chrono::Duration::hours(1)
    }

    fn full_model() -> NationalIdModel {
        NationalIdModel {
            nationality: Some("中華民國（臺灣）".into()),
            unified_no: Some("A123456789".into()),
            name: Some("王小明".into()),
            birthdate: Some("0700101".into()),
            address_of_household: Some("臺北市中正區重慶南路一段122號".into()),
        }
    }

    fn x963(key: &SigningKey) -> Vec<u8> {
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn sign_raw(key: &SigningKey, message: &[u8]) -> [u8; 64] {
        let signature: Signature = key.sign(message);
        let bytes = signature.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        out
    }

    fn base64url(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(bytes)
    }

    struct DeviceFixture {
        key: SigningKey,
        did: String,
        request: PresentationRequest,
    }

    fn device_fixture() -> DeviceFixture {
        let key = SigningKey::random(&mut OsRng);
        let did = did_key::did_from_p256_x963(&x963(&key)).unwrap();
        let request = PresentationRequest::new(
            "Q0hBTExFTkdFLTAwMDAwMA",
            "里長辦公室核對受災戶身分",
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        DeviceFixture { key, did, request }
    }

    fn device_credential_jws(fixture: &DeviceFixture) -> String {
        let credential = national_id(&full_model(), &fixture.did, issued_at());
        let signing_input = jws_signing_input(&credential, &fixture.did).unwrap();
        let signature = sign_raw(&fixture.key, signing_input.as_bytes());
        assemble_jws(&signing_input, &signature)
    }

    fn device_presentation(fixture: &DeviceFixture, request: &PresentationRequest) -> String {
        let credential_jws = device_credential_jws(fixture);
        let enveloped = EnvelopedVerifiableCredential::enveloping_compact_jws(&credential_jws);
        let input = presentation_signing_input(
            enveloped,
            request,
            &fixture.did,
            &x963(&fixture.key),
            presented_at(),
        )
        .unwrap();
        let signature = sign_raw(&fixture.key, input.as_bytes());
        assemble_presentation_jws(&input, &signature)
    }

    #[test]
    fn verifies_a_presentation_made_for_this_request() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let outcome = verify(&jws, &fixture.request, presented_at(), None);
        let verified = outcome.verified().expect("verified");
        assert_eq!(verified.holder, fixture.did);
        assert_eq!(
            verified.credential_types,
            vec!["VerifiableCredential", "NationalIDCredential"]
        );
        assert_eq!(verified.presented_at, presented_at());
        assert_eq!(verified.valid_from, issued_at());
        assert_eq!(verified.valid_until, None);
    }

    #[test]
    fn disclosed_claims_omit_the_did_and_are_ordered_for_reading() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let verified = verify(&jws, &fixture.request, presented_at(), None)
            .verified()
            .cloned()
            .unwrap();
        assert_eq!(
            verified
                .claims
                .iter()
                .map(|c| c.term.clone())
                .collect::<Vec<_>>(),
            vec![
                "name",
                "birthdate",
                "unifiedNo",
                "addressOfHousehold",
                "nationality"
            ]
        );
        assert!(!verified.claims.iter().any(|c| c.term == "id"));
        assert!(!verified.claims.iter().any(|c| c.value == fixture.did));
    }

    #[test]
    fn a_verified_result_says_revocation_was_not_checked() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let verified = verify(&jws, &fixture.request, presented_at(), None)
            .verified()
            .cloned()
            .unwrap();
        assert!(verified
            .caveats
            .contains(&VerificationCaveat::RevocationNotChecked));
        assert_eq!(
            verified.revocation,
            RevocationStatus::NotChecked {
                reason: NotCheckedReason::NoCertificateToCheck
            }
        );
    }

    #[test]
    fn a_verified_result_says_the_checker_could_not_be_authenticated() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let verified = verify(&jws, &fixture.request, presented_at(), None)
            .verified()
            .cloned()
            .unwrap();
        assert!(verified
            .caveats
            .contains(&VerificationCaveat::VerifierNotAuthenticated));
        assert!(verified
            .caveats
            .contains(&VerificationCaveat::SelfIssuedByTheHolder));
        assert!(verified
            .caveats
            .contains(&VerificationCaveat::IdentifierIsLinkable));
        assert!(verified
            .caveats
            .contains(&VerificationCaveat::NoExpiryAsserted));
    }

    #[test]
    fn an_unbound_presentation_is_flagged_and_a_bound_one_is_not() {
        let key = SigningKey::random(&mut OsRng);
        let did = did_key::did_from_p256_x963(&x963(&key)).unwrap();
        let fixture = DeviceFixture {
            key,
            did,
            request: PresentationRequest::new(
                "Q0hBTExFTkdFLTAwMDAwMA",
                "查驗",
                issued_at().timestamp(),
                Some("urn:bonds-tw:verifier:test"),
                None,
                PresentationCredentialSource::SelfIssued,
            )
            .unwrap(),
        };
        let jws = device_presentation(&fixture, &fixture.request);
        let verified = verify(&jws, &fixture.request, presented_at(), None)
            .verified()
            .cloned()
            .unwrap();
        assert!(!verified
            .caveats
            .contains(&VerificationCaveat::NotBoundToThisVerifier));

        let unbound_request = PresentationRequest::new(
            "Q0hBTExFTkdFLTAwMDAwMA",
            "查驗",
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let unbound_jws = device_presentation(&fixture, &unbound_request);
        let unbound_verified = verify(&unbound_jws, &unbound_request, presented_at(), None)
            .verified()
            .cloned()
            .unwrap();
        assert!(unbound_verified
            .caveats
            .contains(&VerificationCaveat::NotBoundToThisVerifier));
    }

    /// The defect this exists for: a presentation photographed at one
    /// counter and shown at the next one.
    #[test]
    fn rejects_a_presentation_answering_another_challenge() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let somebody_elses_request = PresentationRequest::new(
            "QU5PVEhFUi1DSEFMTEVOR0U",
            "里長辦公室核對受災戶身分",
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let outcome = verify(&jws, &somebody_elses_request, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::ChallengeMismatch)
        );
    }

    /// `verify` is pure: it remembers nothing, so the same presentation
    /// verifies as often as it is shown. Consuming a challenge belongs to
    /// the caller's pending-challenge store.
    #[test]
    fn verifying_twice_does_not_consume_the_challenge() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let first = verify(&jws, &fixture.request, presented_at(), None);
        let second = verify(&jws, &fixture.request, presented_at(), None);
        assert!(first.is_verified());
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_a_presentation_made_for_another_verifier() {
        let fixture = device_fixture();
        let request = PresentationRequest::new(
            "Q0hBTExFTkdFLTAwMDAwMA",
            "查驗",
            issued_at().timestamp(),
            Some("urn:bonds-tw:verifier:9f3a1c"),
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let jws = device_presentation(&fixture, &request);
        let other_request = PresentationRequest::new(
            "Q0hBTExFTkdFLTAwMDAwMA",
            "查驗",
            issued_at().timestamp(),
            Some("urn:bonds-tw:verifier:somebody-else"),
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let outcome = verify(&jws, &other_request, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::AudienceMismatch)
        );
    }

    #[test]
    fn rejects_a_reply_whose_holder_was_told_a_different_reason() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let different_purpose = PresentationRequest::new(
            &fixture.request.challenge,
            "免費發放物資登記",
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let outcome = verify(&jws, &different_purpose, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::PurposeMismatch)
        );
    }

    /// A credential file copied off somebody else's phone, presented with
    /// a signature from the thief's own key.
    #[test]
    fn rejects_a_credential_about_someone_other_than_the_presenter() {
        let holder = device_fixture();
        let victim = device_fixture();
        let credential = national_id(&full_model(), &victim.did, issued_at());
        let signing_input = jws_signing_input(&credential, &victim.did).unwrap();
        let signature = sign_raw(&victim.key, signing_input.as_bytes());
        let stolen_credential_jws = assemble_jws(&signing_input, &signature);

        let enveloped =
            EnvelopedVerifiableCredential::enveloping_compact_jws(&stolen_credential_jws);
        let input = presentation_signing_input(
            enveloped,
            &holder.request,
            &holder.did,
            &x963(&holder.key),
            presented_at(),
        )
        .unwrap();
        let signature = sign_raw(&holder.key, input.as_bytes());
        let jws = assemble_presentation_jws(&input, &signature);

        let outcome = verify(&jws, &holder.request, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::CredentialNotBoundToPresenter)
        );
    }

    /// Subject and presenter agree, but a third party signed the
    /// credential. There is no trust list here to evaluate that issuer
    /// against.
    #[test]
    fn rejects_a_credential_issued_by_a_third_party() {
        let holder = device_fixture();
        let authority = device_fixture();
        let credential = national_id(&full_model(), &authority.did, issued_at());
        let mut credential = credential;
        credential
            .credential_subject
            .insert("id".to_string(), holder.did.clone());
        let signing_input = jws_signing_input(&credential, &authority.did).unwrap();
        let signature = sign_raw(&authority.key, signing_input.as_bytes());
        let credential_jws = assemble_jws(&signing_input, &signature);

        let enveloped = EnvelopedVerifiableCredential::enveloping_compact_jws(&credential_jws);
        let input = presentation_signing_input(
            enveloped,
            &holder.request,
            &holder.did,
            &x963(&holder.key),
            presented_at(),
        )
        .unwrap();
        let signature = sign_raw(&holder.key, input.as_bytes());
        let jws = assemble_presentation_jws(&input, &signature);

        let outcome = verify(&jws, &holder.request, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::CredentialIssuerIsNotTheSubject)
        );
    }

    #[test]
    fn rejects_a_presentation_signed_by_another_key() {
        let fixture = device_fixture();
        let forger = SigningKey::random(&mut OsRng);
        let credential_jws = device_credential_jws(&fixture);
        let enveloped = EnvelopedVerifiableCredential::enveloping_compact_jws(&credential_jws);
        let input = presentation_signing_input(
            enveloped,
            &fixture.request,
            &fixture.did,
            &x963(&fixture.key),
            presented_at(),
        )
        .unwrap();
        let signature = sign_raw(&forger, input.as_bytes());
        let jws = assemble_presentation_jws(&input, &signature);

        let outcome = verify(&jws, &fixture.request, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::PresentationSignatureInvalid)
        );
    }

    #[test]
    fn rejects_a_presentation_older_than_the_window() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let late =
            presented_at() + chrono::Duration::seconds(MAXIMUM_PRESENTATION_AGE_SECONDS as i64 + 1);
        let outcome = verify(&jws, &fixture.request, late, None);
        assert!(matches!(
            outcome.failure(),
            Some(VerificationFailure::PresentationTooOld { .. })
        ));
    }

    #[test]
    fn accepts_a_presentation_at_the_edge_of_the_window() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let late =
            presented_at() + chrono::Duration::seconds(MAXIMUM_PRESENTATION_AGE_SECONDS as i64);
        assert!(verify(&jws, &fixture.request, late, None).is_verified());
    }

    #[test]
    fn rejects_a_presentation_dated_beyond_the_clock_skew() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let early =
            presented_at() - chrono::Duration::seconds(MAXIMUM_CLOCK_SKEW_SECONDS as i64 + 1);
        let outcome = verify(&jws, &fixture.request, early, None);
        assert!(matches!(
            outcome.failure(),
            Some(VerificationFailure::PresentationDatedInTheFuture { .. })
        ));
    }

    #[test]
    fn tolerates_a_small_clock_difference() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let early = presented_at() - chrono::Duration::seconds(MAXIMUM_CLOCK_SKEW_SECONDS as i64);
        assert!(verify(&jws, &fixture.request, early, None).is_verified());
    }

    #[test]
    fn rejects_algorithms_other_than_es256() {
        let fixture = device_fixture();
        let jws = device_presentation(&fixture, &fixture.request);
        let segments: Vec<&str> = jws.split('.').collect();
        let header: serde_json::Value =
            serde_json::from_slice(&base64url_decode_strict(segments[0]).unwrap()).unwrap();
        let mut header = header;
        header["alg"] = serde_json::json!("HS256");
        let header_bytes = serde_json::to_vec(&header).unwrap();
        let tampered = format!(
            "{}.{}.{}",
            base64url(&header_bytes),
            segments[1],
            segments[2]
        );
        let outcome = verify(&tampered, &fixture.request, presented_at(), None);
        assert!(matches!(
            outcome.failure(),
            Some(VerificationFailure::UnsupportedSignatureAlgorithm { .. })
        ));
    }

    #[test]
    fn rejects_malformed_input_without_crashing() {
        let fixture = device_fixture();
        for input in [
            "",
            ".",
            "..",
            "...",
            "a.b",
            "a.b.c.d",
            "e30.e30.e30",
            "eyJhbGciOiJFUzI1NiJ9.e30",
        ] {
            let outcome = verify(input, &fixture.request, presented_at(), None);
            assert!(!outcome.is_verified());
            assert!(outcome.failure().is_some());
        }
    }

    // MARK: - Government SD-JWT path

    struct SdJwtFixture {
        serialized: String,
        holder_key: SigningKey,
        holder_did: String,
        issuer_trust: OfflineIssuerTrustSnapshot,
        request: PresentationRequest,
    }

    fn sd_jwt_fixture() -> SdJwtFixture {
        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_did = jwk_did_key::did_from_p256_x963(&x963(&issuer_key)).unwrap();

        let holder_key = SigningKey::random(&mut OsRng);
        let holder_x963 = x963(&holder_key);
        let holder_did = did_key::did_from_p256_x963(&holder_x963).unwrap();
        let (x, y) = holder_x963[1..].split_at(32);
        let cnf_jwk: serde_json::Value =
            serde_json::from_slice(&jwk_did_key::canonical_jwk(x, y)).unwrap();

        let header = serde_json::json!({"alg": "ES256", "typ": "vc+sd-jwt"});
        let payload = serde_json::json!({
            "iss": issuer_did,
            "sub": holder_did,
            "cnf": {"jwk": cnf_jwk},
            "vc": {
                "type": ["VerifiableCredential", "TestCard"],
                "credentialSubject": {},
            },
        });
        let header_b64 = base64url(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64url(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = sign_raw(&issuer_key, signing_input.as_bytes());
        let serialized = format!("{signing_input}.{}~", base64url(&signature));

        let issuer_trust = OfflineIssuerTrustSnapshot {
            issuer_did: issuer_did.clone(),
            display_name: "測試單位".to_string(),
            tax_id: "12345678".to_string(),
            api_updated_at: None,
            verified_at: issued_at().timestamp(),
            network: onchain::NETWORK.to_string(),
            contract_address: onchain::REGISTRY_CONTRACT.to_string(),
            block_number: "0x1".to_string(),
            transaction_hash: "0xabc".to_string(),
        };
        let request = PresentationRequest::new(
            "Q0hBTExFTkdFLTAwMDAwMA",
            "核對政府卡",
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::Twdiw,
        )
        .unwrap();

        SdJwtFixture {
            serialized,
            holder_key,
            holder_did,
            issuer_trust,
            request,
        }
    }

    fn sd_jwt_presentation(fixture: &SdJwtFixture) -> String {
        let enveloped = EnvelopedVerifiableCredential::enveloping_sd_jwt(&fixture.serialized);
        let input = presentation_signing_input(
            enveloped,
            &fixture.request,
            &fixture.holder_did,
            &x963(&fixture.holder_key),
            presented_at(),
        )
        .unwrap();
        let signature = sign_raw(&fixture.holder_key, input.as_bytes());
        assemble_presentation_jws(&input, &signature)
    }

    #[test]
    fn verifies_a_government_sd_jwt_presentation_matched_against_stored_trust() {
        let fixture = sd_jwt_fixture();
        let jws = sd_jwt_presentation(&fixture);
        let outcome = verify(
            &jws,
            &fixture.request,
            presented_at(),
            Some(&fixture.issuer_trust),
        );
        let verified = outcome.verified().expect("verified");
        assert_eq!(verified.holder, fixture.holder_did);
        assert!(verified
            .caveats
            .contains(&VerificationCaveat::GovernmentIssuerMatchedStoredTrust));
        assert!(verified
            .caveats
            .contains(&VerificationCaveat::GovernmentCardIdentifierIsLinkable));
        assert!(!verified
            .caveats
            .contains(&VerificationCaveat::SelfIssuedByTheHolder));
        assert!(!verified
            .caveats
            .contains(&VerificationCaveat::IdentifierIsLinkable));
    }

    #[test]
    fn a_government_sd_jwt_credential_with_no_stored_trust_is_refused() {
        let fixture = sd_jwt_fixture();
        let jws = sd_jwt_presentation(&fixture);
        let outcome = verify(&jws, &fixture.request, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::IssuerNotInOfflineTrustStore)
        );
    }

    #[test]
    fn the_request_naming_one_credential_source_refuses_the_other() {
        let fixture = sd_jwt_fixture();
        let jws = sd_jwt_presentation(&fixture);
        let self_issued_request = PresentationRequest::new(
            &fixture.request.challenge,
            &fixture.request.purpose,
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let outcome = verify(
            &jws,
            &self_issued_request,
            presented_at(),
            Some(&fixture.issuer_trust),
        );
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::CredentialSourceMismatch)
        );

        let device_fixture = device_fixture();
        let device_jws = device_presentation(&device_fixture, &device_fixture.request);
        let twdiw_request = PresentationRequest::new(
            &device_fixture.request.challenge,
            &device_fixture.request.purpose,
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::Twdiw,
        )
        .unwrap();
        let outcome = verify(&device_jws, &twdiw_request, presented_at(), None);
        assert_eq!(
            outcome.failure(),
            Some(&VerificationFailure::CredentialSourceMismatch)
        );
    }

    // MARK: - Revocation caveat

    #[test]
    fn a_snapshot_within_the_freshness_window_is_a_local_snapshot_caveat() {
        let snapshot = RevocationSnapshotInfo {
            root: "0xabc".to_string(),
            crl_number: crl_number_for(presented_at() - chrono::Duration::hours(1)),
            entry_count: 1,
        };
        let status = RevocationStatus::NotRevokedInThisSnapshot { snapshot };
        assert_eq!(
            caveat_for_revocation_status(&status, presented_at()),
            Ok(VerificationCaveat::RevocationCheckedInLocalSnapshotOnly)
        );
    }

    #[test]
    fn a_snapshot_past_the_freshness_window_is_a_stale_caveat() {
        let snapshot = RevocationSnapshotInfo {
            root: "0xabc".to_string(),
            crl_number: crl_number_for(
                presented_at()
                    - chrono::Duration::seconds(MAXIMUM_SNAPSHOT_FRESHNESS_SECONDS + 3600),
            ),
            entry_count: 1,
        };
        let status = RevocationStatus::NotRevokedInThisSnapshot { snapshot };
        assert_eq!(
            caveat_for_revocation_status(&status, presented_at()),
            Ok(VerificationCaveat::RevocationCheckedInStaleSnapshot)
        );
    }

    #[test]
    fn a_revoked_status_is_a_rejection_not_a_caveat() {
        let snapshot = RevocationSnapshotInfo {
            root: "0xabc".to_string(),
            crl_number: crl_number_for(presented_at()),
            entry_count: 1,
        };
        let status = RevocationStatus::Revoked { snapshot };
        assert_eq!(
            caveat_for_revocation_status(&status, presented_at()),
            Err(VerificationFailure::CardholderCertificateRevoked)
        );
    }

    fn crl_number_for(at: DateTime<Utc>) -> i64 {
        let taipei = at + chrono::Duration::hours(8);
        format!(
            "{:04}{:02}{:02}{:02}",
            taipei.format("%Y"),
            taipei.format("%m"),
            taipei.format("%d"),
            taipei.format("%H")
        )
        .parse()
        .unwrap()
    }
}
