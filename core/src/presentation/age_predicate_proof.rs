//! Verifier-first, field-level zero-knowledge proof protocol: the request
//! a verifier hands over, and the package a holder answers with.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/{AgePredicateProof,
//! AgePredicatePrepareCache}.swift`. This is a **different** subsystem
//! from `credential::age_predicate` (a plain, non-ZK disclosed claim) and
//! from the older MOICA cert-chain proof (`ZKProver`/`ZKProofPackage` on
//! iOS, untouched here) — this one proves a hidden birthdate is on or
//! before a cutoff without disclosing it, via the Mopro/OpenAC "Prepare +
//! Show" circuit pair.
//!
//! **What's here and what isn't.** Prepare, Show, reblind and verify are
//! native Mopro FFI calls this crate never makes — see this crate's
//! architecture boundary (network/native-crypto stays native). What's
//! here is the pure data/decision layer around that call: building and
//! validating the request a verifier sends, assembling and validating the
//! package a holder answers with, and deriving the cache key a native
//! prepare-cache should use for the reusable half of the proof. This
//! mirrors the `jws_signing_input`/`assemble_jws` split already used for
//! native signing elsewhere in this crate — core says what's needed and
//! assembles the result; native does the crypto in between.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use rand::RngCore;

use crate::credential::age_predicate;
use crate::presentation::offline_verifier::MAXIMUM_PRESENTATION_AGE_SECONDS;
use crate::presentation::request::{
    base64_url_encode, is_valid_uuid, uuid_v4_string, PresentationCredentialSource,
    MAXIMUM_PURPOSE_LENGTH,
};
use crate::trust::untrusted_text::UntrustedText;

pub const CURRENT_VERSION: i64 = 1;
/// 32 bytes, base64url — wider than `PresentationRequest`'s 16-byte
/// challenge because this nonce is also a public input to the Show
/// circuit, not just a replay guard.
pub const NONCE_BYTE_COUNT: usize = 32;
/// A request older than this (or claiming to be from the future by more
/// than the small clock-skew allowance below) is refused rather than
/// answered — the same lifetime `OfflineVerifier` uses, since both are
/// "how long is one holder interaction allowed to take" limits.
pub const REQUEST_LIFETIME_SECONDS: i64 = MAXIMUM_PRESENTATION_AGE_SECONDS as i64;
/// A request timestamped more than this far in the future is refused
/// outright, rather than accepted as "a little fast" — a verifier cannot
/// mint a request far ahead of now and thereby extend its own window.
const FUTURE_CLOCK_SKEW_SECONDS: i64 = 60;

pub const MAXIMUM_ARTIFACT_BYTES: usize = 2_000_000;
pub const MAXIMUM_PREPARE_CACHE_ENTRIES: usize = 8;
const MAXIMUM_CLAIM_NAME_BYTES: usize = 31;
const MAXIMUM_ISSUER_DID_BYTES: usize = 300;
const MAXIMUM_RESPONSE_URL_BYTES: usize = 512;

/// Birthdate-bearing claim names this app knows how to prove over — the
/// same field spelled differently across issuers (a driving licence's
/// `roc_birthday` vs. a self-issued card's `birthdate`, etc.). Anything
/// else is refused: a verifier statement about an unrecognised field name
/// is not provable, not "provable but untested."
pub const SUPPORTED_BIRTH_CLAIM_NAMES: &[&str] = &[
    "roc_birthday",
    "birthdate",
    "birthday",
    "date_of_birth",
    "birth_date",
    "出生日期",
];

/// Websites this app will post an age proof to, beyond the two-device
/// (BLE) flow. Allow-listed rather than open: a stranger's scanned
/// request must not be able to route a proof anywhere it likes. The
/// package itself carries no claim value — only proofs and public
/// metadata — so the host list exists to bound *where bytes go*, not to
/// protect a secret inside them.
pub fn trusted_response_hosts() -> &'static [&'static str] {
    if cfg!(debug_assertions) {
        &[
            "verifier.mashbean.net",
            "mashbean-vp-verifier.mashbean.workers.dev",
        ]
    } else {
        &["verifier.mashbean.net"]
    }
}

/// HTTPS, an allow-listed host, and nothing that would let a URL smuggle
/// credentials or change where the bytes go.
pub fn is_trusted_response_url(candidate: &str) -> bool {
    if candidate.len() > MAXIMUM_RESPONSE_URL_BYTES {
        return false;
    }
    let Ok(parsed) = url::Url::parse(candidate) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed
            .host_str()
            .is_some_and(|host| trusted_response_hosts().contains(&host))
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum AgePredicateProofError {
    #[error("randomness unavailable")]
    RandomnessUnavailable,
    #[error("malformed request")]
    MalformedRequest,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(i64),
    #[error("stale request")]
    StaleRequest,
    #[error("purpose invalid")]
    PurposeInvalid,
    #[error("source mismatch")]
    SourceMismatch,
    #[error("statement mismatch")]
    StatementMismatch,
    #[error("malformed package")]
    MalformedPackage,
    #[error("untrusted response host")]
    UntrustedResponseHost,
}

use AgePredicateProofError as Error;

/// A verifier-generated request. Unlike the older MOICA holding-proof
/// flow, the nonce exists before proving and is checked as a public
/// circuit input, rather than being bound after the fact.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AgePredicateProofRequest {
    /// A fresh one-time BLE service identifier for the two-device flow.
    pub service_id: String,
    /// base64url of [`NONCE_BYTE_COUNT`] random bytes.
    pub nonce: String,
    pub purpose: String,
    pub credential_source: PresentationCredentialSource,
    /// Gregorian civil date, `YYYY-MM-DD`. The proof establishes the
    /// hidden birth date is at or before this value.
    pub cutoff_date: String,
    pub minimum_age: i32,
    /// Unix seconds, truncated.
    pub created_at: i64,
    /// Where a *web* checker wants the proof posted. `None` for the
    /// two-device flow, where the proof travels over the BLE service
    /// named by `service_id` instead.
    pub response_url: Option<String>,
}

impl AgePredicateProofRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        purpose: &str,
        credential_source: PresentationCredentialSource,
        minimum_age: i32,
        response_url: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Self, Error> {
        let clean = UntrustedText::new(purpose, MAXIMUM_PURPOSE_LENGTH);
        if clean.text.is_empty() || clean.was_truncated || clean.contained_control_characters {
            return Err(Error::PurposeInvalid);
        }

        if !(1..=120).contains(&minimum_age) {
            return Err(Error::MalformedRequest);
        }
        let cutoff = age_predicate::cutoff_date(minimum_age, now).ok_or(Error::MalformedRequest)?;

        if let Some(url) = response_url {
            if !is_trusted_response_url(url) {
                return Err(Error::UntrustedResponseHost);
            }
        }

        let mut nonce_bytes = [0u8; NONCE_BYTE_COUNT];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| Error::RandomnessUnavailable)?;
        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id_bytes)
            .map_err(|_| Error::RandomnessUnavailable)?;

        Ok(Self {
            service_id: uuid_v4_string(id_bytes),
            nonce: base64_url_encode(&nonce_bytes),
            purpose: clean.text,
            credential_source,
            cutoff_date: date_string(cutoff),
            minimum_age,
            created_at: now.timestamp(),
            response_url: response_url.map(str::to_string),
        })
    }

    /// The exact text to transmit: compact, deterministic, printable JSON
    /// with sorted keys, matching iOS's `CodingKeys` letter-for-letter.
    pub fn encoded_for_transport(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("v".to_string(), serde_json::json!(CURRENT_VERSION));
        map.insert("b".to_string(), serde_json::json!(self.service_id));
        map.insert("c".to_string(), serde_json::json!(self.nonce));
        map.insert("p".to_string(), serde_json::json!(self.purpose));
        map.insert(
            "s".to_string(),
            serde_json::json!(self.credential_source.wire_code()),
        );
        map.insert("d".to_string(), serde_json::json!(self.cutoff_date));
        map.insert("a".to_string(), serde_json::json!(self.minimum_age));
        map.insert("t".to_string(), serde_json::json!(self.created_at));
        if let Some(url) = &self.response_url {
            map.insert("u".to_string(), serde_json::json!(url));
        }
        serde_json::Value::Object(map).to_string()
    }

    /// Reads what a scanner or web relay handed back, running it through
    /// the same validation a request built on-device would go through.
    pub fn decode(text: &str, now: DateTime<Utc>) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| Error::MalformedRequest)?;
        let object = value.as_object().ok_or(Error::MalformedRequest)?;

        let version = object
            .get("v")
            .and_then(|v| v.as_i64())
            .ok_or(Error::MalformedRequest)?;
        if version != CURRENT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let service_id = object
            .get("b")
            .and_then(|v| v.as_str())
            .filter(|s| is_valid_uuid(s))
            .ok_or(Error::MalformedRequest)?
            .to_string();
        let nonce = object
            .get("c")
            .and_then(|v| v.as_str())
            .ok_or(Error::MalformedRequest)?;
        if base64_url_decode(nonce).map(|b| b.len()) != Some(NONCE_BYTE_COUNT) {
            return Err(Error::MalformedRequest);
        }
        let purpose = object
            .get("p")
            .and_then(|v| v.as_str())
            .ok_or(Error::MalformedRequest)?;
        let credential_source = object
            .get("s")
            .and_then(|v| v.as_str())
            .and_then(PresentationCredentialSource::from_wire_code)
            .ok_or(Error::MalformedRequest)?;
        let cutoff_date = object
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or(Error::MalformedRequest)?;
        if cutoff_components(cutoff_date).is_none() {
            return Err(Error::MalformedRequest);
        }
        let minimum_age = object
            .get("a")
            .and_then(|v| v.as_i64())
            .filter(|a| (1..=120).contains(a))
            .ok_or(Error::MalformedRequest)? as i32;
        let created_at = object
            .get("t")
            .and_then(|v| v.as_i64())
            .ok_or(Error::MalformedRequest)?;
        let response_url = match object.get("u") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => {
                let text = v.as_str().ok_or(Error::MalformedRequest)?;
                if !is_trusted_response_url(text) {
                    return Err(Error::UntrustedResponseHost);
                }
                Some(text.to_string())
            }
        };

        // Permit a small amount of clock skew, but never let a verifier
        // mint a request far in the future and thereby extend the
        // one-time window.
        let age = now.timestamp() - created_at;
        if !(-FUTURE_CLOCK_SKEW_SECONDS..=REQUEST_LIFETIME_SECONDS).contains(&age) {
            return Err(Error::StaleRequest);
        }

        let clean = UntrustedText::new(purpose, MAXIMUM_PURPOSE_LENGTH);
        if clean.text != purpose
            || clean.text.is_empty()
            || clean.was_truncated
            || clean.contained_control_characters
        {
            return Err(Error::PurposeInvalid);
        }

        Ok(Self {
            service_id,
            nonce: nonce.to_string(),
            purpose: purpose.to_string(),
            credential_source,
            cutoff_date: cutoff_date.to_string(),
            minimum_age,
            created_at,
            response_url,
        })
    }

    /// The circuit literal for `claim_format`'s declared normalization:
    /// `2` is a plain Gregorian `YYYYMMDD`, `3` is the same but ROC-year.
    pub fn cutoff_value(&self, claim_format: u8) -> Result<u64, Error> {
        let (year, month, day) =
            cutoff_components(&self.cutoff_date).ok_or(Error::MalformedRequest)?;
        match claim_format {
            2 => Ok((year * 10_000 + month as i32 * 100 + day as i32) as u64),
            3 => {
                let roc_year = year - age_predicate::RocDate::GREGORIAN_OFFSET;
                if roc_year <= 0 {
                    return Err(Error::MalformedRequest);
                }
                Ok((roc_year * 10_000 + month as i32 * 100 + day as i32) as u64)
            }
            _ => Err(Error::StatementMismatch),
        }
    }
}

/// Only proof objects and verifier-checkable public metadata travel: no
/// SD-JWT, disclosure, birth date, witness or proving key ever leaves the
/// holder. `prepare_proof`/`show_proof` are opaque to this crate — it
/// assembles and bounds-checks them, never inspects their contents.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AgePredicateProofPackage {
    pub version: i64,
    pub request_nonce: String,
    pub credential_source: PresentationCredentialSource,
    pub claim_name: String,
    pub claim_format: u8,
    pub cutoff_date: String,
    pub minimum_age: i32,
    pub issuer_did: String,
    pub prepare_proof: Vec<u8>,
    pub show_proof: Vec<u8>,
    pub prepare_milliseconds: u64,
    pub show_milliseconds: u64,
    /// Unix milliseconds.
    pub created_at: i64,
}

impl AgePredicateProofPackage {
    /// The only constructor, and it validates against `request` before
    /// returning — an invalid package cannot exist in memory, matching
    /// `PresentationRequest::new`'s discipline.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &AgePredicateProofRequest,
        claim_name: &str,
        claim_format: u8,
        issuer_did: &str,
        prepare_proof: Vec<u8>,
        show_proof: Vec<u8>,
        prepare_milliseconds: u64,
        show_milliseconds: u64,
        created_at_millis: i64,
    ) -> Result<Self, Error> {
        let package = Self {
            version: CURRENT_VERSION,
            request_nonce: request.nonce.clone(),
            credential_source: request.credential_source,
            claim_name: claim_name.to_string(),
            claim_format,
            cutoff_date: request.cutoff_date.clone(),
            minimum_age: request.minimum_age,
            issuer_did: issuer_did.to_string(),
            prepare_proof,
            show_proof,
            prepare_milliseconds,
            show_milliseconds,
            created_at: created_at_millis,
        };
        package.validate(request)?;
        Ok(package)
    }

    /// Checked by a holder against its own request before sending, and by
    /// a verifier against the request it issued before trusting the
    /// package answers *that* request and not some other statement.
    pub fn validate(&self, request: &AgePredicateProofRequest) -> Result<(), Error> {
        if self.version != CURRENT_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        if self.request_nonce != request.nonce
            || self.credential_source != request.credential_source
        {
            return Err(Error::SourceMismatch);
        }
        if self.cutoff_date != request.cutoff_date
            || self.minimum_age != request.minimum_age
            || !matches!(self.claim_format, 2 | 3)
            || !SUPPORTED_BIRTH_CLAIM_NAMES.contains(&self.claim_name.as_str())
            || self.claim_name.len() > MAXIMUM_CLAIM_NAME_BYTES
            || !self.issuer_did.starts_with("did:key:")
            || self.issuer_did.len() > MAXIMUM_ISSUER_DID_BYTES
        {
            return Err(Error::StatementMismatch);
        }
        if self.prepare_proof.is_empty()
            || self.show_proof.is_empty()
            || self.prepare_proof.len() > MAXIMUM_ARTIFACT_BYTES
            || self.show_proof.len() > MAXIMUM_ARTIFACT_BYTES
        {
            return Err(Error::MalformedPackage);
        }
        request.cutoff_value(self.claim_format)?;
        Ok(())
    }

    pub fn encoded(&self) -> Vec<u8> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut map = serde_json::Map::new();
        map.insert("version".to_string(), serde_json::json!(self.version));
        map.insert(
            "requestNonce".to_string(),
            serde_json::json!(self.request_nonce),
        );
        map.insert(
            "credentialSource".to_string(),
            serde_json::json!(self.credential_source.wire_code()),
        );
        map.insert("claimName".to_string(), serde_json::json!(self.claim_name));
        map.insert(
            "claimFormat".to_string(),
            serde_json::json!(self.claim_format),
        );
        map.insert(
            "cutoffDate".to_string(),
            serde_json::json!(self.cutoff_date),
        );
        map.insert(
            "minimumAge".to_string(),
            serde_json::json!(self.minimum_age),
        );
        map.insert("issuerDID".to_string(), serde_json::json!(self.issuer_did));
        map.insert(
            "prepareProof".to_string(),
            serde_json::json!(STANDARD.encode(&self.prepare_proof)),
        );
        map.insert(
            "showProof".to_string(),
            serde_json::json!(STANDARD.encode(&self.show_proof)),
        );
        map.insert(
            "prepareMilliseconds".to_string(),
            serde_json::json!(self.prepare_milliseconds),
        );
        map.insert(
            "showMilliseconds".to_string(),
            serde_json::json!(self.show_milliseconds),
        );
        map.insert("createdAt".to_string(), serde_json::json!(self.created_at));
        serde_json::Value::Object(map).to_string().into_bytes()
    }

    pub fn decoded(bytes: &[u8]) -> Result<Self, Error> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| Error::MalformedPackage)?;
        let object = value.as_object().ok_or(Error::MalformedPackage)?;

        let get_str = |key: &str| -> Result<&str, Error> {
            object
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or(Error::MalformedPackage)
        };
        let get_i64 = |key: &str| -> Result<i64, Error> {
            object
                .get(key)
                .and_then(|v| v.as_i64())
                .ok_or(Error::MalformedPackage)
        };
        let get_u64 = |key: &str| -> Result<u64, Error> {
            object
                .get(key)
                .and_then(|v| v.as_u64())
                .ok_or(Error::MalformedPackage)
        };

        let credential_source =
            PresentationCredentialSource::from_wire_code(get_str("credentialSource")?)
                .ok_or(Error::MalformedPackage)?;
        let claim_format = get_u64("claimFormat")?;
        let claim_format: u8 = claim_format
            .try_into()
            .map_err(|_| Error::MalformedPackage)?;
        let prepare_proof = STANDARD
            .decode(get_str("prepareProof")?)
            .map_err(|_| Error::MalformedPackage)?;
        let show_proof = STANDARD
            .decode(get_str("showProof")?)
            .map_err(|_| Error::MalformedPackage)?;

        Ok(Self {
            version: get_i64("version")?,
            request_nonce: get_str("requestNonce")?.to_string(),
            credential_source,
            claim_name: get_str("claimName")?.to_string(),
            claim_format,
            cutoff_date: get_str("cutoffDate")?.to_string(),
            minimum_age: get_i64("minimumAge")? as i32,
            issuer_did: get_str("issuerDID")?.to_string(),
            prepare_proof,
            show_proof,
            prepare_milliseconds: get_u64("prepareMilliseconds")?,
            show_milliseconds: get_u64("showMilliseconds")?,
            created_at: get_i64("createdAt")?,
        })
    }
}

/// A stable, non-reversible key for the credential a prepared state
/// belongs to. Stable is the point: a self-issued card's proved SD-JWT is
/// re-minted with a fresh timestamp on every call, so the key is taken
/// from the *stored* credential and its source, not the ephemeral
/// derivative — otherwise the cache would never hit. Hashed so the
/// directory name a native cache uses carries no credential content.
pub fn prepare_cache_key(source: PresentationCredentialSource, stored_credential: &str) -> String {
    use sha2::{Digest, Sha256};
    let material = format!("{}:{}", source.wire_code(), stored_credential);
    Sha256::digest(material.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Which cache keys a native prepare-cache should evict to stay within
/// [`MAXIMUM_PREPARE_CACHE_ENTRIES`], oldest-last-used first — matching
/// iOS's `evictBeyondLimit`. `entries`: `(key, last_used_at)` pairs;
/// native storage supplies both, since only it knows access/modification
/// times. A card or two, not a history: a wallet that has held many cards
/// should not accumulate birth-date-bearing witnesses for cards it no
/// longer has.
pub fn prepare_cache_keys_to_evict(entries: &[(String, i64)]) -> Vec<String> {
    if entries.len() <= MAXIMUM_PREPARE_CACHE_ENTRIES {
        return Vec::new();
    }
    let mut by_age: Vec<&(String, i64)> = entries.iter().collect();
    by_age.sort_by_key(|(_, last_used_at)| *last_used_at);
    by_age[..entries.len() - MAXIMUM_PREPARE_CACHE_ENTRIES]
        .iter()
        .map(|(key, _)| key.clone())
        .collect()
}

fn date_string(date: NaiveDate) -> String {
    format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day())
}

/// Strict: rejects anything Calendar-style normalization would silently
/// repair (`2008-02-31`), by parsing and then requiring the components to
/// round-trip exactly. A verifier must never have its printed cutoff and
/// numeric circuit input name different days.
fn cutoff_components(value: &str) -> Option<(i32, u32, u32)> {
    let fields: Vec<&str> = value.split('-').collect();
    if fields.len() != 3 || fields[0].len() != 4 || fields[1].len() != 2 || fields[2].len() != 2 {
        return None;
    }
    let year: i32 = fields[0].parse().ok()?;
    let month: u32 = fields[1].parse().ok()?;
    let day: u32 = fields[2].parse().ok()?;
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    if (date.year(), date.month(), date.day()) != (year, month, day) {
        return None;
    }
    Some((year, month, day))
}

fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        // 2026-09-01 12:00 Taipei.
        Utc.with_ymd_and_hms(2026, 9, 1, 4, 0, 0).unwrap()
    }

    use chrono::TimeZone;

    fn sample_request(source: PresentationCredentialSource) -> AgePredicateProofRequest {
        AgePredicateProofRequest::new(
            "超商確認已滿 18 歲",
            source,
            age_predicate::MAJORITY,
            None,
            now(),
        )
        .unwrap()
    }

    // MARK: - AgePredicateProofRequest

    #[test]
    fn request_round_trips_with_verifier_nonce_and_birthday_cutoff() {
        let request = sample_request(PresentationCredentialSource::Twdiw);
        let decoded = AgePredicateProofRequest::decode(
            &request.encoded_for_transport(),
            now() + chrono::Duration::seconds(30),
        )
        .unwrap();

        assert_eq!(decoded, request);
        assert_eq!(decoded.cutoff_date, "2008-09-01");
        assert_eq!(decoded.cutoff_value(2).unwrap(), 20_080_901);
        assert_eq!(decoded.cutoff_value(3).unwrap(), 970_901);
        assert_eq!(base64_url_decode(&decoded.nonce).unwrap().len(), 32);
    }

    #[test]
    fn expired_request_is_refused() {
        let request = sample_request(PresentationCredentialSource::SelfIssued);
        let checked_at = now() + chrono::Duration::seconds(REQUEST_LIFETIME_SECONDS + 1);
        assert_eq!(
            AgePredicateProofRequest::decode(&request.encoded_for_transport(), checked_at),
            Err(Error::StaleRequest)
        );
    }

    #[test]
    fn request_created_far_in_the_future_is_refused() {
        let request = sample_request(PresentationCredentialSource::Twdiw);
        let checked_at = now() - chrono::Duration::seconds(61);
        assert_eq!(
            AgePredicateProofRequest::decode(&request.encoded_for_transport(), checked_at),
            Err(Error::StaleRequest)
        );
    }

    #[test]
    fn impossible_printed_cutoff_is_refused_rather_than_normalised() {
        let request = sample_request(PresentationCredentialSource::SelfIssued);
        let mut value: serde_json::Value =
            serde_json::from_str(&request.encoded_for_transport()).unwrap();
        value["d"] = serde_json::json!("2008-02-31");
        assert_eq!(
            AgePredicateProofRequest::decode(&value.to_string(), now()),
            Err(Error::MalformedRequest)
        );
    }

    #[test]
    fn web_request_carries_its_response_url_and_round_trips() {
        let url =
            "https://verifier.mashbean.net/api/zkp/response/8d6b0c2e-1f0a-4f2f-9c0f-2b5c4a1d9e77";
        let request = AgePredicateProofRequest::new(
            "網頁零知識證明測試",
            PresentationCredentialSource::Twdiw,
            age_predicate::MAJORITY,
            Some(url),
            now(),
        )
        .unwrap();
        let wire = request.encoded_for_transport();
        assert!(wire.contains("\"u\":\"https://verifier.mashbean.net/api/zkp/response/"));
        let decoded =
            AgePredicateProofRequest::decode(&wire, now() + chrono::Duration::seconds(5)).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.response_url.as_deref(), Some(url));
    }

    #[test]
    fn two_device_requests_still_have_no_response_url() {
        let request = sample_request(PresentationCredentialSource::SelfIssued);
        assert_eq!(request.response_url, None);
        assert!(!request.encoded_for_transport().contains("\"u\":"));
    }

    #[test]
    fn response_urls_outside_the_allow_list_are_refused() {
        for text in [
            "http://verifier.mashbean.net/api/zkp/response/abc",
            "https://evil.example/api/zkp/response/abc",
            "https://verifier.mashbean.net.evil.example/x",
            "https://user:secret@verifier.mashbean.net/api/zkp/response/abc",
            "https://verifier.mashbean.net/api/zkp/response/abc#fragment",
        ] {
            assert_eq!(
                AgePredicateProofRequest::new(
                    "確認年齡",
                    PresentationCredentialSource::Twdiw,
                    age_predicate::MAJORITY,
                    Some(text),
                    now(),
                ),
                Err(Error::UntrustedResponseHost),
                "{text}"
            );

            // And on the way in: a scanned code cannot route the proof
            // elsewhere either.
            let honest = sample_request(PresentationCredentialSource::Twdiw);
            let mut value: serde_json::Value =
                serde_json::from_str(&honest.encoded_for_transport()).unwrap();
            value["u"] = serde_json::json!(text);
            assert_eq!(
                AgePredicateProofRequest::decode(&value.to_string(), now()),
                Err(Error::UntrustedResponseHost),
                "{text}"
            );
        }
    }

    // MARK: - AgePredicateProofPackage

    fn sample_package(request: &AgePredicateProofRequest) -> AgePredicateProofPackage {
        AgePredicateProofPackage::new(
            request,
            "birthdate",
            2,
            "did:key:zIssuer",
            vec![1, 2],
            vec![3, 4],
            1_200,
            700,
            now().timestamp_millis(),
        )
        .unwrap()
    }

    #[test]
    fn package_is_bound_to_the_exact_request_and_source() {
        let request = sample_request(PresentationCredentialSource::Twdiw);
        let package = sample_package(&request);
        let decoded = AgePredicateProofPackage::decoded(&package.encoded()).unwrap();
        assert!(decoded.validate(&request).is_ok());

        let other = sample_request(PresentationCredentialSource::SelfIssued);
        assert_eq!(decoded.validate(&other), Err(Error::SourceMismatch));
    }

    #[test]
    fn arbitrary_date_field_cannot_be_relabelled_as_birthdate() {
        let request = sample_request(PresentationCredentialSource::Twdiw);
        assert_eq!(
            AgePredicateProofPackage::new(
                &request,
                "membership_started_at",
                2,
                "did:key:zIssuer",
                vec![1],
                vec![2],
                1,
                1,
                now().timestamp_millis(),
            ),
            Err(Error::StatementMismatch)
        );
    }

    #[test]
    fn oversized_proof_artifact_is_refused_before_native_parsing() {
        let request = sample_request(PresentationCredentialSource::SelfIssued);
        assert_eq!(
            AgePredicateProofPackage::new(
                &request,
                "birthdate",
                2,
                "did:key:zIssuer",
                vec![0; MAXIMUM_ARTIFACT_BYTES + 1],
                vec![2],
                1,
                1,
                now().timestamp_millis(),
            ),
            Err(Error::MalformedPackage)
        );
    }

    #[test]
    fn package_round_trips_through_its_encoding() {
        let request = sample_request(PresentationCredentialSource::Twdiw);
        let package = sample_package(&request);
        let decoded = AgePredicateProofPackage::decoded(&package.encoded()).unwrap();
        assert_eq!(decoded, package);
    }

    #[test]
    fn decoding_rejects_malformed_bytes() {
        for bytes in [&b""[..], b"not json", b"{}", b"[1,2,3]"] {
            assert_eq!(
                AgePredicateProofPackage::decoded(bytes),
                Err(Error::MalformedPackage)
            );
        }
    }

    // MARK: - prepare cache

    #[test]
    fn cache_key_is_stable_per_credential_and_hides_its_content() {
        let credential = "eyJ...national-id...~disclosure~";
        let a = prepare_cache_key(PresentationCredentialSource::SelfIssued, credential);
        let b = prepare_cache_key(PresentationCredentialSource::SelfIssued, credential);
        assert_eq!(
            a, b,
            "same card must map to the same key so the cache can hit"
        );
        assert_eq!(a.len(), 64, "SHA-256 hex");
        assert!(
            !a.contains("national-id"),
            "the key must not carry credential content"
        );
        assert_ne!(
            a,
            prepare_cache_key(
                PresentationCredentialSource::SelfIssued,
                &format!("{credential}x")
            )
        );
        assert_ne!(
            a,
            prepare_cache_key(PresentationCredentialSource::Twdiw, credential)
        );
    }

    #[test]
    fn eviction_keeps_at_most_the_limit_and_never_evicts_the_newest() {
        let entries: Vec<(String, i64)> = (0..=MAXIMUM_PREPARE_CACHE_ENTRIES)
            .map(|i| (format!("{i:064x}"), i as i64))
            .collect();
        let evicted = prepare_cache_keys_to_evict(&entries);
        assert_eq!(evicted.len(), entries.len() - MAXIMUM_PREPARE_CACHE_ENTRIES);
        let newest = &entries.last().unwrap().0;
        assert!(!evicted.contains(newest));
        // The oldest entry (timestamp 0) is the one evicted when exactly
        // one over the limit.
        assert!(evicted.contains(&entries.first().unwrap().0));
    }

    #[test]
    fn eviction_is_a_no_op_at_or_under_the_limit() {
        let entries: Vec<(String, i64)> = (0..MAXIMUM_PREPARE_CACHE_ENTRIES)
            .map(|i| (format!("{i:064x}"), i as i64))
            .collect();
        assert!(prepare_cache_keys_to_evict(&entries).is_empty());
    }
}
