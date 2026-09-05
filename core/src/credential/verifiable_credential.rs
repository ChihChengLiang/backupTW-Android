//! A W3C Verifiable Credential 2.0 data model object.
//!
//! Ported from `backupTW-iOS/backupTW/Model/VerifiableCredential.swift` —
//! see that file for the extensive rationale (JSON-LD term-definition
//! defect, VC 2.0 vs 1.1 field renames, why `credentialSubject` stays a
//! flat string map). Comments here are kept to what a Rust reader needs.
//!
//! **This type is the payload, and by itself it proves nothing.** What a
//! verifier may believe depends entirely on what wraps these bytes — a
//! cardholder certificate signature (not yet ported) or, for credentials
//! issued before that, the device's own key via
//! [`jws_signing_input`]/[`assemble_jws`]. Neither is evidence that the
//! *data* is correct; nothing here may be presented as an official
//! endorsement of the contents.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::age_predicate;
use super::selective_disclosure::{self, Disclosure};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// `issuer_did` is not a `did:key:` DID, so no verification method can
    /// be derived from it.
    #[error("unsupported issuer did")]
    UnsupportedIssuerDid,
    /// The DID passed to the signer is not the one recorded in `issuer`.
    #[error("issuer mismatch")]
    IssuerMismatch,
}

// MARK: - Model

#[derive(Debug, Clone, Default)]
pub struct NationalIdModel {
    pub nationality: Option<String>,
    pub unified_no: Option<String>,
    pub name: Option<String>,
    pub birthdate: Option<String>,
    pub address_of_household: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// Ordered set; the v2 URL has to be the first element per VC 2.0
    /// §4.1.
    #[serde(rename = "@context")]
    pub context: Vec<JsonLdContextEntry>,
    /// Must contain `VerifiableCredential`; more specific types come after
    /// it.
    #[serde(rename = "type")]
    pub types: Vec<String>,
    /// A URL, which for a self-issued credential is the device's own DID.
    pub issuer: String,
    /// XSD 1.1 `dateTimeStamp` — see [`timestamp`] for why the format
    /// matters.
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    /// Flat string map; `id` identifies the subject. When `sd` is present
    /// this holds only `id` — every factual claim has moved behind a
    /// digest.
    #[serde(rename = "credentialSubject")]
    pub credential_subject: BTreeMap<String, String>,
    /// Sorted digests of the claims the issuer committed to, SD-JWT style.
    /// `None` on credentials issued before selective disclosure.
    #[serde(rename = "_sd", skip_serializing_if = "Option::is_none")]
    pub sd: Option<Vec<String>>,
}

// MARK: - Vocabulary

pub const CREDENTIALS_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const BASE_TYPE: &str = "VerifiableCredential";
pub const NATIONAL_ID_TYPE: &str = "NationalIDCredential";

/// Namespace for the terms bonds-tw defines itself. Nothing dereferences
/// this IRI — in JSON-LD a term's IRI is an identifier, not a fetch
/// instruction.
pub const TERM_NAMESPACE: &str = "https://bonds.tw/ns/credentials#";

/// Terms the v2 context already defines, which a credential using them must
/// therefore *not* redefine.
pub fn v2_defined_terms() -> BTreeMap<&'static str, ()> {
    ["id", "type", "name", "description"]
        .into_iter()
        .map(|t| (t, ()))
        .collect()
}

const DID_KEY_PREFIX: &str = "did:key:";

/// The inline `@context` object that gives the national-ID terms an IRI.
///
/// `https://www.w3.org/ns/credentials/v2` is `@protected` and defines no
/// `@vocab`, so a term it does not define has no IRI at all, and JSON-LD
/// expansion drops such terms *silently* — see the Swift source for the
/// measured jsonld.js behavior this exists to avoid.
pub fn national_id_term_definitions() -> JsonLdTermDefinitions {
    let mut terms = BTreeMap::new();
    terms.insert(
        NATIONAL_ID_TYPE.to_string(),
        format!("{TERM_NAMESPACE}NationalIDCredential"),
    );
    for term in [
        "nationality",
        "unifiedNo",
        "birthdate",
        "addressOfHousehold",
    ] {
        terms.insert(term.to_string(), format!("{TERM_NAMESPACE}{term}"));
    }
    terms.insert(
        age_predicate::CLAIM_NAME.to_string(),
        format!("{TERM_NAMESPACE}{}", age_predicate::CLAIM_NAME),
    );
    JsonLdTermDefinitions {
        is_protected: true,
        terms,
    }
}

// MARK: - Building

/// Wraps the MyData national ID fields in a credential.
///
/// **This builds the payload. It secures nothing.** Subject and issuer are
/// the same DID on purpose — the device's own DID in both cases, not a
/// claim that the device vouches for the contents.
///
/// `None` fields are dropped rather than written as `""`: an empty string
/// is a claim ("this address is empty"), while an absent key means "not
/// asserted", which is what a field the MyData PDF never contained means.
pub fn national_id(
    model: &NationalIdModel,
    issuer_did: &str,
    valid_from: DateTime<Utc>,
) -> VerifiableCredential {
    let mut subject = national_id_claims(model, valid_from);
    subject.insert("id".to_string(), issuer_did.to_string());
    VerifiableCredential {
        context: vec![
            JsonLdContextEntry::Url(CREDENTIALS_V2_CONTEXT.to_string()),
            JsonLdContextEntry::Definitions(national_id_term_definitions()),
        ],
        types: vec![BASE_TYPE.to_string(), NATIONAL_ID_TYPE.to_string()],
        issuer: issuer_did.to_string(),
        valid_from: timestamp(valid_from),
        credential_subject: subject,
        sd: None,
    }
}

/// The claims this build derives from a MyData document, in one place so
/// the plain credential and the selectively-disclosable one cannot
/// disagree about what a credential contains.
pub fn national_id_claims(
    model: &NationalIdModel,
    valid_from: DateTime<Utc>,
) -> BTreeMap<String, String> {
    let mut claims = BTreeMap::new();
    if let Some(v) = &model.nationality {
        claims.insert("nationality".to_string(), v.clone());
    }
    if let Some(v) = &model.unified_no {
        claims.insert("unifiedNo".to_string(), v.clone());
    }
    if let Some(v) = &model.name {
        claims.insert("name".to_string(), v.clone());
    }
    if let Some(v) = &model.birthdate {
        claims.insert("birthdate".to_string(), v.clone());
    }
    if let Some(v) = &model.address_of_household {
        claims.insert("addressOfHousehold".to_string(), v.clone());
    }
    // Derived at issuance, the only moment the birthdate and a trustworthy
    // clock are both in hand. Absent when the birthdate is not a form this
    // build can read — see `age_predicate::claim_value` for why that must
    // not become "false".
    if let Some(v) = age_predicate::claim_value(model.birthdate.as_deref(), valid_from) {
        claims.insert(age_predicate::CLAIM_NAME.to_string(), v);
    }
    claims
}

/// The same credential with every factual claim behind a digest, plus the
/// disclosures that open them.
///
/// `credential_subject` keeps only `id`, and that is deliberate rather than
/// tidy: any claim left beside it would be one the holder has no way to
/// withhold.
pub fn selectively_disclosable_national_id(
    model: &NationalIdModel,
    issuer_did: &str,
    valid_from: DateTime<Utc>,
) -> (VerifiableCredential, Vec<Disclosure>) {
    let claims: Vec<(String, String)> = national_id_claims(model, valid_from).into_iter().collect();
    let (digests, disclosures) = selective_disclosure::commit(&claims);

    let mut subject = BTreeMap::new();
    subject.insert("id".to_string(), issuer_did.to_string());

    let credential = VerifiableCredential {
        context: vec![
            JsonLdContextEntry::Url(CREDENTIALS_V2_CONTEXT.to_string()),
            JsonLdContextEntry::Definitions(national_id_term_definitions()),
        ],
        types: vec![BASE_TYPE.to_string(), NATIONAL_ID_TYPE.to_string()],
        issuer: issuer_did.to_string(),
        valid_from: timestamp(valid_from),
        credential_subject: subject,
        sd: Some(digests),
    };
    (credential, disclosures)
}

/// VC 2.0 requires an XSD 1.1 `dateTimeStamp`, which makes the timezone
/// designator mandatory; always emitting UTC sidesteps that entirely.
/// Fractional seconds are dropped: the signed payload has to be
/// reproducible from the same inputs, and two instants a microsecond apart
/// are the same instant as far as this credential is concerned.
pub fn timestamp(date: DateTime<Utc>) -> String {
    date.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// MARK: - Canonical bytes

impl VerifiableCredential {
    /// The bytes a signature over this credential covers.
    ///
    /// Goes through an intermediate [`serde_json::Value`] rather than
    /// serializing the struct directly: serde_json's `Map` is a `BTreeMap`
    /// (this crate does not enable the `preserve_order` feature), so a
    /// struct serialized straight to bytes emits fields in *declaration*
    /// order, but a struct converted to a `Value` first and *then*
    /// serialized emits them sorted — matching Swift's `.sortedKeys`,
    /// recursively, at every nesting level. **Callers must keep these
    /// bytes, not re-derive them** for the same reason `MOICASignedCredential`
    /// (iOS) carries the payload as bytes and only ever decodes it: this
    /// crate's `serde_json` version, or a future one, changing anything
    /// about its output would silently break every stored signature.
    pub fn canonical_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&value)
    }

    /// Lowercase hex SHA-256 of `bytes`.
    pub fn digest_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

// MARK: - JWS

/// The bytes a JWS signature over this credential covers: `base64url(header)
/// + "." + base64url(payload)`. Signing itself is not this crate's job —
/// key storage stays native — so this returns the input for the caller to
/// sign externally and hand to [`assemble_jws`].
///
/// The payload is the credential object itself — *not* a JWT claims set
/// with the credential nested under a `vc` claim; VC-JOSE-COSE forbids that
/// VC 1.1 shape, so no `iss`/`sub`/`nbf` claims are added either.
pub fn jws_signing_input(
    credential: &VerifiableCredential,
    issuer_did: &str,
) -> Result<String, CredentialError> {
    // Signing with a key whose DID differs from the recorded issuer would
    // produce a credential that names one issuer and points its `kid` at
    // another — silently unverifiable, and easy to miss. Refuse instead.
    if credential.issuer != issuer_did {
        return Err(CredentialError::IssuerMismatch);
    }
    let key_id = verification_method_id(issuer_did)?;

    let header = serde_json::json!({
        "alg": "ES256",
        // The media type registered for a secured credential; the 2025
        // Recommendation settled on `vc+jwt` (earlier drafts used
        // `vc+ld+jwt`).
        "typ": "vc+jwt",
        "cty": "vc",
        "kid": key_id,
    });
    let header_bytes =
        serde_json::to_vec(&header).map_err(|_| CredentialError::UnsupportedIssuerDid)?;
    let payload_bytes = credential
        .canonical_bytes()
        .map_err(|_| CredentialError::UnsupportedIssuerDid)?;

    Ok(format!(
        "{}.{}",
        base64url(&header_bytes),
        base64url(&payload_bytes)
    ))
}

/// Combines a `signing_input` (from [`jws_signing_input`]) with its raw
/// `r ‖ s` ECDSA signature into a compact JWS.
///
/// Takes a fixed 64-byte array rather than a `Vec<u8>`/slice on purpose:
/// JOSE wants a fixed-width `r ‖ s`, both left-padded to 32 bytes, and the
/// type itself is what iOS's `guard signature.count == 64` checks at
/// runtime. A future FFI boundary accepting a caller-supplied byte buffer
/// (Kotlin, over UniFFI) will need that runtime check back — this native
/// signature just doesn't need to reintroduce it for a length Rust already
/// guarantees.
pub fn assemble_jws(signing_input: &str, signature: &[u8; 64]) -> String {
    format!("{signing_input}.{}", base64url(signature))
}

/// The `kid` for a `did:key:` issuer: the DID, then the multibase value
/// repeated as the fragment (`did:key:zDn…#zDn…`).
///
/// The did:key algorithm text says to append the *multicodec* value, but
/// every example in that same document — and every implementation —
/// appends the multibase value. The examples win.
pub fn verification_method_id(did: &str) -> Result<String, CredentialError> {
    let multibase_value = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or(CredentialError::UnsupportedIssuerDid)?;
    if multibase_value.is_empty() {
        return Err(CredentialError::UnsupportedIssuerDid);
    }
    Ok(format!("{did}#{multibase_value}"))
}

fn base64url(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn full_model() -> NationalIdModel {
        NationalIdModel {
            nationality: Some("中華民國（臺灣）".into()),
            unified_no: Some("A123456789".into()),
            name: Some("王小明".into()),
            birthdate: Some("0700101".into()),
            address_of_household: Some("臺北市中正區重慶南路一段122號".into()),
        }
    }

    const ISSUER_DID: &str = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";

    fn issued_at() -> DateTime<Utc> {
        Utc.timestamp_opt(1_754_400_000, 0).unwrap()
    }

    fn sample_credential() -> VerifiableCredential {
        national_id(&full_model(), ISSUER_DID, issued_at())
    }

    #[test]
    fn maps_every_national_id_field_into_the_subject() {
        let c = sample_credential();
        assert_eq!(
            c.credential_subject.get("nationality").unwrap(),
            "中華民國（臺灣）"
        );
        assert_eq!(c.credential_subject.get("unifiedNo").unwrap(), "A123456789");
        assert_eq!(c.credential_subject.get("name").unwrap(), "王小明");
        assert_eq!(c.credential_subject.get("birthdate").unwrap(), "0700101");
        assert_eq!(
            c.credential_subject.get("addressOfHousehold").unwrap(),
            "臺北市中正區重慶南路一段122號"
        );
    }

    #[test]
    fn subject_is_identified_by_the_issuer_did() {
        let c = sample_credential();
        assert_eq!(c.credential_subject.get("id").unwrap(), ISSUER_DID);
        assert_eq!(c.issuer, ISSUER_DID);
    }

    #[test]
    fn omits_missing_fields_instead_of_emitting_empty_strings() {
        let sparse = NationalIdModel {
            unified_no: Some("A123456789".into()),
            ..Default::default()
        };
        let c = national_id(&sparse, ISSUER_DID, issued_at());

        assert!(!c.credential_subject.contains_key("nationality"));
        assert!(!c.credential_subject.contains_key("name"));
        assert!(!c.credential_subject.contains_key("birthdate"));
        assert!(!c.credential_subject.contains_key("addressOfHousehold"));
        assert_eq!(c.credential_subject.len(), 2);
        let keys: Vec<&String> = c.credential_subject.keys().collect();
        assert_eq!(keys, vec!["id", "unifiedNo"]);
    }

    #[test]
    fn carries_the_base_type_first() {
        let c = sample_credential();
        assert_eq!(c.types.first().unwrap(), BASE_TYPE);
        assert!(c.types.contains(&NATIONAL_ID_TYPE.to_string()));
    }

    #[test]
    fn encodes_context_with_the_at_sign() {
        let value = serde_json::to_value(sample_credential()).unwrap();
        let obj = value.as_object().unwrap();
        assert!(obj.contains_key("@context"));
        assert!(!obj.contains_key("context"));

        let context = obj["@context"].as_array().unwrap();
        assert_eq!(context[0].as_str().unwrap(), CREDENTIALS_V2_CONTEXT);
    }

    #[test]
    fn embedded_context_is_the_second_entry_and_is_protected() {
        let value = serde_json::to_value(sample_credential()).unwrap();
        let context = value["@context"].as_array().unwrap();
        assert_eq!(context.len(), 2);
        assert_eq!(context[0].as_str().unwrap(), CREDENTIALS_V2_CONTEXT);
        let definitions = context[1].as_object().unwrap();
        assert_eq!(definitions["@protected"].as_bool(), Some(true));
    }

    #[test]
    fn embedded_context_names_the_bonds_terms() {
        let value = serde_json::to_value(sample_credential()).unwrap();
        let definitions = value["@context"][1].as_object().unwrap();
        assert_eq!(
            definitions["NationalIDCredential"].as_str().unwrap(),
            "https://bonds.tw/ns/credentials#NationalIDCredential"
        );
        assert_eq!(
            definitions["unifiedNo"].as_str().unwrap(),
            "https://bonds.tw/ns/credentials#unifiedNo"
        );
    }

    /// Redefining a `@protected` term is an expansion *error*, not an
    /// override — a well-meant `"name"` entry here would take the whole
    /// document down.
    #[test]
    fn embedded_context_does_not_redefine_protected_v2_terms() {
        let value = serde_json::to_value(sample_credential()).unwrap();
        let definitions = value["@context"][1].as_object().unwrap();
        for term in [
            "id",
            "type",
            "name",
            "description",
            "issuer",
            "credentialSubject",
            "validFrom",
            "validUntil",
            "proof",
            "credentialStatus",
            "credentialSchema",
            "evidence",
            "termsOfUse",
            "refreshService",
        ] {
            assert!(
                !definitions.contains_key(term),
                "{term} must not be redefined"
            );
        }
    }

    #[test]
    fn context_survives_a_decode_encode_round_trip() {
        let credential = sample_credential();
        let bytes = credential.canonical_bytes().unwrap();
        let decoded: VerifiableCredential = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, credential);
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn uses_valid_from_rather_than_issuance_date() {
        let value = serde_json::to_value(sample_credential()).unwrap();
        assert!(value.get("issuanceDate").is_none());
        assert_eq!(value["validFrom"].as_str().unwrap(), "2025-08-05T13:20:00Z");
    }

    #[test]
    fn timestamps_are_utc_with_an_explicit_designator() {
        let stamp = timestamp(issued_at());
        assert!(stamp.ends_with('Z'));
        assert!(!stamp.contains('.'));
    }

    /// The signature covers the encoded payload bytes. If encoding the same
    /// credential twice can differ, nobody can re-derive the signing input
    /// from the decoded credential, and the JWS stops being checkable.
    #[test]
    fn encoding_is_deterministic() {
        let credential = sample_credential();
        let first = credential.canonical_bytes().unwrap();
        for _ in 0..32 {
            assert_eq!(credential.canonical_bytes().unwrap(), first);
        }
    }

    #[test]
    fn credentials_built_from_the_same_inputs_are_equal() {
        let a = national_id(&full_model(), ISSUER_DID, issued_at());
        let b = national_id(&full_model(), ISSUER_DID, issued_at());
        assert_eq!(a, b);
    }

    #[test]
    fn verification_method_repeats_the_multibase_value_as_fragment() {
        let key_id = verification_method_id(ISSUER_DID).unwrap();
        assert_eq!(
            key_id,
            format!("{ISSUER_DID}#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv")
        );
    }

    #[test]
    fn rejects_issuers_that_are_not_did_keys() {
        for did in ["", "did:key:", "did:web:example.gov", "zDnaerx9CtbPJ1q36T5"] {
            assert!(verification_method_id(did).is_err(), "{did:?}");
        }
    }

    #[test]
    fn jws_signing_input_refuses_a_different_issuer() {
        let credential = sample_credential();
        let other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        assert_eq!(
            jws_signing_input(&credential, other),
            Err(CredentialError::IssuerMismatch)
        );
    }

    /// Structural shape a real signature would ride on top of: two
    /// dot-joined base64url segments, header declaring ES256 and the
    /// issuer key ID, payload the bare credential with no `vc` wrapper.
    #[test]
    fn jws_signing_input_has_the_right_shape() {
        let credential = sample_credential();
        let input = jws_signing_input(&credential, ISSUER_DID).unwrap();
        let segments: Vec<&str> = input.split('.').collect();
        assert_eq!(segments.len(), 2);
        assert!(segments.iter().all(|s| !s.is_empty()));

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "vc+jwt");
        assert_eq!(header["cty"], "vc");
        assert_eq!(
            header["kid"],
            format!("{ISSUER_DID}#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv")
        );

        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert!(payload.get("vc").is_none());
        assert!(payload.get("@context").is_some());
        assert!(payload.get("credentialSubject").is_some());
        assert_eq!(payload["issuer"], ISSUER_DID);

        let decoded: VerifiableCredential =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert_eq!(decoded, credential);
    }

    #[test]
    fn signing_twice_produces_the_same_signing_input() {
        let credential = sample_credential();
        let first = jws_signing_input(&credential, ISSUER_DID).unwrap();
        let second = jws_signing_input(&credential, ISSUER_DID).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn assemble_jws_produces_three_unpadded_base64url_segments() {
        let credential = sample_credential();
        let input = jws_signing_input(&credential, ISSUER_DID).unwrap();
        let jws = assemble_jws(&input, &[0x42u8; 64]);
        let segments: Vec<&str> = jws.split('.').collect();
        assert_eq!(segments.len(), 3);
        for segment in &segments {
            assert!(!segment.contains('='));
            assert!(!segment.contains('+'));
            assert!(!segment.contains('/'));
        }
    }
}

// MARK: - JSON-LD context

/// One entry of a JSON-LD `@context` array: either a URL a verifier
/// resolves, or an object that defines terms inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonLdContextEntry {
    Url(String),
    Definitions(JsonLdTermDefinitions),
}

impl Serialize for JsonLdContextEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JsonLdContextEntry::Url(url) => url.serialize(serializer),
            JsonLdContextEntry::Definitions(defs) => defs.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for JsonLdContextEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let serde_json::Value::String(url) = value {
            Ok(JsonLdContextEntry::Url(url))
        } else {
            let defs: JsonLdTermDefinitions =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(JsonLdContextEntry::Definitions(defs))
        }
    }
}

/// An inline JSON-LD context object: `@protected`, plus one absolute IRI
/// per term.
///
/// Only the two shapes this credential needs are modelled — a boolean
/// `@protected` and simple `term -> IRI` strings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JsonLdTermDefinitions {
    /// Mirrors what the v2 context does to its own terms: once defined, a
    /// term cannot be quietly redefined by a later context.
    pub is_protected: bool,
    /// Term name -> absolute IRI.
    pub terms: BTreeMap<String, String>,
}

impl Serialize for JsonLdTermDefinitions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        // Written only when true: `"@protected": false` is not the same
        // document as one without the keyword, and round-tripping has to
        // reproduce the exact bytes a signature was taken over.
        if self.is_protected {
            map.serialize_entry("@protected", &true)?;
        }
        for (term, iri) in &self.terms {
            map.serialize_entry(term, iri)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for JsonLdTermDefinitions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: BTreeMap<String, serde_json::Value> = BTreeMap::deserialize(deserializer)?;
        let mut is_protected = false;
        let mut terms = BTreeMap::new();
        for (key, value) in raw {
            if key == "@protected" {
                is_protected = value.as_bool().unwrap_or(false);
            } else if let Some(s) = value.as_str() {
                terms.insert(key, s.to_string());
            }
        }
        Ok(JsonLdTermDefinitions {
            is_protected,
            terms,
        })
    }
}
