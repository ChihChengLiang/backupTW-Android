//! A W3C Verifiable Presentation 2.0, secured as a compact JWS: proof that
//! the device holding a key is here now and answered a verifier's
//! challenge - not proof that the credential's contents are true.
//!
//! Ported from
//! `backupTW-iOS/backupTW/Presentation/VerifiablePresentation.swift` - see
//! that file for the extensive rationale, in particular **every
//! presentation is linkable to every other one** (the holder DID is the
//! public key, repeated verbatim) and the JSON-LD term-definition trap
//! this shares with `VerifiableCredential`: an undefined term (here,
//! `challenge` itself) is dropped *silently* by expansion while the JWS
//! still verifies.
//!
//! **Scoped to the JOSE/device-key path.** `MOICASignedCredential` (the
//! cardholder-certificate envelope this app now issues by default) is not
//! yet ported, so the dispatcher that picks between a card-signed and a
//! device-signed stored credential (`create(credentialJWS:...)` in the
//! Swift source) is not ported either. What *is* here is what that
//! dispatcher hands off to either way: [`subject_identifier`] (read
//! `credentialSubject.id` off a stored credential without verifying it,
//! so a caller can check holder binding before presenting) and
//! [`presentation_signing_input`]/[`assemble_presentation_jws`] (build
//! and finish a presentation around an already-typed
//! [`EnvelopedVerifiableCredential`] - used today for TWDIW SD-JWT cards,
//! after `TWDIWCredentialReader` has checked the issuer signature,
//! disclosure commitments and `cnf.jwk` binding).
//!
//! Key storage stays native, so this follows the same split as
//! `credential::jws_signing_input`/`assemble_jws`: this crate builds the
//! bytes to sign, a caller signs them externally (Keystore), and hands
//! the raw `r ‖ s` signature back to [`assemble_presentation_jws`].

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::credential::{
    timestamp, verification_method_id, JsonLdContextEntry, JsonLdTermDefinitions,
    CREDENTIALS_V2_CONTEXT, TERM_NAMESPACE,
};
use crate::identity::{did_key, jwk_did_key};
use crate::presentation::request::PresentationRequest;
use p256::elliptic_curve::sec1::ToEncodedPoint;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifiablePresentationError {
    /// The holder identifier is not a `did:key:` DID.
    #[error("unsupported holder did")]
    UnsupportedHolderDid,
    /// The signing key does not derive to `holder_did`. Usually means the
    /// device identity was reset since the credential was issued.
    #[error("holder key mismatch")]
    HolderKeyMismatch,
    /// The signing key exists but no DID could be derived from it at all.
    #[error("holder key unusable")]
    HolderKeyUnusable,
    /// The stored credential is not a three-segment compact JWS, or its
    /// payload is not a credential object with a subject identifier.
    #[error("malformed credential")]
    MalformedCredential,
}

pub const BASE_TYPE: &str = "VerifiablePresentation";

/// The inline `@context` object for the terms v2 does not define. See the
/// Swift source for why `challenge`/`audience`/`purpose`/`created` are
/// safe to define at the top level despite v2 defining two of them inside
/// `proof`'s type-scoped context (which never comes into range here).
pub fn presentation_term_definitions() -> JsonLdTermDefinitions {
    let mut terms = BTreeMap::new();
    for term in ["challenge", "audience", "purpose", "created"] {
        terms.insert(term.to_string(), format!("{TERM_NAMESPACE}{term}"));
    }
    JsonLdTermDefinitions {
        is_protected: true,
        terms,
    }
}

/// Terms this presentation uses that the v2 context already declares, and
/// which must therefore not appear in [`presentation_term_definitions`].
pub fn v2_defined_presentation_terms() -> [&'static str; 6] {
    [
        "id",
        "type",
        "holder",
        "verifiableCredential",
        "VerifiablePresentation",
        "EnvelopedVerifiableCredential",
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<JsonLdContextEntry>,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    /// The DID of the device presenting, which is also the credential's
    /// subject.
    pub holder: String,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<EnvelopedVerifiableCredential>,
    /// Echoed verbatim from the verifier's `PresentationRequest`.
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub purpose: String,
    /// XSD 1.1 `dateTimeStamp`, from the holder's clock.
    pub created: String,
}

impl VerifiablePresentation {
    /// The bytes a JWS signature over this presentation covers - see
    /// `VerifiableCredential::canonical_bytes` for why this goes through
    /// an intermediate `serde_json::Value` rather than serializing the
    /// struct directly.
    pub fn canonical_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&value)
    }
}

// MARK: - Enveloped credential

/// A credential that is already secured by its own JOSE envelope,
/// referenced from a presentation. VC 2.0 §4.12: a compact JWS is a
/// *string*, and a bare string in `verifiableCredential` verifies but
/// loses its credential on JSON-LD expansion - this wrapper is what makes
/// it a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopedVerifiableCredential {
    #[serde(rename = "@context")]
    pub context: String,
    /// `data:<media type>,<payload>` - see the `enveloping_*` constructors.
    pub id: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

impl EnvelopedVerifiableCredential {
    pub const TYPE_NAME: &'static str = "EnvelopedVerifiableCredential";
    /// The media type registered by VC-JOSE-COSE for a credential secured
    /// with a compact JWS.
    pub const COMPACT_JWS_PREFIX: &'static str = "data:application/vc+jwt,";
    /// A credential secured by the cardholder's 自然人憑證 rather than a
    /// JOSE signature. `;base64,` because the envelope is JSON.
    pub const MOICA_SIGNED_PREFIX: &'static str = "data:application/vc+moica;base64,";
    /// The IETF-registered SD-JWT media type; the compact SD-JWT
    /// serialization is already URL-safe, so no extra base64 layer.
    pub const SD_JWT_PREFIX: &'static str = "data:application/dc+sd-jwt,";

    pub fn enveloping_compact_jws(jws: &str) -> Self {
        Self {
            context: CREDENTIALS_V2_CONTEXT.to_string(),
            id: format!("{}{jws}", Self::COMPACT_JWS_PREFIX),
            type_name: Self::TYPE_NAME.to_string(),
        }
    }

    pub fn enveloping_moica_signed(serialized: &str) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        Self {
            context: CREDENTIALS_V2_CONTEXT.to_string(),
            id: format!(
                "{}{}",
                Self::MOICA_SIGNED_PREFIX,
                STANDARD.encode(serialized.as_bytes())
            ),
            type_name: Self::TYPE_NAME.to_string(),
        }
    }

    pub fn enveloping_sd_jwt(serialized: &str) -> Self {
        Self {
            context: CREDENTIALS_V2_CONTEXT.to_string(),
            id: format!("{}{serialized}", Self::SD_JWT_PREFIX),
            type_name: Self::TYPE_NAME.to_string(),
        }
    }

    /// The credential's original compact-JWS bytes, or `None` if this
    /// envelope carries some other media type - which is what a future ZK
    /// proof would look like from here, and a case a caller has to handle
    /// rather than assume away.
    pub fn compact_jws(&self) -> Option<&str> {
        self.id.strip_prefix(Self::COMPACT_JWS_PREFIX)
    }

    pub fn moica_signed_serialization(&self) -> Option<String> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let encoded = self.id.strip_prefix(Self::MOICA_SIGNED_PREFIX)?;
        let bytes = STANDARD.decode(encoded).ok()?;
        String::from_utf8(bytes).ok()
    }

    pub fn sd_jwt_serialization(&self) -> Option<&str> {
        self.id.strip_prefix(Self::SD_JWT_PREFIX)
    }
}

// MARK: - Building

/// Reads `credentialSubject.id` out of a compact JWS without verifying
/// it - the credential came from this device's own protected store and
/// this device signed it, so re-verifying here would duplicate a job that
/// belongs to whoever presents to a verifier next.
///
/// Deliberately raw JSON rather than `VerifiableCredential`: that type
/// models only the credentials this app issues, so a credential from
/// another implementation would be reported as malformed when it is
/// merely unfamiliar. Only one field is needed, so only one is read.
pub fn subject_identifier(credential_jws: &str) -> Result<String, VerifiablePresentationError> {
    let segments: Vec<&str> = credential_jws.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|s| s.is_empty()) {
        return Err(VerifiablePresentationError::MalformedCredential);
    }
    let payload_bytes =
        base64url_decode(segments[1]).ok_or(VerifiablePresentationError::MalformedCredential)?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| VerifiablePresentationError::MalformedCredential)?;
    let identifier = payload
        .get("credentialSubject")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or(VerifiablePresentationError::MalformedCredential)?;
    Ok(identifier.to_string())
}

/// The bytes a JWS signature over a presentation covers, wrapping one
/// already-enveloped credential. Signing itself stays native; sign this
/// with the holder's device key and hand the raw `r ‖ s` signature to
/// [`assemble_presentation_jws`].
///
/// `holder_public_key_x963` is the device key's own public key (X9.63
/// uncompressed, 65 bytes) as the caller's key store reports it - checked
/// against what `holder_did` derives to, so a caller holding a stale DID
/// is told so rather than producing a presentation that fails at the far
/// end with no explanation.
pub fn presentation_signing_input(
    enveloped: EnvelopedVerifiableCredential,
    request: &PresentationRequest,
    holder_did: &str,
    holder_public_key_x963: &[u8],
    created_at: DateTime<Utc>,
) -> Result<String, VerifiablePresentationError> {
    let key_id = verification_method_id(holder_did)
        .map_err(|_| VerifiablePresentationError::UnsupportedHolderDid)?;

    let holder_public_key = did_key::p256_public_key_from_did(holder_did)
        .ok()
        .or_else(|| jwk_did_key::p256_public_key_from_did(holder_did).ok())
        .ok_or(VerifiablePresentationError::HolderKeyUnusable)?;
    if holder_public_key.to_encoded_point(false).as_bytes() != holder_public_key_x963 {
        return Err(VerifiablePresentationError::HolderKeyMismatch);
    }

    let presentation = VerifiablePresentation {
        context: vec![
            JsonLdContextEntry::Url(CREDENTIALS_V2_CONTEXT.to_string()),
            JsonLdContextEntry::Definitions(presentation_term_definitions()),
        ],
        types: vec![BASE_TYPE.to_string()],
        holder: holder_did.to_string(),
        verifiable_credential: vec![enveloped],
        challenge: request.challenge.clone(),
        audience: request.audience.clone(),
        purpose: request.purpose.clone(),
        created: timestamp(created_at),
    };

    let header = serde_json::json!({
        "alg": "ES256",
        // VC-JOSE-COSE's media type for a secured presentation. `typ` is
        // the only thing separating this from a credential signed by the
        // same key for a different purpose - JOSE has no `proofPurpose`.
        "typ": "vp+jwt",
        "cty": "vp",
        "kid": key_id,
    });
    let header_bytes = serde_json::to_vec(&header)
        .map_err(|_| VerifiablePresentationError::MalformedCredential)?;
    let payload_bytes = presentation
        .canonical_bytes()
        .map_err(|_| VerifiablePresentationError::MalformedCredential)?;

    Ok(format!(
        "{}.{}",
        base64url_encode(&header_bytes),
        base64url_encode(&payload_bytes)
    ))
}

/// Combines a `signing_input` (from [`presentation_signing_input`]) with
/// its raw `r ‖ s` ECDSA signature into a compact JWS.
pub fn assemble_presentation_jws(signing_input: &str, signature: &[u8; 64]) -> String {
    format!("{signing_input}.{}", base64url_encode(signature))
}

fn base64url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{assemble_jws, jws_signing_input, national_id, NationalIdModel};
    use crate::presentation::request::PresentationCredentialSource;
    use chrono::TimeZone;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;

    /// The W3C-CCG P-256 test vector: certainly not this fixture's key.
    const OTHER_DID: &str = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";

    fn issued_at() -> DateTime<Utc> {
        Utc.timestamp_opt(1_754_400_000, 0).unwrap()
    }

    fn created_at() -> DateTime<Utc> {
        Utc.timestamp_opt(1_754_500_000, 0).unwrap()
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

    struct Fixture {
        key: SigningKey,
        did: String,
        credential_jws: String,
        request: PresentationRequest,
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

    fn fixture() -> Fixture {
        let key = SigningKey::random(&mut OsRng);
        let did = did_key::did_from_p256_x963(&x963(&key)).unwrap();
        let credential = national_id(&full_model(), &did, issued_at());
        let signing_input = jws_signing_input(&credential, &did).unwrap();
        let signature = sign_raw(&key, signing_input.as_bytes());
        let credential_jws = assemble_jws(&signing_input, &signature);
        let request = PresentationRequest::new(
            "Q0hBTExFTkdFLTAwMDAwMA",
            "里長辦公室核對受災戶身分",
            issued_at().timestamp(),
            Some("urn:bonds-tw:verifier:test"),
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        Fixture {
            key,
            did,
            credential_jws,
            request,
        }
    }

    fn presentation_jws(fixture: &Fixture) -> String {
        let enveloped =
            EnvelopedVerifiableCredential::enveloping_compact_jws(&fixture.credential_jws);
        let input = presentation_signing_input(
            enveloped,
            &fixture.request,
            &fixture.did,
            &x963(&fixture.key),
            created_at(),
        )
        .unwrap();
        let signature = sign_raw(&fixture.key, input.as_bytes());
        assemble_presentation_jws(&input, &signature)
    }

    fn header_object(jws: &str) -> serde_json::Value {
        let segment = jws.split('.').next().unwrap();
        serde_json::from_slice(&base64url_decode(segment).unwrap()).unwrap()
    }

    fn payload_object(jws: &str) -> serde_json::Value {
        let segment = jws.split('.').nth(1).unwrap();
        serde_json::from_slice(&base64url_decode(segment).unwrap()).unwrap()
    }

    #[test]
    fn compact_serialization_has_three_segments() {
        let jws = presentation_jws(&fixture());
        let segments: Vec<&str> = jws.split('.').collect();
        assert_eq!(segments.len(), 3);
        assert!(segments.iter().all(|s| !s.is_empty()));
    }

    #[test]
    fn every_segment_is_unpadded_base64_url() {
        let jws = presentation_jws(&fixture());
        for segment in jws.split('.') {
            assert!(!segment.contains('='));
            assert!(!segment.contains('+'));
            assert!(!segment.contains('/'));
        }
    }

    #[test]
    fn header_declares_es256_and_separates_itself_from_a_credential() {
        let f = fixture();
        let jws = presentation_jws(&f);
        let header = header_object(&jws);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "vp+jwt");
        assert_eq!(header["cty"], "vp");
        let fragment = f.did.strip_prefix("did:key:").unwrap();
        assert_eq!(header["kid"], format!("{}#{fragment}", f.did));

        let credential_header = header_object(&f.credential_jws);
        assert_ne!(credential_header["typ"], header["typ"]);
    }

    #[test]
    fn payload_is_a_verifiable_presentation_held_by_this_device() {
        let f = fixture();
        let payload = payload_object(&presentation_jws(&f));
        let object = payload.as_object().unwrap();
        assert!(object.contains_key("@context"));
        assert!(!object.contains_key("context"));
        assert_eq!(object["@context"][0], CREDENTIALS_V2_CONTEXT);
        assert_eq!(
            object["type"],
            serde_json::json!(["VerifiablePresentation"])
        );
        assert_eq!(object["holder"], f.did);
    }

    #[test]
    fn credential_is_enveloped_with_its_bytes_intact() {
        let f = fixture();
        let payload = payload_object(&presentation_jws(&f));
        let credentials = payload["verifiableCredential"].as_array().unwrap();
        assert_eq!(credentials.len(), 1);
        let envelope = &credentials[0];
        assert_eq!(envelope["type"], EnvelopedVerifiableCredential::TYPE_NAME);
        assert_eq!(envelope["@context"], CREDENTIALS_V2_CONTEXT);
        assert_eq!(
            envelope["id"],
            format!(
                "{}{}",
                EnvelopedVerifiableCredential::COMPACT_JWS_PREFIX,
                f.credential_jws
            )
        );

        let decoded = EnvelopedVerifiableCredential::enveloping_compact_jws(&f.credential_jws);
        assert_eq!(decoded.compact_jws(), Some(f.credential_jws.as_str()));
    }

    #[test]
    fn envelope_reports_no_jws_for_another_media_type() {
        let envelope = EnvelopedVerifiableCredential {
            context: CREDENTIALS_V2_CONTEXT.to_string(),
            id: "data:application/vp+sd-jwt,abc".to_string(),
            type_name: EnvelopedVerifiableCredential::TYPE_NAME.to_string(),
        };
        assert_eq!(envelope.compact_jws(), None);
    }

    #[test]
    fn carries_the_challenge_and_purpose_the_verifier_asked() {
        let f = fixture();
        let payload = payload_object(&presentation_jws(&f));
        assert_eq!(payload["challenge"], f.request.challenge);
        assert_eq!(payload["purpose"], f.request.purpose);
        assert_eq!(payload["audience"], "urn:bonds-tw:verifier:test");
    }

    #[test]
    fn omits_the_audience_when_the_verifier_named_none() {
        let f = fixture();
        let anonymous = PresentationRequest::new(
            &f.request.challenge,
            &f.request.purpose,
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let enveloped = EnvelopedVerifiableCredential::enveloping_compact_jws(&f.credential_jws);
        let input =
            presentation_signing_input(enveloped, &anonymous, &f.did, &x963(&f.key), created_at())
                .unwrap();
        let signature = sign_raw(&f.key, input.as_bytes());
        let jws = assemble_presentation_jws(&input, &signature);
        let payload = payload_object(&jws);
        assert!(payload.get("audience").is_none());
    }

    #[test]
    fn created_is_utc_without_fractional_seconds() {
        let f = fixture();
        let payload = payload_object(&presentation_jws(&f));
        let stamp = payload["created"].as_str().unwrap();
        assert_eq!(stamp, "2025-08-06T17:06:40Z");
        assert!(stamp.ends_with('Z'));
        assert!(!stamp.contains('.'));
    }

    #[test]
    fn every_term_the_presentation_uses_resolves_to_an_iri() {
        let f = fixture();
        let payload = payload_object(&presentation_jws(&f));
        let object = payload.as_object().unwrap();
        let context = payload["@context"].as_array().unwrap();
        let definitions = context
            .iter()
            .find_map(|entry| entry.as_object())
            .expect("@context carries no inline definitions");

        let exempt = v2_defined_presentation_terms();
        for term in object.keys() {
            if term == "@context" || exempt.contains(&term.as_str()) {
                continue;
            }
            let iri = definitions
                .get(term)
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{term} has no term definition"));
            assert!(iri.contains("://"), "{term} must map to an absolute IRI");
        }
        for type_name in payload["type"].as_array().unwrap() {
            let type_name = type_name.as_str().unwrap();
            if exempt.contains(&type_name) {
                continue;
            }
            let iri = definitions
                .get(type_name)
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("type {type_name} has no term definition"));
            assert!(iri.contains("://"));
        }
    }

    #[test]
    fn only_terms_the_v2_context_declares_are_exempt_from_definition() {
        assert_eq!(
            v2_defined_presentation_terms(),
            [
                "id",
                "type",
                "holder",
                "verifiableCredential",
                "VerifiablePresentation",
                "EnvelopedVerifiableCredential",
            ]
        );
    }

    #[test]
    fn embedded_context_does_not_redefine_protected_v2_terms() {
        for term in [
            "id",
            "type",
            "holder",
            "verifiableCredential",
            "proof",
            "domain",
            "validFrom",
            "validUntil",
            "credentialStatus",
            "VerifiablePresentation",
            "EnvelopedVerifiableCredential",
        ] {
            assert!(!presentation_term_definitions().terms.contains_key(term));
        }
    }

    #[test]
    fn embedded_context_is_protected_and_names_the_bonds_terms() {
        let definitions = presentation_term_definitions();
        assert!(definitions.is_protected);
        assert_eq!(
            definitions.terms["challenge"],
            "https://bonds.tw/ns/credentials#challenge"
        );
        assert_eq!(
            definitions.terms["audience"],
            "https://bonds.tw/ns/credentials#audience"
        );
        assert_eq!(
            definitions.terms["purpose"],
            "https://bonds.tw/ns/credentials#purpose"
        );
        assert_eq!(
            definitions.terms["created"],
            "https://bonds.tw/ns/credentials#created"
        );
    }

    fn signature_is_valid(jws: &str, key: &SigningKey) -> bool {
        use p256::ecdsa::{signature::Verifier, VerifyingKey};
        let segments: Vec<&str> = jws.split('.').collect();
        let signature_bytes = base64url_decode(segments[2]).unwrap();
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            return false;
        };
        let verifying_key = VerifyingKey::from(key);
        let message = format!("{}.{}", segments[0], segments[1]);
        verifying_key.verify(message.as_bytes(), &signature).is_ok()
    }

    #[test]
    fn presentation_verifies_against_the_device_key() {
        let f = fixture();
        assert!(signature_is_valid(&presentation_jws(&f), &f.key));
    }

    /// The property the whole scheme rests on: a different challenge
    /// produces different signed bytes.
    #[test]
    fn changing_the_challenge_invalidates_the_signature() {
        let f = fixture();
        let jws = presentation_jws(&f);
        let segments: Vec<&str> = jws.split('.').collect();
        let original: VerifiablePresentation =
            serde_json::from_slice(&base64url_decode(segments[1]).unwrap()).unwrap();

        // Re-encoding the untouched presentation has to reproduce the
        // signed bytes exactly.
        let reencoded_input = format!(
            "{}.{}",
            segments[0],
            base64url_encode(&original.canonical_bytes().unwrap())
        );
        assert_eq!(reencoded_input, format!("{}.{}", segments[0], segments[1]));

        let mut tampered = original.clone();
        tampered.challenge = "AAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert_ne!(tampered.challenge, original.challenge);

        let tampered_input = format!(
            "{}.{}",
            segments[0],
            base64url_encode(&tampered.canonical_bytes().unwrap())
        );
        let verifying_key = p256::ecdsa::VerifyingKey::from(&f.key);
        let signature = Signature::from_slice(&base64url_decode(segments[2]).unwrap()).unwrap();
        use p256::ecdsa::signature::Verifier;
        assert!(verifying_key
            .verify(tampered_input.as_bytes(), &signature)
            .is_err());
    }

    #[test]
    fn different_challenges_produce_different_signing_inputs() {
        let f = fixture();
        let other = PresentationRequest::new(
            "AAAAAAAAAAAAAAAAAAAAAA",
            &f.request.purpose,
            issued_at().timestamp(),
            None,
            None,
            PresentationCredentialSource::SelfIssued,
        )
        .unwrap();
        let enveloped = EnvelopedVerifiableCredential::enveloping_compact_jws(&f.credential_jws);
        let second_input =
            presentation_signing_input(enveloped, &other, &f.did, &x963(&f.key), created_at())
                .unwrap();

        let first = presentation_jws(&f);
        let first_payload_segment = first.split('.').nth(1).unwrap();
        let second_payload_segment = second_input.split('.').nth(1).unwrap();
        assert_ne!(first_payload_segment, second_payload_segment);
    }

    #[test]
    fn signing_twice_produces_the_same_signing_input() {
        let f = fixture();
        let build = || {
            let enveloped =
                EnvelopedVerifiableCredential::enveloping_compact_jws(&f.credential_jws);
            presentation_signing_input(enveloped, &f.request, &f.did, &x963(&f.key), created_at())
                .unwrap()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn payload_round_trips_into_the_model_and_back_to_the_same_bytes() {
        let f = fixture();
        let jws = presentation_jws(&f);
        let segments: Vec<&str> = jws.split('.').collect();
        let decoded: VerifiablePresentation =
            serde_json::from_slice(&base64url_decode(segments[1]).unwrap()).unwrap();

        assert_eq!(decoded.holder, f.did);
        assert_eq!(decoded.challenge, f.request.challenge);
        assert_eq!(
            decoded.verifiable_credential[0].compact_jws(),
            Some(f.credential_jws.as_str())
        );
        assert_eq!(
            base64url_encode(&decoded.canonical_bytes().unwrap()),
            segments[1]
        );
    }

    #[test]
    fn rejects_a_holder_identifier_that_is_not_a_did_key() {
        let f = fixture();
        for did in ["", "did:key:", "did:web:example.gov", "zDnaerx9CtbPJ1q36T5"] {
            let enveloped =
                EnvelopedVerifiableCredential::enveloping_compact_jws(&f.credential_jws);
            assert_eq!(
                presentation_signing_input(enveloped, &f.request, did, &x963(&f.key), created_at()),
                Err(VerifiablePresentationError::UnsupportedHolderDid)
            );
        }
    }

    #[test]
    fn rejects_a_holder_identifier_this_key_does_not_derive_to() {
        let f = fixture();
        let enveloped = EnvelopedVerifiableCredential::enveloping_compact_jws(&f.credential_jws);
        assert_eq!(
            presentation_signing_input(
                enveloped,
                &f.request,
                OTHER_DID,
                &x963(&f.key),
                created_at()
            ),
            Err(VerifiablePresentationError::HolderKeyMismatch)
        );
    }

    #[test]
    fn rejects_a_credential_it_cannot_read_a_subject_from() {
        for jws in [
            "",
            "abc",
            "abc.def",
            "abc.def.ghi.jkl",
            "abc..ghi",
            "abc.!!!!.ghi",
            "abc.aGVsbG8.ghi",
            "abc.eyJhIjoxfQ.ghi",
            "abc.eyJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoiWCJ9fQ.ghi",
        ] {
            assert_eq!(
                subject_identifier(jws),
                Err(VerifiablePresentationError::MalformedCredential)
            );
        }
    }

    #[test]
    fn subject_identifier_reads_the_credential_subject_id() {
        let f = fixture();
        assert_eq!(subject_identifier(&f.credential_jws).unwrap(), f.did);
    }
}
