//! A credential plus the 自然人憑證 (MOICA) signature over it - the envelope
//! this project issues by default for self-issued national-ID
//! credentials, secured by a cardholder's own citizen certificate
//! rather than by this device's key.
//!
//! Ported from `backupTW-iOS/backupTW/Model/MOICASignedCredential.swift`,
//! which has the extensive rationale, in particular why this is not a
//! JWS even though the pieces nearly fit (the TBS is a domain prefix
//! plus a digest, spelled as an explicit object so nothing mistakes it
//! for a JWS and hands it to a JOSE verifier that would be right to
//! reject it), and what a card signature does and does not establish
//! (「這位持卡人主張這些值」, not 「內政部背書這些值正確」).
//!
//! Issuance needs a completed TW FidO SIGN round trip, which is native
//! (Android) territory - this crate provides [`to_be_signed`] (the TBS
//! a caller hands to native signing) and [`assemble`] (packaging the
//! result into the envelope), the same `signing_input`/`assemble_*`
//! split every other signed document in this crate uses. The verify
//! path is complete: [`MoicaSignedCredential::verify_against`] checks
//! the whole chain offline.

use std::collections::BTreeMap;

use unicode_normalization::UnicodeNormalization;

use crate::credential::{selective_disclosure, verification_method_id, VerifiableCredential};
use crate::identity::did_key;
use crate::moica::issuer_certificate::{
    DistinguishedNameAttribute, IssuerCertificate, IssuerCertificateError, X509Certificate,
};

/// The only construction this build implements: the TBS is
/// `bonds-tw-credential-v1:` followed by the lowercase hex SHA-256 of
/// the payload bytes, as ASCII, and the signature is RSASSA-PKCS1-v1_5
/// over SHA-256 of that ASCII string.
pub const PAYLOAD_DIGEST_HEX_CONSTRUCTION: &str =
    "bonds-tw-credential-v1/payload-sha256-hex/RSASSA-PKCS1-v1_5-SHA256";

/// Domain separation for the TBS - stops *accidental* cross-protocol
/// signature reuse (an honest-but-different service asking the same
/// cardholder to sign a value that happens to be 64 hex characters),
/// not a malicious relying party (which can put any `sign_data` in
/// front of the card regardless).
pub const TBS_DOMAIN_PREFIX: &str = "bonds-tw-credential-v1:";

/// A PKCS#1 signature under an RSA-2048 key.
pub const SIGNATURE_BYTE_COUNT: usize = 256;

// MARK: - Errors

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MoicaSignedCredentialError {
    /// The envelope's `payload` is not base64url, or its bytes are not
    /// a credential this build can decode.
    #[error("malformed payload")]
    MalformedPayload,
    /// `proof.tbs_construction` names a rule this build does not
    /// implement. Refused rather than assumed - the construction
    /// decides *what* the cardholder's key covered.
    #[error("unsupported proof construction")]
    UnsupportedProofConstruction,
    /// `proof.certificate` is not valid base64 DER, or does not parse.
    #[error("certificate invalid: {0}")]
    CertificateInvalid(IssuerCertificateError),
    /// `proof.signature` is not base64, or is not the 256 bytes an
    /// RSA-2048 PKCS#1 signature occupies.
    #[error("malformed signature")]
    MalformedSignature,
    /// The signature does not verify under the certificate's key. Also
    /// what a tampered payload looks like, deliberately - the digest is
    /// recomputed from the payload on every verification, never stored.
    #[error("signature invalid")]
    SignatureInvalid,
    /// The credential names a did:key issuer, but the optional issuer
    /// JWS does not verify under that key or does not cover these exact
    /// payload bytes.
    #[error("issuer signature invalid")]
    IssuerSignatureInvalid,
    /// The certificate carries no common name.
    #[error("cardholder name missing")]
    CardholderNameMissing,
    /// The credential asserts no `name`, so a card signature over it
    /// binds to nobody in particular.
    #[error("credential name missing")]
    CredentialNameMissing,
    /// The certificate's common name and the credential's `name` claim
    /// are different people.
    #[error("cardholder name differs from subject")]
    CardholderNameDiffersFromSubject,
    /// A disclosure arrived that the card never committed to.
    #[error("disclosure not committed")]
    DisclosureNotCommitted,
}

// MARK: - The envelope

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MoicaCredentialProof {
    /// What the card's key actually covered, named rather than
    /// implied - see [`PAYLOAD_DIGEST_HEX_CONSTRUCTION`].
    #[serde(rename = "tbsConstruction")]
    pub tbs_construction: String,
    /// base64 DER of the cardholder's certificate, exactly as TW FidO's
    /// `result.cert` delivered it.
    pub certificate: String,
    /// base64 of TW FidO's `result.signed_response`.
    pub signature: String,
}

/// A credential plus the 自然人憑證 signature over it. See the module docs
/// for why this is deliberately not a JWS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MoicaSignedCredential {
    /// base64url of the credential's canonical bytes - the bytes, not
    /// the object, so a verifier never depends on its own JSON
    /// encoder producing the same output the issuing device's did.
    pub payload: String,
    pub proof: MoicaCredentialProof,
    /// A compact VC-JOSE-COSE signature by this national ID's own
    /// did:key. Optional only for backward compatibility with
    /// credentials stored before per-card issuer keys existed.
    #[serde(rename = "issuerJWS", skip_serializing_if = "Option::is_none")]
    pub issuer_jws: Option<String>,
    /// The disclosures that open the credential's committed digests,
    /// when it has any. Not signed again - each disclosure's digest is
    /// already in the payload the card signed, so an altered disclosure
    /// no longer matches any commitment.
    #[serde(default)]
    pub disclosures: Vec<String>,
}

impl MoicaSignedCredential {
    pub fn payload_bytes(&self) -> Result<Vec<u8>, MoicaSignedCredentialError> {
        base64url_decode(&self.payload).ok_or(MoicaSignedCredentialError::MalformedPayload)
    }

    /// The credential inside `payload`, decoded on demand rather than
    /// stored beside the bytes so there is no way for the two to
    /// disagree about what this document says.
    pub fn credential(&self) -> Result<VerifiableCredential, MoicaSignedCredentialError> {
        let bytes = self.payload_bytes()?;
        serde_json::from_slice(&bytes).map_err(|_| MoicaSignedCredentialError::MalformedPayload)
    }

    /// The form that goes on disk and into a presentation. JSON, not a
    /// dot-separated compact string - a compact form here would look
    /// exactly like a JWS while verifying under different rules.
    pub fn serialized(&self) -> Result<String, MoicaSignedCredentialError> {
        serde_json::to_string(self).map_err(|_| MoicaSignedCredentialError::MalformedPayload)
    }

    pub fn parse(serialized: &str) -> Result<Self, MoicaSignedCredentialError> {
        serde_json::from_str(serialized).map_err(|_| MoicaSignedCredentialError::MalformedPayload)
    }

    /// Checks the whole chain, offline, against the bundled trust
    /// anchor, and returns what it establishes. Admitting the
    /// certificate first, because it is the check with the most
    /// actionable failure.
    pub fn verify_against(
        &self,
        anchor: &IssuerCertificate,
        now_unix_seconds: i64,
    ) -> Result<MoicaCredentialVerification, MoicaSignedCredentialError> {
        let holder = X509Certificate::parse_base64_der(&self.proof.certificate)
            .map_err(MoicaSignedCredentialError::CertificateInvalid)?;
        anchor
            .validate_holder_certificate(&holder, now_unix_seconds)
            .map_err(MoicaSignedCredentialError::CertificateInvalid)?;
        self.verify_signed_by(&holder)
    }

    /// Everything the trust anchor is not needed for - the logic that
    /// is this project's own, reachable with a throwaway key.
    ///
    /// ⚠️ Never call this directly from a verification path: on its own
    /// it establishes that *some* certificate signed these fields, and
    /// the holder chooses which certificate travels in the envelope -
    /// without the anchor step it accepts a credential signed by a key
    /// the holder generated a moment ago.
    pub fn verify_signed_by(
        &self,
        holder: &X509Certificate,
    ) -> Result<MoicaCredentialVerification, MoicaSignedCredentialError> {
        let payload_bytes = self.payload_bytes()?;
        let credential = self.credential()?;

        if let Some(issuer_jws) = &self.issuer_jws {
            verify_issuer_jws(issuer_jws, &payload_bytes, &credential.issuer)?;
        }

        if self.proof.tbs_construction != PAYLOAD_DIGEST_HEX_CONSTRUCTION {
            return Err(MoicaSignedCredentialError::UnsupportedProofConstruction);
        }

        let signature = base64_decode_standard(&self.proof.signature)
            .ok_or(MoicaSignedCredentialError::MalformedSignature)?;
        if signature.len() != SIGNATURE_BYTE_COUNT {
            return Err(MoicaSignedCredentialError::MalformedSignature);
        }

        // The signed bytes are the domain-prefixed digest *string*, not
        // the digest's raw bytes - see `PAYLOAD_DIGEST_HEX_CONSTRUCTION`.
        let digest = VerifiableCredential::digest_hex(&payload_bytes);
        let tbs = format!("{TBS_DOMAIN_PREFIX}{digest}");
        let verified = holder
            .verifies_pkcs1_sha256(&signature, tbs.as_bytes())
            .map_err(|_| MoicaSignedCredentialError::SignatureInvalid)?;
        if !verified {
            return Err(MoicaSignedCredentialError::SignatureInvalid);
        }

        let cardholder_name = holder
            .subject_attribute(DistinguishedNameAttribute::CommonName)
            .map_err(|_| MoicaSignedCredentialError::CardholderNameMissing)?
            .filter(|name| !name.is_empty())
            .ok_or(MoicaSignedCredentialError::CardholderNameMissing)?;

        // Open whatever the holder chose to hand over. Every disclosure
        // must match a digest the card signed; one that does not is a
        // holder trying to add a claim, and `reveal` refuses the whole set.
        let (opened, withheld): (BTreeMap<String, String>, usize) =
            if let Some(committed) = &credential.sd {
                let revealed = selective_disclosure::reveal(&self.disclosures, committed)
                    .map_err(|_| MoicaSignedCredentialError::DisclosureNotCommitted)?;
                let withheld = selective_disclosure::withheld_count(committed, revealed.len());
                (revealed.into_iter().collect(), withheld)
            } else {
                let mut opened = credential.credential_subject.clone();
                opened.remove("id");
                (opened, 0)
            };

        // The name binding runs only when a name was disclosed -
        // skipping it (when withheld) is not the same as failing it:
        // 內政部 routes the SIGN request to the cardholder named by
        // id_num, so the claims a card signed are that cardholder's
        // whether or not a verifier can re-derive it here.
        let mut cardholder_name_was_checked = false;
        if let Some(subject_name) = opened.get("name").filter(|n| !n.is_empty()) {
            let normalized_cardholder: String = cardholder_name.nfc().collect();
            let normalized_subject: String = subject_name.nfc().collect();
            if normalized_cardholder != normalized_subject {
                return Err(MoicaSignedCredentialError::CardholderNameDiffersFromSubject);
            }
            cardholder_name_was_checked = true;
        } else if credential.sd.is_none() {
            // A plain credential with no name is one this build refuses
            // to have issued - there is nothing for the card signature
            // to bind to.
            return Err(MoicaSignedCredentialError::CredentialNameMissing);
        }

        Ok(MoicaCredentialVerification {
            credential,
            cardholder_name,
            claims: opened,
            withheld_claim_count: withheld,
            cardholder_name_was_checked,
            certificate_serial_number_hex: holder.serial_number_hex(),
        })
    }
}

/// What a verified card-signed credential turned out to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoicaCredentialVerification {
    pub credential: VerifiableCredential,
    /// The cardholder's name, from the certificate's Subject DN. Equal
    /// to the credential's `name` claim when one was disclosed -
    /// verification refuses otherwise.
    pub cardholder_name: String,
    /// The claims this presentation actually opened: every claim for a
    /// plain credential, or the revealed subset for a
    /// selectively-disclosable one.
    pub claims: BTreeMap<String, String>,
    /// How many committed claims were held back. Zero for a plain
    /// credential, which has nothing to hold back.
    pub withheld_claim_count: usize,
    /// Whether the certificate's common name was checked against a
    /// `name` claim. `false` when the holder withheld `name` - a screen
    /// must not report this as though the name had been confirmed.
    pub cardholder_name_was_checked: bool,
    /// The certificate's own serial number, lowercase hex.
    ///
    /// ⚠️ A stable per-certificate correlator, and a 自然人憑證 lasts a
    /// year - showing it to a verifier makes two presentations
    /// linkable. Carried because revocation checking needs it, not
    /// because it is safe to display.
    pub certificate_serial_number_hex: String,
}

// MARK: - Issuing (the pieces that don't need platform signing)

/// The ASCII string to put in `sign_data` for `credential`, and the
/// bytes it covers - joined here so there is exactly one place that
/// knows the TBS's shape, and so a caller cannot hash one serialization
/// while storing another.
pub fn to_be_signed(
    credential: &VerifiableCredential,
) -> Result<(String, Vec<u8>), MoicaSignedCredentialError> {
    let bytes = credential
        .canonical_bytes()
        .map_err(|_| MoicaSignedCredentialError::MalformedPayload)?;
    let tbs = format!(
        "{TBS_DOMAIN_PREFIX}{}",
        VerifiableCredential::digest_hex(&bytes)
    );
    Ok((tbs, bytes))
}

/// Packages a completed TW FidO SIGN round trip into the envelope.
/// Native signing produced `certificate_base64_der`/`signature_base64`
/// over the TBS [`to_be_signed`] returned for `payload_bytes`; this
/// only assembles them - it does not itself verify the result. Callers
/// should call [`MoicaSignedCredential::verify_against`] immediately
/// after, the same "verify at issuance" discipline the Swift source
/// documents: everything that can go wrong here is otherwise silent
/// until somebody tries to present the document, at a counter, to a
/// stranger, offline.
pub fn assemble(
    payload_bytes: &[u8],
    certificate_base64_der: String,
    signature_base64: String,
    issuer_jws: Option<String>,
    disclosures: Vec<String>,
) -> MoicaSignedCredential {
    MoicaSignedCredential {
        payload: base64url_encode(payload_bytes),
        proof: MoicaCredentialProof {
            tbs_construction: PAYLOAD_DIGEST_HEX_CONSTRUCTION.to_string(),
            certificate: certificate_base64_der,
            signature: signature_base64,
        },
        issuer_jws,
        disclosures,
    }
}

/// Checks the national ID's own did:key signature without re-encoding
/// the credential. The payload segment has to be byte-for-byte the
/// payload the 自然人憑證 also signed; otherwise two individually valid
/// signatures could be made to describe two different documents inside
/// one envelope.
fn verify_issuer_jws(
    compact: &str,
    expected_payload: &[u8],
    issuer_did: &str,
) -> Result<(), MoicaSignedCredentialError> {
    let parts: Vec<&str> = compact.split('.').collect();
    let [header_b64, payload_b64, signature_b64] = parts.as_slice() else {
        return Err(MoicaSignedCredentialError::IssuerSignatureInvalid);
    };

    let header_bytes =
        base64url_decode(header_b64).ok_or(MoicaSignedCredentialError::IssuerSignatureInvalid)?;
    let payload_bytes =
        base64url_decode(payload_b64).ok_or(MoicaSignedCredentialError::IssuerSignatureInvalid)?;
    let signature_bytes = base64url_decode(signature_b64)
        .ok_or(MoicaSignedCredentialError::IssuerSignatureInvalid)?;
    if payload_bytes != expected_payload || signature_bytes.len() != 64 {
        return Err(MoicaSignedCredentialError::IssuerSignatureInvalid);
    }

    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| MoicaSignedCredentialError::IssuerSignatureInvalid)?;
    let expected_kid = verification_method_id(issuer_did)
        .map_err(|_| MoicaSignedCredentialError::IssuerSignatureInvalid)?;
    let ok = header.get("alg").and_then(|v| v.as_str()) == Some("ES256")
        && header.get("typ").and_then(|v| v.as_str()) == Some("vc+jwt")
        && header.get("cty").and_then(|v| v.as_str()) == Some("vc")
        && header.get("kid").and_then(|v| v.as_str()) == Some(expected_kid.as_str());
    if !ok {
        return Err(MoicaSignedCredentialError::IssuerSignatureInvalid);
    }

    let public_key = did_key::p256_public_key_from_did(issuer_did)
        .map_err(|_| MoicaSignedCredentialError::IssuerSignatureInvalid)?;
    let signature = p256::ecdsa::Signature::from_slice(&signature_bytes)
        .map_err(|_| MoicaSignedCredentialError::IssuerSignatureInvalid)?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(&public_key);
    let signing_input = format!("{header_b64}.{payload_b64}");

    use p256::ecdsa::signature::Verifier;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| MoicaSignedCredentialError::IssuerSignatureInvalid)
}

fn base64url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn base64url_decode(segment: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(segment).ok()
}

fn base64_decode_standard(segment: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(segment).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{national_id, selectively_disclosable_national_id, NationalIdModel};
    use crate::moica::issuer_certificate::test_certificate;
    use chrono::{TimeZone, Utc};
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use sha2::Digest;

    fn now() -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(1_757_000_000, 0).unwrap()
    }

    fn model() -> NationalIdModel {
        NationalIdModel {
            nationality: Some("TW".to_string()),
            unified_no: Some("A123456789".to_string()),
            name: Some("陳筱玲".to_string()),
            birthdate: Some("0700605".to_string()),
            address_of_household: None,
        }
    }

    fn signed_envelope(
        credential: &VerifiableCredential,
        disclosures: Vec<String>,
        holder_key: &RsaPrivateKey,
    ) -> MoicaSignedCredential {
        let (tbs, payload_bytes) = to_be_signed(credential).unwrap();
        let hashed = sha2::Sha256::digest(tbs.as_bytes());
        let signature = holder_key
            .sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed)
            .unwrap();
        assemble(
            &payload_bytes,
            base64_encode_standard(&[0x30, 0x00]), // placeholder "certificate" bytes - verify_signed_by never re-parses this field
            base64_encode_standard(&signature),
            None,
            disclosures,
        )
    }

    fn base64_encode_standard(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(bytes)
    }

    #[test]
    fn a_plain_credential_verifies_and_binds_the_cardholder_name() {
        let holder_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let credential = national_id(&model(), "did:key:zSelfIssued", now());
        let envelope = signed_envelope(&credential, Vec::new(), &holder_key);
        let holder_certificate = test_certificate("陳筱玲", &holder_key.to_public_key());

        let verification = envelope.verify_signed_by(&holder_certificate).unwrap();
        assert_eq!(verification.cardholder_name, "陳筱玲");
        assert!(verification.cardholder_name_was_checked);
        assert_eq!(verification.withheld_claim_count, 0);
        assert_eq!(
            verification.claims.get("nationality"),
            Some(&"TW".to_string())
        );
    }

    #[test]
    fn a_selectively_disclosable_credential_opens_only_the_chosen_claims() {
        let holder_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let (credential, disclosures) =
            selectively_disclosable_national_id(&model(), "did:key:zSelfIssued", now());
        let chosen: Vec<String> = disclosures
            .iter()
            .filter(|d| d.claim_name == "name")
            .map(|d| d.encoded.clone())
            .collect();
        let envelope = signed_envelope(&credential, chosen, &holder_key);
        let holder_certificate = test_certificate("陳筱玲", &holder_key.to_public_key());

        let verification = envelope.verify_signed_by(&holder_certificate).unwrap();
        assert_eq!(verification.claims.len(), 1);
        assert_eq!(verification.claims.get("name"), Some(&"陳筱玲".to_string()));
        assert!(verification.cardholder_name_was_checked);
        assert!(verification.withheld_claim_count > 0);
    }

    #[test]
    fn withholding_name_skips_the_binding_check_rather_than_failing_it() {
        let holder_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let (credential, disclosures) =
            selectively_disclosable_national_id(&model(), "did:key:zSelfIssued", now());
        let chosen: Vec<String> = disclosures
            .iter()
            .filter(|d| d.claim_name == "nationality")
            .map(|d| d.encoded.clone())
            .collect();
        let envelope = signed_envelope(&credential, chosen, &holder_key);
        // A cardholder certificate for a different name entirely - if the
        // binding ran, this would fail with CardholderNameDiffersFromSubject.
        let holder_certificate = test_certificate("不同的人", &holder_key.to_public_key());

        let verification = envelope.verify_signed_by(&holder_certificate).unwrap();
        assert!(!verification.cardholder_name_was_checked);
        assert!(!verification.claims.contains_key("name"));
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let holder_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let credential = national_id(&model(), "did:key:zSelfIssued", now());
        let mut envelope = signed_envelope(&credential, Vec::new(), &holder_key);
        let holder_certificate = test_certificate("陳筱玲", &holder_key.to_public_key());

        // Edit the payload after signing - the digest recomputed at
        // verification time no longer matches what was actually signed.
        let mut credential = envelope.credential().unwrap();
        credential
            .credential_subject
            .insert("nationality".to_string(), "US".to_string());
        envelope.payload = base64url_encode(&credential.canonical_bytes().unwrap());

        assert_eq!(
            envelope.verify_signed_by(&holder_certificate),
            Err(MoicaSignedCredentialError::SignatureInvalid)
        );
    }

    #[test]
    fn a_name_signed_by_a_different_cardholder_is_refused() {
        let holder_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let credential = national_id(&model(), "did:key:zSelfIssued", now());
        let envelope = signed_envelope(&credential, Vec::new(), &holder_key);
        // Same key (so the signature still verifies), different subject CN.
        let wrong_certificate = test_certificate("完全不同的名字", &holder_key.to_public_key());

        assert_eq!(
            envelope.verify_signed_by(&wrong_certificate),
            Err(MoicaSignedCredentialError::CardholderNameDiffersFromSubject)
        );
    }

    #[test]
    fn a_disclosure_the_card_never_committed_to_is_refused() {
        let holder_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let (credential, _disclosures) =
            selectively_disclosable_national_id(&model(), "did:key:zSelfIssued", now());
        // A disclosure for a claim/value the issuer never committed a digest to.
        let forged =
            crate::credential::selective_disclosure::Disclosure::new("name", "偽造姓名").encoded;
        let envelope = signed_envelope(&credential, vec![forged], &holder_key);
        let holder_certificate = test_certificate("陳筱玲", &holder_key.to_public_key());

        assert_eq!(
            envelope.verify_signed_by(&holder_certificate),
            Err(MoicaSignedCredentialError::DisclosureNotCommitted)
        );
    }

    #[test]
    fn the_envelope_round_trips_through_serialization() {
        let holder_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let credential = national_id(&model(), "did:key:zSelfIssued", now());
        let envelope = signed_envelope(&credential, Vec::new(), &holder_key);

        let serialized = envelope.serialized().unwrap();
        let parsed = MoicaSignedCredential::parse(&serialized).unwrap();
        assert_eq!(parsed, envelope);
    }
}
