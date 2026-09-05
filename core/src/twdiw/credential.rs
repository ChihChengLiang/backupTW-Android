//! Reading a credential issued by 台灣數位憑證皮夾（TWDIW）.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/TWDIWCredential.swift`. See
//! that file for the full rationale — this is a real SD-JWT carried
//! inside a real W3C VCDM 1.1 `vc` claim (`_sd` lives in
//! `vc.credentialSubject`, the type is `vc.type[1]`), despite the issuer
//! metadata claiming `"format": "jwt_vc_json"` for 100% of production
//! configurations; the `~` separator is the only signal that it's SD-JWT
//! at all.
//!
//! **The key comes from `iss`, never from the header's `jku`.** All 43
//! production trust-list issuers embed a usable key in their `did:key`, so
//! following `jku` (a URL the token itself names) could only ever add an
//! attacker-influenced network fetch, never obtain a key `iss` lacks.
//! `jku`/`kid` are still parsed out and kept on the credential for
//! diagnostics — they just get no vote in verification.
//!
//! **Where this does not help: revocation.** The status list is signed by
//! a *different* key than the one in the issuer's DID (measured: the DID
//! publishes `key-1`, status lists are signed by `key-2`). This reader
//! records `status` and leaves checking it to a caller that is online -
//! there is no offline-checkable trust anchor for it at all.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::signature::Verifier;

use crate::credential::selective_disclosure::{self, DisclosureError};
use crate::identity::jwk_did_key;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TwdiwCredentialError {
    /// Not three dot-separated parts before the first `~`.
    #[error("malformed compact serialization")]
    MalformedCompactSerialization,
    /// A part that is not base64url, or whose bytes are not a JSON object.
    #[error("malformed JSON in {part}")]
    MalformedJson { part: &'static str },
    /// `alg` is not `ES256`. Refused rather than trusted: `none` and the
    /// HMAC-for-RSA confusion are the two oldest JWT forgeries there are,
    /// and both begin with a verifier that reads `alg` from the token.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// `typ` is not one this reader knows.
    #[error("unexpected type: {0}")]
    UnexpectedType(String),
    /// `iss`, `sub`, `cnf.jwk`, `vc.type` or `credentialSubject` missing.
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    /// The issuer DID is not a DID this reader can turn into a key.
    #[error("unresolvable issuer")]
    UnresolvableIssuer,
    /// The signature does not verify under the key the issuer's DID names.
    #[error("signature invalid")]
    SignatureInvalid,
    /// `_sd_alg` is present and is not `sha-256`.
    #[error("unsupported digest algorithm: {0}")]
    UnsupportedDigestAlgorithm(String),
    /// A disclosure whose digest the issuer never committed to. The red
    /// line: a holder who could add one could assert anything.
    #[error("undisclosed digest: {0}")]
    UndisclosedDigest(String),
    /// A disclosure that is not a three-element array of strings.
    #[error("malformed disclosure")]
    MalformedDisclosure,
}

/// `vc.credentialStatus`, a StatusList2021 entry.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TwdiwStatusListEntry {
    pub status_list_url: String,
    pub index: i64,
    pub purpose: String,
}

/// A credential in TWDIW's shape, read and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwdiwCredential {
    /// The compact form as received: `<jwt>~<d1>~<d2>~…~`.
    pub serialized: String,
    pub issuer_did: String,
    pub subject_did: String,
    /// The issuer-assigned credential identifier from the signed JWT `jti`.
    pub credential_id: Option<String>,
    /// `vc.type[1]` — the issuer's own opaque identifier for this kind of
    /// card. **This is the only thing distinguishing an identity-proofed
    /// credential from a self-asserted one** — TWDIW carries no IAL, so
    /// what a card can be relied on for is a function of who issued it and
    /// this string, and of nothing else in the credential.
    pub credential_type: String,
    /// Unix timestamp, seconds.
    pub not_before: i64,
    /// Unix timestamp, seconds. `i64::MAX` (this reader's "distant
    /// future") when `exp` is absent.
    pub expires: i64,
    /// The key the credential is bound to, from `cnf.jwk` — X9.63
    /// uncompressed (`0x04 ‖ X ‖ Y`, 65 bytes). The holder proved
    /// possession of it during issuance, so a presentation not signed by
    /// it is not this credential's holder presenting.
    pub holder_key_x963: Vec<u8>,
    pub status: Option<TwdiwStatusListEntry>,
    /// `vc.credentialSchema.id`, if present. Not fetched — recorded.
    pub schema_url: Option<String>,
    /// **Retained, never followed** — see the module docs.
    pub declared_key_source_url: Option<String>,
    pub declared_key_id: Option<String>,
    /// The digests the issuer committed to, in the order they appeared.
    pub commitments: Vec<String>,
    /// The claims the disclosures actually reveal, in disclosure order.
    pub disclosed_claims: Vec<(String, String)>,
}

/// `typ` values this reader accepts. `vc+sd-jwt` is what production
/// emits; `dc+sd-jwt` is the registered media type the IETF work settled
/// on, accepted so a future TWDIW update doesn't make cards already in
/// wallets unreadable.
const ACCEPTED_TYPES: [&str; 2] = ["vc+sd-jwt", "dc+sd-jwt"];

/// Turns TWDIW's wire form into a [`TwdiwCredential`], or refuses it.
pub fn read(serialized: &str, now: i64) -> Result<TwdiwCredential, TwdiwCredentialError> {
    let parts: Vec<&str> = serialized.split('~').collect();
    let jwt = *parts
        .first()
        .ok_or(TwdiwCredentialError::MalformedCompactSerialization)?;
    // A trailing `~` produces a final empty element; anything else empty
    // in the middle is a malformed serialization rather than a disclosure.
    let disclosure_strings: Vec<&str> = parts[1..]
        .iter()
        .copied()
        .filter(|s| !s.is_empty())
        .collect();

    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    let [header_part, payload_part, signature_part] = jwt_parts.as_slice() else {
        return Err(TwdiwCredentialError::MalformedCompactSerialization);
    };

    let header = json_object(header_part, "header")?;
    let payload = json_object(payload_part, "payload")?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if alg != "ES256" {
        return Err(TwdiwCredentialError::UnsupportedAlgorithm(alg));
    }
    if let Some(typ) = header.get("typ").and_then(|v| v.as_str()) {
        if !ACCEPTED_TYPES.contains(&typ) {
            return Err(TwdiwCredentialError::UnexpectedType(typ.to_string()));
        }
    }

    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or(TwdiwCredentialError::MissingClaim("iss"))?
        .to_string();
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(TwdiwCredentialError::MissingClaim("sub"))?
        .to_string();

    // Signature first: nothing below this line should be read out of a
    // document whose issuer has not been established.
    let issuer_key = jwk_did_key::p256_public_key_from_did(&iss)
        .map_err(|_| TwdiwCredentialError::UnresolvableIssuer)?;
    verify(header_part, payload_part, signature_part, &issuer_key)?;

    let holder_key_x963 = payload
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .and_then(|jwk| serde_json::to_vec(jwk).ok())
        .and_then(|bytes| jwk_did_key::p256_public_key_from_jwk_bytes(&bytes).ok())
        .map(|key| {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            key.to_encoded_point(false).as_bytes().to_vec()
        })
        .ok_or(TwdiwCredentialError::MissingClaim("cnf.jwk"))?;

    let vc = payload
        .get("vc")
        .and_then(|v| v.as_object())
        .ok_or(TwdiwCredentialError::MissingClaim("vc"))?;
    let types: Vec<String> = vc
        .get("type")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if types.len() < 2 {
        return Err(TwdiwCredentialError::MissingClaim("vc.type"));
    }
    let subject = vc
        .get("credentialSubject")
        .and_then(|v| v.as_object())
        .ok_or(TwdiwCredentialError::MissingClaim("vc.credentialSubject"))?;

    if let Some(digest_algorithm) = subject.get("_sd_alg").and_then(|v| v.as_str()) {
        if digest_algorithm != "sha-256" {
            return Err(TwdiwCredentialError::UnsupportedDigestAlgorithm(
                digest_algorithm.to_string(),
            ));
        }
    }
    let commitments: Vec<String> = subject
        .get("_sd")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let disclosed_strings: Vec<String> = disclosure_strings.iter().map(|s| s.to_string()).collect();
    let claims = selective_disclosure::reveal(&disclosed_strings, &commitments).map_err(
        |error| match error {
            DisclosureError::UndisclosedDigest(digest) => {
                TwdiwCredentialError::UndisclosedDigest(digest)
            }
            _ => TwdiwCredentialError::MalformedDisclosure,
        },
    )?;

    Ok(TwdiwCredential {
        serialized: serialized.to_string(),
        issuer_did: iss,
        subject_did: sub,
        credential_id: payload
            .get("jti")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        credential_type: types[1].clone(),
        not_before: payload.get("nbf").and_then(number_as_i64).unwrap_or(now),
        expires: payload
            .get("exp")
            .and_then(number_as_i64)
            .unwrap_or(i64::MAX),
        holder_key_x963,
        status: status_entry(vc.get("credentialStatus")),
        schema_url: vc
            .get("credentialSchema")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        declared_key_source_url: header
            .get("jku")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        declared_key_id: header
            .get("kid")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        commitments,
        disclosed_claims: claims,
    })
}

// MARK: - Plumbing

fn json_object(
    part: &str,
    name: &'static str,
) -> Result<serde_json::Map<String, serde_json::Value>, TwdiwCredentialError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| TwdiwCredentialError::MalformedJson { part: name })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| TwdiwCredentialError::MalformedJson { part: name })?;
    value
        .as_object()
        .cloned()
        .ok_or(TwdiwCredentialError::MalformedJson { part: name })
}

/// ES256 over `base64url(header).base64url(payload)`. The signature is
/// the JOSE fixed-width `r ‖ s` pair, not a DER encoding.
fn verify(
    header_part: &str,
    payload_part: &str,
    signature_part: &str,
    key: &p256::PublicKey,
) -> Result<(), TwdiwCredentialError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| TwdiwCredentialError::SignatureInvalid)?;
    let signature = p256::ecdsa::Signature::from_slice(&signature_bytes)
        .map_err(|_| TwdiwCredentialError::SignatureInvalid)?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(key);
    let signing_input = format!("{header_part}.{payload_part}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| TwdiwCredentialError::SignatureInvalid)
}

fn number_as_i64(value: &serde_json::Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_f64().map(|f| f as i64))
}

fn status_entry(value: Option<&serde_json::Value>) -> Option<TwdiwStatusListEntry> {
    let status = value?.as_object()?;
    let url = status.get("statusListCredential")?.as_str()?.to_string();
    let purpose = status.get("statusPurpose")?.as_str()?.to_string();
    // `statusListIndex` is a *string* in production, not a number.
    // Accepting both because the type of an index is exactly the sort of
    // thing that changes between releases, and reading it wrong means
    // checking somebody else's revocation bit.
    let index = match status.get("statusListIndex") {
        Some(serde_json::Value::String(s)) => s.parse::<i64>().ok(),
        Some(v) => v.as_i64(),
        None => None,
    }?;
    Some(TwdiwStatusListEntry {
        status_list_url: url,
        index,
        purpose,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::selective_disclosure::Disclosure;
    use crate::identity::{did_key, jwk_did_key};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    // MARK: - The measured fact: real production digests

    /// The six disclosures of a real 駕照電子卡, exactly as they appeared
    /// after the `~` separators (a driving licence issued 2025-10-07,
    /// TWDIW's own published sample).
    const PRODUCTION_DISCLOSURES: [&str; 6] = [
        "WyJhOFNHY1VKY2RYTW1aM2VTVVM2eERRIiwibmFtZSIsIumZs-etseeOsiJd",
        "WyJwbHowWFN6LW9CSEUwZTUzTFVBeWNBIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd",
        "WyJOdGVYcHFIQWNWZ2p2dXpKQUxJQVpBIiwicm9jX2JpcnRoZGF5IiwiMDU3MDYwNSJd",
        "WyI3RUFnQWFGamVSUlBZUV9kSURwZUhBIiwidHlwZSIsIuaZrumAmuWwj-Wei-i7iiJd",
        "WyJ1NzNEMGs1N252ZUFncUlzMmVQTFJnIiwiY29udHJvbG51bWJlciIsIjQwMTA0MDIwOTE0NDUiXQ",
        "WyJwdENBU0Fvc25BX0RuN2JzRGlGektBIiwiZ0RhdGUiLCIxMDIwNzAxIl0",
    ];

    /// The first two entries of that credential's `vc.credentialSubject._sd`.
    const PRODUCTION_COMMITMENTS: [&str; 2] = [
        "ApkeYAR85EzxAHS1ojnNHhG7wnCDyTt4_iCIX2VKxaw",
        "PDVMnTCDSl0gJrzo9xUwoAhI8YkTZP1BfPiPrCO8tho",
    ];

    #[test]
    fn the_digest_algorithm_matches_production() {
        for (digest, expected_name) in [
            (PRODUCTION_COMMITMENTS[0], "id_number"),
            (PRODUCTION_COMMITMENTS[1], "roc_birthday"),
        ] {
            let matching = PRODUCTION_DISCLOSURES.iter().find(|d| {
                Disclosure::decode(d).map(|dis| dis.digest()) == Some(digest.to_string())
            });
            let name = matching
                .and_then(|d| Disclosure::decode(d))
                .map(|d| d.claim_name);
            assert_eq!(name.as_deref(), Some(expected_name));
        }
    }

    #[test]
    fn the_production_disclosures_decode_to_their_published_values() {
        let claims: Vec<Disclosure> = PRODUCTION_DISCLOSURES
            .iter()
            .filter_map(|d| Disclosure::decode(d))
            .collect();
        assert_eq!(claims.len(), 6);
        let by_name = |name: &str| {
            claims
                .iter()
                .find(|d| d.claim_name == name)
                .map(|d| d.claim_value.clone())
        };
        assert_eq!(by_name("name").as_deref(), Some("陳筱玲"));
        let id_number = by_name("id_number").unwrap();
        assert_eq!(id_number, "A234567890");
        assert_eq!(id_number.chars().count(), 10);
        assert_eq!(by_name("roc_birthday").as_deref(), Some("0570605"));
        assert_eq!(by_name("type").as_deref(), Some("普通小型車"));
        assert_eq!(by_name("controlnumber").as_deref(), Some("4010402091445"));
        assert_eq!(by_name("gDate").as_deref(), Some("1020701"));
    }

    #[test]
    fn the_committed_digests_are_sorted_not_in_claim_order() {
        let mut sorted: Vec<String> = PRODUCTION_DISCLOSURES
            .iter()
            .filter_map(|d| Disclosure::decode(d))
            .map(|d| d.digest())
            .collect();
        sorted.sort();
        assert_eq!(&sorted[..2], &PRODUCTION_COMMITMENTS[..]);
        let unsorted: Vec<String> = PRODUCTION_DISCLOSURES
            .iter()
            .filter_map(|d| Disclosure::decode(d))
            .map(|d| d.digest())
            .collect();
        assert_ne!(sorted, unsorted);
    }

    // MARK: - The container

    const CREDENTIAL_TYPE: &str = "00000000_demo_drivinglicense_202504251418";
    const CREDENTIAL_ID: &str =
        "https://issuer-vc.wallet.gov.tw/api/credential/39d60715-e90c-402a-98aa-test";
    const JKU: &str = "https://issuer-vc.wallet.gov.tw/api/keys";
    const SCHEMA_URL: &str = "https://frontend.wallet.gov.tw/api/schema/00000000/demo/V1/b653ad4b";
    const STATUS_LIST_URL: &str =
        "https://issuer-vc.wallet.gov.tw/api/status-list/00000000_demo_drivinglicense_202504251418/r0";

    struct Fixture {
        issuer_key: SigningKey,
        holder_key: SigningKey,
        disclosures: Vec<Disclosure>,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                issuer_key: SigningKey::random(&mut OsRng),
                holder_key: SigningKey::random(&mut OsRng),
                disclosures: vec![
                    Disclosure::new("name", "陳筱玲"),
                    Disclosure::new("id_number", "A234567890"),
                    Disclosure::new("roc_birthday", "0570605"),
                ],
            }
        }

        fn holder_x963(&self) -> Vec<u8> {
            let vk: p256::ecdsa::VerifyingKey = *self.holder_key.verifying_key();
            vk.to_encoded_point(false).as_bytes().to_vec()
        }

        fn issuer_x963(&self) -> Vec<u8> {
            let vk: p256::ecdsa::VerifyingKey = *self.issuer_key.verifying_key();
            vk.to_encoded_point(false).as_bytes().to_vec()
        }

        fn issuer_did(&self) -> String {
            jwk_did_key::did_from_p256_x963(&self.issuer_x963()).unwrap()
        }

        fn holder_did(&self) -> String {
            jwk_did_key::did_from_p256_x963(&self.holder_x963()).unwrap()
        }

        fn serialized(&self) -> String {
            self.build(&Options::default())
        }

        fn withholding_all_but(&self, name: &str) -> String {
            let present: Vec<Disclosure> = self
                .disclosures
                .iter()
                .filter(|d| d.claim_name == name)
                .cloned()
                .collect();
            self.build(&Options {
                present: Some(present),
                ..Default::default()
            })
        }

        fn adding(&self, extra: Disclosure) -> String {
            let mut present = self.disclosures.clone();
            present.push(extra);
            self.build(&Options {
                present: Some(present),
                ..Default::default()
            })
        }

        fn resigned_by_a_stranger(&self, claiming_key_source: Option<&str>) -> String {
            let stranger = SigningKey::random(&mut OsRng);
            self.build(&Options {
                signed_by: Some(stranger),
                jku: claiming_key_source.map(str::to_owned),
                ..Default::default()
            })
        }

        fn with_header_algorithm(&self, alg: &str) -> String {
            self.build(&Options {
                algorithm: Some(alg.to_owned()),
                ..Default::default()
            })
        }

        fn with_digest_algorithm(&self, alg: &str) -> String {
            self.build(&Options {
                digest_algorithm: Some(alg.to_owned()),
                ..Default::default()
            })
        }

        fn with_p256_pub_issuer_did(&self) -> String {
            let alt = did_key::did_from_p256_x963(&self.issuer_x963()).unwrap();
            self.build(&Options {
                issuer_did_override: Some(alt),
                ..Default::default()
            })
        }

        fn with_tampered_type(&self) -> String {
            let serialized = self.serialized();
            let mut parts: Vec<String> = serialized.split('~').map(str::to_owned).collect();
            let jwt_parts: Vec<String> = parts[0].split('.').map(str::to_owned).collect();
            let payload_bytes = URL_SAFE_NO_PAD.decode(&jwt_parts[1]).unwrap();
            let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
            payload["vc"]["type"] =
                serde_json::json!(["VerifiableCredential", "00000000_something_else"]);
            let canonical = serde_json::to_value(&payload).unwrap();
            let edited = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&canonical).unwrap());
            let rebuilt = format!("{}.{}.{}", jwt_parts[0], edited, jwt_parts[2]);
            parts[0] = rebuilt;
            parts.join("~")
        }

        fn build(&self, options: &Options) -> String {
            let header = serde_json::json!({
                "jku": options.jku.clone().unwrap_or_else(|| JKU.to_string()),
                "kid": "key-1",
                "typ": "vc+sd-jwt",
                "alg": options.algorithm.clone().unwrap_or_else(|| "ES256".to_string()),
            });
            let holder_x963 = self.holder_x963();
            let holder_jwk_bytes =
                jwk_did_key::canonical_jwk(&holder_x963[1..33], &holder_x963[33..65]);
            let holder_jwk: serde_json::Value = serde_json::from_slice(&holder_jwk_bytes).unwrap();

            let disclosures = options
                .present
                .clone()
                .unwrap_or_else(|| self.disclosures.clone());
            let mut sorted_digests: Vec<String> =
                self.disclosures.iter().map(|d| d.digest()).collect();
            sorted_digests.sort();

            let payload = serde_json::json!({
                "iss": options.issuer_did_override.clone().unwrap_or_else(|| self.issuer_did()),
                "sub": self.holder_did(),
                "jti": CREDENTIAL_ID,
                "nbf": 1_759_823_761i64,
                "exp": 2_075_356_561i64,
                "cnf": {"jwk": holder_jwk},
                "vc": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", CREDENTIAL_TYPE],
                    "credentialStatus": {
                        "type": "StatusList2021Entry",
                        "id": format!("{STATUS_LIST_URL}#35"),
                        "statusListIndex": "35",
                        "statusListCredential": STATUS_LIST_URL,
                        "statusPurpose": "revocation",
                    },
                    "credentialSchema": {"id": SCHEMA_URL, "type": "JsonSchema"},
                    "credentialSubject": {
                        "_sd": sorted_digests,
                        "_sd_alg": options.digest_algorithm.clone().unwrap_or_else(|| "sha-256".to_string()),
                    },
                },
            });

            let encoded_header = URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&serde_json::to_value(&header).unwrap()).unwrap());
            let encoded_payload = URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&serde_json::to_value(&payload).unwrap()).unwrap());
            let signing_input = format!("{encoded_header}.{encoded_payload}");
            let signer = options.signed_by.as_ref().unwrap_or(&self.issuer_key);
            let signature: p256::ecdsa::Signature = signer.sign(signing_input.as_bytes());
            let jwt = format!(
                "{signing_input}.{}",
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            );

            let shown: Vec<String> = disclosures.iter().map(|d| d.encoded.clone()).collect();
            let mut all = vec![jwt];
            all.extend(shown);
            // Trailing `~` with no key-binding JWT after it, as production emits.
            format!("{}~", all.join("~"))
        }
    }

    #[derive(Default)]
    struct Options {
        present: Option<Vec<Disclosure>>,
        signed_by: Option<SigningKey>,
        jku: Option<String>,
        algorithm: Option<String>,
        digest_algorithm: Option<String>,
        issuer_did_override: Option<String>,
    }

    #[test]
    fn reads_a_well_formed_credential() {
        let fixture = Fixture::new();
        let credential = read(&fixture.serialized(), 0).unwrap();

        assert_eq!(credential.issuer_did, fixture.issuer_did());
        assert_eq!(credential.subject_did, fixture.holder_did());
        assert_eq!(credential.credential_id.as_deref(), Some(CREDENTIAL_ID));
        assert_eq!(credential.credential_type, CREDENTIAL_TYPE);
        assert_eq!(credential.holder_key_x963, fixture.holder_x963());
        assert_eq!(credential.schema_url.as_deref(), Some(SCHEMA_URL));
        let mut names: Vec<&str> = credential
            .disclosed_claims
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        names.sort();
        assert_eq!(names, vec!["id_number", "name", "roc_birthday"]);
    }

    #[test]
    fn the_trailing_separator_is_not_read_as_a_disclosure() {
        let fixture = Fixture::new();
        let serialized = fixture.serialized();
        assert!(serialized.ends_with('~'));
        let credential = read(&serialized, 0).unwrap();
        assert_eq!(credential.disclosed_claims.len(), 3);
    }

    #[test]
    fn a_holder_may_present_fewer_disclosures_than_were_committed() {
        let fixture = Fixture::new();
        let credential = read(&fixture.withholding_all_but("name"), 0).unwrap();
        assert_eq!(
            credential.disclosed_claims,
            vec![("name".to_string(), "陳筱玲".to_string())]
        );
        assert_eq!(credential.commitments.len(), 3);
    }

    #[test]
    fn a_disclosure_the_issuer_never_committed_to_is_refused() {
        let fixture = Fixture::new();
        let forged = Disclosure::new("type", "大型重型機車");
        let result = read(&fixture.adding(forged), 0);
        assert!(
            matches!(result, Err(TwdiwCredentialError::UndisclosedDigest(_))),
            "{result:?}"
        );
    }

    #[test]
    fn a_credential_signed_by_another_key_is_refused() {
        let fixture = Fixture::new();
        assert_eq!(
            read(&fixture.resigned_by_a_stranger(None), 0),
            Err(TwdiwCredentialError::SignatureInvalid)
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let fixture = Fixture::new();
        assert_eq!(
            read(&fixture.with_tampered_type(), 0),
            Err(TwdiwCredentialError::SignatureInvalid)
        );
    }

    #[test]
    fn an_algorithm_other_than_es256_is_refused() {
        let fixture = Fixture::new();
        let result = read(&fixture.with_header_algorithm("none"), 0);
        assert_eq!(
            result,
            Err(TwdiwCredentialError::UnsupportedAlgorithm(
                "none".to_string()
            ))
        );
    }

    #[test]
    fn an_unknown_digest_algorithm_is_refused_rather_than_assumed() {
        let fixture = Fixture::new();
        let result = read(&fixture.with_digest_algorithm("sha-512"), 0);
        assert_eq!(
            result,
            Err(TwdiwCredentialError::UnsupportedDigestAlgorithm(
                "sha-512".to_string()
            ))
        );
    }

    #[test]
    fn an_issuer_did_in_the_other_spelling_is_named_not_misreported() {
        let fixture = Fixture::new();
        let result = read(&fixture.with_p256_pub_issuer_did(), 0);
        assert_eq!(result, Err(TwdiwCredentialError::UnresolvableIssuer));
    }

    #[test]
    fn the_declared_key_source_is_retained() {
        let fixture = Fixture::new();
        let credential = read(&fixture.serialized(), 0).unwrap();
        assert_eq!(credential.declared_key_source_url.as_deref(), Some(JKU));
        assert_eq!(credential.declared_key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn a_credential_that_points_jku_elsewhere_is_still_checked_against_its_did() {
        let fixture = Fixture::new();
        let result = read(
            &fixture.resigned_by_a_stranger(Some("https://example.invalid/keys")),
            0,
        );
        assert_eq!(result, Err(TwdiwCredentialError::SignatureInvalid));
    }

    #[test]
    fn a_string_status_list_index_is_read() {
        let fixture = Fixture::new();
        let credential = read(&fixture.serialized(), 0).unwrap();
        let status = credential.status.unwrap();
        assert_eq!(status.index, 35);
        assert_eq!(status.purpose, "revocation");
        assert_eq!(status.status_list_url, STATUS_LIST_URL);
    }
}
