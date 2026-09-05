//! Building the signed `vp_token` a verifier asked for.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/OID4VPResponse.swift`. Scoped
//! to the pure pieces: rebuilding a TWDIW SD-JWT to keep only the chosen
//! disclosures ([`reserialise`]), the DIF presentation submission
//! ([`presentation_submission`]), and the `vp_token` itself, split the
//! same way every signed document in this port is
//! ([`vp_token_signing_input`]/[`assemble_vp_token`]) since Keystore
//! signing stays native.
//!
//! **Not yet ported**: which stored card answers a request and what it
//! discloses (`OID4VPResponder.presentationMaterial`/`responseMaterial`/
//! `selfIssuedMaterial`) - that logic scans the credential store (native
//! file I/O) and, for a MOICA-signed national ID, needs
//! `MOICASignedCredential` (not yet ported - see
//! `presentation::verifiable_presentation`'s module docs for the same
//! boundary). Posting the token back is a network call and stays native
//! too.
//!
//! # The deviation this deliberately reproduces
//!
//! The token and submission are built to match the official app's own
//! source (`moda-gov-tw/TWDIW-official-app`,
//! `APP/APPSDK/lib/openid_vc_vp.dart`), not the spec, in ways worth
//! flagging: the VP claim uses the key `context`, not `@context` - the
//! official verifier does no JSON-LD expansion and reads the literal key
//! `context`, so sending a spec-correct `@context` would hand it a
//! document missing the key it looks for. This is TWDIW's own interop
//! defect, not this app's invention; if TWDIW ever fixes it upstream this
//! must change back to `@context`.

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use crate::twdiw::credential::TwdiwCredential;
use crate::twdiw::oid4vp_request::{Oid4VpCredentialFormat, Oid4VpRequest};

/// One credential entry, ready to ride in a `vp_token`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Oid4VpPresentedCredential {
    pub descriptor_id: String,
    pub format: Oid4VpCredentialFormat,
    pub serialized: String,
}

/// Rebuilds a TWDIW SD-JWT keeping only the chosen disclosures.
///
/// The wire form is `<jwt>~<d1>~<d2>~…~`, and `disclosed_claims[i]`
/// corresponds to the `i`-th disclosure segment. Dropping a segment
/// removes that claim from what the verifier can see while the issuer's
/// signature over the JWT - and its digest commitments - stay intact,
/// which is the whole point of selective disclosure. The trailing `~` is
/// preserved because production emits it even with nothing disclosed.
pub fn reserialise(credential: &TwdiwCredential, chosen_claims: &HashSet<String>) -> String {
    let segments: Vec<&str> = credential.serialized.split('~').collect();
    let Some(jwt) = segments.first() else {
        return credential.serialized.clone();
    };

    let mut kept: Vec<&str> = Vec::new();
    // segments[0] is the JWT; disclosure i lives at segments[i+1].
    for (i, (name, _value)) in credential.disclosed_claims.iter().enumerate() {
        if chosen_claims.contains(name) {
            if let Some(segment) = segments.get(i + 1) {
                kept.push(segment);
            }
        }
    }

    let mut parts = vec![*jwt];
    parts.extend(kept);
    format!("{}~", parts.join("~"))
}

/// The DIF presentation submission naming which descriptor a `vp_token`
/// answers and where each credential sits inside it.
///
/// The descriptor is nested and repeats its id, matched to the official
/// app's own builder: the token is a `VerifiablePresentation` JWT whose
/// credential sits at `$.vp.verifiableCredential[<index>]`, so the top
/// level describes the presentation (`jwt_vp`, `path: "$"`) and
/// `path_nested` reaches the credential, carrying **the same `id`** (the
/// verifier's own schema requires it) and the format `jwt_vc` - not
/// `vc+sd-jwt` - except for this project's `vc+moica` extension.
pub fn presentation_submission(
    request: &Oid4VpRequest,
    presented: &[Oid4VpPresentedCredential],
) -> serde_json::Value {
    let descriptor_map: Vec<serde_json::Value> = presented
        .iter()
        .enumerate()
        .map(|(index, credential)| {
            let inner_format = if credential.format == Oid4VpCredentialFormat::Moica {
                "vc+moica"
            } else {
                "jwt_vc"
            };
            serde_json::json!({
                "id": credential.descriptor_id,
                "format": "jwt_vp",
                "path": "$",
                "path_nested": {
                    "id": credential.descriptor_id,
                    "format": inner_format,
                    "path": format!("$.vp.verifiableCredential[{index}]"),
                },
            })
        })
        .collect();

    serde_json::json!({
        // A stable id derived from the exchange rather than random, so a
        // caller can assert on it. The verifier requires only a
        // non-empty string.
        "id": format!("submission-{}", request.state),
        "definition_id": request.definition_id,
        "descriptor_map": descriptor_map,
    })
}

/// Convenience for the legacy one-descriptor request:
/// `presentation_submission` naming `request.input_descriptor_id()`
/// alone.
pub fn presentation_submission_for_request(request: &Oid4VpRequest) -> serde_json::Value {
    presentation_submission_for_descriptor_ids(
        request,
        &[request.input_descriptor_id().to_string()],
    )
}

/// Convenience for a grouped request: one `jwt_vc`-formatted entry per
/// descriptor id, in order.
pub fn presentation_submission_for_descriptor_ids(
    request: &Oid4VpRequest,
    descriptor_ids: &[String],
) -> serde_json::Value {
    let presented: Vec<Oid4VpPresentedCredential> = descriptor_ids
        .iter()
        .map(|id| Oid4VpPresentedCredential {
            descriptor_id: id.clone(),
            format: Oid4VpCredentialFormat::SdJwt,
            serialized: String::new(),
        })
        .collect();
    presentation_submission(request, &presented)
}

/// The bytes a `vp_token` JWT signature covers - built field-for-field to
/// the official app's own token (`openid_vc_vp.dart` `generateVPKx`):
/// `aud` is the verifier's `client_id` verbatim (a `did:key`, no
/// `redirect_uri:` prefix), the key rides in the header as `jwk` rather
/// than a `kid` DID, and `vp.context` is the `…/2018/credentials/v1` URL
/// under the literal key `context` (see the module docs).
///
/// Signing itself stays native (Keystore); `holder_public_key_x963` is
/// the presenting card's own key (X9.63 uncompressed, 65 bytes) as the
/// caller's key store reports it. Sign the returned string and hand the
/// raw `r ‖ s` signature to [`assemble_vp_token`].
pub fn vp_token_signing_input(
    request: &Oid4VpRequest,
    presented: &[String],
    holder_public_key_x963: &[u8],
    now: DateTime<Utc>,
) -> Option<String> {
    if holder_public_key_x963.len() != 65 {
        return None;
    }
    let coordinates = &holder_public_key_x963[1..];
    let (x, y) = coordinates.split_at(32);
    let holder_did =
        crate::identity::jwk_did_key::did_from_p256_x963(holder_public_key_x963).ok()?;

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(x),
        "y": base64url_encode(y),
    });
    let header = serde_json::json!({"typ": "JWT", "alg": "ES256", "jwk": jwk});

    let issued = now.timestamp();
    let vp = serde_json::json!({
        "context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": presented,
    });
    let payload = serde_json::json!({
        "sub": holder_did,
        "aud": request.client_id,
        "iss": holder_did,
        "nbf": issued,
        "vp": vp,
        "exp": issued + 60 * 60 * 24 * 30,
        "nonce": request.nonce,
        "jti": format!("urn:uuid:{}", uuid_v4_lowercase()),
    });

    let header_bytes = serde_json::to_vec(&serde_json::to_value(&header).ok()?).ok()?;
    let payload_bytes = serde_json::to_vec(&serde_json::to_value(&payload).ok()?).ok()?;
    Some(format!(
        "{}.{}",
        base64url_encode(&header_bytes),
        base64url_encode(&payload_bytes)
    ))
}

/// Combines a `signing_input` (from [`vp_token_signing_input`]) with its
/// raw `r ‖ s` ECDSA signature into a compact JWT.
pub fn assemble_vp_token(signing_input: &str, signature: &[u8; 64]) -> String {
    format!("{signing_input}.{}", base64url_encode(signature))
}

fn base64url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn uuid_v4_lowercase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::twdiw::oid4vp_request::Oid4VpRequest;
    use chrono::TimeZone;
    use p256::ecdsa::{
        signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey,
    };
    use rand::rngs::OsRng;

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_754_400_000, 0).unwrap()
    }

    fn sign_raw(key: &SigningKey, message: &[u8]) -> [u8; 64] {
        let signature: Signature = key.sign(message);
        let bytes = signature.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        out
    }

    fn x963(key: &SigningKey) -> Vec<u8> {
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Builds a minimal verified `Oid4VpRequest` for these tests without
    /// going through `Oid4VpRequest::verify` (that machinery is tested in
    /// `oid4vp_request`'s own suite) - constructed directly, since every
    /// field here is public.
    fn sample_request(client_id: &str) -> Oid4VpRequest {
        use crate::twdiw::oid4vp_request::{Oid4VpInputDescriptor, Oid4VpRequestedField};
        Oid4VpRequest {
            response_uri: "https://verifier-oid4vp.wallet.gov.tw/api/oidvp/authorization-response"
                .to_string(),
            client_id: client_id.to_string(),
            nonce: "N-1".to_string(),
            state: "S-1".to_string(),
            input_descriptors: vec![Oid4VpInputDescriptor {
                id: "00000000_vpms_20250605".to_string(),
                credential_format: None,
                credential_type: Some("00000000_vpms_20250605".to_string()),
                requested_fields: vec![Oid4VpRequestedField {
                    path: "$.credentialSubject.name".to_string(),
                }],
                groups: vec![],
                credential_name: None,
                issuer_name: None,
            }],
            submission_requirements: vec![],
            definition_id: "00000000_vpms_20250605".to_string(),
        }
    }

    #[test]
    fn only_chosen_claims_survive_reserialisation() {
        let credential = TwdiwCredential {
            serialized: "JWT~d-name~d-company~d-email~".to_string(),
            issuer_did: "did:key:zIssuer".to_string(),
            subject_did: "did:key:zHolder".to_string(),
            credential_id: None,
            credential_type: "00000000_vpms_20250605".to_string(),
            not_before: 0,
            expires: i64::MAX,
            holder_key_x963: vec![],
            status: None,
            schema_url: None,
            declared_key_source_url: None,
            declared_key_id: None,
            commitments: vec!["c1".to_string(), "c2".to_string(), "c3".to_string()],
            disclosed_claims: vec![
                ("name".to_string(), "王小明".to_string()),
                ("company".to_string(), "有備而來".to_string()),
                ("email".to_string(), "a@b.tw".to_string()),
            ],
        };
        let chosen: HashSet<String> = ["name".to_string()].into_iter().collect();
        let presented = reserialise(&credential, &chosen);
        assert_eq!(presented, "JWT~d-name~");
    }

    #[test]
    fn reserialise_keeps_no_disclosures_when_none_are_chosen() {
        let credential = TwdiwCredential {
            serialized: "JWT~d-name~".to_string(),
            issuer_did: "did:key:zIssuer".to_string(),
            subject_did: "did:key:zHolder".to_string(),
            credential_id: None,
            credential_type: "t".to_string(),
            not_before: 0,
            expires: i64::MAX,
            holder_key_x963: vec![],
            status: None,
            schema_url: None,
            declared_key_source_url: None,
            declared_key_id: None,
            commitments: vec!["c1".to_string()],
            disclosed_claims: vec![("name".to_string(), "王小明".to_string())],
        };
        let presented = reserialise(&credential, &HashSet::new());
        assert_eq!(presented, "JWT~");
    }

    #[test]
    fn the_submission_matches_the_official_builder() {
        let request = sample_request("did:key:zVerifier");
        let submission = presentation_submission_for_request(&request);
        let map = submission["descriptor_map"].as_array().unwrap();
        let descriptor = &map[0];
        let id = descriptor["id"].as_str().unwrap().to_string();
        assert_eq!(descriptor["format"], "jwt_vp");
        assert_eq!(descriptor["path"], "$");
        let nested = &descriptor["path_nested"];
        assert_eq!(nested["id"], id);
        assert_eq!(nested["format"], "jwt_vc");
        assert_eq!(nested["path"], "$.vp.verifiableCredential[0]");
        assert_eq!(submission["definition_id"], "00000000_vpms_20250605");
    }

    #[test]
    fn grouped_pickup_names_a_nested_path_per_descriptor() {
        let request = sample_request("did:key:zVerifier");
        let submission = presentation_submission_for_descriptor_ids(
            &request,
            &["twm-name".to_string(), "twm-last5".to_string()],
        );
        let map = submission["descriptor_map"].as_array().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map[0]["path_nested"]["path"],
            "$.vp.verifiableCredential[0]"
        );
        assert_eq!(
            map[1]["path_nested"]["path"],
            "$.vp.verifiableCredential[1]"
        );
        assert_eq!(map[0]["id"], "twm-name");
        assert_eq!(map[1]["id"], "twm-last5");
    }

    #[test]
    fn the_vp_token_matches_the_official_builder() {
        let holder_key = SigningKey::random(&mut OsRng);
        let holder_x963 = x963(&holder_key);
        let holder_did = crate::identity::jwk_did_key::did_from_p256_x963(&holder_x963).unwrap();
        let request = sample_request("did:key:zVerifierClientId");

        let input = vp_token_signing_input(
            &request,
            &["presented-jws".to_string()],
            &holder_x963,
            now(),
        )
        .unwrap();
        let signature = sign_raw(&holder_key, input.as_bytes());
        let token = assemble_vp_token(&input, &signature);

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes = base64url_decode(parts[1]);
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(payload["aud"], "did:key:zVerifierClientId");
        assert!(!payload["aud"]
            .as_str()
            .unwrap()
            .starts_with("redirect_uri:"));
        assert_eq!(payload["nonce"], "N-1");
        assert_eq!(payload["sub"], holder_did);
        assert_eq!(payload["iss"], holder_did);
        assert!(payload["nbf"].is_number());
        assert!(payload["exp"].is_number());
        assert!(!payload["jti"].as_str().unwrap().is_empty());

        let vp = &payload["vp"];
        assert_eq!(
            vp["context"],
            serde_json::json!(["https://www.w3.org/2018/credentials/v1"])
        );
        assert!(vp.get("@context").is_none());
        assert_eq!(vp["type"], serde_json::json!(["VerifiablePresentation"]));

        let header_bytes = base64url_decode(parts[0]);
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert!(header.get("kid").is_none());
        let jwk = &header["jwk"];
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["kty"], "EC");

        let verifying_key = VerifyingKey::from(&holder_key);
        let signature_bytes = base64url_decode(parts[2]);
        let sig = Signature::from_slice(&signature_bytes).unwrap();
        let message = format!("{}.{}", parts[0], parts[1]);
        assert!(verifying_key.verify(message.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn different_calls_produce_different_jti() {
        let holder_key = SigningKey::random(&mut OsRng);
        let request = sample_request("did:key:zVerifierClientId");
        let first = vp_token_signing_input(&request, &["a".to_string()], &x963(&holder_key), now())
            .unwrap();
        let second =
            vp_token_signing_input(&request, &["a".to_string()], &x963(&holder_key), now())
                .unwrap();
        assert_ne!(first, second);
    }

    fn base64url_decode(segment: &str) -> Vec<u8> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.decode(segment).unwrap()
    }
}
