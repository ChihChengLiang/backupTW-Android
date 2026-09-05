//! The pure, signature-adjacent parts of collecting one credential from a
//! TWDIW issuer.
//!
//! Ported from the non-I/O parts of
//! `backupTW-iOS/backupTW/TWDIW/OID4VCICollection.swift`'s
//! `OID4VCICollector`. The orchestration itself — HTTP requests, Keystore
//! key creation, credential storage — is native's job and lives outside
//! this crate; these are the decisions and byte-shapes an orchestrator
//! needs along the way: the canonical issuer identifier to build requests
//! against, the OID4VCI proof JWT's exact bytes (signed externally, same
//! split as `credential::jws_signing_input`/`assemble_jws`), the
//! form-encoding a token request body needs, and the check that an issued
//! credential is bound to the key this collection created.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use url::Url;

use super::issuer_authorization::normalised_host;

/// Scheme and host from the gate's canonical spelling, path from the
/// offer. Query and fragment are dropped: an issuer identifier with a
/// query string is nothing this flow should build URLs on top of.
pub fn canonical_issuer_identifier(credential_issuer: &str) -> Option<String> {
    let host = normalised_host(credential_issuer).ok()?;
    let parsed = Url::parse(credential_issuer).ok()?;
    let path = parsed.path().trim_end_matches('/');
    Some(format!("https://{host}{path}"))
}

/// The fields an OID4VCI proof JWT asserts.
pub struct ProofClaims<'a> {
    /// The `client_id` this flow authenticates as (and the proof's `iss`,
    /// since the issuer checks the proof's `iss` only against the
    /// `client_id` the access token remembers — the two must agree).
    pub client_id: &'a str,
    /// The gate's canonical issuer identifier. A trailing slash is added
    /// if missing — measured off the deployment; without it the demo
    /// issuer rejects the proof.
    pub issuer_identifier: &'a str,
    /// The holder DID (`kid`), in the TWDIW `jwk_jcs-pub` spelling — the
    /// issuer strips a hardcoded 0xEB51 prefix, so the other spelling
    /// would parse as garbage.
    pub holder_did: &'a str,
    pub nonce: &'a str,
    /// Unix timestamp, seconds.
    pub issued_at: i64,
}

/// The bytes an OID4VCI proof JWT signature covers:
/// `base64url(header) + "." + base64url(payload)`. Signing itself is not
/// this crate's job; hand the result to [`assemble_proof_jwt`] with the
/// resulting `r‖s` signature.
pub fn proof_signing_input(claims: &ProofClaims) -> String {
    let audience = if claims.issuer_identifier.ends_with('/') {
        claims.issuer_identifier.to_string()
    } else {
        format!("{}/", claims.issuer_identifier)
    };
    let header = serde_json::json!({
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "kid": claims.holder_did,
    });
    let payload = serde_json::json!({
        "iss": claims.client_id,
        "aud": audience,
        "iat": claims.issued_at,
        "nonce": claims.nonce,
    });
    format!(
        "{}.{}",
        canonical_base64url(&header),
        canonical_base64url(&payload)
    )
}

/// Combines a `signing_input` (from [`proof_signing_input`]) with its raw
/// `r ‖ s` ECDSA signature into the compact proof JWT.
pub fn assemble_proof_jwt(signing_input: &str, signature: &[u8; 64]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Sorted-key, compact JSON, base64url - same technique as
/// `credential::VerifiableCredential::canonical_bytes`: routing through
/// `serde_json::Value` sorts keys regardless of construction order, so two
/// runs of one proof serialise identically.
fn canonical_base64url(value: &serde_json::Value) -> String {
    let canonical = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Whether the credential's `cnf.jwk` is exactly the public key named by
/// `public_key_x963` (X9.63 uncompressed: `0x04 ‖ X ‖ Y`, 65 bytes).
///
/// Compared as coordinates, not as serialised JWK bytes: the issuer writes
/// the JWK in whatever member order it likes, and two spellings of one key
/// must not read as two keys.
pub fn credential_bound_to(serialized: &str, public_key_x963: &[u8]) -> bool {
    if public_key_x963.len() != 65 {
        return false;
    }
    let jwt = serialized.split('~').next().unwrap_or(serialized);
    let parts: Vec<&str> = jwt.split('.').collect();
    let [_header, payload, _sig] = parts.as_slice() else {
        return false;
    };

    let Some(payload_bytes) = URL_SAFE_NO_PAD.decode(payload).ok() else {
        return false;
    };
    let Ok(payload_json) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
        return false;
    };
    let Some(jwk) = payload_json.get("cnf").and_then(|c| c.get("jwk")) else {
        return false;
    };
    let Some(x) = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
    else {
        return false;
    };
    let Some(y) = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
    else {
        return false;
    };

    x == public_key_x963[1..33] && y == public_key_x963[33..65]
}

/// `application/x-www-form-urlencoded` with the same allowed charset as
/// the Swift source: alphanumerics plus `-._~`.
pub fn form_encode(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("{name}={}", percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let c = byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_issuer_identifier_drops_trailing_slashes_query_and_fragment() {
        assert_eq!(
            canonical_issuer_identifier(
                "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/"
            ),
            Some("https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000".to_string())
        );
        assert_eq!(
            canonical_issuer_identifier(
                "https://Issuer-OID4VCI.Wallet.GOV.TW/api/issuer/00000000?x=1#f"
            ),
            Some("https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000".to_string())
        );
    }

    #[test]
    fn canonical_issuer_identifier_refuses_what_the_host_gate_refuses() {
        assert_eq!(
            canonical_issuer_identifier("http://issuer-oid4vci.wallet.gov.tw/api/"),
            None
        );
    }

    #[test]
    fn the_proof_says_what_the_plan_says_it_must_say() {
        let claims = ProofClaims {
            client_id: "moda_dw",
            issuer_identifier: "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000",
            holder_did: "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kb",
            nonce: "NONCE-1",
            issued_at: 1_700_000_000,
        };
        let input = proof_signing_input(&claims);
        let segments: Vec<&str> = input.split('.').collect();
        assert_eq!(segments.len(), 2);

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], claims.holder_did);

        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        // The issuer checks the proof's `iss` only against the client_id
        // the access token remembers, so it is `moda_dw`.
        assert_eq!(payload["iss"], "moda_dw");
        // Trailing slash measured off the deployment; without it the demo
        // issuer rejects the proof.
        assert_eq!(payload["aud"], format!("{}/", claims.issuer_identifier));
        assert_eq!(payload["nonce"], "NONCE-1");

        let jwt = assemble_proof_jwt(&input, &[0x11u8; 64]);
        let jwt_segments: Vec<&str> = jwt.split('.').collect();
        assert_eq!(jwt_segments.len(), 3);
    }

    #[test]
    fn proof_signing_is_deterministic() {
        let claims = ProofClaims {
            client_id: "moda_dw",
            issuer_identifier: "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000",
            holder_did: "did:key:zTest",
            nonce: "N",
            issued_at: 1,
        };
        let first = proof_signing_input(&claims);
        for _ in 0..8 {
            assert_eq!(proof_signing_input(&claims), first);
        }
    }

    #[test]
    fn the_token_request_body_is_form_encoded_with_the_narrow_charset() {
        let body = form_encode(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            ),
            ("pre-authorized_code", "CODE-1"),
            ("client_id", "moda_dw"),
        ]);
        assert!(body.contains("client_id=moda_dw"));
        assert!(body
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"));
        assert!(body.contains("pre-authorized_code=CODE-1"));
    }

    fn x963_of(private_key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        let verifying_key: p256::ecdsa::VerifyingKey = *private_key.verifying_key();
        verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    fn credential_bound_to_x963(x963: &[u8]) -> String {
        let x = URL_SAFE_NO_PAD.encode(&x963[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&x963[33..65]);
        let payload =
            serde_json::json!({"cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": x, "y": y}}});
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("headerpart.{payload_b64}.sigpart~disclosure1~")
    }

    #[test]
    fn a_credential_bound_to_the_given_key_is_recognised() {
        let key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let x963 = x963_of(&key);
        let serialized = credential_bound_to_x963(&x963);
        assert!(credential_bound_to(&serialized, &x963));
    }

    #[test]
    fn a_credential_bound_to_a_different_key_is_refused() {
        let key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let other = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let serialized = credential_bound_to_x963(&x963_of(&key));
        assert!(!credential_bound_to(&serialized, &x963_of(&other)));
    }

    #[test]
    fn a_malformed_credential_is_refused_not_panicked_on() {
        assert!(!credential_bound_to("not.a~jwt", &[0u8; 65]));
        assert!(!credential_bound_to("", &[0u8; 65]));
        assert!(!credential_bound_to("a.b.c", &[0u8; 65]));
    }
}
