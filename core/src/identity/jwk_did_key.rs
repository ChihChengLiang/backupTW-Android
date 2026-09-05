//! `did:key` in the spelling TWDIW uses: multicodec `jwk_jcs-pub` (0xEB51),
//! whose payload is a JWK, as JSON text.
//!
//! Ported from `backupTW-iOS/backupTW/Crypto/JWKDIDKey.swift`. The essential
//! asymmetry, preserved here: **everything this module produces is
//! JCS-canonical (RFC 8785, member order `crv < kty < x < y`). Nothing it
//! accepts is required to be** — Taiwan's official wallet issues DIDs with
//! `kty` last, and every credential in production was issued to one, so a
//! decoder that enforced the codec's own canonicality rule would reject the
//! only Taiwanese wallet there is. The cost is paid by comparing
//! [`canonical_did`] rather than raw DID strings wherever two DIDs need to be
//! checked as naming the same holder.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

use super::{base58, varint};

/// multicodec `jwk_jcs-pub` (0xEB51) as an unsigned LEB128 varint.
const JWK_JCS_MULTICODEC_PREFIX: [u8; 3] = [0xD1, 0xD6, 0x03];

/// The same code as a number, declared independently of the byte prefix and
/// pinned against it by a test.
pub const JWK_JCS_MULTICODEC_CODE: u64 = 0xEB51;

const DID_KEY_PREFIX: &str = "did:key:";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwkDidKeyError {
    #[error("invalid public key length: {0}")]
    InvalidPublicKeyLength(usize),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("not a did:key")]
    NotADidKey,
    #[error("unsupported multibase encoding")]
    UnsupportedMultibaseEncoding,
    #[error("oversized did")]
    OversizedDid,
    #[error("invalid base58")]
    InvalidBase58,
    #[error("malformed multicodec")]
    MalformedMulticodec,
    /// `0x1200` is the `p256-pub` spelling this app issues itself — a real
    /// DID for the same kind of key, just not this codec.
    #[error("unsupported multicodec: {0:#x}")]
    UnsupportedMulticodec(u64),
    /// The bytes after the multicodec are not JSON, or not a JSON object.
    #[error("malformed jwk")]
    MalformedJwk,
    /// A JWK this decoder cannot turn into a P-256 signing key.
    #[error("unsupported key type: kty={kty:?} crv={crv:?}")]
    UnsupportedKeyType { kty: String, crv: String },
    /// `x` or `y` missing, not base64url, or not 32 bytes.
    #[error("malformed coordinate")]
    MalformedCoordinate,
}

/// `x963`: uncompressed public key, `0x04 || X || Y`.
///
/// Returns `did:key:z2dmzD81…`, about 190 characters — four times the
/// `p256-pub` spelling's length, because the payload is JSON text rather
/// than a compressed point.
pub fn did_from_p256_x963(x963: &[u8]) -> Result<String, JwkDidKeyError> {
    if x963.len() != 65 {
        return Err(JwkDidKeyError::InvalidPublicKeyLength(x963.len()));
    }
    let key = PublicKey::from_sec1_bytes(x963).map_err(|_| JwkDidKeyError::InvalidPublicKey)?;
    let uncompressed = key.to_encoded_point(false);
    let coordinates = &uncompressed.as_bytes()[1..]; // drop the 0x04 marker
    let (x, y) = coordinates.split_at(32);

    let mut payload = Vec::from(JWK_JCS_MULTICODEC_PREFIX);
    payload.extend_from_slice(&canonical_jwk(x, y));
    Ok(format!("{DID_KEY_PREFIX}z{}", base58::encode(&payload)))
}

/// The JCS form of a P-256 public JWK: no whitespace, no escaped solidus,
/// base64url without padding, the four members in the one order RFC 8785
/// permits (`crv` < `kty` < `x` < `y`).
///
/// Written out by hand rather than through a JSON serializer whose key
/// ordering happens to agree today: JCS is a byte-exact contract that an
/// identifier is derived from, and "the serializer currently sorts this way"
/// is not the same promise.
pub fn canonical_jwk(x: &[u8], y: &[u8]) -> Vec<u8> {
    let encoded_x = URL_SAFE_NO_PAD.encode(x);
    let encoded_y = URL_SAFE_NO_PAD.encode(y);
    format!(r#"{{"crv":"P-256","kty":"EC","x":"{encoded_x}","y":"{encoded_y}"}}"#).into_bytes()
}

/// Recovers the signing key a `jwk_jcs-pub` DID names.
///
/// Accepts any JWK member ordering — see the module docs. Everything else is
/// a rejection rather than a repair.
pub fn p256_public_key_from_did(did: &str) -> Result<PublicKey, JwkDidKeyError> {
    let Some(multibase) = did.strip_prefix(DID_KEY_PREFIX) else {
        return Err(JwkDidKeyError::NotADidKey);
    };
    let Some(identifier) = multibase.strip_prefix('z') else {
        return Err(JwkDidKeyError::UnsupportedMultibaseEncoding);
    };

    // Same bound as DidKey, and for the same reason: base conversion is
    // quadratic in the digit count, and this arrives from a QR code held by
    // a stranger. A P-256 JWK DID is about 190 digits.
    if identifier.chars().count() > 1024 {
        return Err(JwkDidKeyError::OversizedDid);
    }

    let decoded = base58::decode(identifier).map_err(|_| JwkDidKeyError::InvalidBase58)?;
    let (code, prefix_len) =
        varint::read_unsigned(&decoded).map_err(|_| JwkDidKeyError::MalformedMulticodec)?;
    if code != JWK_JCS_MULTICODEC_CODE {
        return Err(JwkDidKeyError::UnsupportedMulticodec(code));
    }

    p256_public_key_from_jwk_bytes(&decoded[prefix_len..])
}

/// The canonical spelling of whatever DID is handed in.
///
/// **Compare these, never the raw strings.** A non-canonical DID and the
/// canonical DID for the same key are different strings naming one holder.
/// Idempotent: canonicalising an already-canonical DID returns it unchanged.
pub fn canonical_did(did: &str) -> Result<String, JwkDidKeyError> {
    let key = p256_public_key_from_did(did)?;
    did_from_p256_x963(key.to_encoded_point(false).as_bytes())
}

/// Whether the DID is spelled the way this codec's own canonicality rule
/// (RFC 8785 member order) says it must be. Being non-canonical is not a
/// reason to refuse a credential — see [`canonical_did`] — only a reason to
/// tell somebody, e.g. on a diagnostics screen.
pub fn is_canonical(did: &str) -> bool {
    canonical_did(did).as_deref() == Ok(did)
}

/// `bytes`: the JWK, as the JSON text that follows the multicodec.
pub fn p256_public_key_from_jwk_bytes(bytes: &[u8]) -> Result<PublicKey, JwkDidKeyError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| JwkDidKeyError::MalformedJwk)?;
    let jwk = value.as_object().ok_or(JwkDidKeyError::MalformedJwk)?;

    // Read both before judging either, so the error names the pair.
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
    if kty != "EC" || crv != "P-256" {
        return Err(JwkDidKeyError::UnsupportedKeyType {
            kty: kty.to_owned(),
            crv: crv.to_owned(),
        });
    }

    let x = decode_coordinate(jwk.get("x").and_then(|v| v.as_str()))
        .ok_or(JwkDidKeyError::MalformedCoordinate)?;
    let y = decode_coordinate(jwk.get("y").and_then(|v| v.as_str()))
        .ok_or(JwkDidKeyError::MalformedCoordinate)?;

    let mut x963 = vec![0x04u8];
    x963.extend(x);
    x963.extend(y);
    // SEC1 parsing checks the point is on the curve. A JWK is two integers
    // somebody typed into a JSON object; nothing in the encoding stops them
    // naming a point that is not on P-256.
    PublicKey::from_sec1_bytes(&x963).map_err(|_| JwkDidKeyError::InvalidPublicKey)
}

/// base64url without padding, the only spelling a JWK coordinate may use.
/// Standard base64's `+`/`/` decode to different bytes under the two
/// alphabets, so tolerating them would mean a coordinate that reads cleanly
/// and names a different point — hence the explicit ASCII/charset check
/// before the actual decode, rather than trusting the decoder's own
/// leniency.
fn decode_coordinate(s: Option<&str>) -> Option<Vec<u8>> {
    let s = s.filter(|s| !s.is_empty())?;
    if !s
        .chars()
        .all(|c| c.is_ascii() && (c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    if bytes.len() == 32 {
        Some(bytes)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::did_key;
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    fn random_x963() -> Vec<u8> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key: p256::ecdsa::VerifyingKey = *signing_key.verifying_key();
        verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    fn b64url(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Both DIDs below are real, taken from live TWDIW responses — a
    /// round-trip test against DIDs this codebase generated would pass even
    /// with the member ordering or the multicodec wrong, because it would
    /// only be checking self-agreement.
    const MINISTRY_DID: &str = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbrzifm9txeerMVc9oLUg2nBJJnUtgYcAYd35rw1rCLq8y3bLDDBUPH5yTYB7ocY7oPESPBXqubuwMcRzw9evbeHHyFkwsmDc43myibDChGhDk8zrgZDB4KNyXPiQvkktUwn";
    const OFFICIAL_WALLET_DID: &str = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPodrZSqMbCy9Ndu4UgUGy3RNkhH479eLPpbfAhVSNu7B4oJvUwLzyxiP4Jt5k9cqqmChanxAazTGxJMvGxYDApNkXeDW5MPZgZRkjRgD1yaig5KCEgAaVbg8zrvYjMTi1BzqdDpPpkeSFmJwiej9YNY";
    const OFFICIAL_WALLET_CANONICAL_DID: &str = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnhCBwrGzqyVmK7CZc45E1Gsnwud4DCC5LELR1guUsX2p8zZDMKNhgtvBMsNL3Key6Xs6ZvMLorTbhiqutKH5gPiMr4BPFfC3SWpKDdiyXdBk9d8JfiHVuSbXAs48M6yq9W";

    #[test]
    fn a_real_ministry_did_round_trips_exactly() {
        let key = p256_public_key_from_did(MINISTRY_DID).unwrap();
        assert_eq!(
            did_from_p256_x963(key.to_encoded_point(false).as_bytes()).unwrap(),
            MINISTRY_DID
        );
        assert!(is_canonical(MINISTRY_DID));
    }

    #[test]
    fn the_official_wallets_own_did_is_not_canonical_and_is_accepted_anyway() {
        assert!(!is_canonical(OFFICIAL_WALLET_DID));
        assert!(p256_public_key_from_did(OFFICIAL_WALLET_DID).is_ok());
    }

    #[test]
    fn the_two_spellings_of_the_same_key_are_different_strings() {
        assert_ne!(OFFICIAL_WALLET_DID, OFFICIAL_WALLET_CANONICAL_DID);
        let from_raw = p256_public_key_from_did(OFFICIAL_WALLET_DID).unwrap();
        let from_canonical = p256_public_key_from_did(OFFICIAL_WALLET_CANONICAL_DID).unwrap();
        assert_eq!(
            from_raw.to_encoded_point(false).as_bytes(),
            from_canonical.to_encoded_point(false).as_bytes()
        );
    }

    #[test]
    fn canonicalising_collapses_both_spellings_onto_one() {
        assert_eq!(
            canonical_did(OFFICIAL_WALLET_DID).unwrap(),
            OFFICIAL_WALLET_CANONICAL_DID
        );
        assert_eq!(
            canonical_did(OFFICIAL_WALLET_CANONICAL_DID).unwrap(),
            OFFICIAL_WALLET_CANONICAL_DID
        );
    }

    #[test]
    fn canonicalising_twice_changes_nothing() {
        let once = canonical_did(OFFICIAL_WALLET_DID).unwrap();
        assert_eq!(canonical_did(&once).unwrap(), once);
    }

    #[test]
    fn this_apps_own_did_is_refused_by_the_other_decoder() {
        let x963 = random_x963();
        let ours = did_key::did_from_p256_x963(&x963).unwrap();
        assert_eq!(
            p256_public_key_from_did(&ours),
            Err(JwkDidKeyError::UnsupportedMulticodec(0x1200))
        );
    }

    #[test]
    fn a_jwk_did_is_refused_by_the_p256_pub_decoder() {
        assert_eq!(
            did_key::p256_public_key_from_did(MINISTRY_DID),
            Err(did_key::DidKeyError::UnsupportedMulticodec(
                JWK_JCS_MULTICODEC_CODE
            ))
        );
    }

    #[test]
    fn one_key_has_both_identifiers_and_each_decodes_to_it() {
        let x963 = random_x963();
        let ours = did_key::did_from_p256_x963(&x963).unwrap();
        let theirs = did_from_p256_x963(&x963).unwrap();
        assert_ne!(ours, theirs);
        assert_eq!(
            did_key::p256_public_key_from_did(&ours)
                .unwrap()
                .to_encoded_point(false)
                .as_bytes(),
            x963.as_slice()
        );
        assert_eq!(
            p256_public_key_from_did(&theirs)
                .unwrap()
                .to_encoded_point(false)
                .as_bytes(),
            x963.as_slice()
        );
    }

    #[test]
    fn the_multicodec_bytes_and_the_code_agree() {
        let did = did_from_p256_x963(&random_x963()).unwrap();
        let bytes = base58::decode(&did["did:key:z".len()..]).unwrap();
        assert_eq!(&bytes[..3], &[0xD1, 0xD6, 0x03]);
        assert_eq!(JWK_JCS_MULTICODEC_CODE, 0xEB51);
    }

    #[test]
    fn a_member_ordering_is_tolerated_but_a_wrong_curve_is_not() {
        let jwk = br#"{"crv":"P-384","kty":"EC","x":"AA","y":"AA"}"#;
        assert_eq!(
            p256_public_key_from_jwk_bytes(jwk),
            Err(JwkDidKeyError::UnsupportedKeyType {
                kty: "EC".into(),
                crv: "P-384".into()
            })
        );
    }

    #[test]
    fn a_coordinate_that_is_not_thirty_two_bytes_is_refused() {
        let short = b64url(&[1u8; 31]);
        let full = b64url(&[2u8; 32]);
        let jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{short}","y":"{full}"}}"#);
        assert_eq!(
            p256_public_key_from_jwk_bytes(jwk.as_bytes()),
            Err(JwkDidKeyError::MalformedCoordinate)
        );
    }

    #[test]
    fn standard_base64_in_a_coordinate_is_refused() {
        let mut raw = vec![0xFBu8];
        raw.extend(vec![0xFFu8; 31]);
        let mut coordinate = b64url(&raw);
        assert!(coordinate.contains('-') && coordinate.contains('_'));
        coordinate = coordinate.replace('-', "+").replace('_', "/");
        let jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{coordinate}","y":"{coordinate}"}}"#);
        assert_eq!(
            p256_public_key_from_jwk_bytes(jwk.as_bytes()),
            Err(JwkDidKeyError::MalformedCoordinate)
        );
    }

    #[test]
    fn a_point_that_is_not_on_the_curve_is_refused() {
        let bogus = b64url(&[0xABu8; 32]);
        let jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{bogus}","y":"{bogus}"}}"#);
        assert_eq!(
            p256_public_key_from_jwk_bytes(jwk.as_bytes()),
            Err(JwkDidKeyError::InvalidPublicKey)
        );
    }

    #[test]
    fn non_json_after_the_multicodec_is_refused() {
        assert_eq!(
            p256_public_key_from_jwk_bytes(&[0x00, 0x01, 0x02]),
            Err(JwkDidKeyError::MalformedJwk)
        );
    }

    #[test]
    fn a_multibase_prefix_other_than_z_is_refused() {
        assert_eq!(
            p256_public_key_from_did("did:key:mAAAA"),
            Err(JwkDidKeyError::UnsupportedMultibaseEncoding)
        );
    }

    #[test]
    fn something_that_is_not_a_did_key_is_refused() {
        assert_eq!(
            p256_public_key_from_did("https://example.tw/keys/1"),
            Err(JwkDidKeyError::NotADidKey)
        );
    }

    #[test]
    fn an_absurdly_long_identifier_is_refused_before_it_is_decoded() {
        let long = format!("did:key:z{}", "1".repeat(2000));
        assert_eq!(
            p256_public_key_from_did(&long),
            Err(JwkDidKeyError::OversizedDid)
        );
    }

    #[test]
    fn no_error_carries_any_part_of_the_did() {
        let secret = "z2dmzD81cgPx8Vki7JbuuMmFYrWPodrZSqMbCy9Ndu4UgUGy3RNkhH479eLPpbfAhVSNu7B4oJv";
        let malformed = format!("did:key:{secret}!!!");
        let err = p256_public_key_from_did(&malformed).unwrap_err();
        let text = format!("{err:?}");
        assert!(!text.contains(secret));
        assert!(!text.contains("z2dmzD81"));
    }
}
