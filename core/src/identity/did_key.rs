//! `did:key` for P-256, per the W3C-CCG did:key method specification.
//!
//! Ported from `backupTW-iOS/backupTW/Crypto/DIDKey.swift` — see that file
//! for the extensive rationale behind each check; comments here are kept to
//! what a Rust reader needs, not a re-derivation of the original design
//! notes.
//!
//! The whole method is a pure encoding — no network, no registry — which is
//! why it is the right identifier for a document the holder issues to
//! themselves. The DID *is* the public key, so a verifier who has the DID
//! can check the signature without asking anyone's permission.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

use super::{base58, varint};

/// multicodec `p256-pub` (0x1200) as an unsigned LEB128 varint.
///
/// Two bytes, not one: 0x1200 needs 14 bits, so the low seven (0x00) get the
/// continuation bit set and the remaining seven (0x24) follow.
const P256_MULTICODEC_PREFIX: [u8; 2] = [0x80, 0x24];

/// The same code as a number, which is the form the decoder compares
/// against. Declared independently rather than derived from the byte prefix
/// at runtime and pinned against it by a test — the only arrangement where a
/// typo in either one shows up as a failure.
pub const P256_MULTICODEC_CODE: u64 = 0x1200;

const DID_KEY_PREFIX: &str = "did:key:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DidKeyError {
    /// An X9.63 uncompressed P-256 key is exactly 65 bytes; anything else is
    /// a different curve or a different encoding and would silently produce
    /// a well-formed but wrong DID.
    #[error("invalid public key length: {0}")]
    InvalidPublicKeyLength(usize),
    /// Right length, but not a point on P-256.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Not a `did:key:` DID at all.
    #[error("not a did:key")]
    NotADidKey,
    /// did:key permits multibase encodings other than base58btc; this
    /// implementation speaks only that one.
    #[error("unsupported multibase encoding")]
    UnsupportedMultibaseEncoding,
    /// Longer than any `did:key` identifier can be.
    #[error("oversized did")]
    OversizedDid,
    /// A character outside the base58btc alphabet.
    #[error("invalid base58")]
    InvalidBase58,
    /// The multicodec varint runs off the end of the decoded bytes.
    #[error("malformed multicodec")]
    MalformedMulticodec,
    /// A well-formed multicodec for some other key type: `0xed` is Ed25519,
    /// `0xe7` secp256k1. Both are real DIDs; neither is a P-256 key.
    #[error("unsupported multicodec: {0:#x}")]
    UnsupportedMulticodec(u64),
    /// A compressed P-256 point is exactly 33 bytes.
    #[error("invalid compressed point length: {0}")]
    InvalidCompressedPointLength(usize),
    /// The DID decodes to a valid key but is not the spelling this key
    /// produces (see [`p256_public_key_from_did`] for why that is refused).
    #[error("non-canonical did")]
    NonCanonicalDid,
}

/// `x963`: uncompressed public key, `0x04 || X || Y`.
///
/// Returns `did:key:zDnae…`, always 57 characters for P-256.
pub fn did_from_p256_x963(x963: &[u8]) -> Result<String, DidKeyError> {
    if x963.len() != 65 {
        return Err(DidKeyError::InvalidPublicKeyLength(x963.len()));
    }

    // did:key encodes the *compressed* point (33 bytes). SEC1 parsing both
    // compresses and rejects points that are not on the curve, which is
    // worth more than the modular arithmetic it replaces: a DID derived
    // from a bogus point would be unverifiable and we would only find out
    // at the far end of the flow.
    let key = PublicKey::from_sec1_bytes(x963).map_err(|_| DidKeyError::InvalidPublicKey)?;
    let compressed = key.to_encoded_point(true);

    // multibase prefix "z" == base58btc; the only multibase encoding the
    // did:key document creation algorithm accepts.
    let mut payload = Vec::with_capacity(2 + 33);
    payload.extend_from_slice(&P256_MULTICODEC_PREFIX);
    payload.extend_from_slice(compressed.as_bytes());
    Ok(format!("{DID_KEY_PREFIX}z{}", base58::encode(&payload)))
}

/// Recovers the signing key a `did:key` names — the inverse of
/// [`did_from_p256_x963`].
///
/// **Every failure here is a rejection, never a repair.** A decoder that
/// shrugs off a wrong multibase prefix, an unknown curve, or a non-canonical
/// varint still hands its caller *a* key, and the caller has no way left to
/// notice that it is not the key the DID names.
pub fn p256_public_key_from_did(did: &str) -> Result<PublicKey, DidKeyError> {
    let Some(multibase) = did.strip_prefix(DID_KEY_PREFIX) else {
        return Err(DidKeyError::NotADidKey);
    };

    let Some(identifier) = multibase.strip_prefix('z') else {
        return Err(DidKeyError::UnsupportedMultibaseEncoding);
    };

    // Base conversion is quadratic in the digit count, and the DID arrives
    // from a QR held by a stranger, so its length has to be bounded before
    // any of it is interpreted. The ceiling sits well above a P-256 DID's 48
    // digits so that longer curves (P-521 runs to 95, RSA-4096 to roughly
    // 740) reach the multicodec check and are named for what they are,
    // rather than refused for length.
    if identifier.chars().count() > 1024 {
        return Err(DidKeyError::OversizedDid);
    }

    let decoded = base58::decode(identifier).map_err(|_| DidKeyError::InvalidBase58)?;
    let (code, prefix_len) =
        varint::read_unsigned(&decoded).map_err(|_| DidKeyError::MalformedMulticodec)?;
    if code != P256_MULTICODEC_CODE {
        // Ed25519 and secp256k1 DIDs are well-formed and resolvable, just
        // not by us.
        return Err(DidKeyError::UnsupportedMulticodec(code));
    }

    let compressed = &decoded[prefix_len..];
    if compressed.len() != 33 {
        return Err(DidKeyError::InvalidCompressedPointLength(compressed.len()));
    }

    // SEC1 parsing checks that the point is on the curve, which is why we
    // route through it rather than slicing out the coordinates directly.
    let key = PublicKey::from_sec1_bytes(compressed).map_err(|_| DidKeyError::InvalidPublicKey)?;

    // Canonicality, established by re-encoding rather than by auditing each
    // layer for its own malleability: base58btc and the varint each admit
    // more than one spelling of the same bytes. Everything downstream
    // compares DIDs *as strings*, so two spellings naming one key would mean
    // string inequality no longer implies different holders.
    let x963 = key.to_encoded_point(false);
    if did_from_p256_x963(x963.as_bytes())?.as_str() != did {
        return Err(DidKeyError::NonCanonicalDid);
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_for_tests::rand_core::OsRng;

    // A tiny local shim so we don't need to add `rand_core` as a real
    // dependency just for test key generation; p256 re-exports it.
    mod rand_for_tests {
        pub use p256::elliptic_curve::rand_core;
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn x963(x: &str, y: &str) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend(hex(x));
        out.extend(hex(y));
        out
    }

    fn random_public_key_x963() -> Vec<u8> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key: p256::ecdsa::VerifyingKey = *signing_key.verifying_key();
        verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// The P-256 example from the W3C-CCG did:key method specification
    /// (§Test Vectors). `y` is odd, so the compressed point takes the 0x03
    /// prefix.
    #[test]
    fn encodes_w3c_ccg_p256_vector() {
        let x = "8a0ac59a2d3086e8a12a78fd4773a6d52a0ca61ef6c1419e15a05bcc6dafce7b";
        let y = "79fb17e5bd74c7cca3cab8f89f2de919f2dc63b5dbcb52b382a39daa7b2b2483";
        let did = did_from_p256_x963(&x963(x, y)).unwrap();
        assert_eq!(
            did,
            "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
        );
    }

    #[test]
    fn encodes_jwk_vector() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let x = URL_SAFE_NO_PAD
            .decode("OcPddBMXKURtwbPaZ9SfwEb8vwcvzFufpRwFuXQwf5Y")
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode("nEA7FjXwRJ8CvUInUeMxIaRDTxUvKysqP2dSGcXZJfY")
            .unwrap();
        let mut x963 = vec![0x04];
        x963.extend(x);
        x963.extend(y);
        let did = did_from_p256_x963(&x963).unwrap();
        assert_eq!(
            did,
            "did:key:zDnaeUKTWUXc1HDpGfKbEK31nKLN19yX5aunFd7VK1CUMeyJu"
        );
    }

    #[test]
    fn every_p256_did_shares_the_prefix_and_length() {
        for _ in 0..32 {
            let did = did_from_p256_x963(&random_public_key_x963()).unwrap();
            assert!(did.starts_with("did:key:zDnae"));
            assert_eq!(did.len(), 57);
        }
    }

    #[test]
    fn rejects_wrong_length() {
        for count in [0, 32, 33, 64, 66, 130] {
            let data = vec![0x04u8; count];
            assert_eq!(
                did_from_p256_x963(&data),
                Err(DidKeyError::InvalidPublicKeyLength(count))
            );
        }
    }

    #[test]
    fn rejects_point_not_on_curve() {
        let mut data = vec![0x04u8];
        data.extend(vec![0x01u8; 64]);
        assert_eq!(
            did_from_p256_x963(&data),
            Err(DidKeyError::InvalidPublicKey)
        );
    }

    #[test]
    fn rejects_non_uncompressed_marker() {
        let mut data = vec![0x05u8];
        data.extend(vec![0x01u8; 64]);
        assert_eq!(
            did_from_p256_x963(&data),
            Err(DidKeyError::InvalidPublicKey)
        );
    }

    #[test]
    fn recovers_every_key_the_encoder_publishes() {
        for _ in 0..64 {
            let expected = random_public_key_x963();
            let did = did_from_p256_x963(&expected).unwrap();
            let recovered = p256_public_key_from_did(&did).unwrap();
            assert_eq!(
                recovered.to_encoded_point(false).as_bytes(),
                expected.as_slice()
            );
        }
    }

    #[test]
    fn rejects_what_is_not_a_did_key() {
        let cases = [
            "",
            "did",
            "did:key",
            "did:web:example.gov",
            "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb",
            "DID:KEY:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
            "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
            " did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
        ];
        for did in cases {
            assert_eq!(
                p256_public_key_from_did(did),
                Err(DidKeyError::NotADidKey),
                "{did:?}"
            );
        }
    }

    #[test]
    fn rejects_multibase_encodings_other_than_base58btc() {
        let cases = [
            "did:key:",
            "did:key:mAbCdEfGhIjKlMnOpQrStUvWxYz",
            "did:key:f8024036e2c6a2c6",
            "did:key:ZDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
            "did:key:1DnaerxCtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
        ];
        for did in cases {
            assert_eq!(
                p256_public_key_from_did(did),
                Err(DidKeyError::UnsupportedMultibaseEncoding),
                "{did:?}"
            );
        }
    }

    #[test]
    fn rejects_other_curves_by_name() {
        let cases: [(&str, u64); 3] = [
            (
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                0xed,
            ),
            (
                "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                0xe7,
            ),
            (
                "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F",
                0xec,
            ),
        ];
        for (did, code) in cases {
            assert_eq!(
                p256_public_key_from_did(did),
                Err(DidKeyError::UnsupportedMulticodec(code)),
                "{did:?}"
            );
        }
    }

    #[test]
    fn rejects_a_multicodec_that_never_terminates() {
        for length in [1, 2, 9, 12] {
            let did = format!("did:key:z{}", base58::encode(&vec![0x80u8; length]));
            assert_eq!(
                p256_public_key_from_did(&did),
                Err(DidKeyError::MalformedMulticodec),
                "length {length}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_payload() {
        assert_eq!(
            p256_public_key_from_did("did:key:z"),
            Err(DidKeyError::MalformedMulticodec)
        );
    }

    #[test]
    fn rejects_compressed_points_of_the_wrong_length() {
        for count in [0, 1, 31, 32, 34, 35, 64, 65] {
            let mut payload = vec![0x80u8, 0x24];
            payload.extend(vec![0x02u8; count]);
            let did = format!("did:key:z{}", base58::encode(&payload));
            assert_eq!(
                p256_public_key_from_did(&did),
                Err(DidKeyError::InvalidCompressedPointLength(count)),
                "count {count}"
            );
        }
    }

    #[test]
    fn rejects_coordinates_outside_the_field() {
        for parity in [0x02u8, 0x03u8] {
            let mut payload = vec![0x80u8, 0x24, parity];
            payload.extend(vec![0xffu8; 32]);
            let did = format!("did:key:z{}", base58::encode(&payload));
            assert_eq!(
                p256_public_key_from_did(&did),
                Err(DidKeyError::InvalidPublicKey),
                "parity {parity:#x}"
            );
        }
    }

    #[test]
    fn rejects_a_non_minimal_multicodec_varint() {
        let x963 = random_public_key_x963();
        let key = PublicKey::from_sec1_bytes(&x963).unwrap();
        let canonical = did_from_p256_x963(&x963).unwrap();

        let mut overlong_payload = vec![0x80u8, 0xa4, 0x00];
        overlong_payload.extend_from_slice(key.to_encoded_point(true).as_bytes());
        let overlong = format!("did:key:z{}", base58::encode(&overlong_payload));

        assert_ne!(overlong, canonical);
        assert_eq!(
            p256_public_key_from_did(&overlong),
            Err(DidKeyError::NonCanonicalDid)
        );
        assert_eq!(
            p256_public_key_from_did(&canonical)
                .unwrap()
                .to_encoded_point(false)
                .as_bytes(),
            x963.as_slice()
        );
    }

    #[test]
    fn rejects_a_payload_padded_with_leading_zero_bytes() {
        let x963 = random_public_key_x963();
        let key = PublicKey::from_sec1_bytes(&x963).unwrap();
        let mut padded_payload = vec![0x00u8, 0x80, 0x24];
        padded_payload.extend_from_slice(key.to_encoded_point(true).as_bytes());
        let padded = format!("did:key:z{}", base58::encode(&padded_payload));
        assert!(padded.starts_with("did:key:z1"));
        assert_eq!(
            p256_public_key_from_did(&padded),
            Err(DidKeyError::UnsupportedMulticodec(0x00))
        );
    }

    #[test]
    fn rejects_single_digit_truncation_and_extension() {
        for _ in 0..32 {
            let did = did_from_p256_x963(&random_public_key_x963()).unwrap();
            let truncated = &did[..did.len() - 1];
            assert!(p256_public_key_from_did(truncated).is_err());
            let extended = format!("{did}2");
            assert!(p256_public_key_from_did(&extended).is_err());
        }
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        let base = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZp";
        for c in ["0", "O", "I", "l", "+", "/", "=", " ", "-"] {
            let did = format!("{base}{c}");
            assert_eq!(
                p256_public_key_from_did(&did),
                Err(DidKeyError::InvalidBase58),
                "{c:?}"
            );
        }
    }

    #[test]
    fn rejects_an_identifier_too_long_to_be_a_did_key() {
        let started = std::time::Instant::now();
        let did = format!("did:key:z{}", "z".repeat(200_000));
        assert_eq!(
            p256_public_key_from_did(&did),
            Err(DidKeyError::OversizedDid)
        );
        assert!(started.elapsed().as_secs_f64() < 1.0);
    }

    #[test]
    fn rejects_a_long_run_of_zero_digits_without_decoding_it_as_a_key() {
        let did = format!("did:key:z{}", "1".repeat(100_000));
        assert_eq!(
            p256_public_key_from_did(&did),
            Err(DidKeyError::OversizedDid)
        );

        let did = format!("did:key:z{}", "1".repeat(40));
        assert_eq!(
            p256_public_key_from_did(&did),
            Err(DidKeyError::UnsupportedMulticodec(0x00))
        );
    }

    /// The two spellings of the `p256-pub` multicodec are declared
    /// separately on purpose. This is where they are made to agree.
    #[test]
    fn the_encoders_prefix_is_the_only_one_the_decoder_accepts() {
        let x963 = random_public_key_x963();
        let key = PublicKey::from_sec1_bytes(&x963).unwrap();
        let did = did_from_p256_x963(&x963).unwrap();
        let payload = base58::decode(&did["did:key:z".len()..]).unwrap();

        assert_eq!(&payload[..2], &[0x80, 0x24]);
        assert_eq!(payload.len(), 35);

        for prefix in [vec![0x12u8], vec![0x12u8, 0x00]] {
            let mut forged_payload = prefix;
            forged_payload.extend_from_slice(key.to_encoded_point(true).as_bytes());
            let forged = format!("did:key:z{}", base58::encode(&forged_payload));
            assert_eq!(
                p256_public_key_from_did(&forged),
                Err(DidKeyError::UnsupportedMulticodec(0x12))
            );
        }
    }
}
