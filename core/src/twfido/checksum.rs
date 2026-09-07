//! `sp_checksum`/`idp_checksum` per the TW FidO SP API spec v2.9.
//!
//! Ported from `backupTW-iOS/backupTW/TWFidO/SPChecksum.swift`. The
//! server recomputes `sp_checksum` from the same fields and compares
//! strings, so any disagreement - a field in the wrong order, an
//! uppercase hex digit, encrypting the raw digest instead of its hex
//! string - comes back as a generic rejection with no indication of
//! which part was wrong. Everything here is spelled out rather than
//! inferred, matching the Swift source's own discipline.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChecksumError {
    /// The configured key was not base64, or not 32 bytes once decoded.
    #[error("invalid AES key")]
    InvalidAesKey,
    /// The AEAD seal failed. Should be unreachable with a 12-byte nonce.
    #[error("encryption failed")]
    EncryptionFailed,
    /// The checksum did not open under the key, or opened to bytes that
    /// are not the digest of the given payload.
    #[error("checksum unauthenticated")]
    Unauthenticated,
}

/// Computes `sp_checksum` for a request, or `idp_checksum` verification
/// input for a response - both use the same derivation.
///
/// 1. SHA-256 the payload and render the digest as **lowercase hex**.
/// 2. AES-256-GCM encrypt that 64-character hex *string*, UTF-8
///    encoded - not the 32 raw digest bytes. Encrypting the raw
///    digest yields a 32-byte ciphertext and a checksum the server
///    rejects.
/// 3. Return `hex(nonce) ‖ hex(ciphertext) ‖ hex(tag)`, lowercase. 12 +
///    64 + 16 bytes = 184 hex characters, always.
///
/// **On the nonce.** The spec's .NET sample hard-codes twelve zero
/// bytes. This uses a random nonce instead: reusing a nonce under a
/// fixed GCM key leaks the XOR of plaintexts and the authentication
/// subkey, at which point anyone who has collected two checksums can
/// forge them. The spec's own worked example shows a non-zero nonce,
/// confirming the server accepts both - this costs nothing and removes
/// a real break.
pub fn compute(payload: &str, aes_key_base64: &str) -> Result<String, ChecksumError> {
    let cipher = cipher_from_key(aes_key_base64)?;
    let digest_hex = hex_encode(&Sha256::digest(payload.as_bytes()));

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, digest_hex.as_bytes())
        .map_err(|_| ChecksumError::EncryptionFailed)?;

    let mut combined = nonce.to_vec();
    combined.extend(ciphertext);
    Ok(hex_encode(&combined))
}

/// Verifies a response's `idp_checksum`: opens it under the SP key and
/// confirms the plaintext is the lowercase-hex SHA-256 of `payload`.
///
/// Checked by *opening* the box rather than recomputing and comparing
/// strings - GCM is randomised, so two honest checksums over the same
/// payload never match byte for byte. Two things then have to hold: the
/// box opens under the SP key (origin authentication - only 內政部 and
/// this app hold it), and the plaintext equals the digest of *this*
/// response (so a checksum lifted from an earlier genuine response
/// cannot authenticate a swapped body).
pub fn verify(checksum: &str, payload: &str, aes_key_base64: &str) -> Result<(), ChecksumError> {
    let cipher = cipher_from_key(aes_key_base64)?;
    let combined = hex_decode(checksum).ok_or(ChecksumError::Unauthenticated)?;
    if combined.len() < 12 {
        return Err(ChecksumError::Unauthenticated);
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| ChecksumError::Unauthenticated)?;
    let nonce: &aes_gcm::Nonce<_> = (&nonce_array).into();
    let opened = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ChecksumError::Unauthenticated)?;

    let expected = hex_encode(&Sha256::digest(payload.as_bytes()));
    if opened != expected.as_bytes() {
        return Err(ChecksumError::Unauthenticated);
    }
    Ok(())
}

fn cipher_from_key(aes_key_base64: &str) -> Result<Aes256Gcm, ChecksumError> {
    let key_bytes = base64_decode_standard(aes_key_base64).ok_or(ChecksumError::InvalidAesKey)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| ChecksumError::InvalidAesKey)?;
    let key: &Key<Aes256Gcm> = (&key_array).into();
    Ok(Aes256Gcm::new(key))
}

// MARK: - Payload concatenation
//
// The concatenation order differs between transports in ways that are
// easy to miss - app-to-app inserts `op_mode` after `op_code`; result
// polling carries no `id_num` at all, since the ticket already binds
// the request to a holder. Separate functions rather than one
// parameterised builder, matching the Swift source's own reasoning:
// no call can accidentally emit a combination no transport actually
// uses, whose ordering the spec therefore does not define.
//
// Scoped to what QR-code mode needs (ATH-01 app-to-app ticket issuance
// + ATH-02 result polling) - push's payload shapes are out of scope.

/// ATH-01 app-to-app: `transaction_id ‖ sp_service_id ‖ id_num ‖
/// op_code ‖ op_mode ‖ hint ‖ sign_data`.
pub fn app_to_app_payload(
    transaction_id: &str,
    sp_service_id: &str,
    id_number: &str,
    op_code: &str,
    op_mode: &str,
    hint: &str,
    sign_data: &str,
) -> String {
    format!("{transaction_id}{sp_service_id}{id_number}{op_code}{op_mode}{hint}{sign_data}")
}

/// ATH-02 result polling: `transaction_id ‖ sp_service_id ‖ sp_ticket_id`.
pub fn result_payload(transaction_id: &str, sp_service_id: &str, sp_ticket_id: &str) -> String {
    format!("{transaction_id}{sp_service_id}{sp_ticket_id}")
}

/// The `idp_checksum` payload: `transaction_id ‖ error_code ‖
/// hashed_id_num ‖ signed_response`.
///
/// `cert` is *not* covered - the spec leaves the certificate outside
/// the checksum. Survivable rather than fine: `signed_response` is
/// covered, and a signature only verifies under the public key of the
/// certificate that actually produced it (checked separately against
/// the bundled MOICA issuer). A substituted `cert` fails later instead
/// of never, but it does fail.
pub fn idp_checksum_payload(
    transaction_id: &str,
    error_code: &str,
    hashed_id_number: &str,
    signed_response: &str,
) -> String {
    format!("{transaction_id}{error_code}{hashed_id_number}{signed_response}")
}

// MARK: - Encoding

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Strict: an odd length or anything outside ASCII hex returns `None`
/// rather than a best-effort prefix, since the caller decides whether a
/// response is authentic from this.
fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<char> = value.chars().collect();
    for pair in chars.chunks(2) {
        let byte_str: String = pair.iter().collect();
        bytes.push(u8::from_str_radix(&byte_str, 16).ok()?);
    }
    Some(bytes)
}

fn base64_decode_standard(value: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway key of the right shape - real SP keys never appear
    /// in source.
    fn key() -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode([0x2A; 32])
    }

    const PAYLOAD: &str = "TXNSVCA123456789SIGNAPP2APPHINTU0lHTg==";

    #[test]
    fn checksum_is_184_lowercase_hex_characters() {
        let checksum = compute(PAYLOAD, &key()).unwrap();
        // 12-byte nonce + 64-byte ciphertext (the 64-character digest
        // hex) + 16-byte tag = 92 bytes = 184 hex characters.
        assert_eq!(checksum.len(), 184);
        assert!(checksum
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// The most valuable assertion here: decrypting our own output under
    /// the same key recovers the lowercase hex of SHA-256 over the
    /// payload, not the raw digest bytes - the single most common way to
    /// get this wrong.
    #[test]
    fn checksum_decrypts_to_the_digest_hex_string() {
        let key = key();
        let checksum = compute(PAYLOAD, &key).unwrap();
        assert!(verify(&checksum, PAYLOAD, &key).is_ok());
    }

    #[test]
    fn verify_rejects_a_checksum_over_a_different_payload() {
        let key = key();
        let checksum = compute(PAYLOAD, &key).unwrap();
        assert_eq!(
            verify(&checksum, "a different payload", &key),
            Err(ChecksumError::Unauthenticated)
        );
    }

    #[test]
    fn verify_rejects_a_checksum_under_a_different_key() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let checksum = compute(PAYLOAD, &key()).unwrap();
        let other_key = STANDARD.encode([0x7B; 32]);
        assert_eq!(
            verify(&checksum, PAYLOAD, &other_key),
            Err(ChecksumError::Unauthenticated)
        );
    }

    /// We deliberately diverge from the spec's zero-nonce sample:
    /// reusing a nonce under a fixed GCM key is the one failure mode
    /// GCM does not tolerate.
    #[test]
    fn repeated_calls_produce_different_checksums() {
        let key = key();
        let first = compute(PAYLOAD, &key).unwrap();
        let second = compute(PAYLOAD, &key).unwrap();
        assert_ne!(first, second);
        assert_ne!(
            &first[..24],
            &second[..24],
            "the nonce, not just the ciphertext, must vary"
        );
    }

    #[test]
    fn rejects_a_key_that_is_not_32_bytes() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let short_key = STANDARD.encode([0x2A; 16]);
        assert_eq!(
            compute(PAYLOAD, &short_key),
            Err(ChecksumError::InvalidAesKey)
        );
    }

    #[test]
    fn app_to_app_payload_concatenates_in_spec_order() {
        assert_eq!(
            app_to_app_payload(
                "TXN",
                "SVC",
                "A123456789",
                "SIGN",
                "APP2APP",
                "HINT",
                "U0lHTg=="
            ),
            "TXNSVCA123456789SIGNAPP2APPHINTU0lHTg=="
        );
    }

    #[test]
    fn result_payload_carries_no_id_number() {
        assert_eq!(result_payload("TXN", "SVC", "TICKET-1"), "TXNSVCTICKET-1");
    }
}
