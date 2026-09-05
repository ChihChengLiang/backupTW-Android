//! The UniFFI-exported surface of this crate.
//!
//! Kept as one place so the FFI boundary is easy to audit: everything a
//! Kotlin caller can reach is declared here, not scattered across
//! `identity`/`credential`/`trust`'s own modules.

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;

use crate::identity::{did_key, jwk_did_key};

#[derive(uniffi::Record)]
pub struct WalletIdentity {
    /// This app's own `did:key` spelling (`p256-pub`, multicodec `0x1200`).
    pub did: String,
    /// The `jwk_jcs-pub` spelling (multicodec `0xEB51`) the TWDIW ecosystem
    /// uses — the same key, the other identifier.
    pub jwk_did: String,
}

/// Generates a fresh P-256 wallet identity.
///
/// **Ephemeral and in-memory only — a placeholder, not the real design.**
/// The architecture decision
/// (`docs/2026-09-05-decisions-and-roadmap.md`) is that key storage stays
/// native (Android Keystore), reaching the core only through a
/// trait/callback boundary that doesn't exist yet. This function exists to
/// prove the UniFFI plumbing end-to-end for Phase 4's first vertical-slice
/// step (did:key generation) — the key is thrown away the moment the
/// process exits, and calling this twice gives two unrelated identities.
/// Do not build anything that needs a *stable* identity on top of this
/// until Keystore-backed generation replaces it.
#[uniffi::export]
pub fn generate_ephemeral_wallet_identity() -> WalletIdentity {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key: p256::ecdsa::VerifyingKey = *signing_key.verifying_key();
    let x963 = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    WalletIdentity {
        did: did_key::did_from_p256_x963(&x963).expect("freshly generated key is always valid"),
        jwk_did: jwk_did_key::did_from_p256_x963(&x963)
            .expect("freshly generated key is always valid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_two_valid_did_key_spellings_of_one_key() {
        let identity = generate_ephemeral_wallet_identity();
        assert!(identity.did.starts_with("did:key:zDnae"));
        assert!(identity.jwk_did.starts_with("did:key:z"));

        // Round-trips through this crate's own decoders.
        let from_p256 = did_key::p256_public_key_from_did(&identity.did).unwrap();
        let from_jwk = jwk_did_key::p256_public_key_from_did(&identity.jwk_did).unwrap();
        assert_eq!(
            p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&from_p256, false)
                .as_bytes(),
            p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&from_jwk, false)
                .as_bytes(),
        );
    }

    #[test]
    fn two_calls_give_different_identities() {
        let a = generate_ephemeral_wallet_identity();
        let b = generate_ephemeral_wallet_identity();
        assert_ne!(a.did, b.did);
    }
}
