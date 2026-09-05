//! TWDIW (台灣數位憑證皮夾) OID4VCI protocol logic: reading a credential-offer
//! QR code and deciding whether the issuer it names may be trusted.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/{CredentialOffer,
//! IssuerAuthorization}.swift`. Scoped to the *receive* path (Phase 4's
//! vertical slice needs "receive one credential") - `OID4VPResponse`/
//! `OID4VPRequest`/`OID4VPPresentation` (presentation/showing) and
//! `ConvenienceStorePickup` are a separate area, not yet ported.
//!
//! The actual network calls, Keystore-backed proof signing, and credential
//! storage stay native by design
//! (`docs/2026-09-05-decisions-and-roadmap.md`). This module is the pure
//! decision logic an orchestrator calls into at each step, not the
//! orchestration itself.

pub mod credential_offer;
pub mod issuer_authorization;

pub use credential_offer::{CredentialOffer, CredentialOfferError, CredentialOfferLink};
pub use issuer_authorization::{
    MalformedPage, Refusal, TwdiwIssuer, TwdiwOnChainRecord, TwdiwOnChainVerification, Verdict,
};
