//! TWDIW (台灣數位憑證皮夾) OID4VCI protocol logic: reading a credential-offer
//! QR code and deciding whether the issuer it names may be trusted.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/{CredentialOffer,
//! IssuerAuthorization}.swift`. Scoped to the *receive* path (Phase 4's
//! vertical slice needs "receive one credential") - `OID4VPResponse`/
//! `OID4VPPresentation` (presentation/showing) and `ConvenienceStorePickup`
//! are a separate area, not yet ported. `OID4VPRequest` (what a verifier
//! asked for) is ported, in `oid4vp_request`.
//!
//! The actual network calls, Keystore-backed proof signing, and credential
//! storage stay native by design
//! (`docs/2026-09-05-decisions-and-roadmap.md`). This module is the pure
//! decision logic an orchestrator calls into at each step, not the
//! orchestration itself.

pub mod collection;
pub mod credential;
pub mod credential_offer;
pub mod issuer_authorization;
pub mod moda_card_application;
pub mod oid4vp_request;
pub mod onchain;
pub mod telecom_card_catalog;

pub use collection::{
    assemble_proof_jwt, canonical_issuer_identifier, credential_bound_to, form_encode,
    proof_signing_input, ProofClaims,
};
pub use credential::{
    read as read_credential, TwdiwCredential, TwdiwCredentialError, TwdiwStatusListEntry,
};
pub use credential_offer::{CredentialOffer, CredentialOfferError, CredentialOfferLink};
pub use issuer_authorization::{
    MalformedPage, Refusal, TwdiwIssuer, TwdiwOnChainRecord, TwdiwOnChainVerification, Verdict,
};
pub use moda_card_application::ModaCardApplication;
pub use oid4vp_request::{
    Oid4VpAuthorizeLink, Oid4VpCredentialFormat, Oid4VpInputDescriptor, Oid4VpRequest,
    Oid4VpRequestError, Oid4VpRequestedField, Oid4VpSubmissionRequirement,
};
pub use onchain::{
    check as check_on_chain_record, current_record_call_data, decode_current_record,
    decode_registry_input, is_infrastructure_error, CurrentRegistryRecord, RegistryInput,
};
pub use telecom_card_catalog::{
    telecom_cards_from_vc_list_json, TelecomCard, TelecomCardCatalogError,
};
