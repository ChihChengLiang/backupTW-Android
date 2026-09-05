//! What a holder's phone and a stranger's scanner exchange offline: a
//! verifier's request and the holder's signed reply.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/*.swift`.

pub mod offline_verifier;
pub mod request;
pub mod verifiable_presentation;

pub use offline_verifier::{
    caveat_for_revocation_status, verify, DisclosedClaim, NotCheckedReason,
    OfflineIssuerTrustSnapshot, RevocationSnapshotInfo, RevocationStatus, VerificationCaveat,
    VerificationFailure, VerificationOutcome, VerifiedPresentation,
};
pub use request::{PresentationCredentialSource, PresentationRequest, PresentationRequestError};
pub use verifiable_presentation::{
    assemble_presentation_jws, presentation_signing_input, presentation_term_definitions,
    subject_identifier, v2_defined_presentation_terms, EnvelopedVerifiableCredential,
    VerifiablePresentation, VerifiablePresentationError, BASE_TYPE,
};
