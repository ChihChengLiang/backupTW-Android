//! What a holder's phone and a stranger's scanner exchange offline: a
//! verifier's request and the holder's signed reply.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/*.swift`.

pub mod age_predicate_proof;
pub mod offline_verifier;
pub mod request;
pub mod verifiable_presentation;

pub use age_predicate_proof::{
    is_trusted_response_url, prepare_cache_key, prepare_cache_keys_to_evict,
    trusted_response_hosts, AgePredicateProofError, AgePredicateProofPackage,
    AgePredicateProofRequest, MAXIMUM_ARTIFACT_BYTES, MAXIMUM_PREPARE_CACHE_ENTRIES,
    SUPPORTED_BIRTH_CLAIM_NAMES,
};
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
