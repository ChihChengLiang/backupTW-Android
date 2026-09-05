//! The credential data model, SD-JWT selective disclosure, and the age
//! predicate derived from a national-ID birthdate.
//!
//! Ported from `backupTW-iOS/backupTW/Model/{VerifiableCredential,
//! AgePredicate}.swift` and
//! `backupTW-iOS/backupTW/Presentation/SelectiveDisclosure.swift`.

pub mod age_predicate;
pub mod selective_disclosure;
mod verifiable_credential;

pub use verifiable_credential::*;
