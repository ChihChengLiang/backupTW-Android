//! What a holder's phone and a stranger's scanner exchange offline: a
//! verifier's request and the holder's signed reply.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/*.swift`.

pub mod request;

pub use request::{PresentationCredentialSource, PresentationRequest, PresentationRequestError};
