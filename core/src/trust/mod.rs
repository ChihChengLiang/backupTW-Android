//! Trust-list fetch/verify and untrusted-text display safety.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/{TrustList,
//! UntrustedText}.swift`. Fetching itself (network) stays native; this is
//! the verify/canonicalize/scrub logic.

pub mod trust_list;
pub mod untrusted_text;

pub use trust_list::{Entry as TrustListEntry, Provenance, TrustList, TrustListError};
pub use untrusted_text::UntrustedText;
