//! MOICA (自然人憑證) self-issued national-ID credentials: card-signed
//! (not device-signed) verifiable credentials, secured by a cardholder's
//! citizen certificate rather than by this device's own key.
//!
//! Ported from `backupTW-iOS/backupTW/{ZK/IssuerCertificate,
//! Model/MOICASignedCredential}.swift`.

pub mod credential;
pub mod issuer_certificate;

pub use credential::{
    to_be_signed, MoicaCredentialProof, MoicaCredentialVerification, MoicaSignedCredential,
    MoicaSignedCredentialError,
};
pub use issuer_certificate::{
    CertificateValidity, DistinguishedNameAttribute, IssuerCertificate, IssuerCertificateError,
    MoicaGeneration, X509Certificate,
};
