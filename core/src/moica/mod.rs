//! MOICA (自然人憑證) self-issued national-ID credentials: card-signed
//! (not device-signed) verifiable credentials, secured by a cardholder's
//! citizen certificate rather than by this device's own key.
//!
//! This module currently holds the X.509/RSA trust-anchor layer
//! (ported from `backupTW-iOS/backupTW/ZK/IssuerCertificate.swift`);
//! the credential envelope built on top of it
//! (`Model/MOICASignedCredential.swift`) lands in a follow-up PR.

pub mod issuer_certificate;

pub use issuer_certificate::{
    CertificateValidity, DistinguishedNameAttribute, IssuerCertificate, IssuerCertificateError,
    MoicaGeneration, X509Certificate,
};
