//! X.509 certificate parsing and RSA-PKCS1v15-SHA256 verification for
//! MOICA (自然人憑證) card-signed credentials, plus the bundled trust
//! anchor those certificates chain to.
//!
//! Ported from `backupTW-iOS/backupTW/ZK/IssuerCertificate.swift`. Swift
//! hand-rolled a ~700-line DER/X.509 reader there because iOS's
//! Security.framework does not expose certificate internals
//! (`SecCertificateCopyValues` — the call that would give validity
//! dates and extensions — is macOS-only). Rust has no such platform
//! limitation, so this port uses `x509-parser` (DER/X.509 field
//! extraction) and `rsa`/`sha2` (RSASSA-PKCS1-v1_5-SHA256 verification)
//! instead of reimplementing ASN.1 by hand. What must match the Swift
//! source exactly is not the parsing mechanism but: which fields are
//! extracted and checked (SKI/AKI, validity window, Subject CN, RSA
//! modulus width), the trust-anchor pinning discipline (SHA-256 file
//! digest + serial/key-identifier/modulus restatement + chain-signature
//! check), and the verification algorithm (nothing weaker than
//! RSASSA-PKCS1-v1_5-SHA256).
//!
//! See `core/assets/{MOICA-G3,GRCA-G3}.cer` for the bundled trust
//! anchor's provenance (source URLs, fingerprints, why bundled rather
//! than downloaded) — copied verbatim from the Swift source's own
//! provenance comment; nothing about that reasoning changes here.

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

const MOICA_G3_DER: &[u8] = include_bytes!("../../assets/MOICA-G3.cer");
const GRCA_G3_DER: &[u8] = include_bytes!("../../assets/GRCA-G3.cer");

const PINNED_ISSUER_SHA256: &str =
    "ed793fd0d50a2a398049d598982cf01e75f873b532066caec238f800a06ca9da";
const PINNED_ROOT_SHA256: &str = "57df6f20e04c588e85f35be8832f5d4e78958336ae3b18fb7c9bae0dfead4044";
const PINNED_ISSUER_SERIAL_HEX: &str = "5a202d14b39787d0886c37184ac9b76a";
const PINNED_ROOT_SERIAL_HEX: &str = "cd1de713a9adbf68fe2916d8435415c7";

// MARK: - Errors

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuerCertificateError {
    /// The bundled `.cer` could not be parsed at all.
    #[error("bundled certificate unreadable: {resource}")]
    BundledCertificateUnreadable { resource: &'static str },
    /// The bundled file is not the bytes this build was written
    /// against. No retry helps; someone replaced the file.
    #[error("bundled certificate fingerprint mismatch: {resource}")]
    FingerprintMismatch {
        resource: &'static str,
        expected: String,
        actual: String,
    },
    /// The bundled anchor parses but is not the certificate the pins
    /// describe (wrong serial, wrong key identifier, wrong modulus
    /// width) — distinct from `FingerprintMismatch` because it catches
    /// the case where the digest constant was updated to match a
    /// substituted file but the rest was not.
    #[error("bundled certificate mismatch: {resource}: {detail}")]
    BundledCertificateMismatch {
        resource: &'static str,
        detail: String,
    },
    /// The bundled anchor is not signed by the bundled government root.
    #[error("bundled certificate chain is broken")]
    BundledChainBroken,
    /// The anchor's own validity window has passed.
    #[error("trust anchor expired")]
    TrustAnchorExpired { not_after_unix_seconds: i64 },
    /// This device's clock is behind the anchor's validity window.
    #[error("trust anchor not yet valid")]
    TrustAnchorNotYetValid { not_before_unix_seconds: i64 },
    /// The cardholder certificate could not be parsed at all.
    #[error("holder certificate malformed: {0}")]
    HolderCertificateMalformed(String),
    /// The cardholder certificate has no AuthorityKeyIdentifier, so
    /// there is nothing to match a generation against.
    #[error("holder certificate issuer unknown")]
    HolderIssuerUnknown,
    /// The cardholder certificate names a CA this build cannot prove
    /// for (a real but unsupported generation).
    #[error("holder certificate issuer unsupported: {0:?}")]
    HolderIssuerUnsupported(MoicaGeneration),
    /// The cardholder certificate's AKI says G3 but its signature does
    /// not verify under the bundled G3 key.
    #[error("holder certificate signature invalid")]
    HolderSignatureInvalid,
    #[error("holder certificate expired")]
    HolderCertificateExpired { not_after_unix_seconds: i64 },
    #[error("holder certificate not yet valid")]
    HolderCertificateNotYetValid { not_before_unix_seconds: i64 },
}

impl IssuerCertificateError {
    /// Whether trying the same thing again could produce a different
    /// answer. The two not-yet-valid cases mean "this device's clock is
    /// behind"; everything else is a fixed sequence of bytes that no
    /// retry rewrites.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::TrustAnchorNotYetValid { .. } | Self::HolderCertificateNotYetValid { .. }
        )
    }
}

// MARK: - Generations

/// Which generation of 內政部憑證管理中心 signed a certificate. Distinguished
/// only by the CA's SubjectKeyIdentifier — all three generations share
/// a byte-identical subject DN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoicaGeneration {
    /// RSA-2048, issued 2003, expired 2023-04-21.
    G1,
    /// RSA-2048, valid until 2034-01-02.
    G2,
    /// RSA-4096, valid until 2044-01-23. The only generation this build supports.
    G3,
}

impl MoicaGeneration {
    const G1_KEY_ID: [u8; 20] = [
        0xB6, 0x20, 0xC8, 0xCF, 0xBE, 0x51, 0x8A, 0xA4, 0x54, 0xB9, 0x78, 0xD3, 0x04, 0xD1, 0x0A,
        0xB2, 0xCC, 0x7E, 0x2F, 0x46,
    ];
    const G2_KEY_ID: [u8; 20] = [
        0xFA, 0x9B, 0x34, 0x67, 0x09, 0x0A, 0x98, 0x22, 0xF7, 0x62, 0x48, 0x8B, 0x82, 0x26, 0xA6,
        0x45, 0xC5, 0xC3, 0x22, 0xA4,
    ];
    const G3_KEY_ID: [u8; 20] = [
        0x47, 0x20, 0xA3, 0xB1, 0x26, 0x4B, 0xCD, 0x6D, 0x48, 0xAC, 0xF2, 0x64, 0x08, 0x86, 0x97,
        0x2C, 0x74, 0x54, 0x11, 0x5F,
    ];

    pub fn key_identifier(&self) -> &'static [u8] {
        match self {
            Self::G1 => &Self::G1_KEY_ID,
            Self::G2 => &Self::G2_KEY_ID,
            Self::G3 => &Self::G3_KEY_ID,
        }
    }

    pub fn modulus_bit_count(&self) -> u32 {
        match self {
            Self::G1 | Self::G2 => 2048,
            Self::G3 => 4096,
        }
    }

    /// `None` means "not one we know about" - a future G4, or a
    /// certificate from somewhere else entirely. Treat that as
    /// unsupported, never as "probably fine".
    pub fn matching(key_identifier: &[u8]) -> Option<Self> {
        [Self::G1, Self::G2, Self::G3]
            .into_iter()
            .find(|g| g.key_identifier() == key_identifier)
    }
}

/// How a certificate's validity window looks at a given moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateValidity {
    Valid,
    NotYetValid { not_before_unix_seconds: i64 },
    Expired { not_after_unix_seconds: i64 },
}

// MARK: - Certificate

/// The parts of an X.509 certificate this app has to reason about.
/// Deliberately not a general-purpose certificate type - it carries
/// what the trust-anchor and card-signature checks need and nothing
/// more. Parsed once via `x509-parser`, then fully owned (no borrowed
/// lifetime), matching the Swift `X509Certificate`'s shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Certificate {
    pub der: Vec<u8>,
    /// The `tbsCertificate` element including its own header - the
    /// bytes the issuer signed.
    tbs_certificate: Vec<u8>,
    signature_algorithm_oid: Vec<u8>,
    signature: Vec<u8>,
    /// Serial number content bytes, big-endian, exactly as encoded.
    serial_number: Vec<u8>,
    issuer_name: Vec<u8>,
    subject_name: Vec<u8>,
    not_before_unix_seconds: i64,
    not_after_unix_seconds: i64,
    rsa_modulus: Option<Vec<u8>>,
    rsa_exponent: Option<Vec<u8>>,
    rsa_modulus_bit_count: Option<u32>,
    subject_key_identifier: Option<Vec<u8>>,
    authority_key_identifier: Option<Vec<u8>>,
}

impl X509Certificate {
    /// Lowercase hex SHA-256 of the whole certificate.
    pub fn sha256_hex(&self) -> String {
        hex_encode(&Sha256::digest(&self.der))
    }

    /// Lowercase hex of the serial number's magnitude. DER INTEGERs are
    /// signed, so a serial whose leading byte has the high bit set is
    /// encoded with an extra `0x00` in front; every tool that prints a
    /// serial shows the magnitude, so a pin written from one of those
    /// would never match the encoded bytes without dropping it.
    pub fn serial_number_hex(&self) -> String {
        let mut magnitude = self.serial_number.as_slice();
        if magnitude.len() > 1 && magnitude[0] == 0x00 && magnitude[1] >= 0x80 {
            magnitude = &magnitude[1..];
        }
        hex_encode(magnitude)
    }

    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        self.subject_key_identifier.as_deref()
    }

    pub fn authority_key_identifier(&self) -> Option<&[u8]> {
        self.authority_key_identifier.as_deref()
    }

    pub fn validity(&self, now_unix_seconds: i64) -> CertificateValidity {
        if now_unix_seconds < self.not_before_unix_seconds {
            CertificateValidity::NotYetValid {
                not_before_unix_seconds: self.not_before_unix_seconds,
            }
        } else if now_unix_seconds > self.not_after_unix_seconds {
            CertificateValidity::Expired {
                not_after_unix_seconds: self.not_after_unix_seconds,
            }
        } else {
            CertificateValidity::Valid
        }
    }

    pub fn parse(der: &[u8]) -> Result<Self, IssuerCertificateError> {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| IssuerCertificateError::HolderCertificateMalformed(e.to_string()))?;

        // RFC 5280 §4.1.1.2: the AlgorithmIdentifier inside the signed
        // body and the one outside it must agree - they are signed and
        // unsigned copies of the same claim, so a mismatch means
        // someone edited the unsigned one.
        let outer_oid = cert.signature_algorithm.algorithm.as_bytes().to_vec();
        let inner_oid = cert.tbs_certificate.signature.algorithm.as_bytes().to_vec();
        if outer_oid != inner_oid {
            return Err(IssuerCertificateError::HolderCertificateMalformed(
                "signature algorithm inside and outside the signed body disagree".to_string(),
            ));
        }

        let mut subject_key_identifier = None;
        let mut authority_key_identifier = None;
        for extension in cert.tbs_certificate.extensions() {
            match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => {
                    subject_key_identifier = Some(id.0.to_vec());
                }
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    authority_key_identifier = aki.key_identifier.as_ref().map(|id| id.0.to_vec());
                }
                _ => {}
            }
        }

        let (rsa_modulus, rsa_exponent, rsa_modulus_bit_count) =
            match cert.tbs_certificate.public_key().parsed() {
                Ok(x509_parser::public_key::PublicKey::RSA(key)) => {
                    let bit_count = rsa_modulus_bit_count(key.modulus);
                    (
                        Some(key.modulus.to_vec()),
                        Some(key.exponent.to_vec()),
                        Some(bit_count),
                    )
                }
                _ => (None, None, None),
            };

        Ok(Self {
            der: der.to_vec(),
            tbs_certificate: cert.tbs_certificate.as_ref().to_vec(),
            signature_algorithm_oid: outer_oid,
            signature: cert.signature_value.as_ref().to_vec(),
            serial_number: cert.tbs_certificate.raw_serial().to_vec(),
            issuer_name: cert.tbs_certificate.issuer().as_raw().to_vec(),
            subject_name: cert.tbs_certificate.subject().as_raw().to_vec(),
            not_before_unix_seconds: cert.tbs_certificate.validity().not_before.timestamp(),
            not_after_unix_seconds: cert.tbs_certificate.validity().not_after.timestamp(),
            rsa_modulus,
            rsa_exponent,
            rsa_modulus_bit_count,
            subject_key_identifier,
            authority_key_identifier,
        })
    }

    /// TW FidO hands back standard base64 of the DER. Reject anything
    /// that is not exactly that rather than trying base64url as a
    /// fallback: a silent re-interpretation here becomes a proof that
    /// never verifies, with nothing pointing back to this line.
    pub fn parse_base64_der(base64_der: &str) -> Result<Self, IssuerCertificateError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let der = STANDARD.decode(base64_der).map_err(|_| {
            IssuerCertificateError::HolderCertificateMalformed("not valid base64".to_string())
        })?;
        Self::parse(&der)
    }

    fn rsa_public_key(&self) -> Result<RsaPublicKey, IssuerCertificateError> {
        let (Some(modulus), Some(exponent)) = (&self.rsa_modulus, &self.rsa_exponent) else {
            return Err(IssuerCertificateError::HolderCertificateMalformed(
                "key is not RSA".to_string(),
            ));
        };
        RsaPublicKey::new(
            BigUint::from_bytes_be(modulus),
            BigUint::from_bytes_be(exponent),
        )
        .map_err(|_| {
            IssuerCertificateError::HolderCertificateMalformed("invalid RSA key".to_string())
        })
    }

    /// Whether this certificate's signature verifies under `issuer`'s
    /// public key. Only the arithmetic - says nothing about whether
    /// `issuer` is allowed to sign, is in date, or is the CA you meant.
    pub fn is_signature_valid(
        &self,
        issuer: &X509Certificate,
    ) -> Result<bool, IssuerCertificateError> {
        // SHA-1 is absent on purpose: MOICA G3 signs with SHA-256 and
        // nothing in this pipeline needs to accept a weaker digest.
        const RSA_SHA256: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        if self.signature_algorithm_oid != RSA_SHA256 {
            return Err(IssuerCertificateError::HolderCertificateMalformed(
                "unsupported signature algorithm".to_string(),
            ));
        }
        let key = issuer.rsa_public_key()?;
        let hashed = Sha256::digest(&self.tbs_certificate);
        Ok(key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &self.signature)
            .is_ok())
    }

    /// Whether `signature` is an RSASSA-PKCS1-v1_5 SHA-256 signature
    /// over `message` under **this certificate's subject key** - what a
    /// card-signed credential needs, distinct from `is_signature_valid`
    /// (which asks whether a CA signed this certificate).
    pub fn verifies_pkcs1_sha256(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, IssuerCertificateError> {
        let key = self.rsa_public_key()?;
        let hashed = Sha256::digest(message);
        Ok(key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, signature)
            .is_ok())
    }

    /// The value of `attribute` in this certificate's **Subject** DN -
    /// Subject, never Issuer (the issuer is 內政部憑證管理中心 for every
    /// cardholder, which would make a holder-binding check pass for
    /// everyone).
    pub fn subject_attribute(
        &self,
        attribute: DistinguishedNameAttribute,
    ) -> Result<Option<String>, IssuerCertificateError> {
        directory_name_attribute(&self.subject_name, attribute)
    }

    fn issuer_name_matches_subject(&self, other: &X509Certificate) -> bool {
        self.issuer_name == other.subject_name
    }
}

fn rsa_modulus_bit_count(modulus: &[u8]) -> u32 {
    let mut magnitude = modulus;
    while magnitude.first() == Some(&0) {
        magnitude = &magnitude[1..];
    }
    match magnitude.first() {
        Some(&leading) => (magnitude.len() as u32 - 1) * 8 + (8 - leading.leading_zeros().min(8)),
        None => 0,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// MARK: - Distinguished name

/// A distinguished-name attribute this app reads by name.
///
/// **The 身分證統一編號 is not in the certificate** (measured on a real TW
/// FidO `result.cert`: the Subject DN holds exactly `C=TW`,
/// `CN=<name>`, `serialNumber=<16 digits>`, and the 16-digit
/// `serialNumber` is not the national ID's shape). The only value in
/// the certificate a verifier can compare against a credential's claims
/// is the **name**, and a name is not unique - the binding between "the
/// cardholder who signed" and "the person these fields describe" is
/// enforced by 內政部 at signing time, not by this comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistinguishedNameAttribute {
    /// `2.5.4.3`.
    CommonName,
    /// `2.5.4.5`. **Not** the 身分證統一編號.
    SerialNumber,
}

impl DistinguishedNameAttribute {
    fn object_identifier(&self) -> [u8; 3] {
        match self {
            Self::CommonName => [0x55, 0x04, 0x03],
            Self::SerialNumber => [0x55, 0x04, 0x05],
        }
    }
}

/// `Name ::= RDNSequence`. A DN carrying the same attribute twice is an
/// error rather than "pick one": there is no rule saying which wins, so
/// two implementations reading the same certificate could disagree
/// about whose name is on it.
fn directory_name_attribute(
    raw_name: &[u8],
    attribute: DistinguishedNameAttribute,
) -> Result<Option<String>, IssuerCertificateError> {
    let (_, name) = x509_parser::x509::X509Name::from_der(raw_name)
        .map_err(|e| IssuerCertificateError::HolderCertificateMalformed(e.to_string()))?;
    let oid = attribute.object_identifier();

    let mut found: Option<String> = None;
    for entry in name.iter_attributes() {
        if entry.attr_type().as_bytes() != oid {
            continue;
        }
        if found.is_some() {
            return Err(IssuerCertificateError::HolderCertificateMalformed(format!(
                "distinguished name carries {attribute:?} twice"
            )));
        }
        found = Some(directory_string(entry.attr_value())?);
    }
    Ok(found)
}

/// Decodes the one `DirectoryString` choice the value turned out to be.
/// `TeletexString` is deliberately absent - its character set is
/// under-specified and implementations disagree about whether the bytes
/// are T.61 or Latin-1, which makes a name comparison meaningless.
fn directory_string(value: &asn1_rs::Any) -> Result<String, IssuerCertificateError> {
    let bytes = value.data;
    match value.tag().0 {
        // UTF8String, PrintableString, IA5String - all ASCII-compatible-or-UTF-8.
        12 | 19 | 22 => String::from_utf8(bytes.to_vec()).map_err(|_| {
            IssuerCertificateError::HolderCertificateMalformed(
                "name attribute is not valid UTF-8".to_string(),
            )
        }),
        // BMPString - UTF-16BE. Present in older Taiwanese certificates.
        30 => {
            if !bytes.len().is_multiple_of(2) {
                return Err(IssuerCertificateError::HolderCertificateMalformed(
                    "name attribute is not valid UTF-16".to_string(),
                ));
            }
            let (chunks, _) = bytes.as_chunks::<2>();
            let units: Vec<u16> = chunks.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16(&units).map_err(|_| {
                IssuerCertificateError::HolderCertificateMalformed(
                    "name attribute is not valid UTF-16".to_string(),
                )
            })
        }
        tag => Err(IssuerCertificateError::HolderCertificateMalformed(format!(
            "unsupported name attribute encoding (tag {tag})"
        ))),
    }
}

// MARK: - The trust anchor

/// The bundled 內政部憑證管理中心 G3 certificate, loaded and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerCertificate {
    pub certificate: X509Certificate,
    pub root: X509Certificate,
}

impl IssuerCertificate {
    pub const SUPPORTED_GENERATION: MoicaGeneration = MoicaGeneration::G3;

    /// Loads and fully checks the bundled trust anchor: fingerprint
    /// pin, identity restatement, chain-signature check, validity
    /// window on both certificates.
    pub fn load_bundled(now_unix_seconds: i64) -> Result<Self, IssuerCertificateError> {
        check_fingerprint(MOICA_G3_DER, PINNED_ISSUER_SHA256, "MOICA-G3")?;
        check_fingerprint(GRCA_G3_DER, PINNED_ROOT_SHA256, "GRCA-G3")?;

        let issuer = parse_bundled(MOICA_G3_DER, "MOICA-G3")?;
        let root = parse_bundled(GRCA_G3_DER, "GRCA-G3")?;

        // The digest pin above already fixes these bytes; this restates
        // the identity in independent ways so a substituted file *and*
        // a matching constant update in the same commit is still a
        // conspicuous diff.
        check_identity(
            &issuer,
            "MOICA-G3",
            PINNED_ISSUER_SERIAL_HEX,
            Some(Self::SUPPORTED_GENERATION.key_identifier()),
            Self::SUPPORTED_GENERATION.modulus_bit_count(),
        )?;
        check_identity(&root, "GRCA-G3", PINNED_ROOT_SERIAL_HEX, None, 4096)?;

        // The issuing CA's subject is byte-identical across G1/G2/G3,
        // so this proves only that the file is *a* MOICA certificate -
        // the key-identifier check above is what establishes which one.
        if !issuer.issuer_name_matches_subject(&root) {
            return Err(IssuerCertificateError::BundledChainBroken);
        }
        if !issuer
            .is_signature_valid(&root)
            .map_err(|_| IssuerCertificateError::BundledChainBroken)?
        {
            return Err(IssuerCertificateError::BundledChainBroken);
        }

        // Both anchors are checked - a chain is only as in-date as its
        // weakest link, and the root outlives the sub-CA by five years.
        for certificate in [&root, &issuer] {
            match certificate.validity(now_unix_seconds) {
                CertificateValidity::Valid => {}
                CertificateValidity::Expired {
                    not_after_unix_seconds,
                } => {
                    return Err(IssuerCertificateError::TrustAnchorExpired {
                        not_after_unix_seconds,
                    })
                }
                CertificateValidity::NotYetValid {
                    not_before_unix_seconds,
                } => {
                    return Err(IssuerCertificateError::TrustAnchorNotYetValid {
                        not_before_unix_seconds,
                    })
                }
            }
        }

        Ok(Self {
            certificate: issuer,
            root,
        })
    }

    /// Decides whether a cardholder certificate can be proven by this
    /// build, and returns it parsed if so.
    ///
    /// Checks run in the order a user can act on: (1) which CA issued
    /// it, (2) whether it is in date, (3) whether the signature holds.
    /// Steps 1 and 2 read unauthenticated fields, so their answers are
    /// diagnostics rather than security decisions - nothing is trusted
    /// until step 3.
    pub fn validate_holder_certificate(
        &self,
        holder: &X509Certificate,
        now_unix_seconds: i64,
    ) -> Result<(), IssuerCertificateError> {
        let Some(aki) = holder.authority_key_identifier() else {
            return Err(IssuerCertificateError::HolderIssuerUnknown);
        };
        let Some(generation) = MoicaGeneration::matching(aki) else {
            return Err(IssuerCertificateError::HolderIssuerUnknown);
        };
        if generation != Self::SUPPORTED_GENERATION {
            return Err(IssuerCertificateError::HolderIssuerUnsupported(generation));
        }

        match holder.validity(now_unix_seconds) {
            CertificateValidity::Valid => {}
            CertificateValidity::Expired {
                not_after_unix_seconds,
            } => {
                return Err(IssuerCertificateError::HolderCertificateExpired {
                    not_after_unix_seconds,
                })
            }
            CertificateValidity::NotYetValid {
                not_before_unix_seconds,
            } => {
                return Err(IssuerCertificateError::HolderCertificateNotYetValid {
                    not_before_unix_seconds,
                })
            }
        }

        let signature_holds = holder
            .is_signature_valid(&self.certificate)
            .unwrap_or(false);
        if !signature_holds {
            return Err(IssuerCertificateError::HolderSignatureInvalid);
        }
        Ok(())
    }

    pub fn validate_holder_certificate_base64_der(
        &self,
        base64_der: &str,
        now_unix_seconds: i64,
    ) -> Result<X509Certificate, IssuerCertificateError> {
        let holder = X509Certificate::parse_base64_der(base64_der)?;
        self.validate_holder_certificate(&holder, now_unix_seconds)?;
        Ok(holder)
    }
}

fn check_fingerprint(
    der: &[u8],
    expected: &str,
    resource: &'static str,
) -> Result<(), IssuerCertificateError> {
    let actual = hex_encode(&Sha256::digest(der));
    if actual != expected {
        return Err(IssuerCertificateError::FingerprintMismatch {
            resource,
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

fn parse_bundled(
    der: &[u8],
    resource: &'static str,
) -> Result<X509Certificate, IssuerCertificateError> {
    X509Certificate::parse(der).map_err(|e| IssuerCertificateError::BundledCertificateMismatch {
        resource,
        detail: e.to_string(),
    })
}

fn check_identity(
    certificate: &X509Certificate,
    resource: &'static str,
    serial_number_hex: &str,
    key_identifier: Option<&[u8]>,
    modulus_bit_count: u32,
) -> Result<(), IssuerCertificateError> {
    if certificate.serial_number_hex() != serial_number_hex {
        return Err(IssuerCertificateError::BundledCertificateMismatch {
            resource,
            detail: format!("serial number {}", certificate.serial_number_hex()),
        });
    }
    if let Some(key_identifier) = key_identifier {
        if certificate.subject_key_identifier() != Some(key_identifier) {
            return Err(IssuerCertificateError::BundledCertificateMismatch {
                resource,
                detail: "subject key identifier".to_string(),
            });
        }
    }
    if certificate.rsa_modulus_bit_count != Some(modulus_bit_count) {
        return Err(IssuerCertificateError::BundledCertificateMismatch {
            resource,
            detail: format!(
                "RSA modulus is {} bits",
                certificate
                    .rsa_modulus_bit_count
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "not RSA".to_string())
            ),
        });
    }
    Ok(())
}

/// A synthetic certificate built directly from a throwaway RSA key,
/// bypassing DER parsing entirely - shared with `moica::credential`'s
/// own tests. Reachable with a throwaway key, matching the Swift test
/// suite's exact split: a real MOICA-signed certificate is a real
/// person's and is not something to check into a repository, so
/// `verify_signed_by`/`verifies_pkcs1_sha256` are what a throwaway key
/// can exercise fully; only the chain-to-the-real-anchor step cannot be.
#[cfg(test)]
pub(crate) fn test_certificate(common_name: &str, key: &RsaPublicKey) -> X509Certificate {
    use rsa::traits::PublicKeyParts;
    X509Certificate {
        der: Vec::new(),
        tbs_certificate: Vec::new(),
        signature_algorithm_oid: Vec::new(),
        signature: Vec::new(),
        serial_number: vec![0x01],
        issuer_name: Vec::new(),
        subject_name: der_name_with_common_name(common_name),
        not_before_unix_seconds: 0,
        not_after_unix_seconds: i64::MAX,
        rsa_modulus: Some(key.n().to_bytes_be()),
        rsa_exponent: Some(key.e().to_bytes_be()),
        rsa_modulus_bit_count: Some(key.size() as u32 * 8),
        subject_key_identifier: None,
        authority_key_identifier: None,
    }
}

/// Hand-encodes `Name ::= RDNSequence` carrying exactly one `CN=<value>`
/// UTF8String attribute - the minimal shape `subject_attribute` needs to
/// parse, for tests that have no real certificate to draw one from.
#[cfg(test)]
fn der_name_with_common_name(value: &str) -> Vec<u8> {
    fn der_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else {
            let bytes = len.to_be_bytes();
            let trimmed: Vec<u8> = bytes.iter().skip_while(|&&b| b == 0).copied().collect();
            let mut out = vec![0x80 | trimmed.len() as u8];
            out.extend(trimmed);
            out
        }
    }
    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_length(content.len()));
        out.extend_from_slice(content);
        out
    }
    // commonName OID 2.5.4.3
    let oid = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    let utf8_value = der_tlv(0x0C, value.as_bytes());
    let mut attribute_value = oid;
    attribute_value.extend(utf8_value);
    let attribute_type_and_value = der_tlv(0x30, &attribute_value);
    let relative_distinguished_name = der_tlv(0x31, &attribute_type_and_value);
    der_tlv(0x30, &relative_distinguished_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        1_757_000_000 // 2025-09-04, well inside every relevant validity window
    }

    #[test]
    fn the_bundled_trust_anchor_loads_and_checks_out() {
        let anchor = IssuerCertificate::load_bundled(now()).unwrap();
        assert_eq!(
            anchor.certificate.serial_number_hex(),
            PINNED_ISSUER_SERIAL_HEX
        );
        assert_eq!(anchor.root.serial_number_hex(), PINNED_ROOT_SERIAL_HEX);
        // MOICA-G3's own SubjectKeyIdentifier is what becomes the
        // AuthorityKeyIdentifier of every certificate *it* signs
        // (cardholder certificates) - not of itself.
        assert_eq!(
            anchor.certificate.subject_key_identifier(),
            Some(MoicaGeneration::G3.key_identifier())
        );
        // Its own AKI points at the root's SKI (GRCA-G3), confirming
        // the parsed chain-of-issuance relationship independently of
        // the signature check `load_bundled` already ran.
        assert_eq!(
            anchor.certificate.authority_key_identifier(),
            anchor.root.subject_key_identifier()
        );
    }

    #[test]
    fn verifies_pkcs1_sha256_round_trips_with_a_throwaway_key() {
        use rand::rngs::OsRng;
        use rsa::RsaPrivateKey;

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let certificate = test_certificate("測試持卡人", &public_key);

        let message = b"bonds-tw-credential-v1:deadbeef";
        let hashed = Sha256::digest(message);
        let signature = private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
            .unwrap();

        assert!(certificate
            .verifies_pkcs1_sha256(&signature, message)
            .unwrap());
        assert!(!certificate
            .verifies_pkcs1_sha256(&signature, b"a different message")
            .unwrap());

        assert_eq!(
            certificate
                .subject_attribute(DistinguishedNameAttribute::CommonName)
                .unwrap(),
            Some("測試持卡人".to_string())
        );
    }

    #[test]
    fn generation_matching_finds_g3_and_refuses_unknown_ids() {
        assert_eq!(
            MoicaGeneration::matching(MoicaGeneration::G3.key_identifier()),
            Some(MoicaGeneration::G3)
        );
        assert_eq!(MoicaGeneration::matching(&[0u8; 20]), None);
    }

    #[test]
    fn a_random_key_id_is_not_a_recognised_generation() {
        assert!(MoicaGeneration::matching(b"not a real key identifier!!").is_none());
    }
}
