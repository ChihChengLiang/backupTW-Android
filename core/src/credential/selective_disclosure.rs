//! Showing one field without showing the rest.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/SelectiveDisclosure.swift`.
//!
//! A note on scope, not a silent divergence: the iOS decoder strictly
//! requires a disclosure to be a three-element array of all-strings, and
//! `docs/roadmap-2026-08-27.md` (iOS side) already flags this as an
//! unresolved compatibility gap against real telecom/convenience-store
//! cards, whose actual disclosure shape has never been observed in the
//! wild. This port replicates the same strict behavior rather than
//! guessing at a looser one — loosening a security-relevant parser against
//! an unobserved format would be exactly the kind of "repair, not
//! rejection" this codebase's own `did:key` code argues against. Fix it
//! once a real vector exists to test against, not before.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisclosureError {
    /// A disclosure arrived whose digest is not among the ones the issuer
    /// committed to. The holder is trying to add a claim.
    #[error("undisclosed digest: {0}")]
    UndisclosedDigest(String),
    /// The same claim name arrived twice.
    #[error("duplicate claim: {0}")]
    DuplicateClaim(String),
    /// A disclosure string that is not a valid three-element array.
    #[error("malformed disclosure: {0}")]
    MalformedDisclosure(String),
}

/// One hidden claim and the secret needed to reveal it, in the SD-JWT shape.
///
/// The wire form is `base64url(JSON([salt, name, value]))`, and the digest
/// that goes in the credential is taken over **that string**, not over the
/// decoded array — digesting the decoded form would make the value depend
/// on this build's JSON serializer (key order, spacing, escaping), and two
/// implementations that disagree about any of those would compute different
/// digests for the same disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    pub salt: String,
    pub claim_name: String,
    pub claim_value: String,
    /// `base64url(JSON([salt, name, value]))`.
    pub encoded: String,
}

impl Disclosure {
    /// # Why the salt is 128 bits and not, say, a counter
    ///
    /// Without a salt, a digest over a claim drawn from a small domain (a
    /// handful of nationalities, ~40,000 plausible birthdates) is
    /// recoverable by a verifier hashing every candidate until one matches
    /// an entry in `_sd`. Every disclosure gets its own 128 bits from the
    /// system CSPRNG; reusing one salt across claims would also let a
    /// verifier confirm two credentials came from the same issuance.
    pub fn new(claim_name: impl Into<String>, claim_value: impl Into<String>) -> Self {
        Self::with_salt(claim_name, claim_value, random_salt())
    }

    pub fn with_salt(
        claim_name: impl Into<String>,
        claim_value: impl Into<String>,
        salt: String,
    ) -> Self {
        let claim_name = claim_name.into();
        let claim_value = claim_value.into();
        let array = [salt.as_str(), claim_name.as_str(), claim_value.as_str()];
        let json = serde_json::to_vec(&array).unwrap_or_else(|_| b"[]".to_vec());
        let encoded = URL_SAFE_NO_PAD.encode(json);
        Self {
            salt,
            claim_name,
            claim_value,
            encoded,
        }
    }

    /// `base64url(SHA-256(encoded))` — what appears in the credential's
    /// `_sd`.
    pub fn digest(&self) -> String {
        digest_of(&self.encoded)
    }

    /// Rebuilds a disclosure from the wire, refusing anything that is not
    /// exactly a three-element array of non-empty strings (salt and claim
    /// name; an empty claim *value* is a legitimate assertion).
    ///
    /// Strict on purpose: a disclosure carrying a nested object or a number
    /// would be a different shape than the one whose digest the issuer
    /// committed to, and accepting it would mean the verifier and the
    /// issuer disagree about what was disclosed.
    pub fn decode(encoded: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        let array: Vec<serde_json::Value> = serde_json::from_slice(&bytes).ok()?;
        let [salt, name, value] = <[serde_json::Value; 3]>::try_from(array).ok()?;
        let salt = salt.as_str()?.to_owned();
        let claim_name = name.as_str()?.to_owned();
        let claim_value = value.as_str()?.to_owned();
        if salt.is_empty() || claim_name.is_empty() {
            return None;
        }
        Some(Self {
            salt,
            claim_name,
            claim_value,
            encoded: encoded.to_owned(),
        })
    }
}

fn digest_of(encoded: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()))
}

fn random_salt() -> String {
    let mut bytes = [0u8; 16];
    // The system CSPRNG, not a generator seeded for speed: this is the
    // value that stops a verifier brute-forcing an undisclosed claim.
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Turns claims into (`_sd` digests, disclosures).
///
/// The digest array is **sorted**, and that is a security property rather
/// than tidiness. Left in claim order, position would leak which digest
/// belongs to which field: a verifier receiving only the second entry's
/// disclosure would learn that the first, undisclosed one is whatever the
/// issuer always puts first. Sorting by the digest — a value with no
/// relationship to the claim name — destroys that correspondence.
pub fn commit(claims: &[(String, String)]) -> (Vec<String>, Vec<Disclosure>) {
    let disclosures: Vec<Disclosure> = claims
        .iter()
        .map(|(name, value)| Disclosure::new(name.clone(), value.clone()))
        .collect();
    let mut digests: Vec<String> = disclosures.iter().map(Disclosure::digest).collect();
    digests.sort();
    (digests, disclosures)
}

/// Verifies a set of presented disclosures against the issuer's committed
/// digests, and returns the claims they reveal.
///
/// Every disclosure must match a committed digest. A holder who could
/// present a disclosure the issuer never committed to could assert anything
/// — the entire value of the credential rests on this check.
///
/// The reverse is deliberately *not* an error: committed digests with no
/// matching disclosure are the whole point. Those are the claims being
/// withheld, and a verifier that demanded all of them would have abolished
/// selective disclosure while appearing to implement it.
pub fn reveal(
    encoded_disclosures: &[String],
    committed_digests: &[String],
) -> Result<Vec<(String, String)>, DisclosureError> {
    let committed: std::collections::HashSet<&str> =
        committed_digests.iter().map(String::as_str).collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut claims = Vec::with_capacity(encoded_disclosures.len());

    for encoded in encoded_disclosures {
        let disclosure = Disclosure::decode(encoded)
            .ok_or_else(|| DisclosureError::MalformedDisclosure(encoded.clone()))?;
        let digest = disclosure.digest();
        if !committed.contains(digest.as_str()) {
            return Err(DisclosureError::UndisclosedDigest(digest));
        }
        if !seen.insert(disclosure.claim_name.clone()) {
            // Two disclosures for one claim name can carry different
            // values, and which one wins would depend on iteration order.
            return Err(DisclosureError::DuplicateClaim(disclosure.claim_name));
        }
        claims.push((disclosure.claim_name, disclosure.claim_value));
    }
    Ok(claims)
}

/// How many claims were held back — the number a screen should show so the
/// verifier knows the presentation is partial.
///
/// A verifier looking at three fields cannot otherwise tell whether that is
/// the whole credential or three of eight, and "this is everything" is a
/// materially different statement from "this is what they chose to show".
pub fn withheld_count(committed_digests: &[String], revealed: usize) -> usize {
    committed_digests.len().saturating_sub(revealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Vec<(String, String)> {
        vec![
            ("nationality".into(), "中華民國".into()),
            ("unifiedNo".into(), "A123456789".into()),
            ("name".into(), "王小明".into()),
            ("birthdate".into(), "1990-01-01".into()),
            ("addressOfHousehold".into(), "臺北市中正區某路 1 號".into()),
        ]
    }

    #[test]
    fn reveals_only_what_was_chosen() {
        let (digests, disclosures) = commit(&claims());
        let birthdate = disclosures
            .iter()
            .find(|d| d.claim_name == "birthdate")
            .unwrap();

        let revealed = reveal(std::slice::from_ref(&birthdate.encoded), &digests).unwrap();
        assert_eq!(revealed.len(), 1);
        assert_eq!(
            revealed[0],
            ("birthdate".to_string(), "1990-01-01".to_string())
        );

        let material = format!("{}{}", digests.join(""), birthdate.encoded);
        for hidden in ["A123456789", "王小明", "臺北市中正區某路 1 號", "中華民國"]
        {
            assert!(
                !material.contains(hidden),
                "{hidden} leaked into the commitments"
            );
        }
        assert_eq!(withheld_count(&digests, 1), 4);
    }

    #[test]
    fn salts_make_digests_unguessable() {
        let a = Disclosure::new("nationality", "中華民國");
        let b = Disclosure::new("nationality", "中華民國");
        assert_ne!(
            a.digest(),
            b.digest(),
            "unsalted - a verifier could brute-force this"
        );
        assert_ne!(a.salt, b.salt);

        let salt_bytes = URL_SAFE_NO_PAD.decode(&a.salt).unwrap();
        assert_eq!(salt_bytes.len(), 16);
    }

    #[test]
    fn digest_order_does_not_track_claim_order() {
        let (digests, _) = commit(&claims());
        let mut sorted = digests.clone();
        sorted.sort();
        assert_eq!(digests, sorted);

        // Same claims in a different order must produce a self-sorted
        // list too (each `commit` call salts fresh, so the actual digest
        // *values* legitimately differ between the two calls - only their
        // internal ordering is the property under test).
        let mut reversed = claims();
        reversed.reverse();
        let (shuffled, _) = commit(&reversed);
        let mut shuffled_sorted = shuffled.clone();
        shuffled_sorted.sort();
        assert_eq!(shuffled, shuffled_sorted);
    }

    #[test]
    fn refuses_a_claim_the_issuer_never_committed_to() {
        let (digests, _) = commit(&claims());
        let forged = Disclosure::new("isOver18", "true");
        assert_eq!(
            reveal(std::slice::from_ref(&forged.encoded), &digests),
            Err(DisclosureError::UndisclosedDigest(forged.digest()))
        );
    }

    #[test]
    fn refuses_a_tampered_value() {
        let (digests, disclosures) = commit(&claims());
        let original = disclosures
            .iter()
            .find(|d| d.claim_name == "birthdate")
            .unwrap();
        let tampered = Disclosure::with_salt("birthdate", "2010-01-01", original.salt.clone());

        assert_ne!(tampered.digest(), original.digest());
        assert_eq!(
            reveal(std::slice::from_ref(&tampered.encoded), &digests),
            Err(DisclosureError::UndisclosedDigest(tampered.digest()))
        );
    }

    #[test]
    fn refuses_duplicate_claim_names() {
        let a = Disclosure::new("name", "王小明");
        let b = Disclosure::new("name", "李小華");
        let mut digests = vec![a.digest(), b.digest()];
        digests.sort();

        assert_eq!(
            reveal(&[a.encoded.clone(), b.encoded.clone()], &digests),
            Err(DisclosureError::DuplicateClaim("name".to_string()))
        );
    }

    #[test]
    fn withholding_is_not_an_error() {
        let (digests, disclosures) = commit(&claims());
        assert!(reveal(&[], &digests).is_ok());

        let two: Vec<String> = disclosures
            .iter()
            .take(2)
            .map(|d| d.encoded.clone())
            .collect();
        let revealed = reveal(&two, &digests).unwrap();
        assert_eq!(revealed.len(), 2);
        assert_eq!(withheld_count(&digests, revealed.len()), 3);
    }

    #[test]
    fn refuses_malformed_disclosures() {
        let junk = [
            "not-base64url!!".to_string(),
            URL_SAFE_NO_PAD.encode("[1,2,3]"),
            URL_SAFE_NO_PAD.encode(r#"["salt","name"]"#),
            URL_SAFE_NO_PAD.encode(r#"["","name","v"]"#),
        ];
        for j in junk {
            assert!(reveal(std::slice::from_ref(&j), &[]).is_err(), "{j}");
        }
    }

    #[test]
    fn digest_is_stable_across_the_wire() {
        let original = Disclosure::new("birthdate", "1990-01-01");
        let rebuilt = Disclosure::decode(&original.encoded).unwrap();
        assert_eq!(rebuilt, original);
        assert_eq!(rebuilt.digest(), original.digest());
    }
}
