//! Who a verifier is willing to believe, and how that set can change in an
//! emergency without anybody being able to change it quietly.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/TrustList.swift` — see
//! that file for the extensive rationale (why this is a commitment rather
//! than a fetch, why the commitment is over a hand-reproducible
//! tab-separated form rather than JSON, and two adversarial findings this
//! design closes: a `note` field that could smuggle a whole forged row past
//! the delimiter check, and U+2028/U+2029 splitting a line without being a
//! control character).
//!
//! **A note on the JSON wire format's exact bytes**: [`TrustList::encoded`]
//! produces sorted-key, pretty-printed JSON, and [`TrustList::decoded`]'s
//! round-trip check only requires *this crate's own* encoder and decoder to
//! agree — which they do, by construction. Swift's `JSONEncoder`
//! `.prettyPrinted` output uses `"key" : value` (a space *before* the
//! colon too); `serde_json`'s pretty printer does not. If a real
//! Swift-published trust-list JSON file is ever handed to this decoder,
//! the two need to be checked byte-for-byte before assuming interop — this
//! has not been done. [`TrustList::canonical_form`] (what actually gets
//! published/hashed/anchored) has no such gap: it's verified against an
//! independent, non-Swift-derived vector in this module's tests.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_general_category::{get_general_category, GeneralCategory};

/// Bumped when the meaning of any field changes; an unrecognised version is
/// refused rather than guessed at.
pub const CURRENT_VERSION: i32 = 1;

/// A ceiling per field, so a list cannot be made enormous by one value.
const MAXIMUM_FIELD_LENGTH: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The issuer's identifier. A `did:key` for a device- or mirror-issued
    /// credential; for MOICA the RSA modulus is what actually gets
    /// checked, and this is the label a person reads.
    pub id: String,
    /// What a human should see. Never rendered from `id`.
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// Why this issuer is on the list, so a list that has grown over time
    /// can be audited by reading it.
    pub note: String,
    /// Whether this entry is a mirror standing in for an unavailable
    /// primary issuer, rather than a primary issuer itself.
    #[serde(rename = "isMirror")]
    pub is_mirror: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustList {
    pub version: i32,
    /// When this list was published, as the string the publisher wrote —
    /// kept verbatim so the digest is over what they published, not over
    /// this build's re-rendering of it.
    pub published_at: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustListError {
    #[error("unsupported version: {0}")]
    UnsupportedVersion(i32),
    #[error("commitment mismatch: expected {expected}, actual {actual}")]
    CommitmentMismatch { expected: String, actual: String },
    #[error("duplicate issuer: {0}")]
    DuplicateIssuer(String),
    #[error("empty trust list")]
    Empty,
    /// **The fix for a collision that worked.** The canonical form joins
    /// fields with tab and rows with newline; without this check, a `note`
    /// could carry `"\n" + a whole forged row` and produce a
    /// byte-identical canonical form (and commitment) to a list with an
    /// extra trusted issuer — see the module docs.
    #[error("field {field} contains a delimiter character")]
    FieldContainsDelimiter { field: String },
    #[error("field {field} is too long ({bytes} bytes)")]
    FieldTooLong { field: String, bytes: usize },
    /// An identifier outside printable ASCII, or empty.
    #[error("identifier is not printable ASCII: {0}")]
    IdentifierNotPrintableAscii(String),
    /// The bytes parsed, but they are not the bytes this build emits for
    /// what they parsed to — duplicate keys, unknown keys, or different
    /// formatting.
    #[error("not canonical JSON")]
    NotCanonicalJson,
}

/// Where a validated list's authority came from.
///
/// Two cases, deliberately: there is no `pinnedInBinary` because there is
/// no pinned commitment yet, and no on-chain-anchored case because there is
/// no chain to walk. Adding one later should mean auditing every match on
/// this enum, which is exactly why it isn't a bool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// The list matched a commitment the caller supplied. Where the caller
    /// got that value is the caller's business and is *not* established
    /// here.
    MatchedSuppliedExpectation { commitment: String },
    /// Well formed, and nobody said which list to expect. **Not a pass.**
    Unconfirmed,
}

/// Everything that may never appear inside a value: Cc union Cf (control
/// and format characters), plus U+2028/U+2029 (Zl/Zp - line/paragraph
/// separators that split a line exactly like `\n` without being a control
/// character), plus the bidi override/isolate ranges explicitly (redundant
/// with Cf, kept for the same belt-and-braces reason the Swift source
/// does).
fn is_forbidden(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Control | GeneralCategory::Format
    ) || c == '\u{2028}'
        || c == '\u{2029}'
        || ('\u{202A}'..='\u{202E}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// What an `id` may contain: printable ASCII, and nothing else.
///
/// Not decoration: sorting decides row order and therefore the digest.
/// Restricting `id` to printable ASCII removes any question of
/// normalization-aware vs. byte-wise sort disagreeing (unlike Swift's
/// `String.<`, Rust's `str` `Ord` already compares UTF-8 bytes directly —
/// but the restriction stays, matching the source, so the guarantee does
/// not rest on that implementation detail alone).
fn is_allowed_in_identifier(c: char) -> bool {
    ('\u{21}'..='\u{7E}').contains(&c)
}

impl TrustList {
    /// SHA-256 over [`canonical_form`](Self::canonical_form), lowercase
    /// hex. This is the value that gets published, printed, read aloud on
    /// the radio, or eventually anchored on-chain.
    pub fn commitment(&self) -> String {
        Sha256::digest(self.canonical_form().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The bytes the digest is taken over.
    ///
    /// Line-oriented and explicit rather than JSON: the property that
    /// matters is that two implementations agree byte for byte, and a
    /// format a person can reproduce by hand is one that can be checked
    /// when it matters. Entries are sorted by `id`'s UTF-8 bytes so
    /// publication order cannot change the digest.
    pub fn canonical_form(&self) -> String {
        // The entry count is in the header, so a row cannot be smuggled in
        // or out without the digest moving even if some future field
        // escapes the delimiter check.
        let mut lines = vec![
            format!(
                "bonds.tw/trust-list/v{}/{}",
                self.version,
                self.entries.len()
            ),
            self.published_at.clone(),
        ];
        let mut sorted_entries: Vec<&Entry> = self.entries.iter().collect();
        sorted_entries.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
        for entry in sorted_entries {
            // Tab-separated. `displayName` and `note` are included too: a
            // list that could be relabelled without changing its digest
            // would let somebody rename an issuer to impersonate another
            // while still matching a published value.
            lines.push(format!(
                "{}\t{}\t{}\t{}",
                entry.id,
                if entry.is_mirror { "mirror" } else { "primary" },
                entry.display_name,
                entry.note,
            ));
        }
        // An explicit terminator, so a truncated file is not a shorter
        // list with a different-but-valid digest.
        lines.push("end".to_string());
        lines.join("\n") + "\n"
    }

    /// Checks the list is well formed and, when an expected commitment is
    /// supplied, that it is the list that was published.
    ///
    /// `expected_commitment`'s absence is **not** a pass: it means "nobody
    /// told this device which list to expect", and the caller has to
    /// render that as the weaker [`Provenance::Unconfirmed`] it is.
    pub fn validate(
        &self,
        expected_commitment: Option<&str>,
    ) -> Result<Provenance, TrustListError> {
        if self.version != CURRENT_VERSION {
            return Err(TrustListError::UnsupportedVersion(self.version));
        }
        if self.entries.is_empty() {
            return Err(TrustListError::Empty);
        }

        // Checked before anything else that reads a field, and checked on
        // every field including the ones that look like metadata.
        let check = |name: &str, value: &str| -> Result<(), TrustListError> {
            if value.chars().any(is_forbidden) {
                return Err(TrustListError::FieldContainsDelimiter {
                    field: name.to_string(),
                });
            }
            if value.len() > MAXIMUM_FIELD_LENGTH {
                return Err(TrustListError::FieldTooLong {
                    field: name.to_string(),
                    bytes: value.len(),
                });
            }
            Ok(())
        };
        check("publishedAt", &self.published_at)?;
        for entry in &self.entries {
            check(&format!("id of {}", entry.id), &entry.id)?;
            check(&format!("displayName of {}", entry.id), &entry.display_name)?;
            check(&format!("note of {}", entry.id), &entry.note)?;
            // Non-empty first: an empty identifier would otherwise
            // vacuously satisfy "every character is allowed" and
            // `trusts("")` would answer yes.
            if entry.id.is_empty() || !entry.id.chars().all(is_allowed_in_identifier) {
                return Err(TrustListError::IdentifierNotPrintableAscii(
                    entry.id.clone(),
                ));
            }
        }

        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if !seen.insert(entry.id.clone()) {
                // Two entries for one issuer can disagree about
                // `is_mirror`, and which one wins would then depend on
                // iteration order.
                return Err(TrustListError::DuplicateIssuer(entry.id.clone()));
            }
        }

        if let Some(expected_commitment) = expected_commitment {
            let actual = self.commitment();
            // Case-insensitive: a hex digest differing only in case is
            // the same digest, and refusing it would be a false alarm
            // during exactly the emergency this list is for.
            if actual.to_lowercase() != expected_commitment.to_lowercase() {
                return Err(TrustListError::CommitmentMismatch {
                    expected: expected_commitment.to_string(),
                    actual,
                });
            }
            return Ok(Provenance::MatchedSuppliedExpectation { commitment: actual });
        }
        Ok(Provenance::Unconfirmed)
    }

    // MARK: - Asking

    pub fn entry(&self, issuer: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == issuer)
    }

    /// Whether this list names `issuer`, compared by UTF-8 bytes.
    pub fn trusts(&self, issuer: &str) -> bool {
        let wanted = issuer.as_bytes();
        self.entries.iter().any(|e| e.id.as_bytes() == wanted)
    }

    // MARK: - Wire form

    /// Sorted-key, pretty-printed JSON — see the module docs for the caveat
    /// on matching Swift's exact byte format.
    pub fn encoded(&self) -> serde_json::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Wire<'a> {
            version: i32,
            #[serde(rename = "publishedAt")]
            published_at: &'a str,
            entries: &'a [Entry],
        }
        let wire = Wire {
            version: self.version,
            published_at: &self.published_at,
            entries: &self.entries,
        };
        // Same technique as core::credential::VerifiableCredential::canonical_bytes:
        // routing through Value sorts every object's keys (this crate
        // doesn't enable serde_json's preserve_order feature), regardless
        // of struct field declaration order.
        let value = serde_json::to_value(wire)?;
        serde_json::to_string_pretty(&value).map(String::into_bytes)
    }

    /// Decodes and validates in one step, so there is no window in which
    /// an unvalidated list exists and could be asked a question.
    ///
    /// **The published bytes must be exactly the bytes this type would
    /// emit.** The commitment is computed from the *parsed* fields, so
    /// anything in the JSON the parse doesn't model — duplicate keys,
    /// unknown keys — is invisible to it, and different parsers disagree
    /// about both. Closed by one rule: re-encode the parse and require it
    /// to equal the input, byte for byte.
    pub fn decoded(
        data: &[u8],
        expected_commitment: Option<&str>,
    ) -> Result<(TrustList, Provenance), TrustListError> {
        #[derive(Deserialize)]
        struct Wire {
            version: i32,
            #[serde(rename = "publishedAt")]
            published_at: String,
            entries: Vec<Entry>,
        }
        let wire: Wire =
            serde_json::from_slice(data).map_err(|_| TrustListError::NotCanonicalJson)?;
        let list = TrustList {
            version: wire.version,
            published_at: wire.published_at,
            entries: wire.entries,
        };
        let provenance = list.validate(expected_commitment)?;
        let reencoded = list
            .encoded()
            .map_err(|_| TrustListError::NotCanonicalJson)?;
        if reencoded != data {
            return Err(TrustListError::NotCanonicalJson);
        }
        Ok((list, provenance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_list(entries: Option<Vec<Entry>>, version: i32) -> TrustList {
        TrustList {
            version,
            published_at: "2026-08-09T00:00:00Z".to_string(),
            entries: entries.unwrap_or_else(|| {
                vec![
                    Entry {
                        id: "did:key:zPrimary".into(),
                        display_name: "內政部憑證管理中心".into(),
                        note: "MOICA-G3".into(),
                        is_mirror: false,
                    },
                    Entry {
                        id: "did:key:zMirror".into(),
                        display_name: "境外鏡像簽發者".into(),
                        note: "緊急期備援".into(),
                        is_mirror: true,
                    },
                ]
            }),
        }
    }

    #[test]
    fn commitment_is_independent_of_entry_order() {
        let forwards = sample_list(None, CURRENT_VERSION);
        let mut reversed_entries = forwards.entries.clone();
        reversed_entries.reverse();
        let backwards = TrustList {
            entries: reversed_entries,
            ..forwards.clone()
        };
        assert_eq!(forwards.commitment(), backwards.commitment());
    }

    #[test]
    fn renaming_an_issuer_changes_the_commitment() {
        let original = sample_list(None, CURRENT_VERSION);
        let mut renamed = original.clone();
        renamed.entries[1].display_name = "內政部憑證管理中心".to_string();
        assert_ne!(original.commitment(), renamed.commitment());
    }

    #[test]
    fn promoting_a_mirror_changes_the_commitment() {
        let original = sample_list(None, CURRENT_VERSION);
        let mut promoted = original.clone();
        for e in &mut promoted.entries {
            e.is_mirror = false;
        }
        assert_ne!(original.commitment(), promoted.commitment());
    }

    #[test]
    fn refuses_a_mismatched_commitment() {
        let list = sample_list(None, CURRENT_VERSION);
        assert_eq!(
            list.validate(Some("deadbeef")),
            Err(TrustListError::CommitmentMismatch {
                expected: "deadbeef".into(),
                actual: list.commitment()
            })
        );
        assert!(list.validate(Some(&list.commitment())).is_ok());
        assert!(list
            .validate(Some(&list.commitment().to_uppercase()))
            .is_ok());
    }

    #[test]
    fn refuses_duplicate_issuers() {
        let entries = vec![
            Entry {
                id: "did:key:zSame".into(),
                display_name: "甲".into(),
                note: "".into(),
                is_mirror: false,
            },
            Entry {
                id: "did:key:zSame".into(),
                display_name: "乙".into(),
                note: "".into(),
                is_mirror: true,
            },
        ];
        assert_eq!(
            sample_list(Some(entries), CURRENT_VERSION).validate(None),
            Err(TrustListError::DuplicateIssuer("did:key:zSame".into()))
        );
    }

    #[test]
    fn refuses_empty_and_unknown_versions() {
        assert_eq!(
            sample_list(Some(vec![]), CURRENT_VERSION).validate(None),
            Err(TrustListError::Empty)
        );
        assert_eq!(
            sample_list(None, 99).validate(None),
            Err(TrustListError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn round_trips_and_validates_on_decode() {
        let list = sample_list(None, CURRENT_VERSION);
        let bytes = list.encoded().unwrap();
        let (decoded, _) = TrustList::decoded(&bytes, Some(&list.commitment())).unwrap();
        assert_eq!(decoded, list);
        assert!(decoded.trusts("did:key:zMirror"));
        assert!(!decoded.trusts("did:key:zNobody"));
        assert!(decoded.entry("did:key:zMirror").unwrap().is_mirror);
    }

    #[test]
    fn decoding_refuses_a_mismatched_commitment() {
        let bytes = sample_list(None, CURRENT_VERSION).encoded().unwrap();
        assert!(TrustList::decoded(&bytes, Some("00")).is_err());
    }

    #[test]
    fn canonical_form_is_legible() {
        let text = sample_list(None, CURRENT_VERSION).canonical_form();
        assert!(text.starts_with("bonds.tw/trust-list/v1/2\n2026-08-09T00:00:00Z\n"));
        assert!(text.ends_with("end\n"));
        assert!(text.contains("did:key:zMirror\tmirror\t境外鏡像簽發者\t緊急期備援"));
    }

    // MARK: - Independent-implementation vector

    /// Produced by an independent (non-Rust, non-Swift-derived) Python
    /// implementation written from the prose description of the format,
    /// not from either codebase - see `TrustListVectorTests.swift` for the
    /// exact procedure. Deliberately awkward: two ids whose supplied order
    /// differs from their byte order, CJK in `displayName`, an empty
    /// `note`, one mirror and one primary.
    fn vector_list() -> TrustList {
        TrustList {
            version: 1,
            published_at: "2026-08-18".to_string(),
            entries: vec![
                Entry {
                    id: "did:key:zB".into(),
                    display_name: "內政部憑證管理中心".into(),
                    note: "".into(),
                    is_mirror: false,
                },
                Entry {
                    id: "did:key:zA".into(),
                    display_name: "鏡像".into(),
                    note: "備援".into(),
                    is_mirror: true,
                },
            ],
        }
    }

    const VECTOR_CANONICAL_FORM: &str = "bonds.tw/trust-list/v1/2\n\
        2026-08-18\n\
        did:key:zA\tmirror\t鏡像\t備援\n\
        did:key:zB\tprimary\t內政部憑證管理中心\t\n\
        end\n";

    const VECTOR_COMMITMENT: &str =
        "79b81ee31af4d43bbc8815ba8e900417fb2bf2ae8726ffc60a388eb8fc2bc802";

    #[test]
    fn a_second_implementation_produces_the_same_bytes() {
        assert_eq!(vector_list().canonical_form(), VECTOR_CANONICAL_FORM);
    }

    #[test]
    fn a_second_implementation_produces_the_same_commitment() {
        assert_eq!(vector_list().commitment(), VECTOR_COMMITMENT);
    }

    #[test]
    fn publication_order_does_not_move_the_digest() {
        let mut reversed = vector_list();
        reversed.entries.reverse();
        assert_eq!(reversed.commitment(), vector_list().commitment());
    }

    #[test]
    fn a_trailing_empty_field_is_part_of_the_digest() {
        assert!(vector_list()
            .canonical_form()
            .contains("內政部憑證管理中心\t\n"));
    }

    #[test]
    fn every_field_reaches_the_digest() {
        let baseline = vector_list().commitment();
        let original = vector_list().entries[0].clone();

        let mut with_renamed = vector_list();
        with_renamed.entries[0].display_name = format!("{}股份有限公司", original.display_name);
        assert_ne!(with_renamed.commitment(), baseline);

        let mut with_note = vector_list();
        with_note.entries[0].note = "x".to_string();
        assert_ne!(with_note.commitment(), baseline);

        let mut with_id = vector_list();
        with_id.entries[0].id = format!("{}x", original.id);
        assert_ne!(with_id.commitment(), baseline);

        let mut with_mirror = vector_list();
        with_mirror.entries[0].is_mirror = !original.is_mirror;
        assert_ne!(with_mirror.commitment(), baseline);
    }

    #[test]
    fn the_header_carries_the_entry_count() {
        assert!(vector_list()
            .canonical_form()
            .starts_with("bonds.tw/trust-list/v1/2\n"));
        let one = TrustList {
            entries: vec![vector_list().entries[0].clone()],
            ..vector_list()
        };
        assert!(one
            .canonical_form()
            .starts_with("bonds.tw/trust-list/v1/1\n"));
    }

    // MARK: - Collision / hostile-input regression

    /// **The collision that worked**, reproduced: without the delimiter
    /// check, a `note` carrying an embedded newline and tab-separated
    /// fields spells out a second, forged row. Both lists below produce
    /// the same canonical bytes if the check is removed; with it, list A
    /// (the one carrying the payload) is refused outright.
    #[test]
    fn a_field_carrying_a_delimiter_is_refused() {
        let forged_note = "MOICA G3\ndid:key:zZEvil\tmirror\tEvil Mirror\tforged\n";
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "did:key:zHonest".into(),
                display_name: "Honest".into(),
                note: forged_note.into(),
                is_mirror: false,
            }],
        };
        assert!(matches!(
            list.validate(None),
            Err(TrustListError::FieldContainsDelimiter { .. })
        ));
    }

    #[test]
    fn a_carriage_return_is_refused() {
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "did:key:zHonest".into(),
                display_name: "x\ry".into(),
                note: "".into(),
                is_mirror: false,
            }],
        };
        assert!(matches!(
            list.validate(None),
            Err(TrustListError::FieldContainsDelimiter { .. })
        ));
    }

    /// U+2028 LINE SEPARATOR is category Zl, not a control character, and
    /// every line-splitter on a typical machine (Foundation, Python,
    /// Rust's own `str::lines()` does *not* split on it, for what it's
    /// worth - but display code / CoreText does) treats it as one. Must
    /// still be refused.
    #[test]
    fn a_line_separator_cannot_enter_a_field() {
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "did:key:zHonest".into(),
                display_name: "MOICA G3\u{2028}did:key:zBackup".into(),
                note: "".into(),
                is_mirror: false,
            }],
        };
        assert!(matches!(
            list.validate(None),
            Err(TrustListError::FieldContainsDelimiter { .. })
        ));
    }

    #[test]
    fn bidirectional_overrides_are_refused() {
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "did:key:zHonest".into(),
                display_name: "\u{202E}reversed".into(),
                note: "".into(),
                is_mirror: false,
            }],
        };
        assert!(matches!(
            list.validate(None),
            Err(TrustListError::FieldContainsDelimiter { .. })
        ));
    }

    #[test]
    fn an_identifier_outside_printable_ascii_is_refused() {
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "did:key:ze\u{0301}".into(),
                display_name: "x".into(),
                note: "".into(),
                is_mirror: false,
            }],
        };
        assert!(matches!(
            list.validate(None),
            Err(TrustListError::IdentifierNotPrintableAscii(_))
        ));
    }

    #[test]
    fn an_enormous_field_is_refused() {
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "did:key:zHonest".into(),
                display_name: "x".repeat(600),
                note: "".into(),
                is_mirror: false,
            }],
        };
        assert!(matches!(
            list.validate(None),
            Err(TrustListError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn an_empty_identifier_is_refused() {
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "".into(),
                display_name: "x".into(),
                note: "".into(),
                is_mirror: false,
            }],
        };
        assert!(matches!(
            list.validate(None),
            Err(TrustListError::IdentifierNotPrintableAscii(_))
        ));
    }

    /// Compared by UTF-8 bytes, not Unicode canonical equivalence: `é`
    /// (precomposed) and `e` + combining acute (decomposed) are the same
    /// Swift `String` but different bytes, and only the restriction to
    /// printable ASCII (enforced in `validate`, not in `trusts` itself)
    /// keeps this from mattering in practice.
    #[test]
    fn membership_is_answered_on_bytes() {
        let list = TrustList {
            version: CURRENT_VERSION,
            published_at: "2026-08-13".into(),
            entries: vec![Entry {
                id: "did:key:z\u{00E9}".into(), // precomposed é
                display_name: "x".into(),
                note: "".into(),
                is_mirror: false,
            }],
        };
        assert!(!list.trusts("did:key:ze\u{0301}")); // decomposed e + combining acute
    }
}
