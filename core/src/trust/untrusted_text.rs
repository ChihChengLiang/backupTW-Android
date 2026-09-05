//! Text that arrived inside a stranger's document, prepared for a screen.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/UntrustedText.swift` —
//! see that file for the full rationale, including the real attack this
//! type exists to close (a `\u{202E}`-reversed name followed by two blank
//! lines and a forged "✅ officially issued" line, rendered in the app's
//! own card style). Only the core scrubbing type is ported here;
//! `ClaimLabel`/`PresentableClaims`/`VerifiedResultSection` are
//! presentation-layer (localization, screen layout) and stay native.
//!
//! Every Unicode scalar Foundation calls a control or format character —
//! **Cc and Cf** (U+0000-U+001F, U+007F-U+009F, the bidi embeddings/
//! overrides, the isolates, U+200E/U+200F, U+200B, U+FEFF) — **plus**
//! U+2028 and U+2029, which are categories Zl and Zp and are therefore
//! *not* Cc/Cf despite breaking a line exactly the way `\n` does.

use unicode_general_category::{get_general_category, GeneralCategory};

/// U+FFFD REPLACEMENT CHARACTER, which is what it is for.
pub const MARKER: char = '\u{FFFD}';

/// The longest field *value* the result screen will draw.
pub const MAXIMUM_VALUE_LENGTH: usize = 120;

/// The longest field *name*.
pub const MAXIMUM_TERM_LENGTH: usize = 40;

fn is_unsafe(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Control | GeneralCategory::Format
    ) || c == '\u{2028}'
        || c == '\u{2029}'
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedText {
    /// Safe to hand to a text view: no line breaks, no bidirectional
    /// overrides, no zero-width padding, and no longer than the limit it
    /// was built with.
    pub text: String,
    /// The source was longer than the limit and `text` is a prefix of it.
    pub was_truncated: bool,
    /// At least one scalar was replaced by [`MARKER`].
    pub contained_control_characters: bool,
}

impl UntrustedText {
    pub fn new(raw: &str, limit: usize) -> Self {
        let mut kept = String::new();
        let mut replaced = false;
        let mut inside_run = false;
        for c in raw.chars() {
            if is_unsafe(c) {
                replaced = true;
                if !inside_run {
                    kept.push(MARKER);
                    inside_run = true;
                }
            } else {
                inside_run = false;
                kept.push(c);
            }
        }

        // Trimmed *after* stripping, and only of plain whitespace: a
        // marker that ended up at either end is exactly the thing worth
        // seeing, so it must not be trimmed away.
        let sanitized = kept.trim_matches(|c: char| c.is_whitespace() && c != MARKER);

        // Counted in chars (Unicode scalars), not bytes: closer to what a
        // reader perceives than a byte count, though - like the Swift
        // `Character` count - still not exactly grapheme-cluster-accurate
        // for combining marks. The Swift source explicitly leaves
        // combining marks alone for the same reason (clipped by the card,
        // bounded by this same limit), so undercounting a decomposed
        // grapheme by a scalar or two is the same trade already made
        // there, not a new one.
        let char_count = sanitized.chars().count();
        let (text, was_truncated) = if char_count > limit {
            (
                format!("{}…", sanitized.chars().take(limit).collect::<String>()),
                true,
            )
        } else {
            (sanitized.to_string(), false)
        };

        UntrustedText {
            text,
            was_truncated,
            contained_control_characters: replaced,
        }
    }

    pub fn value(raw: &str) -> Self {
        Self::new(raw, MAXIMUM_VALUE_LENGTH)
    }

    pub fn term(raw: &str) -> Self {
        Self::new(raw, MAXIMUM_TERM_LENGTH)
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_and_format_characters() {
        let result = UntrustedText::value("王小明\u{202E}\n\n✅ forged line");
        assert!(result.contained_control_characters);
        assert!(!result.text.contains('\u{202E}'));
        assert!(!result.text.contains('\n'));
        assert!(result.text.contains(MARKER));
    }

    #[test]
    fn a_run_of_removed_scalars_becomes_one_marker() {
        let zero_width_run = "a".to_string() + &"\u{200B}".repeat(500) + "b";
        let result = UntrustedText::new(&zero_width_run, 1000);
        assert_eq!(result.text.matches(MARKER).count(), 1);
        assert_eq!(result.text, format!("a{MARKER}b"));
    }

    #[test]
    fn line_separator_and_paragraph_separator_are_stripped() {
        for c in ['\u{2028}', '\u{2029}'] {
            let result = UntrustedText::new(&format!("a{c}b"), 100);
            assert!(result.contained_control_characters, "{c:?}");
            assert_eq!(result.text, format!("a{MARKER}b"));
        }
    }

    #[test]
    fn ordinary_text_passes_through_unchanged() {
        let result = UntrustedText::value("內政部核發，統一編號 A123456789");
        assert!(!result.contained_control_characters);
        assert!(!result.was_truncated);
        assert_eq!(result.text, "內政部核發，統一編號 A123456789");
    }

    #[test]
    fn a_marker_at_the_edge_is_not_trimmed_away() {
        let result = UntrustedText::new("\u{202E}text", 100);
        assert!(result.text.starts_with(MARKER));
    }

    #[test]
    fn truncates_at_the_limit_and_says_so() {
        let long = "x".repeat(200);
        let result = UntrustedText::value(&long);
        assert!(result.was_truncated);
        assert_eq!(result.text.chars().count(), MAXIMUM_VALUE_LENGTH + 1); // +1 for the ellipsis
        assert!(result.text.ends_with('…'));
    }

    #[test]
    fn combining_marks_are_left_alone() {
        // U+0301 COMBINING ACUTE ACCENT: Mn, not Cc/Cf, not stripped.
        let result = UntrustedText::value("e\u{0301}");
        assert!(!result.contained_control_characters);
        assert_eq!(result.text, "e\u{0301}");
    }
}
