//! What a verifier hands to a holder to start an offline presentation.
//!
//! Ported from `backupTW-iOS/backupTW/Presentation/PresentationRequest.swift`
//! — see that file for the full rationale, including why `audience` is
//! worth less than it looks (a relay Mallory can still run) and why
//! `purpose`/`audience` are scrubbed of control and bidi characters rather
//! than just control characters: `U+2028`/`U+2029` break a line exactly the
//! way `\n` does but are categories Zl/Zp, not Cc/Cf, so `is_unsafe` (the
//! same predicate `trust::UntrustedText` scrubs display text with) has to
//! catch both.
//!
//! **Everything in here is untrusted** except what this device wrote
//! itself: the verifier's device did not write this object, a stranger's
//! screen did, so `purpose`/`audience` are length-bounded and scrubbed
//! before they ever reach a caller.

use rand::RngCore;

use crate::trust::untrusted_text::is_unsafe;

/// The wire format this app writes and accepts.
pub const VERSION: i64 = 2;
/// Version 1 did not carry a credential source; it meant the only flow
/// that existed at the time, the self-issued document.
pub const LEGACY_VERSION: i64 = 1;

/// 16 bytes = 128 bits, base64url to 22 characters.
pub const CHALLENGE_BYTE_COUNT: usize = 16;
pub const MAXIMUM_CHALLENGE_LENGTH: usize = 64;
pub const MAXIMUM_PURPOSE_LENGTH: usize = 100;
pub const MAXIMUM_AUDIENCE_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresentationRequestError {
    /// The system CSPRNG refused. Deliberately reported rather than
    /// falling back to a weaker source - see [`PresentationRequest::generate`].
    #[error("randomness unavailable")]
    RandomnessUnavailable,
    #[error("malformed encoding")]
    MalformedEncoding,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(i64),
    #[error("malformed challenge")]
    MalformedChallenge,
    #[error("empty purpose")]
    EmptyPurpose,
    #[error("purpose too long")]
    PurposeTooLong,
    #[error("purpose contains control characters")]
    PurposeContainsControlCharacters,
    #[error("malformed audience")]
    MalformedAudience,
}

/// Which locally stored credential family the verifier is asking to
/// inspect, named by the verifier rather than guessed by the holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PresentationCredentialSource {
    #[default]
    SelfIssued,
    Twdiw,
}

impl PresentationCredentialSource {
    fn wire_code(self) -> &'static str {
        match self {
            Self::SelfIssued => "s",
            Self::Twdiw => "g",
        }
    }

    fn from_wire_code(code: &str) -> Option<Self> {
        match code {
            "s" => Some(Self::SelfIssued),
            "g" => Some(Self::Twdiw),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationRequest {
    /// The verifier's freshness value, base64url. Replay protection rests
    /// entirely on this being unpredictable and consumed exactly once.
    pub challenge: String,
    /// Human-readable, verifier-supplied, shown to the holder before they
    /// agree to present. Untrusted.
    pub purpose: String,
    /// A stable identifier for this verifier. `None` rather than `Some("")`
    /// when the verifier has none - see the type-level docs on why that
    /// distinction matters to `OfflineVerifier`.
    pub audience: Option<String>,
    /// The verifier's clock when the request was made, truncated to whole
    /// seconds (Unix epoch). Advisory only - never part of any freshness
    /// decision, which rests on the challenge instead.
    pub created_at: i64,
    /// A one-time BLE service identifier the holder should advertise
    /// under, as its canonical uppercase-hyphenated text, or `None` when
    /// this verifier is only offering the camera.
    pub link_service_id: Option<String>,
    pub credential_source: PresentationCredentialSource,
}

impl PresentationRequest {
    /// base64url's unreserved alphabet (RFC 4648 §5).
    fn challenge_is_valid_alphabet(challenge: &str) -> bool {
        challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// The only constructor, and it validates, so an invalid request
    /// cannot exist in memory.
    pub fn new(
        challenge: &str,
        purpose: &str,
        created_at: i64,
        audience: Option<&str>,
        link_service_id: Option<String>,
        credential_source: PresentationCredentialSource,
    ) -> Result<Self, PresentationRequestError> {
        if challenge.is_empty()
            || challenge.chars().count() > MAXIMUM_CHALLENGE_LENGTH
            || !Self::challenge_is_valid_alphabet(challenge)
        {
            return Err(PresentationRequestError::MalformedChallenge);
        }

        let trimmed_purpose = purpose.trim();
        if trimmed_purpose.is_empty() {
            return Err(PresentationRequestError::EmptyPurpose);
        }
        if trimmed_purpose.chars().count() > MAXIMUM_PURPOSE_LENGTH {
            return Err(PresentationRequestError::PurposeTooLong);
        }
        if trimmed_purpose.chars().any(is_unsafe) {
            return Err(PresentationRequestError::PurposeContainsControlCharacters);
        }

        let checked_audience = match audience.map(str::trim) {
            Some(trimmed) if !trimmed.is_empty() => {
                if trimmed.chars().count() > MAXIMUM_AUDIENCE_LENGTH
                    || trimmed.chars().any(is_unsafe)
                {
                    return Err(PresentationRequestError::MalformedAudience);
                }
                Some(trimmed.to_string())
            }
            _ => None,
        };

        Ok(Self {
            challenge: challenge.to_string(),
            purpose: trimmed_purpose.to_string(),
            audience: checked_audience,
            created_at,
            link_service_id,
            credential_source,
        })
    }

    /// Mints a request with a fresh challenge and a fresh one-time BLE
    /// service identifier - minted with the challenge and thrown away with
    /// it. Verifier side.
    pub fn generate(
        purpose: &str,
        audience: Option<&str>,
        credential_source: PresentationCredentialSource,
        now: i64,
    ) -> Result<Self, PresentationRequestError> {
        let mut bytes = [0u8; CHALLENGE_BYTE_COUNT];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| PresentationRequestError::RandomnessUnavailable)?;
        let challenge = base64_url_encode(&bytes);

        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id_bytes)
            .map_err(|_| PresentationRequestError::RandomnessUnavailable)?;
        let link_service_id = Some(uuid_v4_string(id_bytes));

        Self::new(
            &challenge,
            purpose,
            now,
            audience,
            link_service_id,
            credential_source,
        )
    }

    /// The exact text to put in the verifier's QR: compact, deterministic,
    /// printable JSON with sorted keys.
    pub fn encoded_for_transport(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("v".to_string(), serde_json::json!(VERSION));
        map.insert("c".to_string(), serde_json::json!(self.challenge));
        map.insert("p".to_string(), serde_json::json!(self.purpose));
        if let Some(audience) = &self.audience {
            map.insert("a".to_string(), serde_json::json!(audience));
        }
        if let Some(id) = &self.link_service_id {
            map.insert("b".to_string(), serde_json::json!(id));
        }
        map.insert(
            "k".to_string(),
            serde_json::json!(self.credential_source.wire_code()),
        );
        map.insert("t".to_string(), serde_json::json!(self.created_at));
        serde_json::Value::Object(map).to_string()
    }

    /// Reads what a scanner handed back, running it through the same
    /// validation a request built on-device would go through - a hostile
    /// request is precisely the one that arrives encoded.
    pub fn decode(text: &str) -> Result<Self, PresentationRequestError> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| PresentationRequestError::MalformedEncoding)?;
        let object = value
            .as_object()
            .ok_or(PresentationRequestError::MalformedEncoding)?;

        let version = object
            .get("v")
            .and_then(|v| v.as_i64())
            .ok_or(PresentationRequestError::MalformedEncoding)?;
        if version != VERSION && version != LEGACY_VERSION {
            return Err(PresentationRequestError::UnsupportedVersion(version));
        }

        let challenge = object
            .get("c")
            .and_then(|v| v.as_str())
            .ok_or(PresentationRequestError::MalformedEncoding)?;
        let purpose = object
            .get("p")
            .and_then(|v| v.as_str())
            .ok_or(PresentationRequestError::MalformedEncoding)?;
        let created_at = object
            .get("t")
            .and_then(|v| v.as_i64())
            .ok_or(PresentationRequestError::MalformedEncoding)?;
        let audience = match object.get("a") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(
                v.as_str()
                    .ok_or(PresentationRequestError::MalformedEncoding)?
                    .to_string(),
            ),
        };
        let link_service_id = match object.get("b") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => {
                let text = v
                    .as_str()
                    .ok_or(PresentationRequestError::MalformedEncoding)?;
                if !is_valid_uuid(text) {
                    return Err(PresentationRequestError::MalformedEncoding);
                }
                Some(text.to_string())
            }
        };
        // A v1 sender did not know government-card offline presentation.
        // Ignore an injected `k` and retain v1's only defined meaning.
        let credential_source = if version == LEGACY_VERSION {
            PresentationCredentialSource::SelfIssued
        } else {
            let code = object
                .get("k")
                .and_then(|v| v.as_str())
                .ok_or(PresentationRequestError::MalformedEncoding)?;
            PresentationCredentialSource::from_wire_code(code)
                .ok_or(PresentationRequestError::MalformedEncoding)?
        };

        Self::new(
            challenge,
            purpose,
            created_at,
            audience.as_deref(),
            link_service_id,
            credential_source,
        )
    }
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn uuid_v4_string(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn is_valid_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            b == b'-'
        } else {
            b.is_ascii_hexdigit()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const ISSUED_AT: i64 = 1_754_400_000;

    #[test]
    fn generated_challenge_carries_128_bits_of_base64_url() {
        let request = PresentationRequest::generate(
            "里長辦公室核對身分",
            None,
            Default::default(),
            ISSUED_AT,
        )
        .unwrap();
        assert_eq!(request.challenge.chars().count(), 22);
        assert!(PresentationRequest::challenge_is_valid_alphabet(
            &request.challenge
        ));
        assert!(!request.challenge.contains('='));
    }

    #[test]
    fn generated_challenges_do_not_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let request =
                PresentationRequest::generate("查驗", None, Default::default(), ISSUED_AT).unwrap();
            seen.insert(request.challenge);
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn rejects_challenges_that_are_not_base64_url() {
        for challenge in [
            "",
            " ",
            "abc def",
            "abc+def",
            "abc/def",
            "abc=",
            "abc\"def",
            "挑戰",
            &"a".repeat(67),
        ] {
            assert_eq!(
                PresentationRequest::new(
                    challenge,
                    "查驗",
                    ISSUED_AT,
                    None,
                    None,
                    Default::default()
                ),
                Err(PresentationRequestError::MalformedChallenge)
            );
        }
    }

    #[test]
    fn rejects_a_purpose_that_tells_the_holder_nothing() {
        for purpose in ["", "   ", "\n\t "] {
            assert_eq!(
                PresentationRequest::new(
                    "abcd",
                    purpose,
                    ISSUED_AT,
                    None,
                    None,
                    Default::default()
                ),
                Err(PresentationRequestError::EmptyPurpose)
            );
        }
    }

    #[test]
    fn rejects_a_purpose_longer_than_the_cap() {
        let too_long = "查".repeat(MAXIMUM_PURPOSE_LENGTH + 1);
        assert_eq!(
            PresentationRequest::new("abcd", &too_long, ISSUED_AT, None, None, Default::default()),
            Err(PresentationRequestError::PurposeTooLong)
        );
    }

    #[test]
    fn accepts_a_purpose_exactly_at_the_cap() {
        let at_cap = "查".repeat(MAXIMUM_PURPOSE_LENGTH);
        let request =
            PresentationRequest::new("abcd", &at_cap, ISSUED_AT, None, None, Default::default())
                .unwrap();
        assert_eq!(request.purpose.chars().count(), MAXIMUM_PURPOSE_LENGTH);
    }

    #[test]
    fn rejects_a_purpose_carrying_control_or_bidi_characters() {
        for purpose in [
            "核對\n身分",
            "核對\u{202E}身分",
            "核對\u{0000}身分",
            "核對\u{200B}身分",
            "核對\u{2066}身分",
            "核對\u{200F}身分",
            "核對\u{2028}身分",
            "核對\u{2029}身分",
        ] {
            assert_eq!(
                PresentationRequest::new(
                    "abcd",
                    purpose,
                    ISSUED_AT,
                    None,
                    None,
                    Default::default()
                ),
                Err(PresentationRequestError::PurposeContainsControlCharacters)
            );
        }
    }

    #[test]
    fn trims_surrounding_whitespace_from_the_purpose() {
        let request = PresentationRequest::new(
            "abcd",
            "  里長辦公室核對身分  ",
            ISSUED_AT,
            None,
            None,
            Default::default(),
        )
        .unwrap();
        assert_eq!(request.purpose, "里長辦公室核對身分");
    }

    #[test]
    fn treats_an_absent_or_blank_audience_as_no_audience() {
        for audience in [None, Some(""), Some("   "), Some("\n")] {
            let request = PresentationRequest::new(
                "abcd",
                "查驗",
                ISSUED_AT,
                audience,
                None,
                Default::default(),
            )
            .unwrap();
            assert_eq!(request.audience, None);
        }
    }

    #[test]
    fn trims_and_keeps_an_audience_that_was_given() {
        let request = PresentationRequest::new(
            "abcd",
            "查驗",
            ISSUED_AT,
            Some("  urn:bonds-tw:verifier:6f3a  "),
            None,
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            request.audience.as_deref(),
            Some("urn:bonds-tw:verifier:6f3a")
        );
    }

    #[test]
    fn rejects_an_audience_that_is_overlong_or_carries_control_characters() {
        let overlong = "u".repeat(MAXIMUM_AUDIENCE_LENGTH + 1);
        for audience in [
            "urn:\u{202E}bonds",
            "urn:bonds\u{0000}verifier",
            overlong.as_str(),
        ] {
            assert_eq!(
                PresentationRequest::new(
                    "abcd",
                    "查驗",
                    ISSUED_AT,
                    Some(audience),
                    None,
                    Default::default()
                ),
                Err(PresentationRequestError::MalformedAudience)
            );
        }
    }

    #[test]
    fn carries_the_audience_through_transport_and_omits_it_when_absent() {
        let named = PresentationRequest::new(
            "abcd",
            "查驗",
            ISSUED_AT,
            Some("urn:bonds-tw:verifier:6f3a"),
            None,
            Default::default(),
        )
        .unwrap();
        let named_text = named.encoded_for_transport();
        assert!(named_text.contains("\"a\":\"urn:bonds-tw:verifier:6f3a\""));
        assert_eq!(PresentationRequest::decode(&named_text).unwrap(), named);

        let anonymous =
            PresentationRequest::new("abcd", "查驗", ISSUED_AT, None, None, Default::default())
                .unwrap();
        let anonymous_text = anonymous.encoded_for_transport();
        assert!(!anonymous_text.contains("\"a\""));
        assert_eq!(
            PresentationRequest::decode(&anonymous_text).unwrap(),
            anonymous
        );
        assert_eq!(
            PresentationRequest::decode(
                "{\"a\":null,\"c\":\"abcd\",\"p\":\"查驗\",\"t\":1754400000,\"v\":1}"
            )
            .unwrap(),
            anonymous
        );
    }

    #[test]
    fn round_trips_through_its_transport_encoding() {
        let request = PresentationRequest::generate(
            "里長辦公室核對受災戶身分",
            None,
            Default::default(),
            ISSUED_AT,
        )
        .unwrap();
        let decoded = PresentationRequest::decode(&request.encoded_for_transport()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn transport_encoding_is_deterministic() {
        let request =
            PresentationRequest::generate("查驗", None, Default::default(), ISSUED_AT).unwrap();
        let first = request.encoded_for_transport();
        for _ in 0..32 {
            assert_eq!(request.encoded_for_transport(), first);
        }
    }

    #[test]
    fn transport_encoding_is_compact_and_printable() {
        let request = PresentationRequest::generate(
            "里長辦公室核對受災戶身分",
            None,
            Default::default(),
            ISSUED_AT,
        )
        .unwrap();
        let text = request.encoded_for_transport();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let object = json.as_object().unwrap();

        let mut keys: Vec<&str> = object.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(keys, vec!["b", "c", "k", "p", "t", "v"]);
        assert_eq!(object["v"].as_i64(), Some(VERSION));
        assert_eq!(
            object["k"].as_str(),
            Some(PresentationCredentialSource::SelfIssued.wire_code())
        );
        assert_eq!(object["t"].as_i64(), Some(ISSUED_AT));
        assert!(is_valid_uuid(object["b"].as_str().unwrap()));

        assert!(
            text.len() < 200,
            "request grew to {} bytes; QR version 10 @ M holds 213",
            text.len()
        );
    }

    #[test]
    fn rejects_requests_from_a_newer_protocol_version() {
        let text = "{\"c\":\"abcd\",\"p\":\"查驗\",\"t\":1754400000,\"v\":3}";
        assert_eq!(
            PresentationRequest::decode(text),
            Err(PresentationRequestError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn request_carries_government_credential_source_and_v1_means_self_issued() {
        let government = PresentationRequest::generate(
            "核對政府卡",
            None,
            PresentationCredentialSource::Twdiw,
            ISSUED_AT,
        )
        .unwrap();
        let encoded = government.encoded_for_transport();
        assert!(encoded.contains("\"k\":\"g\""));
        assert_eq!(
            PresentationRequest::decode(&encoded)
                .unwrap()
                .credential_source,
            PresentationCredentialSource::Twdiw
        );

        let legacy =
            PresentationRequest::decode("{\"c\":\"abcd\",\"p\":\"查驗\",\"t\":1754400000,\"v\":1}")
                .unwrap();
        assert_eq!(
            legacy.credential_source,
            PresentationCredentialSource::SelfIssued
        );
    }

    #[test]
    fn rejects_malformed_transport_text() {
        for text in [
            "",
            "not json",
            "{}",
            "[1,2,3]",
            "{\"v\":1,\"c\":\"abcd\"}",
            "{\"v\":1,\"c\":\"abcd\",\"p\":\"查驗\"}",
            "{\"v\":1,\"c\":\"abcd\",\"p\":\"查驗\",\"t\":\"2025-08-05\"}",
        ] {
            assert_eq!(
                PresentationRequest::decode(text),
                Err(PresentationRequestError::MalformedEncoding)
            );
        }
    }

    #[test]
    fn decoded_requests_go_through_the_same_validation() {
        assert_eq!(
            PresentationRequest::decode("{\"c\":\"\",\"p\":\"查驗\",\"t\":1754400000,\"v\":1}"),
            Err(PresentationRequestError::MalformedChallenge)
        );
        assert_eq!(
            PresentationRequest::decode(
                "{\"c\":\"abcd\",\"p\":\"核對\\u202e身分\",\"t\":1754400000,\"v\":1}"
            ),
            Err(PresentationRequestError::PurposeContainsControlCharacters)
        );
    }
}
