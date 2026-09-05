//! What a credential-offer QR code actually said — and nothing more.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/CredentialOffer.swift`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialOfferError {
    /// Not an `openid-credential-offer` link at all.
    #[error("not a credential offer")]
    NotACredentialOffer,
    /// The link carries both `credential_offer` and `credential_offer_uri`.
    /// OID4VCI says exactly one; a link that says two things is not argued
    /// with, because whichever one a wallet picked would be the attacker's
    /// choice presented as the wallet's.
    #[error("ambiguous offer form")]
    AmbiguousOfferForm,
    /// Neither form present.
    #[error("missing offer form")]
    MissingOfferForm,
    /// The offer document is not a JSON object.
    #[error("malformed offer JSON")]
    MalformedOfferJson,
    /// No `credential_issuer`.
    #[error("missing credential_issuer")]
    MissingCredentialIssuer,
    /// `credential_configuration_ids` missing, empty, or not strings.
    #[error("missing credential_configuration_ids")]
    MissingConfigurationIds,
    /// The offer carries no pre-authorized code grant. The demo flow this
    /// module exists for is pre-authorized only; an authorization-code
    /// offer is a different protocol leg this wallet has not implemented.
    #[error("no pre-authorized grant")]
    NoPreAuthorizedGrant,
}

/// The two ways an offer link can carry its offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOfferLink {
    /// `credential_offer_uri=…` — a URL to fetch the offer from.
    ByReference { fetch_url: String },
    /// `credential_offer=…` — the offer document inline, percent-decoded.
    ByValue { json: String },
}

/// The schemes a credential-offer link can arrive under.
///
/// - `openid-credential-offer` is the OID4VCI standard.
/// - `modadigitalwallet` is 台灣數位憑證皮夾 官方 App 的自訂 scheme — the telecom
///   門號電子卡 flow finishes inside the carrier's own app, which hands the
///   offer back only under this scheme.
const OFFER_SCHEMES: [&str; 2] = ["openid-credential-offer", "modadigitalwallet"];

impl CredentialOfferLink {
    /// Reads a link from a **scanned string**, tolerating the framing a QR
    /// carries.
    ///
    /// The official deep link embeds a CR+LF right after
    /// `credential_offer?` — a raw newline inside the query would make the
    /// parameter name read as `\r\ncredential_offer_uri`, so the lookup
    /// finds nothing and the whole thing is rejected. A scanner's input is
    /// bytes off a camera, not a URL the OS built, so newlines are
    /// stripped and surrounding whitespace trimmed before a URL is formed.
    pub fn parse_scanned(scanned: &str) -> Result<Self, CredentialOfferError> {
        let cleaned = scanned.replace(['\r', '\n'], "");
        let cleaned = cleaned.trim();

        // Unwrap the TWDIW relay page: the demo cards' QR carries a link to
        // `frontend*.wallet.gov.tw/api/moda/vcqrcode?…&deeplink=<base64url
        // of the deep link>`, not the deep link itself. Its `deeplink`
        // parameter is the real thing; decode it and parse that. Nothing
        // is trusted that the gates do not re-check.
        if let Some(deeplink) = relay_deeplink(cleaned) {
            return Self::parse_scanned(&deeplink);
        }
        Self::parse_url(cleaned)
    }

    /// Reads a link, or says exactly why not.
    ///
    /// This function does not fetch, does not validate hosts, does not
    /// parse the offer — it answers one question: which of the two forms
    /// is this, and what is its payload.
    pub fn parse_url(url: &str) -> Result<Self, CredentialOfferError> {
        let parsed = Url::parse(url).map_err(|_| CredentialOfferError::NotACredentialOffer)?;
        let scheme = parsed.scheme().to_lowercase();
        if !OFFER_SCHEMES.contains(&scheme.as_str()) {
            return Err(CredentialOfferError::NotACredentialOffer);
        }
        // `modadigitalwallet://credential_offer?…` puts `credential_offer`
        // in the host position. A standard `openid-credential-offer://?…`
        // has an empty host and the same query. Either way the parameters
        // are read the same; the host word, when present, must be
        // `credential_offer` and nothing else.
        if let Some(host) = parsed.host_str() {
            if !host.is_empty() && host != "credential_offer" {
                return Err(CredentialOfferError::NotACredentialOffer);
            }
        }

        let mut by_reference: Option<String> = None;
        let mut by_value: Option<String> = None;
        for (name, value) in parsed.query_pairs() {
            if name == "credential_offer_uri" {
                by_reference = Some(value.into_owned());
            } else if name == "credential_offer" {
                by_value = Some(value.into_owned());
            }
        }

        match (by_reference, by_value) {
            (Some(_), Some(_)) => Err(CredentialOfferError::AmbiguousOfferForm),
            (Some(uri), None) => Ok(CredentialOfferLink::ByReference { fetch_url: uri }),
            (None, Some(json)) => Ok(CredentialOfferLink::ByValue { json }),
            (None, None) => Err(CredentialOfferError::MissingOfferForm),
        }
    }
}

/// The real deep link a TWDIW `vcqrcode` relay URL wraps, or `None` if this
/// is not that page.
///
/// The inner deep link uses a custom scheme, so it does not satisfy the
/// `http(s)` guard on a second pass — the single unwrap in
/// [`CredentialOfferLink::parse_scanned`] cannot loop.
fn relay_deeplink(s: &str) -> Option<String> {
    let url = Url::parse(s).ok()?;
    let scheme = url.scheme().to_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let host = url.host_str()?.to_lowercase();
    if !host.ends_with(".wallet.gov.tw") {
        return None;
    }
    if !url.path().contains("vcqrcode") {
        return None;
    }
    let encoded = url
        .query_pairs()
        .find(|(name, _)| name.trim() == "deeplink")
        .map(|(_, value)| value.into_owned())?;
    let bytes = base64url_decode(&encoded)?;
    String::from_utf8(bytes).ok()
}

/// base64url (RFC 4648 §5) decoding: `-_` for `+/`, and padding that the
/// URL form usually omits, restored before the standard decoder is asked.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// One parsed credential offer, reduced to what collection needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialOffer {
    /// The issuer identifier the offer names. **Untrusted** until
    /// `issuer_authorization::confirm` has agreed it belongs to the
    /// organisation the offer was fetched from.
    pub credential_issuer: String,
    /// Which credentials are on offer. The demo flow offers one; the type
    /// is a list because the field is, and picking the first is the
    /// caller's decision to make where the user can see it.
    pub configuration_ids: Vec<String>,
    pub pre_authorized_code: String,
    /// Whether the token request must carry a transaction code the user is
    /// told out of band. Carried as a fact; prompting for it is UI's job.
    pub requires_transaction_code: bool,
}

const PRE_AUTHORIZED_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

impl CredentialOffer {
    /// Parses the offer document.
    ///
    /// Reads field-by-field from a generic JSON value rather than via a
    /// strongly-typed deserializer: the shapes here are measured off a
    /// live deployment, not taken from a spec, and a decoder that silently
    /// drops a mis-typed field is exactly the wrong tool for a document an
    /// attacker may have written.
    pub fn parse(json: &[u8]) -> Result<Self, CredentialOfferError> {
        let root: serde_json::Value =
            serde_json::from_slice(json).map_err(|_| CredentialOfferError::MalformedOfferJson)?;
        let root = root
            .as_object()
            .ok_or(CredentialOfferError::MalformedOfferJson)?;

        let issuer = root
            .get("credential_issuer")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(CredentialOfferError::MissingCredentialIssuer)?;

        let ids: Vec<String> = root
            .get("credential_configuration_ids")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .filter(|ids: &Vec<String>| !ids.is_empty())
            .ok_or(CredentialOfferError::MissingConfigurationIds)?;

        let grant = root
            .get("grants")
            .and_then(|v| v.as_object())
            .and_then(|grants| grants.get(PRE_AUTHORIZED_GRANT))
            .and_then(|v| v.as_object())
            .ok_or(CredentialOfferError::NoPreAuthorizedGrant)?;
        let code = grant
            .get("pre-authorized_code")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(CredentialOfferError::NoPreAuthorizedGrant)?;

        Ok(CredentialOffer {
            credential_issuer: issuer.to_owned(),
            configuration_ids: ids,
            pre_authorized_code: code.to_owned(),
            requires_transaction_code: grant.contains_key("tx_code"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(query: &str) -> String {
        format!("openid-credential-offer://?{query}")
    }

    #[test]
    fn a_by_reference_link_carries_its_fetch_url() {
        let parsed = CredentialOfferLink::parse_url(&link(
            "credential_offer_uri=https%3A%2F%2Fissuer-sandbox.wallet.gov.tw%2Foffer",
        ))
        .unwrap();
        assert_eq!(
            parsed,
            CredentialOfferLink::ByReference {
                fetch_url: "https://issuer-sandbox.wallet.gov.tw/offer".into()
            }
        );
    }

    #[test]
    fn a_by_value_link_carries_its_document() {
        let parsed =
            CredentialOfferLink::parse_url(&link("credential_offer=%7B%22a%22%3A1%7D")).unwrap();
        assert_eq!(
            parsed,
            CredentialOfferLink::ByValue {
                json: r#"{"a":1}"#.into()
            }
        );
    }

    #[test]
    fn a_link_saying_both_is_not_argued_with() {
        let result = CredentialOfferLink::parse_url(&link(
            "credential_offer=%7B%7D&credential_offer_uri=https%3A%2F%2Fa",
        ));
        assert_eq!(result, Err(CredentialOfferError::AmbiguousOfferForm));
    }

    #[test]
    fn a_link_saying_neither_is_named() {
        let result = CredentialOfferLink::parse_url(&link("unrelated=1"));
        assert_eq!(result, Err(CredentialOfferError::MissingOfferForm));
    }

    #[test]
    fn another_scheme_is_not_a_credential_offer() {
        let result = CredentialOfferLink::parse_url("https://bonds.tw/?credential_offer_uri=x");
        assert_eq!(result, Err(CredentialOfferError::NotACredentialOffer));
    }

    #[test]
    fn the_official_app_scheme_is_understood() {
        let parsed = CredentialOfferLink::parse_url(
            "modadigitalwallet://credential_offer?credential_offer_uri=https%3A%2F%2Fissuer-oid4vci.wallet.gov.tw%2Fapi%2Fissuer%2F00000000%2Foffer",
        )
        .unwrap();
        assert_eq!(
            parsed,
            CredentialOfferLink::ByReference {
                fetch_url: "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/offer".into()
            }
        );
    }

    #[test]
    fn the_inbound_official_deep_link_with_crlf_framing_still_reads() {
        let framed = "modadigitalwallet://credential_offer?\r\ncredential_offer_uri=https%3A%2F%2Fissuer-oid4vci.wallet.gov.tw%2Fapi%2Fissuer%2F00000000%2Foffer";
        let parsed = CredentialOfferLink::parse_scanned(framed).unwrap();
        assert_eq!(
            parsed,
            CredentialOfferLink::ByReference {
                fetch_url: "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/offer".into()
            }
        );
    }

    #[test]
    fn the_official_scheme_with_a_wrong_host_is_refused() {
        let result = CredentialOfferLink::parse_url(
            "modadigitalwallet://something_else?credential_offer_uri=x",
        );
        assert_eq!(result, Err(CredentialOfferError::NotACredentialOffer));
    }

    fn offer_json(issuer: &str, ids: &str, grants: &str) -> Vec<u8> {
        format!(r#"{{"credential_issuer":"{issuer}","credential_configuration_ids":{ids},"grants":{grants}}}"#)
            .into_bytes()
    }

    const DEFAULT_ISSUER: &str = "https://issuer-sandbox.wallet.gov.tw/api/issuer/00000000";
    const DEFAULT_IDS: &str = r#"["00000000_demo_drivinglicense_202504251418"]"#;
    const DEFAULT_GRANTS: &str = r#"{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"CODE-1"}}"#;

    #[test]
    fn a_well_formed_offer_is_read() {
        let offer =
            CredentialOffer::parse(&offer_json(DEFAULT_ISSUER, DEFAULT_IDS, DEFAULT_GRANTS))
                .unwrap();
        assert_eq!(offer.credential_issuer, DEFAULT_ISSUER);
        assert_eq!(
            offer.configuration_ids,
            vec!["00000000_demo_drivinglicense_202504251418"]
        );
        assert_eq!(offer.pre_authorized_code, "CODE-1");
        assert!(!offer.requires_transaction_code);
    }

    #[test]
    fn a_transaction_code_requirement_is_carried_as_a_fact() {
        let grants = r#"{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"CODE-1","tx_code":{"length":6}}}"#;
        let offer =
            CredentialOffer::parse(&offer_json(DEFAULT_ISSUER, DEFAULT_IDS, grants)).unwrap();
        assert!(offer.requires_transaction_code);
    }

    #[test]
    fn an_offer_without_a_pre_authorized_grant_is_named_not_generically_rejected() {
        let result = CredentialOffer::parse(&offer_json(
            DEFAULT_ISSUER,
            DEFAULT_IDS,
            r#"{"authorization_code":{}}"#,
        ));
        assert_eq!(result, Err(CredentialOfferError::NoPreAuthorizedGrant));
    }

    #[test]
    fn an_offer_without_an_issuer_is_refused() {
        let result = CredentialOffer::parse(br#"{"credential_configuration_ids":["x"]}"#);
        assert_eq!(result, Err(CredentialOfferError::MissingCredentialIssuer));
    }

    #[test]
    fn an_offer_offering_nothing_is_refused() {
        let result = CredentialOffer::parse(&offer_json(DEFAULT_ISSUER, "[]", DEFAULT_GRANTS));
        assert_eq!(result, Err(CredentialOfferError::MissingConfigurationIds));
    }
}
