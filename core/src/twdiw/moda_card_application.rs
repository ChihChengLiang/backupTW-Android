//! Recognising a 皮夾夥伴卡 「申請卡片」 QR, reduced to the two things needed to
//! resolve it.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/ModaServiceURLResolver.swift`.
//! Scoped to the pure recognition step, [`ModaCardApplication::parse`].
//!
//! # What this QR is, and is not
//!
//! Measured off the official app on 2026-08-27: some 皮夾夥伴卡 cannot hand
//! a holder a credential offer straight away — the issuer has to see them
//! complete a flow first (電信卡 verifies the phone number on the line,
//! 駕照驗證卡 makes them log in to 監理服務網). Their printed QR therefore
//! does **not** carry a `modadigitalwallet://credential_offer` deep link.
//! It carries a plain `https` URL —
//! `https://frontend.wallet.gov.tw/api/moda/qrcode?mode=vc&vcUid=<UID>` —
//! that only *identifies which card* is being applied for. The deep link
//! comes later, out of the issuer's own web page, once the holder has
//! done what the issuer needs.
//!
//! So this is not an offer and must never be parsed as one. `parse`
//! recognises exactly this shape and nothing else; anything that is not
//! this shape returns `None`, so a real `openid-credential-offer` /
//! `modadigitalwallet` link falls straight through to the offer parser
//! and collects the way it always did. `parse` runs *before* that parser
//! in the scan loop, so widening this match is how an ordinary offer
//! would get swallowed here and never reach the issuer gates.
//!
//! Resolving the parsed `vc_uid` to the issuer's own page
//! (`GET {frontendBase}/api/moda/dwapp/serviceUrl/{vcUid}?mode={mode}`)
//! is a network call and stays native.

use crate::twdiw::issuer_authorization::normalised_host;

/// The 201i (`DW-MODA-201i`) response: what the frontend says about the
/// card being applied for, once [`ModaCardApplication`]'s `vc_uid`/`mode`
/// have been resolved (`GET
/// {frontendBase}/api/moda/dwapp/serviceUrl/{vcUid}?mode={mode}`, a
/// network call that stays native).
///
/// Every field is optional because the official client treats them as
/// optional (`CustomTabBarViewModel.getStaticVerifiableCredential` guards
/// all three and bails if any is missing). `card_type` is the Swift
/// struct's `type` (a Rust keyword) — `1` means the issuer flow opens in
/// the system browser; anything else means an embedded webview.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DwModa201iResponse {
    pub card_type: Option<i64>,
    pub name: Option<String>,
    /// The issuer's own page the holder finishes the application on —
    /// **not** trusted to issue anything. Whatever deep link it eventually
    /// hands back still goes through `CredentialOfferLink::parse` and both
    /// issuer gates before a credential is minted.
    pub issuer_service_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum DwModa201iResponseError {
    /// A 2xx reply whose body was not the JSON shape expected.
    #[error("malformed response")]
    MalformedResponse,
}

#[derive(serde::Deserialize)]
struct RawDwModa201iResponse {
    #[serde(default, rename = "type")]
    card_type: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "issuerServiceUrl")]
    issuer_service_url: Option<String>,
}

/// Parses the 201i response body. This document comes from the moda
/// frontend the app already trusts for the trust list itself, not from an
/// attacker-writable offer — so, matching the iOS source, a malformed
/// field is carried through as `None` rather than dropping the whole
/// response; only a body that isn't the expected JSON shape at all is an
/// error.
pub fn parse_dw_modal_201i_response(
    json: &[u8],
) -> Result<DwModa201iResponse, DwModa201iResponseError> {
    let raw: RawDwModa201iResponse =
        serde_json::from_slice(json).map_err(|_| DwModa201iResponseError::MalformedResponse)?;
    Ok(DwModa201iResponse {
        card_type: raw.card_type,
        name: raw.name,
        issuer_service_url: raw.issuer_service_url,
    })
}

/// The vcUid and mode carried by a static card-application QR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModaCardApplication {
    pub vc_uid: String,
    pub mode: String,
}

impl ModaCardApplication {
    /// Recognises the static card-application QR shape, or returns `None`
    /// for anything else - including a real credential offer, which must
    /// fall through to that parser untouched.
    ///
    /// CR/LF are stripped first for the same reason `CredentialOfferLink`
    /// does it: a scanner's input is bytes off a camera, and the official
    /// QR framing has been seen to wrap raw newlines into the query.
    pub fn parse(scanned: &str) -> Option<Self> {
        let cleaned: String = scanned
            .chars()
            .filter(|&c| c != '\r' && c != '\n')
            .collect();
        let cleaned = cleaned.trim();

        // `https` only, host suffix on `.wallet.gov.tw` (the leading dot
        // so `notwallet.gov.tw` cannot match), no userinfo/odd port/
        // non-ASCII host - the same normalisation the trust-list host
        // comparison uses, since a QR is just as untrusted a source here.
        let host = normalised_host(cleaned).ok()?;
        if !host.ends_with(".wallet.gov.tw") {
            return None;
        }

        let url = url::Url::parse(cleaned).ok()?;
        // Exact, so the `/api/moda/vcqrcode` relay page (a different
        // official shape the offer parser already unwraps) does not also
        // match here.
        if url.path() != "/api/moda/qrcode" {
            return None;
        }

        let mut mode: Option<String> = None;
        let mut vc_uid: Option<String> = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "mode" if mode.is_none() => mode = Some(value.into_owned()),
                "vcUid" if vc_uid.is_none() => vc_uid = Some(value.into_owned()),
                _ => {}
            }
        }
        // Required present and non-empty rather than defaulted, so a
        // malformed QR is a miss (falls through to the offer parser)
        // rather than a guess.
        let mode = mode.filter(|m| !m.is_empty())?;
        let vc_uid = vc_uid.filter(|v| !v.is_empty())?;

        Some(Self { vc_uid, mode })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_201i_response_with_every_field() {
        let body = r#"{"type":1,"name":"台灣大哥大門號電子卡","issuerServiceUrl":"https://twm5g.com/8fk2j"}"#;
        let parsed = parse_dw_modal_201i_response(body.as_bytes()).unwrap();
        assert_eq!(
            parsed,
            DwModa201iResponse {
                card_type: Some(1),
                name: Some("台灣大哥大門號電子卡".to_string()),
                issuer_service_url: Some("https://twm5g.com/8fk2j".to_string()),
            }
        );
    }

    #[test]
    fn a_missing_field_becomes_none_not_an_error() {
        let parsed = parse_dw_modal_201i_response(b"{}").unwrap();
        assert_eq!(
            parsed,
            DwModa201iResponse {
                card_type: None,
                name: None,
                issuer_service_url: None,
            }
        );
    }

    #[test]
    fn rejects_a_non_json_body() {
        assert_eq!(
            parse_dw_modal_201i_response(b"not json"),
            Err(DwModa201iResponseError::MalformedResponse)
        );
    }

    #[test]
    fn recognises_the_static_card_application_qr() {
        let scanned = "https://frontend.wallet.gov.tw/api/moda/qrcode?mode=vc&vcUid=ABC";
        let parsed = ModaCardApplication::parse(scanned).unwrap();
        assert_eq!(parsed.vc_uid, "ABC");
        assert_eq!(parsed.mode, "vc");
    }

    #[test]
    fn strips_carriage_return_and_newline_framing() {
        let scanned = "https://frontend.wallet.gov.tw/api/moda/qrcode?\r\nmode=vc&vcUid=ABC\n";
        let parsed = ModaCardApplication::parse(scanned).unwrap();
        assert_eq!(parsed.vc_uid, "ABC");
        assert_eq!(parsed.mode, "vc");
    }

    #[test]
    fn admits_sibling_hosts_under_the_same_domain() {
        let scanned = "https://frontend-uat.wallet.gov.tw/api/moda/qrcode?mode=vc&vcUid=XYZ";
        assert_eq!(ModaCardApplication::parse(scanned).unwrap().vc_uid, "XYZ");
    }

    #[test]
    fn does_not_swallow_a_real_credential_offer() {
        let offer = "modadigitalwallet://credential_offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer";
        assert_eq!(ModaCardApplication::parse(offer), None);
    }

    #[test]
    fn does_not_swallow_a_standard_openid_offer() {
        let offer =
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer";
        assert_eq!(ModaCardApplication::parse(offer), None);
    }

    #[test]
    fn rejects_a_random_url() {
        assert_eq!(
            ModaCardApplication::parse("https://example.com/foo?mode=vc&vcUid=ABC"),
            None
        );
    }

    #[test]
    fn rejects_plaintext_http() {
        let scanned = "http://frontend.wallet.gov.tw/api/moda/qrcode?mode=vc&vcUid=ABC";
        assert_eq!(ModaCardApplication::parse(scanned), None);
    }

    #[test]
    fn rejects_a_look_alike_domain() {
        let scanned = "https://frontend.notwallet.gov.tw/api/moda/qrcode?mode=vc&vcUid=ABC";
        assert_eq!(ModaCardApplication::parse(scanned), None);
    }

    #[test]
    fn rejects_the_relay_endpoint() {
        let scanned = "https://frontend.wallet.gov.tw/api/moda/vcqrcode?mode=vc&vcUid=ABC";
        assert_eq!(ModaCardApplication::parse(scanned), None);
    }

    #[test]
    fn rejects_missing_or_empty_values() {
        assert_eq!(
            ModaCardApplication::parse("https://frontend.wallet.gov.tw/api/moda/qrcode?mode=vc"),
            None
        );
        assert_eq!(
            ModaCardApplication::parse(
                "https://frontend.wallet.gov.tw/api/moda/qrcode?mode=vc&vcUid="
            ),
            None
        );
        assert_eq!(
            ModaCardApplication::parse("https://frontend.wallet.gov.tw/api/moda/qrcode?vcUid=ABC"),
            None
        );
    }

    #[test]
    fn rejects_non_url_garbage() {
        assert_eq!(ModaCardApplication::parse("not a url at all"), None);
    }
}
