//! The 「申請新卡」 directory, reduced to the telecom 門號電子卡 a holder can
//! start.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/TelecomCardCatalog.swift`.
//! Scoped to the pure parse, [`telecom_cards_from_vc_list_json`] - fetching
//! `GET {frontendBase}/api/moda/dwapp/apply/vcList?name=&page=0&size=50`
//! is a network call and stays native.
//!
//! The three telecom 門號電子卡 are all `type == 1`: the issuer flow opens
//! in an external app/browser rather than an embedded webview, the holder
//! is sent to the carrier to verify the phone number on the line, and the
//! carrier's app hands the credential offer back over the
//! `modadigitalwallet://credential_offer` deep link.

use serde::Deserialize;

/// One entry of the official 「申請新卡」 catalogue, kept to what the apply
/// flow needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelecomCard {
    pub vc_uid: String,
    pub name: String,
    /// Where applying for this card begins - the carrier's own entry URL.
    /// Opened externally (`type == 1`); it is **not** trusted to issue
    /// anything. The offer the carrier eventually returns still passes
    /// both `issuer_authorization` gates before a credential is minted.
    pub issuer_service_url: String,
    /// `1` → the apply flow opens externally (every telecom card measured).
    pub card_type: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelecomCardCatalogError {
    /// A 2xx reply whose body was not the `{data:{vcItems:[…]}}` shape
    /// expected.
    #[error("malformed response")]
    MalformedResponse,
}

#[derive(Deserialize)]
struct Envelope {
    data: Option<Payload>,
}

#[derive(Deserialize)]
struct Payload {
    #[serde(rename = "vcItems")]
    vc_items: Option<Vec<RawItem>>,
}

#[derive(Deserialize)]
struct RawItem {
    #[serde(default, rename = "vcUid")]
    vc_uid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    card_type: Option<i64>,
    #[serde(default, rename = "issuerServiceUrl")]
    issuer_service_url: Option<String>,
}

/// The parse, split off from the fetch so it can be exercised with a
/// canned body and never a socket.
///
/// Deserializes into an all-optional raw mirror rather than refusing on
/// the first bad field: the directory is a list the app does not
/// control, and one entry missing a field must drop that entry, not fail
/// the whole fetch and hide the telecom cards behind an unrelated row.
pub fn telecom_cards_from_vc_list_json(
    data: &[u8],
) -> Result<Vec<TelecomCard>, TelecomCardCatalogError> {
    let envelope: Envelope =
        serde_json::from_slice(data).map_err(|_| TelecomCardCatalogError::MalformedResponse)?;
    let items = envelope
        .data
        .and_then(|payload| payload.vc_items)
        .ok_or(TelecomCardCatalogError::MalformedResponse)?;

    Ok(items
        .into_iter()
        .filter_map(|item| {
            // An entry with no service URL cannot start an application, so
            // it is dropped rather than shown as a dead row.
            let vc_uid = item.vc_uid.filter(|s| !s.is_empty())?;
            let name = item.name.filter(|s| !s.is_empty())?;
            let issuer_service_url = item.issuer_service_url.filter(|s| !s.is_empty())?;
            // Keep only the telephone-number cards. The three carriers all
            // name their card 「…門號電子卡」 (two also carry 「電信」), so
            // matching either 「電信」 or 「門號」 admits them and nothing
            // else in the catalogue.
            if !(name.contains("電信") || name.contains("門號")) {
                return None;
            }
            // `type` defaults to 1 (external open) when absent: every
            // telecom card measured is `type == 1`, and an external-open
            // assumption for a card that reached this filter is the safe
            // one - the alternative would silently drop a telecom card
            // over a missing scalar.
            Some(TelecomCard {
                vc_uid,
                name,
                issuer_service_url,
                card_type: item.card_type.unwrap_or(1),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_VC_LIST: &str = r#"
{
  "code": "0",
  "message": "success",
  "data": {
    "totalPages": 1,
    "vcItems": [
      {"vcUid": "97176270_twmdiwvc_postpaid", "name": "台灣大哥大門號電子卡", "type": 1, "logoUrl": "https://x/twm.png", "issuerServiceUrl": "https://twm5g.com/8fk2j"},
      {"vcUid": "97179430_fet_vc_prod", "name": "遠傳電信門號電子卡", "type": 1, "logoUrl": "https://x/fet.png", "issuerServiceUrl": "https://dspservice.fetnet.net/twdiwotp/entry"},
      {"vcUid": "96979933_name_phonel5_phonel3", "name": "中華電信門號電子卡", "type": 1, "logoUrl": "https://x/cht.png", "issuerServiceUrl": "https://123.cht.com.tw/DigitalIdentityWallet"},
      {"vcUid": "97000000_driver_licence", "name": "駕照驗證卡", "type": 1, "logoUrl": "https://x/dl.png", "issuerServiceUrl": "https://motc.example/login"},
      {"vcUid": "97111111_broken_phone", "name": "測試門號卡", "type": 1, "logoUrl": "https://x/n.png", "issuerServiceUrl": null}
    ]
  }
}
"#;

    #[test]
    fn keeps_only_the_three_telecom_cards() {
        let cards = telecom_cards_from_vc_list_json(SAMPLE_VC_LIST.as_bytes()).unwrap();
        assert_eq!(
            cards,
            vec![
                TelecomCard {
                    vc_uid: "97176270_twmdiwvc_postpaid".to_string(),
                    name: "台灣大哥大門號電子卡".to_string(),
                    issuer_service_url: "https://twm5g.com/8fk2j".to_string(),
                    card_type: 1,
                },
                TelecomCard {
                    vc_uid: "97179430_fet_vc_prod".to_string(),
                    name: "遠傳電信門號電子卡".to_string(),
                    issuer_service_url: "https://dspservice.fetnet.net/twdiwotp/entry".to_string(),
                    card_type: 1,
                },
                TelecomCard {
                    vc_uid: "96979933_name_phonel5_phonel3".to_string(),
                    name: "中華電信門號電子卡".to_string(),
                    issuer_service_url: "https://123.cht.com.tw/DigitalIdentityWallet".to_string(),
                    card_type: 1,
                },
            ]
        );
    }

    #[test]
    fn drops_a_non_telecom_card_even_with_a_service_url() {
        let cards = telecom_cards_from_vc_list_json(SAMPLE_VC_LIST.as_bytes()).unwrap();
        assert!(!cards.iter().any(|c| c.name.contains("駕照")));
        assert!(!cards.iter().any(|c| c.vc_uid == "97000000_driver_licence"));
    }

    #[test]
    fn drops_a_telecom_card_with_no_service_url() {
        let cards = telecom_cards_from_vc_list_json(SAMPLE_VC_LIST.as_bytes()).unwrap();
        assert!(!cards.iter().any(|c| c.vc_uid == "97111111_broken_phone"));
    }

    #[test]
    fn matches_on_either_keyword() {
        let body = r#"{"data": {"vcItems": [
          {"vcUid": "a", "name": "某某電信卡", "type": 1, "issuerServiceUrl": "https://a/x"},
          {"vcUid": "b", "name": "某某門號卡", "type": 1, "issuerServiceUrl": "https://b/x"},
          {"vcUid": "c", "name": "學生證", "type": 2, "issuerServiceUrl": "https://c/x"}
        ]}}"#;
        let cards = telecom_cards_from_vc_list_json(body.as_bytes()).unwrap();
        assert_eq!(
            cards.iter().map(|c| c.vc_uid.clone()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn defaults_missing_type_to_external_open() {
        let body = r#"{"data":{"vcItems":[{"vcUid":"a","name":"某電信門號卡","issuerServiceUrl":"https://a/x"}]}}"#;
        let cards = telecom_cards_from_vc_list_json(body.as_bytes()).unwrap();
        assert_eq!(cards.first().unwrap().card_type, 1);
    }

    #[test]
    fn rejects_a_malformed_body() {
        assert_eq!(
            telecom_cards_from_vc_list_json(b"not json"),
            Err(TelecomCardCatalogError::MalformedResponse)
        );
        assert_eq!(
            telecom_cards_from_vc_list_json(b"{}"),
            Err(TelecomCardCatalogError::MalformedResponse)
        );
    }

    #[test]
    fn a_catalogue_with_no_telecom_card_is_empty_not_an_error() {
        let body = r#"{"data":{"vcItems":[{"vcUid":"a","name":"學生證","type":2,"issuerServiceUrl":"https://a/x"}]}}"#;
        assert!(telecom_cards_from_vc_list_json(body.as_bytes())
            .unwrap()
            .is_empty());
    }
}
