//! The official offline-verifier flow's response shapes: the catalogue of
//! pickup scenarios, the transaction/deep-link start reply, and the
//! encrypted barcode image.
//!
//! Ported from
//! `backupTW-iOS/backupTW/TWDIW/ConvenienceStorePickup.swift`. Scoped to
//! the pure parsing - [`scenarios`], [`parse_start`], [`parse_barcode`],
//! [`credential_serial`] - and [`Countdown`], which turns a verifier's
//! stated lifetime into an absolute, testable deadline so time spent
//! backgrounded cannot make an expired store token look current.
//!
//! **Not yet ported**: the four-call orchestration itself
//! (`ConvenienceStorePickupClient.begin`/`presentAndGenerate`/
//! `regenerate`) - catalogue fetch, trust-list host matching, on-chain
//! verification, the OID4VP exchange, and posting for the barcode are all
//! network/trust-list calls and stay native. The barcode's own bytes are
//! never regenerated locally either way: a store scanner trusts only the
//! image the verifier itself produced.

use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvenienceStorePickupScenario {
    pub vp_uid: String,
    pub name: String,
    pub verifier_module_url: String,
    pub logo_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvenienceStorePickupError {
    /// A 2xx reply whose body was not the shape expected.
    #[error("malformed response")]
    MalformedResponse,
    /// The server answered with a non-"0" application code.
    #[error("server code: {0}")]
    ServerCode(String),
    /// The barcode reply's `qrcode`/`totptimeout` did not decode to a real
    /// PNG with a positive lifetime.
    #[error("invalid barcode image")]
    InvalidBarcodeImage,
}

pub const SEVEN_ELEVEN_VP_UID: &str = "22555003_711pickup";
pub const TELECOM_CREDENTIAL_TYPES: [&str; 3] = [
    "96979933_name_phonel5_phonel3",
    "97179430_fet_vc_prod",
    "97176270_twmdiwvc_postpaid",
];

#[derive(Deserialize)]
struct CatalogueEnvelope {
    code: Option<String>,
    data: Option<CataloguePayload>,
}

#[derive(Deserialize)]
struct CataloguePayload {
    #[serde(rename = "vpItems")]
    vp_items: Option<Vec<CatalogueItem>>,
}

#[derive(Deserialize)]
struct CatalogueItem {
    #[serde(default, rename = "vpUid")]
    vp_uid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "verifierModuleUrl")]
    verifier_module_url: Option<String>,
    #[serde(default, rename = "logoUrl")]
    logo_url: Option<String>,
}

/// Reads the `offline/vpList` catalogue, dropping any entry with no
/// endpoint to start a pickup at.
pub fn scenarios(
    data: &[u8],
) -> Result<Vec<ConvenienceStorePickupScenario>, ConvenienceStorePickupError> {
    let envelope: CatalogueEnvelope =
        serde_json::from_slice(data).map_err(|_| ConvenienceStorePickupError::MalformedResponse)?;
    if !(envelope.code.is_none() || envelope.code.as_deref() == Some("0")) {
        return Err(ConvenienceStorePickupError::MalformedResponse);
    }
    let items = envelope
        .data
        .and_then(|payload| payload.vp_items)
        .ok_or(ConvenienceStorePickupError::MalformedResponse)?;

    Ok(items
        .into_iter()
        .filter_map(|item| {
            let vp_uid = item.vp_uid.filter(|s| !s.is_empty())?;
            let name = item.name.filter(|s| !s.is_empty())?;
            let verifier_module_url = item.verifier_module_url.filter(|s| !s.is_empty())?;
            Some(ConvenienceStorePickupScenario {
                vp_uid,
                name,
                verifier_module_url,
                logo_url: item.logo_url,
            })
        })
        .collect())
}

/// Reads the `code` field, tolerating either a JSON string or number the
/// way `NSNumber.stringValue` does.
fn check_server_code(
    envelope: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ConvenienceStorePickupError> {
    let code = match envelope.get("code") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => return Err(ConvenienceStorePickupError::MalformedResponse),
    };
    if code != "0" {
        return Err(ConvenienceStorePickupError::ServerCode(code));
    }
    Ok(())
}

/// Reads the 401 start reply: a transaction id and the verifier's own
/// `modadigitalwallet://authorize` deep link.
pub fn parse_start(data: &[u8]) -> Result<(String, String), ConvenienceStorePickupError> {
    let envelope: serde_json::Value =
        serde_json::from_slice(data).map_err(|_| ConvenienceStorePickupError::MalformedResponse)?;
    let object = envelope
        .as_object()
        .ok_or(ConvenienceStorePickupError::MalformedResponse)?;
    check_server_code(object)?;

    let body = object
        .get("data")
        .and_then(|v| v.as_object())
        .ok_or(ConvenienceStorePickupError::MalformedResponse)?;
    let transaction_id = body
        .get("transactionId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or(ConvenienceStorePickupError::MalformedResponse)?;
    let deep_link = body
        .get("deepLink")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or(ConvenienceStorePickupError::MalformedResponse)?;
    Ok((transaction_id.to_string(), deep_link.to_string()))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConvenienceStorePickupBarcode {
    /// The verifier's own PNG bytes, kept exactly - never re-encoded.
    pub image_data: Vec<u8>,
    pub lifetime_seconds: f64,
    pub generated_at: DateTime<Utc>,
}

const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Reads the 402 reply: a `data:image/png;base64,…` QR image and its
/// lifetime in seconds. Every sub-failure past a valid server code -
/// missing fields, a non-PNG image, an oversized image, a non-positive
/// lifetime - is reported the same way, matching the single guard Swift
/// reads them all through.
pub fn parse_barcode(
    data: &[u8],
    now: DateTime<Utc>,
) -> Result<ConvenienceStorePickupBarcode, ConvenienceStorePickupError> {
    let envelope: serde_json::Value =
        serde_json::from_slice(data).map_err(|_| ConvenienceStorePickupError::MalformedResponse)?;
    let object = envelope
        .as_object()
        .ok_or(ConvenienceStorePickupError::MalformedResponse)?;
    check_server_code(object)?;

    (|| {
        let body = object.get("data")?.as_object()?;
        let data_url = body.get("qrcode")?.as_str()?;
        let comma = data_url.find(',')?;
        if !data_url[..comma]
            .to_lowercase()
            .starts_with("data:image/png;base64")
        {
            return None;
        }
        let image_data = decode_base64_ignoring_unknown(&data_url[comma + 1..])?;
        if !image_data.starts_with(&PNG_MAGIC) || image_data.len() > 5_000_000 {
            return None;
        }
        let timeout: f64 = body.get("totptimeout")?.as_str()?.parse().ok()?;
        if timeout <= 0.0 {
            return None;
        }
        Some(ConvenienceStorePickupBarcode {
            image_data,
            lifetime_seconds: timeout,
            generated_at: now,
        })
    })()
    .ok_or(ConvenienceStorePickupError::InvalidBarcodeImage)
}

/// Standard base64, tolerating stray characters (e.g. embedded
/// whitespace) the way `Data(base64Encoded:options:.ignoreUnknownCharacters)`
/// does.
fn decode_base64_ignoring_unknown(text: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    STANDARD.decode(cleaned).ok()
}

/// Converts a verifier-provided lifetime into an absolute, testable
/// deadline. Always asks the deadline again rather than decrementing a
/// counter, so time spent in the background cannot make an expired store
/// token look current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvenienceStorePickupCountdown {
    pub expires_at: DateTime<Utc>,
}

impl ConvenienceStorePickupCountdown {
    pub fn new(barcode: &ConvenienceStorePickupBarcode) -> Self {
        let millis = (barcode.lifetime_seconds * 1000.0).round() as i64;
        Self {
            expires_at: barcode.generated_at + chrono::Duration::milliseconds(millis),
        }
    }

    pub fn remaining_seconds(&self, now: DateTime<Utc>) -> i64 {
        let remaining = (self.expires_at - now).num_milliseconds() as f64 / 1000.0;
        (remaining.ceil() as i64).max(0)
    }
}

/// The display serial for a signed-credential identifier URL: its last
/// path component, or the last `/`-separated segment for a string that is
/// not itself a URL.
pub fn credential_serial(identifier: &str) -> Option<String> {
    let trimmed = identifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(url) = url::Url::parse(trimmed) {
        if let Some(last) = url.path_segments().and_then(|mut s| s.next_back()) {
            if !last.is_empty() {
                return Some(last.to_string());
            }
        }
    }
    trimmed.split('/').next_back().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn official_catalogue_shape_keeps_the_verifier_module() {
        let body = r#"
        {
          "code":"0","message":"SUCCESS","data":{"vpItems":[
            {"vpUid":"23060248_tfmdw_pickup","name":"全家便利商店包裹取貨","verifierModuleUrl":"https://23060248.wallet.gov.tw/oid4vp","logoUrl":null},
            {"vpUid":"22555003_711pickup","name":"統一超商包裹取貨","verifierModuleUrl":"https://22555003.wallet.gov.tw/oid4vp","logoUrl":"https://22555003.wallet.gov.tw/logo.png"},
            {"vpUid":"broken","name":"缺少端點","verifierModuleUrl":null,"logoUrl":null}
          ]}}
        "#;

        let scenarios = scenarios(body.as_bytes()).unwrap();
        assert_eq!(scenarios.len(), 2);
        let seven_eleven = scenarios
            .iter()
            .find(|s| s.vp_uid == SEVEN_ELEVEN_VP_UID)
            .unwrap();
        assert_eq!(seven_eleven.name, "統一超商包裹取貨");
        assert_eq!(
            seven_eleven.verifier_module_url,
            "https://22555003.wallet.gov.tw/oid4vp"
        );
    }

    #[test]
    fn start_response_keeps_transaction_and_authorize_link() {
        let link = "modadigitalwallet://authorize?client_id=did:key:zTest&request_uri=https%3A%2F%2F22555003.wallet.gov.tw%2Frequest%2Fopaque";
        let body = serde_json::json!({
            "code": "0",
            "message": "SUCCESS",
            "data": {"transactionId": "transaction-not-logged", "deepLink": link},
        });
        let (transaction_id, deep_link) = parse_start(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(transaction_id, "transaction-not-logged");
        assert_eq!(deep_link, link);
    }

    #[test]
    fn signed_credential_url_becomes_the_displayed_serial() {
        assert_eq!(
            credential_serial(
                "https://issuer-vc.wallet.gov.tw/api/credential/39d60715-e90c-402a-98aa-test"
            ),
            Some("39d60715-e90c-402a-98aa-test".to_string())
        );
        assert_eq!(credential_serial(""), None);
    }

    const ONE_BY_ONE_PNG_BASE64: &str =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

    #[test]
    fn verifier_png_and_lifetime_are_the_only_barcode_source() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let png = STANDARD.decode(ONE_BY_ONE_PNG_BASE64).unwrap();
        let body = serde_json::json!({
            "code": "0",
            "data": {
                "qrcode": format!("data:image/png;base64,{}", STANDARD.encode(&png)),
                "totptimeout": "300",
            },
        });
        let generated = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let barcode = parse_barcode(&serde_json::to_vec(&body).unwrap(), generated).unwrap();

        assert_eq!(barcode.image_data, png);
        assert_eq!(barcode.lifetime_seconds, 300.0);
        assert_eq!(barcode.generated_at, generated);
    }

    #[test]
    fn verifier_lifetime_counts_down_from_an_absolute_deadline() {
        let barcode = ConvenienceStorePickupBarcode {
            image_data: vec![],
            lifetime_seconds: 300.0,
            generated_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        };
        let countdown = ConvenienceStorePickupCountdown::new(&barcode);

        assert_eq!(
            countdown.remaining_seconds(Utc.timestamp_opt(1_000, 0).unwrap()),
            300
        );
        assert_eq!(
            countdown.remaining_seconds(Utc.timestamp_opt(1_001, 200_000_000).unwrap()),
            299
        );
        assert_eq!(
            countdown.remaining_seconds(Utc.timestamp_opt(1_060, 0).unwrap()),
            240
        );
        assert_eq!(
            countdown.remaining_seconds(Utc.timestamp_opt(1_300, 0).unwrap()),
            0
        );
        assert_eq!(
            countdown.remaining_seconds(Utc.timestamp_opt(1_400, 0).unwrap()),
            0
        );
    }

    #[test]
    fn a_non_png_or_server_refusal_is_never_shown_as_a_barcode() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let text_image = STANDARD.encode(b"not a png");
        let malformed = serde_json::json!({
            "code": "0",
            "data": {"qrcode": format!("data:image/png;base64,{text_image}"), "totptimeout": "300"},
        });
        assert_eq!(
            parse_barcode(&serde_json::to_vec(&malformed).unwrap(), Utc::now()),
            Err(ConvenienceStorePickupError::InvalidBarcodeImage)
        );

        let refused = serde_json::json!({"code": "4021", "message": "refused"});
        assert_eq!(
            parse_start(&serde_json::to_vec(&refused).unwrap()),
            Err(ConvenienceStorePickupError::ServerCode("4021".to_string()))
        );
    }
}
