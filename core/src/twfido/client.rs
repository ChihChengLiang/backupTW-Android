//! Request/response shapes, ticket handling and result classification
//! for the TW FidO SP API's SIGN operation, scoped to what QR-code
//! mode needs: app-to-app ticket issuance (ATH-01) and result polling
//! (ATH-02).
//!
//! Ported from `backupTW-iOS/backupTW/TWFidO/TWFidOClient.swift`. The
//! actual HTTP POST stays native, the same architecture boundary every
//! other network-facing module in this crate uses: this builds request
//! bodies and interprets response bytes, a caller sends the request and
//! hands the reply straight back in.
//!
//! Push (ATH-03) and the official-document-consent signing target are
//! out of scope - neither is needed to get a citizen-certificate
//! signature over a credential's TBS via QR mode.

use super::checksum;

// MARK: - What the cardholder's key is asked to sign

/// What the cardholder's 自然人憑證 key is asked to sign.
///
/// # Why this is an enum and not a `String`
///
/// `CredentialTbs` is per-credential and binds the cardholder's
/// signature to a specific set of claims, via
/// `moica::to_be_signed`'s domain-prefixed digest - which is the whole
/// point of issuing under 自然人憑證 rather than under the device key.
/// A caller passing the bare digest, or an unrelated string, here
/// produces a signature that generates fine and verifies against
/// nothing; the type name says what must go in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningTarget {
    /// A credential's complete TBS from `moica::to_be_signed` - the
    /// `bonds-tw-credential-v1:` domain prefix and the digest, already
    /// joined.
    CredentialTbs(String),
}

impl SigningTarget {
    pub fn to_be_signed(&self) -> &str {
        match self {
            Self::CredentialTbs(tbs) => tbs,
        }
    }
}

/// `sign_data` is the base64 of the TBS. `tbs_encoding: "base64"`
/// refers to this wrapping only - what the card's key covers is
/// `SHA-256(target.to_be_signed())`, computed by the card itself; every
/// consumer downstream (`moica::MoicaSignedCredential::verify_signed_by`)
/// wants the unwrapped string.
pub fn sign_data(target: &SigningTarget) -> String {
    base64_encode_standard(target.to_be_signed().as_bytes())
}

// MARK: - Preconditions

/// What the spec allows for `time_limit`, seconds.
pub const ALLOWED_TIME_LIMITS: (i64, i64) = (30, 600);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// `time_limit` outside the 30-600 seconds the spec allows. A
    /// caller bug, not a holder-facing failure - the number is the
    /// whole diagnosis.
    #[error("invalid time limit: {0}")]
    InvalidTimeLimit(i64),
    /// The response was not the documented envelope shape at all.
    #[error("invalid response")]
    InvalidResponse,
    /// A terminal `error_code` from the SP API.
    #[error("server error {code}: {message:?}")]
    Server {
        code: String,
        message: Option<String>,
    },
    /// `error_code` was "0" but a field the caller depends on was
    /// absent.
    #[error("missing result field: {0}")]
    MissingResultField(String),
    /// `sp_ticket` was not `base64url(payload).base64url(digest)`
    /// carrying `transaction_id`/`sp_ticket_id`.
    #[error("malformed ticket: {0}")]
    MalformedTicket(String),
    /// The return URL could not be expressed in a deep link.
    #[error("invalid return url")]
    InvalidReturnUrl,
    /// `idp_checksum` did not authenticate the response - it did not
    /// open under the SP AES key, or it opened but covers a different
    /// response. Either way the body is not evidence of anything
    /// 內政部 said.
    #[error("unauthenticated result")]
    UnauthenticatedResult,
}

/// Everything that can be known to be wrong before a request is built.
/// A request body carries 身分證統一編號 in the clear, so a caller bug
/// must not be paid for with a disclosure - this runs before any body
/// exists.
pub fn validate_time_limit(time_limit: i64) -> Result<(), ClientError> {
    let (min, max) = ALLOWED_TIME_LIMITS;
    if time_limit < min || time_limit > max {
        return Err(ClientError::InvalidTimeLimit(time_limit));
    }
    Ok(())
}

// MARK: - ATH-01: app-to-app ticket issuance

pub const OP_CODE: &str = "SIGN";
pub const APP_TO_APP_OP_MODE: &str = "APP2APP";
/// PKCS#1 produces the bare RSA signature `moica::X509Certificate::
/// verifies_pkcs1_sha256` consumes. PKCS#7/CMS wrap it in a structure
/// that parser cannot read, so this is a constraint, not a preference.
pub const SIGN_TYPE: &str = "PKCS#1";
pub const TBS_ENCODING: &str = "base64";
pub const HASH_ALGORITHM: &str = "SHA256";

/// The `sp_checksum` payload for an ATH-01 app-to-app request.
#[allow(clippy::too_many_arguments)]
pub fn app_to_app_checksum_payload(
    transaction_id: &str,
    sp_service_id: &str,
    id_number: &str,
    hint: &str,
    sign_data: &str,
) -> String {
    checksum::app_to_app_payload(
        transaction_id,
        sp_service_id,
        id_number,
        OP_CODE,
        APP_TO_APP_OP_MODE,
        hint,
        sign_data,
    )
}

/// The ATH-01 request body, JSON-encoded and ready to POST.
/// `sp_checksum` is computed by the caller from
/// [`app_to_app_checksum_payload`] via `checksum::compute` - this
/// function only assembles the body, so a caller cannot accidentally
/// sign one payload and send another.
#[allow(clippy::too_many_arguments)]
pub fn app_to_app_request_body(
    transaction_id: &str,
    sp_service_id: &str,
    sp_checksum: &str,
    id_number: &str,
    hint: &str,
    time_limit: i64,
    sign_data: &str,
) -> Vec<u8> {
    let body = serde_json::json!({
        "transaction_id": transaction_id,
        "sp_service_id": sp_service_id,
        "sp_checksum": sp_checksum,
        "id_num": id_number,
        "op_code": OP_CODE,
        "op_mode": APP_TO_APP_OP_MODE,
        "hint": hint,
        // Integer, not a string - the spec's field table types
        // `time_limit` as Integer and the official JAVA sample posts
        // `formBody.put("time_limit", 600)`.
        "time_limit": time_limit,
        "sign_info": {
            "sign_data": sign_data,
            "sign_type": SIGN_TYPE,
            "tbs_encoding": TBS_ENCODING,
            "hash_algorithm": HASH_ALGORITHM,
        },
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Reads the `sp_ticket` out of a successful ATH-01 response body.
/// `{ error_code, error_message, result: { sp_ticket } }`.
pub fn parse_ticket_response(body: &[u8]) -> Result<String, ClientError> {
    let envelope: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ClientError::InvalidResponse)?;
    let (error_code, error_message) = read_envelope_status(&envelope)?;
    if error_code != "0" {
        return Err(ClientError::Server {
            code: error_code,
            message: error_message,
        });
    }
    let sp_ticket = envelope
        .get("result")
        .and_then(|r| r.get("sp_ticket"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ClientError::MissingResultField("sp_ticket".to_string()))?;
    Ok(sp_ticket.to_string())
}

// MARK: - Ticket

/// An issued `sp_ticket`, with the two identifiers unpacked from it.
/// The transport hands back only the opaque string, but polling for
/// the result needs `transaction_id` and `sp_ticket_id`, both of which
/// live inside the ticket's own payload - so decoding is mandatory,
/// not a debug convenience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub sp_ticket: String,
    pub transaction_id: String,
    pub sp_ticket_id: String,
}

#[derive(serde::Deserialize)]
struct TicketClaims {
    transaction_id: String,
    sp_ticket_id: String,
}

/// `sp_ticket` is `base64url(payload) "." base64url(digest)`. Split on
/// the **last** dot: the digest is a single trailing segment, but
/// nothing promises the payload segment is dot-free.
pub fn parse_ticket(sp_ticket: &str) -> Result<Ticket, ClientError> {
    let separator = sp_ticket
        .rfind('.')
        .ok_or_else(|| ClientError::MalformedTicket("missing '.' separator".to_string()))?;
    let encoded_payload = &sp_ticket[..separator];
    let payload_bytes = base64url_decode(encoded_payload)
        .ok_or_else(|| ClientError::MalformedTicket("payload is not base64url".to_string()))?;
    let claims: TicketClaims = serde_json::from_slice(&payload_bytes).map_err(|_| {
        ClientError::MalformedTicket("payload is not the expected JSON".to_string())
    })?;
    Ok(Ticket {
        sp_ticket: sp_ticket.to_string(),
        transaction_id: claims.transaction_id,
        sp_ticket_id: claims.sp_ticket_id,
    })
}

// MARK: - Deep link

/// `mobilemoica://moica.moi.gov.tw/a2a/verifySign?…` - what QR-code
/// mode encodes into a scannable image, and what app-to-app mode would
/// hand to the OS directly.
///
/// Built by hand rather than through a generic query-string encoder,
/// because a permissive encoder percent-encodes `=` but leaves `+`/`/`
/// raw. `rtn_url` is standard base64, so both can appear - and if the
/// receiving side form-decodes, a `+` becomes a space, the base64
/// decode fails, and the holder signs successfully but never gets
/// back. Only unreserved characters (RFC 3986 §2.3) are left
/// unescaped; everything else is percent-encoded.
pub fn deep_link(ticket: &Ticket, return_url: &str) -> Result<String, ClientError> {
    let return_url_base64 = base64_encode_standard(return_url.as_bytes());
    // base64url, not the bare transaction id: the parameter is defined
    // as base64url, and a raw UUID would decode without complaint into
    // meaningless bytes, silently stalling the return leg.
    let return_value = base64url_encode(ticket.transaction_id.as_bytes());

    let query = [
        format!("sp_ticket={}", percent_encode_unreserved(&ticket.sp_ticket)),
        format!("rtn_url={}", percent_encode_unreserved(&return_url_base64)),
        format!("rtn_val={}", percent_encode_unreserved(&return_value)),
    ]
    .join("&");

    let url = format!("mobilemoica://moica.moi.gov.tw/a2a/verifySign?{query}");
    if url::Url::parse(&url).is_err() {
        return Err(ClientError::InvalidReturnUrl);
    }
    Ok(url)
}

// MARK: - ATH-02: result polling

/// The `sp_checksum` payload for an ATH-02 result-polling request.
pub fn result_checksum_payload(
    transaction_id: &str,
    sp_service_id: &str,
    sp_ticket_id: &str,
) -> String {
    checksum::result_payload(transaction_id, sp_service_id, sp_ticket_id)
}

/// The ATH-02 request body, JSON-encoded and ready to POST.
pub fn result_request_body(
    transaction_id: &str,
    sp_service_id: &str,
    sp_checksum: &str,
    sp_ticket_id: &str,
) -> Vec<u8> {
    let body = serde_json::json!({
        "transaction_id": transaction_id,
        "sp_service_id": sp_service_id,
        "sp_checksum": sp_checksum,
        "sp_ticket_id": sp_ticket_id,
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// The signature material, once the holder has approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignResult {
    /// Base64 DER of the **holder's** certificate. The issuing CA
    /// (MOICA G3) is bundled with the app separately -
    /// `moica::IssuerCertificate::load_bundled` - never taken from
    /// here.
    pub cert: String,
    /// Base64 PKCS#1 signature over the requested TBS.
    pub signed_response: String,
    pub hashed_id_number: String,
}

/// One poll of ATH-02. Returns `Ok(None)` while the holder has not
/// finished - the caller owns the retry cadence (the spec asks for at
/// least 4 seconds between attempts) and, more importantly, owns the
/// deadline. No timeout here on purpose: looping forever would outlive
/// the ticket's own `time_limit` and leave a caller's UI wedged with
/// nothing to cancel.
///
/// Authenticates the body via `idp_checksum` before reading anything
/// out of it - see `checksum::verify`'s docs for why. `transaction_id`/
/// `sp_service_id` are the same values the request was built from;
/// `aes_key_base64` is the SP key.
pub fn parse_result_response(
    body: &[u8],
    transaction_id: &str,
    aes_key_base64: &str,
) -> Result<Option<SignResult>, ClientError> {
    let envelope: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ClientError::InvalidResponse)?;
    let (error_code, error_message) = read_envelope_status(&envelope)?;
    if error_code != "0" {
        if is_pending(&error_code) {
            return Ok(None);
        }
        return Err(ClientError::Server {
            code: error_code,
            message: error_message,
        });
    }

    let result = envelope
        .get("result")
        .ok_or_else(|| ClientError::MissingResultField("result".to_string()))?;

    // hashed_id_num/signed_response degrade to empty when absent, in
    // the same degraded form the server itself would have hashed - the
    // checksum is over what the server sent, not over what we wish it
    // had sent.
    let hashed_id_num = result
        .get("hashed_id_num")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let signed_response_field = result
        .get("signed_response")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let idp_checksum = result
        .get("idp_checksum")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ClientError::MissingResultField("idp_checksum".to_string()))?;
    let payload = checksum::idp_checksum_payload(
        transaction_id,
        &error_code,
        &hashed_id_num,
        &signed_response_field,
    );
    checksum::verify(idp_checksum, &payload, aes_key_base64)
        .map_err(|_| ClientError::UnauthenticatedResult)?;

    let cert = result
        .get("cert")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ClientError::MissingResultField("cert".to_string()))?
        .to_string();
    if signed_response_field.is_empty() {
        return Err(ClientError::MissingResultField(
            "signed_response".to_string(),
        ));
    }

    Ok(Some(SignResult {
        cert,
        signed_response: signed_response_field,
        hashed_id_number: hashed_id_num,
    }))
}

/// Terminal-vs-pending classification. The API sometimes prefixes the
/// code with the operation (`"SP-API-ATH-02-…"`) and sometimes appends
/// a colon-separated explanation, so both forms are normalised before
/// the lookup.
pub fn is_pending(error_code: &str) -> bool {
    const PENDING_ERROR_CODES: [&str; 4] = [
        "20002",
        "20003",
        "SP-API-ATH-02-SPTKTID_TXNLOG_NF",
        "SPTKTID_TXNLOG_NF",
    ];
    let head = error_code.split(':').next().unwrap_or("").trim();
    PENDING_ERROR_CODES.contains(&head)
}

/// Whether a failed poll may simply be tried again, bounded by the
/// ticket's own deadline.
///
/// **Why this matters, measured on real hardware.** The app-to-app
/// flow *guarantees* a transport failure: the first poll fires in the
/// same breath as the deep-link hand-off, so the request is in flight
/// exactly as the app backgrounds - a suspended app's sockets are the
/// OS's to kill. The holder signs, MOICA reports success, the return
/// leg foregrounds the app, and the parked request completes with a
/// connection-lost error. A polling loop that treats that as terminal
/// then throws away a ticket that is still valid and a signature that
/// already exists.
///
/// Scoped to what this module itself can classify -
/// [`ClientError::InvalidResponse`] is retryable, everything else here
/// is terminal. A native caller must additionally treat its own
/// transport-layer failures (an HTTP error status, a dropped
/// connection) as retryable too - this function cannot see those,
/// since the network call stays native.
pub fn is_transient_client_error(error: &ClientError) -> bool {
    matches!(error, ClientError::InvalidResponse)
}

// MARK: - Envelope

/// `error_code` is documented as a string but arrives as a bare number
/// in some deployments, so both are accepted rather than failing the
/// whole response.
fn read_envelope_status(
    envelope: &serde_json::Value,
) -> Result<(String, Option<String>), ClientError> {
    let object = envelope.as_object().ok_or(ClientError::InvalidResponse)?;
    let error_code = match object.get("error_code") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => return Err(ClientError::InvalidResponse),
    };
    let error_message = object
        .get("error_message")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok((error_code, error_message))
}

// MARK: - Encoding

fn base64_encode_standard(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(bytes)
}

fn base64url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};
    // The payload segment carries no padding; the standard base64url
    // decoder requires it, so pad before decoding rather than reaching
    // for a second no-pad decoder for the same alphabet.
    let mut padded = value.to_string();
    let remainder = padded.len() % 4;
    if remainder > 0 {
        padded.push_str(&"=".repeat(4 - remainder));
    }
    URL_SAFE.decode(padded).ok()
}

/// Unreserved characters only (RFC 3986 §2.3). Anything else is
/// escaped, which is always valid and removes every question about how
/// the receiver decodes the query.
fn percent_encode_unreserved(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let c = byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    fn key() -> String {
        STANDARD.encode([0x2A; 32])
    }

    #[test]
    fn validate_time_limit_accepts_the_documented_range() {
        assert!(validate_time_limit(30).is_ok());
        assert!(validate_time_limit(600).is_ok());
        assert_eq!(
            validate_time_limit(29),
            Err(ClientError::InvalidTimeLimit(29))
        );
        assert_eq!(
            validate_time_limit(601),
            Err(ClientError::InvalidTimeLimit(601))
        );
    }

    #[test]
    fn sign_data_is_base64_of_the_tbs() {
        let target = SigningTarget::CredentialTbs("bonds-tw-credential-v1:deadbeef".to_string());
        assert_eq!(
            sign_data(&target),
            STANDARD.encode("bonds-tw-credential-v1:deadbeef")
        );
    }

    fn make_ticket(transaction_id: &str, sp_ticket_id: &str) -> String {
        let claims =
            serde_json::json!({"transaction_id": transaction_id, "sp_ticket_id": sp_ticket_id});
        let payload = base64url_encode(&serde_json::to_vec(&claims).unwrap());
        format!("{payload}.digest-segment")
    }

    #[test]
    fn parse_ticket_reads_the_two_identifiers() {
        let sp_ticket = make_ticket("TXN-1", "STID-1");
        let ticket = parse_ticket(&sp_ticket).unwrap();
        assert_eq!(ticket.transaction_id, "TXN-1");
        assert_eq!(ticket.sp_ticket_id, "STID-1");
        assert_eq!(ticket.sp_ticket, sp_ticket);
    }

    #[test]
    fn parse_ticket_rejects_a_missing_separator() {
        assert_eq!(
            parse_ticket("no-dot-here"),
            Err(ClientError::MalformedTicket(
                "missing '.' separator".to_string()
            ))
        );
    }

    #[test]
    fn parse_ticket_rejects_non_json_payload() {
        assert_eq!(
            parse_ticket("bm90anNvbg.digest"),
            Err(ClientError::MalformedTicket(
                "payload is not the expected JSON".to_string()
            ))
        );
    }

    #[test]
    fn deep_link_carries_the_ticket_and_encoded_return_url() {
        let sp_ticket = make_ticket("TXN-1", "STID-1");
        let ticket = parse_ticket(&sp_ticket).unwrap();
        let url = deep_link(&ticket, "backuptw://twfido/callback").unwrap();
        assert!(url.starts_with("mobilemoica://moica.moi.gov.tw/a2a/verifySign?"));
        assert!(url.contains("sp_ticket="));
        assert!(url.contains("rtn_url="));
        assert!(url.contains("rtn_val="));
        // None of the reserved base64 characters leak into the *query*
        // unescaped - the scheme/host/path portion legitimately has
        // its own slashes.
        let query = url.split('?').nth(1).unwrap();
        assert!(!query.contains('+'));
        assert!(!query.contains('/'));
    }

    #[test]
    fn deep_link_rtn_val_is_base64url_of_the_transaction_id() {
        let sp_ticket = make_ticket("TXN-1", "STID-1");
        let ticket = parse_ticket(&sp_ticket).unwrap();
        let url = deep_link(&ticket, "backuptw://twfido/callback").unwrap();
        let expected = percent_encode_unreserved(&base64url_encode(b"TXN-1"));
        assert!(url.contains(&format!("rtn_val={expected}")));
    }

    #[test]
    fn is_pending_normalises_prefixed_and_suffixed_codes() {
        assert!(is_pending("20002"));
        assert!(is_pending("SP-API-ATH-02-SPTKTID_TXNLOG_NF"));
        assert!(is_pending("20002: still waiting"));
        assert!(!is_pending("20099"));
        assert!(!is_pending("0"));
    }

    fn signed_result_envelope(
        transaction_id: &str,
        error_code: &str,
        hashed_id_num: &str,
        signed_response: &str,
        cert: &str,
        aes_key: &str,
    ) -> Vec<u8> {
        let payload = checksum::idp_checksum_payload(
            transaction_id,
            error_code,
            hashed_id_num,
            signed_response,
        );
        let idp_checksum = checksum::compute(&payload, aes_key).unwrap();
        let envelope = serde_json::json!({
            "error_code": error_code,
            "error_message": null,
            "result": {
                "hashed_id_num": hashed_id_num,
                "signed_response": signed_response,
                "cert": cert,
                "idp_checksum": idp_checksum,
            },
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    #[test]
    fn parse_result_response_reads_an_authenticated_success() {
        let key = key();
        let body = signed_result_envelope("TXN-1", "0", "hashed-id", "c2lnbmVk", "Y2VydA==", &key);
        let result = parse_result_response(&body, "TXN-1", &key)
            .unwrap()
            .unwrap();
        assert_eq!(result.cert, "Y2VydA==");
        assert_eq!(result.signed_response, "c2lnbmVk");
        assert_eq!(result.hashed_id_number, "hashed-id");
    }

    #[test]
    fn parse_result_response_is_pending_returns_none() {
        let envelope = serde_json::json!({"error_code": "20002", "error_message": "pending"});
        let body = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(parse_result_response(&body, "TXN-1", &key()).unwrap(), None);
    }

    #[test]
    fn parse_result_response_rejects_an_unauthenticated_body() {
        let key = key();
        let mut body_value: serde_json::Value = serde_json::from_slice(&signed_result_envelope(
            "TXN-1",
            "0",
            "hashed-id",
            "c2lnbmVk",
            "Y2VydA==",
            &key,
        ))
        .unwrap();
        // Tamper with the signed_response after the checksum was computed.
        body_value["result"]["signed_response"] = serde_json::json!("dGFtcGVyZWQ=");
        let body = serde_json::to_vec(&body_value).unwrap();
        assert_eq!(
            parse_result_response(&body, "TXN-1", &key),
            Err(ClientError::UnauthenticatedResult)
        );
    }

    #[test]
    fn parse_result_response_rejects_a_terminal_server_error() {
        let envelope = serde_json::json!({"error_code": "99999", "error_message": "refused"});
        let body = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            parse_result_response(&body, "TXN-1", &key()),
            Err(ClientError::Server {
                code: "99999".to_string(),
                message: Some("refused".to_string())
            })
        );
    }

    #[test]
    fn parse_result_response_tolerates_a_bare_integer_error_code() {
        let envelope = serde_json::json!({"error_code": 20002});
        let body = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(parse_result_response(&body, "TXN-1", &key()).unwrap(), None);
    }

    #[test]
    fn parse_ticket_response_reads_a_successful_ticket() {
        let envelope = serde_json::json!({"error_code": "0", "result": {"sp_ticket": "abc.def"}});
        let body = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(parse_ticket_response(&body).unwrap(), "abc.def");
    }

    #[test]
    fn parse_ticket_response_rejects_a_server_refusal() {
        let envelope =
            serde_json::json!({"error_code": "40001", "error_message": "invalid checksum"});
        let body = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            parse_ticket_response(&body),
            Err(ClientError::Server {
                code: "40001".to_string(),
                message: Some("invalid checksum".to_string())
            })
        );
    }

    #[test]
    fn is_transient_client_error_matches_only_invalid_response() {
        assert!(is_transient_client_error(&ClientError::InvalidResponse));
        assert!(!is_transient_client_error(
            &ClientError::UnauthenticatedResult
        ));
        assert!(!is_transient_client_error(&ClientError::Server {
            code: "1".to_string(),
            message: None
        }));
        assert!(!is_transient_client_error(&ClientError::InvalidTimeLimit(
            1
        )));
    }
}
