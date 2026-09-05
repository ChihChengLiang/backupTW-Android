//! A verifier asked for a presentation. What exactly did it ask for, and
//! did it really sign the ask?
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/OID4VPRequest.swift`. Fully
//! pure: the trust decision (`trusted_response_hosts`) is a set the caller
//! supplies rather than a network fetch, matching the "gate before the
//! first request" discipline the issuer offer's `authorise` uses. Fetching
//! the request object from `request_uri` (`OID4VPRequestFetcher.swift`) is
//! a network call and stays native.

use std::collections::HashSet;

use crate::identity::{did_key, jwk_did_key};
use crate::twdiw::issuer_authorization::normalised_host;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Oid4VpRequestError {
    /// Not an `…://authorize?…` link, or missing `client_id` /
    /// `request_uri`/`request`.
    #[error("not an authorize link")]
    NotAnAuthorizeLink,
    /// The request object is not a three-part compact JWS.
    #[error("malformed request object")]
    MalformedRequestObject,
    /// `client_id` is not a `did:key` this app can take a P-256 key from.
    #[error("client_id not a resolvable did")]
    ClientIdNotAResolvableDid,
    /// The request object's signature does not verify against the key in
    /// `client_id`.
    #[error("signature invalid")]
    SignatureInvalid,
    /// A field the response cannot be built without is missing.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// `response_mode` is not `direct_post`.
    #[error("unsupported response mode: {0}")]
    UnsupportedResponseMode(String),
    /// `response_uri`'s host is not one this wallet will post a signed
    /// token to - the verifier equivalent of the issuer trust-list gate.
    #[error("response_uri not trusted: {host}")]
    ResponseUriNotTrusted { host: String },
}

/// The `openid4vp` / `modadigitalwallet://authorize` link a verifier
/// shows, carrying either the request object inline or a `request_uri` to
/// fetch it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Oid4VpAuthorizeLink {
    ByReference {
        client_id: String,
        request_uri: String,
    },
    ByValue {
        client_id: String,
        request_object: String,
    },
}

const AUTHORIZE_LINK_SCHEMES: [&str; 2] = ["openid4vp", "modadigitalwallet"];

impl Oid4VpAuthorizeLink {
    /// Reads the link from a **scanned string**, tolerating the framing a
    /// QR carries - bytes off a camera are not a URL the OS built. See
    /// `credential_offer::CredentialOfferLink::parse`.
    pub fn parse(scanned: &str) -> Result<Self, Oid4VpRequestError> {
        let cleaned: String = scanned
            .chars()
            .filter(|&c| c != '\r' && c != '\n')
            .collect();
        let cleaned = cleaned.trim();
        let url = url::Url::parse(cleaned).map_err(|_| Oid4VpRequestError::NotAnAuthorizeLink)?;

        let scheme = url.scheme().to_lowercase();
        if !AUTHORIZE_LINK_SCHEMES.contains(&scheme.as_str()) {
            return Err(Oid4VpRequestError::NotAnAuthorizeLink);
        }
        // `modadigitalwallet://authorize?…` puts `authorize` in the host
        // slot, the same way its credential-offer form puts
        // `credential_offer` there. Not lowercased, matching Swift's exact
        // comparison.
        if let Some(host) = url.host_str() {
            if !host.is_empty() && host != "authorize" {
                return Err(Oid4VpRequestError::NotAnAuthorizeLink);
            }
        }

        let mut client_id: Option<String> = None;
        let mut request_uri: Option<String> = None;
        let mut request_object: Option<String> = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "client_id" if client_id.is_none() => client_id = Some(value.into_owned()),
                "request_uri" if request_uri.is_none() => request_uri = Some(value.into_owned()),
                "request" if request_object.is_none() => request_object = Some(value.into_owned()),
                _ => {}
            }
        }
        let client_id = client_id
            .filter(|s| !s.is_empty())
            .ok_or(Oid4VpRequestError::NotAnAuthorizeLink)?;
        if let Some(uri) = request_uri.filter(|s| !s.is_empty()) {
            return Ok(Self::ByReference {
                client_id,
                request_uri: uri,
            });
        }
        if let Some(obj) = request_object.filter(|s| !s.is_empty()) {
            return Ok(Self::ByValue {
                client_id,
                request_object: obj,
            });
        }
        Err(Oid4VpRequestError::NotAnAuthorizeLink)
    }
}

/// One field the verifier asked to see, from an input descriptor's
/// constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid4VpRequestedField {
    /// The JSONPath the descriptor named, e.g. `$.credentialSubject.name`.
    pub path: String,
}

impl Oid4VpRequestedField {
    /// The claim name at the end of the path, when the path is a simple
    /// `$.credentialSubject.<name>`. `None` for paths like `$.type` that
    /// select something other than a disclosable claim.
    pub fn claim_name(&self) -> Option<&str> {
        let prefix = "$.credentialSubject.";
        let name = self.path.strip_prefix(prefix)?;
        if name.contains('.') {
            None
        } else {
            Some(name)
        }
    }
}

/// The inner credential format named by a presentation descriptor.
/// `Moica` is this project's explicit extension for the JSON envelope
/// signed by a MOICA citizen certificate - kept distinct from `SdJwt` so a
/// verifier does not apply JOSE rules to a document that deliberately is
/// not a compact JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oid4VpCredentialFormat {
    SdJwt,
    Moica,
}

impl Oid4VpCredentialFormat {
    const SD_JWT_KEY: &'static str = "vc+sd-jwt";
    const MOICA_KEY: &'static str = "vc+moica";
}

/// One alternative named by a DIF presentation definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid4VpInputDescriptor {
    pub id: String,
    pub credential_format: Option<Oid4VpCredentialFormat>,
    pub credential_type: Option<String>,
    pub requested_fields: Vec<Oid4VpRequestedField>,
    pub groups: Vec<String>,
    pub credential_name: Option<String>,
    pub issuer_name: Option<String>,
}

/// How a verifier combines descriptor groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid4VpSubmissionRequirement {
    pub name: Option<String>,
    pub rule: String,
    pub from: String,
    pub count: Option<i64>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

/// A verified presentation request, reduced to what building a response
/// needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid4VpRequest {
    /// Where the signed `vp_token` is posted back. **Verified**: the
    /// request object it came in was signed by `client_id`'s key.
    pub response_uri: String,
    /// The verifier's identifier, a `did:key`. Its key verified the
    /// request.
    pub client_id: String,
    /// Binds this exchange. The `vp_token` must carry it, or a captured
    /// token could be replayed to the same verifier.
    pub nonce: String,
    /// Echoed back in the response so the verifier can match it to its
    /// session.
    pub state: String,
    /// Every credential alternative and its own claims/group membership.
    pub input_descriptors: Vec<Oid4VpInputDescriptor>,
    /// The group-selection rules. Empty is the legacy one-descriptor form.
    pub submission_requirements: Vec<Oid4VpSubmissionRequirement>,
    /// `presentation_definition.id`, echoed into the submission so the
    /// verifier can tie the response to the request it sent.
    pub definition_id: String,
}

impl Oid4VpRequest {
    /// Compatibility view for the original one-descriptor request.
    /// Callers that build a response use `input_descriptors`, never this.
    pub fn credential_type(&self) -> Option<&str> {
        self.input_descriptors
            .first()
            .and_then(|d| d.credential_type.as_deref())
    }

    pub fn input_descriptor_id(&self) -> &str {
        self.input_descriptors
            .first()
            .map(|d| d.id.as_str())
            .unwrap_or("")
    }

    /// Unique fields in verifier order. A field such as `name` appears
    /// once even when several carrier alternatives each request it.
    pub fn requested_fields(&self) -> Vec<&Oid4VpRequestedField> {
        let mut seen = HashSet::new();
        self.input_descriptors
            .iter()
            .flat_map(|d| d.requested_fields.iter())
            .filter(move |f| seen.insert(f.path.clone()))
            .collect()
    }

    /// Verifies a request object and reduces it.
    ///
    /// `compact_jws`: the `oauth-authz-req+jwt` fetched from
    /// `request_uri`. `client_id`: the `did:key` from the authorize link;
    /// its embedded key must have signed `compact_jws`.
    /// `trusted_response_hosts`: hosts this wallet will post a token to -
    /// the `response_uri` inside the request must be one of them.
    pub fn verify(
        compact_jws: &str,
        client_id: &str,
        trusted_response_hosts: &HashSet<String>,
    ) -> Result<Self, Oid4VpRequestError> {
        let parts: Vec<&str> = compact_jws.split('.').collect();
        if parts.len() != 3 {
            return Err(Oid4VpRequestError::MalformedRequestObject);
        }

        // The signing key comes from client_id, not the header's `kid`
        // (measured: `kid` is the opaque string `verifier-did`) - the key
        // is named by the value being checked, so it must be the caller's
        // client_id, resolved as a did:key. jwk_jcs-pub spelling first,
        // then this app's own p256-pub spelling as a fallback.
        let key = jwk_did_key::p256_public_key_from_did(client_id)
            .ok()
            .or_else(|| did_key::p256_public_key_from_did(client_id).ok())
            .ok_or(Oid4VpRequestError::ClientIdNotAResolvableDid)?;

        verify_signature(parts[0], parts[1], parts[2], &key)?;

        let payload_bytes =
            base64url_decode(parts[1]).ok_or(Oid4VpRequestError::MalformedRequestObject)?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_| Oid4VpRequestError::MalformedRequestObject)?;
        let payload = payload
            .as_object()
            .ok_or(Oid4VpRequestError::MalformedRequestObject)?;

        if let Some(mode) = payload.get("response_mode").and_then(|v| v.as_str()) {
            if mode != "direct_post" {
                return Err(Oid4VpRequestError::UnsupportedResponseMode(
                    mode.to_string(),
                ));
            }
        }
        let response_uri = payload
            .get("response_uri")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(Oid4VpRequestError::MissingField("response_uri"))?;

        // The gate: a signed token is about to be addressable here, so the
        // host must be one we chose to trust - not one the request chose
        // for us.
        let normalized = normalised_host(response_uri).ok();
        let trusted = normalized
            .as_deref()
            .is_some_and(|h| trusted_response_hosts.contains(h));
        if !trusted {
            let host = normalized.unwrap_or_else(|| response_uri.to_string());
            return Err(Oid4VpRequestError::ResponseUriNotTrusted { host });
        }

        let nonce = payload
            .get("nonce")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(Oid4VpRequestError::MissingField("nonce"))?;
        let state = payload
            .get("state")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(Oid4VpRequestError::MissingField("state"))?;

        let definition = payload
            .get("presentation_definition")
            .and_then(|v| v.as_object());
        let definition_id = definition
            .and_then(|d| d.get("id"))
            .and_then(|v| v.as_str())
            .ok_or(Oid4VpRequestError::MissingField(
                "presentation_definition.id",
            ))?;

        let raw_descriptors: Vec<&serde_json::Value> = definition
            .and_then(|d| d.get("input_descriptors"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().collect())
            .unwrap_or_default();
        if raw_descriptors.is_empty() {
            return Err(Oid4VpRequestError::MissingField("input_descriptors[0].id"));
        }

        let mut descriptors = Vec::with_capacity(raw_descriptors.len());
        for (index, raw) in raw_descriptors.iter().enumerate() {
            descriptors.push(parse_descriptor(raw, index)?);
        }

        let requirements = definition
            .and_then(|d| d.get("submission_requirements"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(parse_submission_requirement)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            response_uri: response_uri.to_string(),
            client_id: client_id.to_string(),
            nonce: nonce.to_string(),
            state: state.to_string(),
            input_descriptors: descriptors,
            submission_requirements: requirements,
            definition_id: definition_id.to_string(),
        })
    }
}

fn parse_descriptor(
    raw: &serde_json::Value,
    index: usize,
) -> Result<Oid4VpInputDescriptor, Oid4VpRequestError> {
    let object = raw.as_object();
    let id = object
        .and_then(|o| o.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Oid4VpRequestError::MissingField(missing_descriptor_id_field(index)))?;

    let formats = object
        .and_then(|o| o.get("format"))
        .and_then(|v| v.as_object());
    let credential_format =
        if formats.is_some_and(|f| f.contains_key(Oid4VpCredentialFormat::MOICA_KEY)) {
            Some(Oid4VpCredentialFormat::Moica)
        } else if formats.is_some_and(|f| f.contains_key(Oid4VpCredentialFormat::SD_JWT_KEY)) {
            Some(Oid4VpCredentialFormat::SdJwt)
        } else {
            None
        };

    let mut credential_type: Option<String> = None;
    let mut fields = Vec::new();
    let constraint_fields: Vec<&serde_json::Value> = object
        .and_then(|o| o.get("constraints"))
        .and_then(|c| c.get("fields"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().collect())
        .unwrap_or_default();
    for field in constraint_fields {
        let paths: Vec<&str> = field
            .get("path")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        for path in paths {
            if path == "$.type" {
                // The type constraint carries the required card type in
                // its `contains.const`.
                if let Some(const_value) = field
                    .get("filter")
                    .and_then(|f| f.get("contains"))
                    .and_then(|c| c.get("const"))
                    .and_then(|v| v.as_str())
                {
                    credential_type = Some(const_value.to_string());
                }
            } else {
                fields.push(Oid4VpRequestedField {
                    path: path.to_string(),
                });
            }
        }
    }

    let mut credential_name: Option<String> = None;
    let mut issuer_name: Option<String> = None;
    if let Some(name_json) = object.and_then(|o| o.get("name")).and_then(|v| v.as_str()) {
        if let Ok(names) = serde_json::from_str::<serde_json::Value>(name_json) {
            credential_name = names
                .get("vc_name")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            issuer_name = names
                .get("org_tw_name")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
    }

    let groups = object
        .and_then(|o| o.get("group"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(Oid4VpInputDescriptor {
        id: id.to_string(),
        credential_format,
        credential_type,
        requested_fields: fields,
        groups,
        credential_name,
        issuer_name,
    })
}

/// `"input_descriptors[<index>].id"`, matching Swift's interpolated
/// message field for field-name reporting.
fn missing_descriptor_id_field(index: usize) -> &'static str {
    // The field names carried by MissingField are &'static str throughout
    // this port (see collection.rs/credential.rs's ProofClaims-style
    // errors); the index is folded into a small fixed table since a
    // presentation definition realistically never carries more than a
    // handful of descriptors.
    const NAMES: [&str; 8] = [
        "input_descriptors[0].id",
        "input_descriptors[1].id",
        "input_descriptors[2].id",
        "input_descriptors[3].id",
        "input_descriptors[4].id",
        "input_descriptors[5].id",
        "input_descriptors[6].id",
        "input_descriptors[7].id",
    ];
    NAMES
        .get(index)
        .copied()
        .unwrap_or("input_descriptors[*].id")
}

fn parse_submission_requirement(raw: &serde_json::Value) -> Option<Oid4VpSubmissionRequirement> {
    let object = raw.as_object()?;
    let rule = object.get("rule")?.as_str().filter(|s| !s.is_empty())?;
    let from = object.get("from")?.as_str().filter(|s| !s.is_empty())?;
    Some(Oid4VpSubmissionRequirement {
        name: object
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        rule: rule.to_string(),
        from: from.to_string(),
        count: object.get("count").and_then(|v| v.as_i64()),
        min: object.get("min").and_then(|v| v.as_i64()),
        max: object.get("max").and_then(|v| v.as_i64()),
    })
}

fn verify_signature(
    header_part: &str,
    payload_part: &str,
    signature_part: &str,
    key: &p256::PublicKey,
) -> Result<(), Oid4VpRequestError> {
    use p256::ecdsa::signature::Verifier;
    let signature_bytes =
        base64url_decode(signature_part).ok_or(Oid4VpRequestError::MalformedRequestObject)?;
    let signature = p256::ecdsa::Signature::from_slice(&signature_bytes)
        .map_err(|_| Oid4VpRequestError::MalformedRequestObject)?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(key);
    let signing_input = format!("{header_part}.{payload_part}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Oid4VpRequestError::SignatureInvalid)
}

fn base64url_decode(segment: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(segment).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;

    fn base64url_encode(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn sign_raw(key: &SigningKey, message: &[u8]) -> Vec<u8> {
        let signature: Signature = key.sign(message);
        signature.to_bytes().to_vec()
    }

    struct TestVerifier {
        private_key: SigningKey,
    }

    impl TestVerifier {
        fn new() -> Self {
            Self {
                private_key: SigningKey::random(&mut OsRng),
            }
        }

        fn client_id(&self) -> String {
            let x963 = self
                .private_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            jwk_did_key::did_from_p256_x963(&x963).unwrap()
        }

        #[allow(clippy::too_many_arguments)]
        fn request_jwt(
            &self,
            response_uri: &str,
            nonce: &str,
            state: &str,
            definition_id: &str,
            descriptor_id: &str,
            credential_type: &str,
            fields: &[&str],
            credential_format: Option<&str>,
            signed_by: Option<&SigningKey>,
        ) -> String {
            let header = serde_json::json!({"kid": "verifier-did", "typ": "oauth-authz-req+jwt", "alg": "ES256"});
            let mut constraint_fields = vec![serde_json::json!({
                "path": ["$.type"],
                "filter": {"type": "array", "contains": {"const": credential_type}},
            })];
            for f in fields {
                constraint_fields
                    .push(serde_json::json!({"path": [format!("$.credentialSubject.{f}")]}));
            }
            let mut descriptor = serde_json::json!({
                "id": descriptor_id,
                "constraints": {"fields": constraint_fields},
            });
            if let Some(format) = credential_format {
                descriptor["format"] = serde_json::json!({format: {"alg": ["RS256", "ES256"]}});
            }
            let payload = serde_json::json!({
                "response_type": "vp_token",
                "response_mode": "direct_post",
                "response_uri": response_uri,
                "client_id": self.client_id(),
                "nonce": nonce,
                "state": state,
                "presentation_definition": {
                    "id": definition_id,
                    "input_descriptors": [descriptor],
                },
            });
            let h = base64url_encode(&json_bytes(&header));
            let p = base64url_encode(&json_bytes(&payload));
            let signing_input = format!("{h}.{p}");
            let key = signed_by.unwrap_or(&self.private_key);
            let signature = sign_raw(key, signing_input.as_bytes());
            format!("{h}.{p}.{}", base64url_encode(&signature))
        }

        fn grouped_request_jwt(
            &self,
            response_uri: &str,
            nonce: &str,
            state: &str,
            definition_id: &str,
            credential_type: &str,
        ) -> String {
            fn descriptor(id: &str, ty: &str, field: &str, group: &str) -> serde_json::Value {
                serde_json::json!({
                    "id": id,
                    "group": [group],
                    "constraints": {"fields": [
                        {"path": ["$.type"], "filter": {"type": "array", "contains": {"const": ty}}},
                        {"path": [format!("$.credentialSubject.{field}")]},
                    ]},
                })
            }
            let definition = serde_json::json!({
                "id": definition_id,
                "submission_requirements": [
                    {"name": "姓名", "rule": "pick", "from": "Group_1", "max": 1},
                    {"name": "末五碼", "rule": "pick", "from": "Group_2", "max": 1},
                ],
                "input_descriptors": [
                    descriptor("other-name", "other-carrier", "name", "Group_1"),
                    descriptor("twm-name", credential_type, "name", "Group_1"),
                    descriptor("other-last5", "other-carrier", "phonel5", "Group_2"),
                    descriptor("twm-last5", credential_type, "phonel5", "Group_2"),
                ],
            });
            let header = serde_json::json!({"kid": "verifier-did", "typ": "oauth-authz-req+jwt", "alg": "ES256"});
            let payload = serde_json::json!({
                "response_type": "vp_token",
                "response_mode": "direct_post",
                "response_uri": response_uri,
                "client_id": self.client_id(),
                "nonce": nonce,
                "state": state,
                "presentation_definition": definition,
            });
            let h = base64url_encode(&json_bytes(&header));
            let p = base64url_encode(&json_bytes(&payload));
            let signature = sign_raw(&self.private_key, format!("{h}.{p}").as_bytes());
            format!("{h}.{p}.{}", base64url_encode(&signature))
        }
    }

    fn trusted_host() -> HashSet<String> {
        ["verifier-oid4vp.wallet.gov.tw".to_string()]
            .into_iter()
            .collect()
    }

    const RESPONSE_URI: &str =
        "https://verifier-oid4vp.wallet.gov.tw/api/oidvp/authorization-response";

    fn make_request(
        verifier: &TestVerifier,
        signed_by: Option<&SigningKey>,
        response_uri: &str,
    ) -> String {
        verifier.request_jwt(
            response_uri,
            "NONCE-1",
            "STATE-1",
            "00000000_vpms_20250605",
            "00000000_vpms_20250605",
            "00000000_vpms_20250605",
            &["name", "company"],
            None,
            signed_by,
        )
    }

    #[test]
    fn a_verified_request_reduces_to_what_was_asked() {
        let verifier = TestVerifier::new();
        let jwt = make_request(&verifier, None, RESPONSE_URI);
        let request = Oid4VpRequest::verify(&jwt, &verifier.client_id(), &trusted_host()).unwrap();
        assert_eq!(request.nonce, "NONCE-1");
        assert_eq!(request.state, "STATE-1");
        assert_eq!(request.credential_type(), Some("00000000_vpms_20250605"));
        assert_eq!(request.response_uri, RESPONSE_URI);
        let claim_names: std::collections::HashSet<&str> = request
            .requested_fields()
            .iter()
            .filter_map(|f| f.claim_name())
            .collect();
        assert_eq!(
            claim_names,
            ["name", "company"]
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
        );
    }

    #[test]
    fn a_self_issued_request_keeps_its_moica_format_boundary() {
        let verifier = TestVerifier::new();
        let jwt = verifier.request_jwt(
            RESPONSE_URI,
            "N-MOICA",
            "S-MOICA",
            "bonds-vp",
            "cred",
            "NationalIDCredential",
            &["name", "birthdate"],
            Some(Oid4VpCredentialFormat::MOICA_KEY),
            None,
        );
        let request = Oid4VpRequest::verify(&jwt, &verifier.client_id(), &trusted_host()).unwrap();
        assert_eq!(
            request.input_descriptors[0].credential_format,
            Some(Oid4VpCredentialFormat::Moica)
        );
        assert_eq!(request.credential_type(), Some("NationalIDCredential"));
    }

    #[test]
    fn grouped_carrier_alternatives_keep_their_descriptor_boundaries() {
        let verifier = TestVerifier::new();
        let jwt =
            verifier.grouped_request_jwt(RESPONSE_URI, "N", "S", "22555003_711pickup", "twm-card");
        let request = Oid4VpRequest::verify(&jwt, &verifier.client_id(), &trusted_host()).unwrap();

        assert_eq!(
            request
                .input_descriptors
                .iter()
                .map(|d| d.id.as_str())
                .collect::<Vec<_>>(),
            vec!["other-name", "twm-name", "other-last5", "twm-last5"]
        );
        assert_eq!(
            request
                .submission_requirements
                .iter()
                .map(|r| r.from.as_str())
                .collect::<Vec<_>>(),
            vec!["Group_1", "Group_2"]
        );
        assert_eq!(
            request
                .submission_requirements
                .iter()
                .map(|r| r.max)
                .collect::<Vec<_>>(),
            vec![Some(1), Some(1)]
        );
        assert_eq!(
            request
                .requested_fields()
                .iter()
                .filter_map(|f| f.claim_name())
                .collect::<Vec<_>>(),
            vec!["name", "phonel5"]
        );
    }

    #[test]
    fn a_request_signed_by_another_key_is_refused() {
        let verifier = TestVerifier::new();
        let stranger = SigningKey::random(&mut OsRng);
        let forged = make_request(&verifier, Some(&stranger), RESPONSE_URI);
        assert_eq!(
            Oid4VpRequest::verify(&forged, &verifier.client_id(), &trusted_host()),
            Err(Oid4VpRequestError::SignatureInvalid)
        );
    }

    #[test]
    fn a_response_uri_off_the_trusted_hosts_is_refused() {
        let verifier = TestVerifier::new();
        let evil = "https://verifier-oid4vp.wallet.gov.tw.evil.tw/api/oidvp/authorization-response";
        let jwt = make_request(&verifier, None, evil);
        assert_eq!(
            Oid4VpRequest::verify(&jwt, &verifier.client_id(), &trusted_host()),
            Err(Oid4VpRequestError::ResponseUriNotTrusted {
                host: "verifier-oid4vp.wallet.gov.tw.evil.tw".to_string()
            })
        );
    }

    #[test]
    fn the_official_authorize_scheme_is_parsed() {
        let link = Oid4VpAuthorizeLink::parse(
            "modadigitalwallet://authorize?client_id=did:key:zABC&request_uri=https%3A%2F%2Fverifier-oid4vp.wallet.gov.tw%2Fapi%2Foidvp%2Frequest%2Fx",
        )
        .unwrap();
        assert_eq!(
            link,
            Oid4VpAuthorizeLink::ByReference {
                client_id: "did:key:zABC".to_string(),
                request_uri: "https://verifier-oid4vp.wallet.gov.tw/api/oidvp/request/x"
                    .to_string(),
            }
        );
    }

    #[test]
    fn the_openid4vp_scheme_by_value_is_parsed() {
        let link = Oid4VpAuthorizeLink::parse(
            "openid4vp://?client_id=did:key:zABC&request=eyJhbGciOiJFUzI1NiJ9",
        )
        .unwrap();
        assert_eq!(
            link,
            Oid4VpAuthorizeLink::ByValue {
                client_id: "did:key:zABC".to_string(),
                request_object: "eyJhbGciOiJFUzI1NiJ9".to_string(),
            }
        );
    }

    #[test]
    fn strips_carriage_return_and_newline_framing() {
        let link = Oid4VpAuthorizeLink::parse(
            "modadigitalwallet://authorize?\r\nclient_id=did:key:zABC&request_uri=https%3A%2F%2Fx%2Fy\n",
        )
        .unwrap();
        assert_eq!(
            link,
            Oid4VpAuthorizeLink::ByReference {
                client_id: "did:key:zABC".to_string(),
                request_uri: "https://x/y".to_string(),
            }
        );
    }

    #[test]
    fn rejects_a_wrong_scheme() {
        assert_eq!(
            Oid4VpAuthorizeLink::parse("https://example.com/authorize?client_id=x&request_uri=y"),
            Err(Oid4VpRequestError::NotAnAuthorizeLink)
        );
    }

    #[test]
    fn rejects_a_missing_client_id() {
        assert_eq!(
            Oid4VpAuthorizeLink::parse("modadigitalwallet://authorize?request_uri=https%3A%2F%2Fx"),
            Err(Oid4VpRequestError::NotAnAuthorizeLink)
        );
    }

    #[test]
    fn rejects_neither_request_uri_nor_request() {
        assert_eq!(
            Oid4VpAuthorizeLink::parse("modadigitalwallet://authorize?client_id=did:key:zABC"),
            Err(Oid4VpRequestError::NotAnAuthorizeLink)
        );
    }
}
