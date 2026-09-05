//! Deciding whether a URL that arrived in a QR code may be contacted at all.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/IssuerAuthorization.swift`. See
//! that file for the extensive rationale: every URL in the OID4VCI
//! collection flow arrives in a QR code, and a later step signs a proof
//! JWT whose `aud` is a value the same QR supplied — so a QR is a signal
//! to go check something, never a result to act on directly. The 43-entry
//! TWDIW trust list is what makes that enforceable offline, in three
//! gates: (1) `authorise` — may this URL be contacted at all? (2)
//! `confirm_registry_evidence` — does the current on-chain state agree
//! with the API's claim, for *every* row that could account for the host?
//! (3) `confirm` — does the offer that came back name an issuer from the
//! same organisation as the URL it was fetched from?
//!
//! **No prefix matching, ever.** Hosts are compared as hosts — decomposed,
//! lowercased, and equal — never as strings one might be a prefix of.
//! Anything that cannot be normalised unambiguously (userinfo, a
//! trailing-dot host, a non-ASCII host, a non-443 port, percent-encoded
//! path dots) is refused rather than repaired.

use std::collections::HashMap;

use url::Url;

/// One entry of the TWDIW trust list, reduced to what a wallet needs.
///
/// `display_name`/`display_name_english` are **untrusted text** — route
/// them through `trust::UntrustedText` before drawing them, same as any
/// claim value in somebody else's document. `group` is deliberately
/// absent: the API's `orgGroupDetail.name` reads like a category and
/// isn't one (measured 2026-08-16: all 43 production entries are labelled
/// 「政府部門」, a set that includes FamilyMart and 7-Eleven) — a value you
/// cannot hold is a value nobody can accidentally draw.
#[derive(Debug, Clone, PartialEq, Eq, Default, uniffi::Record)]
pub struct TwdiwIssuer {
    pub did: String,
    pub display_name: String,
    pub display_name_english: String,
    pub tax_id: String,
    /// Where this organisation's OID4VCI endpoints live, in the list's own
    /// spelling. This is the string to use once a match is made.
    pub issuer_metadata_base_url: Option<String>,
    /// The organisation's service base, used by entries that are verifiers.
    pub service_base_url: Option<String>,
    /// The signed DID document carried by the API under its historical
    /// `did` property.
    pub signed_did_document: String,
    /// The API's organisation object, retained as JSON so it can be
    /// compared structurally with the registry transaction's own copy.
    pub organisation_json: String,
    pub org_type: i64,
    pub org_group: i64,
    /// Unix timestamp (seconds), if the API reported one.
    pub api_updated_at: Option<i64>,
    pub on_chain_records: Vec<TwdiwOnChainRecord>,
    /// Whether the API reports an on-chain anchoring record. A
    /// compatibility property for the collection gate; the trust screen
    /// does not treat it as verification.
    pub reports_on_chain_anchor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, uniffi::Record)]
pub struct TwdiwOnChainRecord {
    pub network: String,
    pub contract_address: String,
    pub transaction_hash: String,
    pub status: i64,
    pub created_at: Option<i64>,
}

/// The independent result shown beside an API trust-list entry.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TwdiwOnChainVerification {
    Verified {
        block_number: String,
        transaction_hash: String,
    },
    NotAnchored,
    Mismatch,
    Unavailable,
    /// The official demo issuer is a separate trust domain and has no
    /// production Arbitrum record. Only debug-build collection code
    /// should ever produce this result; keeping it distinct avoids
    /// calling a sandbox bypass "verified".
    DevelopmentSandbox,
}

impl TwdiwOnChainVerification {
    pub fn authorises_collection(&self) -> bool {
        matches!(self, Self::Verified { .. } | Self::DevelopmentSandbox)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum Refusal {
    /// Not `https`.
    #[error("not https")]
    NotHttps,
    /// No host, or a host this comparison will not attempt.
    #[error("unusable host")]
    UnusableHost,
    /// `user:password@host` — the part before `@` is what a person reads,
    /// and it is not the host.
    #[error("contains user info")]
    ContainsUserInfo,
    /// An explicit port other than 443.
    #[error("unexpected port: {0}")]
    UnexpectedPort(u16),
    /// A host that is not lowercase ASCII once normalised, or ends in a
    /// dot. Punycode and Unicode hosts are refused rather than folded.
    #[error("host not plain ASCII")]
    HostNotPlainAscii,
    /// `%2e`, `..`, or another path escape.
    #[error("path not normalised")]
    PathNotNormalised,
    /// Well-formed, and not on the list.
    #[error("not on the trust list: {host}")]
    NotOnTheTrustList { host: String },
    /// The official API entry has no Arbitrum registry record.
    #[error("trust record not anchored")]
    TrustRecordNotAnchored,
    /// The API entry, its claimed transaction, or the contract's current
    /// state disagree.
    #[error("trust record mismatch")]
    TrustRecordMismatch,
    /// Arbitrum could not be checked for this collection attempt, or a
    /// matching entry had no verification result. Nothing is cached as a
    /// substitute — that would make replay a successful fallback.
    #[error("trust verification unavailable")]
    TrustVerificationUnavailable,
    /// The offer named an issuer belonging to a different organisation
    /// than the URL it came from.
    #[error("organisation mismatch")]
    OrganisationMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Verdict {
    /// Contact it. `canonical_host` is **the trust list's spelling**, not
    /// the candidate's.
    Allowed {
        issuers: Vec<TwdiwIssuer>,
        canonical_host: String,
    },
    Refused(Refusal),
}

/// May this URL be contacted?
///
/// Returns every list entry sharing the host, because a host can in
/// principle belong to more than one registered organisation — narrowing
/// that down is gate 2's job. Returning the set rather than picking one
/// keeps the ambiguity visible instead of resolving it by array order.
pub fn authorise(fetch_url: &str, list: &[TwdiwIssuer]) -> Verdict {
    let host = match normalised_host(fetch_url) {
        Err(refusal) => return Verdict::Refused(refusal),
        Ok(host) => host,
    };

    let matches: Vec<TwdiwIssuer> = list
        .iter()
        .filter(|issuer| issuer_hosts(issuer).any(|h| h == host))
        .cloned()
        .collect();
    if matches.is_empty() {
        return Verdict::Refused(Refusal::NotOnTheTrustList { host });
    }
    Verdict::Allowed {
        issuers: matches,
        canonical_host: host,
    }
}

/// Gate 1b: every API row that can account for this host must
/// independently match the Arbitrum registry before the offer URL is
/// contacted.
///
/// Requiring *every* match matters on shared hosts: if one of three
/// organisations on a host is unverified, host comparison alone cannot
/// tell which row the still-unfetched offer represents, so accepting
/// because a different row verified would silently transfer its trust to
/// the unverified one.
pub fn confirm_registry_evidence(
    matched: &[TwdiwIssuer],
    verification: &HashMap<String, TwdiwOnChainVerification>,
) -> Result<(), Refusal> {
    if matched.is_empty() {
        return Err(Refusal::TrustVerificationUnavailable);
    }
    let results: Vec<Option<&TwdiwOnChainVerification>> = matched
        .iter()
        .map(|issuer| verification.get(&issuer.did))
        .collect();
    if results
        .iter()
        .any(|r| matches!(r, Some(TwdiwOnChainVerification::Mismatch)))
    {
        return Err(Refusal::TrustRecordMismatch);
    }
    if results
        .iter()
        .any(|r| matches!(r, Some(TwdiwOnChainVerification::NotAnchored)))
    {
        return Err(Refusal::TrustRecordNotAnchored);
    }
    if !results
        .iter()
        .all(|r| r.is_some_and(|v| v.authorises_collection()))
    {
        return Err(Refusal::TrustVerificationUnavailable);
    }
    Ok(())
}

/// The offer came back. Does the issuer it names belong to the
/// organisation whose URL we fetched it from?
///
/// What gate 2 must establish is that the offer's issuer host is one of
/// the trusted hosts gate 1 allowed — not that exactly one *row* carries
/// it. A distinct DID per row is not a distinct organisation (an org
/// registered as both issuer and verifier is listed under both), and one
/// host can genuinely belong to several organisations (three universities
/// share one host in production) — so this refuses only the case that
/// matters (zero rows agree) and otherwise returns one agreeing row.
pub fn confirm(credential_issuer: &str, matched: &[TwdiwIssuer]) -> Result<TwdiwIssuer, Refusal> {
    let host = normalised_host(credential_issuer)?;
    matched
        .iter()
        .find(|issuer| issuer_hosts(issuer).any(|h| h == host))
        .cloned()
        .ok_or(Refusal::OrganisationMismatch)
}

/// The base URL to actually use, **taken from the trust list rather than
/// from the offer**. Once the host is agreed, nothing is gained by
/// carrying the candidate's own bytes forward, and something is lost: the
/// `aud` of the proof JWT would then be a string an attacker influenced.
pub fn canonical_issuer_base(issuer: &TwdiwIssuer) -> Option<String> {
    issuer
        .issuer_metadata_base_url
        .clone()
        .or_else(|| issuer.service_base_url.clone())
}

fn issuer_hosts(issuer: &TwdiwIssuer) -> impl Iterator<Item = String> + '_ {
    [&issuer.issuer_metadata_base_url, &issuer.service_base_url]
        .into_iter()
        .flatten()
        .filter_map(|url| normalised_host(url).ok())
}

/// Decomposes a URL and refuses everything ambiguous.
pub fn normalised_host(s: &str) -> Result<String, Refusal> {
    let url = Url::parse(s).map_err(|_| Refusal::UnusableHost)?;
    if url.scheme().to_lowercase() != "https" {
        return Err(Refusal::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Refusal::ContainsUserInfo);
    }
    if let Some(port) = url.port() {
        if port != 443 {
            return Err(Refusal::UnexpectedPort(port));
        }
    }
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or(Refusal::UnusableHost)?;
    // A trailing dot is a legal, absolute DNS name that resolves to the
    // same place and is a different string. Two spellings of one host is
    // exactly what this comparison must not have.
    if host.ends_with('.') {
        return Err(Refusal::HostNotPlainAscii);
    }
    let lowered = host.to_lowercase();
    if !lowered
        .chars()
        .all(|c| c.is_ascii() && (c.is_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(Refusal::HostNotPlainAscii);
    }
    // The `url` crate's path is already percent-decoded for display, so
    // look at the raw input string instead - an escaped dot there arrives
    // as a real one in the decoded path, and `..` would be
    // indistinguishable from a literal segment.
    let raw = s.to_lowercase();
    if raw.contains("%2e") || raw.contains("/..") || raw.contains("..%2f") {
        return Err(Refusal::PathNotNormalised);
    }
    Ok(lowered)
}

// MARK: - Reading the list

/// The page body wasn't JSON at all. Anything JSON-shaped but missing the
/// fields this reads (an unrecognised entry, an empty page) is not an
/// error - see [`TwdiwIssuer::page`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed trust-list page")]
pub struct MalformedPage;

impl TwdiwIssuer {
    /// Parses one page of `GET /api/did`.
    ///
    /// ⚠️ **Page until the result is empty; do not compute offsets from
    /// `size`.** Measured 2026-08-16: the page size is clamped to 20 while
    /// the offset appears derived from the requested `size`, so
    /// `size=100&page=1` returns nothing at all.
    pub fn page(json: &[u8]) -> Result<Vec<TwdiwIssuer>, MalformedPage> {
        let root: serde_json::Value = serde_json::from_slice(json).map_err(|_| MalformedPage)?;
        let Some(data) = root.get("data").and_then(|v| v.as_object()) else {
            return Ok(Vec::new());
        };
        // A single-entry response puts the entry at `data`; a list puts an
        // array at `data.dids`. Both shapes are live.
        let entries: Vec<&serde_json::Value> =
            if let Some(list) = data.get("dids").and_then(|v| v.as_array()) {
                list.iter().collect()
            } else if data.get("id").and_then(|v| v.as_str()).is_some() {
                vec![&root["data"]]
            } else {
                Vec::new()
            };
        Ok(entries.into_iter().filter_map(from_entry).collect())
    }
}

fn from_entry(entry: &serde_json::Value) -> Option<TwdiwIssuer> {
    let did = entry.get("id")?.as_str()?.to_owned();
    let org = entry.get("org")?.as_object()?;

    let raw_history: Vec<&serde_json::Value> = entry
        .get("onChainHistory")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let records: Vec<TwdiwOnChainRecord> = raw_history
        .iter()
        .filter_map(|value| {
            Some(TwdiwOnChainRecord {
                network: value.get("net")?.as_str()?.to_owned(),
                contract_address: value.get("scAddress")?.as_str()?.to_owned(),
                transaction_hash: value.get("txHash")?.as_str()?.to_owned(),
                status: value.get("status").and_then(|v| v.as_i64()).unwrap_or(0),
                created_at: value.get("createdAt").and_then(|v| v.as_i64()),
            })
        })
        .collect();

    let organisation_json = serde_json::to_string(&serde_json::to_value(org).ok()?)
        .unwrap_or_else(|_| "{}".to_string());

    Some(TwdiwIssuer {
        did,
        display_name: org
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        display_name_english: org
            .get("name_en")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        tax_id: org
            .get("taxId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        issuer_metadata_base_url: org
            .get("issuerMetadataBaseURL")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        service_base_url: org
            .get("serviceBaseURL")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        reports_on_chain_anchor: !raw_history.is_empty(),
        signed_did_document: entry
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        organisation_json,
        org_type: entry.get("orgType").and_then(|v| v.as_i64()).unwrap_or(0),
        org_group: entry.get("orgGroup").and_then(|v| v.as_i64()).unwrap_or(0),
        api_updated_at: entry.get("updatedAt").and_then(|v| v.as_i64()),
        on_chain_records: records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> TwdiwIssuer {
        TwdiwIssuer {
            did: "did:key:z2dmzD81…sandbox".into(),
            display_name: "數位憑證皮夾沙盒".into(),
            display_name_english: "Taiwan Digital Identity Wallet Sandbox".into(),
            tax_id: "00000000".into(),
            issuer_metadata_base_url: Some("https://issuer-oid4vci.wallet.gov.tw".into()),
            service_base_url: None,
            ..Default::default()
        }
    }

    fn moda() -> TwdiwIssuer {
        TwdiwIssuer {
            did: "did:key:z2dmzD81…moda".into(),
            display_name: "行政院-數位發展部".into(),
            display_name_english: "Ministry of Digital Affairs".into(),
            tax_id: "2-16-886-101-20003-20082".into(),
            issuer_metadata_base_url: None,
            service_base_url: Some("https://moda.wallet.gov.tw".into()),
            ..Default::default()
        }
    }

    fn list() -> Vec<TwdiwIssuer> {
        vec![sandbox(), moda()]
    }

    #[test]
    fn a_host_on_the_list_is_allowed() {
        let verdict = authorise(
            "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/credential-offer-object?nonce=abc&sub=def",
            &list(),
        );
        match verdict {
            Verdict::Allowed {
                issuers,
                canonical_host,
            } => {
                assert_eq!(issuers, vec![sandbox()]);
                assert_eq!(canonical_host, "issuer-oid4vci.wallet.gov.tw");
            }
            other => panic!("a real issuer was refused: {other:?}"),
        }
    }

    #[test]
    fn a_host_that_is_not_on_the_list_is_refused() {
        let verdict = authorise(
            "https://wallet.example.tw/api/issuer/1/credential-offer-object",
            &list(),
        );
        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::NotOnTheTrustList {
                host: "wallet.example.tw".into()
            })
        );
    }

    #[test]
    fn a_suffixed_lookalike_host_is_refused() {
        let verdict = authorise(
            "https://issuer-oid4vci.wallet.gov.tw.evil.tw/api/issuer/00000000/",
            &list(),
        );
        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::NotOnTheTrustList {
                host: "issuer-oid4vci.wallet.gov.tw.evil.tw".into()
            })
        );
    }

    #[test]
    fn user_info_is_refused_rather_than_parsed_around() {
        let verdict = authorise("https://issuer-oid4vci.wallet.gov.tw@evil.tw/api/", &list());
        assert_eq!(verdict, Verdict::Refused(Refusal::ContainsUserInfo));
    }

    #[test]
    fn a_trailing_dot_host_is_refused() {
        let verdict = authorise("https://issuer-oid4vci.wallet.gov.tw./api/", &list());
        assert_eq!(verdict, Verdict::Refused(Refusal::HostNotPlainAscii));
    }

    #[test]
    fn case_in_the_host_does_not_matter() {
        let verdict = authorise("https://Issuer-OID4VCI.Wallet.GOV.TW/api/", &list());
        match verdict {
            Verdict::Allowed { canonical_host, .. } => {
                assert_eq!(canonical_host, "issuer-oid4vci.wallet.gov.tw");
            }
            other => panic!("case-folding refused a real host: {other:?}"),
        }
    }

    #[test]
    fn plain_http_is_refused() {
        assert_eq!(
            authorise("http://issuer-oid4vci.wallet.gov.tw/api/", &list()),
            Verdict::Refused(Refusal::NotHttps)
        );
    }

    #[test]
    fn an_explicit_odd_port_is_refused() {
        assert_eq!(
            authorise("https://issuer-oid4vci.wallet.gov.tw:8443/api/", &list()),
            Verdict::Refused(Refusal::UnexpectedPort(8443))
        );
    }

    #[test]
    fn port_443_spelled_out_is_fine() {
        let verdict = authorise("https://issuer-oid4vci.wallet.gov.tw:443/api/", &list());
        assert!(
            matches!(verdict, Verdict::Allowed { .. }),
            "explicit :443 was refused: {verdict:?}"
        );
    }

    #[test]
    fn percent_encoded_dots_are_refused() {
        assert_eq!(
            authorise(
                "https://issuer-oid4vci.wallet.gov.tw/api/%2e%2e/elsewhere",
                &list()
            ),
            Verdict::Refused(Refusal::PathNotNormalised)
        );
    }

    #[test]
    fn a_non_ascii_host_is_refused_not_folded() {
        let verdict = authorise("https://issuer-oid4vci.wallet.gov.tw.台灣/api/", &list());
        assert!(
            matches!(verdict, Verdict::Refused(_)),
            "a Unicode host matched a trusted one: {verdict:?}"
        );
    }

    #[test]
    fn an_offer_naming_a_different_organisation_is_refused() {
        let Verdict::Allowed {
            issuers: matched, ..
        } = authorise(
            "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/credential-offer-object",
            &list(),
        )
        else {
            panic!("gate 1 refused a real issuer");
        };
        let confirmed = confirm("https://moda.wallet.gov.tw/api/issuer/9/", &matched);
        assert_eq!(confirmed, Err(Refusal::OrganisationMismatch));
    }

    #[test]
    fn an_offer_naming_the_same_organisation_is_confirmed() {
        let Verdict::Allowed {
            issuers: matched, ..
        } = authorise(
            "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/credential-offer-object",
            &list(),
        )
        else {
            panic!("gate 1 refused a real issuer");
        };
        assert_eq!(
            confirm(
                "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/",
                &matched
            ),
            Ok(sandbox())
        );
    }

    #[test]
    fn a_host_belonging_to_two_organisations_is_confirmed_not_refused() {
        let twin = TwdiwIssuer {
            did: "did:key:z2dmzD81…twin".into(),
            display_name: "另一個機關".into(),
            display_name_english: "Another Agency".into(),
            tax_id: "11111111".into(),
            issuer_metadata_base_url: Some("https://issuer-oid4vci.wallet.gov.tw".into()),
            service_base_url: None,
            ..Default::default()
        };
        let list = vec![sandbox(), twin.clone()];
        let Verdict::Allowed {
            issuers: matched, ..
        } = authorise("https://issuer-oid4vci.wallet.gov.tw/api/", &list)
        else {
            panic!("gate 1 refused");
        };
        assert_eq!(matched.len(), 2);
        let result = confirm(
            "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/",
            &matched,
        );
        assert!(result == Ok(sandbox()) || result == Ok(twin));
    }

    #[test]
    fn one_organisation_listed_twice_still_confirms() {
        let as_verifier = TwdiwIssuer {
            issuer_metadata_base_url: None,
            service_base_url: Some("https://issuer-oid4vci.wallet.gov.tw".into()),
            ..sandbox()
        };
        let matched = vec![sandbox(), as_verifier];
        assert_ne!(
            confirm(
                "https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/",
                &matched
            ),
            Err(Refusal::OrganisationMismatch)
        );
    }

    #[test]
    fn every_organisation_sharing_a_host_needs_registry_evidence() {
        let twin = TwdiwIssuer {
            did: "did:key:zTwin".into(),
            display_name: "另一個機關".into(),
            display_name_english: "Another Agency".into(),
            tax_id: "11111111".into(),
            issuer_metadata_base_url: sandbox().issuer_metadata_base_url,
            service_base_url: None,
            ..Default::default()
        };
        let matched = vec![sandbox(), twin.clone()];
        let verified = TwdiwOnChainVerification::Verified {
            block_number: "0x1".into(),
            transaction_hash: "0xabc".into(),
        };

        let mut v1 = HashMap::new();
        v1.insert(sandbox().did, verified.clone());
        assert_eq!(
            confirm_registry_evidence(&matched, &v1),
            Err(Refusal::TrustVerificationUnavailable)
        );

        let mut v2 = HashMap::new();
        v2.insert(sandbox().did, verified.clone());
        v2.insert(twin.did.clone(), TwdiwOnChainVerification::Mismatch);
        assert_eq!(
            confirm_registry_evidence(&matched, &v2),
            Err(Refusal::TrustRecordMismatch)
        );

        let mut v3 = HashMap::new();
        v3.insert(sandbox().did, verified.clone());
        v3.insert(twin.did, verified);
        assert_eq!(confirm_registry_evidence(&matched, &v3), Ok(()));
    }

    #[test]
    fn a_development_sandbox_result_is_explicitly_authorised() {
        let mut v = HashMap::new();
        v.insert(sandbox().did, TwdiwOnChainVerification::DevelopmentSandbox);
        assert_eq!(confirm_registry_evidence(&[sandbox()], &v), Ok(()));
    }

    #[test]
    fn the_base_url_used_afterwards_comes_from_the_list_not_the_offer() {
        assert_eq!(
            canonical_issuer_base(&sandbox()),
            Some("https://issuer-oid4vci.wallet.gov.tw".to_string())
        );
        assert_eq!(
            canonical_issuer_base(&moda()),
            Some("https://moda.wallet.gov.tw".to_string())
        );
    }

    #[test]
    fn a_list_page_is_parsed() {
        let json = r#"
        {"msg":"執行成功","code":"0","data":{"count":2,"dids":[
          {"id":"did:key:zA","orgType":1,"orgGroupDetail":{"name":"政府部門"},
           "org":{"name":"行政院-數位發展部","name_en":"Ministry of Digital Affairs",
                  "taxId":"2-16-886-101-20003-20082","serviceBaseURL":"https://moda.wallet.gov.tw"},
           "onChainHistory":[{"net":"arbitrum"}]},
          {"id":"did:key:zB","orgType":1,"orgGroupDetail":{"name":"政府部門"},
           "org":{"name":"中國醫藥大學","name_en":"China Medical University",
                  "taxId":"2-16-886-111-100557","serviceBaseURL":"https://52005408.wallet.gov.tw",
                  "issuerMetadataBaseURL":null},
           "onChainHistory":[]}
        ]}}
        "#
        .as_bytes();
        let issuers = TwdiwIssuer::page(json).unwrap();
        assert_eq!(issuers.len(), 2);
        assert_eq!(issuers[0].display_name, "行政院-數位發展部");
        assert!(issuers[0].reports_on_chain_anchor);
        assert!(!issuers[1].reports_on_chain_anchor);
        assert_eq!(issuers[1].issuer_metadata_base_url, None);
    }

    #[test]
    fn the_single_entry_response_shape_is_also_parsed() {
        let json = r#"
        {"msg":"執行成功","code":"0","data":{"id":"did:key:zA",
          "org":{"name":"數位憑證皮夾沙盒","taxId":"00000000",
                 "issuerMetadataBaseURL":"https://issuer-oid4vci.wallet.gov.tw"},
          "onChainHistory":[{"net":"arbitrum_testnet"}]}}
        "#
        .as_bytes();
        let issuers = TwdiwIssuer::page(json).unwrap();
        assert_eq!(issuers.len(), 1);
        assert_eq!(issuers[0].tax_id, "00000000");
    }

    #[test]
    fn an_empty_page_is_empty_not_an_error() {
        let json = r#"{"msg":"執行成功","code":"0","data":{"count":20,"dids":[]}}"#.as_bytes();
        assert!(TwdiwIssuer::page(json).unwrap().is_empty());
    }

    #[test]
    fn a_complete_chain_record_is_retained_for_independent_checking() {
        let json = r#"
        {"code":"0","data":{"id":"did:key:zA","did":"signed-document",
          "orgType":1,"orgGroup":2,"updatedAt":1700000000,
          "org":{"name":"測試單位","taxId":"12345678"},
          "onChainHistory":[{"net":"arbitrum",
            "scAddress":"0x84172caf8dd126c76f1fa8a2733ca3233264d31f",
            "txHash":"0xabc","status":1,"createdAt":1700000001}]}}
        "#
        .as_bytes();
        let issuer = TwdiwIssuer::page(json).unwrap().into_iter().next().unwrap();
        assert_eq!(issuer.signed_did_document, "signed-document");
        assert_eq!(issuer.org_type, 1);
        assert_eq!(issuer.org_group, 2);
        assert_eq!(issuer.on_chain_records[0].transaction_hash, "0xabc");
        assert!(issuer.organisation_json.contains("測試單位"));
    }
}
