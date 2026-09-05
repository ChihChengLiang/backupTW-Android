//! Independent on-chain verification of a trust-list issuer entry.
//!
//! Ported from `backupTW-iOS/backupTW/TWDIW/TWDIWOnChainVerifier.swift`.
//! Scoped to the pure half only: ABI encoding/decoding of the registry
//! contract's calldata and return data, and the `check` that turns a
//! fetched Arbitrum record into a `TwdiwOnChainVerification`. The actual
//! JSON-RPC call - batching `eth_getTransactionByHash`/
//! `eth_getTransactionReceipt`/`eth_call`, POSTing it, and reading back
//! each call's `result`/`error` - is network I/O and stays native by
//! design (`docs/2026-09-05-decisions-and-roadmap.md`). A caller: builds
//! the batch using [`current_record_call_data`] for the `eth_call` leg,
//! sends it, then hands the raw `result` values of each reply straight to
//! [`check`] (via [`decode_current_record`] for the `eth_call` leg).
//!
//! **A historical transaction alone is not enough.** An API replay could
//! present a record that was later replaced or revoked, so `check`
//! requires the registry's *current* state (queried live, in the same
//! attempt) to agree with the API's claim too - not just the transaction
//! that originally wrote it.

use crate::twdiw::issuer_authorization::{
    TwdiwIssuer, TwdiwOnChainRecord, TwdiwOnChainVerification,
};

pub const NETWORK: &str = "arbitrum";
pub const REGISTRY_CONTRACT: &str = "0x84172caf8dd126c76f1fa8a2733ca3233264d31f";
/// `registerOrg(...)`-family selector, derived from the deployed contract.
pub const METHOD_SELECTOR: &str = "f6e0d282";
/// `getDocById(bytes)`, derived from the deployed contract selector and
/// checked against the live return shape on 2026-08-31.
pub const CURRENT_RECORD_SELECTOR: &str = "fba6fe49";
pub const RPC_URL: &str = "https://arb1.arbitrum.io/rpc";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryInput {
    pub did: String,
    pub signed_did_document: String,
    pub organisation_json: String,
    pub org_type: i64,
    pub org_group: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentRegistryRecord {
    pub signed_did_document: String,
    pub organisation_json: String,
    pub org_type: i64,
    pub org_group: i64,
    pub revoked: bool,
}

/// ABI-decodes the production registry method. It has six 32-byte head
/// words; the first three are offsets to strings and the next two are the
/// category values this check compares. The final word is not needed.
pub fn decode_registry_input(value: &str) -> Option<RegistryInput> {
    let hex = strip_0x(value);
    if hex.len() < 8 || !hex[..8].eq_ignore_ascii_case(METHOD_SELECTOR) {
        return None;
    }
    let bytes = data_from_hex(&hex[8..])?;
    if bytes.len() < 192 {
        return None;
    }
    let did = abi_string(&bytes, 0, 0, 6)?;
    let signed_did_document = abi_string(&bytes, 1, 0, 6)?;
    let organisation_json = abi_string(&bytes, 2, 0, 6)?;
    let org_type = abi_integer(&bytes, 3, 0)?;
    let org_group = abi_integer(&bytes, 4, 0)?;
    Some(RegistryInput {
        did,
        signed_did_document,
        organisation_json,
        org_type,
        org_group,
    })
}

/// ABI-encodes `getDocById(bytes)` for a current-state lookup. The DID is
/// bounded before allocation because every byte came from the network.
pub fn current_record_call_data(did: &str) -> Option<String> {
    let value = did.as_bytes();
    if value.is_empty() || value.len() > 4_096 {
        return None;
    }
    let mut encoded = abi_word(32)?;
    encoded.extend(abi_word(value.len() as i64)?);
    encoded.extend_from_slice(value);
    let padding = (32 - value.len() % 32) % 32;
    encoded.extend(std::iter::repeat_n(0u8, padding));
    Some(format!(
        "0x{CURRENT_RECORD_SELECTOR}{}",
        hex_encode(&encoded)
    ))
}

/// Decodes the live contract's current record return:
/// `(signedDIDDocument, organisationJSON, orgType, orgGroup, revoked)`.
pub fn decode_current_record(value: &str) -> Option<CurrentRegistryRecord> {
    let hex = strip_0x(value);
    let bytes = data_from_hex(hex)?;
    if bytes.len() < 32 {
        return None;
    }
    let base = abi_integer(&bytes, 0, 0)?;
    if base < 32 || base > bytes.len() as i64 - 160 {
        return None;
    }
    let base = base as usize;
    let signed_did_document = abi_string(&bytes, 0, base, 5)?;
    let organisation_json = abi_string(&bytes, 1, base, 5)?;
    let org_type = abi_integer(&bytes, 2, base)?;
    let org_group = abi_integer(&bytes, 3, base)?;
    let revoked_value = abi_integer(&bytes, 4, base)?;
    if revoked_value != 0 && revoked_value != 1 {
        return None;
    }
    Some(CurrentRegistryRecord {
        signed_did_document,
        organisation_json,
        org_type,
        org_group,
        revoked: revoked_value == 1,
    })
}

/// JSON-RPC infrastructure errors mean the independent source could not be
/// checked and must be shown as unavailable. A contract execution revert
/// is different: Arbitrum answered, but the claimed current record does
/// not exist, so the caller records a mismatch through the nil decoded
/// value rather than through this.
pub fn is_infrastructure_error(reply: &serde_json::Value) -> bool {
    let Some(error) = reply.get("error").and_then(|e| e.as_object()) else {
        return false;
    };
    let message = error
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_lowercase();
    !message.contains("execution reverted")
}

/// Checks that the successful Arbitrum transaction named by the API
/// actually wrote the same DID, signed DID document, organisation object
/// and category values, *and* that the registry's current state still
/// agrees. `transaction`/`receipt` are the raw `result` objects of
/// `eth_getTransactionByHash`/`eth_getTransactionReceipt`.
pub fn check(
    issuer: &TwdiwIssuer,
    record: &TwdiwOnChainRecord,
    transaction: Option<&serde_json::Value>,
    receipt: Option<&serde_json::Value>,
    current: Option<&CurrentRegistryRecord>,
) -> TwdiwOnChainVerification {
    let outcome = (|| -> Option<TwdiwOnChainVerification> {
        if record.network.to_lowercase() != NETWORK
            || record.contract_address.to_lowercase() != REGISTRY_CONTRACT
            || record.status != 1
        {
            return None;
        }
        let transaction = transaction?.as_object()?;
        let receipt = receipt?.as_object()?;
        let hash = transaction.get("hash")?.as_str()?;
        if hash.to_lowercase() != record.transaction_hash.to_lowercase() {
            return None;
        }
        let to = transaction.get("to")?.as_str()?;
        if to.to_lowercase() != REGISTRY_CONTRACT {
            return None;
        }
        if receipt.get("status")?.as_str()? != "0x1" {
            return None;
        }
        let input = transaction.get("input")?.as_str()?;
        let decoded = decode_registry_input(input)?;
        if decoded.did != issuer.did
            || decoded.signed_did_document != issuer.signed_did_document
            || decoded.org_type != issuer.org_type
            || decoded.org_group != issuer.org_group
            || !json_objects_equal(&decoded.organisation_json, &issuer.organisation_json)
        {
            return None;
        }
        let current = current?;
        if current.signed_did_document != issuer.signed_did_document
            || current.org_type != issuer.org_type
            || current.org_group != issuer.org_group
            || current.revoked
            || !json_objects_equal(&current.organisation_json, &issuer.organisation_json)
        {
            return None;
        }
        let block_number = transaction.get("blockNumber")?.as_str()?.to_owned();
        Some(TwdiwOnChainVerification::Verified {
            block_number,
            transaction_hash: record.transaction_hash.clone(),
        })
    })();
    outcome.unwrap_or(TwdiwOnChainVerification::Mismatch)
}

fn json_objects_equal(lhs: &str, rhs: &str) -> bool {
    let (Ok(left), Ok(right)) = (
        serde_json::from_str::<serde_json::Value>(lhs),
        serde_json::from_str::<serde_json::Value>(rhs),
    ) else {
        return false;
    };
    left == right
}

fn abi_string(
    data: &[u8],
    head_word: usize,
    base: usize,
    head_word_count: usize,
) -> Option<String> {
    let offset = abi_integer(data, head_word, base)?;
    if offset < (head_word_count * 32) as i64 || offset % 32 != 0 {
        return None;
    }
    let offset = offset as usize;
    if base > data.len().checked_sub(offset)?.checked_sub(32)? {
        return None;
    }
    let start = base + offset;
    let length = integer(data.get(start..start + 32)?)?;
    if length < 0 || length as usize > data.len() - start - 32 {
        return None;
    }
    let length = length as usize;
    String::from_utf8(data.get(start + 32..start + 32 + length)?.to_vec()).ok()
}

fn abi_integer(data: &[u8], word: usize, base: usize) -> Option<i64> {
    let start = base + word * 32;
    if start + 32 > data.len() {
        return None;
    }
    integer(&data[start..start + 32])
}

fn abi_word(value: i64) -> Option<Vec<u8>> {
    if value < 0 {
        return None;
    }
    let mut bytes = vec![0u8; 32];
    bytes[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    Some(bytes)
}

fn integer(bytes: &[u8]) -> Option<i64> {
    if bytes.len() != 32 || bytes[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut value: i64 = 0;
    for &byte in &bytes[24..] {
        value = value.checked_mul(256)?.checked_add(byte as i64)?;
    }
    Some(value)
}

fn strip_0x(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

fn data_from_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<char> = value.chars().collect();
    for pair in chars.chunks(2) {
        let byte_str: String = pair.iter().collect();
        bytes.push(u8::from_str_radix(&byte_str, 16).ok()?);
    }
    Some(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(value: i64) -> Vec<u8> {
        abi_word(value).unwrap()
    }

    fn input(strings: &[&str], org_type: i64, org_group: i64) -> String {
        let mut tail: Vec<u8> = Vec::new();
        let mut offsets: Vec<i64> = Vec::new();
        for s in strings {
            offsets.push(32 * 6 + tail.len() as i64);
            let value = s.as_bytes();
            tail.extend(word(value.len() as i64));
            tail.extend_from_slice(value);
            let padding = (32 - value.len() % 32) % 32;
            tail.extend(std::iter::repeat_n(0u8, padding));
        }
        let mut data = Vec::new();
        for offset in offsets {
            data.extend(word(offset));
        }
        data.extend(word(org_type));
        data.extend(word(org_group));
        data.extend(word(0));
        data.extend(tail);
        format!("0x{METHOD_SELECTOR}{}", hex_encode(&data))
    }

    fn current_result(
        signed: &str,
        organisation: &str,
        org_type: i64,
        org_group: i64,
        revoked: bool,
    ) -> String {
        let values: [&[u8]; 2] = [signed.as_bytes(), organisation.as_bytes()];
        let mut tail: Vec<u8> = Vec::new();
        let mut offsets: Vec<i64> = Vec::new();
        for value in values {
            offsets.push(32 * 5 + tail.len() as i64);
            tail.extend(word(value.len() as i64));
            tail.extend_from_slice(value);
            tail.extend(std::iter::repeat_n(0u8, (32 - value.len() % 32) % 32));
        }
        let mut tuple = Vec::new();
        for offset in offsets {
            tuple.extend(word(offset));
        }
        tuple.extend(word(org_type));
        tuple.extend(word(org_group));
        tuple.extend(word(if revoked { 1 } else { 0 }));
        tuple.extend(tail);
        let mut outer = word(32);
        outer.extend(tuple);
        format!("0x{}", hex_encode(&outer))
    }

    fn sample_issuer() -> TwdiwIssuer {
        TwdiwIssuer {
            did: "did:key:zA".to_string(),
            display_name: "測試單位".to_string(),
            display_name_english: "Test".to_string(),
            tax_id: "12345678".to_string(),
            issuer_metadata_base_url: Some("https://issuer.example".to_string()),
            service_base_url: None,
            reports_on_chain_anchor: true,
            signed_did_document: "signed-document".to_string(),
            organisation_json: r#"{"name":"測試單位"}"#.to_string(),
            org_type: 1,
            org_group: 2,
            api_updated_at: None,
            on_chain_records: vec![sample_record()],
        }
    }

    fn sample_record() -> TwdiwOnChainRecord {
        TwdiwOnChainRecord {
            network: NETWORK.to_string(),
            contract_address: REGISTRY_CONTRACT.to_string(),
            transaction_hash: "0xabc".to_string(),
            status: 1,
            created_at: None,
        }
    }

    #[test]
    fn registry_input_round_trips_the_three_records_and_categories() {
        let raw = input(
            &[
                "did:key:zA",
                "signed.did.document",
                r#"{"name":"測試單位"}"#,
            ],
            1,
            2,
        );
        let decoded = decode_registry_input(&raw).unwrap();
        assert_eq!(decoded.did, "did:key:zA");
        assert_eq!(decoded.signed_did_document, "signed.did.document");
        assert_eq!(decoded.organisation_json, r#"{"name":"測試單位"}"#);
        assert_eq!(decoded.org_type, 1);
        assert_eq!(decoded.org_group, 2);
    }

    #[test]
    fn a_different_method_selector_is_refused() {
        let raw = input(&["a", "b", "{}"], 1, 1);
        let tampered = format!("0x00000000{}", &raw[10..]);
        assert_eq!(decode_registry_input(&tampered), None);
    }

    #[test]
    fn current_record_call_uses_the_deployed_getter_and_bounds_the_did() {
        let call = current_record_call_data("did:key:zA").unwrap();
        assert!(call.starts_with(&format!("0x{CURRENT_RECORD_SELECTOR}")));
        assert!(call.contains(&hex_encode("did:key:zA".as_bytes())));
        assert_eq!(current_record_call_data(""), None);
        assert_eq!(current_record_call_data(&"a".repeat(4_097)), None);
    }

    #[test]
    fn current_record_return_decodes_all_fields_and_revocation() {
        let raw = current_result("signed-document", r#"{"name":"測試單位"}"#, 1, 2, true);
        let decoded = decode_current_record(&raw).unwrap();
        assert_eq!(decoded.signed_did_document, "signed-document");
        assert_eq!(decoded.organisation_json, r#"{"name":"測試單位"}"#);
        assert_eq!(decoded.org_type, 1);
        assert_eq!(decoded.org_group, 2);
        assert!(decoded.revoked);
    }

    #[test]
    fn historical_transaction_cannot_hide_a_changed_or_revoked_current_record() {
        let issuer = sample_issuer();
        let record = sample_record();
        let transaction = serde_json::json!({
            "hash": "0xabc",
            "to": REGISTRY_CONTRACT,
            "input": input(&["did:key:zA", "signed-document", r#"{"name":"測試單位"}"#], 1, 2),
            "blockNumber": "0x42",
        });
        let receipt = serde_json::json!({ "status": "0x1" });

        let current = CurrentRegistryRecord {
            signed_did_document: "signed-document".to_string(),
            organisation_json: r#"{"name":"測試單位"}"#.to_string(),
            org_type: 1,
            org_group: 2,
            revoked: false,
        };
        assert_eq!(
            check(
                &issuer,
                &record,
                Some(&transaction),
                Some(&receipt),
                Some(&current)
            ),
            TwdiwOnChainVerification::Verified {
                block_number: "0x42".to_string(),
                transaction_hash: "0xabc".to_string(),
            }
        );

        let replaced = CurrentRegistryRecord {
            signed_did_document: "newer-document".to_string(),
            ..current.clone()
        };
        assert_eq!(
            check(
                &issuer,
                &record,
                Some(&transaction),
                Some(&receipt),
                Some(&replaced)
            ),
            TwdiwOnChainVerification::Mismatch
        );

        let revoked = CurrentRegistryRecord {
            revoked: true,
            ..current
        };
        assert_eq!(
            check(
                &issuer,
                &record,
                Some(&transaction),
                Some(&receipt),
                Some(&revoked)
            ),
            TwdiwOnChainVerification::Mismatch
        );
    }

    #[test]
    fn missing_current_record_is_a_mismatch_not_a_verified_result() {
        let issuer = sample_issuer();
        let record = sample_record();
        let transaction = serde_json::json!({
            "hash": "0xabc",
            "to": REGISTRY_CONTRACT,
            "input": input(&["did:key:zA", "signed-document", r#"{"name":"測試單位"}"#], 1, 2),
            "blockNumber": "0x42",
        });
        let receipt = serde_json::json!({ "status": "0x1" });
        assert_eq!(
            check(&issuer, &record, Some(&transaction), Some(&receipt), None),
            TwdiwOnChainVerification::Mismatch
        );
    }

    #[test]
    fn an_rpc_infrastructure_error_is_reported_but_an_execution_revert_is_not() {
        let infra =
            serde_json::json!({ "error": { "code": -32000, "message": "upstream unavailable" } });
        assert!(is_infrastructure_error(&infra));

        let revert = serde_json::json!({ "error": { "code": 3, "message": "execution reverted" } });
        assert!(!is_infrastructure_error(&revert));

        let ok = serde_json::json!({ "result": "0x" });
        assert!(!is_infrastructure_error(&ok));
    }
}
