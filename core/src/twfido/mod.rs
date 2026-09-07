//! TW FidO (內政部行動自然人憑證): the SP API that gets a citizen-certificate
//! signature over a credential's TBS, feeding `moica::MoicaSignedCredential`.
//!
//! Ported from `backupTW-iOS/backupTW/TWFidO/{TWFidOClient,SPChecksum}.swift`,
//! scoped to what QR-code mode needs (see
//! `docs/2026-09-05-moica-integration-plan.md`): app-to-app ticket
//! issuance (ATH-01) and result polling (ATH-02). The actual HTTP POST
//! and QR rendering stay native by design
//! (`docs/2026-09-05-decisions-and-roadmap.md`); this crate builds
//! request bodies, the deep link to encode as a QR, and interprets
//! response bytes.

pub mod checksum;
pub mod client;

pub use checksum::ChecksumError;
pub use client::{
    app_to_app_checksum_payload, app_to_app_request_body, deep_link, is_pending,
    is_transient_client_error, parse_result_response, parse_ticket, parse_ticket_response,
    result_checksum_payload, result_request_body, sign_data, validate_time_limit, ClientError,
    SignResult, SigningTarget, Ticket, ALLOWED_TIME_LIMITS,
};
