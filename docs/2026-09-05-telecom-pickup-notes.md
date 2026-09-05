# Telecom credential convenience-store pickup — field notes (2026-09-05)

Summarized from an external field report on the 7-Eleven convenience-
store pickup feature, shared by the iOS developer. Original:
[pro.mashbean.net/reports/2026-09-02-telecom-credential-convenience-store-pickup](https://pro.mashbean.net/reports/2026-09-02-telecom-credential-convenience-store-pickup/),
sourced from [backupTW-iOS PR #56](https://github.com/bonds-tw/backupTW-iOS/pull/56),
[moda-gov-tw/TWDIW-official-app](https://github.com/moda-gov-tw/TWDIW-official-app),
and its [QR verification spec](https://github.com/moda-gov-tw/TWDIW-official-app/blob/main/Docs/QR%20Code%20%E9%A9%97%E8%AD%89%E8%A6%8F%E6%A0%BC%E8%AA%AA%E6%98%8E%E6%96%87%E4%BB%B6.md).

Feature: present a telecom credential (e.g. a mobile phone card) via
OpenID4VP, receive a short-lived encrypted QR code, and complete
package pickup at a convenience-store POS terminal **with no network
connectivity at the POS**. This is a Phase 5 feature area (see
`docs/2026-09-05-decisions-and-roadmap.md`).

## Three-layer verification model

1. **OpenID4VP layer** — wallet validates the telecom credential,
   selectively discloses name + last 5 phone digits.
2. **Offline QR layer** — a government module encrypts the necessary
   fields into the QR; the POS decrypts locally, no network round trip.
3. **Business layer** — the logistics system matches the package and
   prevents duplicate pickup.

## Protocol flow (7 steps)

1. Query the official VP service directory; find the
   `22555003_711pickup` verifier module URL.
2. Create a transaction with that module → get `transactionId` +
   authorization deep link.
3. Fetch the signed OpenID4VP request; validate `nonce`, `state`,
   request host, response host, and required fields.
4. User confirms disclosure of name + phone; build the VP with the
   telecom card credential.
5. POST the VP to the verifier; keep `holder_key` and the transaction
   receipt.
6. Sign an ES256 JWT with the same holder key over `transactionId`;
   request the QR from the verifier module.
7. Validate the PNG response (file size ≤5 MB, non-negative expiry),
   display it.

Service discovery endpoint:
```
GET https://frontend.wallet.gov.tw/api/moda/dwapp/offline/vpList?name=&page=0&size=100
```

## QR code structure

| Field | Content | Purpose |
|---|---|---|
| `t` | Transaction type (e.g. `"pickup"`) | Scenario identification |
| `d` | Base64 ChaCha20-Poly1305 ciphertext | TOTP + disclosed fields |
| `h` | HMAC of decrypted plaintext | Integrity + key possession |
| `k` | Key identifier | Selects which verification key |

Offline verification at the POS: three keys (`privateKey`, `totpKey`,
`hmacKey`), X25519/ECDH key derivation, ChaCha20-Poly1305 decryption,
then TOTP + HMAC validation — all without network.

## Timing — the one thing to get right on Android

- UI countdown shown to the user: 5 minutes (300s).
- TOTP validity: 60 seconds, ±30s clock tolerance.
- The source report explicitly flags a gap: it's undocumented whether
  the POS validates on a 60s or 300s cycle, or whether the QR
  auto-rotates. Treat this as unresolved, not assumed.

**Implementation rule**: compute an absolute deadline
(`generatedAt + lifetime`) and derive remaining time from wall clock
on every recompute — never decrement a counter. A decrementing counter
does not survive backgrounding (e.g. a biometric prompt interrupting
the flow) the way an absolute deadline does. This applies directly to
Android process/lifecycle suspension, same risk as iOS backgrounding.

## Security posture to carry over

- **Fail closed on host/definition mismatches.** Request URI and
  response URI must resolve to the same host as the service directory
  entry; `definitionID` must match the pickup scenario; disclosed
  fields must be exactly `name` + `phonel5`. Any mismatch halts
  immediately — no partial/degraded flow.
- **Service-directory listing ≠ trust.** Being discoverable in the
  official directory only proves discoverability. Independently verify
  verifier host, trust list membership, on-chain record, definition
  ID, and response URI — don't shortcut to "it's in the directory."
- **Treat every external response as untrusted**: validate HTTP
  status, structure, and (for the QR) PNG magic bytes, size, and
  expiry before rendering.
- **Logging discipline**: never log the QR, transaction ID, name,
  phone, or decrypted plaintext. Diagnostics should carry only stage,
  timestamp, error type, and build info. This constraint applies to
  automated tests and performance monitoring too, not just production
  logging paths.
- POS key lifecycle (generation/distribution/rotation/revocation) is
  entirely server-/retail-partner-side — the Android app holds none of
  those keys and has no lever over their governance, but interop
  depends on it, so it's worth knowing this is out of the app's control
  if pickup ever fails for a whole store chain at once.

## Format version risk (same caveat as the TWDIW protocol notes)

This flow was built against DIF Presentation Exchange
(`presentation_definition`/`presentation_submission`) and bare
`did:key` client IDs — **not** OpenID4VP 1.0 Final's DCQL model and
`decentralized_identifier` client-id prefix. Build with a
capability-negotiation seam; don't hardcode the pre-Final shapes into
the shared Rust core.

## Test matrix to carry into Android's test suite

Protocol/timing:
- Baseline successful pickup.
- QR expiry at the 60s boundary and at the 300s boundary (both, since
  which one the POS actually enforces is unconfirmed).
- Replay-attack prevention; clock-skew handling (±30s); duplicate
  pickup rejection; cross-telecom-provider credentials; cross-chain
  (Family Mart, Hi-Life) compatibility.

Device conditions (translate directly to Android equivalents):
- Low battery / no-power at the POS.
- Network interruption mid-transaction.
- Screen reactivation after a biometric prompt (Face ID → BiometricPrompt).
- Manual retry after a failed scan.
- Different POS hardware vendors.
- Accessibility: screen readers, high contrast.

## What's still missing (per the source report)

- A formal TWDIW pickup profile: service directory contract, deep
  link shape, exact OpenID4VP version, field names, QR schema, error
  codes — currently reverse-engineered, not documented.
- Clear boundary between TOTP/HMAC freshness (crypto-layer) and
  business-layer duplicate-pickup prevention — these are two different
  mechanisms and the report notes their responsibilities aren't
  clearly separated in the current design.
- A conformance test suite covering error cases, offline operation,
  and third-party wallet scenarios specifically (as opposed to just
  the official app's happy path).

Where this belongs in the roadmap: the protocol/crypto logic (steps
1–6, QR field parsing, deadline computation) belongs in the shared
Rust core per `docs/2026-09-05-decisions-and-roadmap.md`; only the
UI/camera/QR-rendering surface is Android-native.
