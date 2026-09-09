# backupTW-Android (有備而來)

A Rust + Android rewrite of [backupTW-iOS](https://github.com/bonds-tw/backupTW-iOS),
Taiwan's `TWDIW`/citizen-credential digital wallet. **Active
development, not released.**

It's a rewrite, not a straight port: ~55K lines of pure UIKit Swift
share no UI code with Android, and deep platform primitives (App
Attest, Secure Enclave/Keychain) don't map 1:1 either. What *is*
shared is the protocol/business logic — DID handling, SD-JWT parsing,
OID4VCI/OID4VP flows, trust-list verification, and more — rebuilt as a
platform-agnostic Rust core, using iOS's Swift implementation and its
XCTest suite as the behavioral spec to build against. See
[`docs/2026-09-05-decisions-and-roadmap.md`](docs/2026-09-05-decisions-and-roadmap.md)
for the full reasoning and the six-phase roadmap this follows.

## Repo layout

- **`core/`** — the shared Rust crate (`backuptw-core`): DID/JWK,
  credential model, SD-JWT selective disclosure, OID4VCI/OID4VP,
  trust-list + on-chain verification, MOICA (自然人憑證) credential
  verification, the TW FidO signing protocol, offline presentation,
  and the age-predicate ZK proof's data layer. Exposed to Kotlin via
  UniFFI (`core/src/ffi.rs`). Network I/O, Keystore-backed signing, and
  actual ZK proving stay native by design — `core/` is pure protocol
  logic, fully testable with `cargo test`.
- **`android/wallet/`** — the real Android app, in progress. See
  [`android/README.md`](android/README.md) for build instructions.
- **`android/app/`** — a throwaway validation harness for the Mopro/
  Spartan2 ZK proving pipeline, unrelated to the app shell.
- **`docs/`** — dated decision records and investigation notes
  (`YYYY-MM-DD-<slug>.md`). Point-in-time snapshots — check the repo
  state and open issues before trusting anything there as current.
- **`backupTW-iOS/`** — the reference implementation, vendored as a
  git submodule. Read-only reference, not built as part of this repo.
- **`infra/`** — dev-box provisioning (Terraform + Nix).

## What's ported, what isn't

| Feature | Core (Rust) | Android | Live-verified | Notes |
|---|---|---|---|---|
| DID/JWK (`did:key`, both spellings) | ✅ | ✅ | ✅ | |
| Verifiable credential model / SD-JWT selective disclosure | ✅ | ✅ | ✅ | |
| Age predicate (plain disclosed claim, non-ZK) | ✅ | ✅ | ✅ | Not the ZK proof below |
| OID4VCI credential receive (TWDIW) | ✅ | ✅ | ✅ | Telecom card apply flow |
| OID4VP credential presentation (TWDIW) | ✅ | ✅ | ✅ | |
| Trust-list fetch/verify + on-chain verification | ✅ | ✅ | ✅ | Some field-report items still unverified against production ([#37](https://github.com/ChihChengLiang/backupTW-Android/issues/37)) |
| 7-Eleven / convenience-store pickup | ✅ | ✅ | ✅ | Confirmed against a real POS terminal; one QR-timing detail still unconfirmed ([#38](https://github.com/ChihChengLiang/backupTW-Android/issues/38)) |
| MOICA credential envelope (X.509/citizen-cert verification) | ✅ | ⛔ | ⛔ | Verification logic is done; nothing can issue one yet — needs TW FidO below |
| TW FidO SP API (MOICA signing protocol) | ✅ | ⛔ | ⛔ | Blocked on renewed SP dev credentials and Android networking/QR/UI ([#34](https://github.com/ChihChengLiang/backupTW-Android/issues/34), [#35](https://github.com/ChihChengLiang/backupTW-Android/issues/35)) |
| Age-predicate ZK proof (real Mopro/Spartan2 proving) | ✅ | 🟡 dev-only smoke test | 🟡 partial | Fixture credential only (no real issuance path); a real device or less-contended host needed to observe full completion ([#41](https://github.com/ChihChengLiang/backupTW-Android/issues/41), [#42](https://github.com/ChihChengLiang/backupTW-Android/issues/42), [#43](https://github.com/ChihChengLiang/backupTW-Android/issues/43)); whether the underlying backend is actually zero-knowledge is a separate, still-open question ([#36](https://github.com/ChihChengLiang/backupTW-Android/issues/36)) |
| Offline presentation/verifier (BLE/QR, holder ↔ verifier) | ✅ | ⛔ | ⛔ | Core logic + FFI only; no transport protocol or UI yet ([#51](https://github.com/ChihChengLiang/backupTW-Android/issues/51)) |
| MyData vault (hashing/PDF normalization/ZIP handling) | ⛔ | ⛔ | ⛔ | Not started ([#48](https://github.com/ChihChengLiang/backupTW-Android/issues/48)) |
| Android Keystore-backed signing | ✅ | ✅ | ✅ | |
| Play Integrity (App Attest equivalent) | ⛔ | ⛔ | ⛔ | Not started |

✅ done · 🟡 partial · ⛔ not started/blocked

## Building

See [`android/README.md`](android/README.md) for the actual build
commands (native library + UniFFI bindings regeneration, Gradle
assembly, on-device verification notes). For the Rust core alone:
`cd core && cargo test`.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
