# backupTW Android — decisions & roadmap (2026-09-05)

Status at time of writing: repo scaffolded with `backupTW-iOS` vendored
as a submodule for reference. No Android app code, no Rust core code,
and no CI exist yet. Remote dev environment and GitHub write access
are being set up separately and are not ready yet. This document is
the first in a dated series (see `docs/` convention below) tracking
decisions and plans as the port progresses — nothing here should be
assumed still accurate without checking current repo state first.

## Docs convention

Flat, dated markdown files under `docs/`, named `YYYY-MM-DD-<slug>.md`,
written in English. This mirrors `backupTW-iOS/docs/`'s convention
(dated checkpoints + topical plan docs) but in English rather than
Traditional Chinese, since that's this repo's working language.

## Why this is a rewrite, not a port

Source repo facts (see `backupTW-iOS/docs/roadmap-2026-08-27.md`,
`twdiw-integration-plan.md`, `trust-chain-recommendation.md`):

- ~55K LOC of pure UIKit Swift, zero SwiftUI — no shareable UI code.
- Deep platform security primitives (App Attest, Secure Enclave/
  Keychain) that don't map 1:1 to Android equivalents.
- One genuinely reusable core: the ZK age-predicate circuit, already
  built as Rust wrapped via Mopro/UniFFI for iOS
  (`backupTW-iOS/Native/OpenACAge/`, `Native/OpenACAgePackage/`).
- No NFC anywhere in the app (confirmed by grep; the official Android
  MOICA holder SDK has NFC, this app deliberately skips it).
- ZK proving keys are ~950MB, downloaded at runtime, excluded from
  backup — needs an Android storage-management equivalent.

## Decisions made

**UI toolkit: Jetpack Compose.** Closest modern analogue to a
from-scratch UIKit app; no legacy Android View baggage to inherit
since there's no existing Android code.

**Business/protocol logic: a new shared Rust core**, not Kotlin
Multiplatform and not a straight Kotlin rewrite. Scope:

- In Rust: DID/JWK handling, SD-JWT VC parsing + selective disclosure,
  OID4VCI/OID4VP message flows, trust-list fetch/verify, credential
  data model, MyData vault crypto (hashing/PDF normalization/ZIP
  handling).
- Explicitly *not* in Rust — stays native per platform instead: HTTP
  transport, Keystore/Keychain-backed key storage, biometric prompts,
  file-system paths. These are injected into the core via a
  trait/callback boundary, so the core never touches the network or
  secure storage directly. This mirrors how `HolderKeyring`/
  `DeviceKey.swift` already separate key operations from storage on
  iOS.
- Exposed to Kotlin via UniFFI — the same mechanism already used for
  the ZK circuit (Mopro generates UniFFI bindings).
- **Android is the sole consumer for now.** iOS's existing Swift
  business logic is shipping and tested (35K LOC of XCTest); it is
  *not* migrated onto this core as part of this effort. Whether iOS
  later adopts it is a separate decision, to be made only after the
  Android app ships and the core has proven itself — not assumed now.
- The core lives inside this repo (`core/`), not a new repo, and is
  structured as a self-contained Cargo workspace member with no
  Android-specific dependencies — so it could be extracted to its own
  repo later with minimal friction if iOS ever adopts it. This is
  itself a decision that could be revisited; it is not a commitment to
  a permanent location.

Rationale for ruling out the alternatives: KMP still requires
per-platform glue and doesn't reduce iOS's maintenance burden (iOS
stays Swift either way); a straight Kotlin rewrite duplicates every
protocol/crypto decision iOS already made, including bugs it's already
found and fixed.

## Open questions (unresolved as of this writing)

- **MOICA on Android — partially resolved 2026-09-05.** An official
  Android app exists (`tw.gov.moi.tfido` on Google Play, Android 12+)
  and documents App-to-App, QR-code, and push as its three integrator
  transports — the SP REST backend is platform-agnostic. Decision:
  build **QR-code mode first** for Android (zero OS-specific
  integration risk, reuses the same SP API path already proven on
  iOS); spike the App-to-App intent contract in parallel since its
  exact mechanics aren't public and require MOI's integrator docs.
  Expect this integration to be difficult regardless of transport —
  see `docs/2026-09-05-moica-integration-plan.md` for detail.
- Exact Android `minSdk`/target SDK, package name, and module layout
  within `android/` — deferred to Phase 0 execution.
- Whether/when iOS adopts the shared Rust core — explicitly deferred,
  see above.

## Roadmap: minimal setup → full port

**Phase 0 — minimal setup.** Remote dev environment (Android Studio,
JDK, NDK, Rust toolchain, `cargo-ndk`, `uniffi-bindgen`) and GitHub
access, both being handled outside this doc. Repo skeleton: `core/`
(Rust workspace), `android/` (Gradle/Compose app shell), `docs/`. No
app code yet — tooling and scaffolding only.

**Phase 1 — de-risk the ZK core on Android, before any UI.** Mopro's
mobile crate is currently built for iOS via
`cargo build --release --bin ios` (see `build-ios.sh`); Mopro's
standard scaffold ships an equivalent `bin/android.rs`, so the Android
path is `cargo build --release --bin android` via `cargo-ndk`,
producing per-ABI `.so` + Kotlin bindings instead of an XCFramework.
Validate end-to-end against the same fixed test vectors iOS's
`age_assets.rs` release gate uses (sign a fixed SD-JWT, prove a hidden
birth-date predicate, reblind, check the verifier statement) in a
minimal JVM/instrumented harness — no Android UI needed for this
phase. Exit criterion: Kotlin-side proving/verification matches iOS's
vectors. This is the first real go/no-go gate for the whole port.

**Phase 2 — shared Rust core (protocol/business logic).** Build the
new crate scoped above. iOS's Swift implementation and its XCTest
suite become the *behavioral spec* to replay against this core — not
code to port, but the source of truth for expected behavior and edge
cases.

**Phase 3 — platform security primitives (redesign, not translation).**
Android Keystore/StrongBack key generation + attestation replacing
Keychain/Secure Enclave concepts; Play Integrity API replacing App
Attest (different verdict model, needs a Google server round-trip —
may require backend changes, flagged as a cross-repo dependency). The
MOICA spike (see open questions) should happen here at the latest,
ideally earlier.

**Phase 4 — Android app shell + first vertical slice.** Compose
scaffolding, navigation, design tokens translated from
`backupTW-iOS/docs/design-system.md`. First vertical slice: install
identity (did:key generation) → receive one credential via OID4VCI
sandbox → display it. Touches the Rust core, key storage, network, and
UI without needing MOICA, Play Integrity, or ZK proving yet — smallest
slice that proves the architecture wires together end-to-end.

**Phase 5 — feature build-out to parity.** Work through remaining
feature areas in roughly iOS's roadmap priority order: TWDIW/
government card display, MyData vault, ZK proving flow (using the
Phase 1 core), physical card/electronic-document pickup QR. Each area
gated by tests translated from the XCTest spec into JUnit/Espresso.

**Phase 6 — release readiness.** Signing/release pipeline (Play App
Signing), Play Integrity backend wiring, closed testing track, staged
rollout.

## Verification notes

There is no single end-to-end test until Phase 4's vertical slice
exists. Phase 1's exit criterion is the first concrete go/no-go
checkpoint. Treat any claim of "done" before that checkpoint as
unverified.
