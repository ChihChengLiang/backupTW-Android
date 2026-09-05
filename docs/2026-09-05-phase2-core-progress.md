# Phase 2 progress: the shared Rust core (2026-09-05)

Companion to `docs/2026-09-05-session-checkpoint.md` (Phase 0/Phase 1) and
`docs/2026-09-05-decisions-and-roadmap.md` (the six-phase roadmap this
executes). That checkpoint doc was framed as "nothing built yet — planning
only"; this one picks up once Phase 1 passed its exit criterion and Phase 2
(the shared Rust core, `core/`) actually started. Kept separate rather than
appended, since the two are different in kind — infra/tooling vs. actual
protocol logic — and the first doc was already long.

## What's done

Two PRs, both scoped as self-contained slices of Phase 2's stated area (DID/
JWK, SD-JWT VC parsing + selective disclosure, OID4VCI/OID4VP, trust-list,
credential data model, MyData vault crypto):

1. **[#3](https://github.com/ChihChengLiang/backupTW-Android/pull/3) — merged.**
   `core/src/identity/`: `did:key` in both spellings this ecosystem uses —
   `did_key` (`p256-pub`, multicodec `0x1200`, this app's own credentials)
   and `jwk_did_key` (`jwk_jcs-pub`, multicodec `0xEB51`, what TWDIW uses —
   encodes JCS-canonical per RFC 8785 but decodes any member ordering,
   since the official wallet's own DIDs violate the codec it encodes with).
   50 tests, ported from `DIDKeyTests.swift`/`DIDKeyDecodeTests.swift`/
   `JWKDIDKeyTests.swift`, including round-trips against two **real**
   production DIDs pulled from live TWDIW responses on 2026-08-16 (the
   ministry's, canonical; the official wallet's, deliberately not).

2. **[#4](https://github.com/ChihChengLiang/backupTW-Android/pull/4) — open,
   awaiting review.** `core/src/credential/`: the W3C VC 2.0 data model
   (`verifiable_credential`), SD-JWT commit/reveal
   (`selective_disclosure`), and the 民國-birthdate age-at-issuance
   predicate (`age_predicate`). 37 more tests (87 total in `core/`).

Both native-only so far (`cargo test`, no UniFFI/Android wiring) — same
sequencing as Phase 1 (native validation first, cross-compile later), and
deliberately deferred rather than skipped: see "Not yet done" below.

## Design choices worth recording

- **`core/` is one crate (`backuptw-core`), not a workspace of many.**
  The roadmap doc calls it a "Rust workspace" in the Phase 0 description;
  this could grow into one later if it gets unwieldy, but starting with
  submodules under `src/` avoids premature structure for two modules.
- **Canonical JSON via `serde_json::Value`, not a hand-written sorter.**
  Swift's `.sortedKeys` JSONEncoder option needed a Rust equivalent for
  byte-reproducible signed bytes. The trick: `serde_json`'s `Map` is
  `BTreeMap`-backed unless the `preserve_order` feature is on (this crate
  doesn't enable it), so converting a struct to `serde_json::Value` before
  serializing — rather than serializing the struct directly, which streams
  fields in declaration order — sorts every object's keys, recursively, at
  every nesting level, for free. `canonical_bytes()` does exactly this
  two-hop conversion; the reasoning is in its doc comment so a future
  editor doesn't "simplify" it back to a direct `to_vec(&self)` and
  silently break signature reproducibility.
- **Signing itself stays out of the core, on purpose.** `jws_signing_input`
  returns the bytes to sign; `assemble_jws` takes a caller-supplied 64-byte
  `r‖s` signature and finishes the job. This matches the architecture
  decision that Keystore/Keychain-backed key storage stays native and
  reaches the core only through a boundary — there's no trait/callback
  abstraction yet because native-only testing doesn't need one; that's
  UniFFI-wiring work, not core-logic work.
- **A known iOS strictness gap was replicated, not fixed.** iOS's SD-JWT
  disclosure decoder requires exactly a three-element all-string array;
  `docs/roadmap-2026-08-27.md` (iOS side) already flags this as rejecting
  real telecom/convenience-store cards whose actual disclosure shape has
  never been observed. Loosening it here without a real vector to test
  against would be guessing at a security-relevant parser — exactly what
  this codebase's own `did:key` code argues against ("every failure is a
  rejection, never a repair"). Documented in `selective_disclosure`'s
  module doc comment as a scope note, not a silent divergence. Fix it once
  a real vector exists.

## Not yet done

- **UniFFI/Android wiring for either module.** Both are native-only. The
  natural next step before more Rust modules pile up unwired is proving the
  same UniFFI→Kotlin loop Phase 1 proved for Mopro's generated bindings
  also works for *hand-written* `#[uniffi::export]` code — those are
  different code paths in `uniffi-rs` and neither is validated yet for this
  crate.
- **CI is scoped but not merged.** `.github/workflows/core.yml` (fmt,
  clippy, test) is written and verified locally against every commit in
  both PRs, but pushing it hit a real GitHub restriction: the fine-grained
  PAT this session authenticates `gh` with (see the PR #1/#2 discussion)
  has `Pull requests: Read and write` but not the separate `Workflows`
  permission that GitHub requires for any push touching
  `.github/workflows/*`, OAuth-app-scoped or not. Blocked on the project
  owner adding that permission to the existing token (same token, no
  re-auth needed) — not re-attempted since.
- **The rest of Phase 2's scope**: OID4VCI/OID4VP (the largest area,
  ~2,600 LOC on iOS — and carries real policy questions already flagged in
  this session's scoping survey, not just porting work: `client_id`
  currently spoofs `moda_dw`'s value, and ID-token signature verification
  is disabled on iOS — decisions for the project owner, not something to
  resolve unilaterally mid-port), trust-list fetch/verify (~1,250 LOC,
  self-contained, no policy questions — a plausible next slice), and
  MyData vault crypto (~1,250 LOC, needs a zip-slip-protection re-port,
  security-critical).

## Verification notes

Every native test in both PRs passed on the box (`cargo test`/`clippy
--all-targets -- -D warnings`/`fmt --check`, all clean) before commit — see
each PR's description for the exact counts. Nothing here has been validated
through UniFFI or on an Android runtime; treat "passes `cargo test`" as
what it says and no more, same caveat as Phase 1's native-only checkpoint
before the Android cross-compile existed.
