# Handoff

Where this project stands, and what a fresh session (human or agent)
needs to pick it back up. Written 2026-09-19, at the end of an active
development session; the dev EC2 box this was built on is being shut
down after this. See `docs/2026-09-05-session-checkpoint.md` and
`docs/2026-09-05-decisions-and-roadmap.md` for the earlier planning
history this session continued from — both are point-in-time
snapshots (see the root `README.md`'s note on `docs/`), superseded
where they disagree with this file or the code itself.

## What this is

`backupTW-Android` — a Rust + Android rewrite of
[backupTW-iOS](https://github.com/bonds-tw/backupTW-iOS), Taiwan's
TWDIW citizen-credential digital wallet. Active development, not
released. Full rationale and architecture in the root `README.md`.

## Current state, against the original 6-phase roadmap

(`docs/2026-09-05-decisions-and-roadmap.md`'s "Roadmap" section)

- **Phase 0-1** (setup, ZK de-risking) — done.
- **Phase 2** (shared Rust core) — substantially done: DID/JWK,
  SD-JWT selective disclosure, OID4VCI/OID4VP, trust-list + on-chain
  verification, MOICA credential-envelope verification, TW FidO
  protocol logic, offline-presentation core logic, age-predicate ZK
  data layer. See the root README's feature table for the exact
  per-feature breakdown.
- **Phase 3** (platform security primitives) — Keystore-backed
  signing is done and live-verified. Play Integrity not started.
  MOICA verification logic is done but nothing can *issue* a MOICA
  credential yet - blocked on the TW FidO SP API (issues #34, #35).
- **Phase 4** (app shell + first vertical slice) — done, and the app
  has grown well past "first vertical slice": a real 3-tab bottom-nav
  shell, a real design system (pink Material3 theme + hand-drawn
  Canvas icons, no icon library dependency), and two fully live
  end-to-end flows (telecom-card receive, 7-Eleven pickup) plus
  credential-management UI (per-credential History and Details
  screens) built on top of them. See "What the app actually does
  today" below.
- **Phase 5** (feature build-out to parity) — partial. 7-Eleven
  pickup is done and live-verified against a real POS. MyData vault
  is entirely unstarted (#48). The ZK age-predicate proof has a real
  Mopro/Spartan2 proving path but only against a fixture credential,
  dev-tools-only, not wired into any real user flow (#41, #42, #43).
  Offline BLE/QR presentation has core logic + FFI only, no transport
  or UI (#51).
- **Phase 6** (release readiness) — not started. No signing/release
  pipeline, no Play Integrity backend wiring, no closed testing
  track.

## What the app actually does today

Install `android/wallet` and you get a real 3-tab app (`MainActivity.kt`):

- **Credentials** — a card-stack view of stored telecom credentials
  (pink theme, `HomeScreen.kt`). Tap a card to see that credential's
  own **Credential History** (add/authorization event log,
  `CredentialHistoryScreen.kt`, backed by the new
  `CredentialHistoryStore`) and, from there, its **Credential
  Details** (VC No., expiry, per-claim reveal toggles,
  `CredentialDetailsScreen.kt`).
- **Add** — browse the live telecom-card catalog and apply for a
  card; completes via a real `modadigitalwallet://credential_offer`
  deep link from the carrier (`ApplyForCardScreen.kt`).
- **Present** — the live 7-Eleven pickup flow: live catalog, trust-
  list + on-chain verifier checks, a real signed OID4VP presentation
  (selectively disclosing exactly name + last-5 phone digits), and a
  real verifier-issued encrypted barcode with a live countdown
  (`PickupScreen.kt`/`PickupClient.kt`). The consent screen shows
  exactly what's being disclosed, masked by default with a reveal
  toggle. See `docs/2026-09-10-seven-eleven-pickup-data-flow.md` for
  a full trace of what crosses the network at each step.
- **Developer Tools** (off the main nav, reached from a link on the
  Credentials tab) — infrastructure smoke tests (Keystore signing,
  encrypted storage, credential-history round-trip, live trust-list
  fetch) and a real Mopro/Spartan2 ZK age-predicate proof run against
  a fixture credential (no real MOICA credential exists yet to prove
  over). Also holds the fixture-only regression demo
  (`FixtureDemoScreen.kt`).

## Repo hygiene done this session

- All local feature branches (this box's own clone) were deleted
  after confirming each was merged into `main` (`git branch
  --merged main`).
- Stale branches on `origin` were **not** deleted - 44 were found
  merged (or, in one case, a confirmed-abandoned artifact of an
  earlier stacked-PR mistake this session hit and corrected via PR
  #47), but bulk-deleting them was left for the repo owner rather
  than done unilaterally. If they start bothering you: everything
  reachable from `main`'s history is unaffected either way (deleting
  a merged branch only removes the ref, not the commits), and turning
  on GitHub's "automatically delete head branches" repo setting stops
  this from piling up again on future PRs.
- `android/README.md`'s top section, which described `wallet/` as a
  no-navigation/no-storage/no-design-system fixture harness, was
  rewritten - that description had gone stale several PRs ago and
  would have misled the next reader badly.

## Known gotchas (learned the hard way this session, worth not re-learning)

- **`./gradlew` is unreliable in this dev-box setup** - it broke
  silently partway through an earlier session for no diagnosed
  reason. Use `cd android && gradle ...` (the Nix-provided `gradle`),
  matching this file and `android/README.md`.
- **GitHub does not auto-retarget a stacked PR's base** when an
  intermediate branch merges. After any "merged" report, run
  `git fetch origin -q && git checkout main -q && git pull -q` and
  verify with `git log --oneline main` before branching again -
  don't trust the report alone. This bit the session twice.
  (This handoff's own final PR followed that same pattern.)
- **The Android emulator needs `-no-window` in this headless
  environment** (`emulator -avd dev -no-snapshot-save -no-boot-anim
  -no-window -gpu swiftshader_indirect`) - without it, it fails
  immediately with a Qt-platform-plugin error since there's no
  display.
- **`EncryptedFile`-backed stores (`CredentialStore`,
  `CredentialHistoryStore`, `TrustSnapshotStore`) can't be seeded
  from outside the app** - their encryption key is Android-Keystore-
  backed per install, so `adb push`-ing a plaintext file into their
  directory produces a file that isn't valid ciphertext and fails to
  decrypt. To seed real-looking data for UI verification, either (a)
  push a `.jws` file that's never actually read (works for
  `CredentialStore.allIds()`-only checks, since that just lists
  filenames), or (b) temporarily add a debug `LaunchedEffect` that
  calls the store's own `save`/`append` from inside the running app,
  screenshot, then revert the debug code before committing - this
  was the pattern used repeatedly across the Credential
  History/Details/consent-screen PRs.
- **APK size**: the debug build is ~120 MB, dominated by bundled ZK
  proving native libraries (`libopenac_age_mobile_app.so` alone is
  ~33 MB per ABI) - too large for a direct in-chat file send (30 MB
  cap). A GitHub Release (draft, if the repo is public and the build
  shouldn't be publicly listed) is the practical way to hand someone
  a real APK.
- **This sandbox has real network access** to the live TWDIW/
  7-Eleven sandbox endpoints (confirmed repeatedly this session) -
  but carrier phone-verification (OTP) can't be completed headlessly,
  so a full live receive→pickup round trip can't be exercised
  end-to-end from here without a human completing that step on a
  real phone.

## Open issues (as of this writing)

Grouped by theme - see each issue for detail:

**Live-verification gaps** (logic believed correct, not yet confirmed
against a real production backend/device):
[#34](https://github.com/ChihChengLiang/backupTW-Android/issues/34)
TW FidO SP API checksum/ticket/polling,
[#35](https://github.com/ChihChengLiang/backupTW-Android/issues/35)
MOICA app-to-app intent hand-off,
[#36](https://github.com/ChihChengLiang/backupTW-Android/issues/36)
vendored Spartan2 fork soundness,
[#37](https://github.com/ChihChengLiang/backupTW-Android/issues/37)
TWDIW production endpoints,
[#38](https://github.com/ChihChengLiang/backupTW-Android/issues/38)
7-Eleven QR TOTP window (60s vs 300s).

**Unstarted/blocked feature work**:
[#41](https://github.com/ChihChengLiang/backupTW-Android/issues/41)/
[#42](https://github.com/ChihChengLiang/backupTW-Android/issues/42)/
[#43](https://github.com/ChihChengLiang/backupTW-Android/issues/43)
wire real ZK proving into an actual user flow (currently dev-tools-
only against a fixture),
[#48](https://github.com/ChihChengLiang/backupTW-Android/issues/48)
MyData vault (entirely unstarted),
[#51](https://github.com/ChihChengLiang/backupTW-Android/issues/51)
offline BLE/QR presentation transport + UI.

None of this session's UI work (nav bar, credential history/details,
consent-screen restructure) resolved or touched any of these - they're
all still open and accurate.

## Resuming development

1. **Dev environment**: `infra/README.md` has the full EC2 provisioning
   flow (Terraform) - `terraform apply` from wherever that was last run
   (not from inside this box; no AWS credentials or Terraform state
   live here). Once the box is up, `nix develop` at the repo root pulls
   the whole Android + Rust toolchain reproducibly.
2. **Build**: `android/README.md` has native-library/UniFFI-binding
   regeneration steps and Gradle commands; `cd core && cargo test` for
   the Rust core alone.
3. **This session's PR trail** (chronological, most recent last) for
   context on recent UI decisions: #52 (README/LICENSE), #53 (pink
   theme + card stack), #54 (pickup-flow polish), #55 (bottom nav
   bar), #56 (data-flow doc), #57 (credential history), #58
   (credential details), #59 (consent-screen restructure).

## This session's transcript

<https://claude.ai/code/session_01CJXBvyFVggkAgoUWyEU14E>
