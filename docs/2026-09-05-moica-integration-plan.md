# MOICA integration plan for Android (2026-09-05)

## What MOICA is

MOICA (行動自然人憑證 / "TW FidO") is Taiwan's Ministry of Interior
mobile citizen-certificate app — the phone-based replacement for the
physical 自然人憑證 smart card. It holds the citizen's certificate and
produces RSA signatures gated by the phone's biometrics/PIN, exposed
to relying-party apps through a government-run backend, the "TW FidO
SP API." backupTW-iOS's `TWFidO/TWFidOClient.swift` and
`TWFidO/MOICACallbackRouter.swift` are the reference implementation.

The SP REST API (`moise/sp/getSpTicket`, `moise/sp/getAthOrSignResult`,
etc.) is platform-agnostic — same backend for iOS and Android. Only
the client-side hand-off to the MOICA app differs per platform.

## Confirmed: an Android MOICA app exists

[行動自然人憑證](https://play.google.com/store/apps/details?id=tw.gov.moi.tfido)
(`tw.gov.moi.tfido`, Google Play, Android 12+) is live and documents
three integrator transports, matching what iOS already implements:

1. **App-to-App** — iOS builds a `mobilemoica://moica.moi.gov.tw/a2a/verifySign?...`
   deep link and receives a wake-up callback on its own registered
   scheme (`backuptw://`); the real result is fetched by polling
   `getAthOrSignResult`, not read from the callback. The Android-side
   mechanics (custom-scheme intent filter vs. Android App Link vs.
   explicit package targeting) are **not confirmed** — MOI publishes
   this behind an "介接單位專區" (integrator zone) at
   [fido.moi.gov.tw/pt/agency](https://fido.moi.gov.tw/pt/agency),
   likely gated on the same SP credentials backupTW already holds as a
   registered integrator.
2. **QR-code scan** — display a QR, user scans with MOICA's camera,
   poll the same result endpoint. No OS-specific integration at all.
3. **Push (ATH-03)** — already implemented in `TWFidOClient.requestSignPush`;
   requires a pre-bound device, so not a first-run flow.

## Decision: QR-code mode first

Confirmed with the user 2026-09-05. QR-code mode de-risks the Android
port by avoiding the one unresolved unknown (App-to-App's Android
intent contract) entirely, and reuses the exact SP API code path
already validated on iOS — only the client-side hand-off changes.

Spike the App-to-App intent scheme in parallel via MOI's integrator
docs/contact (0800-080-117, cse@moica.nat.gov.tw), and upgrade to it
later if confirmed — same-device app-switch is the better end-state
UX, but QR is the pragmatic first target.

**Expectation, stated explicitly by the user**: MOICA integration is
known to be difficult from the iOS experience. Budget for obstacles —
undocumented behavior, inconsistent error codes, and fields that don't
match the spec are the norm here, not the exception (see also the
TW FidO client code's extensive comments on exactly these kinds of
gaps, e.g. push's `op_mode` being silently required-absent, or
`error_code` arriving as either a string or a bare integer depending
on deployment).

## Open follow-ups

- Confirm whether backupTW's existing SP registration (service ID +
  AES key) is platform-agnostic or needs a separate Android
  registration.
- Get the actual Android App-to-App technical spec from MOI's
  integrator zone once GitHub/vendor access allows following up.
- Design the QR-code flow's polling/timeout logic to match
  `TWFidOClient.fetchResult`'s existing terminal-vs-pending
  classification (`isPending(errorCode:)`) and its "no timeout, caller
  owns the deadline" contract — that logic is protocol-level and
  belongs in the shared Rust core (see the architecture decisions in
  `docs/2026-09-05-decisions-and-roadmap.md`), not reimplemented per
  platform.

Sources: [行動自然人憑證 - Google Play](https://play.google.com/store/apps/details?id=tw.gov.moi.tfido), [介接單位專區](https://fido.moi.gov.tw/pt/agency), [下載App](https://fido.moi.gov.tw/pt/downloadApp).
