# TWDIW protocol field notes for the Android port (2026-09-05)

Summarized from an external field report on production TWDIW endpoints
(August 2026), shared by the iOS developer. Original:
[bonds-tw.github.io/twdiw](https://bonds-tw.github.io/twdiw/), which
also points to [TWDIW: The Missing Manual](https://docs.denkeni.org/twdiw)
(Denken Chen) and [moda-gov-tw/TWDIW-official-app](https://github.com/moda-gov-tw/TWDIW-official-app).

These are protocol/security facts, not iOS-specific — they belong in
the shared Rust core's design (OID4VCI/OID4VP, DID/JWK, trust-list;
see `docs/2026-09-05-decisions-and-roadmap.md`), not something to
rediscover per platform.

## DID method: did:key quirks

- Production issuers use multicodec `0xEB51` (`jwk_jcs-pub`), **not**
  standard `p256-pub` (`0x1200`).
- JWK member order is `crv, kty, x, y` (canonical per RFC 8785) — the
  reference server-side parser uses a hardcoded 3-byte slice `D1D603`
  with no validation.
- DIDs must be compared as canonical JCS forms, not as raw strings —
  a non-canonical but valid DID exists in the wild (see test vectors
  below) and string comparison fails silently against it.

## SD-JWT specifics

- Digest is computed over the **base64url-encoded disclosure string
  as ASCII bytes**, not over decoded JSON bytes. Test vector:
  `base64url(SHA-256(disclosure_b64url_string.encode('ascii')))`
  reproduces the published `_sd` entries.
- `statusListIndex` is serialized as a **string** (`"35"`), not a
  number — a reader that only accepts integers silently drops
  revocation data.
- Credentials are VCDM 1.1 hybrid: `_sd`/`_sd_alg` live under
  `vc.credentialSubject`; the human-relevant type is at `vc.type[1]`,
  which is a 40-character machine ID
  (e.g. `"00000000_demo_drivinglicense_202504251418"`) — the
  human-readable name only exists in issuer metadata (online, 701 KB
  response), so **offline wallets cannot display a recognizable card
  name** without a cached copy.

## Trust list / DID registry

- Endpoint: `GET https://frontend.wallet.gov.tw/api/did?size=20&page=0&orgType=1&status=1`
  — 43 production entries (not the 882 credential *configurations*,
  a different number from a different endpoint — don't conflate them).
- `orgType`: 1 = issuer, 2 = verifier.
- Every entry is labeled `orgGroupDetail.name: "政府部門"` (government)
  regardless of whether it's actually FamilyMart, 7-Eleven, or a
  telecom carrier — **do not surface this field to users verbatim.**
- Page size is clamped to 20 server-side; compute pagination offsets
  from the returned size, not the requested one.
- 41 of 43 entries are anchored on Arbitrum One
  (`0x84172caf8dd126c76f1fa8a2733ca3233264d31f`).

## Issuer keys and status lists

- `GET https://issuer-vc.wallet.gov.tw/api/keys` returns two keys:
  `key-1` signs credentials (appears in the issuer's DID document),
  `key-2` signs status lists (**distributed only over TLS, no on-chain
  or DID anchoring** — there is no offline root of trust for
  revocation).
- Status list validity window is exactly 86,400 seconds from the last
  *signing* time, not from fetch time — display absolute `exp`, not
  "valid 24 hours."
- Compressed status list: 76 bytes; decompressed: 16,384 bytes;
  capacity: 131,072 bits.

## Security issues in the reference implementation — do not replicate

These are bugs in the official SDK/app, called out explicitly so they
aren't copied by mistake when using that SDK as a reference:

1. **TLS hostname verification is disabled** on four connection types
   (issuer key, status list, schema, DID lookups) via a
   `HostnameVerifier` that unconditionally returns `true`. This is a
   known vulnerability in the reference implementation, not a required
   integration pattern — the Android port must keep hostname
   verification on.
2. **Verification order flaw**: status list and schema are fetched
   *before* the issuer signature is verified, and both URLs come from
   the unverified payload. Combined with (1), a malicious VP POST can
   trigger arbitrary GETs. Verify the issuer signature first.
3. **Selective disclosure field leakage**: the reference SDK matches
   requested fields by *substring search* against decoded JSON
   (salt + value + name), so a field named `number` can match both
   `id_number` and `controlnumber`, and a disclosure matching two
   requested fields gets appended twice. Match on exact claim names.
4. VP objects emit `'context'` instead of `'@context'` — a JSON-LD
   spec violation. Harmless today only because the current TWDIW
   verifier doesn't do JSON-LD expansion; don't propagate the bug.

## Structural gaps (not bugs, but real constraints)

- **No third-party wallet registration/trust model.** The sandbox
  account application flow only covers `issuer-sandbox` and
  `verifier-sandbox` — there is no `wallet-sandbox`. `client_id` is an
  echo check only; nothing cryptographically distinguishes an official
  wallet from a third-party one. Don't assume any privilege separation
  exists.
- **No age-predicate credential from the government side.** Driving
  licences carry `roc_birthday` (ROC calendar) directly — proving
  "over 18" from an official credential means disclosing the full
  birthdate. (This is exactly why backupTW's own ZK age-predicate
  circuit exists as a self-issued derivative — see
  `docs/2026-09-05-decisions-and-roadmap.md`'s Phase 1/2, and note the
  self-issued proof must keep a visible `selfIssued` source label per
  `backupTW-iOS/Native/OpenACAge/README.md`.)

## Test vectors (real production data, safe to commit — no personal data)

Canonical ministry DID:
```
did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbrzifm9txeerMVc9oLUg2nBJJnUtgYcAYd35rw1rCLq8y3bLDDBUPH5yTYB7ocY7oPESPBXqubuwMcRzw9evbeHHyFkwsmDc43myibDChGhDk8zrgZDB4KNyXPiQvkktUwn
```

Non-canonical but still-valid holder DID:
```
did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPodrZSqMbCy9Ndu4UgUGy3RNkhH479eLPpbfAhVSNu7B4oJvUwLzyxiP4Jt5k9cqqmChanxAazTGxJMvGxYDApNkXeDW5MPZgZRkjRgD1yaig5KCEgAaVbg8zrvYjMTi1BzqdDpPpkeSFmJwiej9YNY
```

SD-JWT digest check (Python):
```python
import hashlib, base64
b64u_e = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
D = "WyJwbHowWFN6LW9CSEUwZTUzTFVBeWNBIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd"
print(b64u_e(hashlib.sha256(D.encode('ascii')).digest()))
# ApkeYAR85EzxAHS1ojnNHhG7wnCDyTt4_iCIX2VKxaw
```

These should become fixed test vectors in the Rust core's test suite
(Phase 2), the same role `age_assets.rs`'s fixed vector plays for the
ZK circuit release gate.

## Known unresolved (per the source report, not yet re-verified)

- Whether non-`moda_dw` `client_id`s are accepted — testing stalled
  before the token step.
- Whether all claim values are strings vs. typed — only the driving
  licence was sampled.
- `universal_telecom_card` and `convenience_store` credential
  structures — require phone verification to collect, not yet
  captured. (Partially covered by the separate telecom pickup report,
  see `docs/2026-09-05-telecom-pickup-notes.md`.)
- Holder DID canonicality beyond the one sample above.

## Format version risk

This data reflects DIF Presentation Exchange (`presentation_definition`/
`presentation_submission`) and bare `did:key` client IDs — **not**
OpenID4VP 1.0 Final's DCQL query model and `decentralized_identifier`
client-id prefix. Build the Rust core with a version-negotiation seam
rather than hardcoding the pre-Final shapes, since the official
service is expected to migrate.
