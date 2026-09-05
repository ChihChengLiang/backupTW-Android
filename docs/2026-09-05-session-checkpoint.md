# Session checkpoint (2026-09-05)

First working session on this port. Nothing built yet — this is
planning, docs, and dev-environment bootstrapping only. Full detail is
in the other dated docs from today; this is the index + what's still
open.

## What happened today

- `backupTW-iOS` vendored as a git submodule for reference.
- Architecture decisions made and written up:
  `docs/2026-09-05-decisions-and-roadmap.md` — Compose UI, a new
  shared Rust core for protocol/business logic (Android-first, iOS
  migration explicitly deferred), six-phase roadmap from minimal setup
  to release.
- MOICA (行動自然人憑證) investigated: an official Android app exists
  (`tw.gov.moi.tfido`). Decided to build QR-code mode first (avoids the
  one unconfirmed unknown — the Android App-to-App intent contract).
  Detail in `docs/2026-09-05-moica-integration-plan.md`. **Expect this
  integration to be genuinely difficult** — flagged explicitly by the
  project owner from iOS experience.
- Two external field reports (shared by the iOS developer) mined for
  reusable technical detail and written up:
  - `docs/2026-09-05-twdiw-protocol-notes.md` — DID/JWK and SD-JWT
    quirks, trust-list/status-list endpoint details, real test
    vectors, and four security bugs in the official reference SDK
    that must **not** be copied (disabled TLS hostname verification,
    a verify-before-fetch ordering flaw, substring-based disclosure
    matching, `context` vs `@context`).
  - `docs/2026-09-05-telecom-pickup-notes.md` — the 7-Eleven
    credential pickup flow: protocol steps, QR crypto scheme, and the
    absolute-deadline-not-decrementing-counter timing rule.
- AWS access debugged and fixed:
  - Root cause of the disconnected `aws-mcp` MCP server: the AWS CLI
    session it proxies through had expired, and the server config had
    no profile pinned, so it silently rode on whatever `default`
    resolved to.
  - A dedicated IAM user, `my-agent` (arn
    `arn:aws:iam::060057062568:user/my-agent`), now exists with
    `AmazonEC2FullAccess` + `SignInLocalDevelopmentAccess` attached —
    sufficient for `infra/main.tf`'s EC2 provisioning and broad enough
    for other EC2-based project needs, at the cost of not being scoped
    to just this project's actions.
  - `~/.claude.json`'s global `aws-mcp` server config now pins
    `AWS_PROFILE=my-agent` explicitly instead of falling back to
    `default` (which was, at one point during debugging, root —
    root is no longer in use for this project going forward).

## Open items for next session

1. **Restart Claude Code (or reconnect the `aws-mcp` MCP server)** to
   pick up the new config, then verify `mcp__aws-mcp__*` tools actually
   appear and work — this was fixed but not yet end-to-end verified
   inside a live MCP session.
2. **GitHub write access for the agent is still not set up** — the
   user flagged this as needed early on; still pending as of this
   checkpoint.
3. **The EC2 dev box hasn't been provisioned yet.** `infra/` has
   working Terraform (`terraform apply` with `allowed_ssh_cidr` and
   `git_repo_url` vars) but it has not been run. Phase 0 of the
   roadmap isn't complete until this exists.
4. Once the dev box + toolchain exist, start **Phase 1**: get the
   OpenACAge Mopro/Rust ZK circuit building for Android via
   `cargo-ndk`, validated against the same fixed test vectors iOS's
   `age_assets.rs` uses. This is the first real go/no-go gate for the
   whole port (see `docs/2026-09-05-decisions-and-roadmap.md`).
5. Spike the MOICA Android App-to-App intent contract via MOI's
   integrator zone (fido.moi.gov.tw/pt/agency) or contact info, in
   parallel with building the QR-first flow — not blocking, but don't
   let it go unstarted for long.
