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

1. ~~Restart Claude Code (or reconnect the `aws-mcp` MCP server) to pick
   up the new config, then verify `mcp__aws-mcp__*` tools actually
   appear and work.~~ **Done (2026-09-05):** confirmed end-to-end in a
   live session — `sts:GetCallerIdentity` and `ec2:DescribeRegions`
   both succeeded under the `my-agent` profile. Note for future use:
   `call_boto3`'s `operation_name` must be botocore CamelCase (e.g.
   `GetCallerIdentity`), not the boto3 client's snake_case method name
   (`get_caller_identity`) — the latter throws `OperationNotFoundError`.
2. **GitHub write access for the agent is still not set up** — the
   user flagged this as needed early on; still pending as of this
   checkpoint.
3. ~~The EC2 dev box hasn't been provisioned yet.~~ **Done
   (2026-09-05):** applied via `terraform apply` (instance id
   `i-061fb5a94405be5b8`, public IP `100.54.247.25`, `ssh
   ubuntu@100.54.247.25`). Note: Terraform wasn't installed locally —
   installed via `brew install hashicorp/tap/terraform` (the core-tap
   `terraform` formula was removed after HashiCorp's license change).
   Ran with `AWS_PROFILE=my-agent` explicitly since the `aws` provider
   block in `main.tf` doesn't pin a profile. `allowed_ssh_cidr` was
   set to the current public IP (`36.237.125.84/32`, via
   `curl https://checkip.amazonaws.com`) — **re-derive this if the
   apply is ever re-run from a different network**, don't reuse the
   stale value.

   Two real bugs found and fixed in `infra/` while bootstrapping (fixes
   are in `user_data.sh.tpl`/`README.md`, but the *live* box needed
   manual recovery since its user_data already ran and won't re-run on
   its own):
   - The Nix installer needs `$HOME` set; cloud-init runs `user_data`
     as root with no `$HOME`, so it aborted the whole script (`set
     -euxo pipefail`) partway through, before cloning the repo or
     writing `BOOTSTRAP_DONE`. Fixed by exporting `HOME=/root` first.
   - `git_repo_url` in SSH form (`git@github.com:...`) fails from
     cloud-init — no access to a local `ssh-agent`, so it hits "Host
     key verification failed." Since this repo is public, switched the
     default/example to the HTTPS form and added
     `--recurse-submodules` to the clone (the `backupTW-iOS` submodule
     needs it too — its own URL was already HTTPS).

   The live box was fixed by hand over SSH (re-ran the Nix installer
   with `HOME=/root`, cloned the repo over HTTPS with
   `--recurse-submodules`, wrote `BOOTSTRAP_DONE` manually) rather than
   destroying/recreating — cheaper than a full replace, but means this
   instance's actual boot history differs slightly from what a fresh
   `terraform apply` with the fixed template would do.

4. ~~`nix develop` hasn't been run/validated yet.~~ **Done
   (2026-09-05):** `cd ~/project/infra && nix develop` now succeeds —
   Android SDK (`build-tools`, `cmdline-tools`, `emulator`, `licenses`,
   `platform-tools`, `platforms`, `system-images`) at `$ANDROID_HOME`,
   JDK 17.0.15, Node v22.16.0, Gradle 8.10.2. `flake.lock` generated on
   the box and copied back into `infra/` in the repo.

   Note the path: `flake.nix` lives in `infra/`, not the repo root, so
   it's `cd project/infra && nix develop`, **not** `cd project && nix
   develop` as `README.md` / the `BOOTSTRAP_DONE` message currently
   say — that's still wrong and should be fixed (either move
   `flake.nix` to the repo root, or fix the docs/message to point at
   `infra/`).

   Two more real bugs found and fixed in `infra/flake.nix` getting
   here:
   - `android-nixpkgs.inputs.nixpkgs.follows = "nixpkgs"` broke the
     `emulator` derivation: our pinned `nixos-24.11` snapshot had
     already dropped the standalone `libgbm` top-level attribute,
     which `android-nixpkgs`'s emulator build requires. Removed the
     `follows` override (its own README shows this as optional,
     commented out, for exactly this reason) so it uses its own
     tested `nixpkgs` pin instead.
   - `cmdline-tools-latest` (currently version 23) ships a new
     self-downloading `android` CLI (replacing `sdkmanager`) that
     fetches and unpacks itself into `$HOME` on first run — this
     can't work inside Nix's network-less, read-only build sandbox
     and failed with `.android-wrapped: cannot execute: required file
     not found` while building `android-sdk-env`. Confirmed this
     isn't a canary-vs-stable channel issue (broke identically on
     both `android-nixpkgs` branches). Fixed by pinning the explicit
     `cmdline-tools-19-0` attribute instead of `cmdline-tools-latest`.

5. Once the dev box + toolchain exist, start **Phase 1**: get the
   OpenACAge Mopro/Rust ZK circuit building for Android via
   `cargo-ndk`, validated against the same fixed test vectors iOS's
   `age_assets.rs` uses. This is the first real go/no-go gate for the
   whole port (see `docs/2026-09-05-decisions-and-roadmap.md`).
6. Spike the MOICA Android App-to-App intent contract via MOI's
   integrator zone (fido.moi.gov.tw/pt/agency) or contact info, in
   parallel with building the QR-first flow — not blocking, but don't
   let it go unstarted for long.
