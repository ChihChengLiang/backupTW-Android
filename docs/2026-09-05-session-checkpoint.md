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
2. ~~GitHub write access for the agent is still not set up.~~ **Done
   (2026-09-05):** this is specifically for a Claude Code session
   running *on the EC2 box* to push its own commits (not this local
   session). Set up as a repo-scoped deploy key, not a PAT:
   - Generated a dedicated ed25519 keypair on the box
     (`~/.ssh/id_ed25519_github`, comment
     `backupTW-Android-ec2-devbox`).
   - Registered its public half as a **write-enabled deploy key** on
     `ChihChengLiang/backupTW-Android` via
     `gh repo deploy-key add ... --allow-write` (run locally, using
     the user's own `gh` auth — the box has no GitHub auth of its
     own). Visible under repo Settings → Deploy keys, id
     `162363320`.
   - Pointed the box at it via `~/.ssh/config` (`Host github.com`
     forcing that `IdentityFile`), switched `~/project`'s `origin`
     remote from HTTPS to SSH, and set `git config user.name`/
     `user.email` on the box to match the user's own
     (`ChihChengLiang` / `chihchengliang@gmail.com`) so box-authored
     commits read the same as any other commit in history.
   - Verified with a real push: created `test/deploy-key-verify`,
     committed, pushed, confirmed it landed on GitHub, then deleted
     it both remotely and locally (confirmed gone via a 404 on the
     branches API) — no lingering test artifacts.
   - Note: deploy keys are scoped to exactly this one repo (can't
     read/write anything else), which is why this was preferred over
     a personal access token for a single-project dev box.
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

5. ~~Once the dev box + toolchain exist, start **Phase 1**~~ **Native
   half done (2026-09-05):** `flake.nix` gained Rust + Android NDK
   (r27) + `cargo-ndk` + `circom` (from `nixpkgs-unstable` — nixos-24.11's
   2.2.0 is too old for the circuits' `pragma circom 2.2.3`) + a full
   C/C++ toolchain (`gcc`, `cmake`, `gnum4`, `autoconf`, `automake`,
   `libtool`, `nasm` — needed to build vendored GMP + witnesscalc from
   source) + `corepack` (zkID's `circom/` package pins `yarn@4.13.0`).
   Also moved `flake.nix`/`flake.lock` from `infra/` to the repo root
   (was already flagged wrong above).

   Cloned `ethereum/zkID` fresh at the pinned/reviewed commit
   (`b395e09c225ff45b003f0087c28e2e208e22f944`, confirmed still == HEAD)
   to `~/zkID` (outside the repo, like `build-ios.sh` expects), applied
   the `OpenACAge/` overlay (`zkid-mobile.patch`, `predicate.rs`,
   `age_assets.rs`, `cargo-config.toml`, `witnesscalc-adapter.patch`).
   Compiled `jwt_2k`/`show` via `circomkit` (`bash scripts/compile.sh`)
   — **output `.r1cs` files are byte-identical, hash-identical to the
   ones pinned in `RELEASE-openac-age-v1.md`**, confirming circuit
   compilation is fully deterministic. Built and ran
   `age_assets` natively (`cargo build --release --bin age_assets`,
   x86_64-linux, no Android cross-compilation needed for this gate —
   it's a build-machine-side release gate, not part of the mobile
   binary): **passed** — `linked proof accepted; prepare=4264ms
   show=121ms` (iOS's own numbers were 19,203ms/777ms on different
   hardware; timing isn't the pass criterion, the accepted verdict is).

   Real bugs/gaps found along the way:
   - circomkit's JS-based Groth16 `setup` throws for any non-`bn128`
     prime (`circomkit.json` here uses `secq256r1`) — a red herring at
     first. The actual key-generation path for this project doesn't go
     through circomkit's setup at all: `setup_jwt_keys`/`setup_show_keys`
     (exposed by the `zkid-mobile.patch` overlay) call into
     `ecdsa-spartan2`, which uses `spartan2::R1CSSNARK` — a **Spartan**
     SNARK (transparent, no trusted setup, no ptau), not Groth16.
   - **Flagged, unresolved, needs crypto review:**
     `docs/2026-09-05-spartan2-zk-property-unverified.md` — the vendored
     `spartan2` fork (`0xVikasRushi/Spartan2`, branch `openac-sdk`) has a
     README stating "The proofs are *not* zero-knowledge (we plan to add
     it in the near future)", unverified as stale-vs-live for the pinned
     commit. If live, this would be a serious problem (the whole point of
     the circuit is hiding the birth date) — needs someone to actually
     read the Hyrax/Bulletproofs commitment code, not just the README.
     Functional validation above was continued in parallel per
     project-owner direction; passing it does **not** clear this concern.

   Work so far is on a local branch, `android-phase0-tooling` (not
   pushed) — project owner wants commits accumulated to a reasonable
   size before opening a PR, not pushed straight to `main` piecemeal.

   **Android cross-compile: done (2026-09-05, same session).**
   `cargo build --release --bin android` via `cargo-ndk`, `arm64-v8a`
   only so far (`ANDROID_ARCHS=aarch64-linux-android`; the other 3 ABIs
   are presumably the same fix, not yet run). Produced
   `wallet-unit-poc/mobile/MoproAndroidBindings/`:
   `jniLibs/arm64-v8a/libopenac_age_mobile_app.so` (the whole Rust
   core — circuits + witnesscalc + the Spartan2 stack — cross-compiled
   via the NDK), `jniLibs/arm64-v8a/libc++_shared.so`, and
   `uniffi/mopro/mopro.kt` (generated Kotlin FFI bindings).

   Two real upstream bugs found and worked around in `mopro-ffi`
   0.3.5's `src/app_config/android.rs` (patched directly in the local
   `~/.cargo/registry` checkout — **not** a durable fix, needs a
   proper `[patch]`/fork if this is going to be relied on repeatedly):
   - `build_for_arch`'s `out_lib_path` joined `build_dir` twice
     (`build_dir.join(format!("{}/{}/{}/{}", build_dir.display(), ...))`),
     so the post-`cargo ndk` `fs::copy` of the built `.so` always
     failed with ENOENT even though `cargo-ndk` itself had already
     correctly placed the library. Fix: drop the redundant
     `build_dir.display()` from the format string.
   - The crate's own `[profile.release]` sets `strip = true`. Stripped
     symbols include the UniFFI metadata `library_mode::generate_bindings`
     needs to introspect the built `.so`; with it stripped,
     `find_components` silently returns zero components, so
     `write_bindings` "succeeds" having written nothing, and the next
     step (`reformat_kotlin_package`) then fails trying to create a
     `uniffi/<module>/` dir that was never created — a confusing
     downstream symptom for an upstream (root) cause. Worked around
     with `CARGO_PROFILE_RELEASE_STRIP=false` for this build only, not
     a change to the crate itself.

   **Phase 1 exit criterion: met (2026-09-05, same session).** Added
   `android/` — a minimal single-Activity harness (**not** the Phase 4
   app shell, see `android/README.md` for that distinction), whose
   `MainActivity` replays `age_assets.rs`'s fixed vector through the
   Kotlin/UniFFI bindings. Required: an x86_64 API 34 AVD (created and
   booted headless for the first time this session — boots in ~40s on
   this box's KVM, no issues), a second cross-compile targeting
   `x86_64-linux-android` (arm64-v8a alone isn't enough since a plain
   host JVM can't load either — needs a real Android runtime, hence
   the emulator).

   Result, on-device, via the generated Kotlin API (not the Rust
   binary): **`RESULT: PASS (prepare=7549ms show=237ms)`** — setup,
   prove, reblind, and verify all succeeded end-to-end through the JNI
   boundary. This is the actual stated Phase 1 exit criterion; the
   earlier native run and successful cross-compile de-risked the
   crypto/circuit and FFI-linkage sides respectively, but this is the
   first point Kotlin-side validation actually happened.

   Three more real bugs found and fixed/documented (detail in
   `android/README.md`):
   - `cargo-ndk`/`mopro-ffi` only copies the final crate's own `.so`
     into `jniLibs/` — not `libwitnesscalc_jwt_2k.so`/
     `libwitnesscalc_show.so`, which `ecdsa-spartan2` also builds
     (dynamically linked, loaded at runtime) but leaves buried under
     `target/<abi>/release/build/.../out/witnesscalc/package/lib/`.
     Missing them produces a generic-looking `SynthesisError` with no
     hint it's a missing-library problem.
   - Generated `mopro.kt` (UniFFI 0.29) has each `ZkProofException`
     subclass declare both a constructor `val message: String` *and* a
     separate `override val message` getter — a genuine Kotlin name
     collision (not a compiler-version strictness issue), hand-patched
     (constructor property marked `override`, redundant getter
     dropped).
   - Files pushed into `Android/data/<pkg>/...` (external storage) via
     plain `adb shell mkdir`/`push` end up owned by `shell` and are
     invisible to the app's own process under scoped storage's per-app
     FUSE isolation — `ls`/POSIX permissions look completely normal,
     but `File.exists()` from inside the app returns `false`. Fixed by
     using internal storage (`filesDir`) instead, staged via
     `adb push` to `/data/local/tmp` + `run-as cp` into place.

   Generated artifacts (`jniLibs/*.so`, `uniffi/mopro/mopro.kt`,
   ~50MB) are gitignored, not committed — matches the project's
   existing practice of not vendoring large generated ZK artifacts
   (r1cs/keys aren't committed either, see
   `backupTW-iOS/Native/OpenACAge/README.md`).

   **Still open:** only `arm64-v8a`/`x86_64` built so far, not
   `armv7`/`i686`; nothing automates the zkID-clone → overlay → compile
   → cross-compile → copy-into-android/ pipeline (it's still the exact
   manual command sequence run this session); and the Spartan2
   zero-knowledge question
   (`docs/2026-09-05-spartan2-zk-property-unverified.md`) is unrelated
   to and unresolved by any of this — a *correct* verdict from a
   non-hiding proof system would still show `RESULT: PASS` here.
6. Spike the MOICA Android App-to-App intent contract via MOI's
   integrator zone (fido.moi.gov.tw/pt/agency) or contact info, in
   parallel with building the QR-first flow — not blocking, but don't
   let it go unstarted for long.
