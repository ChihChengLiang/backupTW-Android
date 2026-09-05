{
  description = "Android dev environment (ported from iOS) — reproducible via Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    # Deliberately does NOT follow our "nixpkgs" input: android-nixpkgs's
    # SDK/emulator derivations are only tested against its own pinned
    # nixpkgs revision, and forcing ours onto it can break them (e.g. the
    # emulator derivation's "libgbm" argument isn't satisfiable on every
    # nixpkgs revision).
    #
    # Pinned to the "stable" branch, not "main" — main tracks Google's
    # daily-updated "canary" SDK channel, whose newest cmdline-tools build
    # shipped a broken CLI wrapper (".android-wrapped: cannot execute:
    # required file not found") when we tried it.
    android-nixpkgs.url = "github:tadfisher/android-nixpkgs/stable";
  };

  outputs = { self, nixpkgs, flake-utils, android-nixpkgs }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; config.allowUnfree = true; };

        androidSdk = android-nixpkgs.sdk.${system} (sdkPkgs: with sdkPkgs; [
          # Not cmdline-tools-latest (currently v23): that release replaced
          # sdkmanager with a new "android" CLI that self-downloads/unpacks
          # into $HOME on first run, which fails inside Nix's network-less,
          # read-only build sandbox ("required file not found" building
          # android-sdk-env). Pinned to the last version before that change.
          cmdline-tools-19-0
          platform-tools
          build-tools-34-0-0
          platforms-android-34
          emulator
          system-images-android-34-google-apis-x86-64
          # r27, the last NDK line before Google's next major toolchain bump;
          # matches what current cargo-ndk / Mopro Android builds expect.
          ndk-27-3-13750724
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            androidSdk
            pkgs.jdk17
            pkgs.nodejs_22 # Claude Code runtime
            pkgs.git
            pkgs.gradle
            # Rust toolchain for the shared core (core/) and the OpenACAge
            # Mopro ZK circuit crate, both built for Android via cargo-ndk.
            # rustup (not pkgs.cargo/rustc) because we need the
            # aarch64/armv7/x86_64/i686-linux-android stdlib targets, which
            # aren't in nixpkgs' rustc build.
            pkgs.rustup
            pkgs.cargo-ndk
            pkgs.pkg-config
            # For compiling the OpenACAge zkID circuits (jwt_2k/show) via
            # circomkit before the Android Mopro build can run.
            pkgs.circom
          ];

          shellHook = ''
            export ANDROID_HOME=${androidSdk}/share/android-sdk
            export ANDROID_SDK_ROOT=$ANDROID_HOME
            export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.3.13750724
            export ANDROID_NDK_ROOT=$ANDROID_NDK_HOME
            export PATH=$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$PATH
            export RUSTUP_HOME="$HOME/.rustup"
            export CARGO_HOME="$HOME/.cargo"
            export PATH="$CARGO_HOME/bin:$PATH"
            if ! rustup toolchain list 2>/dev/null | grep -q stable; then
              rustup toolchain install stable >/dev/null
              rustup default stable >/dev/null
            fi
            for target in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android; do
              rustup target add "$target" >/dev/null 2>&1 || true
            done
            corepack enable --install-directory "$HOME/.local/bin" >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
            echo "Android SDK ready at $ANDROID_HOME"
            echo "Android NDK ready at $ANDROID_NDK_HOME"
            echo "Rust: $(rustc --version 2>/dev/null || echo 'not yet installed, run once more')"
            echo "First time: avdmanager create avd -n dev -k \"system-images;android-34;google_apis;x86_64\""
          '';
        };
      });
}
