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
          ];

          shellHook = ''
            export ANDROID_HOME=${androidSdk}/share/android-sdk
            export ANDROID_SDK_ROOT=$ANDROID_HOME
            export PATH=$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$PATH
            echo "Android SDK ready at $ANDROID_HOME"
            echo "First time: avdmanager create avd -n dev -k \"system-images;android-34;google_apis;x86_64\""
          '';
        };
      });
}
