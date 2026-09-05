{
  description = "Android dev environment (ported from iOS) — reproducible via Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    android-nixpkgs = {
      url = "github:tadfisher/android-nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, android-nixpkgs }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; config.allowUnfree = true; };

        androidSdk = android-nixpkgs.sdk.${system} (sdkPkgs: with sdkPkgs; [
          cmdline-tools-latest
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
