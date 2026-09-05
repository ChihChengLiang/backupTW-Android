#!/usr/bin/env bash
set -euxo pipefail

# --- KVM + basics ---
apt-get update
apt-get install -y qemu-kvm git curl
usermod -aG kvm ubuntu

# --- Nix, multi-user install with flakes enabled ---
curl -L https://nixos.org/nix/install | sh -s -- --daemon
mkdir -p /etc/nix
echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# --- Project checkout ---
sudo -u ubuntu -H bash -c 'git clone ${git_repo_url} /home/ubuntu/project' || true

# --- Claude Code ---
# Verify the current install command in Anthropic's docs (docs.claude.com) —
# this changes between releases, so don't hardcode it blindly.
# su - ubuntu -c "curl -fsSL <claude-code-install-url> | bash"

cat > /home/ubuntu/BOOTSTRAP_DONE <<'EOF'
Bootstrap finished.
  ssh in, then:
    cd project
    nix develop        # pulls the Android SDK/JDK/tooling from flake.nix
    avdmanager create avd -n dev -k "system-images;android-34;google_apis;x86_64"
EOF
chown ubuntu:ubuntu /home/ubuntu/BOOTSTRAP_DONE
