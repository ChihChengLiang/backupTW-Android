#!/usr/bin/env bash
set -euxo pipefail

# --- KVM + basics ---
apt-get update
apt-get install -y qemu-kvm git curl
usermod -aG kvm ubuntu

# --- Nix, multi-user install with flakes enabled ---
# cloud-init runs this as root without $HOME set, which the Nix installer requires.
export HOME=/root
curl -L https://nixos.org/nix/install | sh -s -- --daemon
mkdir -p /etc/nix
echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# --- Project checkout ---
# Use an HTTPS repo URL unless the box has a deploy key registered for SSH —
# cloud-init has no access to your local ssh-agent, so an SSH URL will fail
# with "Host key verification failed" on a public/private repo alike.
sudo -u ubuntu -H bash -c 'git clone --recurse-submodules ${git_repo_url} /home/ubuntu/project' || true

# --- Claude Code ---
# Verify the current install command in Anthropic's docs (docs.claude.com) —
# this changes between releases, so don't hardcode it blindly.
# su - ubuntu -c "curl -fsSL <claude-code-install-url> | bash"

cat > /home/ubuntu/BOOTSTRAP_DONE <<'EOF'
Bootstrap finished.
  ssh in, then:
    cd project/infra   # flake.nix lives here, not the repo root
    nix develop        # pulls the Android SDK/JDK/tooling from flake.nix
    avdmanager create avd -n dev -k "system-images;android-34;google_apis;x86_64"
EOF
chown ubuntu:ubuntu /home/ubuntu/BOOTSTRAP_DONE
