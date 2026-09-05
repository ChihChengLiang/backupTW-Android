# Android dev EC2 environment

Two layers, deliberately separate:

- **`infra/`** (Terraform) — provisions the EC2 box itself: instance type,
  nested virtualization, security group, disk, and the bootstrap script.
- **`flake.nix`** (repo root) — the reproducible toolchain *inside* the box:
  Android SDK/NDK, Rust + cargo-ndk, JDK, Node (for Claude Code), Gradle.
  Runs identically on this instance, a replacement instance, or your laptop.

## First-time setup

```bash
cd infra
terraform init
terraform apply \
  -var="allowed_ssh_cidr=YOUR_IP/32" \
  -var="git_repo_url=https://github.com/you/your-repo.git"
```

Wait ~2 min for `user_data.sh.tpl` to finish (installs Nix, clones the repo),
then:

```bash
ssh ubuntu@$(terraform output -raw public_ip)
cat BOOTSTRAP_DONE   # confirms bootstrap finished
cd project
nix develop           # pulls the whole Android + Rust toolchain
avdmanager create avd -n dev -k "system-images;android-34;google_apis;x86_64"
emulator -avd dev -no-window -gpu swiftshader_indirect &
```

Then install Claude Code inside the shell (check current install command in
Anthropic's docs) and point it at this project — `.mcp.json` in the repo root
already registers the `android` MCP server so Claude Code can screenshot,
tap, and inspect the emulator's UI tree without you connecting a screen.

## Lifecycle via your agent

Since your agent has AWS MCP and will manage the instance lifecycle, prefer
routing that through Terraform rather than raw EC2 API calls, so state
stays declarative and diffable:

```bash
terraform apply     # create / update
terraform destroy   # tear down (stop paying for the metal-adjacent instance type)
```

If you want the agent to just stop/start (not destroy) between sessions to
save cost without losing the disk, that's a plain `aws ec2 stop-instances` /
`start-instances` call via AWS MCP — Terraform doesn't need to know about
that state change since instance ID and volumes are unaffected.

## Notes

- `allowed_ssh_cidr` — keep this your IP, never `0.0.0.0/0`.
- `instance_type` defaults to `c8i.2xlarge` for nested-virt KVM acceleration.
  Swap to a `.metal` type (drop the `cpu_options` block) if you'd rather have
  bare-metal KVM with no capability flag to track.
- Root volume defaults to 150GB — SDK + system images + Gradle caches add up.
