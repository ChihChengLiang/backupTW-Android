variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "android-dev"
}

variable "instance_type" {
  type        = string
  default     = "c8i.2xlarge" # 8 vCPU / 16GB — bump if the emulator + Gradle feel slow
  description = "Must be a nested-virtualization-capable family (c8i/m8i/r8i + flex, or 7th-gen) unless you switch to a .metal type"
}

variable "root_volume_gb" {
  type        = number
  default     = 150
  description = "Android SDK + system images + Gradle/AVD caches eat space fast"
}

variable "allowed_ssh_cidr" {
  type        = string
  description = "Your IP in CIDR form, e.g. 1.2.3.4/32 — never leave this 0.0.0.0/0"
}

variable "public_key_path" {
  type    = string
  default = "~/.ssh/id_ed25519.pub"
}

variable "git_repo_url" {
  type        = string
  description = "Repo the instance clones on first boot (the ported Android project)"
}
