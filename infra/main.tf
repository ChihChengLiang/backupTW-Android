terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Uncomment once you have a state bucket — keeps state off the laptop
  # and lets your agent apply/destroy without you holding the only copy.
  # backend "s3" {
  #   bucket = "your-tfstate-bucket"
  #   key    = "android-dev-ec2/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.aws_region
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "dev" {
  name_prefix = "${var.project_name}-sg-"
  description = "Android dev box: SSH only by default"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Only open this if you're pointing an external adb client (e.g. your
  # laptop, or a physical device) at the emulator on this box.
  # ingress {
  #   description = "ADB"
  #   from_port   = 5555
  #   to_port     = 5555
  #   protocol    = "tcp"
  #   cidr_blocks = [var.allowed_ssh_cidr]
  # }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg" }
}

resource "aws_key_pair" "dev" {
  key_name_prefix = "${var.project_name}-"
  public_key      = file(var.public_key_path)
}

resource "aws_instance" "dev" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  # Nested virtualization gives the Android emulator real KVM acceleration.
  # Supported on 8th-gen Intel families (c8i/m8i/r8i + flex variants) and
  # some 7th-gen types. If your chosen instance_type doesn't support it,
  # switch to a .metal type instead and drop this block — metal instances
  # get KVM directly with no flag needed.
  cpu_options {
    nested_virtualization = "enabled"
  }

  key_name               = aws_key_pair.dev.key_name
  vpc_security_group_ids = [aws_security_group.dev.id]

  root_block_device {
    volume_size           = var.root_volume_gb
    volume_type            = "gp3"
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    git_repo_url = var.git_repo_url
  })
  user_data_replace_on_change = true

  tags = { Name = var.project_name }
}
