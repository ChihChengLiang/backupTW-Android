output "public_ip" {
  value = aws_instance.dev.public_ip
}

output "ssh_command" {
  value = "ssh ubuntu@${aws_instance.dev.public_ip}"
}

output "instance_id" {
  value = aws_instance.dev.id
}
