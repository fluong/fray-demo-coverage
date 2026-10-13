# Minimal Secrets Manager secret for coverage (plan-only).
variable "name" {
  type = string
}

resource "aws_secretsmanager_secret" "this" {
  name = var.name
}

output "arn" {
  value = aws_secretsmanager_secret.this.arn
}

output "name" {
  value = aws_secretsmanager_secret.this.name
}

output "address" {
  value = aws_secretsmanager_secret.this
}
