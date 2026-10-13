variable "aws_access_key" {
  type      = string
  default   = "test"
  sensitive = true
}

variable "aws_secret_key" {
  type      = string
  default   = "test"
  sensitive = true
}

variable "aws_sts_endpoint" {
  type        = string
  default     = null
  description = "LocalStack STS URL for CI. Null skips the custom endpoint."
}
