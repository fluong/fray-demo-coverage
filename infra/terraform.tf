terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Plan-only CI provider. LocalStack STS when TF_VAR_aws_sts_endpoint is set.
# Never apply these fixtures.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = var.aws_access_key
  secret_key                  = var.aws_secret_key
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  dynamic "endpoints" {
    for_each = var.aws_sts_endpoint == null ? [] : [var.aws_sts_endpoint]
    content {
      sts = endpoints.value
    }
  }
}
