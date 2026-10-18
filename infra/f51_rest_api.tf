# ---------------------------------------------------------------------------
# F51-* REST API Gateway resource policies (Action v0.40.0+ for invoke-policy
# rows). Five REGIONAL or PRIVATE APIs with MOCK integrations; method auth is
# AWS_IAM everywhere so public entry flows stay mitigated when they appear.
# Plan pin v0.39.0: any non-empty inline policy or PRIVATE endpoint keeps the
# REST APIs off the DFD (no new expected rows). f51_cross also sets an empty
# inline policy document so a linked rest_api_policy alone does not create an
# internet entry before invoke-policy attrs ship.
# ---------------------------------------------------------------------------

resource "aws_security_group" "f51_execute_api_vpce" {
  name        = "${local.name}-f51-execute-api-vpce"
  description = "Interface endpoint for F51 REST API fixtures (no world ingress)"
  vpc_id      = aws_vpc.this.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.this.cidr_block]
  }
}

resource "aws_vpc_endpoint" "f51_execute_api" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.us-east-1.execute-api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.private.id, aws_subnet.private_b.id]
  security_group_ids = [
    aws_security_group.f51_execute_api_vpce.id,
  ]
  private_dns_enabled = false
  tags                = { Name = "${local.name}-f51-execute-api" }
}

# --- f51_open: Allow * execute-api:Invoke (no conditions) ---
# Later (Action v0.40.0+): invoke policy open (high); public client edge; entry auth mitigated (AWS_IAM).

resource "aws_api_gateway_rest_api" "f51_open" {
  name = "${local.name}-f51-open-fake"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowWorldInvoke"
      Effect    = "Allow"
      Principal = "*"
      Action    = "execute-api:Invoke"
      Resource  = "${aws_api_gateway_rest_api.f51_open.execution_arn}/*"
    }]
  })
}

resource "aws_api_gateway_resource" "f51_open" {
  rest_api_id = aws_api_gateway_rest_api.f51_open.id
  parent_id   = aws_api_gateway_rest_api.f51_open.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "f51_open" {
  rest_api_id   = aws_api_gateway_rest_api.f51_open.id
  resource_id   = aws_api_gateway_resource.f51_open.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "f51_open" {
  rest_api_id = aws_api_gateway_rest_api.f51_open.id
  resource_id = aws_api_gateway_resource.f51_open.id
  http_method = aws_api_gateway_method.f51_open.http_method
  type        = "MOCK"
  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_deployment" "f51_open" {
  rest_api_id = aws_api_gateway_rest_api.f51_open.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.f51_open.id,
      aws_api_gateway_method.f51_open.id,
      aws_api_gateway_integration.f51_open.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "f51_open" {
  deployment_id = aws_api_gateway_deployment.f51_open.id
  rest_api_id   = aws_api_gateway_rest_api.f51_open.id
  stage_name    = "prod"
}

# --- f51_vpce: Allow * + Deny unless aws:SourceVpce matches in-plan endpoint ---
# Later (Action v0.40.0+): invoke policy mitigated; no public client edge.

resource "aws_api_gateway_rest_api" "f51_vpce" {
  name = "${local.name}-f51-vpce-fake"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowInvoke"
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.f51_vpce.execution_arn}/*"
      },
      {
        Sid       = "DenyOutsideVpce"
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.f51_vpce.execution_arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.f51_execute_api.id
          }
        }
      },
    ]
  })
}

resource "aws_api_gateway_resource" "f51_vpce" {
  rest_api_id = aws_api_gateway_rest_api.f51_vpce.id
  parent_id   = aws_api_gateway_rest_api.f51_vpce.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "f51_vpce" {
  rest_api_id   = aws_api_gateway_rest_api.f51_vpce.id
  resource_id   = aws_api_gateway_resource.f51_vpce.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "f51_vpce" {
  rest_api_id = aws_api_gateway_rest_api.f51_vpce.id
  resource_id = aws_api_gateway_resource.f51_vpce.id
  http_method = aws_api_gateway_method.f51_vpce.http_method
  type        = "MOCK"
  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_deployment" "f51_vpce" {
  rest_api_id = aws_api_gateway_rest_api.f51_vpce.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.f51_vpce.id,
      aws_api_gateway_method.f51_vpce.id,
      aws_api_gateway_integration.f51_vpce.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "f51_vpce" {
  deployment_id = aws_api_gateway_deployment.f51_vpce.id
  rest_api_id   = aws_api_gateway_rest_api.f51_vpce.id
  stage_name    = "prod"
}

# --- f51_cross: foreign account Allow on aws_api_gateway_rest_api_policy ---
# Later (Action v0.40.0+): invoke policy open (medium); no public client edge.
# Empty inline policy keeps the v0.39.0 plan pin from emitting an internet entry.

resource "aws_api_gateway_rest_api" "f51_cross" {
  name = "${local.name}-f51-cross-fake"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = []
  })
}

resource "aws_api_gateway_rest_api_policy" "f51_cross" {
  rest_api_id = aws_api_gateway_rest_api.f51_cross.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowForeignRoot"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::444455556666:root"
      }
      Action   = "execute-api:Invoke"
      Resource = "${aws_api_gateway_rest_api.f51_cross.execution_arn}/*"
    }]
  })
}

resource "aws_api_gateway_resource" "f51_cross" {
  rest_api_id = aws_api_gateway_rest_api.f51_cross.id
  parent_id   = aws_api_gateway_rest_api.f51_cross.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "f51_cross" {
  rest_api_id   = aws_api_gateway_rest_api.f51_cross.id
  resource_id   = aws_api_gateway_resource.f51_cross.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "f51_cross" {
  rest_api_id = aws_api_gateway_rest_api.f51_cross.id
  resource_id = aws_api_gateway_resource.f51_cross.id
  http_method = aws_api_gateway_method.f51_cross.http_method
  type        = "MOCK"
  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_deployment" "f51_cross" {
  rest_api_id = aws_api_gateway_rest_api.f51_cross.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.f51_cross.id,
      aws_api_gateway_method.f51_cross.id,
      aws_api_gateway_integration.f51_cross.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "f51_cross" {
  deployment_id = aws_api_gateway_deployment.f51_cross.id
  rest_api_id   = aws_api_gateway_rest_api.f51_cross.id
  stage_name    = "prod"
}

# --- f51_ip: Allow * + Deny NotIpAddress aws:SourceIp (TEST-NET-3) ---
# Later (Action v0.40.0+): invoke policy open (medium); no public client edge.

resource "aws_api_gateway_rest_api" "f51_ip" {
  name = "${local.name}-f51-ip-fake"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowInvoke"
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.f51_ip.execution_arn}/*"
      },
      {
        Sid       = "DenyOutsideTestNet"
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.f51_ip.execution_arn}/*"
        Condition = {
          NotIpAddress = {
            "aws:SourceIp" = ["203.0.113.0/24"]
          }
        }
      },
    ]
  })
}

resource "aws_api_gateway_resource" "f51_ip" {
  rest_api_id = aws_api_gateway_rest_api.f51_ip.id
  parent_id   = aws_api_gateway_rest_api.f51_ip.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "f51_ip" {
  rest_api_id   = aws_api_gateway_rest_api.f51_ip.id
  resource_id   = aws_api_gateway_resource.f51_ip.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "f51_ip" {
  rest_api_id = aws_api_gateway_rest_api.f51_ip.id
  resource_id = aws_api_gateway_resource.f51_ip.id
  http_method = aws_api_gateway_method.f51_ip.http_method
  type        = "MOCK"
  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_deployment" "f51_ip" {
  rest_api_id = aws_api_gateway_rest_api.f51_ip.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.f51_ip.id,
      aws_api_gateway_method.f51_ip.id,
      aws_api_gateway_integration.f51_ip.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "f51_ip" {
  deployment_id = aws_api_gateway_deployment.f51_ip.id
  rest_api_id   = aws_api_gateway_rest_api.f51_ip.id
  stage_name    = "prod"
}

# --- f51_private: PRIVATE + VPC endpoint + VPCE Deny pattern ---
# Later (Action v0.40.0+): invoke policy mitigated; no public client edge.

resource "aws_api_gateway_rest_api" "f51_private" {
  name = "${local.name}-f51-private-fake"
  endpoint_configuration {
    types = ["PRIVATE"]
    vpc_endpoint_ids = [
      aws_vpc_endpoint.f51_execute_api.id,
    ]
  }
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowInvoke"
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.f51_private.execution_arn}/*"
      },
      {
        Sid       = "DenyOutsideVpce"
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.f51_private.execution_arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.f51_execute_api.id
          }
        }
      },
    ]
  })
}

resource "aws_api_gateway_resource" "f51_private" {
  rest_api_id = aws_api_gateway_rest_api.f51_private.id
  parent_id   = aws_api_gateway_rest_api.f51_private.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "f51_private" {
  rest_api_id   = aws_api_gateway_rest_api.f51_private.id
  resource_id   = aws_api_gateway_resource.f51_private.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "f51_private" {
  rest_api_id = aws_api_gateway_rest_api.f51_private.id
  resource_id = aws_api_gateway_resource.f51_private.id
  http_method = aws_api_gateway_method.f51_private.http_method
  type        = "MOCK"
  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_deployment" "f51_private" {
  rest_api_id = aws_api_gateway_rest_api.f51_private.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.f51_private.id,
      aws_api_gateway_method.f51_private.id,
      aws_api_gateway_integration.f51_private.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "f51_private" {
  deployment_id = aws_api_gateway_deployment.f51_private.id
  rest_api_id   = aws_api_gateway_rest_api.f51_private.id
  stage_name    = "prod"
}
