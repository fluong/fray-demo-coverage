# Deliberately insecure plan-only fixtures for Fray regression coverage.
# NEVER terraform apply. Fake ARNs/IDs only.
# Layout/constraints: .cursor/rules/terraform.mdc (four flat files —
# terraform.tf, inputs.tf, main.tf, outputs.tf; no modules).
#
# Shared network: inline VPC/subnets/SGs — no aws_ami, aws_caller_identity,
# aws_availability_zones, aws_ssm_parameter, aws_eks_cluster_auth, or remote state.

locals {
  name     = "fray-coverage"
  # Hard-coded fake AMI — never resolved from AWS.
  fake_ami = "ami-0fraycoverage00fake"
  az       = "us-east-1a"
  assume_eks = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
  assume_ec2 = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  assume_lambda = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  assume_ecs = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = local.az
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name}-public" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name}-public-b" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# (a) aws_instance bastion — FR-034 open
# Public subnet + associate_public_ip_address + SG 22 from 0.0.0.0/0.
# Expected: FR-034 open on aws_instance.bastion
# ---------------------------------------------------------------------------

resource "aws_security_group" "bastion_ssh" {
  name        = "${local.name}-bastion-ssh"
  description = "Intentional world SSH for FR-034 coverage"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "bastion" {
  ami                         = local.fake_ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.bastion_ssh.id]
  tags                        = { Name = "${local.name}-bastion" }
}

# ---------------------------------------------------------------------------
# (b) aws_autoscaling_group via launch_template ($Latest) — FR-034 open
# Public NI + SG 3389 from 0.0.0.0/0.
# Expected: FR-034 open on aws_autoscaling_group.rdp
# ---------------------------------------------------------------------------

resource "aws_security_group" "asg_rdp" {
  name        = "${local.name}-asg-rdp"
  description = "Intentional world RDP for FR-034 coverage"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_launch_template" "rdp" {
  name_prefix   = "${local.name}-rdp-"
  image_id      = local.fake_ami
  instance_type = "t3.micro"

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.asg_rdp.id]
  }
}

resource "aws_autoscaling_group" "rdp" {
  name                = "${local.name}-rdp"
  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = [aws_subnet.public.id]

  launch_template {
    id      = aws_launch_template.rdp.id
    version = "$Latest"
  }
}

# ---------------------------------------------------------------------------
# (c) aws_eks_cluster + aws_eks_node_group — FR-034 open
# remote_access { ec2_ssh_key } with NO source_security_group_ids, public subnet.
# Expected: FR-034 open on aws_eks_node_group.workers
# ---------------------------------------------------------------------------



resource "aws_iam_role" "eks_cluster" {
  name               = "${local.name}-eks-cluster"
  assume_role_policy = local.assume_eks
}

resource "aws_iam_role" "eks_node" {
  name               = "${local.name}-eks-node"
  assume_role_policy = local.assume_ec2
}

resource "aws_eks_cluster" "this" {
  name     = local.name
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = [aws_subnet.public.id, aws_subnet.public_b.id]
  }
}

resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "workers"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = [aws_subnet.public.id]
  ami_type        = "AL2_x86_64"
  instance_types  = ["t3.medium"]

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  # Empty source_security_group_ids → AWS opens SSH to 0.0.0.0/0 (FR-034).
  remote_access {
    ec2_ssh_key = "fray-coverage-fake-key"
  }
}

# ---------------------------------------------------------------------------
# (d) Bedrock Lambdas — FR-017 / FR-004
# Pinned eu-west-1 foundation-model → FR-004 mitigated, contributes eu-west-1.
# global. inference profile → FR-004 mitigated; combineBedrockRegions → global
# so FR-017 open on signal:iam_service:bedrock.
# Expected: FR-004 mitigated (both policies); FR-017 open (bedrock signal)
# ---------------------------------------------------------------------------


resource "aws_iam_role" "bedrock_pinned" {
  name               = "${local.name}-bedrock-pinned"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "bedrock_pinned" {
  name = "bedrock-pinned"
  role = aws_iam_role.bedrock_pinned.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = ["arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"]
    }]
  })
}

resource "aws_lambda_function" "bedrock_pinned" {
  function_name = "${local.name}-bedrock-pinned"
  role          = aws_iam_role.bedrock_pinned.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

resource "aws_iam_role" "bedrock_global" {
  name               = "${local.name}-bedrock-global"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "bedrock_global" {
  name = "bedrock-global"
  role = aws_iam_role.bedrock_global.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["bedrock:InvokeModel"]
      # Fake account id; global. profile pins FR-017 open via combineBedrockRegions.
      Resource = ["arn:aws:bedrock:us-east-1:123456789012:inference-profile/global.anthropic.claude-sonnet-4"]
    }]
  })
}

resource "aws_lambda_function" "bedrock_global" {
  function_name = "${local.name}-bedrock-global"
  role          = aws_iam_role.bedrock_global.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

# ---------------------------------------------------------------------------
# (e) FR-032 — two root task definitions (B-44).
#
# bucketFlows reads each service's task_role_arn (not execution_role_arn).
# FR-032 when: to.kind=object_storage AND authz_scope exists; pass: scope=resource.
#
# Policy style: same as before — literal jsonencode ARNs plus a literal-only
# data.aws_iam_policy_document (B-45 plan-time data sources in prior_state).
# Worker uses the same pair so both workloads exercise the same IAM shapes.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "uploads" {
  bucket = "${local.name}-uploads-fake"
}

resource "aws_s3_bucket" "worker" {
  bucket = "${local.name}-worker-fake"
}


resource "aws_iam_role" "ecs_exec" {
  name               = "${local.name}-ecs-exec"
  assume_role_policy = local.assume_ecs
}

resource "aws_iam_role" "ecs_task" {
  name               = "${local.name}-ecs-task"
  assume_role_policy = local.assume_ecs
}

resource "aws_iam_role" "ecs_task_worker" {
  name               = "${local.name}-ecs-task-worker"
  assume_role_policy = local.assume_ecs
}

resource "aws_ecs_cluster" "this" {
  name = local.name
}

resource "aws_ecs_task_definition" "app" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_exec.arn
  task_role_arn            = aws_iam_role.ecs_task.arn
  container_definitions = jsonencode([{
    name      = "app"
    image     = "public.ecr.aws/docker/library/nginx:1.27"
    essential = true
  }])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_exec.arn
  task_role_arn            = aws_iam_role.ecs_task_worker.arn
  container_definitions = jsonencode([{
    name      = "worker"
    image     = "public.ecr.aws/docker/library/nginx:1.27"
    essential = true
  }])
}

resource "aws_security_group" "ecs" {
  name   = "${local.name}-ecs"
  vpc_id = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_service" "app" {
  name            = local.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = [aws_subnet.public.id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }
}

resource "aws_ecs_service" "worker" {
  name            = "${local.name}-worker"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = [aws_subnet.public.id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }
}

# App task role: literal + data-doc → uploads bucket only.
resource "aws_iam_role_policy" "known" {
  name = "known-literal-arns"
  role = aws_iam_role.ecs_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:DeleteObject"]
      Resource = ["arn:aws:s3:::${local.name}-uploads-fake/*"]
    }]
  })
}

data "aws_iam_policy_document" "datadoc" {
  statement {
    sid       = "S3Write"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${local.name}-uploads-fake/*"]
  }
}

resource "aws_iam_role_policy" "datadoc" {
  name   = "datadoc-from-data"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.datadoc.json
}

# Worker task role: same IAM shapes, different bucket (B-44, no cross-grant).
resource "aws_iam_role_policy" "worker_known" {
  name = "worker-known-literal-arns"
  role = aws_iam_role.ecs_task_worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:DeleteObject"]
      Resource = ["arn:aws:s3:::${local.name}-worker-fake/*"]
    }]
  })
}

data "aws_iam_policy_document" "worker_datadoc" {
  statement {
    sid       = "S3WriteWorker"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${local.name}-worker-fake/*"]
  }
}

resource "aws_iam_role_policy" "worker_datadoc" {
  name   = "worker-datadoc-from-data"
  role   = aws_iam_role.ecs_task_worker.id
  policy = data.aws_iam_policy_document.worker_datadoc.json
}


# ---------------------------------------------------------------------------
# (f) API Gateway HTTP API + Lambda URL — FR-001 open
# HTTP API route authorization NONE; function URL authorization_type NONE.
# Expected: FR-001 open on aws_apigatewayv2_route.public and
#           aws_lambda_function_url.open
# ---------------------------------------------------------------------------

resource "aws_iam_role" "api_lambda" {
  name               = "${local.name}-api-lambda"
  assume_role_policy = local.assume_lambda
}

resource "aws_lambda_function" "api" {
  function_name = "${local.name}-api"
  role          = aws_iam_role.api_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

resource "aws_apigatewayv2_api" "http" {
  name          = "${local.name}-http"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "public" {
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "GET /open"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

resource "aws_lambda_function_url" "open" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "NONE"
}

# ---------------------------------------------------------------------------
# (g) ALB with Cognito-authenticated HTTPS listener — FR-001 mitigated
# Internet-facing ALB; default_action authenticate-cognito then forward.
# Expected: FR-001 mitigated on aws_lb.cognito (omitted from SARIF)
# ---------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name   = "${local.name}-alb"
  vpc_id = aws_vpc.this.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "cognito" {
  name               = "${local.name}-cognito"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public.id, aws_subnet.public_b.id]
}

resource "aws_lb_target_group" "app" {
  name        = "${local.name}-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id
  target_type = "ip"
}

resource "aws_cognito_user_pool" "app" {
  name = "${local.name}-pool"
}

resource "aws_cognito_user_pool_client" "app" {
  name                                 = "${local.name}-client"
  user_pool_id                         = aws_cognito_user_pool.app.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid"]
  callback_urls                        = ["https://example.invalid/callback"]
  supported_identity_providers         = ["COGNITO"]
}

resource "aws_cognito_user_pool_domain" "app" {
  domain       = "${local.name}-fake"
  user_pool_id = aws_cognito_user_pool.app.id
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.cognito.arn
  port              = 443
  protocol          = "HTTPS"
  # Fake ACM ARN — plan-only; never applied.
  certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000000"

  default_action {
    type = "authenticate-cognito"
    authenticate_cognito {
      user_pool_arn       = aws_cognito_user_pool.app.arn
      user_pool_client_id = aws_cognito_user_pool_client.app.id
      user_pool_domain    = aws_cognito_user_pool_domain.app.domain
    }
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
