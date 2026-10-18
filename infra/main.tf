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
  # B-72 negative: policy Resource via local (not a direct bucket attribute ref).
  b72_local_resource = "${aws_s3_bucket.b72_local.arn}/*"
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

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.11.0/24"
  availability_zone       = local.az
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-private" }
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.12.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-private-b" }
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
# (e) FR-032 — two root task definitions (B-44) + root secret on app (B-43/B-49).
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

# ---------------------------------------------------------------------------
# (f2) DynamoDB — B-14 R2 (Action v0.34.0+ for nosql_db + IAM table flows).
# sessions: deletion protection on (FR-040 mitigated).
# audit: deletion protection off (FR-040 open).
# App task role: scoped GetItem/PutItem/Query on sessions (+ index/*) only →
# FR-039 mitigated on app→sessions.
# audit_writer Lambda: dynamodb:* on "*" plus explicit audit table ARN so the
# client names audit only → one flow, account scope → FR-039 open on
# audit_writer→audit (no flow to sessions).
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "sessions" {
  name                        = "${local.name}-sessions"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "audit" {
  name                        = "${local.name}-audit"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = false

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_iam_role" "audit_writer" {
  name               = "${local.name}-audit-writer"
  assume_role_policy = local.assume_lambda
}

data "aws_iam_policy_document" "audit_writer_ddb" {
  statement {
    sid       = "DynamoDBAccountWide"
    actions   = ["dynamodb:*"]
    resources = ["*"]
  }
  statement {
    sid       = "DynamoDBAuditTable"
    actions   = ["dynamodb:*"]
    resources = [aws_dynamodb_table.audit.arn]
  }
}

resource "aws_iam_role_policy" "audit_writer_ddb" {
  name   = "audit-writer-dynamodb"
  role   = aws_iam_role.audit_writer.id
  policy = data.aws_iam_policy_document.audit_writer_ddb.json
}

resource "aws_lambda_function" "audit_writer" {
  function_name = "${local.name}-audit-writer"
  role          = aws_iam_role.audit_writer.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

# ---------------------------------------------------------------------------
# (g) B-14 R1 — EC2 + ASG instance-profile IAM (infra now; IAM-derived flows
# need Fray Action v0.33.0+). Plan-only / LocalStack-compatible.
# app_vm: scoped S3 on uploads (FR-032 mitigated once client emits VM→S3).
# db_worker ASG: rds-db:connect on "*" (FR-028 open once client links ASG→RDS).
# Both workloads are private (no public IP); FR-034 stays mitigated, not open.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "ec2_app" {
  name               = "${local.name}-ec2-app"
  assume_role_policy = local.assume_ec2
}

resource "aws_iam_role_policy" "ec2_app_s3" {
  name = "ec2-app-s3"
  role = aws_iam_role.ec2_app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = [
        "arn:aws:s3:::${aws_s3_bucket.uploads.bucket}",
        "arn:aws:s3:::${aws_s3_bucket.uploads.bucket}/*",
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_app" {
  name = "${local.name}-ec2-app"
  role = aws_iam_role.ec2_app.name
}

resource "aws_security_group" "app_vm" {
  name   = "${local.name}-app-vm"
  vpc_id = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app_vm" {
  ami                         = local.fake_ami
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private.id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ec2_app.name
  vpc_security_group_ids      = [aws_security_group.app_vm.id]
  tags                        = { Name = "${local.name}-app-vm" }
}

resource "aws_iam_role" "asg_db" {
  name               = "${local.name}-asg-db"
  assume_role_policy = local.assume_ec2
}

resource "aws_iam_role_policy" "asg_db_rds" {
  name = "asg-db-rds"
  role = aws_iam_role.asg_db.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["rds-db:connect"]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_instance_profile" "asg_db" {
  name = "${local.name}-asg-db"
  role = aws_iam_role.asg_db.name
}

resource "aws_security_group" "db_worker" {
  name   = "${local.name}-db-worker"
  vpc_id = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_launch_template" "db_worker" {
  name_prefix   = "${local.name}-db-worker-"
  image_id      = local.fake_ami
  instance_type = "t3.micro"

  iam_instance_profile {
    name = aws_iam_instance_profile.asg_db.name
  }

  vpc_security_group_ids = [aws_security_group.db_worker.id]
}

resource "aws_autoscaling_group" "db_worker" {
  name                = "${local.name}-db-worker"
  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = [aws_subnet.private.id]

  launch_template {
    id      = aws_launch_template.db_worker.id
    version = "1"
  }
}

resource "aws_secretsmanager_secret" "app" {
  name = "${local.name}-app-fake"
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
  # secret created in the same plan → container_definitions unknown at plan; Fray reads it from the configuration (B-49, v0.25.1).
  container_definitions = jsonencode([{
    name      = "app"
    image     = "public.ecr.aws/docker/library/nginx:1.27"
    essential = true
    portMappings = [{
      containerPort = 8080
      protocol      = "tcp"
    }]
    secrets = [{
      name      = "APP_SECRET"
      valueFrom = aws_secretsmanager_secret.app.arn
    }]
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

resource "aws_security_group" "app" {
  name   = "${local.name}-app"
  vpc_id = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "worker" {
  name   = "${local.name}-worker"
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
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = true
  }
  # Fronted by the public ALB so FR-035 has end-to-end coverage
  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = 8080
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
    security_groups  = [aws_security_group.worker.id]
    assign_public_ip = true
  }
}

# Declared DB scope: the task role's only database policy is a managed-policy
# ARN with no in-plan document, so the parser emits the SG flow without
# authz_scope. fray.yaml fills account (see annotations.flows). Not on the ALB.
resource "aws_iam_role" "ecs_task_declared" {
  name               = "${local.name}-ecs-task-declared"
  assume_role_policy = local.assume_ecs
}

resource "aws_iam_role_policy_attachment" "declared_rds" {
  role       = aws_iam_role.ecs_task_declared.name
  policy_arn = "arn:aws:iam::123456789012:policy/app-db"
}

resource "aws_ecs_task_definition" "declared" {
  family                   = "${local.name}-declared"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_exec.arn
  task_role_arn            = aws_iam_role.ecs_task_declared.arn
  container_definitions = jsonencode([{
    name      = "declared"
    image     = "public.ecr.aws/docker/library/nginx:1.27"
    essential = true
  }])
}

resource "aws_security_group" "declared" {
  name   = "${local.name}-declared"
  vpc_id = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_service" "declared" {
  name            = "${local.name}-declared"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.declared.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = [aws_subnet.public.id]
    security_groups  = [aws_security_group.declared.id]
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

# Execution role: resource-scoped GetSecretValue (ready when B-49 reads secrets).
resource "aws_iam_role_policy" "ecs_exec_secrets" {
  name = "ecs-exec-secrets"
  role = aws_iam_role.ecs_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      # name-* is plan-known; the random ARN suffix is not (never applied).
      Resource = ["arn:aws:secretsmanager:us-east-1:123456789012:secret:${aws_secretsmanager_secret.app.name}-*"]
    }]
  })
}

# ---------------------------------------------------------------------------
# (e2) RDS — future FR-028 coverage (Action still v0.30.0: FR-028 not evaluated).
# App task role: rds-db:connect scoped to this instance's dbuser ARN.
# Worker task role: rds-db:connect on "*" (account-wide).
# Data docs (B-44): do not jsonencode interpolated resource_id into role policy.
# ---------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db"
  subnet_ids = [aws_subnet.private.id, aws_subnet.private_b.id]
}

resource "aws_security_group" "db" {
  name   = "${local.name}-db"
  vpc_id = aws_vpc.this.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [
      aws_security_group.app.id,
      aws_security_group.worker.id,
      aws_security_group.declared.id,
      aws_security_group.db_worker.id,
      aws_security_group.db_control_wildcard.id,
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FR-028 coverage: app scoped (mitigated), worker account-wide (open)
resource "aws_db_instance" "main" {
  identifier                          = "${local.name}-db"
  engine                              = "postgres"
  engine_version                      = "16"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "app"
  manage_master_user_password         = true
  iam_database_authentication_enabled = true
  storage_encrypted                   = true
  publicly_accessible                 = false
  deletion_protection                 = false
  skip_final_snapshot                 = true
  db_subnet_group_name                = aws_db_subnet_group.main.name
  vpc_security_group_ids              = [aws_security_group.db.id]
}

data "aws_iam_policy_document" "app_rds" {
  statement {
    sid     = "RDSIAMAuthApp"
    actions = ["rds-db:connect"]
    resources = [
      "arn:aws:rds-db:us-east-1:123456789012:dbuser:${aws_db_instance.main.resource_id}/app",
    ]
  }
}

resource "aws_iam_role_policy" "app_rds" {
  name   = "app-rds-connect"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.app_rds.json
}

data "aws_iam_policy_document" "app_dynamodb_sessions" {
  statement {
    sid = "DynamoDBSessions"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
    ]
    resources = [
      aws_dynamodb_table.sessions.arn,
      "${aws_dynamodb_table.sessions.arn}/index/*",
    ]
  }
}

resource "aws_iam_role_policy" "app_dynamodb_sessions" {
  name   = "app-dynamodb-sessions"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.app_dynamodb_sessions.json
}

data "aws_iam_policy_document" "worker_rds" {
  statement {
    sid     = "RDSIAMAuthWorker"
    actions = ["rds-db:connect"]
    # deliberately account-wide: FR-028 open in coverage
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "worker_rds" {
  name   = "worker-rds-connect"
  role   = aws_iam_role.ecs_task_worker.id
  policy = data.aws_iam_policy_document.worker_rds.json
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

# ---------------------------------------------------------------------------
# (h) B-14 R3 — ElastiCache (Action v0.35.0+ for cache kind + FR-041/042/043).
# Plan-only; private subnets. v0.34.1 ignores these resource types in the DFD.
# ---------------------------------------------------------------------------

resource "aws_elasticache_subnet_group" "cache" {
  name       = "${local.name}-cache"
  subnet_ids = [aws_subnet.private.id, aws_subnet.private_b.id]
}

resource "aws_security_group" "cache_redis_secure" {
  name        = "${local.name}-cache-redis-secure"
  description = "Redis cache: app SG only (FR-041 mitigated at v0.35+)"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_elasticache_replication_group" "cache_redis_secure" {
  replication_group_id       = "${local.name}-redis-secure"
  description                = "R3 cache fixture: restricted SG + encryption on"
  engine                     = "redis"
  engine_version             = "7.0"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 1
  parameter_group_name       = "default.redis7"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.cache.name
  security_group_ids         = [aws_security_group.cache_redis_secure.id]
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
}

resource "aws_security_group" "cache_redis_open" {
  name        = "${local.name}-cache-redis-open"
  description = "Redis cache: world ingress on 6379 (FR-041/042/043 open at v0.35+)"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 6379
    to_port     = 6379
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

resource "aws_elasticache_replication_group" "cache_redis_open" {
  replication_group_id       = "${local.name}-redis-open"
  description                = "R3 cache fixture: 0.0.0.0/0 + encryption off"
  engine                     = "redis"
  engine_version             = "7.0"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 1
  parameter_group_name       = "default.redis7"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.cache.name
  security_group_ids         = [aws_security_group.cache_redis_open.id]
  transit_encryption_enabled = false
  at_rest_encryption_enabled = false
}

resource "aws_security_group" "cache_memcached" {
  name        = "${local.name}-cache-memcached"
  description = "Memcached: restricted ingress (FR-041/042 mitigated; no FR-043 on memcached)"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port       = 11211
    to_port         = 11211
    protocol        = "tcp"
    security_groups = [aws_security_group.worker.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_elasticache_cluster" "cache_memcached" {
  cluster_id                 = "${local.name}-memcached"
  engine                     = "memcached"
  engine_version             = "1.6.17"
  node_type                  = "cache.t3.micro"
  num_cache_nodes            = 1
  parameter_group_name       = "default.memcached1.6"
  port                       = 11211
  subnet_group_name          = aws_elasticache_subnet_group.cache.name
  security_group_ids         = [aws_security_group.cache_memcached.id]
  transit_encryption_enabled = true
}

# ---------------------------------------------------------------------------
# (i) FR-046 — RDS control-plane IAM on compute that already reaches the DB.
# D: scoped ModifyDBInstance + CreateDBSnapshot on aws_db_instance.main (app task role).
# E: second role with rds:* on * on a dedicated ECS service (private, DB SG peer).
# Evaluated at Action v0.35.0+; v0.34.1 ignores control-plane actions.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "app_db_control" {
  statement {
    sid = "RDSControlPlaneScoped"
    actions = [
      "rds:ModifyDBInstance",
      "rds:CreateDBSnapshot",
    ]
    resources = [aws_db_instance.main.arn]
  }
}

resource "aws_iam_role_policy" "app_db_control" {
  name   = "app-db-control-plane"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.app_db_control.json
}

resource "aws_iam_role" "db_control_wildcard" {
  name               = "${local.name}-db-control-wildcard"
  assume_role_policy = local.assume_ecs
}

data "aws_iam_policy_document" "db_control_wildcard" {
  statement {
    sid       = "RDSControlPlaneAccount"
    actions   = ["rds:*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "db_control_wildcard" {
  name   = "db-control-wildcard"
  role   = aws_iam_role.db_control_wildcard.id
  policy = data.aws_iam_policy_document.db_control_wildcard.json
}

resource "aws_ecs_task_definition" "db_control_wildcard" {
  family                   = "${local.name}-db-control-wildcard"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_exec.arn
  task_role_arn            = aws_iam_role.db_control_wildcard.arn
  container_definitions = jsonencode([{
    name      = "db-control"
    image     = "public.ecr.aws/docker/library/nginx:1.27"
    essential = true
  }])
}

resource "aws_security_group" "db_control_wildcard" {
  name   = "${local.name}-db-control-wildcard"
  vpc_id = aws_vpc.this.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_service" "db_control_wildcard" {
  name            = "${local.name}-db-control-wildcard"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.db_control_wildcard.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = [aws_subnet.private.id]
    security_groups  = [aws_security_group.db_control_wildcard.id]
    assign_public_ip = false
  }
}

# ---------------------------------------------------------------------------
# (j) B-71 — Lambda execution-role S3 grants (Action v0.35.0+ for Lambda→bucket flows).
# F: one bucket, one Lambda, readable grant.
# G: one role, two buckets in one statement, one Lambda.
# H: AmazonS3ReadOnlyAccess + scoped inline on the same bucket → account scope.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "b71_one" {
  bucket = "${local.name}-b71-one-fake"
}

resource "aws_iam_role" "b71_reader" {
  name               = "${local.name}-b71-reader"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "b71_reader_s3" {
  name = "b71-reader-s3"
  role = aws_iam_role.b71_reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::${aws_s3_bucket.b71_one.bucket}",
        "arn:aws:s3:::${aws_s3_bucket.b71_one.bucket}/*",
      ]
    }]
  })
}

resource "aws_lambda_function" "b71_reader" {
  function_name = "${local.name}-b71-reader"
  role          = aws_iam_role.b71_reader.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

resource "aws_s3_bucket" "b71_a" {
  bucket = "${local.name}-b71-a-fake"
}

resource "aws_s3_bucket" "b71_b" {
  bucket = "${local.name}-b71-b-fake"
}

resource "aws_iam_role" "b71_dual" {
  name               = "${local.name}-b71-dual"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "b71_dual_s3" {
  name = "b71-dual-s3"
  role = aws_iam_role.b71_dual.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject"]
      Resource = [
        "arn:aws:s3:::${aws_s3_bucket.b71_a.bucket}/*",
        "arn:aws:s3:::${aws_s3_bucket.b71_b.bucket}/*",
      ]
    }]
  })
}

resource "aws_lambda_function" "b71_dual" {
  function_name = "${local.name}-b71-dual"
  role          = aws_iam_role.b71_dual.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

resource "aws_s3_bucket" "b71_h" {
  bucket = "${local.name}-b71-h-fake"
}

resource "aws_iam_role" "b71_h" {
  name               = "${local.name}-b71-h"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy_attachment" "b71_h_readonly" {
  role       = aws_iam_role.b71_h.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy" "b71_h_scoped" {
  name = "b71-h-scoped"
  role = aws_iam_role.b71_h.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::${aws_s3_bucket.b71_h.bucket}/*"]
    }]
  })
}

resource "aws_lambda_function" "b71_h" {
  function_name = "${local.name}-b71-h"
  role          = aws_iam_role.b71_h.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

# ---------------------------------------------------------------------------
# (k) B-72 — jsonencode inline IAM with plan-unknown bucket ARNs (Action v0.35.0+).
# I: Resource = "${aws_s3_bucket.X.arn}/*" in jsonencode → authz_scope=resource.
# J: Resource built from local.* → authz_scope omitted (negative).
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "b72_jsonencode" {
  bucket = "${local.name}-b72-jsonencode-fake"
}

resource "aws_iam_role" "b72_jsonencode" {
  name               = "${local.name}-b72-jsonencode"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "b72_jsonencode" {
  name = "b72-jsonencode-s3"
  role = aws_iam_role.b72_jsonencode.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "${aws_s3_bucket.b72_jsonencode.arn}/*"
    }]
  })
}

resource "aws_lambda_function" "b72_jsonencode" {
  function_name = "${local.name}-b72-jsonencode"
  role          = aws_iam_role.b72_jsonencode.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

resource "aws_s3_bucket" "b72_local" {
  bucket = "${local.name}-b72-local-fake"
}

resource "aws_iam_role" "b72_local" {
  name               = "${local.name}-b72-local"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "b72_local" {
  name = "b72-local-s3"
  role = aws_iam_role.b72_local.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = local.b72_local_resource
    }]
  })
}

resource "aws_lambda_function" "b72_local" {
  function_name = "${local.name}-b72-local"
  role          = aws_iam_role.b72_local.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

# ---------------------------------------------------------------------------
# (l) B-73 — DynamoDB table resource policies (Action v0.36.0+ for FR-048).
# Separate tables from sessions/audit. No IAM flows to these tables on v0.35.2.
# K–O: aws_dynamodb_resource_policy (skipped by parser until v0.36.0).
# P: no resource policy (mitigated FR-048 once attrs emit false).
# deletion_protection_enabled=true keeps FR-040 mitigated on v0.35.2 prep pin.
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "ddb_rp_world" {
  name                        = "${local.name}-ddb-rp-world"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_resource_policy" "ddb_rp_world" {
  resource_arn = aws_dynamodb_table.ddb_rp_world.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetItem"
      Effect    = "Allow"
      Principal = "*"
      Action    = "dynamodb:GetItem"
      Resource  = aws_dynamodb_table.ddb_rp_world.arn
    }]
  })
}

resource "aws_dynamodb_table" "ddb_rp_foreign" {
  name                        = "${local.name}-ddb-rp-foreign"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_resource_policy" "ddb_rp_foreign" {
  resource_arn = aws_dynamodb_table.ddb_rp_foreign.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ForeignRoot"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111122223333:root"
      }
      Action   = "dynamodb:GetItem"
      Resource = aws_dynamodb_table.ddb_rp_foreign.arn
    }]
  })
}

resource "aws_dynamodb_table" "ddb_rp_same" {
  name                        = "${local.name}-ddb-rp-same"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_resource_policy" "ddb_rp_same" {
  resource_arn = aws_dynamodb_table.ddb_rp_same.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "dynamodb:GetItem"
      Resource = aws_dynamodb_table.ddb_rp_same.arn
    }]
  })
}

resource "aws_dynamodb_table" "ddb_rp_org" {
  name                        = "${local.name}-ddb-rp-org"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_resource_policy" "ddb_rp_org" {
  resource_arn = aws_dynamodb_table.ddb_rp_org.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgRestrictedWorld"
      Effect    = "Allow"
      Principal = "*"
      Action    = "dynamodb:GetItem"
      Resource  = aws_dynamodb_table.ddb_rp_org.arn
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "o-exampleorgid"
        }
      }
    }]
  })
}

resource "aws_dynamodb_table" "ddb_rp_deny_cond" {
  name                        = "${local.name}-ddb-rp-deny-cond"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_resource_policy" "ddb_rp_deny_cond" {
  resource_arn = aws_dynamodb_table.ddb_rp_deny_cond.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrg"
        Effect    = "Allow"
        Principal = "*"
        Action    = "dynamodb:GetItem"
        Resource  = aws_dynamodb_table.ddb_rp_deny_cond.arn
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
      {
        Sid       = "DenyOtherOrg"
        Effect    = "Deny"
        Principal = "*"
        Action    = "dynamodb:*"
        Resource  = aws_dynamodb_table.ddb_rp_deny_cond.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
    ]
  })
}

resource "aws_dynamodb_table" "ddb_rp_doc" {
  name                        = "${local.name}-ddb-rp-doc"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

data "aws_iam_policy_document" "ddb_rp_doc" {
  statement {
    sid    = "SourceAccountRestricted"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_dynamodb_table.ddb_rp_doc.arn,
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = ["vpce-0123456789abcdef0"]
    }
  }
}

resource "aws_dynamodb_resource_policy" "ddb_rp_doc" {
  resource_arn = aws_dynamodb_table.ddb_rp_doc.arn
  policy       = data.aws_iam_policy_document.ddb_rp_doc.json
}

resource "aws_dynamodb_table" "ddb_rp_none" {
  name                        = "${local.name}-ddb-rp-none"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}

# ---------------------------------------------------------------------------
# (m) S3 bucket policies + Secrets Manager resource policies (Action v0.37.0+
# for FR-049 / FR-050). Separate buckets/secrets from B-71 uploads and app
# secret. No IAM flows to these resources on the v0.36.0 pin.
# S-K–S-O, S-BPA: aws_s3_bucket_policy (parser links at v0.37.0+).
# S-INLINE skipped: AWS provider ~> 6.0 has no `policy` on aws_s3_bucket.
# SM-*: aws_secretsmanager_secret_policy (+ block_public_policy on SM-BPP).
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "s3_rp_world" {
  bucket = "${local.name}-s3-rp-world-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_world" {
  bucket = aws_s3_bucket.s3_rp_world.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_world" {
  bucket = aws_s3_bucket.s3_rp_world.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.s3_rp_world.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_foreign" {
  bucket = "${local.name}-s3-rp-foreign-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_foreign" {
  bucket = aws_s3_bucket.s3_rp_foreign.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_foreign" {
  bucket = aws_s3_bucket.s3_rp_foreign.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ForeignRoot"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111122223333:root"
      }
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.s3_rp_foreign.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_same" {
  bucket = "${local.name}-s3-rp-same-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_same" {
  bucket = aws_s3_bucket.s3_rp_same.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_same" {
  bucket = aws_s3_bucket.s3_rp_same.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.s3_rp_same.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_org" {
  bucket = "${local.name}-s3-rp-org-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_org" {
  bucket = aws_s3_bucket.s3_rp_org.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_org" {
  bucket = aws_s3_bucket.s3_rp_org.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgRestrictedWorld"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.s3_rp_org.arn}/*"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "o-exampleorgid"
        }
      }
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_deny_cond" {
  bucket = "${local.name}-s3-rp-deny-cond-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_deny_cond" {
  bucket = aws_s3_bucket.s3_rp_deny_cond.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_deny_cond" {
  bucket = aws_s3_bucket.s3_rp_deny_cond.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrg"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.s3_rp_deny_cond.arn}/*"
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
      {
        Sid       = "DenyOtherOrg"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.s3_rp_deny_cond.arn,
          "${aws_s3_bucket.s3_rp_deny_cond.arn}/*",
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
    ]
  })
}

resource "aws_s3_bucket" "s3_rp_doc" {
  bucket = "${local.name}-s3-rp-doc-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_doc" {
  bucket = aws_s3_bucket.s3_rp_doc.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "s3_rp_doc" {
  statement {
    sid    = "SourceVpceRestricted"
    effect = "Allow"
    actions = [
      "s3:GetObject",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      "${aws_s3_bucket.s3_rp_doc.arn}/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = ["vpce-0123456789abcdef0"]
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_doc" {
  bucket = aws_s3_bucket.s3_rp_doc.id
  policy = data.aws_iam_policy_document.s3_rp_doc.json
}

resource "aws_s3_bucket" "s3_rp_bpa" {
  bucket = "${local.name}-s3-rp-bpa-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_bpa" {
  bucket = aws_s3_bucket.s3_rp_bpa.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_bpa" {
  bucket = aws_s3_bucket.s3_rp_bpa.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetObjectBlockedByBpa"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.s3_rp_bpa.arn}/*"
    }]
  })
}

resource "aws_s3_bucket_public_access_block" "s3_rp_bpa" {
  bucket = aws_s3_bucket.s3_rp_bpa.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_secretsmanager_secret" "sm_rp_world" {
  name = "${local.name}-sm-rp-world-fake"
}

resource "aws_secretsmanager_secret_policy" "sm_rp_world" {
  secret_arn = aws_secretsmanager_secret.sm_rp_world.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetSecretValue"
      Effect    = "Allow"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = aws_secretsmanager_secret.sm_rp_world.arn
    }]
  })
}

resource "aws_secretsmanager_secret" "sm_rp_block" {
  name = "${local.name}-sm-rp-block-fake"
}

resource "aws_secretsmanager_secret_policy" "sm_rp_block" {
  secret_arn            = aws_secretsmanager_secret.sm_rp_block.arn
  block_public_policy   = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetSecretValueBlocked"
      Effect    = "Allow"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = aws_secretsmanager_secret.sm_rp_block.arn
    }]
  })
}

resource "aws_secretsmanager_secret" "sm_rp_same" {
  name = "${local.name}-sm-rp-same-fake"
}

resource "aws_secretsmanager_secret_policy" "sm_rp_same" {
  secret_arn = aws_secretsmanager_secret.sm_rp_same.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "secretsmanager:GetSecretValue"
      Resource = aws_secretsmanager_secret.sm_rp_same.arn
    }]
  })
}

resource "aws_secretsmanager_secret" "sm_rp_none" {
  name = "${local.name}-sm-rp-none-fake"
}

# ---------------------------------------------------------------------------
# (n) SQS / SNS access policies + queue IAM (Action v0.38.0+ for FR-044 /
# FR-045). Queues/topics are not mapped at v0.37.0 (no FR-044/045 rows on
# the current pin). No data.aws_caller_identity or allowed_account_ids.
# Q-*: aws_sqs_queue + aws_sqs_queue_policy (queue_url, policy).
# T-*: aws_sns_topic; T-DEFAULT has no aws_sns_topic_policy (AWS owner-only).
# F45-*: new inline policies on existing b71_reader / b71_dual Lambdas only.
# ---------------------------------------------------------------------------

resource "aws_sqs_queue" "sqs_rp_world" {
  name = "${local.name}-sqs-rp-world-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_world" {
  queue_url = aws_sqs_queue.sqs_rp_world.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldSend"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.sqs_rp_world.arn
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_foreign" {
  name = "${local.name}-sqs-rp-foreign-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_foreign" {
  queue_url = aws_sqs_queue.sqs_rp_foreign.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ForeignRoot"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::444455556666:root"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.sqs_rp_foreign.arn
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_same" {
  name = "${local.name}-sqs-rp-same-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_same" {
  queue_url = aws_sqs_queue.sqs_rp_same.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.sqs_rp_same.arn
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_org" {
  name = "${local.name}-sqs-rp-org-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_org" {
  queue_url = aws_sqs_queue.sqs_rp_org.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgRestrictedWorld"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.sqs_rp_org.arn
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "o-exampleorgid"
        }
      }
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_deny_cond" {
  name = "${local.name}-sqs-rp-deny-cond-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_deny_cond" {
  queue_url = aws_sqs_queue.sqs_rp_deny_cond.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrg"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.sqs_rp_deny_cond.arn
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
      {
        Sid       = "DenyOtherOrg"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.sqs_rp_deny_cond.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
    ]
  })
}

resource "aws_sqs_queue" "sqs_rp_doc" {
  name = "${local.name}-sqs-rp-doc-fake"
}

data "aws_iam_policy_document" "sqs_rp_doc" {
  statement {
    sid    = "SourceVpceRestricted"
    effect = "Allow"
    actions = [
      "sqs:SendMessage",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_sqs_queue.sqs_rp_doc.arn,
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = ["vpce-0123456789abcdef0"]
    }
  }
}

resource "aws_sqs_queue_policy" "sqs_rp_doc" {
  queue_url = aws_sqs_queue.sqs_rp_doc.id
  policy    = data.aws_iam_policy_document.sqs_rp_doc.json
}

resource "aws_sqs_queue" "sqs_rp_none" {
  name = "${local.name}-sqs-rp-none-fake"
}

resource "aws_sns_topic" "sns_rp_world" {
  name = "${local.name}-sns-rp-world-fake"
}

resource "aws_sns_topic_policy" "sns_rp_world" {
  arn = aws_sns_topic.sns_rp_world.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldPublish"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.sns_rp_world.arn
    }]
  })
}

resource "aws_sns_topic" "sns_rp_default" {
  name = "${local.name}-sns-rp-default-fake"
}

resource "aws_sns_topic" "sns_rp_owner" {
  name = "${local.name}-sns-rp-owner-fake"
}

resource "aws_sns_topic_policy" "sns_rp_owner" {
  arn = aws_sns_topic.sns_rp_owner.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "SourceOwnerStar"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.sns_rp_owner.arn
      Condition = {
        StringEquals = {
          "AWS:SourceOwner" = "111122223333"
        }
      }
    }]
  })
}

# F45-RES: scoped SQS + SNS on b71_reader (existing S3 policy unchanged).
resource "aws_iam_role_policy" "b71_reader_f45_queues" {
  name = "b71-reader-f45-queues"
  role = aws_iam_role.b71_reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SendOneQueue"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = [aws_sqs_queue.sqs_rp_none.arn]
      },
      {
        Sid      = "PublishDefaultTopic"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.sns_rp_default.arn]
      },
    ]
  })
}

# F45-ACC: account-wide SQS on b71_dual (existing dual-bucket S3 policy unchanged).
resource "aws_iam_role_policy" "b71_dual_sqs_account" {
  name = "b71-dual-sqs-account"
  role = aws_iam_role.b71_dual.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllSQS"
      Effect   = "Allow"
      Action   = ["sqs:*"]
      Resource = ["*"]
    }]
  })
}
