# Thin ECS app module so Fray can read container_definitions from the *root*
# module call (valueFrom = module.secret_*.arn) when planned values are unknown.
# Plan-only; never apply.

variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

# Passed from the root module call; Fray's readRootContainers parses this.
variable "container_definitions" {
  type = any
}

# Optional ARN so callRefs(module.ecs_*) includes the bucket for the
# data.aws_iam_policy_document null-resources path (IAM shape b).
variable "bucket_arn" {
  type    = string
  default = ""
}

locals {
  assume_ecs = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = local.assume_ecs
}

resource "aws_ecs_cluster" "this" {
  name = var.name
}

resource "aws_ecs_task_definition" "app" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.task.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions    = jsonencode([for name, c in var.container_definitions : merge({ name = name }, c)])
}

resource "aws_security_group" "ecs" {
  name   = "${var.name}-ecs"
  vpc_id = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_service" "app" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  tags = {
    Name            = var.name
    coverage_bucket = var.bucket_arn != "" ? var.bucket_arn : "none"
  }
}

output "task_role_id" {
  value = aws_iam_role.task.id
}

output "task_role_name" {
  value = aws_iam_role.task.name
}
