terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1"
}
variable "domain" {
  description = "Domain for the ALB (e.g., guard.company.com)"
}
variable "vpc_id" {}
variable "subnet_ids" {
  type = list(string)
}
variable "public_subnet_ids" {
  type = list(string)
}
variable "gemini_api_key" {
  sensitive = true
}
variable "api_keys" {
  description = "Comma-separated API keys"
  sensitive   = true
}

# ─── ECR ──────────────────────────────────────────────────────────────────────

resource "aws_ecr_repository" "api" {
  name                 = "promptguard-api"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
}

# ─── ECS Cluster ──────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "main" {
  name = "promptguard"
}

# ─── Secrets ──────────────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "api_config" {
  name = "promptguard/api-config"
}

resource "aws_secretsmanager_secret_version" "api_config" {
  secret_id = aws_secretsmanager_secret.api_config.id
  secret_string = jsonencode({
    GEMINI_API_KEY                = var.gemini_api_key
    PROMPTGUARD_API_KEYS          = var.api_keys
    PROMPTGUARD_API_AUTH_ENABLED   = "true"
  })
}

# ─── IAM ──────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "task_execution" {
  name = "promptguard-task-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "secrets_access" {
  name = "secrets-access"
  role = aws_iam_role.task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.api_config.arn] }]
  })
}

# ─── CloudWatch ───────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/promptguard-api"
  retention_in_days = 30
}

# ─── Security Groups ─────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name   = "promptguard-alb"
  vpc_id = var.vpc_id
  ingress { from_port = 443; to_port = 443; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "tasks" {
  name   = "promptguard-tasks"
  vpc_id = var.vpc_id
  ingress { from_port = 8000; to_port = 8000; protocol = "tcp"; security_groups = [aws_security_group.alb.id] }
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
}

# ─── ALB ──────────────────────────────────────────────────────────────────────

resource "aws_lb" "main" {
  name               = "promptguard-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "api" {
  name        = "promptguard-api"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check { path = "/health"; interval = 30 }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.main.arn
  default_action { type = "forward"; target_group_arn = aws_lb_target_group.api.arn }
}

resource "aws_acm_certificate" "main" {
  domain_name       = var.domain
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
}

# ─── Task Definition ─────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "api" {
  family                   = "promptguard-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([{
    name  = "api"
    image = "${aws_ecr_repository.api.repository_url}:latest"
    portMappings = [{ containerPort = 8000 }]
    environment = [
      { name = "PROMPTGUARD_HOST", value = "0.0.0.0" },
      { name = "PROMPTGUARD_PORT", value = "8000" },
      { name = "GEMINI_ENABLED", value = "true" },
    ]
    secrets = [
      { name = "GEMINI_API_KEY", valueFrom = "${aws_secretsmanager_secret.api_config.arn}:GEMINI_API_KEY::" },
      { name = "PROMPTGUARD_API_KEYS", valueFrom = "${aws_secretsmanager_secret.api_config.arn}:PROMPTGUARD_API_KEYS::" },
      { name = "PROMPTGUARD_API_AUTH_ENABLED", valueFrom = "${aws_secretsmanager_secret.api_config.arn}:PROMPTGUARD_API_AUTH_ENABLED::" },
    ]
    logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = aws_cloudwatch_log_group.api.name, "awslogs-region" = var.region, "awslogs-stream-prefix" = "api" } }
  }])
}

# ─── Service ──────────────────────────────────────────────────────────────────

resource "aws_ecs_service" "api" {
  name            = "promptguard-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.subnet_ids
    security_groups = [aws_security_group.tasks.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }
}

# ─── Auto Scaling ─────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "api" {
  max_capacity       = 10
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification { predefined_metric_type = "ECSServiceAverageCPUUtilization" }
    target_value = 70.0
  }
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "alb_dns" {
  value = aws_lb.main.dns_name
}

output "ecr_url" {
  value = aws_ecr_repository.api.repository_url
}
