# PromptGuard AI — Deployment Guide

Production deployment options for PromptGuard AI.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Self-Hosted Docker Compose with TLS](#self-hosted-docker-compose-with-tls)
3. [AWS ECS/Fargate with ALB](#aws-ecsfargate-with-alb)
4. [GCP Cloud Run](#gcp-cloud-run)
5. [Production Checklist](#production-checklist)

---

## Prerequisites

- Docker and Docker Compose installed
- A domain name (for TLS)
- API keys generated for your services
- (Optional) Gemini API key for AI-enhanced detection

---

## Self-Hosted Docker Compose with TLS

The simplest production deployment using nginx as a TLS-terminating reverse proxy.

### Directory Structure

```
/opt/promptguard/
├── docker-compose.prod.yml
├── .env
├── nginx/
│   └── nginx.conf
└── certs/
    ├── fullchain.pem
    └── privkey.pem
```

### 1. Create production compose file

Use `deploy/docker-compose.prod.yml` from this repository.

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
PROMPTGUARD_API_AUTH_ENABLED=true
PROMPTGUARD_API_KEYS=pk_prod_your_key_here
PROMPTGUARD_CORS_ORIGINS=https://your-domain.com
GEMINI_API_KEY=your-gemini-key
PROMPTGUARD_WEBHOOK_URLS=https://your-siem.com/webhook
```

### 3. Obtain TLS certificates

```bash
# Using Let's Encrypt / certbot
certbot certonly --standalone -d guard.your-domain.com
cp /etc/letsencrypt/live/guard.your-domain.com/fullchain.pem certs/
cp /etc/letsencrypt/live/guard.your-domain.com/privkey.pem certs/
```

### 4. Deploy

```bash
docker compose -f docker-compose.prod.yml up -d
```

API available at `https://guard.your-domain.com`

---

## AWS ECS/Fargate with ALB

Serverless container deployment with auto-scaling and managed load balancing.

### Architecture

```
Internet → ALB (TLS) → ECS Fargate Tasks → PromptGuard API
                                          → PromptGuard Dashboard
```

### Deploy with Terraform

```bash
cd deploy/aws
terraform init
terraform plan -var="domain=guard.your-domain.com"
terraform apply
```

### Required Variables

| Variable | Description |
|----------|-------------|
| `domain` | Domain for the ALB certificate |
| `vpc_id` | VPC to deploy into |
| `subnet_ids` | Private subnets for Fargate tasks |
| `public_subnet_ids` | Public subnets for ALB |
| `gemini_api_key` | Gemini API key (stored in Secrets Manager) |
| `api_keys` | Comma-separated API keys |

### Key Resources Created

- ECS Cluster (Fargate)
- Task Definition (512 CPU, 1024 MB)
- ALB with HTTPS listener
- ACM certificate (auto-validated via DNS)
- CloudWatch log group
- Security groups (ALB → tasks on port 8000)
- Secrets Manager secret for API keys

### Scaling

The Terraform template includes auto-scaling based on CPU utilization:
- Min: 1 task
- Max: 10 tasks
- Scale up at 70% CPU

---

## GCP Cloud Run

Fully managed serverless deployment with automatic scaling to zero.

### Deploy with gcloud CLI

```bash
# Build and push
gcloud builds submit --tag gcr.io/YOUR_PROJECT/promptguard-api ./

# Deploy
gcloud run deploy promptguard-api \
  --image gcr.io/YOUR_PROJECT/promptguard-api \
  --platform managed \
  --region us-central1 \
  --port 8000 \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 10 \
  --set-env-vars "PROMPTGUARD_API_AUTH_ENABLED=true" \
  --set-secrets "GEMINI_API_KEY=promptguard-gemini-key:latest,PROMPTGUARD_API_KEYS=promptguard-api-keys:latest" \
  --allow-unauthenticated
```

### Deploy with Terraform

```bash
cd deploy/gcp
terraform init
terraform plan -var="project_id=your-project"
terraform apply
```

### Key Resources Created

- Cloud Run service
- Secret Manager secrets for API keys
- Custom domain mapping (optional)
- Cloud Armor WAF policy (optional)

---

## Production Checklist

### Security

- [ ] `PROMPTGUARD_API_AUTH_ENABLED=true`
- [ ] Strong API keys generated (32+ chars, random)
- [ ] `PROMPTGUARD_CORS_ORIGINS` restricted to your domains only
- [ ] TLS termination configured (ALB, Cloud Run, or nginx)
- [ ] API keys stored in secret manager (not in env files on disk)
- [ ] Rate limiting configured appropriately for your traffic

### Monitoring

- [ ] Health check configured on `/health`
- [ ] Log aggregation set up (CloudWatch, Cloud Logging, ELK)
- [ ] Alerts on 5xx error rate
- [ ] Dashboard polling `/v1/stats` for threat metrics
- [ ] Webhook alerts configured for DENY events

### Performance

- [ ] At least 2 instances for high availability
- [ ] Auto-scaling configured based on CPU/request count
- [ ] Database on persistent volume (EFS, GCS, or local SSD)
- [ ] Gemini API quota sufficient for your scan volume

### Data

- [ ] SQLite database on persistent storage (not ephemeral container filesystem)
- [ ] Backup strategy for policy database
- [ ] Audit log retention policy defined
- [ ] SARIF export scheduled for GitHub integration
