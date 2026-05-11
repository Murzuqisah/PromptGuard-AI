terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "GCP project ID"
}
variable "region" {
  default = "us-central1"
}
variable "gemini_api_key" {
  sensitive = true
}
variable "api_keys" {
  description = "Comma-separated API keys"
  sensitive   = true
}
variable "domain" {
  description = "Custom domain (optional)"
  default     = ""
}

# ─── Secrets ──────────────────────────────────────────────────────────────────

resource "google_secret_manager_secret" "gemini_key" {
  secret_id = "promptguard-gemini-key"
  replication { auto {} }
}

resource "google_secret_manager_secret_version" "gemini_key" {
  secret      = google_secret_manager_secret.gemini_key.id
  secret_data = var.gemini_api_key
}

resource "google_secret_manager_secret" "api_keys" {
  secret_id = "promptguard-api-keys"
  replication { auto {} }
}

resource "google_secret_manager_secret_version" "api_keys" {
  secret      = google_secret_manager_secret.api_keys.id
  secret_data = var.api_keys
}

# ─── Cloud Run Service ────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "api" {
  name     = "promptguard-api"
  location = var.region

  template {
    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      image = "gcr.io/${var.project_id}/promptguard-api:latest"

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "PROMPTGUARD_HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "PROMPTGUARD_PORT"
        value = "8000"
      }
      env {
        name  = "PROMPTGUARD_API_AUTH_ENABLED"
        value = "true"
      }
      env {
        name  = "GEMINI_ENABLED"
        value = "true"
      }
      env {
        name = "GEMINI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gemini_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "PROMPTGUARD_API_KEYS"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.api_keys.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get { path = "/health" }
        initial_delay_seconds = 5
      }
      liveness_probe {
        http_get { path = "/health" }
        period_seconds = 30
      }
    }
  }

  traffic {
    percent = 100
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
  }
}

# ─── Public Access ────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.api.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "service_url" {
  value = google_cloud_run_v2_service.api.uri
}
