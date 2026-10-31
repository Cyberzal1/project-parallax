terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project_id" {
  type    = string
  default = "gcp-sg-parallax-sandbox"
}

resource "google_service_account" "sa_agent_runner" {
  account_id   = "sa-agent-runner"
  display_name = "Vertex AI Workspace Ops Agent Service Account"
}

resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name     = "vertex-ops-agent"
  location = "asia-southeast1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.sa_agent_runner.email
    containers {
      image = "asia-southeast1-docker.pkg.dev/gcp-sg-parallax-sandbox/agents/vertex-ops:1.0.0"
    }
  }
}

# [FLAW] Project-wide SecretAccessor binding granting access to ALL secrets
resource "google_project_iam_member" "project_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}

# [FLAW] Project-wide TokenCreator binding allowing transitive SA impersonation
resource "google_project_iam_member" "project_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
