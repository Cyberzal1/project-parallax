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

# Non-Human Identity (NHI) for the Cloud Run Vertex AI Agent
resource "google_service_account" "sa_agent_runner" {
  account_id   = "sa-agent-runner"
  display_name = "Vertex AI Workspace Ops Agent Service Account"
}

# Publicly reachable Cloud Run v2 Service hosting the AI Agent
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

# INTENTIONAL ARCHITECTURAL FLAW (Step 01 Prepare / Step 02 Scan Blindspot):
# Grants project-wide Secret Manager access instead of scoping to non-sensitive workspace secrets.
resource "google_project_iam_member" "agent_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}

# Secondary transitive privilege risk: allows token minting on the project
resource "google_project_iam_member" "agent_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
