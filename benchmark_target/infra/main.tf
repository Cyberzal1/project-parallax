terraform {
  required_version = ">= 1.6.0"
}

resource "google_service_account" "sa_agent_runner" {
  account_id   = "sa-agent-runner"
  display_name = "Vertex AI Ops Agent Service Account"
}

resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name     = "vertex-ops-agent"
  location = "asia-southeast1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.sa_agent_runner.email
    containers {
      image = "asia-southeast1-docker.pkg.dev/gcp-sg-parallax-sandbox/agents/v:1"
    }
  }
}

resource "google_secret_manager_secret" "workspace_doc_quarterly_notes" {
  secret_id = "workspace-doc-quarterly-notes"
}

resource "google_project_iam_member" "agent_secret_accessor" {
  project = "gcp-sg-parallax-sandbox"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}

resource "google_project_iam_member" "agent_token_creator" {
  project = "gcp-sg-parallax-sandbox"
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
