# Minimal reference module: a small GKE cluster + the zk-proof-gateway Helm
# chart. UNAPPLIED reference code -- see README.md in this directory.
# Deliberately does NOT touch Confidential Space; that is out of scope for
# this pass (see Spec.md P3 and the root README's security status).

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_container_cluster" "zkgw" {
  name     = var.cluster_name
  location = var.region

  # Managed via the dedicated node pool below instead of the default one.
  remove_default_node_pool = true
  initial_node_count       = 1
}

resource "google_container_node_pool" "zkgw_nodes" {
  name       = "${var.cluster_name}-pool"
  location   = var.region
  cluster    = google_container_cluster.zkgw.name
  node_count = var.node_count

  node_config {
    machine_type = var.machine_type
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.zkgw.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.zkgw.master_auth[0].cluster_ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = "https://${google_container_cluster.zkgw.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(google_container_cluster.zkgw.master_auth[0].cluster_ca_certificate)
  }
}

resource "helm_release" "zkgw" {
  name      = "zkgw"
  chart     = "${path.module}/../../helm/zk-proof-gateway"
  namespace = "default"

  depends_on = [google_container_node_pool.zkgw_nodes]

  # Image repo/tag, registry contents (governance pub key, signed
  # predicates), and networkPolicy.enabled all come from the chart's own
  # values.yaml / --set overrides at apply time -- nothing cluster-specific
  # is hardcoded here.
}
