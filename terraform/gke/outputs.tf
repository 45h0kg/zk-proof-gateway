output "cluster_endpoint" {
  value       = google_container_cluster.zkgw.endpoint
  description = "GKE cluster API endpoint."
}

output "cluster_name" {
  value = google_container_cluster.zkgw.name
}
