variable "project_id" {
  description = "GCP project id to deploy into."
  type        = string
}

variable "region" {
  description = "GCP region for the cluster."
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  type    = string
  default = "zkgw-demo"
}

variable "node_count" {
  description = "Node count for the small demo node pool."
  type        = number
  default     = 1
}

variable "machine_type" {
  type    = string
  default = "e2-small"
}
