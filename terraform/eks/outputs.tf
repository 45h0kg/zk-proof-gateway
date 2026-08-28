output "cluster_endpoint" {
  value = aws_eks_cluster.zkgw.endpoint
}

output "cluster_name" {
  value = aws_eks_cluster.zkgw.name
}
