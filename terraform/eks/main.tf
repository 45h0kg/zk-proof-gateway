# Minimal reference module: a small EKS cluster (own VPC, two public
# subnets, one node group) + the zk-proof-gateway Helm chart. UNAPPLIED
# reference code -- see README.md in this directory. Deliberately does NOT
# touch Nitro Enclaves; that is out of scope for this pass (see Spec.md P3
# and the root README's security status).

provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "zkgw" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.cluster_name}-vpc" }
}

resource "aws_internet_gateway" "zkgw" {
  vpc_id = aws_vpc.zkgw.id
  tags   = { Name = "${var.cluster_name}-igw" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.zkgw.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name                                        = "${var.cluster_name}-public-${count.index}"
    "kubernetes.io/role/elb"                    = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.zkgw.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.zkgw.id
  }
  tags = { Name = "${var.cluster_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "zkgw" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids = aws_subnet.public[*].id
  }

  depends_on = [aws_iam_role_policy_attachment.cluster_policy]
}

resource "aws_iam_role" "node" {
  name = "${var.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_eks_node_group" "zkgw" {
  cluster_name    = aws_eks_cluster.zkgw.name
  node_group_name = "${var.cluster_name}-ng"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = aws_subnet.public[*].id
  instance_types  = [var.node_instance_type]

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = 1
    max_size     = var.node_desired_size + 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr,
  ]
}

data "aws_eks_cluster_auth" "zkgw" {
  name = aws_eks_cluster.zkgw.name
}

provider "kubernetes" {
  host                   = aws_eks_cluster.zkgw.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.zkgw.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.zkgw.token
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.zkgw.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.zkgw.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.zkgw.token
  }
}

resource "helm_release" "zkgw" {
  name      = "zkgw"
  chart     = "${path.module}/../../helm/zk-proof-gateway"
  namespace = "default"

  depends_on = [aws_eks_node_group.zkgw]

  # Image repo/tag, registry contents, and networkPolicy.enabled all come
  # from the chart's own values.yaml / --set overrides at apply time --
  # nothing cluster-specific is hardcoded here.
}
