# EKS reference module -- UNAPPLIED

Stands up a small EKS cluster (its own VPC, two public subnets across two
AZs, one node group) and installs the `zk-proof-gateway` Helm chart from
`../../helm/zk-proof-gateway`.

**This module has only been `terraform validate`d and `terraform fmt
-check`ed.** It has not been applied against a real AWS account -- review
the instance type/desired size (cost), IAM scope, and the chart's
`values.yaml` (image repo/tag, registry contents) before running `apply`
yourself.

Deliberately does not touch Nitro Enclaves -- that's out of scope for this
pass; see the root README's security status and `Spec.md`.

**State security:** this module uses local Terraform state by default,
which is unencrypted and can contain a short-lived cluster auth token
(from `data.aws_eks_cluster_auth`) in plaintext. For anything beyond a
disposable local run, configure a remote backend with encryption at rest
(e.g. an S3 bucket with SSE-KMS) instead of local state.

```bash
terraform init
terraform validate
terraform fmt -check
# terraform apply   # NOT run here
```
