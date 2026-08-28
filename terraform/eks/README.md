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

```bash
terraform init
terraform validate
terraform fmt -check
# terraform apply   # NOT run here
```
