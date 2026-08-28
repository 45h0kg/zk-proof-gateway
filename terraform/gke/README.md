# GKE reference module -- UNAPPLIED

Stands up a small GKE cluster (one demo node pool) and installs the
`zk-proof-gateway` Helm chart from `../../helm/zk-proof-gateway`.

**This module has only been `terraform validate`d and `terraform fmt
-check`ed.** It has not been applied against a real GCP project -- review
the node count/machine type (cost), IAM scope, and the chart's
`values.yaml` (image repo/tag, registry contents) before running `apply`
yourself.

Deliberately does not touch Confidential Space -- that's out of scope for
this pass; see the root README's security status and `Spec.md`.

```bash
terraform init
terraform validate
terraform fmt -check
# terraform apply -var project_id=<your-gcp-project>   # NOT run here
```
