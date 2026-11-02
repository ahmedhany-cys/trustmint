# Changelog

## 0.1.0 (2026-11-02)

First release.

- Reach analysis (PUBLIC, TENANT, PROJECT, PROTECTED, NONE) with witness tokens.
- Sources: AWS IAM role trust policies and OIDC providers, Google workload identity pool
  providers and IAM bindings, Entra classic and flexible federated identity credentials,
  Terraform plan JSON.
- Platforms: GitHub Actions (name-based and immutable subjects, enterprise issuers),
  GitLab CI, HCP Terraform, CircleCI, Kubernetes/EKS.
- GitHub workflow analysis for untrusted triggers with `id-token: write`.
- Rules TM001 to TM010; text, Markdown, JSON and SARIF output; `explain`, `selfcheck`,
  `collect aws`, `assemble`; composite GitHub Action.
