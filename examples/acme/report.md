# TrustMint report

20 federation trusts analysed from `examples/acme/snapshot.json`.

| Severity | Findings |
|---|---|
| critical | 11 |
| high | 7 |
| medium | 3 |
| low | 1 |
| info | 4 |

## Reach per identity

| Reach | Identity | Cloud | Issuer | Privilege | Who can mint a matching token |
|---|---|---|---|---|---|
| **PUBLIC** | `analytics-reader@acme-prod.iam.gserviceaccount.com` | gcp | github | read | any GitHub user, from a repository in an account they create |
| **PUBLIC** | `arn:aws:iam::111122223333:role/gh-ci-readonly` | aws | github | read | any GitHub user, from a repository in an account they create |
| **PUBLIC** | `arn:aws:iam::111122223333:role/gh-release-main` | aws | github | write | whoever owns or registers the GitHub account or organization `acmeattacker` |
| **PUBLIC** | `projects/acme-artifacts` | gcp | gitlab | write | any GitLab user who creates the group `acme-groupattacker` |
| **TENANT** | `analytics-reader@acme-prod.iam.gserviceaccount.com` | gcp | github | read | any member of `acme` who can create or push to a repository the trust does not name (here `acme/tm-probe-repo`) |
| **TENANT** | `arn:aws:iam::111122223333:role/gh-org-admin` | aws | github | admin | any member of `acme` who can create or push to a repository the trust does not name (here `acme/attacker`) |
| **TENANT** | `platform-automation` | azure | github | admin | any member of `acme` who can create or push to a repository the trust does not name (here `acme/attacker`) |
| **PROJECT** | `arn:aws:iam::111122223333:role/circleci-deploy` | aws | circleci | write | anyone who can trigger a pipeline in project `7d1f0b2e-0000-4000-8000-0000000000dd`, from any branch |
| **PROJECT** | `arn:aws:iam::111122223333:role/eks-payments-irsa` | aws | kubernetes | read | anyone who can create a service account or pod in namespace `payments` (here `attacker`) |
| **PROJECT** | `arn:aws:iam::111122223333:role/gh-infra-any-branch` | aws | github | write | anyone who can push a branch in `acme/infra` (e.g. `attacker`) |
| **PROJECT** | `arn:aws:iam::111122223333:role/tfc-prod-network` | aws | terraform | admin | anyone who can queue a plan in workspace `prod-network` |
| **PROJECT** | `deployer@acme-prod.iam.gserviceaccount.com` | gcp | github | admin | anyone who can push a branch in `acme/data-pipeline` (e.g. `tm-probe-branch`) |
| **PROJECT** | `deployer@acme-prod.iam.gserviceaccount.com` | gcp | github | admin | anyone who can push a branch in `acme/data-pipeline` (e.g. `tm-probe-branch`) |
| **PROTECTED** | `aks-orders-workload` | azure | kubernetes | read | pods running as `orders/orders-api` |
| **PROTECTED** | `arn:aws:iam::111122223333:role/gh-deploy-prod` | aws | github | write | workflows running on the protected environment `production` of `acme/payments-api` |
| **PROTECTED** | `arn:aws:iam::111122223333:role/gh-payments-immutable` | aws | github | write | workflows running on the protected branch `main` of `acme/payments-api` |
| **PROTECTED** | `gitlab-deployer@acme-prod.iam.gserviceaccount.com` | gcp | gitlab | write | pipelines on the protected branch `main` of `acme-group/platform/deployer` |
| **PROTECTED** | `payments-deployer` | azure | github | write | workflows running on the protected branch `main` of `acme/payments-api` |
| **NONE** | `arn:aws:iam::111122223333:role/gh-web-broken` | aws | github | write | nothing (dead trust) |
| **UNDECIDED** | `arn:aws:iam::111122223333:role/google-sso-broker` | aws | generic | read | undecided |

## Findings

### CRITICAL · TM001 · Anyone on the CI platform can assume this identity

- **Identity:** `analytics-reader@acme-prod.iam.gserviceaccount.com` (gcp, privilege read)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by any GitHub user, from a repository in an account they create. The witness token below satisfies the trust and its audience check.
- **Assumes:** `tm-probe-owner` is not one of the declared owners
- **Fix:** Use an attribute condition on `assertion.repository_id` and `assertion.repository_owner_id`, and bind the service account to a single `attribute.repository_id/...` principalSet. Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json gcp.service_accounts[1] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github-legacy`

```json
{
  "sub": "repo:tm-probe-owner@43698738/tm-probe-repo@13741129:ref:refs/heads/main",
  "aud": "https://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github-legacy",
  "repository": "tm-probe-owner/tm-probe-repo",
  "repository_owner": "tm-probe-owner",
  "ref": "refs/heads/main",
  "event_name": "push",
  "job_workflow_ref": "tm-probe-owner/tm-probe-repo/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM001 · Anyone on the CI platform can assume this identity

- **Identity:** `arn:aws:iam::111122223333:role/gh-ci-readonly` (aws, privilege read)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by any GitHub user, from a repository in an account they create. The witness token below satisfies the trust and its audience check.
- **Assumes:** `tm-probe-owner` is not one of the declared owners
- **Fix:** Use StringEquals on `token.actions.githubusercontent.com:sub` (not StringLike). Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json aws.roles[1] Statement[0]`

```json
{
  "sub": "repo:tm-probe-owner@43698738/tm-probe-repo@13741129:ref:refs/heads/main",
  "aud": "sts.amazonaws.com",
  "repository": "tm-probe-owner/tm-probe-repo",
  "repository_owner": "tm-probe-owner",
  "ref": "refs/heads/main",
  "event_name": "push",
  "job_workflow_ref": "tm-probe-owner/tm-probe-repo/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM001 · Anyone on the CI platform can assume this identity

- **Identity:** `arn:aws:iam::111122223333:role/gh-release-main` (aws, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by whoever owns or registers the GitHub account or organization `acmeattacker`. The witness token below satisfies the trust and its audience check.
- **Assumes:** `acmeattacker` is not one of the declared owners
- **Fix:** Use StringEquals on `token.actions.githubusercontent.com:sub` (not StringLike). Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json aws.roles[3] Statement[0]`

```json
{
  "sub": "repo:acmeattacker@87330698/attacker@54139022:ref:refs/heads/main",
  "aud": "sts.amazonaws.com",
  "repository": "acmeattacker/attacker",
  "repository_owner": "acmeattacker",
  "ref": "refs/heads/main",
  "event_name": "push",
  "job_workflow_ref": "acmeattacker/attacker/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM001 · Anyone on the CI platform can assume this identity

- **Identity:** `projects/acme-artifacts` (gcp, privilege write)
- **Issuer:** `https://gitlab.com` (GitLab CI)
- **Why:** Reachable by any GitLab user who creates the group `acme-groupattacker`. The witness token below satisfies the trust and its audience check.
- **Fix:** Pin the full subject `project_path:GROUP/PROJECT:ref_type:branch:ref:main` with an exact match. Where the cloud can read extra claims (Google, flexible Entra credentials), also require `ref_protected == 'true'` and `project_id`, which survives renames.
- **Source:** `examples/acme/snapshot.json gcp.resource_policies[0] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/gitlab-pool/providers/gitlab`

```json
{
  "sub": "project_path:acme-groupattacker/attacker/tm-probe-project:ref_type:branch:ref:main",
  "aud": "https://gitlab.com",
  "ref": "main",
  "project_path": "acme-groupattacker/attacker/tm-probe-project",
  "ref_protected": "true"
}
```

### CRITICAL · TM002 · Any repository or project in the organization can assume this identity

- **Identity:** `arn:aws:iam::111122223333:role/gh-org-admin` (aws, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by any member of `acme` who can create or push to a repository the trust does not name (here `acme/attacker`). The witness token below satisfies the trust and its audience check.
- **Assumes:** Needs a repository that still emits name-based subjects (created before 2026-07-15 and never renamed or transferred). New repositories get immutable subjects, which narrows this path but does not close it: plenty of such repositories already exist.
- **Fix:** Use StringEquals on `token.actions.githubusercontent.com:sub` (not StringLike). Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json aws.roles[2] Statement[0]`

```json
{
  "sub": "repo:acme/attacker:ref:refs/heads/main",
  "aud": "sts.amazonaws.com",
  "repository": "acme/attacker",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "push",
  "job_workflow_ref": "acme/attacker/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM002 · Any repository or project in the organization can assume this identity

- **Identity:** `platform-automation` (azure, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by any member of `acme` who can create or push to a repository the trust does not name (here `acme/attacker`). The witness token below satisfies the trust and its audience check.
- **Assumes:** Needs a repository that still emits name-based subjects (created before 2026-07-15 and never renamed or transferred). New repositories get immutable subjects, which narrows this path but does not close it: plenty of such repositories already exist.
- **Fix:** Use one federated credential per exact subject; in flexible credentials also match `repository_id` and `repository_owner_id`. Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json azure.identities[1].federated_credentials[0]`

```json
{
  "sub": "repo:acme/attacker:ref:refs/heads/main",
  "aud": "api://AzureADTokenExchange",
  "repository": "acme/attacker",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "push",
  "job_workflow_ref": "acme/attacker/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM004 · A workflow with an untrusted trigger can mint a token this identity accepts

- **Identity:** `analytics-reader@acme-prod.iam.gserviceaccount.com` (gcp, privilege read)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview` runs on `pull_request_target` with id-token: write and checks out and runs pull request code, so anyone who can open a pull request controls a job that can mint this token. Its tokens carry the base branch `main`, which this trust accepts.
- **Fix:** Do not grant id-token: write to jobs triggered by pull_request_target, workflow_run or issue_comment. Run untrusted code in a `pull_request` job without cloud access, and deploy from a separate job on push to a protected branch, behind an environment with required reviewers.
- **Source:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview`

```json
{
  "sub": "repo:acme/payments-api:ref:refs/heads/main",
  "aud": "https://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github",
  "repository": "acme/payments-api",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "pull_request_target",
  "job_workflow_ref": "acme/payments-api/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM004 · A workflow with an untrusted trigger can mint a token this identity accepts

- **Identity:** `arn:aws:iam::111122223333:role/gh-org-admin` (aws, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview` runs on `pull_request_target` with id-token: write and checks out and runs pull request code, so anyone who can open a pull request controls a job that can mint this token. Its tokens carry the base branch `main`, which this trust accepts.
- **Fix:** Do not grant id-token: write to jobs triggered by pull_request_target, workflow_run or issue_comment. Run untrusted code in a `pull_request` job without cloud access, and deploy from a separate job on push to a protected branch, behind an environment with required reviewers.
- **Source:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview`

```json
{
  "sub": "repo:acme/payments-api:ref:refs/heads/main",
  "aud": "sts.amazonaws.com",
  "repository": "acme/payments-api",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "pull_request_target",
  "job_workflow_ref": "acme/payments-api/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM004 · A workflow with an untrusted trigger can mint a token this identity accepts

- **Identity:** `arn:aws:iam::111122223333:role/gh-payments-immutable` (aws, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview` runs on `pull_request_target` with id-token: write and checks out and runs pull request code, so anyone who can open a pull request controls a job that can mint this token. Its tokens carry the base branch `main`, which this trust accepts. The job names this identity directly.
- **Fix:** Do not grant id-token: write to jobs triggered by pull_request_target, workflow_run or issue_comment. Run untrusted code in a `pull_request` job without cloud access, and deploy from a separate job on push to a protected branch, behind an environment with required reviewers.
- **Source:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview`

```json
{
  "sub": "repo:acme@4417213/payments-api@921384422:ref:refs/heads/main",
  "aud": "sts.amazonaws.com",
  "repository": "acme/payments-api",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "pull_request_target",
  "job_workflow_ref": "acme/payments-api/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM004 · A workflow with an untrusted trigger can mint a token this identity accepts

- **Identity:** `payments-deployer` (azure, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview` runs on `pull_request_target` with id-token: write and checks out and runs pull request code, so anyone who can open a pull request controls a job that can mint this token. Its tokens carry the base branch `main`, which this trust accepts.
- **Fix:** Do not grant id-token: write to jobs triggered by pull_request_target, workflow_run or issue_comment. Run untrusted code in a `pull_request` job without cloud access, and deploy from a separate job on push to a protected branch, behind an environment with required reviewers.
- **Source:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview`

```json
{
  "sub": "repo:acme/payments-api:ref:refs/heads/main",
  "aud": "api://AzureADTokenExchange",
  "repository": "acme/payments-api",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "pull_request_target",
  "job_workflow_ref": "acme/payments-api/.github/workflows/deploy.yml@refs/heads/main"
}
```

### CRITICAL · TM004 · A workflow with an untrusted trigger can mint a token this identity accepts

- **Identity:** `platform-automation` (azure, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview` runs on `pull_request_target` with id-token: write and checks out and runs pull request code, so anyone who can open a pull request controls a job that can mint this token. Its tokens carry the base branch `main`, which this trust accepts.
- **Fix:** Do not grant id-token: write to jobs triggered by pull_request_target, workflow_run or issue_comment. Run untrusted code in a `pull_request` job without cloud access, and deploy from a separate job on push to a protected branch, behind an environment with required reviewers.
- **Source:** `examples/acme/workflows/payments-api/.github/workflows/pr-preview.yml#preview`

```json
{
  "sub": "repo:acme/payments-api:ref:refs/heads/main",
  "aud": "api://AzureADTokenExchange",
  "repository": "acme/payments-api",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "pull_request_target",
  "job_workflow_ref": "acme/payments-api/.github/workflows/deploy.yml@refs/heads/main"
}
```

### HIGH · TM002 · Any repository or project in the organization can assume this identity

- **Identity:** `analytics-reader@acme-prod.iam.gserviceaccount.com` (gcp, privilege read)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by any member of `acme` who can create or push to a repository the trust does not name (here `acme/tm-probe-repo`). The witness token below satisfies the trust and its audience check.
- **Fix:** Use an attribute condition on `assertion.repository_id` and `assertion.repository_owner_id`, and bind the service account to a single `attribute.repository_id/...` principalSet. Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json gcp.service_accounts[1] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github`

```json
{
  "sub": "repo:acme@34701011/tm-probe-repo@87664473:ref:refs/heads/main",
  "aud": "https://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github",
  "repository": "acme/tm-probe-repo",
  "repository_owner": "acme",
  "ref": "refs/heads/main",
  "event_name": "push",
  "job_workflow_ref": "acme/tm-probe-repo/.github/workflows/deploy.yml@refs/heads/main"
}
```

### HIGH · TM003 · Unprotected branches, pull requests or plans can assume this identity

- **Identity:** `arn:aws:iam::111122223333:role/circleci-deploy` (aws, privilege write)
- **Issuer:** `https://oidc.circleci.com/org/2b7e4c1a-0000-4000-8000-0000000000cc` (CircleCI)
- **Why:** Reachable by anyone who can trigger a pipeline in project `7d1f0b2e-0000-4000-8000-0000000000dd`, from any branch. The witness token below satisfies the trust and its audience check.
- **Fix:** Match the subject prefix `org/ORG_ID/project/PROJECT_ID/` and, where the cloud can read custom claims, `oidc.circleci.com/vcs-ref` or a restricted context id.
- **Source:** `examples/acme/snapshot.json aws.roles[9] Statement[0]`

```json
{
  "sub": "org/2b7e4c1a-0000-4000-8000-0000000000cc/project/7d1f0b2e-0000-4000-8000-0000000000dd/user/attacker",
  "aud": "2b7e4c1a-0000-4000-8000-0000000000cc",
  "oidc.circleci.com/vcs-ref": "refs/heads/main"
}
```

### HIGH · TM003 · Unprotected branches, pull requests or plans can assume this identity

- **Identity:** `arn:aws:iam::111122223333:role/gh-infra-any-branch` (aws, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by anyone who can push a branch in `acme/infra` (e.g. `attacker`). The witness token below satisfies the trust and its audience check.
- **Fix:** Use StringEquals on `token.actions.githubusercontent.com:sub` (not StringLike). Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json aws.roles[4] Statement[0]`

```json
{
  "sub": "repo:acme/infra:ref:refs/heads/attacker",
  "aud": "sts.amazonaws.com",
  "repository": "acme/infra",
  "repository_owner": "acme",
  "ref": "refs/heads/attacker",
  "event_name": "push",
  "job_workflow_ref": "acme/infra/.github/workflows/deploy.yml@refs/heads/attacker"
}
```

### HIGH · TM003 · Unprotected branches, pull requests or plans can assume this identity

- **Identity:** `arn:aws:iam::111122223333:role/tfc-prod-network` (aws, privilege admin)
- **Issuer:** `https://app.terraform.io` (HCP Terraform)
- **Why:** Reachable by anyone who can queue a plan in workspace `prod-network`. The witness token below satisfies the trust and its audience check.
- **Fix:** Pin the organization, project and workspace exactly, and use separate roles for `run_phase:plan` (read-only) and `run_phase:apply`. Never wildcard the organization.
- **Source:** `examples/acme/snapshot.json aws.roles[8] Statement[0]`

```json
{
  "sub": "organization:acme:project:Default Project:workspace:prod-network:run_phase:plan",
  "aud": "aws.workload.identity",
  "terraform_run_phase": "plan"
}
```

### HIGH · TM003 · Unprotected branches, pull requests or plans can assume this identity

- **Identity:** `deployer@acme-prod.iam.gserviceaccount.com` (gcp, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by anyone who can push a branch in `acme/data-pipeline` (e.g. `tm-probe-branch`). The witness token below satisfies the trust and its audience check.
- **Fix:** Use an attribute condition on `assertion.repository_id` and `assertion.repository_owner_id`, and bind the service account to a single `attribute.repository_id/...` principalSet. Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json gcp.service_accounts[0] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github`

```json
{
  "sub": "repo:acme/data-pipeline:ref:refs/heads/tm-probe-branch",
  "aud": "https://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github",
  "repository": "acme/data-pipeline",
  "repository_owner": "acme",
  "ref": "refs/heads/tm-probe-branch",
  "event_name": "push",
  "job_workflow_ref": "acme/data-pipeline/.github/workflows/deploy.yml@refs/heads/tm-probe-branch"
}
```

### HIGH · TM003 · Unprotected branches, pull requests or plans can assume this identity

- **Identity:** `deployer@acme-prod.iam.gserviceaccount.com` (gcp, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Reachable by anyone who can push a branch in `acme/data-pipeline` (e.g. `tm-probe-branch`). The witness token below satisfies the trust and its audience check.
- **Fix:** Use an attribute condition on `assertion.repository_id` and `assertion.repository_owner_id`, and bind the service account to a single `attribute.repository_id/...` principalSet. Pin it to the immutable subject of the one workflow context that needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with deployment protection rules on that environment, or `...:ref:refs/heads/main` with branch protection. Remove wildcards in the owner and repository parts.
- **Source:** `examples/acme/snapshot.json gcp.service_accounts[0] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github-legacy`

```json
{
  "sub": "repo:acme/data-pipeline:ref:refs/heads/tm-probe-branch",
  "aud": "https://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github-legacy",
  "repository": "acme/data-pipeline",
  "repository_owner": "acme",
  "ref": "refs/heads/tm-probe-branch",
  "event_name": "push",
  "job_workflow_ref": "acme/data-pipeline/.github/workflows/deploy.yml@refs/heads/tm-probe-branch"
}
```

### HIGH · TM007 · The issuer is not a CI platform TrustMint models

- **Identity:** `arn:aws:iam::111122223333:role/google-sso-broker` (aws, privilege read)
- **Issuer:** `https://accounts.google.com` (an unrecognized issuer)
- **Why:** The trust accepts any token from https://accounts.google.com: it checks no claims. For a shared issuer that means anyone with an account there.
- **Fix:** Declare the platform behind this issuer in the context file (`issuers`), or review the trust by hand and require an exact subject.
- **Source:** `examples/acme/snapshot.json aws.roles[10] Statement[0]`

### MEDIUM · TM003 · Unprotected branches, pull requests or plans can assume this identity

- **Identity:** `arn:aws:iam::111122223333:role/eks-payments-irsa` (aws, privilege read)
- **Issuer:** `https://oidc.eks.eu-west-1.amazonaws.com/id/7C1A0E5D3B9F4A2E8D6C` (Kubernetes)
- **Why:** Reachable by anyone who can create a service account or pod in namespace `payments` (here `attacker`). The witness token below satisfies the trust and its audience check.
- **Fix:** Use StringEquals on `<issuer>:sub` with the exact `system:serviceaccount:NAMESPACE:NAME`, and `<issuer>:aud` = `sts.amazonaws.com`.
- **Source:** `examples/acme/snapshot.json aws.roles[7] Statement[0]`

```json
{
  "sub": "system:serviceaccount:payments:attacker",
  "aud": "sts.amazonaws.com"
}
```

### MEDIUM · TM005 · The trust is bound to names that someone else could take over

- **Identity:** `deployer@acme-prod.iam.gserviceaccount.com` (gcp, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** The trust still matches when the owner and repository IDs change, so whoever takes over the name `acme/data-pipeline` after it is renamed, transferred or deleted would inherit it. It checks names, which can be reused, rather than immutable IDs.
- **Fix:** Bind to immutable identifiers: GitHub `repository_id` / `repository_owner_id` or the immutable `sub` format, GitLab `project_id`.
- **Source:** `examples/acme/snapshot.json gcp.service_accounts[0] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github`

```json
{
  "sub": "repo:acme@80458764/data-pipeline@60587327:ref:refs/heads/tm-probe-branch",
  "aud": "https://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github",
  "repository": "acme/data-pipeline",
  "repository_owner": "acme",
  "ref": "refs/heads/tm-probe-branch",
  "event_name": "push",
  "job_workflow_ref": "acme/data-pipeline/.github/workflows/deploy.yml@refs/heads/tm-probe-branch"
}
```

### MEDIUM · TM005 · The trust is bound to names that someone else could take over

- **Identity:** `deployer@acme-prod.iam.gserviceaccount.com` (gcp, privilege admin)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** The trust still matches when the owner and repository IDs change, so whoever takes over the name `acme/data-pipeline` after it is renamed, transferred or deleted would inherit it. It checks names, which can be reused, rather than immutable IDs.
- **Fix:** Bind to immutable identifiers: GitHub `repository_id` / `repository_owner_id` or the immutable `sub` format, GitLab `project_id`.
- **Source:** `examples/acme/snapshot.json gcp.service_accounts[0] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github-legacy`

```json
{
  "sub": "repo:acme@80458764/data-pipeline@60587327:ref:refs/heads/tm-probe-branch",
  "aud": "https://iam.googleapis.com/projects/987654321098/locations/global/workloadIdentityPools/github-pool/providers/github-legacy",
  "repository": "acme/data-pipeline",
  "repository_owner": "acme",
  "ref": "refs/heads/tm-probe-branch",
  "event_name": "push",
  "job_workflow_ref": "acme/data-pipeline/.github/workflows/deploy.yml@refs/heads/tm-probe-branch"
}
```

### LOW · TM005 · The trust is bound to names that someone else could take over

- **Identity:** `gitlab-deployer@acme-prod.iam.gserviceaccount.com` (gcp, privilege write)
- **Issuer:** `https://gitlab.com` (GitLab CI)
- **Why:** The trust still matches when the owner and repository IDs change, so whoever takes over the path `acme-group/platform/deployer` after it is renamed, transferred or deleted would inherit it. It checks names, which can be reused, rather than immutable IDs.
- **Fix:** Bind to immutable identifiers: GitHub `repository_id` / `repository_owner_id` or the immutable `sub` format, GitLab `project_id`.
- **Source:** `examples/acme/snapshot.json gcp.service_accounts[2] bindings[0] via projects/987654321098/locations/global/workloadIdentityPools/gitlab-pool/providers/gitlab`

```json
{
  "sub": "project_path:acme-group/platform/deployer:ref_type:branch:ref:main",
  "aud": "https://gitlab.com",
  "ref": "main",
  "project_path": "acme-group/platform/deployer",
  "ref_protected": "true"
}
```

### INFO · TM006 · No token satisfies this trust (dead or broken trust)

- **Identity:** `arn:aws:iam::111122223333:role/gh-web-broken` (aws, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** `sub` is compared with 'repo:acme/web:*' using exact equality, so the wildcard is matched literally (use StringLike, or better, an exact subject). 
- **Fix:** Remove the trust if nothing uses it, or correct it so it names exactly the pipeline that needs it.
- **Source:** `examples/acme/snapshot.json aws.roles[5] Statement[0]`

### INFO · TM010 · The trust only accepts name-based GitHub subjects

- **Identity:** `arn:aws:iam::111122223333:role/gh-deploy-prod` (aws, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Only name-based subjects (`repo:OWNER/REPO:...`) satisfy this trust. It keeps working for repositories that have not opted in, and will stop matching once the repository is renamed, transferred or opted into immutable subjects.
- **Fix:** Plan the migration: add the immutable subject `repo:OWNER@OWNER_ID/REPO@REPO_ID:...` before opting the repository in, then remove the name-based one.
- **Source:** `examples/acme/snapshot.json aws.roles[0] Statement[0]`

### INFO · TM010 · The trust only accepts name-based GitHub subjects

- **Identity:** `arn:aws:iam::111122223333:role/gh-infra-any-branch` (aws, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Only name-based subjects (`repo:OWNER/REPO:...`) satisfy this trust. It keeps working for repositories that have not opted in, and will stop matching once the repository is renamed, transferred or opted into immutable subjects.
- **Fix:** Plan the migration: add the immutable subject `repo:OWNER@OWNER_ID/REPO@REPO_ID:...` before opting the repository in, then remove the name-based one.
- **Source:** `examples/acme/snapshot.json aws.roles[4] Statement[0]`

### INFO · TM010 · The trust only accepts name-based GitHub subjects

- **Identity:** `payments-deployer` (azure, privilege write)
- **Issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Why:** Only name-based subjects (`repo:OWNER/REPO:...`) satisfy this trust. It keeps working for repositories that have not opted in, and will stop matching once the repository is renamed, transferred or opted into immutable subjects.
- **Fix:** Plan the migration: add the immutable subject `repo:OWNER@OWNER_ID/REPO@REPO_ID:...` before opting the repository in, then remove the name-based one.
- **Source:** `examples/acme/snapshot.json azure.identities[0].federated_credentials[0]`
