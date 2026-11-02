# Rules

Every finding has a rule ID, a severity, the identity and issuer, the actor who can mint a
matching token, a witness token where there is one, the assumptions it rests on, and a fix.

## TM001

**Anyone on the CI platform can assume this identity.** Severity: critical.

A token minted by an account the attacker creates (or registers, for a lookalike name)
satisfies the trust. Typical causes: no subject condition at all; a wildcard in the owner
(`repo:acme*`, `repo:*`); a Google provider without an attribute condition bound pool-wide;
a GitLab `namespace_path.startsWith('acme')` without a trailing `/`; a Terraform trust that
wildcards the organization.

**Fix:** match the full subject exactly, with the owner/organization/group spelled out and
followed by its delimiter. Prefer immutable identifiers where the platform has them.

## TM002

**Any repository or project in the organization can assume this identity.** Severity:
high, critical when the identity has admin privileges.

The owner is pinned but the repository, project, workspace or namespace is not
(`repo:acme/*`, `project_path:acme/*`, `workspace:*`, `system:serviceaccount:*`). Every
member who can create a repository, or push to any existing one, controls a workflow that
can mint the token.

**Fix:** one trust per repository and context. For shared deployment pipelines, pin a
reusable workflow (`job_workflow_ref`) where the cloud can read that claim *and* restrict
which repositories may call it.

## TM003

**Unprotected branches, pull requests or plans can assume this identity.** Severity:
medium, high when the identity can write or administer.

The repository is pinned but the ref is not (`repo:acme/infra:*`), the trust accepts
`pull_request`, a Terraform trust accepts `run_phase:plan`, a CircleCI trust accepts any
pipeline in a project, or a Kubernetes trust accepts any service account in a namespace.
Anyone with push access can mint the token from a branch that skips review.

**Fix:** pin a protected branch or, better, a GitHub environment with required reviewers
and a deployment branch policy (`repo:O/R:environment:production`). Use separate read-only
roles for pull requests and Terraform plans.

## TM004

**A workflow with an untrusted trigger can mint a token this identity accepts.**
Severity: critical if the job checks out and runs pull request code, medium otherwise.

`pull_request_target`, `workflow_run` and `issue_comment` run in the base repository's
context, so their tokens carry the base branch (`ref:refs/heads/main`). If the job has
`id-token: write`, even an exactly pinned trust accepts its tokens. When the job also checks
out the pull request head, anyone who can open a pull request runs code with the identity.

**Fix:** never give `id-token: write` to these triggers. Build untrusted code in a
`pull_request` job with no cloud access; deploy from a separate job on push to a protected
branch, behind an environment with required reviewers.

## TM005

**The trust is bound to names that someone else could take over.** Severity: low, medium
for admin identities.

TrustMint re-mints the witness token with new owner and repository IDs, as if the name had
been released and claimed by someone else. If the trust still matches, it trusts names.
On GitHub this affects bindings on the name-based `repository` / `repository_owner` claims
(for example Google `attribute.repository/acme/app` bindings) and GitHub Enterprise Server
subjects. Exact name-based AWS or Entra subjects are *not* flagged on github.com, because a
recreated repository receives an immutable subject that no longer matches them.

**Fix:** bind to `repository_id` and `repository_owner_id`, or to the immutable subject
`repo:OWNER@OWNER_ID/REPO@REPO_ID:...`. On GitLab, use `project_id`.

## TM006

**No token satisfies this trust.** Severity: info.

Usually `StringEquals` with a `*` (the wildcard is compared literally), a classic Entra
credential with a wildcard subject, or a subject for a repository or format that no longer
exists. Dead trusts are harmless until someone "fixes" them by widening them.

**Fix:** delete the trust, or correct it to the exact subject of the pipeline that uses it.

## TM007

**The issuer is not a CI platform TrustMint models.** Severity: info, high when the trust
checks no claims at all.

Examples: `accounts.google.com`, Cognito, Bitbucket, Buildkite, a self-hosted GitLab or GHES
that the context file does not declare.

**Fix:** declare self-hosted issuers in the context (`issuers`). Review the rest by hand and
require an exact subject and audience.

## TM008

**The trust could not be fully evaluated.** Severity: info.

Part of the condition uses something TrustMint does not model (an `aws:SourceIp` key, a CEL
function such as `extract()`, an Entra operator other than `eq`/`matches`, a `google.groups`
binding). The reported reach is a lower bound.

## TM009

**A workflow runs untrusted code with `id-token: write`.** Severity: high.

Same pattern as TM004, but none of the trusts in the inputs accepts the job's token. Any
trust you add for that repository's default branch later would be exposed immediately.

## TM010

**The trust only accepts name-based GitHub subjects.** Severity: info.

Since 2026, GitHub issues immutable subjects (`repo:OWNER@ID/REPO@ID:...`) for repositories
created, renamed or transferred after the switch, and for repositories that opt in. A trust
that only accepts `repo:OWNER/REPO:...` will stop working when its repository migrates.

**Fix:** add the immutable subject alongside the old one, opt the repository in, confirm the
workflow works, then remove the name-based subject.
