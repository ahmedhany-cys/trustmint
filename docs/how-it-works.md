# How TrustMint works

## The question

A federation trust says: *a token from issuer X whose claims satisfy condition C may act as
identity Y.* The security question is not whether C contains a wildcard, but **who can
obtain a token from X that satisfies C**. That depends on two things the cloud policy does
not show: the format of X's tokens, and which parts of a token each kind of user controls.

TrustMint encodes both per CI platform, then searches for a token each class of actor can
really obtain that the trust accepts.

## One condition tree

Sources translate each cloud's syntax into a small expression tree
(`src/trustmint/conditions.py`): `Match(claim, op, values)` with `equals`, `glob`, `prefix`,
`suffix`, `contains`, `regex` and `present`, combined with `AllOf`, `AnyOf` and `Not`.

Evaluation is three-valued. `Unknown` nodes (unmodeled operators, keys or functions)
evaluate to *undecided*, and Kleene logic keeps that honest: `false AND undecided` is false,
`true AND undecided` is undecided.

| Cloud | Translation |
|---|---|
| AWS | Each Allow statement with `sts:AssumeRoleWithWebIdentity` and a `Federated` principal becomes one trust. Condition operators map to `Match` nodes; `IfExists`, `ForAnyValue`, `ForAllValues` (vacuously true on a missing key) and `Null` follow IAM semantics. Deny statements for the same principal are added as `NOT`. The provider's client ID list becomes the audience check. Keys for another provider can never be present; `aws:*` keys are undecidable. |
| Google | A `GcpFederation` node runs the provider's attribute mapping (CEL) on the claims, rejects tokens without `google.subject`, evaluates the attribute condition (CEL errors reject the token, as Google does), then applies the IAM binding's member filter: a subject, an attribute value, or the whole pool. A binding on a pool is evaluated once per provider in that pool. |
| Entra | Classic credentials compare `sub` exactly. Flexible credentials' `claimsMatchingExpression` is parsed (`eq`, `matches` with `*`, `and`, `or`, parentheses). |

## Platform token models

Each model (`src/trustmint/platforms/`) knows the claims its issuer emits and builds
candidate tokens per actor class. Candidates come from three places:

1. **The trust's own literals.** Every string the condition compares with is collected,
   with the claim it is compared against. Exact literals tell TrustMint which owners,
   repositories, refs and IDs the trust names.
2. **Wildcard instantiation.** Wildcards (and prefix, suffix, contains and simple regex
   comparisons) are filled with attacker-chosen text, including structural text such as
   `attacker/attacker:ref:refs/heads/attacker`, then parsed back with the platform's subject
   grammar. This is how `repo:acme*` yields an organization called `acmeattacker`.
   Results that the platform could not produce, like a branch name containing `:`, are
   dropped.
3. **Fresh probes.** `tm-probe-owner`, `tm-probe-repo`, `tm-probe-branch` and so on stand for
   "something the actor creates".

Each candidate is classified by who could mint it:

- the owner is not one you own → **PUBLIC** (capped to TENANT for issuers dedicated to one
  organization, enterprise or cluster);
- the repository/project/workspace/namespace is not one the trust names or the context
  declares → **TENANT**;
- the ref is a pull request, an unprotected branch or tag, a `plan` phase, or any service
  account in a namespace → **PROJECT**;
- otherwise → **PROTECTED**, with the protection assumption stated.

The analyzer keeps the broadest class whose token passes the trust and its audience check.
Because the CI job chooses the audience on GitHub, GitLab, HCP Terraform and Kubernetes,
TrustMint tries every audience the trust accepts; on CircleCI the audience is fixed to the
organization ID.

### GitHub Actions

| Claim | Controlled by |
|---|---|
| owner, repository | anyone, for accounts and repositories they create |
| repository in an org | org members who can create or push to repositories |
| ref / branch / tag | anyone with push access to the repository |
| environment | anyone who can run a job targeting it, unless deployment protection rules restrict branches |
| `pull_request` subject | same-repository pull requests (fork pull requests do not get `id-token: write`) |
| `job_workflow_ref` | any caller that can use the reusable workflow |
| audience | the job (`core.getIDToken(audience)`) |

Subjects come in two formats. GitHub's changelog of 23 April 2026 introduced immutable
subjects, `repo:OWNER@OWNER_ID/REPO@REPO_ID:...`. Microsoft's migration guide (July 2026)
states that from 15 July 2026 GitHub applies them automatically to repositories that are
created, renamed or transferred, and that existing repositories keep name-based subjects
until they opt in; immutable subjects are not available on GitHub Enterprise Server.
TrustMint therefore:

- generates both formats for existing repositories, and immutable ones for anything an
  attacker creates now (with a note when only a legacy-format witness matches);
- tests subject recycling (TM005) by re-minting the witness with new IDs in the format a
  recreated repository would get;
- reports trusts that only accept the name-based format (TM010).

The `repository` claim stays name-based, so bindings on it remain recyclable.

### GitLab CI

`project_path:GROUP[/SUBGROUP]/PROJECT:ref_type:branch|tag:ref:REF`, plus `namespace_path`,
`project_path`, `ref_protected` and ID claims. Anyone can create a top-level group on
gitlab.com. A candidate on a protected ref carries `ref_protected: "true"`; an unprotected
one `"false"`, so conditions that check `ref_protected` (possible on Google and flexible
Entra credentials, not on AWS) are credited.

### HCP Terraform

`organization:ORG:project:PROJECT:workspace:WS:run_phase:plan|apply`, per HashiCorp's
workload identity token documentation. Anyone can create an organization on
app.terraform.io. Plan-phase tokens are available to anyone who can queue a plan, so
trusts that accept `run_phase:*` are PROJECT; apply-only trusts are PROTECTED, assuming
applies need approval.

### CircleCI

Issuer `https://oidc.circleci.com/org/ORG_ID` (one per organization), subject
`org/ORG_ID/project/PROJECT_ID/user/USER_ID`, audience fixed to the organization ID. The V1
subject has no branch, so a trust on the subject alone is PROJECT at best; branch or
context restrictions need the `oidc.circleci.com/vcs-ref` or `context-ids` claims.

### Kubernetes (EKS IRSA and others)

`system:serviceaccount:NAMESPACE:NAME`, one issuer per cluster. Wildcard namespaces are
TENANT (anyone who can create a namespace or service account anywhere in the cluster),
wildcard names are PROJECT, an exact service account is PROTECTED. Other Kubernetes issuers
(AKS, GKE, self-managed) are recognized when declared in the context.

## Workflow analysis

`src/trustmint/workflows.py` reads `.github/workflows/*.yml` and keeps jobs whose effective
permissions include `id-token: write` (job permissions replace workflow permissions;
`write-all` counts). For jobs triggered by `pull_request_target`, `workflow_run` or
`issue_comment`, it records whether the job checks out pull request code and which cloud
identities its steps name (`role-to-assume`, `workload_identity_provider`,
`service_account`, `client-id`).

The analyzer then builds the token such a job would get (the base branch or the job's
environment, both subject formats, the triggering event) and tests every GitHub trust
against it. Trusts that are already PUBLIC are skipped; for the rest a match is TM004.

## Ranking witnesses

Many tokens can satisfy a trust at the same reach. The reported witness prefers immutable
subjects for things an attacker creates, legacy subjects for existing repositories, values
the attacker obviously chose (`attacker`, `tm-probe-*`), branch pushes over tags or
environments, and then the shortest subject.

## Assumptions TrustMint states

- Owners and repositories: from the context file, otherwise inferred from the trust.
- Protected refs: from the context file, otherwise `main`, `master` and refs the trust pins
  exactly are assumed protected.
- Environments pinned by a trust are assumed to have deployment protection rules.
- Reusable workflows named by `job_workflow_ref` are assumed callable by the caller in the
  witness.

Each finding lists the assumptions its witness depends on.
