# Snapshot format

A snapshot is one JSON file with `"schema": "trustmint/snapshot@1"` and any of the sections
below. Each section uses the shape the cloud's own CLI prints, so exports can be pasted in
with little or no change. [examples/acme/snapshot.json](../examples/acme/snapshot.json) is a
complete example.

```json
{
  "schema": "trustmint/snapshot@1",
  "context": { "owners": [], "repos": [], "protected_refs": {}, "issuers": {} },
  "aws":   { "oidc_providers": [], "roles": [] },
  "gcp":   { "providers": [], "service_accounts": [], "resource_policies": [] },
  "azure": { "identities": [] }
}
```

## context

| Field | Meaning |
|---|---|
| `owners` | GitHub owners, GitLab top-level groups, HCP Terraform organizations you own. When set, anything else is treated as someone else's. |
| `repos` | `owner/repo`, `group/sub/project`, `org/workspace`, a CircleCI project ID, or `k8s:namespace/serviceaccount`. |
| `protected_refs` | `{"owner/repo": ["main", "production"]}`: protected branches, tags and environments. Replaces the default assumption for that repository. |
| `issuers` | `{"https://issuer": {"platform": "github\|gitlab\|terraform\|circleci\|kubernetes", "scope": "public\|tenant"}}` for self-hosted issuers. |

The context can also be passed separately with `--context FILE` and `--owner NAME`.

## aws

`oidc_providers`: `Arn`, `Url`, `ClientIDList`, as from
`aws iam get-open-id-connect-provider`.

`roles`: `RoleName`, `Arn`, `AssumeRolePolicyDocument` (object, JSON string, or the
URL-encoded string the raw IAM API returns), optional `AttachedManagedPolicies`
(`PolicyName`, `PolicyArn`), `InlinePolicies` (`{name: document}`) and `Privilege`
(`read|write|admin`) to override the computed level.

`trustmint collect aws` produces this section from a live account using read-only calls.

## gcp

`providers`: objects from

```bash
gcloud iam workload-identity-pools providers list --workload-identity-pool=POOL --location=global --project=PROJECT --format=json
```

`service_accounts`: `email`, `iam_policy` (from
`gcloud iam service-accounts get-iam-policy EMAIL --format=json`), optional `roles` (roles
the service account holds, for the privilege level) and `privilege`. Bindings with
`roles/iam.workloadIdentityUser`, `roles/iam.serviceAccountTokenCreator` or
`roles/iam.serviceAccountOpenIdTokenCreator` are analysed.

`resource_policies`: `resource` and `iam_policy` for resources that grant roles to
federated principals directly (for example `gcloud projects get-iam-policy PROJECT
--format=json`). Every binding with a `principal://` or `principalSet://` member is
analysed.

## azure

`identities`: `name`, `kind` (`app` or `managed_identity`), `federated_credentials` (from
`az ad app federated-credential list --id APP_OBJECT_ID` or
`az identity federated-credential list --identity-name NAME --resource-group RG`), optional
`role_assignments` (`role`, `scope`, as from `az role assignment list --assignee ID`) and
`privilege`.

## Building a snapshot from CLI exports

```bash
trustmint assemble \
  --gcp-providers providers.json \
  --gcp-sa-policy deployer@acme-prod.iam.gserviceaccount.com=deployer-policy.json \
  --azure-app payments-deployer=payments-fic.json \
  --azure-mi aks-orders=aks-fic.json \
  --context context.json \
  -o snapshot.json
```

Several snapshots can be scanned together: `trustmint scan -s aws.json -s gcp.json`.
