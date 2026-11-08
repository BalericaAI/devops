# SEIR Foundations — Google Cloud Prerequisites for GitHub Actions

**Lab:** GitHub Actions -> Google Cloud | **Method:** GitHub OIDC -> Google Cloud WIF -> scoped service account | **Recommended:** No service account JSON keys

## What GitHub Actions needs

The GitHub runner issues an OIDC token for a workflow run. Google Cloud trusts only the matching identity claims. GitHub workflow permission `id-token: write` permits requesting an OIDC token; it does **not** grant write permission to Google Cloud.

**Student values:** `PROJECT_ID`, `PROJECT_NUMBER`, `POOL_ID=seir-gh`, `PROVIDER_ID=github`, `REPO=OWNER/REPOSITORY`, `SA_NAME=seir-gh-ci`. Use a real GitHub owner/repository identifier.

## The rule: no special Google Cloud key for this platform

Google Cloud uses **Workload Identity Federation (WIF)** to trust a short-lived external OIDC identity. The tool supplies an identity assertion; Google Security Token Service checks the provider's issuer, audience, claims, and conditions. You can then access permitted resources directly or impersonate a Google Cloud service account. **A long-lived service account JSON key is not required.**

- **Authentication:** Can Google Cloud identify the pipeline?
- **Authorization:** What can that identity do? Authentication success does **not** prove permission to deploy.
- **Identity isolation:** You can use the same Google Cloud project for all three tools, but use separate narrowly scoped providers and service accounts for lab auditability. Never share one unrestricted key across students.
- **Project ID vs project number:** `my-lab-project` is a project ID; `123456789012` is a project number. Pool resource names and principal identifiers require the **number**.
- **No DNA sample required.** The cloud only wants a trusted token, not your genome.

### Student prerequisite checklist

- [ ] Google Cloud project selected; project ID and project number recorded
- [ ] Billing status confirmed for any billable services; lab budget/alerts understood
- [ ] Google Cloud IAM/STS and Service Account Credentials APIs enabled
- [ ] Workload Identity Pool and provider created in the appropriate project
- [ ] Dedicated service account created (this guide uses impersonation for consistency)
- [ ] Principal authorization restricted to the correct repository, connection, or Harness scope
- [ ] `roles/iam.workloadIdentityUser` granted **on the service account** to the restricted federated identity
- [ ] Required resource permissions granted **to the service account**, separately
- [ ] The pipeline executes a non-secret identity verification step
- [ ] Screenshot captures run result and configuration identifiers **without printing tokens**

> Administrator setup: Creating pools/providers, enabling APIs, assigning IAM permissions, and managing service accounts require appropriate administrator permissions. Students should not give their pipelines Owner/Editor permissions merely to make a lab pass.

### Shared Google Cloud setup (Cloud Shell)

The following is a **starting template**; substitute unique IDs and run only in a lab project where you have authority. It intentionally does **not** create an unrestricted provider. Each guide gives its platform-specific provider restrictions.

```bash
export PROJECT_ID="YOUR_GCP_PROJECT_ID"
gcloud config set project "$PROJECT_ID"
export PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com cloudresourcemanager.googleapis.com
# Use the correct POOL_ID from the platform-specific setup below.
```

Create a dedicated service account after choosing the platform's `SA_NAME`:

```bash
gcloud iam service-accounts create "$SA_NAME" --display-name="SEIR CI federation"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
```

If a resource or service account already exists, verify and reuse it rather than blindly recreating it. Account owners may instead provision these centrally for the class.

### How to check identity without leaking credentials

Use `gcloud auth list --filter=status:ACTIVE --format='value(account)'` and `gcloud config get-value project` after login. For a stronger check of the token exchange, run `gcloud auth print-access-token >/dev/null` (do not display the token). Successful token exchange means authentication worked, **not** that Cloud Run/GKE/Artifact Registry permissions are available.

### What screenshots students submit

1. Workload identity provider name and its issuer (hide unnecessary account data).
2. Service account email and the targeted `Workload Identity User` IAM binding.
3. Successful CI run / connector validation with secret-safe logs.
4. A short explanation of why no long-lived JSON key was required.

### Troubleshooting first principles

| Symptom | First check |
|---|---|
| `invalid_grant` / token rejected | Issuer, audience, token freshness, provider attribute mappings/conditions |
| `PERMISSION_DENIED` during impersonation | Correct `roles/iam.workloadIdentityUser` binding on the **target service account** |
| Token exchange succeeds, resource call fails | Missing resource-level IAM role or API not enabled |
| Wrong project | Project **ID** vs **number**, active `gcloud` project, wrong service account |
| Unexpectedly empty credentials | Platform step lacks OIDC permission or token isn't passed to the consuming step |

### Official references

- [Google Cloud WIF overview](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
- [Google Cloud deployment-pipeline federation guide](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
- [Google Cloud service account pipeline practices](https://docs.cloud.google.com/iam/docs/best-practices-for-using-service-accounts-in-deployment-pipelines)

**Lab exit requirement:** A keyless authentication check succeeds, no token or service account private key appears in logs, and the student can distinguish identity from permissions.

## Platform-specific Google Cloud setup

In Cloud Shell after the shared setup commands:

```bash
export POOL_ID="seir-gh"
export PROVIDER_ID="github"
export SA_NAME="seir-gh-ci"
export REPO="YOUR_GITHUB_OWNER/YOUR_GITHUB_REPO"
export GH_OWNER="YOUR_GITHUB_OWNER"

gcloud iam workload-identity-pools create "$POOL_ID" \
  --location=global --display-name="SEIR GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
  --location=global --workload-identity-pool="$POOL_ID" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" \
  --attribute-condition="assertion.repository_owner=='${GH_OWNER}' && assertion.repository=='${REPO}'"

gcloud iam service-accounts create "$SA_NAME" --display-name="SEIR GitHub Actions CI"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.repository/${REPO}"
```

For a production deployment, further restrict identity by immutable GitHub repository ID and/or protected branch/environment claims. Check the exact claim values before changing conditions.

## GitHub repository configuration

Repository -> **Settings -> Secrets and variables -> Actions -> Variables**. Add **nonsecret** values:

- `GCP_PROJECT_ID`: GCP project ID
- `GCP_WORKLOAD_IDENTITY_PROVIDER`: `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/seir-gh/providers/github`
- `GCP_SERVICE_ACCOUNT`: `seir-gh-ci@PROJECT_ID.iam.gserviceaccount.com`

### Starter authentication workflow

Save as `.github/workflows/gcp-auth-check.yml`:

```yaml
name: SEIR GCP authentication check
on:
  workflow_dispatch:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  verify-gcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: auth
        uses: google-github-actions/auth@v3
        with:
          project_id: ${{ vars.GCP_PROJECT_ID }}
          workload_identity_provider: ${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ vars.GCP_SERVICE_ACCOUNT }}
      - uses: google-github-actions/setup-gcloud@v3
      - name: Check active Google Cloud identity
        run: |
          gcloud auth list --filter=status:ACTIVE --format='value(account)'
          gcloud config get-value project
          gcloud auth print-access-token >/dev/null
          echo "Google Cloud keyless authentication succeeded"
```

**Why this works:** GitHub supplies an ephemeral identity token; `auth@v3` exchanges it for Google Cloud credentials through WIF, with service account impersonation. `setup-gcloud` makes the CLI available. The cloud service account's **resource** permissions still have to be granted separately.

**Troubleshooting:** `id-token: write` missing; repo/owner mismatch in condition; wrong provider resource name; IAM propagation delay; action needs `checkout` before `auth`; running from an untrusted fork; incorrect service account email.

**Official platform source:** [google-github-actions/auth](https://github.com/google-github-actions/auth/blob/main/README.md)
