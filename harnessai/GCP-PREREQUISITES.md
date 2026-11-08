# SEIR Foundations — Google Cloud Prerequisites for Harness CI

**Lab:** Harness CI -> Google Cloud | **Method:** Harness OIDC -> Google Cloud WIF via GCP connector -> service account impersonation | **Recommended:** No service account JSON keys

## What Harness needs

Harness is not Google Cloud and does not need its own Google password. For supported Harness steps, configure a **GCP connector with OIDC authentication** that references a Google Cloud Workload Identity Pool, Provider, project, and service account. Harness has different runtime environments (Harness Cloud and self-hosted delegates); the supported connector/step combination matters.

**Very important:** Passing a GCP connector to an integration step does **not** mean every arbitrary `Run` shell step inherits `gcloud` credentials. For the introductory lab, first validate the **connector** and use a supported GCP-aware CI step (for example, Build and Push to GAR, when available). A later lab can use the documented GCP OIDC Token plugin or explicitly configure credentials for a CLI step. Never paste a downloaded service account key into YAML to work around a missing OIDC feature.

**Student values:** `PROJECT_ID`, `PROJECT_NUMBER`, `POOL_ID=seir-harness`, `PROVIDER_ID=harness`, `SA_NAME=seir-harness-ci`, Harness account ID, Harness region/cluster issuer URL, Harness organization and project identifiers, and GCP connector identifier.

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

## Harness issuer and GCP provider setup

1. Identify the correct Harness account OIDC issuer from your Harness cluster/account settings and the current Harness GCP connector documentation. Do **not** assume it is `app.harness.io`; Harness has multiple clusters.
2. Review the OIDC token claims and the documented audience value for the intended GCP connector. Restrict the Google provider to the actual Harness account/project identity. Where project-level `sub` scopes are supported, restrict on them; verify any feature-flag requirements.
3. In Google Cloud, create a workload identity pool and **OIDC provider** with the exact issuer, allowed audience, claim mappings, and an account/project-specific attribute condition. Do not create a catch-all provider.
4. Create a dedicated Google Cloud service account (for example `seir-harness-ci`) and grant `roles/iam.workloadIdentityUser` to **only** the verified Harness federated principal or principal set.
5. Give the service account the specific resource permissions required by the next lab (e.g. Artifact Registry writer on a lab repository), not Owner or Editor.

You can create the pool and service account in Cloud Shell after the shared setup:

```bash
export POOL_ID="seir-harness"
export SA_NAME="seir-harness-ci"
gcloud iam workload-identity-pools create "$POOL_ID" \
  --location=global --display-name="SEIR Harness CI"
gcloud iam service-accounts create "$SA_NAME" \
  --display-name="SEIR Harness CI"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
```

**Instructor gate:** Do not execute a `providers create-oidc` command with guessed issuer, audience, or subject conditions. Inspect the actual Harness OIDC connector configuration, token claim documentation, and available features in your account first. Apply the restricted Google WIF provider and service-account IAM binding using those verified values. Those values differ by Harness cluster and can be feature-dependent. This is a deliberate verification step, not a request for a long-lived Google key.

## Configure the Harness GCP connector

1. Harness **Project -> Connectors -> New Connector -> Google Cloud Platform** (the exact menu wording may vary).
2. Select **OIDC authentication** where supported for the chosen Harness runtime and step.
3. Enter:
   - Workload identity pool resource: `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/seir-harness`
   - Provider ID: `harness` (after creating the provider)
   - GCP project ID: `YOUR_PROJECT_ID`
   - Service account email: `seir-harness-ci@YOUR_PROJECT_ID.iam.gserviceaccount.com`
4. Use the **Test Connection** function. Keep screenshots of the test result and relevant connector fields.
5. Test a supported CI operation using this connector. If using Artifact Registry, create a test repository and grant `roles/artifactregistry.writer` at the repository scope before running a publish step.

### Connector YAML *illustration* (not a complete importable object)

```yaml
connector:
  type: Gcp
  spec:
    credential:
      type: OidcAuthentication
      spec:
        workloadPoolId: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/seir-harness
        providerId: harness
        gcpProjectId: YOUR_PROJECT_ID
        serviceAccountEmail: seir-harness-ci@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

This is the credential section shown in Harness's GCP connector guidance. A full connector object also needs required metadata, and compatibility depends on the selected feature and runtime. **It is not a standalone `gcloud` login step.**

## Student proof of success

- First: Connector test succeeds using OIDC.
- Second: A supported GCP integration step can perform one limited, instructor-approved operation (such as pushing a small image to a dedicated GAR repository).
- Third: Student explains why this **does not automatically authenticate** arbitrary CI Run shell commands.

If the lab specifically demands `gcloud auth list` in a plain Run step, use the documented GCP OIDC Token plugin or a validated credential handoff for your Harness version; do not claim that a connector test populates `GOOGLE_APPLICATION_CREDENTIALS` in every shell.

**Troubleshooting:** mismatched Harness cluster issuer; unsupported OIDC connector/runtime combination; unmapped or overbroad claims; wrong pool path; service account impersonation role missing; connector available only at another account/org/project scope; Google Artifact Registry permissions missing despite successful connector validation.

**Official sources:** [Harness GCP OIDC connector example](https://developer.harness.io/docs/continuous-delivery/cd-infrastructure/terraform-infra/run-a-terraform-plan-with-the-terraform-plan-step/) | [Harness CI release notes on OIDC/GAR/GCP token plugin](https://developer.harness.io/release-notes/continuous-integration/)
