# SEIR Foundations — Google Cloud Prerequisites for Azure DevOps Pipelines

**Lab:** Azure Pipelines -> Google Cloud | **Method:** Azure DevOps workload identity service connection -> Google Cloud WIF -> scoped service account | **Recommended:** No Google service account JSON keys

## What Azure DevOps needs

The pipeline must request an OIDC identity token from an **Azure Resource Manager workload identity federation service connection**, then exchange it via Google Cloud STS. The Azure subscription used for connection setup does not make your pipeline a Google Cloud identity. Remove unnecessary Azure subscription permissions from the service connection.

**2026/2027 warning:** Azure DevOps is moving from `vstoken.dev.azure.com` issuers to **Microsoft Entra** issuers (`login.microsoftonline.com`). New service connections generally use the Entra issuer, and the legacy issuer is scheduled for retirement July 1, 2027. **Do not hard-code the issuer from an old tutorial.** Copy the actual service connection issuer and subject from your Azure DevOps UI, then configure the matching Google provider. See [Microsoft's migration guidance](https://learn.microsoft.com/azure/devops/pipelines/release/convert-service-connections).

**Student values:** `PROJECT_ID`, `PROJECT_NUMBER`, `POOL_ID=seir-ado`, `PROVIDER_ID=azure-devops`, `SA_NAME=seir-ado-ci`, Azure DevOps service connection name, actual issuer URL, actual subject identifier, and Entra app object ID / claims as appropriate.

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

## Azure DevOps setup first

1. Open **Project Settings -> Service connections -> New service connection -> Azure Resource Manager**.
2. Choose workload identity federation (prefer the current supported Entra issuer path). Have the instructor/administrator configure the app registration or managed identity and any required Azure-side federation.
3. Name it `seir-gcp-wif`; authorize **only** the selected lab pipeline, not all pipelines.
4. Copy the **Issuer**, **Subject identifier**, and relevant application object ID (`oid` claim), where applicable.
5. Limit or remove any Azure subscription role assigned automatically when not needed for this GCP-only lab.

## Google Cloud setup for that connection

In Cloud Shell, after the common setup, use actual values copied from your service connection:

```bash
export POOL_ID="seir-ado"
export PROVIDER_ID="azure-devops"
export SA_NAME="seir-ado-ci"
export ADO_ISSUER="PASTE_ACTUAL_SERVICE_CONNECTION_ISSUER"
export ADO_SUBJECT="PASTE_ACTUAL_SUBJECT_IDENTIFIER"
export ADO_OBJECT_ID="PASTE_APPLICATION_OBJECT_ID_FOR_OID_CLAIM"

gcloud iam workload-identity-pools create "$POOL_ID" \
  --location=global --display-name="SEIR Azure DevOps"

gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
  --location=global --workload-identity-pool="$POOL_ID" \
  --issuer-uri="$ADO_ISSUER" \
  --allowed-audiences="fb60f99c-7a34-4190-8149-302f77469936" \
  --attribute-mapping="google.subject=assertion.sub,attribute.oid=assertion.oid" \
  --attribute-condition="assertion.sub=='${ADO_SUBJECT}' && assertion.oid=='${ADO_OBJECT_ID}'"

gcloud iam service-accounts create "$SA_NAME" --display-name="SEIR Azure DevOps CI"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --role=roles/iam.workloadIdentityUser \
  --member="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/subject/${ADO_SUBJECT}"
```

**Important:** The OIDC token's actual `iss`, `aud`, `sub`, and `oid` must match this provider. The Google deployment-pipeline guide describes its Azure DevOps audience as `fb60f99c-7a34-4190-8149-302f77469936`. Confirm whether the current Entra-issued token for your connection uses the documented claim set before assuming the example will work. If the actual Entra issuer/claims differ, update the provider and restrictions to match; do not weaken the provider to accept arbitrary subjects or issuers.

## Starter Azure pipeline: request token, use Google Cloud STS

Use a Microsoft-hosted Ubuntu agent with `gcloud` installed (install the Google Cloud CLI if the chosen image lacks it). Set the five `GCP_*` pipeline variables and set your real service connection name.

```yaml
trigger: none
pool:
  vmImage: ubuntu-latest
variables:
  GCP_PROJECT_ID: 'YOUR_PROJECT_ID'
  GCP_PROJECT_NUMBER: 'YOUR_PROJECT_NUMBER'
  GCP_POOL_ID: 'seir-ado'
  GCP_PROVIDER_ID: 'azure-devops'
  GCP_SERVICE_ACCOUNT: 'seir-ado-ci@YOUR_PROJECT_ID.iam.gserviceaccount.com'
steps:
  - task: AzureCLI@2
    displayName: 'Obtain Azure DevOps OIDC token and verify GCP auth'
    inputs:
      azureSubscription: 'seir-gcp-wif'
      addSpnToEnvironment: true
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: |
        set -euo pipefail
        command -v gcloud >/dev/null || { echo 'Install Google Cloud CLI on the agent'; exit 1; }
        umask 077
        TOKEN_FILE="$(Agent.TempDirectory)/seir-ado-oidc.jwt"
        CONFIG_FILE="$(Agent.TempDirectory)/seir-gcp-wif.json"
        printf '%s' "$idToken" > "$TOKEN_FILE"
        export TOKEN_FILE CONFIG_FILE
        python3 - <<'PYCODE'
        import json, os
        p=os.environ['GCP_PROJECT_NUMBER']; pool=os.environ['GCP_POOL_ID']
        provider=os.environ['GCP_PROVIDER_ID']; sa=os.environ['GCP_SERVICE_ACCOUNT']
        cfg={
          'type':'external_account',
          'audience':f'//iam.googleapis.com/projects/{p}/locations/global/workloadIdentityPools/{pool}/providers/{provider}',
          'subject_token_type':'urn:ietf:params:oauth:token-type:jwt',
          'token_url':'https://sts.googleapis.com/v1/token',
          'credential_source':{'file':os.environ['TOKEN_FILE']},
          'service_account_impersonation_url':f'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken'
        }
        with open(os.environ['CONFIG_FILE'],'w') as f: json.dump(cfg,f)
        PYCODE
        trap 'rm -f "$TOKEN_FILE" "$CONFIG_FILE"' EXIT
        gcloud auth login --cred-file="$CONFIG_FILE" --quiet >/dev/null
        gcloud config set project "$GCP_PROJECT_ID" >/dev/null
        gcloud auth print-access-token >/dev/null
        gcloud auth list --filter=status:ACTIVE --format='value(account)'
        echo 'Keyless Google Cloud authentication succeeded'
    env:
      GCP_PROJECT_ID: $(GCP_PROJECT_ID)
      GCP_PROJECT_NUMBER: $(GCP_PROJECT_NUMBER)
      GCP_POOL_ID: $(GCP_POOL_ID)
      GCP_PROVIDER_ID: $(GCP_PROVIDER_ID)
      GCP_SERVICE_ACCOUNT: $(GCP_SERVICE_ACCOUNT)
```

**Caveat:** `AzureCLI@2` obtains its `idToken` from the authorized service connection; this is not a generic `Bash@3` token automatically available to all tasks. The example uses and cleans short-lived files **inside one step**. If you split steps, you must deliberately hand off credentials and keep them protected. The example requires a configured service connection, suitable Microsoft permissions, and a Google Cloud CLI installation; it is a starting template, not an execution-tested configuration.

**Troubleshooting:** wrong issuer due to migration; mismatched `oid`/`sub`; old provider audience; service connection not authorized for the pipeline; missing `gcloud` on runner; `idToken` not exposed; insufficient service account IAM.

**Official sources:** [Google Cloud deployment pipeline federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines) | [Microsoft service connection federation](https://learn.microsoft.com/azure/devops/pipelines/release/configure-workload-identity)
