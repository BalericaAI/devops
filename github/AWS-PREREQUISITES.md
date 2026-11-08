# AWS Prerequisites — GitHub Actions

**SEIR Foundations | DevOps | Student setup**

## Goal

Connect a GitHub Actions workflow to **your existing AWS account** without creating an IAM user or a permanent access key. GitHub issues an OIDC identity token; AWS STS verifies it and returns **temporary role credentials** to the workflow.

**No DNA sample. No separate AWS account. No downloadable CSV containing AWS secret keys.**

## What is shared across all three platforms?

The AWS **account ID**, **Region**, target resources (later ECR/ECS), and **IAM authorization model** are the same. You do **not** need three AWS accounts, three IAM users, three long-lived access keys, or a different secret key for every CI/CD vendor. Each pipeline can request temporary credentials for an IAM role through AWS Security Token Service (STS).

A common AWS account can have three **separate IAM roles** to isolate GitHub, Azure DevOps, and Harness: this is a security boundary, **not** evidence that each platform needs its own access-key pair. You could technically share a role with carefully scoped trust statements, but separate roles make audit logs and revocation easier for a class.

| Item | Is it secret? | Example / explanation |
|---|---|---|
| AWS account ID | No | 12-digit AWS account identifier |
| AWS Region | No | `us-east-1` (choose the same Region as your resources) |
| IAM role ARN | No | `arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>` |
| OIDC issuer / audience / subject | No | Identity claims AWS checks |
| Temporary STS credentials | **Yes** | Automatically issued for a limited time; do not log or commit |
| IAM access key ID + secret access key | **Yes** | **Not needed** for the preferred OIDC approach |

**Two IAM policies, two different questions:** The IAM **trust policy** answers *who may assume the role?* The IAM **permissions policy** answers *what may the assumed role do in AWS?*

### AWS prerequisites checklist

- [ ] Sign in to an AWS account with an appropriately privileged administrator or class-provided sandbox identity.
- [ ] Know the 12-digit AWS account ID and your chosen Region.
- [ ] Have authorization to configure an IAM OIDC provider and a narrowly trusted IAM role (or ask the instructor to create them).
- [ ] Use an AWS IAM **role**, not the root account, for pipeline execution.
- [ ] Keep the initial verification step read-only: `aws sts get-caller-identity`.
- [ ] Do **not** commit credentials, temporary tokens, `.aws/credentials`, or private files into Git.
- [ ] Once the identity test works, request only the ECR/ECS permissions specifically needed by a later deployment lab.

> `aws sts get-caller-identity` tells you which IAM identity AWS sees. It does **not** prove you are authorized to create, push, or deploy anything. It normally needs no explicit identity-based IAM Allow statement.

## 1. Values to collect

- AWS account ID: `<ACCOUNT_ID>`
- AWS Region: `<AWS_REGION>` (example `us-east-1`)
- GitHub owner: `<OWNER>` (user or organization)
- GitHub repository: `<REPOSITORY>`
- Branch: `main` (change if your class uses another)
- IAM role name: `SEIR-GitHubActions-ReadIdentity`

## 2. Create the GitHub OIDC identity provider in AWS (once per AWS account)

AWS Console → **IAM** → **Identity providers** → **Add provider**:

- Provider type: **OpenID Connect**
- Provider URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

If the provider already exists, reuse it. Do not create duplicates.

## 3. Create the IAM role and constrain its trust

AWS Console → IAM → Roles → Create role → **Web identity**, choose the GitHub provider and audience above. Set a restrictive trust policy for the specific repository/branch:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:<OWNER>/<REPOSITORY>:ref:refs/heads/main"
      }
    }
  }]
}
```

Replace every placeholder. **GitHub's subject format can vary**, including newer immutable-ID subjects for some repositories created after July 15, 2026, and environment-based subjects. Check the repository's actual OIDC subject format before applying this example; do not weaken the condition to `*` to make it pass. This example assumes the legacy owner/repository + `main` branch subject.

For the first `get-caller-identity` test, do not grant EC2/ECR/ECS permissions. Keep the role limited; grant deployment permissions in a later lab.

## 4. Add the workflow's authentication step

In `.github/workflows/aws-identity.yml`:

```yaml
name: AWS identity smoke test
on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  verify-aws:
    runs-on: ubuntu-latest
    steps:
      - name: Request short-lived AWS credentials
        uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/SEIR-GitHubActions-ReadIdentity
          aws-region: us-east-1

      - name: See which AWS identity was assumed
        run: aws sts get-caller-identity
```

Replace the AWS account ID and Region. In production, pin third-party Actions to audited commit SHAs rather than mutable major-version tags. This example is intentionally simple for the first lab.

Run it via **GitHub → Actions → AWS identity smoke test → Run workflow**.

## 5. Understand the login flow

`GitHub job → GitHub OIDC token → AWS IAM OIDC provider + role trust policy → AWS STS → temporary credentials → AWS CLI`

GitHub's `id-token: write` permits issuing an OIDC token; it does **not** by itself allow AWS access. AWS decides whether to trust the token and assume the role.

## 6. Troubleshooting

| Symptom | Check |
|---|---|
| `Not authorized to perform sts:AssumeRoleWithWebIdentity` | Provider, audience, role trust, exact repository/branch subject |
| `Credentials could not be loaded` | `id-token: write`, configure-aws-credentials step, role ARN |
| Subject mismatch despite correct repo | Check whether your GitHub repository uses immutable-ID or environment subject claims |
| Identity works, ECR fails | You passed authentication but need ECR authorization for the later lab |
| Using a pull request from a fork | Do not grant deployment role to untrusted fork workflows; use separate read-only validation |

## Required student evidence

1. Screenshot of IAM role name and trust-policy **conditions** (no tokens/secrets).
2. Screenshot of the GitHub Actions run showing the identity test succeeded.
3. Output of `get-caller-identity` showing the correct AWS **Account** and assumed-role **Arn** (redact if class policy requires).
4. A sentence explaining why no AWS access key was generated.

## Official references

- https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws
- https://github.com/aws-actions/configure-aws-credentials
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
