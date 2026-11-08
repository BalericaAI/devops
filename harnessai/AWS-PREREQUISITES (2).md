# AWS Prerequisites — Harness CI / AWS Connector

**SEIR Foundations | DevOps | Student setup**

## Goal

Configure Harness to authenticate to the **same existing AWS account** using a dedicated **AWS connector with OIDC federation**, not a long-lived IAM access key. Harness uses the connector for AWS-aware platform steps (including AWS artifact and deployment operations). Harness CI builds and arbitrary shell scripts do **not** automatically inherit the connector's credentials.

**No separate AWS account or Harness-specific AWS key. No DNA sample.** Harness has its own account/project IDs, but those are identifiers, not AWS credentials.

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

## 1. Collect Harness and AWS values

- AWS account ID: `<ACCOUNT_ID>`
- AWS Region: `<AWS_REGION>`
- Harness account ID: `<HARNESS_ACCOUNT_ID>`
- Harness hostname: typically `app.harness.io` (use the hostname for your actual Harness instance)
- Harness organization / project identifiers: `<ORG_ID>` / `<PROJECT_ID>`
- AWS role name: `SEIR-Harness-ReadIdentity`
- Connector ID: `seir_aws_oidc`

## 2. Create the Harness AWS OIDC provider in AWS

Harness Console → Account settings: find the **Harness account ID**. For Harness SaaS hosted at `app.harness.io`, in AWS Console → IAM → Identity providers → Add provider:

- Type: **OpenID Connect**
- Provider URL: `https://app.harness.io/ng/api/oidc/account/<HARNESS_ACCOUNT_ID>`
- Audience: `sts.amazonaws.com`

If your Harness environment uses another hostname, use the exact provider endpoint displayed in Harness documentation for that environment. Do not treat the Harness account ID or project ID as an AWS secret.

## 3. Create the AWS IAM role

Create IAM role `SEIR-Harness-ReadIdentity` with **Web identity** trust on the specific Harness OIDC provider. Harness OIDC claims and optional scope conditions depend on your account configuration; **copy the actual claims and AWS trust-policy guidance from the Harness AWS connector flow** and restrict `sub` to the expected scope where supported. Do not guess a `sub` claim, use wildcards across the whole Harness account, or copy GitHub's subject format.

The following is only a **structural illustration**, not a complete deployable trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/app.harness.io/ng/api/oidc/account/<HARNESS_ACCOUNT_ID>"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "app.harness.io/ng/api/oidc/account/<HARNESS_ACCOUNT_ID>:aud": "sts.amazonaws.com"
      }
    }
  }]
}
```

**Before use, narrow this illustration with the supported subject or other documented trust constraints for your Harness account; do not use it as-is.** The AWS permission policy can initially have no permissions if you are verifying STS identity alone. Harness AWS connector **validation** may also require `ec2:DescribeRegions` on `*`, depending on the account feature flag `CDS_AWS_DESCRIBE_REGIONS_OPTIONAL`; see below.

## 4. Create the Harness AWS connector

Harness → **Project settings** (or organization/account connectors, as authorized) → **Connectors** → **New Connector** → **AWS**:

1. Set name `SEIR AWS OIDC` and identifier `seir_aws_oidc`.
2. Under credentials choose **Use OIDC**.
3. Enter the IAM role ARN `arn:aws:iam::<ACCOUNT_ID>:role/SEIR-Harness-ReadIdentity`.
4. Complete the remaining fields for your Harness account and save.
5. Test the connection. Restrict connector access to the student project as appropriate.

**Validation detail:** By default, Harness AWS connector validation may call `ec2:DescribeRegions`; grant it minimally using this role policy if the connector test requests it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "ec2:DescribeRegions",
    "Resource": "*"
  }]
}
```

If the feature flag `CDS_AWS_DESCRIBE_REGIONS_OPTIONAL` is enabled, Harness can use `sts:GetCallerIdentity` instead for connector validation. The flag is account-specific; do not assume it is enabled.

## 5. Distinguish connector access from shell access

The prior class CI starter pipeline uses `type: Run` shell steps on Harness Cloud. **A successful AWS connector does not automatically inject AWS credentials into those generic Run steps.** For later AWS deployment or ECR work, configure an AWS-aware step to use your connector.

If you must call `aws sts get-caller-identity` from a generic CI shell, you need an explicit credential-delivery mechanism supported by your Harness CI environment, such as the **Harness AWS OIDC token plugin**, which obtains short-lived credentials and has documented prerequisites / feature flags. Do not place static IAM keys into the sample Run YAML or claim the AWS connector alone makes AWS CLI authentication work.

For this first prerequisite lesson, the **connector validation** is the initial Harness-native smoke test. An AWS CLI identity test is a separate follow-on exercise once CI token injection is configured and verified for the class account.

## 6. Authentication flow

`Harness connector/authorized platform step → Harness OIDC token → AWS IAM provider + scoped role trust → AWS STS → temporary role credentials → AWS API`

A Harness Git connector authenticates to a repository. It does **not** authenticate to AWS. A Harness AWS connector authenticates AWS operations. These are two different connectors and two different trust relationships.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| OIDC connector test fails | Correct Harness hostname/account ID, provider URL, audience, IAM role trust scope |
| `DescribeRegions` access denied | Provide `ec2:DescribeRegions` for connector validation or verify account-specific alternative flag |
| Harness Run step reports no AWS credentials | The connector is **not** implicitly injected into Run steps; use supported CI credential-delivery integration |
| Git repository clone works but AWS fails | Git connector is not AWS connector |
| AWS login works but ECR/ECS fails | Add only the task-specific IAM permission policy later |
| UI looks different | Confirm Harness account/feature availability and whether the class uses classic or v1 pipelines |

## Required student evidence

1. Screenshot of the OIDC AWS connector settings, with no secrets.
2. Screenshot of matching AWS OIDC provider and constrained IAM role trust.
3. Connector test output showing its verification result (and any required validation permission).
4. Two sentences explaining why a Harness **Git connector** and **AWS connector** are different.
5. Explain why `Run` steps do not inherit AWS connector credentials by default.

## Official references

- https://developer.harness.io/docs/platform/connectors/cloud-providers/ref-cloud-providers/aws-connector-settings-reference/
- https://developer.harness.io/docs/continuous-integration/secure-ci/aws-oidc-token-plugin/
- https://developer.harness.io/docs/infra-as-code-management/configuration/connectors-and-variables/aws-connector-auth/
