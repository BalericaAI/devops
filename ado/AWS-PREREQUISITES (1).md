# AWS Prerequisites — Azure DevOps (ADO) Pipelines

**SEIR Foundations | DevOps | Student setup**

## Goal

Allow **Azure DevOps Pipelines** to authenticate to the **same AWS account** used by the other DevOps labs. Use the **AWS Toolkit for Azure DevOps** with OIDC federation so the pipeline receives temporary AWS credentials without storing a static AWS secret access key.

**You are not creating an Azure subscription to deploy into AWS.** An Azure DevOps organization/project is the pipeline control plane; the AWS account remains the target.

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

## 1. Values and platform prerequisites

- AWS account ID: `<ACCOUNT_ID>`
- AWS Region: `<AWS_REGION>`
- Azure DevOps **organization name**: `<ADO_ORG_NAME>`
- Azure DevOps **project name**: `<ADO_PROJECT_NAME>`
- Azure DevOps **organization GUID**: `<ADO_ORG_GUID>` (not the organization name)
- AWS service connection name: `seir-aws-oidc`
- IAM role name: `SEIR-AzureDevOps-ReadIdentity`
- AWS Toolkit for Azure DevOps extension **version 1.15.0 or later**, installed and permitted in the organization.

> This is an **AWS** service connection provided by the AWS Toolkit, **not** an Azure Resource Manager service connection. The two aren't interchangeable.

## 2. Create an AWS service connection (no keys)

Azure DevOps → **Project settings** → **Service connections** → **New service connection** → **AWS**:

1. Name: `seir-aws-oidc`.
2. Role to assume: `arn:aws:iam::<ACCOUNT_ID>:role/SEIR-AzureDevOps-ReadIdentity`.
3. Enable **Use OIDC**.
4. Leave **Access key ID** and **Secret access key** empty.
5. Save. Authorize only the pipeline(s) needing this connection; do not grant universal access.

If the AWS role does not exist yet, an initial test may fail and still expose the required issuer/subject in task logs; use the token claim values and AWS's documented setup to finish the federation. Do not paste actual OIDC tokens into class submissions.

## 3. Create an AWS OIDC identity provider

AWS Console → IAM → Identity providers → Add provider:

- Provider type: **OpenID Connect**
- Provider URL: `https://vstoken.dev.azure.com/<ADO_ORG_GUID>`
- Audience: `api://AzureADTokenExchange`

Use the exact issuer that Azure DevOps reports, rather than guessing the GUID. An existing matching provider can be reused.

## 4. Create the AWS IAM role trust policy

Create a web-identity role named `SEIR-AzureDevOps-ReadIdentity`. Constrain it to the **one exact Azure DevOps service connection**:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/vstoken.dev.azure.com/<ADO_ORG_GUID>"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "vstoken.dev.azure.com/<ADO_ORG_GUID>:aud": "api://AzureADTokenExchange",
        "vstoken.dev.azure.com/<ADO_ORG_GUID>:sub": "sc://<ADO_ORG_NAME>/<ADO_PROJECT_NAME>/seir-aws-oidc"
      }
    }
  }]
}
```

Substitute the actual issuer, audience, and subject from the connection/token claims. For this initial identity-only lab, the role needs no ECR or ECS permission policy.

## 5. Create a tiny verification pipeline

At repository root, make `azure-pipelines-aws-identity.yml`:

```yaml
trigger: none

pool:
  vmImage: ubuntu-latest

steps:
  - task: AWSCLI@1
    displayName: Verify AWS federated identity
    inputs:
      awsCredentials: 'seir-aws-oidc'
      regionName: 'us-east-1'
      awsCommand: 'sts'
      awsSubCommand: 'get-caller-identity'
```

Change the Region if needed. Create an Azure Pipeline referencing this YAML and manually run it. Approve the service connection for this pipeline if prompted.

The **AWSCLI@1 task** is supplied by the AWS Toolkit extension. A generic `script: aws sts get-caller-identity` does **not** automatically activate the AWS service connection; use the AWS task (or `AWSShellScript@1` when you need shell/SDK tooling).

## 6. Authentication flow

`Azure Pipelines → AWS service connection → ADO OIDC token → AWS IAM provider + trust policy → AWS STS → temporary role credentials → AWS Toolkit task`

Azure DevOps authenticates its own users separately. Signing into Azure DevOps does not mean AWS trusts the pipeline; IAM federation establishes that trust.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| AWS task not recognized | AWS Toolkit extension installed/allowed (>=1.15.0 for this OIDC workflow) |
| Service connection access denied | Project-level connection permissions and pipeline authorization |
| `AssumeRoleWithWebIdentity` denied | Issuer GUID, `api://AzureADTokenExchange` audience, exact `sc://` subject and role ARN |
| Generic script says no credentials | Use `AWSCLI@1` or `AWSShellScript@1` with the connection |
| Identity test passes but deployment fails | IAM permission policy for the particular ECR/ECS actions is still missing |

## Required student evidence

1. AWS Toolkit version and service connection showing **Use OIDC** (no secret values).
2. IAM OIDC provider and role trust **conditions**.
3. Successful `AWSCLI@1` output with AWS Account and assumed role ARN.
4. One sentence explaining why an Azure DevOps project is **not** an AWS account or access key.

## Official references

- https://aws.amazon.com/blogs/modernizing-with-aws/how-to-federate-into-aws-from-azure-devops-using-openid-connect/
- https://github.com/aws/aws-toolkit-azure-devops
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
