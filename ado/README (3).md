# SEIR Foundations DevOps Introduction: Azure DevOps Pipelines (ADO)

> **Audience:** SEIR Foundations students moving from Jenkins to modern CI/CD.  
> **Lab level:** Beginner | **Goal:** Run automated Python tests after retrieving application code.  
> **Scope:** CI only. No production deployment, AWS credentials, or real banking data.

## Learning objectives

By the end of this introduction, students will be able to explain what starts a pipeline, where it runs, how code is retrieved, how dependencies are installed, how unit tests report failures, and where to inspect execution logs.

## Why this platform?

Azure DevOps Pipelines is Microsoft's CI/CD service for building, testing, and deploying code. It supports Azure Repos and GitHub repositories. Pipeline YAML describes **triggers, pools, jobs, and tasks**. Microsoft-hosted agents can run the lab without students setting up a Jenkins server.

**Why learn it?** ADO is widely encountered in enterprise Microsoft environments, and it teaches students to distinguish repository hosting, pipeline orchestration, service connections, and build agents.

## Essential vocabulary

| ADO concept | Meaning |
| --- | --- |
| `trigger` | Starts CI after matching branch pushes |
| `pr` | PR triggers for supported external repos such as GitHub |
| Pipeline | YAML build/test process |
| Pool / agent | Machine assigned to execute tasks |
| `task` | Packaged ADO functionality, such as selecting Python |
| `script` | Commands executed by an agent |
| Service connection | Managed integration to external services (later labs) |

## Compared with Jenkins

Jenkins uses a `Jenkinsfile` and requires a controller plus available agents or externally managed hosting. In this lab, the pipeline is defined as YAML and executed using the platform's hosted infrastructure. **The underlying CI lifecycle remains the same:** source-code change → fetch code → prepare runtime → install dependencies → test → report result. Hosted does not mean free or unlimited; confirm available account capacity and quotas.

## The shared demonstration application

All three platforms use the **same Python test project**. This is intentional: students should compare pipeline engines rather than three different applications.

At repository root, create `app.py`:

```python
def calculate_balance(deposit, withdrawal):
    return deposit - withdrawal
```

Create `tests/test_app.py`:

```python
from app import calculate_balance

def test_deposit():
    assert calculate_balance(100, 0) == 100

def test_withdrawal():
    assert calculate_balance(100, 40) == 60

def test_overdraft():
    assert calculate_balance(100, 150) == -50
```

Create `requirements.txt`:

```text
pytest>=8,<10
```

Run locally from the repository root using `python -m pip install -r requirements.txt` and `python -m pytest -v`. All three tests should pass.


## Student setup and first run

1. Create or access an Azure DevOps organization and project with Azure Pipelines enabled.
2. Connect the GitHub `seir-devops-lab` repository; authorize the integration when prompted.
3. Add the shared Python files and the `azure-pipelines.yml` shown below to repository root.
4. In **Pipelines > New pipeline**, choose GitHub, select the repository, and choose the existing YAML file.
5. Run it and inspect each task in the job logs. Expect **3 passed**.
6. If the organization requires pipeline authorization or has no available hosted parallelism, request access/hosted capacity or use an approved self-hosted agent.

**Azure Repos caveat:** for Azure Repos Git, pull request validation is configured via **branch policies** rather than the YAML `pr` keyword. This introductory example assumes a GitHub repository connected to ADO.

## Starter pipeline YAML

**Save this as `azure-pipelines.yml`.** The same file is included alongside this README.

```yaml
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - checkout: self
    displayName: 'Checkout repository'
  - task: UsePythonVersion@0
    displayName: 'Set up Python 3.12'
    inputs:
      versionSpec: '3.12'
  - script: |
      python -m pip install -r requirements.txt
    displayName: 'Install dependencies'
  - script: python -m pytest -v
    displayName: 'Run tests'
```

## Exercise: Make the pipeline fail, then fix it

1. Run the initial pipeline and capture evidence showing the three successful tests.
2. Edit `tests/test_app.py`, changing the expected withdrawal result from `60` to `999`.
3. Commit and push the change. For platforms without a configured push trigger, start a pipeline run manually.
4. Find the failing assertion and identify which stage/job/step reported it.
5. Restore the expected value to `60`, commit, and run the pipeline again.
6. Explain in your own words what the execution agent/runner did and where the YAML was stored.

## Troubleshooting guide

- **Pipeline queued but never starts:** check agent/parallel-job entitlement and pool permissions.
- **GitHub connection denied:** verify installation/authorization of the Azure Pipelines GitHub integration.
- **PR does not validate:** determine whether your code is in GitHub or Azure Repos; configure Azure Repos branch policy if necessary.
- **Python version selection fails:** check agent image/tool availability and `UsePythonVersion@0`.
- **Tests fail:** inspect the exact failing task and distinguish assertion failures from missing files or packages.

## Evidence students must submit

- Screenshot of the YAML file in source control or the platform's pipeline editor.
- Screenshot of a successful pipeline execution showing **3 passed**.
- Screenshot of an intentionally failed test and its log/error.
- Screenshot of the corrected pipeline succeeding again.
- A short paragraph identifying the trigger, execution machine, code checkout, dependency installation, and test command.

## Security and operational habits

- Never hardcode API keys, GitHub tokens, or cloud credentials in YAML.
- Use the minimum permissions required and approved connectors/service connections.
- Keep sample data synthetic; never use customer banking records in this teaching repo.
- Review third-party actions, task versions, and build logs before reusing them in production.
- Treat AI-generated troubleshooting suggestions as proposals to validate, not guaranteed fixes.

## Where we go next

Add multistage pipelines, publish test artifacts, use approvals/environments and secure service connections, and eventually deploy to Azure or AWS ECS.

## Official documentation

https://learn.microsoft.com/en-us/azure/devops/pipelines/ecosystems/python?view=azure-devops
https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/tool/use-python-version?view=azure-devops
https://learn.microsoft.com/en-us/azure/devops/pipelines/repos/azure-repos-git?view=azure-devops#pr-triggers
