# SEIR Foundations DevOps Introduction: Harness CI (with AI-assisted DevOps follow-up)

> **Audience:** SEIR Foundations students moving from Jenkins to modern CI/CD.  
> **Lab level:** Beginner | **Goal:** Run automated Python tests after retrieving application code.  
> **Scope:** CI only. No production deployment, AWS credentials, or real banking data.

## Learning objectives

By the end of this introduction, students will be able to explain what starts a pipeline, where it runs, how code is retrieved, how dependencies are installed, how unit tests report failures, and where to inspect execution logs.

## Why this platform?

Harness is a software delivery platform with CI and deployment capabilities. Unlike GitHub Actions' repository-native configuration, Harness commonly uses **projects, organizations, connectors, stages, and runtime settings** to describe and operate a pipeline. This introductory example uses **classic Harness CI pipeline YAML**, not newer v1 simplified YAML.

**Harness AI distinction:** Harness AI-assisted features can help diagnose execution failures or recommend improvements, depending on the capabilities enabled for the account. **The YAML below is a standard deterministic Harness CI pipeline, not an autonomous AI agent.** Students will first understand the underlying CI execution before exploring any available AI functionality.

## Essential vocabulary

| Harness concept | Meaning |
| --- | --- |
| Organization / project | Scope and governance for the pipeline |
| Connector | Authorized link to source-control or another service |
| Codebase | Repository and branch used for a build |
| CI stage | Build/test portion of the pipeline |
| Runtime | Hosted or self-managed execution infrastructure |
| Run step | Shell commands inside the stage |
| Trigger | Separately configured event to start a pipeline automatically |

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

1. Obtain access to a Harness account and a project with **CI** enabled and an available Harness Cloud build runtime.
2. Create a GitHub connector authorized to read the `seir-devops-lab` repository.
3. Add the shared Python files to the GitHub repository.
4. Create a Harness CI pipeline in the UI and switch to the **classic YAML** definition (not v1). Paste the example below.
5. Replace `YOUR_PROJECT_ID`, `YOUR_ORG_ID`, and `YOUR_GITHUB_CONNECTOR` with real identifiers; verify the repository name.
6. Save and manually run the pipeline on `main`. Inspect the Run step; expect **3 passed**.
7. **Optional automation:** create a GitHub push trigger in Harness and test with a new commit. The sample YAML's fixed `main` build does not itself install an event trigger.

**Runtime note:** Harness plan, region, and infrastructure configuration determine availability of Harness Cloud and installed tools. This sample creates a Python virtual environment inside one Run step so installation and testing share the same environment. If `python3 -m venv` is unavailable, select/configure a supported runtime with Python/venv.

## Starter pipeline YAML

**Save this as `harness-pipeline.yaml`.** The same file is included alongside this README.

```yaml
pipeline:
  name: SEIR DevOps - Harness CI
  identifier: seir_devops_ci
  projectIdentifier: YOUR_PROJECT_ID
  orgIdentifier: YOUR_ORG_ID
  tags: {}
  properties:
    ci:
      codebase:
        connectorRef: YOUR_GITHUB_CONNECTOR
        repoName: seir-devops-lab
        build:
          type: branch
          spec:
            branch: main
  stages:
    - stage:
        name: Build and Test
        identifier: build_and_test
        type: CI
        spec:
          cloneCodebase: true
          platform:
            os: Linux
            arch: Amd64
          runtime:
            type: Cloud
            spec: {}
          execution:
            steps:
              - step:
                  type: Run
                  name: Run Python tests
                  identifier: run_python_tests
                  spec:
                    shell: Bash
                    command: |-
                      python3 --version
                      python3 -m venv .venv
                      . .venv/bin/activate
                      python -m pip install -r requirements.txt
                      python -m pytest -v
```

## Exercise: Make the pipeline fail, then fix it

1. Run the initial pipeline and capture evidence showing the three successful tests.
2. Edit `tests/test_app.py`, changing the expected withdrawal result from `60` to `999`.
3. Commit and push the change. For platforms without a configured push trigger, start a pipeline run manually.
4. Find the failing assertion and identify which stage/job/step reported it.
5. Restore the expected value to `60`, commit, and run the pipeline again.
6. Explain in your own words what the execution agent/runner did and where the YAML was stored.

## Troubleshooting guide

- **Connector not found / clone failure:** verify connector identifier, credentials and repository access.
- **Cannot start the pipeline:** verify CI entitlement, org/project access and Harness Cloud availability.
- **YAML validation fails:** ensure the pipeline uses **classic** YAML, not the simplified v1 format.
- **`venv` or Python missing:** check the selected build runtime and Python installation.
- **Pushes do not trigger a run:** configure a separate Harness GitHub trigger; a `build` branch selector is not a webhook trigger.
- **AI assistance not shown:** verify that the specific Harness AI feature is supported and enabled; this ordinary CI YAML does not activate an AI feature.

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

Introduce optional Harness AI-assisted troubleshooting, test intelligence where supported, artifact creation, deployment approvals and promotion to ECS.

## Official documentation

https://developer.harness.io/docs/continuous-integration/development-guides/ci-dotnet/
https://developer.harness.io/docs/continuous-integration/
