# SEIR Foundations DevOps Introduction: GitHub Actions

> **Audience:** SEIR Foundations students moving from Jenkins to modern CI/CD.  
> **Lab level:** Beginner | **Goal:** Run automated Python tests after retrieving application code.  
> **Scope:** CI only. No production deployment, AWS credentials, or real banking data.

## Learning objectives

By the end of this introduction, students will be able to explain what starts a pipeline, where it runs, how code is retrieved, how dependencies are installed, how unit tests report failures, and where to inspect execution logs.

## Why this platform?

GitHub Actions is a GitHub-native automation service. A **workflow** is defined in YAML inside `.github/workflows/`. A GitHub event, such as pushing code, starts a workflow. A **job** runs on a **runner**, and its **steps** execute commands or reusable Actions. For this lab, the hosted runner handles the machine provisioning; you do not install or maintain Jenkins.

**Why learn it?** GitHub is a common source-control platform, and Actions turns commits and pull requests into repeatable test results. Its fundamental concepts transfer to other CI/CD services.

## Essential vocabulary

| GitHub concept | Meaning |
| --- | --- |
| Event / `on` | Decides when a workflow starts |
| Workflow | YAML automation definition |
| Job | Group of steps on a runner |
| Runner / `runs-on` | Machine that executes the job |
| Action / `uses` | Reusable automation component |
| Command / `run` | Shell command performed by a step |

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

1. Create a GitHub repository called `seir-devops-lab` with a `main` branch.
2. Add the shared Python files from below.
3. Create `.github/workflows/ci.yml` with the example in this README.
4. Commit and push. Open **Actions** and select the workflow run.
5. Expand each step and inspect the console output. The run should show **3 passed**.
6. Use **Run workflow** to try a manual execution (enabled by `workflow_dispatch`).

## Starter pipeline YAML

**Save this as `.github/workflows/ci.yml`.** The same file is included alongside this README.

```yaml
name: SEIR DevOps - GitHub Actions
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          python -m pip install -r requirements.txt
      - name: Run tests
        run: python -m pytest -v
```

## Exercise: Make the pipeline fail, then fix it

1. Run the initial pipeline and capture evidence showing the three successful tests.
2. Edit `tests/test_app.py`, changing the expected withdrawal result from `60` to `999`.
3. Commit and push the change. For platforms without a configured push trigger, start a pipeline run manually.
4. Find the failing assertion and identify which stage/job/step reported it.
5. Restore the expected value to `60`, commit, and run the pipeline again.
6. Explain in your own words what the execution agent/runner did and where the YAML was stored.

## Troubleshooting guide

- **Workflow does not start:** verify the file is under `.github/workflows/`, Actions is enabled, and the branch is `main`.
- **`ModuleNotFoundError: app`:** execute tests from repository root, keep `app.py` at root, and verify the file was committed.
- **No successful tests:** read the `Run tests` step; determine whether it is an environment error or an assertion failure.
- **Permissions error:** verify repository/workflow settings; this lab grants only read access to repository contents.

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

Extend the workflow to build a Docker image, push it to Amazon ECR using AWS OIDC federation, and deploy to ECS after approval.

## Official documentation

https://docs.github.com/en/actions/tutorials/build-and-test-code/python
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
