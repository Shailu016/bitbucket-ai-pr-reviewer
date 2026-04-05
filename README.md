
# Bitbucket AI Pull Request Reviewer

An automated, high-speed AI code reviewer for Bitbucket Pipelines. It triggers automatically on new PRs, scans for hardcoded secrets locally to prevent data exfiltration, and injects linter output into the LLM prompt for cross-file architectural context.

## Features
* **Fully Automated:** Runs instantly when a pull request is raised without manual intervention.
* **Zero Secret Exfiltration:** A local Python scanner checks the Git diff for AWS keys, Github tokens, and generic secrets before making any LLM API calls.
* **Cross-File Context:** Runs `npm ci` and a fast linter, injecting `stdout` errors directly into the AI's prompt to catch architectural breaks instead of just nitpicking style.
* **Built for Speed:** Uses a lightweight `python-nodejs-slim` Docker image and skips slow native builds.

## Setup Instructions

1. Copy `pr_reviewer.py` to the root of your repository.
2. Update or copy the `bitbucket-pipelines.yml` file into your repository.
3. In Bitbucket, navigate to **Repository settings > Repository variables** and add the following:
   * `LLM_API_KEY`: Your chosen AI provider API key (Secured).
   * `BITBUCKET_USER`: Your Bitbucket username.
   * `BITBUCKET_APP_PASSWORD`: Your Bitbucket App Password (needs Read/Write access for Pull Requests).

## Usage
Once configured, the pipeline will run automatically on any newly opened or updated pull request. If secrets are detected, the pipeline will fail locally. Otherwise, it will post a detailed AI review as a comment on the PR.

