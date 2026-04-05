
# Bitbucket AI Pull Request Reviewer

An automated, high-speed, enterprise-grade AI code reviewer for Bitbucket Pipelines. It triggers automatically on new PRs, scans for hardcoded secrets locally to prevent data exfiltration, injects linter output into the LLM prompt for cross-file architectural context, and actively blocks merges if critical bugs are found.

## 🔥 Advanced Features

* **Fully Automated:** Runs instantly when a pull request is raised or updated without manual intervention.
* **Zero Secret Exfiltration:** A local Python scanner checks the Git diff for AWS keys, Github tokens, generic API keys, and more before making *any* external LLM API calls. If secrets are found, it halts the pipeline locally so your credentials never leave your server.
* **Cross-File Architectural Context:** Runs `npm ci` and a fast linter, injecting `stdout` errors directly into the AI's prompt. This forces the AI to catch breaking changes across multiple files instead of just guessing from a single diff.
* **Intelligent Noise Filtering:** Automatically ignores noisy files (`package-lock.json`, `.min.js`, `.svg`) and surgically truncates massive diffs to save AI tokens and prevent context-window hallucinations.
* **Pipeline Blocking:** If the AI detects a "Critical Blocker" (and the `--block-on-critical` flag is set), the script actively fails the Bitbucket pipeline, preventing bad code from being merged.
* **Network Resilience:** Built-in exponential backoff and retry logic smoothly handles Bitbucket/LLM API rate limits (HTTP 429) and timeouts, ensuring your CI/CD pipeline doesn't fail due to flaky networks.
* **Auto-Approvals:** If the AI finds zero issues across all checks, it automatically posts a clean "STATUS: PERFECT 🚀" approval message so developers can merge immediately.
* **Built for Speed:** Uses a lightweight `python-nodejs-slim` Docker image and skips slow native C++ builds to run in seconds instead of minutes.

## ⚙️ Setup Instructions

1. Copy `pr_reviewer.py` to the root of your repository.
2. Update or copy the `bitbucket-pipelines.yml` file into your repository.
3. In Bitbucket, navigate to **Repository settings > Repository variables** and add the following:
   * `LLM_API_KEY`: Your chosen AI provider API key (Secured).
   * `BITBUCKET_USER`: Your Bitbucket username.
   * `BITBUCKET_APP_PASSWORD`: Your Bitbucket App Password (needs Read/Write access for Pull Requests).

## 🚀 Usage

Once configured, the pipeline will run automatically on any newly opened or updated pull request. 

* If secrets are detected, the pipeline will fail locally immediately. 
* If the code is clean, it will post a detailed AI review as a comment on the PR. 
* If critical blockers are found by the AI, it will flag them and fail the pipeline to protect your production environment.
