#!/usr/bin/env python3
import os
import sys
import time
import logging
import argparse
import re
import json
from functools import wraps
from typing import Any, Callable, List, Optional, Dict, Tuple

import requests
from requests.exceptions import RequestException, HTTPError

# =========================
# Configuration & Constants
# =========================

BITBUCKET_API_BASE = "https://api.bitbucket.org/2.0"
MAX_DIFF_CHARS = 80000
MAX_LLM_RETRIES = 2
DIFF_RETRY_DELAY = 5

# Smart Noise Filtering
EXCLUDED_EXTENSIONS = {
    '.svg', '.png', '.jpg', '.jpeg', '.lock', '.min.js', '.min.css', '.map'
}
EXCLUDED_FILES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock'
}

# Local Secret Scrubbing Patterns
SECRET_PATTERNS = {
    "AWS Access Key": r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",  # noqa: E501
    "Generic Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    "RSA Private Key": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
    "GitHub Token": r"(?i)gh[p|u|s|r]_[A-Za-z0-9_]" + r"{36}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
    "Password in URL": r"(?i)https?://[^:\n\s]+:[^@\n\s]+@[^/\n\s]+",
    "Slack Webhook": r"https://hooks" + r"\.slack\.com/services/[A-Za-z0-9/]+",
}

# File size limits for diff processing
MAX_FILE_DIFF_CHARS = 20000
MAX_FILES_IN_DIFF = 50

SYSTEM_PROMPT = (
    "You are an elite Senior Code Reviewer. "
    "You value reliability, security, and performance."
)

REVIEW_PROMPT_TEMPLATE = """
ROLE: Senior Code Reviewer
CONTEXT: Reviewing a Pull Request for a production Vue.js/JavaScript application.

Repository: {repo_name}
Title: {title}
Author: {author}
Description: {description}

PROPOSED CHANGES (The Diff):
{diff}

REVIEW CHECKLIST:
1. BUGS: Logic errors, null/undefined access, off-by-one errors, wrong variable names, incorrect conditions.
2. BREAKING CHANGES: Does this PR break any existing functionality? Will other files/components that depend on changed code still work correctly?
3. SYNTAX: Missing brackets, unclosed tags, trailing commas, undefined variables, misspelled identifiers, incorrect imports.
4. SECURITY: Hardcoded credentials, unvalidated user input, XSS vulnerabilities.
5. PERFORMANCE: O(N^2) operations, unnecessary re-renders, missing debounce on frequent events.

CRITICAL RULES:
- ONLY report issues you are highly confident about. Do NOT guess or speculate.
- Every issue MUST reference a specific file name and what is wrong. Example: "In `UserCard.vue`, the prop `userName` is accessed but never defined in props."
- Do NOT give generic advice like 'add logging', 'consider error handling', 'update dependencies', or 'add tests'. Only flag concrete, specific problems visible in the diff.
- Do NOT comment on code style, formatting, or naming conventions unless they cause actual bugs.
- If a section has zero issues, write exactly: "None found."

OUTPUT FORMAT:
- If the code has ZERO issues across all sections, respond EXACTLY with: STATUS: PERFECT
- Otherwise use this exact Markdown structure:

### 🛑 Critical Blockers
[Issues that WILL cause bugs, crashes, or broken functionality in production.]

### 🔤 Syntax & Typo Issues
[Code that will fail to compile or run — missing brackets, undefined variables, import errors.]

### ⚠️ Potential Issues
[Things that could break under specific conditions. Must be specific — state the exact scenario.]

### 💡 Quick Wins
[Small, concrete improvements that directly improve the changed code. No generic advice.]
"""

# =========================
# Custom Exceptions & Logging
# =========================

class ConfigurationError(Exception):
    pass


class APIConnectionError(Exception):
    pass


class LLMParsingError(Exception):
    pass

logger = logging.getLogger(__name__)

def setup_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def sanitize_log_string(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'(Bearer\s+)[A-Za-z0-9\-\._~+]+', r'\1***MASKED***', text)
    text = re.sub(r'(Basic\s+)[A-Za-z0-9\+=]+', r'\1***MASKED***', text)
    return text[:1000] + "...[TRUNCATED]" if len(text) > 1000 else text

# =========================
# Enhanced Retry Logic
# =========================

def with_retries(exceptions: tuple, tries: int = 3, delay: int = 2, 
                 backoff: int = 2, max_total_time: int = 60) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            mtries, mdelay = tries, delay
            
            while mtries > 0:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    elapsed = time.time() - start_time
                    mtries -= 1
                    
                    if mtries == 0 or elapsed + mdelay > max_total_time:
                        err_msg = f"Final failure in {func.__name__}. Error: {e}"
                        logger.error(err_msg)
                        raise
                    
                    warn_msg = f"Transient error in {func.__name__}. Retrying in {mdelay}s..."
                    logger.warning(warn_msg)
                    time.sleep(mdelay)
                    mdelay *= backoff
            return func(*args, **kwargs)
        return wrapper
    return decorator


def safe_json_loads(text: str, default: Any = None) -> Any:
    try:
        return json.loads(text) if text else default
    except (json.JSONDecodeError, TypeError):
        return default

# =========================
# API Clients
# =========================

@with_retries((RequestException,), tries=3, max_total_time=45)
def bitbucket_request(method: str, url: str, auth: tuple, 
                      timeout: int, **kwargs) -> Any:
    logger.debug(f"Request: {method} {url}")
    try:
        resp = requests.request(
            method, url, auth=auth, timeout=timeout, **kwargs
        )
        resp.encoding = 'utf-8'
        
        if not resp.ok:
            err_log = sanitize_log_string(resp.text)
            logger.error(f"Bitbucket API Error [{resp.status_code}]: {err_log}")
        resp.raise_for_status()
        
        if resp.status_code == 204:
            return None
            
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return resp.json()
        return resp.text
        
    except HTTPError as e:
        status = e.response.status_code
        err_txt = sanitize_log_string(e.response.text)
        if status in (401, 403):
            raise APIConnectionError("Bitbucket Auth Error.")
        elif status == 404:
            raise APIConnectionError(f"Bitbucket Not Found (404): {url}")
        elif status == 429:
            raise APIConnectionError("Bitbucket Rate Limit Exceeded.")
        raise APIConnectionError(f"Bitbucket HTTP {status}: {err_txt}")
    except RequestException as e:
        raise APIConnectionError(f"Network error: {str(e)}")

def _build_llm_request(prompt: str, config: argparse.Namespace) -> Tuple[str, dict, dict]:
    url = f"{config.llm_base}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.llm_key}", 
        "Content-Type": "application/json"
    }
    body = {
        "model": config.llm_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT}, 
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
    }
    return url, headers, body


@with_retries((RequestException,), tries=3, max_total_time=120)
def generate_llm_review(prompt: str, config: argparse.Namespace) -> str:
    if not prompt or not isinstance(prompt, str):
        raise ValueError("Prompt must be a valid, non-empty string.")
    
    url, headers, body = _build_llm_request(prompt, config)
    last_exception = None
    
    for attempt in range(MAX_LLM_RETRIES + 1):
        try:
            resp = requests.post(
                url, headers=headers, json=body, timeout=config.llm_timeout
            )
            if not resp.ok:
                err_log = sanitize_log_string(resp.text)
                logger.error(f"LLM API Error [{resp.status_code}]: {err_log}")
                
                if resp.status_code == 429:
                    wait_time = min(30 * (2 ** attempt), 120)
                    logger.warning(f"Rate limited. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                if resp.status_code >= 500:
                    last_exception = APIConnectionError(f"LLM server error: {resp.status_code}")
                    continue
                    
            resp.raise_for_status()
            
            data = safe_json_loads(resp.text)
            if not data or not isinstance(data, dict):
                raise LLMParsingError("Invalid JSON response from LLM.")
            
            choices = data.get("choices")
            if not choices or not isinstance(choices, list) or len(choices) == 0:
                raise LLMParsingError("LLM response missing 'choices' array.")
                
            content = choices[0].get("message", {}).get("content")
            if not content or not isinstance(content, str) or not content.strip():
                raise LLMParsingError("LLM returned empty or invalid text content.")
                
            return content.strip()
            
        except (LLMParsingError, APIConnectionError) as e:
            last_exception = e
            if attempt < MAX_LLM_RETRIES:
                wait_time = min(10 * (2 ** attempt), 60)
                logger.warning(f"LLM error (attempt {attempt + 1}). Retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
            continue
        except RequestException as e:
            last_exception = APIConnectionError(f"LLM network error: {e}")
            if attempt < MAX_LLM_RETRIES:
                wait_time = min(10 * (2 ** attempt), 60)
                logger.warning(f"LLM network error (attempt {attempt + 1}). Retrying in {wait_time}s")
                time.sleep(wait_time)
            continue
    
    raise last_exception or APIConnectionError("LLM generation failed after retries")

# =========================
# Domain Logic & Formatting
# =========================

def scan_for_secrets(diff: str) -> List[Dict[str, str]]:
    if not diff or not isinstance(diff, str):
        return []
        
    found_secrets = []
    # Only scan added lines (+), ignore context and removed lines (-)
    added_lines = "\n".join([line for line in diff.split('\n') if line.startswith('+') and not line.startswith('+++')])

    for secret_name, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, added_lines)
        for match in matches:
            found_secrets.append({
                'type': secret_name,
                'line_preview': match.group(0)[:50],
            })
    return found_secrets

def _parse_diff_header(line: str) -> Optional[Dict[str, str]]:
    if not line.startswith('diff --git'):
        return None
    
    parts = line.split(' ')
    if len(parts) < 3:
        return None
    
    file_path = parts[-1]
    file_name = file_path.split('/')[-1]
    ext = os.path.splitext(file_name)[1].lower()
    
    return {
        'path': file_path,
        'name': file_name,
        'ext': ext,
    }


def _count_diff_stats(raw_diff: str) -> Dict[str, int]:
    file_count = 0
    for line in raw_diff.split('\n'):
        if line.startswith('diff --git'):
            file_count += 1
    return {'files': file_count}


def filter_noise_from_diff(raw_diff: str) -> str:
    if not raw_diff or not isinstance(raw_diff, str):
        return ""
    
    stats = _count_diff_stats(raw_diff)
    if stats['files'] > MAX_FILES_IN_DIFF:
        logger.warning(f"Diff contains {stats['files']} files (max {MAX_FILES_IN_DIFF}). Truncating.")
    
    filtered_lines = []
    skip_current_file = False
    current_file_chars = 0
    
    for line in raw_diff.split('\n'):
        header = _parse_diff_header(line)
        if header:
            current_file_chars = 0
            
            if header['ext'] in EXCLUDED_EXTENSIONS or header['name'] in EXCLUDED_FILES:
                logger.debug(f"Filtering out noisy file: {header['name']}")
                skip_current_file = True
            else:
                skip_current_file = False
                
        if skip_current_file:
            continue
        
        if current_file_chars > MAX_FILE_DIFF_CHARS:
            if not filtered_lines or filtered_lines[-1] != f"\n... [WARNING: FILE TRUNCATED ({MAX_FILE_DIFF_CHARS} char limit)]":
                filtered_lines.append(f"\n... [WARNING: FILE TRUNCATED ({MAX_FILE_DIFF_CHARS} char limit)]")
            continue
        
        current_file_chars += len(line) + 1
        filtered_lines.append(line)
            
    return '\n'.join(filtered_lines)

def post_pr_comment(base_url: str, auth: tuple, 
                    timeout: int, review_text: str) -> None:
    logger.info("Posting new AI review comment...")
    comments_url = f"{base_url}/comments"
    payload = {
        "content": {"raw": f"### :robot_face: AI Code Review\n\n{review_text}"}
    }
    
    try:
        bitbucket_request("POST", comments_url, auth, timeout, json=payload)
    except APIConnectionError as e:
        logger.error(f"Failed to post comment to Bitbucket: {e}")

def build_review_prompt(pr: dict, diff: str, linter_errors: str = "") -> str:
    if not diff or not isinstance(diff, str):
        diff = ""
        
    if len(diff) > MAX_DIFF_CHARS:
        logger.warning("Diff exceeds maximum threshold. Truncating.")
        diff = diff[:MAX_DIFF_CHARS] + "\n\n... [WARNING: DIFF TRUNCATED]"
        
    dest_repo = pr.get("destination", {}).get("repository", {})
    base_prompt = REVIEW_PROMPT_TEMPLATE.format(
        repo_name=dest_repo.get("full_name", "Unknown"),
        title=pr.get("title", "Untitled"),
        author=pr.get("author", {}).get("display_name", "Unknown"),
        description=(pr.get("description") or "(none)").strip(),
        diff=diff
    ).strip()

    if linter_errors and isinstance(linter_errors, str) and linter_errors.strip():
        safe_linter = linter_errors.strip()

        # If the linter passed with no errors, skip injecting noise
        if "No lint errors found!" in safe_linter:
            logger.info("Linter passed cleanly. No cross-file issues.")
            return base_prompt

        # Filter out npm noise — keep only actual error lines
        noise_keywords = [
            "npm warn", "npm WARN", "npx", "browserslist", "caniuse-lite",
            "update-browserslist", "Why you should", "https://github.com",
            "DONE ", "lint", "vue-cli-service", "@", ">",
        ]
        error_lines = []
        for line in safe_linter.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            if any(noise in stripped for noise in noise_keywords):
                continue
            error_lines.append(stripped)

        # If after filtering there are no real errors, skip injection
        if not error_lines:
            logger.info("Linter output was only warnings/noise. Skipping.")
            return base_prompt

        if len(error_lines) > 200:
            logger.warning("Too many linter errors. Truncating to 200.")
            error_lines = error_lines[:200]

        formatted_errors = "\n".join(f"- {line}" for line in error_lines)

        logger.info(f"Injecting {len(error_lines)} real linter errors into prompt.")
        cross_file_context = f"""

### 🚨 CROSS-FILE ISSUES (from JS/Vue Linter) 🚨
The following errors were found by running the project's linter AFTER applying this PR's changes.
These errors may exist in files NOT shown in the diff — meaning this PR may have broken something elsewhere.

{formatted_errors}

INSTRUCTIONS FOR CROSS-FILE ISSUES:
- For each error above, explain in plain English what broke and which file is affected.
- If the error was clearly caused by changes in this PR's diff, put it in "🛑 Critical Blockers".
- If the error existed before this PR (pre-existing issue), briefly note it but do NOT block the PR.
- Format each finding as: **[file:line]** — clear one-sentence explanation of what is broken.
"""
        return base_prompt + cross_file_context

    return base_prompt

# =========================
# Orchestration
# =========================

def parse_positive_int(value: str, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (ValueError, TypeError):
        return default

def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-timeout", type=int, 
                        default=parse_positive_int(os.getenv("API_TIMEOUT", "15"), 15))
    parser.add_argument("--llm-timeout", type=int, 
                        default=parse_positive_int(os.getenv("LLM_TIMEOUT", "60"), 60))
    parser.add_argument("--llm-key", default=os.getenv("LLM_API_KEY"))
    parser.add_argument("--llm-base", default=os.getenv("LLM_API_BASE", "https://api.openai.com/v1"))
    parser.add_argument("--llm-model", default=os.getenv("LLM_MODEL", "gpt-4o-mini"))
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    
    is_blocking = os.getenv("BLOCK_ON_CRITICAL", "false").lower() == "true"
    parser.add_argument("--block-on-critical", action="store_true", default=is_blocking)
    
    args = parser.parse_args()
    
    missing_vars = []
    if not args.llm_key:
        missing_vars.append("LLM_API_KEY")
    if not os.getenv("BITBUCKET_USER"):
        missing_vars.append("BITBUCKET_USER")
    if not os.getenv("BITBUCKET_APP_PASSWORD"):
        missing_vars.append("BITBUCKET_APP_PASSWORD")
    
    if missing_vars:
        raise ConfigurationError(f"Missing credentials: {', '.join(missing_vars)}")
        
    return args

def main() -> int:
    try:
        args = get_args()
        setup_logging(args.log_level)
        
        workspace = os.getenv("BITBUCKET_WORKSPACE")
        repo_slug = os.getenv("BITBUCKET_REPO_SLUG")
        pr_id = os.getenv("BITBUCKET_PR_ID")
        
        linter_errors = os.getenv("LINTER_OUTPUT", "").strip()
        
        if not all([workspace, repo_slug, pr_id]):
            logger.info("BITBUCKET_PR_ID missing. Skipping PR Review.")
            return 0

        auth = (os.getenv("BITBUCKET_USER"), os.getenv("BITBUCKET_APP_PASSWORD"))
        base_url = f"{BITBUCKET_API_BASE}/repositories/{workspace}/{repo_slug}/pullrequests/{pr_id}"

        logger.info(f"Starting analysis for PR #{pr_id}...")
        pr_details = bitbucket_request("GET", base_url, auth, args.api_timeout)
        
        raw_diff = bitbucket_request("GET", f"{base_url}/diff", auth, args.api_timeout)
        if not raw_diff or not isinstance(raw_diff, str) or not raw_diff.strip():
            logger.info("Diff is empty. Waiting 5 seconds...")
            time.sleep(5)
            raw_diff = bitbucket_request("GET", f"{base_url}/diff", auth, args.api_timeout)
            
            if not raw_diff or not isinstance(raw_diff, str) or not raw_diff.strip():
                logger.warning("PR diff is permanently empty. Skipping analysis.")
                return 0

        clean_diff = filter_noise_from_diff(raw_diff)
        if not clean_diff.strip():
            logger.info("Diff contained only noisy files. Skipping AI analysis.")
            return 0

        found_secrets = scan_for_secrets(clean_diff)
        if found_secrets:
            secret_types = list(set(s['type'] for s in found_secrets))
            secrets_str = ', '.join(secret_types)
            logger.error(f"🚨 HARDCODED SECRETS DETECTED: {secrets_str}. Blocking LLM.")
            warning_msg = (
                "### 🚨 CRITICAL SECURITY ALERT 🚨\n\n"
                f"Hardcoded secrets detected: `{secrets_str}`\n\n"
                "**AI review aborted.** Please remove all secrets before proceeding.\n\n"
                "#### Details:\n"
                + "\n".join(f"- **{s['type']}**: `{s['line_preview']}...`" for s in found_secrets[:10])
            )
            post_pr_comment(base_url, auth, args.api_timeout, warning_msg)
            return 1

        prompt = build_review_prompt(pr_details, clean_diff, linter_errors)
        review = generate_llm_review(prompt, args)

        if "STATUS: PERFECT" in review:
            logger.info("AI Verdict: Perfect. Posting approval comment.")
            approval_msg = (
                "**STATUS: PERFECT** 🚀\n\n"
                "No critical blockers or edge cases found. Great work!"
            )
            post_pr_comment(base_url, auth, args.api_timeout, approval_msg)
        else:
            post_pr_comment(base_url, auth, args.api_timeout, review)

        if args.block_on_critical:
            blockers = re.search(r'### 🛑 Critical Blockers(.*?)(###|$)', review, re.DOTALL)
            if blockers:
                content = blockers.group(1).strip().lower()
                if content and "none found" not in content:
                    logger.error("❌ Critical Blockers found. Failing pipeline.")
                    return 1

        logger.info("PR review completed successfully.")
        return 0

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        return 2
    except APIConnectionError as e:
        logger.error(f"API connection error: {e}")
        return 3
    except LLMParsingError as e:
        logger.error(f"LLM parsing error: {e}")
        return 4
    except Exception:
        logger.exception("Critical failure in the PR Review Pipeline:")
        return 1

if __name__ == "__main__":
    sys.exit(main())
