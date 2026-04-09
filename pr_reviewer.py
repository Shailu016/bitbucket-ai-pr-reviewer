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
    "AWS Access Key": r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Generic Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    "RSA Private Key": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
    "GitHub Token": r"(?i)gh[pousr]_[A-Za-z0-9_]{36,40}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
    "Password in URL": r"(?i)https?://[^:\n\s]+:[^@\n\s]+@[^/\n\s]+",
    "Slack Webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
}

# Configurable Heuristics (Replaces hardcoded ground-truth logic)
GROUND_TRUTH_HEURISTICS = {
    "reactnativewebview": "Native app bridge/detection timing risk: ensure idempotent checks, as bridge may late-arrive.",
    "store.commit": "Potential unsafe state mutation in lifecycle: verify guard clauses and awaited actions.",
    "dispatch": "Potential unsafe state mutation in lifecycle: verify guard clauses and awaited actions.",
    "updatewindowwidth": "Layout recalculation triggered by window width changes; ensure debounced or guarded to avoid thrash.",
    "resize": "Layout recalculation triggered by window width changes; ensure debounced or guarded to avoid thrash.",
    "timezone": "Date/Time formatting across locales could vary; verify locale handling and timezone normalization.",
    "i18n": "Date/Time formatting across locales could vary; verify locale handling and timezone normalization."
}

# File size limits for diff processing
MAX_FILE_DIFF_CHARS = 20000
MAX_FILES_IN_DIFF = 50
MAX_CONTEXT_FILES = 5
MAX_CONTEXT_PER_FILE = 15000

# Strict System Prompts to eliminate AI hallucinated warnings
SYSTEM_PROMPT = (
    "You are an elite, pragmatic Senior Code Reviewer. "
    "Your goal is to find DEFINITIVE bugs, security flaws, and performance regressions. "
    "DO NOT act like a linter. DO NOT point out theoretical edge cases unless they represent a high-probability risk. "
    "If a piece of code is logically sound based on the provided context, assume it works. "
    "Never use phrases like 'this could potentially' or 'this might'. If you cannot prove it is a bug based on the diff, DO NOT mention it."
)

# UPDATED: Now mandates a PR Summary format
REVIEW_PROMPT_TEMPLATE = """
ROLE: Pragmatic Senior Code Reviewer
CONTEXT: Reviewing a Pull Request for a production application.

Repository: {repo_name}
Title: {title}
Author: {author}
Description: {description}

PROPOSED CHANGES:
{diff}

FULL FILE CONTEXT:
{full_context}

INSTRUCTIONS:
1. PR SUMMARY: You MUST start your response with a "### 📝 PR Summary" section containing 2-3 bullet points translating the technical diff into a plain-English summary of what this PR accomplishes (e.g., "Adds user authentication component", "Fixes memory leak in dashboard").
2. CODE REVIEW: After the summary, provide a "### 🔎 Code Review" section.
3. In the review section, ONLY report actual, provable bugs or severe security flaws. Ignore stylistic preferences.
4. If there are no definitive bugs to report, write "**STATUS: PERFECT** 🚀 - No critical issues found." under the Code Review section.
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
            raise APIConnectionError(f"Retry exhausted for {func.__name__}")
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
    
    active_model = config.llm_model
    if len(prompt) > 60000 and config.llm_fallback_model:
        logger.warning(f"Prompt is very large ({len(prompt)} chars). Switching to fallback model: {config.llm_fallback_model}")
        active_model = config.llm_fallback_model

    body = {
        "model": active_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT}, 
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
    }
    return url, headers, body

@with_retries((RequestException,), tries=3, max_total_time=120)
def generate_llm_review(prompt: str, config: argparse.Namespace) -> str:
    if not prompt or not isinstance(prompt, str):
        raise ValueError("Prompt must be a valid, non-empty string.")
    
    url, headers, body = _build_llm_request(prompt, config)
    last_exception = None
    
    for attempt in range(4):
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
                raise LLMParsingError("LLM Parsing: empty content.")
                
            return content.strip()
            
        except (LLMParsingError, APIConnectionError) as e:
            last_exception = e
            if attempt < 3:
                wait_time = min(10 * (2 ** attempt), 60)
                logger.warning(f"LLM error (attempt {attempt + 1}). Retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
            continue
        except RequestException as e:
            last_exception = APIConnectionError(f"LLM network error: {e}")
            if attempt < 3:
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
    m = re.match(r"^diff --git a/(.+) b/(.+)$", line)
    if not m:
        return None
    file_path = m.group(1)
    file_name = file_path.split('/')[-1]
    ext = os.path.splitext(file_name)[1].lower()
    return {'path': file_path, 'name': file_name, 'ext': ext}

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
                skip_current_file = True
            else:
                skip_current_file = False
                
        if skip_current_file:
            continue
        
        if current_file_chars > MAX_FILE_DIFF_CHARS:
            if not filtered_lines or filtered_lines[-1] != f"... [WARNING: FILE TRUNCATED ({MAX_FILE_DIFF_CHARS} chars)]":
                filtered_lines.append(f"... [WARNING: FILE TRUNCATED ({MAX_FILE_DIFF_CHARS} chars)]")
            continue
        
        current_file_chars += len(line) + 1
        filtered_lines.append(line)
            
    return '\n'.join(filtered_lines)

def post_pr_comment(base_url: str, auth: tuple, 
                    timeout: int, review_text: str) -> None:
    logger.info("Posting new AI review comment...")
    comments_url = f"{base_url}/comments"
    payload = {
        "content": {"raw": f"{review_text}"} # Removed robot face prefix here, as it's handled by the LLM template now
    }
    
    try:
        bitbucket_request("POST", comments_url, auth, timeout, json=payload)
    except APIConnectionError as e:
        logger.error(f"Failed to post comment to Bitbucket: {e}")

def generate_ground_truth(pr: dict, diff: str, full_context: str) -> str:
    issues = set()
    d_lower = (diff or "").lower()
    ctx_lower = (full_context or "").lower()

    for keyword, warning in GROUND_TRUTH_HEURISTICS.items():
        if keyword in d_lower or keyword in ctx_lower:
            issues.add(f"- {warning}")

    if "ghp_" in ctx_lower or "bearer" in ctx_lower:
        issues.add("- Potential secrets leakage in full context; ensure secret scrubbing is comprehensive.")

    if not issues:
        return ""
    
    return "GROUND-TRUTH HEURISTICS DETECTED:\n" + "\n".join(issues)

# =========================
# Context Fetching
# =========================

def safe_truncate(text: str, max_chars: int, truncation_msg: str) -> str:
    if len(text) <= max_chars:
        return text
    cut_index = text.rfind('\n', 0, max_chars)
    if cut_index == -1:
        cut_index = max_chars  
    return text[:cut_index] + f"\n\n... {truncation_msg}"

def fetch_file_content(workspace: str, repo_slug: str, commit_hash: str, file_path: str, auth: tuple, timeout: int = 30) -> str:
    url = f"{BITBUCKET_API_BASE}/repositories/{workspace}/{repo_slug}/src/{commit_hash}/{file_path}"
    resp = requests.get(url, auth=auth, timeout=timeout)
    if resp.ok:
        return resp.text
    return ""

def build_review_prompt(pr: dict, diff: str, linter_errors: str = "", full_context: str = "") -> str:
    if not diff or not isinstance(diff, str):
        diff = ""
    dest_repo = pr.get("destination", {}).get("repository", {})
    base_prompt = REVIEW_PROMPT_TEMPLATE.format(
        repo_name=dest_repo.get("full_name", "Unknown"),
        title=pr.get("title", "Untitled"),
        author=pr.get("author", {}).get("display_name", "Unknown"),
        description=(pr.get("description") or "(none)").strip(),
        full_context=full_context,
        diff=diff
    )
    base_prompt = base_prompt.strip()

    ground_truth = generate_ground_truth(pr, diff, full_context)
    if ground_truth:
        base_prompt += "\n\n" + ground_truth

    if linter_errors and isinstance(linter_errors, str) and linter_errors.strip():
        safe = linter_errors.strip()
        if "No lint errors found" in safe:
            return base_prompt
            
        noise_keywords = [
            "npm warn", "npm WARN", "npx", "browserslist", "caniuse-lite",
            "update-browserslist", "Why you should", "https://github.com",
            "DONE ", "lint", "vue-cli-service", "@", ">"
        ]
        error_lines = []
        for line in safe.split('\n'):
            stripped = line.strip()
            if not stripped or any(n in stripped for n in noise_keywords):
                continue
            error_lines.append(stripped)
            
        if error_lines:
            formatted = "\n- ".join(error_lines)
            base_prompt += "\n\n### LINTER FINDINGS\n- " + formatted

    return base_prompt

def fetch_context_for_changes(workspace: str, repo_slug: str, source_commit: str, changed_paths: List[str], auth: tuple) -> str:
    parts: List[str] = []
    for i, path in enumerate(changed_paths):
        if i >= MAX_CONTEXT_FILES:
            break
        content = fetch_file_content(workspace, repo_slug, source_commit, path, auth, timeout=30)
        if not content:
            continue
            
        if len(content) > MAX_CONTEXT_PER_FILE:
            content = safe_truncate(content, MAX_CONTEXT_PER_FILE, "[TRUNCATED FILE CONTEXT TO PREVENT TOKEN OVERFLOW]")
            
        parts.append(f"--- FILE: {path} ---\n{content}")
    return "\n\n".join(parts)

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
    parser.add_argument("--llm-fallback-model", default=os.getenv("LLM_FALLBACK_MODEL", "gpt-4o"))
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
            logger.info("BITBUCKET_PR_ID missing. Skipping review.")
            return 0

        auth = (os.getenv("BITBUCKET_USER"), os.getenv("BITBUCKET_APP_PASSWORD"))
        base_url = f"{BITBUCKET_API_BASE}/repositories/{workspace}/{repo_slug}/pullrequests/{pr_id}"

        logger.info(f"Starting analysis for PR #{pr_id}...")
        pr_details = bitbucket_request("GET", base_url, auth, args.api_timeout)
        
        raw_diff = bitbucket_request("GET", f"{base_url}/diff", auth, args.api_timeout)
        if not raw_diff or not isinstance(raw_diff, str) or not raw_diff.strip():
            logger.info("Diff is empty or unavailable. Waiting 5 seconds...")
            time.sleep(5)
            raw_diff = bitbucket_request("GET", f"{base_url}/diff", auth, args.api_timeout)
            if not raw_diff or not isinstance(raw_diff, str) or not raw_diff.strip():
                logger.warning("PR diff is permanently empty. Skipping analysis.")
                return 0

        clean_diff = filter_noise_from_diff(raw_diff)
        if not clean_diff.strip():
            logger.info("Diff contained only noisy files. Skipping AI analysis.")
            return 0

        # --- Active Secret Scanning Integration ---
        secrets = scan_for_secrets(clean_diff)
        if secrets:
            logger.error(f"❌ {len(secrets)} Secrets detected in diff! Failing pipeline immediately.")
            secret_details = "\n".join([f"- **{s['type']}**: `{s['line_preview']}...`" for s in secrets])
            secret_msg = f"### 🛑 CRITICAL SECURITY RISK\n\nHardcoded secrets detected in this PR. Please rotate these credentials immediately and remove them from the commit history:\n{secret_details}"
            post_pr_comment(base_url, auth, args.api_timeout, secret_msg)
            return 1  

        changed_paths: List[str] = []
        if workspace and repo_slug:
            source_commit = pr_details.get("source", {}).get("commit", {}).get("hash", "")
            for line in raw_diff.splitlines():
                header = _parse_diff_header(line)
                if header:
                    if header["ext"] in EXCLUDED_EXTENSIONS or header["name"] in EXCLUDED_FILES:
                        continue
                    changed_paths.append(header["path"])
            
            seen = set()
            unique_changed = []
            for p in changed_paths:
                if p not in seen:
                    unique_changed.append(p)
                    seen.add(p)

            full_context = ""
            if source_commit:
                full_context = fetch_context_for_changes(
                    workspace, repo_slug, source_commit, unique_changed[:MAX_CONTEXT_FILES], auth
                )
        else:
            full_context = ""

        prompt = build_review_prompt(pr_details, clean_diff, linter_errors, full_context=full_context)
        
        logger.info("Generating LLM review...")
        review = generate_llm_review(prompt, args)

        # UPDATED: Post the dynamically generated review (which now includes the Summary)
        if "STATUS: PERFECT" in review:
            logger.info("AI Verdict: Perfect. Posting summary and approval comment.")
        else:
            logger.info("AI Verdict: Issues found. Posting summary and review comment.")
            
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
