import os
import re

# Define what "secrets" look like
SECRET_PATTERNS = {
    "API Key": r"(api[_-]?key\s*[:=]\s*[\'\"][A-Za-z0-9_\-]{16,}[\'\"])",
    "Token": r"(token\s*[:=]\s*[\'\"][A-Za-z0-9_\-]{16,}[\'\"])",
    "Password": r"(password\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"])",
    "AWS Secret": r"(aws_secret_access_key\s*[:=]\s*[\'\"][A-Za-z0-9/+=]{40}[\'\"])",
}

def scan_file(file_path):
    flagged_lines = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        for idx, line in enumerate(lines):
            for name, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    flagged_lines.append((idx + 1, name, line.strip()_
