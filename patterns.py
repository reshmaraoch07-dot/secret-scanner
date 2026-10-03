"""
Secret Scanner - Pattern Definitions and Utility Functions
Defines regex patterns for detecting passwords, API keys, secret keys, tokens,
database credentials, and cloud credentials with severity levels and masking logic.
"""

import re

# Severity Levels
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# List of Supported Extensions
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".java", ".c", ".cpp", ".html", ".css",
    ".json", ".xml", ".yaml", ".yml", ".env", ".txt",
    ".properties", ".ini", ".config", ".sh", ".bash"
}

# Directories to exclude during scanning
DEFAULT_EXCLUDE_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv",
    "dist", "build", ".idea", ".vscode", ".pytest_cache", "tests", "demo_samples"
}

# Secret Pattern Definitions
# Each pattern contains:
# - name: Friendly type name
# - pattern: Compiled regex pattern
# - severity: HIGH, MEDIUM, or LOW
# - description: Brief explanation

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": SEVERITY_HIGH,
        "description": "Exposed AWS Access Key ID"
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r"(?i)\b[a-z0-9_-]*(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "severity": SEVERITY_HIGH,
        "description": "Exposed AWS Secret Access Key"
    },
    {
        "name": "Password Assignment",
        "pattern": re.compile(
            r"(?i)\b[a-z0-9_-]*(?:password|passwd|pass_word|db_password|db_pass|user_password|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"
        ),
        "severity": SEVERITY_HIGH,
        "description": "Exposed hardcoded password"
    },
    {
        "name": "API Key Assignment",
        "pattern": re.compile(
            r"(?i)\b[a-z0-9_-]*(?:api[_-]?key|apikey|api_secret|app_key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?"
        ),
        "severity": SEVERITY_HIGH,
        "description": "Exposed API Key"
    },
    {
        "name": "Secret Key Assignment",
        "pattern": re.compile(
            r"(?i)\b[a-z0-9_-]*(?:secret[_-]?key|client[_-]?secret|private[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?"
        ),
        "severity": SEVERITY_HIGH,
        "description": "Exposed Secret Key"
    },
    {
        "name": "Access / Auth Token",
        "pattern": re.compile(
            r"(?i)\b[a-z0-9_-]*(?:access[_-]?token|auth[_-]?token|jwt[_-]?token|bearer[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?"
        ),
        "severity": SEVERITY_HIGH,
        "description": "Exposed Access / Auth Token"
    },
    {
        "name": "Database Connection String",
        "pattern": re.compile(
            r"(?i)\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp):\/\/[^:\s]+:([^@\s]+)@[^:\s]+"
        ),
        "severity": SEVERITY_HIGH,
        "description": "Database URL containing username/password credentials"
    },
    {
        "name": "Private Key Block",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        "severity": SEVERITY_HIGH,
        "description": "Embedded RSA/EC Private Key Header"
    },
    {
        "name": "Generic Token",
        "pattern": re.compile(
            r"(?i)\b[a-z0-9_-]*(?:token|auth_key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{12,})['\"]?"
        ),
        "severity": SEVERITY_MEDIUM,
        "description": "Potential authentication token"
    },
    {
        "name": "Database Config",
        "pattern": re.compile(
            r"(?i)\b[a-z0-9_-]*(?:database_url|db_uri|db_host|db_connection)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?"
        ),
        "severity": SEVERITY_MEDIUM,
        "description": "Database connection setting"
    },
    {
        "name": "Suspicious Config Value",
        "pattern": re.compile(
            r"(?i)\b[a-z0-9_-]*(?:auth_user|db_user|smtp_user)\s*[:=]\s*['\"]?([^\s'\"]{3,})['\"]?"
        ),
        "severity": SEVERITY_LOW,
        "description": "Exposed system/service username or parameter"
    }
]

# Words that indicate non-secret placeholder or code comment/label lines
FALSE_POSITIVE_INDICATORS = [
    "example", "placeholder", "your_password", "enter_password",
    "change_me", "mypassword", "xxxx", "123456789", "<password>", "{$"
]

def is_comment_or_label(line: str) -> bool:
    """
    Determines if a line is a code comment or UI text label/prompt/docstring/HTML markup.
    Helps reduce false positives on comments and print/input UI strings.
    """
    stripped = line.strip()
    # Check common line comments and docstring boundaries
    if stripped.startswith(("#", "//", "/*", "*", "<!--", ";", '"""', "'''")):
        # If it's a docstring or comment line without explicit variable assignment, skip
        if not re.search(r"^[A-Za-z0-9_-]+\s*[:=]\s*['\"]", line):
            return True
        if stripped.startswith(("#", "//", "/*", "<!--", ";")):
            return True
    
    # Check print/log/input statements, HTML tags or placeholders
    lower_line = stripped.lower()
    if any(tag in lower_line for tag in ["print(", "console.log(", "logger.", "input(", "placeholder=", "<label>", "<input>", "<code>", "</code>", "<pre>", "</pre>", "<p>", "</p>", "<textarea>"]):
        return True

    return False


def mask_secret(secret_val: str) -> str:
    """
    Safely masks a secret string so that the raw value is never revealed.
    Examples:
        'mypassword123' -> 'my********'
        'AKIA_EXAMPLE_KEY' -> 'AKIA_***********'
        'abc' -> '***'
    """
    if not secret_val:
        return "*******"
    
    val_str = str(secret_val).strip("'\"")
    length = len(val_str)
    
    if length <= 4:
        return "*" * length
    elif length <= 8:
        return val_str[:1] + "*" * (length - 1)
    else:
        # Keep first 2 characters, mask the rest
        return val_str[:2] + "*" * (length - 2)


def mask_line_context(line: str, secret_val: str) -> str:
    """
    Masks occurrences of the secret value inside the entire source line.
    """
    if not secret_val or secret_val not in line:
        return line.strip()
    
    masked_val = mask_secret(secret_val)
    return line.replace(secret_val, masked_val).strip()
