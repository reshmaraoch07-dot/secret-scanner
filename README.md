# 🔐 Secret Scanner — DevSecOps Code Security Audit Tool

A lightweight, clean, web-based security tool designed for DevOps/DevSecOps education and demonstration. **Secret Scanner** scans source code files to detect accidentally hardcoded secrets such as passwords, API keys, access tokens, AWS keys, and database credentials before code is committed or deployed.

---

## 📌 1. Project Objective

In modern software development, accidentally committing sensitive credentials to public or private Git repositories is a major security vulnerability. 

The objective of **Secret Scanner** is to demonstrate how automated security scanning (**DevSecOps**) can be integrated seamlessly into a continuous integration / continuous deployment (**CI/CD**) pipeline using **GitHub Actions**, catching exposed credentials early in the development lifecycle (Shift-Left Security).

---

## 🚨 2. Problem Statement

Developers frequently hardcode secrets during rapid prototyping:
```python
# Dangerous practice!
API_KEY = "sk_live_998877665544332211"
DATABASE_URL = "postgres://admin:mypassword123@localhost:5432/mydb"
```
When pushed to repositories, automated bots harvest these exposed credentials within minutes, leading to unauthorized data breaches, cloud resource exploitation, and financial loss.

---

## 🛡️ 3. Proposed Solution

**Secret Scanner** acts as a pre-commit / CI gatekeeper:
1. **Scans codebase files** using customizable Python Regular Expressions (Regex).
2. **Masks detected secret values** (e.g. `password = "my********"`) so sensitive data is never displayed in logs or UI.
3. **Fails CI/CD workflows** with **Exit Code 1** when secrets are found, blocking pull requests or deployment builds.
4. **Passes clean code** with **Exit Code 0** when no secrets are detected.

---

## ✨ 4. Key Features

* **Multi-Format File Scanning:** Supports `.py`, `.js`, `.java`, `.c`, `.cpp`, `.html`, `.css`, `.json`, `.xml`, `.yaml`, `.yml`, `.env`, `.txt`, `.properties`, `.ini`, `.config`, `.sh`.
* **Pattern Detection:**
  * Passwords & Hashes (`password = "..."`, `db_password = "..."`)
  * API Keys (`API_KEY = "..."`, `app_key = "..."`)
  * Secret Keys & Client Secrets (`SECRET_KEY = "..."`)
  * Auth / Access Tokens (`access_token = "..."`, `bearer_token = "..."`)
  * Database Credentials & Connection Strings (`postgres://user:pass@host/db`)
  * AWS Access Key IDs (`AKIA` followed by 16 alphanumeric characters)
  * Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
* **Safe Secret Masking:** Never displays full secret strings; replaces values with asterisks `*`.
* **Severity Levels:** Categorizes findings into `HIGH`, `MEDIUM`, and `LOW`.
* **Dual Operation Modes:**
  * **Command-Line Interface (CLI):** `python scanner.py .` for terminal & CI automation.
  * **Interactive Web Dashboard:** Modern Flask UI with file drag-and-drop, folder path scanning, and live code snippet analysis.
* **Scan History:** Keeps track of previous scans in a lightweight local JSON file (`scan_history.json`).
* **CI/CD Automation:** Native GitHub Actions workflow (`.github/workflows/security-scan.yml`).
* **False Positive Reduction:** Skips code comments (`#`, `//`), UI prompt text (`print("enter password")`), docstrings, and standard ignored directories (`.git`, `venv`, `node_modules`, `__pycache__`).

---

## 🛠️ 5. Technologies Used

* **Frontend:** HTML5, CSS3 (Vanilla Dark Security Theme with Glassmorphism), JavaScript (ES6 fetch API)
* **Backend:** Python 3, Flask Web Framework
* **Security Scanner Engine:** Python `re` (Regular Expressions)
* **DevOps / CI/CD:** Git, GitHub, GitHub Actions
* **Testing:** Python `unittest` framework

---

## 🏗️ 6. Project Architecture

```
secret-scanner/
│
├── app.py                      # Flask Web Application & REST API
├── scanner.py                  # Core Scanning Engine & CLI Entrypoint
├── patterns.py                 # Secret Regex Patterns, Severities & Masking Logic
├── example.py                  # Sample File for College Demo
├── requirements.txt            # Python Dependencies (Flask, pytest)
├── README.md                   # Project Documentation
├── .gitignore                  # Git Exclusion Rules (venv, .env, __pycache__)
│
├── tests/
│   └── test_scanner.py         # Automated Test Suite (8 Test Cases)
│
├── templates/
│   └── index.html              # Web Dashboard HTML Template
│
├── static/
│   ├── style.css               # Security Dark Mode Stylesheet
│   └── script.js               # Frontend Interactivity & API Client
│
└── .github/
    └── workflows/
        └── security-scan.yml   # GitHub Actions CI/CD Pipeline
```

---

## 🔄 7. DevSecOps Workflow

```
Developer writes code
         │
         ▼
        Git (Local commit)
         │
         ▼
      GitHub (Push / Pull Request)
         │
         ▼
  GitHub Actions (CI Runner)
         │
         ▼
    Run Tests (python -m unittest)
         │
         ▼
Secret Scanner Audit (python scanner.py .)
         │
    ┌────┴────┐
    ▼         ▼
 ✅ PASS   ❌ FAIL (Exit Code 1)
```

---

## ⚙️ 8. How the Scanner Works

```
   +-----------------------+
   |   Source Code Files   |
   +-----------------------+
               |
               v
   +-----------------------+
   |   Directory Filtering |  ---> Skips .git, venv, node_modules, __pycache__
   +-----------------------+
               |
               v
   +-----------------------+
   |  Line-by-Line Regex   |  ---> Skips comments (# //) & UI print strings
   |   Pattern Matching    |
   +-----------------------+
               |
               v
   +-----------------------+
   |   Secret Masking &    |  ---> Replaces raw credentials with asterisks (my********)
   | Severity Categorizer  |
   +-----------------------+
               |
        +------+------+
        |             |
        v             v
  [0 Secrets]    [Secrets Found]
        |             |
        v             v
    Exit Code 0   Exit Code 1
  ✅ PASS (CI)   ❌ FAIL (CI)
```

---

## 💻 8. Installation & Setup Instructions

### Prerequisites
* Python 3.8 or higher installed on your system.
* Git installed.

### Step 1: Clone or Navigate to Directory
```bash
cd /path/to/secret-scanner
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
```

### Step 3: Activate Virtual Environment
* **On macOS / Linux:**
  ```bash
  source venv/bin/activate
  ```
* **On Windows:**
  ```cmd
  venv\Scripts\activate
  ```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 9. How to Run Locally

### 1. Launch Web Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### 2. Run Command-Line Scanner (CLI)
You can scan any folder or file directly from the terminal without running Flask:
```bash
python scanner.py .
```
Or scan a specific folder:
```bash
python scanner.py /path/to/project
```

### 3. Run Automated Unit Tests
```bash
python -m unittest discover tests
```

---

## 📊 10. CLI Output Examples

### Example 1 — Successful Scan (No Secrets Detected)
```
Scanning project path: '.'...
==================================================
                SECRET SCANNER
==================================================
Target Path    : /Users/student/secret-scanner
Files Scanned  : 5
Lines Scanned  : 620
Secrets Found  : 0
Scan Duration  : 14.25 ms
--------------------------------------------------
==================================================
✅ SECURITY SCAN PASSED
No potential secrets were detected.
==================================================
```
*(Exit code: `0`)*

---

### Example 2 — Failed Scan (Secrets Detected)
```
Scanning project path: '.'...
==================================================
                SECRET SCANNER
==================================================
Target Path    : /Users/student/my-app
Files Scanned  : 8
Lines Scanned  : 940
Secrets Found  : 2
Scan Duration  : 22.10 ms
--------------------------------------------------

DETAILED FINDINGS:
--------------------------------------------------
1. File     : config.py
   Line     : 12
   Type     : Password Assignment
   Severity : HIGH
   Match    : password = "my********"

2. File     : app.js
   Line     : 27
   Type     : API Key Assignment
   Severity : HIGH
   Match    : API_KEY = "sk************************"

==================================================
❌ SECURITY SCAN FAILED
Potential secrets detected in codebase!
==================================================
```
*(Exit code: `1`)*

---

## 🔄 11. GitHub Actions CI/CD Integration

The workflow `.github/workflows/security-scan.yml` automatically triggers on every `git push` or `pull_request`:

1. Checkouts the codebase.
2. Sets up Python 3.11 environment.
3. Installs requirements (`pip install -r requirements.txt`).
4. Executes unit tests (`python -m unittest discover tests`).
5. Executes the secret scanner CLI (`python scanner.py .`).
6. If exit code is `0`, GitHub Actions marks the workflow with **`✅ Security scan passed`**.
7. If exit code is `1`, GitHub Actions marks the workflow with **`❌ Security scan failed`**, preventing broken code from merging.

---

## 🎓 12. College Presentation Demonstration Steps

Follow these simple steps during your presentation to impress evaluators:

### Demo 1 — Safe Code (Build Passes)
1. Open `example.py` in VS Code / text editor:
   ```python
   name = "Student"
   age = 20
   print("Welcome to Secret Scanner Demo")
   ```
2. Run in terminal: `python scanner.py .`
3. Show output: **`✅ SECURITY SCAN PASSED`** (Exit Code 0).
4. Explain: "When pushed to GitHub, GitHub Actions workflow passes."

### Demo 2 — Secret Detected (Build Fails)
1. Modify `example.py` by adding a fake password line:
   ```python
   name = "Student"
   password = "mypassword123"
   ```
2. Run in terminal: `python scanner.py .`
3. Show output: **`❌ SECURITY SCAN FAILED`** with masked match `password = "my********"` (Exit Code 1).
4. Explain: "The scanner blocks deployment in GitHub Actions before credentials reach production."

---

## ⚠️ 13. Project Limitations Disclaimer

> **Notice:** This tool detects pattern-based credentials using Regular Expressions. It cannot guarantee that every detected value is a live credential, nor can it guarantee detection of highly obfuscated secrets. It is designed for educational and demonstration purposes to illustrate DevSecOps concepts.

---

## 🔮 14. Future Enhancements

* Shannon Entropy calculation to detect high-entropy random key strings.
* Pre-commit hook git integration (`.git/hooks/pre-commit`).
* Support for regex custom pattern files (`.secretscanner.yml`).
* Integration with Slack/Discord webhook alerts on scan failure.


