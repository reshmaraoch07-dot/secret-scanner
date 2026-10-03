"""
Secret Scanner - Core Scanning Engine & CLI Tool
Can be imported as a library or executed directly from the command line.
Returns exit code 0 when clean, exit code 1 when secrets are detected.
"""

import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple

from patterns import (
    SECRET_PATTERNS,
    SUPPORTED_EXTENSIONS,
    DEFAULT_EXCLUDE_DIRS,
    is_comment_or_label,
    mask_secret,
    mask_line_context,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW
)


def is_file_supported(file_path: Path) -> bool:
    """Checks if the file extension is supported for security scanning."""
    return file_path.suffix.lower() in SUPPORTED_EXTENSIONS or file_path.name.lower() in [".env", ".config", ".properties"]


def scan_line(line: str, line_number: int, file_path_str: str) -> List[Dict[str, Any]]:
    """
    Scans a single line of text against all registered secret regex patterns.
    Returns a list of finding objects.
    """
    findings = []
    
    # Skip comment-only or UI prompt lines unless explicit assignment is present
    if is_comment_or_label(line):
        return findings

    for pattern_info in SECRET_PATTERNS:
        matches = pattern_info["pattern"].finditer(line)
        for match in matches:
            # Extracted secret string or full match group
            secret_val = match.group(1) if match.groups() else match.group(0)
            masked_val = mask_secret(secret_val)
            masked_line = mask_line_context(line, secret_val)

            finding = {
                "file": file_path_str,
                "line": line_number,
                "type": pattern_info["name"],
                "severity": pattern_info["severity"],
                "description": pattern_info["description"],
                "masked_value": masked_val,
                "masked_context": masked_line,
                "status": "DETECTED"
            }
            findings.append(finding)
            # Avoid duplicate triggers on the exact same match span
            break

    return findings


def scan_content(content: str, filename: str = "uploaded_code.txt") -> Dict[str, Any]:
    """
    Scans raw string content (e.g., uploaded file or code paste).
    Returns scan metrics and findings.
    """
    start_time = time.time()
    lines = content.splitlines()
    total_lines = len(lines)
    all_findings = []

    for line_idx, line in enumerate(lines, start=1):
        line_findings = scan_line(line, line_idx, filename)
        all_findings.extend(line_findings)

    duration_ms = round((time.time() - start_time) * 1000, 2)
    
    # Calculate severity stats
    high_count = sum(1 for f in all_findings if f["severity"] == SEVERITY_HIGH)
    medium_count = sum(1 for f in all_findings if f["severity"] == SEVERITY_MEDIUM)
    low_count = sum(1 for f in all_findings if f["severity"] == SEVERITY_LOW)

    return {
        "files_scanned": 1,
        "lines_scanned": total_lines,
        "total_secrets": len(all_findings),
        "high_severity": high_count,
        "medium_severity": medium_count,
        "low_severity": low_count,
        "passed": len(all_findings) == 0,
        "duration_ms": duration_ms,
        "findings": all_findings
    }


def scan_file(file_path: Path) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Reads a single file safely line-by-line and scans for secrets.
    Returns (line_count, findings_list).
    """
    line_count = 0
    findings = []

    try:
        # Open with utf-8, fallback with ignore on decoding errors
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f, start=1):
                line_count += 1
                line_findings = scan_line(line, line_idx, str(file_path))
                findings.extend(line_findings)
    except Exception as e:
        # Return empty on unreadable binary or permission error
        pass

    return line_count, findings


def scan_directory(target_path: str) -> Dict[str, Any]:
    """
    Recursively scans a target directory or file, skipping excluded paths.
    """
    start_time = time.time()
    root_path = Path(target_path).resolve()

    total_files = 0
    total_lines = 0
    all_findings = []

    if not root_path.exists():
        return {
            "error": f"Target path '{target_path}' does not exist.",
            "passed": False,
            "files_scanned": 0,
            "lines_scanned": 0,
            "total_secrets": 0,
            "findings": []
        }

    if root_path.is_file():
        if is_file_supported(root_path):
            l_count, findings = scan_file(root_path)
            total_files = 1
            total_lines = l_count
            all_findings.extend(findings)
    else:
        for current_root, dirs, files in os.walk(root_path):
            # Exclude specified directories in-place to prevent traversing them
            dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS and not d.startswith(".")]

            for file_name in files:
                file_path = Path(current_root) / file_name
                if is_file_supported(file_path):
                    # Relative path display for cleaner output
                    try:
                        rel_path_str = str(file_path.relative_to(root_path))
                    except ValueError:
                        rel_path_str = str(file_path)

                    l_count, findings = scan_file(file_path)
                    total_files += 1
                    total_lines += l_count
                    
                    # Update file path string in findings to relative path
                    for f in findings:
                        f["file"] = rel_path_str
                    all_findings.extend(findings)

    duration_ms = round((time.time() - start_time) * 1000, 2)

    high_count = sum(1 for f in all_findings if f["severity"] == SEVERITY_HIGH)
    medium_count = sum(1 for f in all_findings if f["severity"] == SEVERITY_MEDIUM)
    low_count = sum(1 for f in all_findings if f["severity"] == SEVERITY_LOW)

    return {
        "target_path": str(root_path),
        "files_scanned": total_files,
        "lines_scanned": total_lines,
        "total_secrets": len(all_findings),
        "high_severity": high_count,
        "medium_severity": medium_count,
        "low_severity": low_count,
        "passed": len(all_findings) == 0,
        "duration_ms": duration_ms,
        "findings": all_findings
    }


def print_cli_report(result: Dict[str, Any]) -> None:
    """Prints a clean CLI report to terminal."""
    print("\n" + "=" * 50)
    print("                SECRET SCANNER                ")
    print("=" * 50)
    print(f"Target Path    : {result.get('target_path', '.')}")
    print(f"Files Scanned  : {result['files_scanned']}")
    print(f"Lines Scanned  : {result['lines_scanned']}")
    print(f"Secrets Found  : {result['total_secrets']}")
    print(f"Scan Duration  : {result.get('duration_ms', 0)} ms")
    print("-" * 50)

    if result["total_secrets"] > 0:
        print("\nDETAILED FINDINGS:")
        print("-" * 50)
        for idx, finding in enumerate(result["findings"], start=1):
            print(f"{idx}. File     : {finding['file']}")
            print(f"   Line     : {finding['line']}")
            print(f"   Type     : {finding['type']}")
            print(f"   Severity : {finding['severity']}")
            print(f"   Match    : {finding['masked_context']}")
            print("")

        print("=" * 50)
        print("❌ SECURITY SCAN FAILED")
        print("Potential secrets detected in codebase!")
        print("=" * 50 + "\n")
    else:
        print("=" * 50)
        print("✅ SECURITY SCAN PASSED")
        print("No potential secrets were detected.")
        print("=" * 50 + "\n")


def main():
    """Command Line Interface Entry Point."""
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"\nScanning project path: '{target}'...")

    result = scan_directory(target)

    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)

    print_cli_report(result)

    # Return exit code 0 if scan passed (no secrets), 1 if secrets found
    if result["passed"]:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
