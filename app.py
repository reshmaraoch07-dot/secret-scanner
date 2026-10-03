"""
Secret Scanner - Flask Web Application
Provides interactive web dashboard, API endpoints for file upload, folder path scanning,
code paste scanning, and scan history tracking.
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify

from scanner import scan_content, scan_directory, is_file_supported
from patterns import DEFAULT_EXCLUDE_DIRS

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload limit

HISTORY_FILE = Path(__file__).parent / "scan_history.json"


def load_history():
    """Loads scan history from JSON file or returns empty list."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_history(record):
    """Appends a new scan record to history file."""
    history = load_history()
    record["id"] = len(history) + 1
    record["timestamp"] = datetime.now().strftime("%d %b %Y, %I:%M %p")
    # Insert newest first
    history.insert(0, record)
    # Keep last 50 scans
    history = history[:50]
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save scan history: {e}")
    return history


@app.route("/")
def index():
    """Renders the main Secret Scanner dashboard."""
    history = load_history()
    return render_template("index.html", history=history)


@app.route("/api/scan-text", methods=["POST"])
def api_scan_text():
    """API endpoint to scan raw code text pasted in UI."""
    data = request.get_json() or {}
    text_content = data.get("text", "")
    filename = data.get("filename", "snippet.txt")

    if not text_content.strip():
        return jsonify({"error": "Code text cannot be empty."}), 400

    result = scan_content(text_content, filename)
    result["target"] = filename
    save_history({
        "target": f"Snippet ({filename})",
        "files_scanned": result["files_scanned"],
        "lines_scanned": result["lines_scanned"],
        "total_secrets": result["total_secrets"],
        "passed": result["passed"],
        "duration_ms": result["duration_ms"]
    })

    return jsonify(result)


@app.route("/api/scan-files", methods=["POST"])
def api_scan_files():
    """API endpoint to scan uploaded files."""
    if 'files' not in request.files:
        return jsonify({"error": "No files uploaded."}), 400

    uploaded_files = request.files.getlist("files")
    if not uploaded_files or all(f.filename == "" for f in uploaded_files):
        return jsonify({"error": "Please select valid files to scan."}), 400

    start_time = time.time()
    total_files = 0
    total_lines = 0
    all_findings = []

    for file_obj in uploaded_files:
        if file_obj.filename == "":
            continue
        
        filename = file_obj.filename
        try:
            content = file_obj.read().decode("utf-8", errors="ignore")
            res = scan_content(content, filename)
            total_files += 1
            total_lines += res["lines_scanned"]
            all_findings.extend(res["findings"])
        except Exception as e:
            continue

    duration_ms = round((time.time() - start_time) * 1000, 2)
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in all_findings if f["severity"] == "LOW")

    result = {
        "files_scanned": total_files,
        "lines_scanned": total_lines,
        "total_secrets": len(all_findings),
        "high_severity": high_count,
        "medium_severity": medium_count,
        "low_severity": low_count,
        "passed": len(all_findings) == 0,
        "duration_ms": duration_ms,
        "findings": all_findings,
        "target": f"{total_files} Uploaded File(s)"
    }

    save_history({
        "target": result["target"],
        "files_scanned": result["files_scanned"],
        "lines_scanned": result["lines_scanned"],
        "total_secrets": result["total_secrets"],
        "passed": result["passed"],
        "duration_ms": result["duration_ms"]
    })

    return jsonify(result)


@app.route("/api/scan-path", methods=["POST"])
def api_scan_path():
    """API endpoint to scan local directory path."""
    data = request.get_json() or {}
    path_str = data.get("path", ".").strip()

    if not os.path.exists(path_str):
        return jsonify({"error": f"Path '{path_str}' does not exist on local system."}), 404

    result = scan_directory(path_str)
    if "error" in result:
        return jsonify({"error": result["error"]}), 400

    result["target"] = path_str
    save_history({
        "target": f"Path: {path_str}",
        "files_scanned": result["files_scanned"],
        "lines_scanned": result["lines_scanned"],
        "total_secrets": result["total_secrets"],
        "passed": result["passed"],
        "duration_ms": result["duration_ms"]
    })

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def api_history():
    """Returns past scan history."""
    return jsonify(load_history())


@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Clears scan history."""
    if HISTORY_FILE.exists():
        try:
            os.remove(HISTORY_FILE)
        except Exception as e:
            pass
    return jsonify({"status": "success", "history": []})


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error occurred"}), 500


if __name__ == "__main__":
    print("\n🔐 Starting Secret Scanner Web Application...")
    print("📍 Local Web UI: http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
