/* ==========================================================================
   Secret Scanner - Frontend Logic & API Client
   ========================================================================== */

let selectedFiles = [];
let currentFindings = [];
let currentScanData = null;

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initDropzone();
});

/* TAB NAVIGATION */
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTabId = btn.getAttribute('data-tab');

            tabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));

            btn.classList.add('active');
            const targetPane = document.getElementById(targetTabId);
            if (targetPane) targetPane.classList.remove('hidden');

            if (targetTabId === 'tab-history') {
                refreshHistoryTable();
            }
        });
    });
}

/* SCAN MODE SWITCHING */
function switchScanMode(mode) {
    const modeBtns = document.querySelectorAll('.mode-btn');
    const modeContents = document.querySelectorAll('.mode-content');

    modeBtns.forEach(b => b.classList.remove('active'));
    modeContents.forEach(c => c.classList.add('hidden'));

    if (mode === 'upload') {
        modeBtns[0].classList.add('active');
        document.getElementById('mode-upload').classList.remove('hidden');
    } else if (mode === 'path') {
        modeBtns[1].classList.add('active');
        document.getElementById('mode-path').classList.remove('hidden');
    } else if (mode === 'text') {
        modeBtns[2].classList.add('active');
        document.getElementById('mode-text').classList.remove('hidden');
    }
}

/* DROPZONE & FILE UPLOAD */
function initDropzone() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');

    if (!dropzone || !fileInput) return;

    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        });
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleSelectedFiles(files);
    });

    fileInput.addEventListener('change', (e) => {
        handleSelectedFiles(e.target.files);
    });
}

function handleSelectedFiles(fileList) {
    if (!fileList || fileList.length === 0) return;

    selectedFiles = Array.from(fileList);
    const countSpan = document.getElementById('file-count');
    const previewList = document.getElementById('file-items');
    const previewBox = document.getElementById('file-list-preview');

    countSpan.textContent = selectedFiles.length;
    previewList.innerHTML = '';

    selectedFiles.forEach(f => {
        const li = document.createElement('li');
        li.textContent = `📄 ${f.name} (${(f.size / 1024).toFixed(1)} KB)`;
        previewList.appendChild(li);
    });

    previewBox.classList.remove('hidden');
}

function clearFileSelection() {
    selectedFiles = [];
    document.getElementById('file-input').value = '';
    document.getElementById('file-list-preview').classList.add('hidden');
}

/* API SCAN EXECUTIONS */

// 1. Scan Uploaded Files
async function startFileScan() {
    if (selectedFiles.length === 0) {
        alert('Please select files first.');
        return;
    }

    const formData = new FormData();
    selectedFiles.forEach(f => formData.append('files', f));

    showLoading(true);

    try {
        const response = await fetch('/api/scan-files', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        showLoading(false);

        if (!response.ok) {
            alert(data.error || 'Failed to scan files.');
            return;
        }

        renderResults(data);
    } catch (err) {
        showLoading(false);
        alert('Error communicating with scanner backend: ' + err.message);
    }
}

// 2. Scan Path
async function startPathScan() {
    const pathInput = document.getElementById('target-path-input');
    const pathVal = pathInput.value.trim();

    if (!pathVal) {
        alert('Please enter a valid directory path.');
        return;
    }

    showLoading(true);

    try {
        const response = await fetch('/api/scan-path', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: pathVal })
        });
        const data = await response.json();
        showLoading(false);

        if (!response.ok) {
            alert(data.error || 'Failed to scan path.');
            return;
        }

        renderResults(data);
    } catch (err) {
        showLoading(false);
        alert('Error communicating with scanner backend: ' + err.message);
    }
}

// 3. Scan Text Snippet
async function startTextScan() {
    const snippetArea = document.getElementById('snippet-text');
    const textVal = snippetArea.value.trim();

    if (!textVal) {
        alert('Please paste code content to scan.');
        return;
    }

    showLoading(true);

    try {
        const response = await fetch('/api/scan-text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: textVal, filename: 'pasted_code.py' })
        });
        const data = await response.json();
        showLoading(false);

        if (!response.ok) {
            alert(data.error || 'Failed to scan snippet.');
            return;
        }

        renderResults(data);
    } catch (err) {
        showLoading(false);
        alert('Error communicating with scanner backend: ' + err.message);
    }
}

/* UI LOADING & RENDERING */
function showLoading(isLoading) {
    const loadingBox = document.getElementById('scan-loading');
    const resultsWrapper = document.getElementById('scan-results-wrapper');

    if (isLoading) {
        loadingBox.classList.remove('hidden');
        resultsWrapper.classList.add('hidden');
    } else {
        loadingBox.classList.add('hidden');
    }
}

function renderResults(data) {
    currentScanData = data;
    currentFindings = data.findings || [];

    const wrapper = document.getElementById('scan-results-wrapper');
    const banner = document.getElementById('status-banner');
    const bannerIcon = document.getElementById('banner-icon');
    const bannerTitle = document.getElementById('banner-title');
    const bannerDesc = document.getElementById('banner-desc');

    // Populate Metrics
    document.getElementById('res-files').textContent = data.files_scanned;
    document.getElementById('res-lines').textContent = data.lines_scanned;
    document.getElementById('res-secrets').textContent = data.total_secrets;
    document.getElementById('res-high').textContent = data.high_severity || 0;
    document.getElementById('res-med').textContent = data.medium_severity || 0;
    document.getElementById('res-low').textContent = data.low_severity || 0;
    document.getElementById('res-duration').textContent = `${data.duration_ms} ms`;

    // Configure Status Banner
    if (data.passed) {
        banner.className = 'status-banner pass';
        bannerIcon.textContent = '✅';
        bannerTitle.textContent = 'SECURITY SCAN PASSED';
        bannerDesc.textContent = 'No potential secrets detected in the scanned files. Code is safe for CI/CD deployment.';
    } else {
        banner.className = 'status-banner fail';
        bannerIcon.textContent = '❌';
        bannerTitle.textContent = 'SECURITY ISSUES FOUND';
        bannerDesc.textContent = `Warning: ${data.total_secrets} potential secret(s) detected. Fix credentials before committing to repository.`;
    }

    renderFindingsTable(currentFindings);
    wrapper.classList.remove('hidden');
    wrapper.scrollIntoView({ behavior: 'smooth' });
}

function renderFindingsTable(findings) {
    const tbody = document.getElementById('findings-tbody');
    const noMsg = document.getElementById('no-findings-msg');
    const tableContainer = document.querySelector('.table-responsive');

    tbody.innerHTML = '';

    if (!findings || findings.length === 0) {
        tableContainer.classList.add('hidden');
        noMsg.classList.remove('hidden');
        return;
    }

    tableContainer.classList.remove('hidden');
    noMsg.classList.add('hidden');

    findings.forEach((item, idx) => {
        const tr = document.createElement('tr');

        let badgeClass = 'badge-sev-low';
        if (item.severity === 'HIGH') badgeClass = 'badge-sev-high';
        else if (item.severity === 'MEDIUM') badgeClass = 'badge-sev-medium';

        tr.innerHTML = `
            <td>${idx + 1}</td>
            <td><code>${escapeHtml(item.file)}</code></td>
            <td><strong>${item.line}</strong></td>
            <td>${escapeHtml(item.type)}</td>
            <td><span class="badge ${badgeClass}">${item.severity}</span></td>
            <td><code class="masked-code">${escapeHtml(item.masked_value)}</code></td>
            <td><code>${escapeHtml(item.masked_context)}</code></td>
        `;

        tbody.appendChild(tr);
    });
}

function filterFindings(severity) {
    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(b => b.classList.remove('active'));

    event.target.classList.add('active');

    if (severity === 'ALL') {
        renderFindingsTable(currentFindings);
    } else {
        const filtered = currentFindings.filter(f => f.severity === severity);
        renderFindingsTable(filtered);
    }
}

function searchFindings() {
    const q = document.getElementById('findings-search').value.toLowerCase();
    const filtered = currentFindings.filter(f => 
        f.file.toLowerCase().includes(q) ||
        f.type.toLowerCase().includes(q) ||
        f.masked_context.toLowerCase().includes(q)
    );
    renderFindingsTable(filtered);
}

function resetScanView() {
    clearFileSelection();
    document.getElementById('snippet-text').value = '';
    document.getElementById('scan-results-wrapper').classList.add('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function exportScanJSON() {
    if (!currentScanData) return;
    const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secret_scan_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

/* HISTORY MANAGEMENT */
async function refreshHistoryTable() {
    try {
        const res = await fetch('/api/history');
        const history = await res.json();
        const tbody = document.getElementById('history-tbody');
        const countSpan = document.getElementById('history-count');

        countSpan.textContent = history.length;
        tbody.innerHTML = '';

        if (!history || history.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-msg">No scan history recorded yet. Perform a scan above!</td></tr>`;
            return;
        }

        history.forEach(item => {
            const tr = document.createElement('tr');
            const badgeClass = item.passed ? 'badge-pass' : 'badge-fail';
            const statusText = item.passed ? '✅ Passed' : '❌ Failed';

            tr.innerHTML = `
                <td>#${item.id}</td>
                <td>${escapeHtml(item.timestamp)}</td>
                <td><code>${escapeHtml(item.target)}</code></td>
                <td>${item.files_scanned}</td>
                <td>${item.lines_scanned}</td>
                <td><strong>${item.total_secrets}</strong></td>
                <td><span class="badge ${badgeClass}">${statusText}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Failed to fetch scan history', err);
    }
}

async function clearHistory() {
    if (!confirm('Are you sure you want to clear scan history?')) return;
    try {
        await fetch('/api/history/clear', { method: 'POST' });
        refreshHistoryTable();
    } catch (err) {
        alert('Failed to clear history: ' + err.message);
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
