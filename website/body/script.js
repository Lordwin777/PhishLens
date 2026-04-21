let scanHistory = [];
let scanCount = 0;
let isDark = true;
let lastResult = null;
let currentMode = 'single';

document.getElementById('url-input').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') scanURL();
});

// ── Mode Switch ──
function switchMode(mode) {
    currentMode = mode;
    document.getElementById('mode-single').style.display = mode === 'single' ? 'block' : 'none';
    document.getElementById('mode-bulk').style.display   = mode === 'bulk'   ? 'block' : 'none';
    document.getElementById('tab-single').classList.toggle('active', mode === 'single');
    document.getElementById('tab-bulk').classList.toggle('active', mode === 'bulk');
}

// ── Theme Toggle ──
function toggleTheme() {
    isDark = !isDark;
    document.body.className = isDark ? 'dark' : 'light';
    document.getElementById('theme-btn').textContent = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
}

// ── Paste from Clipboard ──
async function pasteFromClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        document.getElementById('url-input').value = text;
        previewURL();
        document.getElementById('url-input').focus();
    } catch (err) {
        alert('Could not access clipboard. Please paste manually with Ctrl+V.');
    }
}

// ── URL Preview ──
function previewURL() {
    const input = document.getElementById('url-input').value.trim();
    const preview = document.getElementById('url-preview');

    if (!input) { preview.style.display = 'none'; return; }

    try {
        let urlToParse = input;
        if (!urlToParse.startsWith('http')) urlToParse = 'http://' + urlToParse;
        const parsed = new URL(urlToParse);

        document.getElementById('preview-protocol').textContent = parsed.protocol.replace(':', '') || '—';
        document.getElementById('preview-protocol').className = 'preview-value' + (parsed.protocol === 'https:' ? ' highlight' : '');
        document.getElementById('preview-domain').textContent = parsed.hostname || '—';
        document.getElementById('preview-domain').className = 'preview-value highlight';
        document.getElementById('preview-path').textContent = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : '—';
        document.getElementById('preview-path').className = 'preview-value';
        document.getElementById('preview-params').textContent = parsed.search ? parsed.search : '—';
        document.getElementById('preview-params').className = 'preview-value';

        preview.style.display = 'block';
    } catch (e) {
        preview.style.display = 'none';
    }
}

// ── Single Scan ──
function scanURL() {
    const url = document.getElementById('url-input').value.trim();
    if (!url) { alert('Please enter a URL.'); return; }

    const btn = document.getElementById('scan-btn');
    btn.textContent = '⏳ Scanning...';
    btn.disabled = true;
    document.getElementById('result-box').style.display = 'none';
    document.getElementById('scan-animation').style.display = 'block';

    fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById('scan-animation').style.display = 'none';
        if (data.error) {
            alert('Error: ' + data.error);
        } else {
            lastResult = data;
            showResult(data);
            addToHistory(data);
            updateScanCount();
        }
        btn.textContent = '🔍 Scan URL';
        btn.disabled = false;
    })
    .catch(err => {
        document.getElementById('scan-animation').style.display = 'none';
        alert('Connection error. Make sure server is running.');
        btn.textContent = '🔍 Scan URL';
        btn.disabled = false;
    });
}

// ── Bulk Scan ──
async function scanBulk() {
    const raw = document.getElementById('bulk-input').value.trim();
    if (!raw) { alert('Please paste at least one URL.'); return; }

    const urls = raw.split('\n').map(u => u.trim()).filter(u => u.length > 0);
    if (urls.length === 0) { alert('No valid URLs found.'); return; }

    const btn = document.getElementById('bulk-btn');
    btn.disabled = true;
    btn.textContent = '⏳ Scanning...';
    document.getElementById('bulk-results').style.display = 'none';
    document.getElementById('bulk-animation').style.display = 'block';

    const results = [];
    let safe = 0, phishing = 0, suspicious = 0;

    for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        const pct = Math.round(((i + 1) / urls.length) * 100);
        document.getElementById('bulk-progress-fill').style.width = pct + '%';
        document.getElementById('bulk-progress-fill').style.animation = 'none';
        document.getElementById('bulk-progress-text').textContent =
            `Scanning ${i + 1} of ${urls.length}: ${url.substring(0, 40)}...`;

        try {
            const res = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            const data = await res.json();
            results.push(data);
            updateScanCount();

            if (data.verdict === 'SAFE') safe++;
            else if (data.verdict.includes('PHISHING')) phishing++;
            else suspicious++;
        } catch (e) {
            results.push({ url, verdict: 'ERROR', verdict_icon: '❌', confidence: 0, reason: 'Could not connect', blacklist_hit: false });
        }
    }

    document.getElementById('bulk-animation').style.display = 'none';
    renderBulkResults(results, safe, phishing, suspicious);

    btn.disabled = false;
    btn.textContent = '🔍 Scan All URLs';
}

function renderBulkResults(results, safe, phishing, suspicious) {
    // Summary cards
    document.getElementById('bulk-summary').innerHTML = `
        <div class="summary-card total">
            <span class="summary-num">${results.length}</span>
            <span class="summary-label">Total Scanned</span>
        </div>
        <div class="summary-card safe">
            <span class="summary-num">${safe}</span>
            <span class="summary-label">✅ Safe</span>
        </div>
        <div class="summary-card phish">
            <span class="summary-num">${phishing}</span>
            <span class="summary-label">🚨 Phishing</span>
        </div>
        <div class="summary-card sus">
            <span class="summary-num">${suspicious}</span>
            <span class="summary-label">⚠️ Suspicious</span>
        </div>
    `;

    // Table rows
    const tbody = document.getElementById('bulk-table-body');
    tbody.innerHTML = '';

    results.forEach((r, i) => {
        const isPhishing = r.verdict && r.verdict.includes('PHISHING');
        const isSafe = r.verdict === 'SAFE';
        const rowClass = isPhishing ? 'row-phishing' : isSafe ? 'row-safe' : 'row-sus';
        const pillClass = isPhishing ? 'phishing' : isSafe ? 'safe' : 'suspicious';

        const tr = document.createElement('tr');
        tr.className = rowClass;
        tr.innerHTML = `
            <td>${i + 1}</td>
            <td style="max-width:280px; word-break:break-all;">${r.url}</td>
            <td><span class="verdict-pill ${pillClass}">${r.verdict_icon || ''} ${r.verdict}</span></td>
            <td>${r.confidence}%</td>
            <td>${r.reason}</td>
        `;
        tbody.appendChild(tr);
    });

    document.getElementById('bulk-results').style.display = 'block';
}

function resetBulk() {
    document.getElementById('bulk-input').value = '';
    document.getElementById('bulk-results').style.display = 'none';
}

// ── Scan Counter ──
function updateScanCount() {
    scanCount++;
    document.getElementById('scan-count').textContent = scanCount;
}

// ── Show Result ──
function showResult(data) {
    const box    = document.getElementById('result-box');
    const header = document.getElementById('verdict-header');

    document.getElementById('verdict-icon').textContent     = data.verdict_icon;
    document.getElementById('verdict-text').textContent     = data.verdict;
    document.getElementById('result-url').textContent       = data.url;
    document.getElementById('result-reason').textContent    = data.reason;
    document.getElementById('confidence-value').textContent = data.confidence;

    header.className = '';
    if (data.verdict === 'SAFE') header.classList.add('safe');
    else if (data.verdict.includes('PHISHING')) header.classList.add('phishing');
    else header.classList.add('suspicious');

    const bar = document.getElementById('confidence-bar');
    bar.style.width = data.confidence + '%';
    bar.className = '';
    if (data.confidence >= 50)      bar.classList.add('high');
    else if (data.confidence >= 20) bar.classList.add('medium');
    else                            bar.classList.add('low');

    updateGauge(data.confidence);

    document.getElementById('blacklist-warning').style.display =
        data.blacklist_hit ? 'block' : 'none';

    const featureList = document.getElementById('feature-list');
    featureList.innerHTML = '';
    for (const [feature, score] of Object.entries(data.details)) {
        const item  = document.createElement('div');
        item.className = 'feature-item';

        const name  = document.createElement('span');
        name.className   = 'feature-name';
        name.textContent = feature.replace(/_/g, ' ');

        const badge = document.createElement('span');
        badge.className  = 'badge';
        if (score === 1) { badge.classList.add('safe'); badge.textContent = '✅ Legitimate'; }
        else if (score === 0) { badge.classList.add('suspicious'); badge.textContent = '⚠️ Suspicious'; }
        else { badge.classList.add('phishing'); badge.textContent = '🚨 Phishing'; }

        item.appendChild(name);
        item.appendChild(badge);
        featureList.appendChild(item);
    }

    box.style.display = 'block';
}

// ── Risk Gauge ──
function updateGauge(confidence) {
    const gaugeFill = document.getElementById('gauge-fill');
    const gaugeText = document.getElementById('gauge-text');
    const totalLength = 157;
    const offset = totalLength - (confidence / 100) * totalLength;
    let color = '#22c55e';
    if (confidence >= 50)      color = '#ef4444';
    else if (confidence >= 20) color = '#f97316';
    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.stroke = color;
    gaugeFill.style.transition = 'stroke-dashoffset 0.8s ease, stroke 0.4s ease';
    gaugeText.textContent = confidence + '%';
    gaugeText.style.fill = color;
}

// ── Scan History ──
function addToHistory(data) {
    scanHistory = scanHistory.filter(h => h.url !== data.url);
    scanHistory.unshift({ url: data.url, verdict: data.verdict, confidence: data.confidence });
    if (scanHistory.length > 5) scanHistory.pop();
    renderHistory();
}

function renderHistory() {
    const section = document.getElementById('history-section');
    const list    = document.getElementById('history-list');
    if (scanHistory.length === 0) { section.style.display = 'none'; return; }
    section.style.display = 'block';
    list.innerHTML = '';
    scanHistory.forEach(item => {
        const div = document.createElement('div');
        div.className = 'history-item';
        div.onclick = () => {
            document.getElementById('url-input').value = item.url;
            previewURL();
            scanURL();
        };
        const urlSpan = document.createElement('span');
        urlSpan.className = 'history-url';
        urlSpan.textContent = item.url;
        const badge = document.createElement('span');
        badge.className = 'history-badge';
        if (item.verdict === 'SAFE') { badge.classList.add('safe'); badge.textContent = '✅ Safe'; }
        else if (item.verdict.includes('PHISHING')) { badge.classList.add('phishing'); badge.textContent = '🚨 ' + item.verdict; }
        else { badge.classList.add('suspicious'); badge.textContent = '⚠️ ' + item.verdict; }
        div.appendChild(urlSpan);
        div.appendChild(badge);
        list.appendChild(div);
    });
}

// ── Export PDF ──
function exportPDF() {
    if (!lastResult) { alert('No scan result to export.'); return; }
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const r = lastResult;
    const now = new Date().toLocaleString();

    doc.setFontSize(20);
    doc.setTextColor(15, 23, 42);
    doc.text('PhishLens — Scan Report', 20, 20);
    doc.setDrawColor(200, 200, 200);
    doc.line(20, 25, 190, 25);

    doc.setFontSize(14);
    doc.setTextColor(r.verdict === 'SAFE' ? 5 : 150, r.verdict === 'SAFE' ? 100 : 0, r.verdict === 'SAFE' ? 50 : 0);
    doc.text('Verdict: ' + r.verdict_icon + ' ' + r.verdict, 20, 35);

    doc.setFontSize(11);
    doc.setTextColor(50, 50, 50);
    doc.text('URL: ' + r.url, 20, 48, { maxWidth: 170 });
    doc.text('Confidence: ' + r.confidence + '%', 20, 62);
    doc.text('Reason: ' + r.reason, 20, 72);
    doc.text('Found in blacklist: ' + (r.blacklist_hit ? 'Yes' : 'No'), 20, 82);
    doc.text('Scanned at: ' + now, 20, 92);

    doc.setFontSize(13);
    doc.setTextColor(15, 23, 42);
    doc.text('Feature Breakdown:', 20, 108);

    doc.setFontSize(10);
    let y = 118;
    for (const [feature, score] of Object.entries(r.details)) {
        const status = score === 1 ? 'Legitimate' : score === 0 ? 'Suspicious' : 'Phishing';
        doc.setTextColor(score === 1 ? 5 : score === 0 ? 150 : 180, score === 1 ? 100 : score === 0 ? 80 : 0, score === 1 ? 50 : 0);
        doc.text(feature.replace(/_/g, ' ') + ': ' + status, 20, y);
        y += 8;
        if (y > 270) { doc.addPage(); y = 20; }
    }

    doc.setFontSize(9);
    doc.setTextColor(150, 150, 150);
    doc.text('Generated by PhishLens — Phishing URL Detector', 20, 285);
    doc.save('PhishLens_Report_' + Date.now() + '.pdf');
}

// ── Reset ──
function resetScan() {
    document.getElementById('url-input').value = '';
    document.getElementById('result-box').style.display = 'none';
    document.getElementById('url-preview').style.display = 'none';
    document.getElementById('url-input').focus();
}