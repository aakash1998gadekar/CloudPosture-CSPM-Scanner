let allFindings = [];

async function loadDashboard() {
    try {
        const response = await fetch('/api/dashboard/summary');
        const data = await response.json();
        updateKPIs(data);
        renderServiceChart(data.by_service);
        renderSeverityChart(data.by_severity);
        allFindings = data.recent_findings || [];
        renderFindings(allFindings);
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

function updateKPIs(data) {
    document.querySelector('#kpi-score .kpi-value').textContent = data.compliance_score + '%';
    document.querySelector('#kpi-total .kpi-value').textContent = data.total_checks;
    document.querySelector('#kpi-passed .kpi-value').textContent = data.passed;
    document.querySelector('#kpi-failed .kpi-value').textContent = data.failed;

    const criticalCount = data.critical_findings ? data.critical_findings.length : 0;
    document.querySelector('#kpi-critical .kpi-value').textContent = criticalCount;
}

function renderServiceChart(byService) {
    const services = Object.keys(byService);
    const passed = services.map(s => byService[s].passed || 0);
    const failed = services.map(s => byService[s].failed || 0);
    const warnings = services.map(s => byService[s].warnings || 0);

    const traces = [
        { x: services, y: passed, name: 'Passed', type: 'bar', marker: { color: '#3fb950' } },
        { x: services, y: failed, name: 'Failed', type: 'bar', marker: { color: '#f85149' } },
        { x: services, y: warnings, name: 'Warning', type: 'bar', marker: { color: '#d29922' } },
    ];

    const layout = {
        barmode: 'stack',
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        font: { color: '#8b949e' },
        margin: { t: 10, b: 40, l: 40, r: 10 },
        height: 250,
        legend: { orientation: 'h', y: -0.2 },
        xaxis: { gridcolor: '#30363d' },
        yaxis: { gridcolor: '#30363d' },
    };

    Plotly.newPlot('chart-services', traces, layout, { responsive: true, displayModeBar: false });
}

function renderSeverityChart(bySeverity) {
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const colors = ['#ff4757', '#f85149', '#d29922', '#58a6ff'];
    const values = severities.map(s => (bySeverity[s] && bySeverity[s].failed) || 0);
    const labels = severities.filter((_, i) => values[i] > 0);
    const filteredValues = values.filter(v => v > 0);
    const filteredColors = colors.filter((_, i) => values[i] > 0);

    const trace = {
        labels: labels,
        values: filteredValues,
        type: 'pie',
        hole: 0.5,
        marker: { colors: filteredColors },
        textinfo: 'label+value',
        textfont: { color: '#e6edf3' },
    };

    const layout = {
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        font: { color: '#8b949e' },
        margin: { t: 10, b: 10, l: 10, r: 10 },
        height: 250,
        showlegend: false,
    };

    Plotly.newPlot('chart-severity', [trace], layout, { responsive: true, displayModeBar: false });
}

function renderFindings(findings) {
    const tbody = document.getElementById('findings-body');
    tbody.innerHTML = '';

    findings.forEach((f, idx) => {
        const row = document.createElement('tr');
        row.onclick = () => showFindingDetail(f);
        row.innerHTML = `
            <td><span class="badge badge-${f.status.toLowerCase()}">${f.status}</span></td>
            <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
            <td>${f.service}</td>
            <td>${f.check_id}</td>
            <td>${f.title}</td>
            <td>${f.cis_benchmark}</td>
            <td title="${f.resource}">${truncate(f.resource, 40)}</td>
        `;
        tbody.appendChild(row);
    });
}

function filterFindings() {
    const service = document.getElementById('filter-service').value;
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;

    let filtered = allFindings;
    if (service) filtered = filtered.filter(f => f.service === service);
    if (severity) filtered = filtered.filter(f => f.severity === severity);
    if (status) filtered = filtered.filter(f => f.status === status);

    renderFindings(filtered);
}

function showFindingDetail(finding) {
    document.getElementById('modal-title').textContent = finding.title;
    document.getElementById('modal-body').innerHTML = `
        <p><strong>Description:</strong> ${finding.description}</p>
        <p><strong>Severity:</strong> <span class="badge badge-${finding.severity.toLowerCase()}">${finding.severity}</span></p>
        <p><strong>Status:</strong> <span class="badge badge-${finding.status.toLowerCase()}">${finding.status}</span></p>
        <p><strong>Service:</strong> ${finding.service}</p>
        <p><strong>CIS Benchmark:</strong> ${finding.cis_benchmark}</p>
        <p><strong>Resource:</strong> <code>${finding.resource}</code></p>
        <p><strong>Remediation:</strong> ${finding.remediation}</p>
        ${finding.remediation_cli ? `<div class="remediation-box">${finding.remediation_cli}</div>` : ''}
    `;
    document.getElementById('finding-modal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('finding-modal').style.display = 'none';
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(str.length - len) : str;
}

async function runScan() {
    const btn = document.getElementById('rescan-btn');
    btn.textContent = '⏳ Scanning...';
    btn.disabled = true;

    try {
        await fetch('/api/scan/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        await loadDashboard();
    } catch (error) {
        console.error('Scan failed:', error);
    } finally {
        btn.textContent = '🔄 Re-Scan';
        btn.disabled = false;
    }
}

// Load on page ready
document.addEventListener('DOMContentLoaded', loadDashboard);

// Close modal on outside click
document.getElementById('finding-modal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeModal();
});
