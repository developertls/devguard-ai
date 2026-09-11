// js/ui.js — Renders, loaders, toasts, diff viewer y utilidades de UI

/* ── TOAST ── */
export function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const icons = { success: '<i class="fa-solid fa-check"></i>', error: '<i class="fa-solid fa-xmark"></i>', info: '<i class="fa-solid fa-circle-info"></i>' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

/* ── SKELETON LOADER ── */
export function showSkeleton(container) {
  container.innerHTML = `
    <div class="skeleton skeleton-line" style="width:60%"></div>
    <div class="skeleton skeleton-line" style="width:40%"></div>
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-line" style="width:50%"></div>
  `;
}

/* ── LOADING BUTTON ── */
export function setButtonLoading(btn, loading) {
  if (loading) {
    btn.dataset.originalText = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Analizando...`;
    btn.classList.add('loading');
    btn.disabled = true;
  } else {
    btn.innerHTML = btn.dataset.originalText || btn.innerHTML;
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

/* ── SEVERITY BADGE ── */
export function badge(severity) {
  const s = (severity || 'NONE').toUpperCase();
  const map = {
    CRITICAL: 'badge-critical', HIGH: 'badge-high',
    MEDIUM: 'badge-medium', LOW: 'badge-low',
    NONE: 'badge-none', SAFE: 'badge-safe',
    VULNERABLE: 'badge-critical', OUTDATED: 'badge-medium'
  };
  return `<span class="badge ${map[s] || 'badge-none'}">${s}</span>`;
}

/* ── RISK BANNER ── */
export function riskBanner(risk, count, label) {
  const r = (risk || 'SAFE').toLowerCase();
  const icons = { critical: '<i class="fa-solid fa-skull-crossbones"></i>', high: '<i class="fa-solid fa-triangle-exclamation"></i>', medium: '<i class="fa-solid fa-bolt"></i>', low: '<i class="fa-solid fa-circle-info"></i>', safe: '<i class="fa-solid fa-shield-halved"></i>' };
  return `
    <div class="risk-banner ${r}">
      <span>${icons[r] || '<i class="fa-solid fa-magnifying-glass"></i>'}</span>
      <span>${count} ${label} · Riesgo ${risk}</span>
    </div>`;
}

/* ── CODE DIFF BLOCK ── */
export function diffBlock(vulnerable, fixed) {
  if (!vulnerable && !fixed) return '';
  const vuln = (vulnerable || '').split('\n');
  const fixd = (fixed || '').split('\n');
  const html = [
    ...vuln.filter(Boolean).map(l => `<div class="diff-line removed">- ${escapeHtml(l)}</div>`),
    ...fixd.filter(Boolean).map(l => `<div class="diff-line added">+ ${escapeHtml(l)}</div>`)
  ].join('');
  return `<div class="diff-block">${html}</div>`;
}

/* ── ESCAPE HTML ── */
export function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ── COPY TO CLIPBOARD ── */
export function copyText(text) {
  navigator.clipboard.writeText(text)
    .then(() => showToast('Copiado al portapapeles', 'success'))
    .catch(() => showToast('No se pudo copiar', 'error'));
}

/* ── EXPORT AS JSON ── */
export function exportJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

/* ── EXPORT AS TXT ── */
export function exportTXT(text, filename) {
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

/* ── RENDER SECRET SCANNER RESULTS ── */
export function renderSecrets(data, container) {
  const findings = data.findings || [];

  if (findings.length === 0) {
    container.innerHTML = `
      ${riskBanner('SAFE', 0, 'secretos encontrados')}
      <div class="results-placeholder">
        <div class="placeholder-icon">✅</div>
        <p>No se detectaron secretos expuestos</p>
      </div>`;
    return;
  }

  const html = `
    ${riskBanner(findings[0]?.severity || 'HIGH', findings.length, 'secretos encontrados')}
    <div class="results-summary">
      <span class="results-title">🔍 Secret Scanner</span>
      <button class="export-btn" onclick="window.__exportSecrets && window.__exportSecrets()">⬇ Exportar</button>
    </div>
    ${findings.map(f => `
      <div class="finding-card">
        <div class="finding-header">
          <span class="finding-title">${escapeHtml(f.type || 'Secret')}</span>
          ${badge(f.severity)}
          ${f.line ? `<span class="finding-line">Línea ${f.line}</span>` : ''}
        </div>
        ${f.value_masked ? `<div class="finding-masked">${escapeHtml(f.value_masked)}</div>` : ''}
        <p class="finding-desc">${escapeHtml(f.description || '')}</p>
        ${f.fix ? `<div class="finding-fix">💡 ${escapeHtml(f.fix)}</div>` : ''}
      </div>
    `).join('')}
    <div style="margin-top:16px;padding:12px 16px;background:var(--bg-tertiary);border-radius:var(--radius-md);font-size:.82rem;color:var(--text-secondary)">
      ${escapeHtml(data.summary || '')}
    </div>`;

  container.innerHTML = html;
}

/* ── RENDER VULNERABILITY RESULTS ── */
export function renderVulns(data, container) {
  const vulns = data.vulnerabilities || [];

  if (vulns.length === 0) {
    container.innerHTML = `
      ${riskBanner('SAFE', 0, 'vulnerabilidades')}
      <div class="results-placeholder">
        <div class="placeholder-icon">✅</div>
        <p>No se detectaron vulnerabilidades OWASP</p>
      </div>`;
    return;
  }

  container.innerHTML = `
    ${riskBanner(data.overall_risk, vulns.length, 'vulnerabilidades')}
    <div class="results-summary">
      <span class="results-title">⚡ Vulnerability Analyzer</span>
      <button class="export-btn" onclick="window.__exportVulns && window.__exportVulns()">⬇ Exportar</button>
    </div>
    ${vulns.map(v => `
      <div class="finding-card">
        <div class="finding-header">
          <span class="finding-title">${escapeHtml(v.type || 'Vulnerability')}</span>
          ${badge(v.severity)}
          ${v.line ? `<span class="finding-line">Línea ${v.line}</span>` : ''}
        </div>
        <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap">
          ${v.owasp ? `<span class="badge badge-none">${escapeHtml(v.owasp)}</span>` : ''}
          ${v.mitre ? `<span class="badge badge-none">${escapeHtml(v.mitre)}</span>` : ''}
          ${v.cvss  ? `<span class="badge badge-none">CVSS ${v.cvss}</span>` : ''}
        </div>
        <p class="finding-desc">${escapeHtml(v.description || '')}</p>
        ${diffBlock(v.code_vulnerable, v.code_fixed)}
      </div>
    `).join('')}`;
}

/* ── RENDER DEPENDENCY RESULTS ── */
export function renderDeps(data, container) {
  const deps = data.dependencies || [];
  const vuln = deps.filter(d => d.status === 'VULNERABLE');
  const outdated = deps.filter(d => d.status === 'OUTDATED');

  container.innerHTML = `
    ${riskBanner(vuln.length > 0 ? 'HIGH' : outdated.length > 0 ? 'MEDIUM' : 'SAFE',
      data.vulnerable_count || 0, `de ${data.total_count || deps.length} dependencias vulnerables`)}
    <div class="results-summary">
      <span class="results-title">📦 Dependency Checker</span>
      <button class="export-btn" onclick="window.__exportDeps && window.__exportDeps()">⬇ Exportar</button>
    </div>
    <table class="dep-table">
      <thead>
        <tr>
          <th>Paquete</th>
          <th>Versión</th>
          <th>Estado</th>
          <th>Remediación</th>
        </tr>
      </thead>
      <tbody>
        ${deps.map(d => `
          <tr>
            <td><span class="dep-name">${escapeHtml(d.name || '')}</span></td>
            <td><span class="dep-name" style="color:var(--text-muted)">${escapeHtml(d.current_version || '')}</span></td>
            <td>${badge(d.status === 'SAFE' ? 'SAFE' : d.severity)}</td>
            <td>
              ${d.cve ? `<span style="font-size:.75rem;color:var(--accent-red)">${escapeHtml(d.cve)}</span><br>` : ''}
              ${d.recommended_version ? `<span class="dep-fix">→ ${escapeHtml(d.recommended_version)}</span>` : ''}
              ${d.fix_command ? `<br><span class="dep-fix">${escapeHtml(d.fix_command)}</span>` : ''}
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    <div style="margin-top:16px;padding:12px 16px;background:var(--bg-tertiary);border-radius:var(--radius-md);font-size:.82rem;color:var(--text-secondary)">
      ${escapeHtml(data.summary || '')}
    </div>`;
}

/* ── RENDER THREAT MODEL ── */
export function renderThreat(data, container) {
  const threats = data.threats || [];
  const strideColors = {
    'Spoofing': 'var(--accent-blue)',
    'Tampering': 'var(--accent-orange)',
    'Repudiation': 'var(--accent-yellow)',
    'Information Disclosure': 'var(--accent-red)',
    'Denial of Service': 'var(--accent-purple)',
    'Elevation of Privilege': 'var(--accent-cyan)'
  };

  container.innerHTML = `
    <div class="results-summary">
      <span class="results-title">🗺️ Threat Model STRIDE</span>
      <button class="export-btn" onclick="window.__exportThreat && window.__exportThreat()">⬇ Exportar</button>
    </div>
    ${(data.priority_actions || []).length > 0 ? `
      <div style="margin-bottom:20px">
        <div style="font-size:.8rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Acciones prioritarias</div>
        <ol class="priority-list">
          ${data.priority_actions.map((a, i) => `
            <li><span class="priority-num">${i+1}</span>${escapeHtml(a)}</li>
          `).join('')}
        </ol>
      </div>` : ''}
    <div class="stride-grid">
      ${threats.map(t => `
        <div class="threat-card">
          <div class="threat-category" style="color:${strideColors[t.category] || 'var(--accent-purple)'}">
            ${escapeHtml(t.category || '')}
          </div>
          <div class="threat-name">${escapeHtml(t.threat || '')}</div>
          <div class="threat-meta">
            ${badge(t.risk)}
            <span class="badge badge-none">Likelihood: ${escapeHtml(t.likelihood || '')}</span>
            <span class="badge badge-none">Impact: ${escapeHtml(t.impact || '')}</span>
          </div>
          ${t.affected_component ? `<div style="font-size:.78rem;color:var(--text-muted);margin-bottom:8px">Componente: ${escapeHtml(t.affected_component)}</div>` : ''}
          ${(t.mitigations || []).length > 0 ? `
            <ul class="threat-mitigations">
              ${t.mitigations.map(m => `<li>${escapeHtml(m)}</li>`).join('')}
            </ul>` : ''}
        </div>
      `).join('')}
    </div>
    ${(data.attack_surface || []).length > 0 ? `
      <div style="margin-top:16px;padding:12px 16px;background:var(--bg-tertiary);border-radius:var(--radius-md)">
        <div style="font-size:.78rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px">Superficie de ataque</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${data.attack_surface.map(s => `<span class="badge badge-none">${escapeHtml(s)}</span>`).join('')}
        </div>
      </div>` : ''}`;
}

/* ── RENDER SAST RULE ── */
export function renderSAST(data, container) {
  container.innerHTML = `
    <div class="results-summary">
      <span class="results-title">⚙️ Regla Semgrep Generada</span>
    </div>

    <div style="margin-bottom:16px;padding:12px 16px;background:var(--bg-tertiary);border-radius:var(--radius-md)">
      <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap">
        <span class="badge badge-none">ID: ${escapeHtml(data.rule_id || 'custom-rule')}</span>
        ${badge(data.severity)}
        ${(data.languages || []).map(l => `<span class="badge badge-none">${escapeHtml(l)}</span>`).join('')}
      </div>
      <p style="font-size:.85rem;color:var(--text-secondary)">${escapeHtml(data.description || '')}</p>
    </div>

    <div class="semgrep-block">
      <div class="semgrep-header">
        <span>📄 semgrep-rule.yaml</span>
        <button class="semgrep-copy" id="copySemgrep">Copiar regla</button>
      </div>
      <pre class="semgrep-code" id="semgrepCode">${escapeHtml(data.rule_yaml || '')}</pre>
    </div>

    ${data.github_actions_snippet ? `
      <div class="semgrep-block">
        <div class="semgrep-header">
          <span>🔧 GitHub Actions (.github/workflows/semgrep.yml)</span>
          <button class="semgrep-copy" id="copyGHA">Copiar snippet</button>
        </div>
        <pre class="semgrep-code" id="ghaCode">${escapeHtml(data.github_actions_snippet)}</pre>
      </div>` : ''}

    ${data.explanation ? `
      <div style="padding:16px;background:var(--accent-blue-dim);border:1px solid rgba(59,130,246,.2);border-radius:var(--radius-md)">
        <div style="font-size:.78rem;font-weight:700;color:var(--accent-blue);text-transform:uppercase;margin-bottom:6px">Explicación</div>
        <p style="font-size:.85rem;color:var(--text-secondary);line-height:1.6">${escapeHtml(data.explanation)}</p>
      </div>` : ''}`;

  // Bind copy buttons
  document.getElementById('copySemgrep')?.addEventListener('click', () => {
    copyText(data.rule_yaml || '');
  });
  document.getElementById('copyGHA')?.addEventListener('click', () => {
    copyText(data.github_actions_snippet || '');
  });
}
