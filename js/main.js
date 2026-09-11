// js/main.js — Consolidado para ejecución local sin servidor (file://)

/* ==========================================================================
   PROMPTS
   ========================================================================== */
const PROMPTS = {
  secretScanner: `You are a security expert. Analyze code for exposed secrets (API keys, tokens, passwords, credentials, private keys, connection strings).
Respond ONLY in valid JSON, no markdown:
{"findings":[{"line":number,"type":"string","severity":"CRITICAL|HIGH|MEDIUM","value_masked":"string","description":"string","fix":"string"}],"summary":"string","risk_score":number}
If none found: {"findings":[],"summary":"No secrets detected","risk_score":0}`,

  vulnerabilityAnalyzer: `You are an application security expert. Analyze code for OWASP Top 10 vulnerabilities: SQLi, XSS, IDOR, SSRF, RCE, path traversal, insecure deserialization, broken auth.
Respond ONLY in valid JSON, no markdown:
{"vulnerabilities":[{"line":number,"type":"string","owasp":"string","severity":"CRITICAL|HIGH|MEDIUM|LOW","description":"string","code_vulnerable":"string","code_fixed":"string","mitre":"string","cvss":number}],"summary":"string","overall_risk":"CRITICAL|HIGH|MEDIUM|LOW|SAFE"}
If none found: {"vulnerabilities":[],"summary":"No vulnerabilities detected","overall_risk":"SAFE"}`,

  dependencyChecker: `You are a supply chain security expert. Analyze this dependency file for packages with known CVEs, outdated versions, or security risks.
Respond ONLY in valid JSON, no markdown:
{"dependencies":[{"name":"string","current_version":"string","status":"VULNERABLE|OUTDATED|SAFE","severity":"CRITICAL|HIGH|MEDIUM|LOW|NONE","cve":"string|null","description":"string","recommended_version":"string|null","fix_command":"string|null"}],"summary":"string","vulnerable_count":number,"total_count":number}`,

  threatModeler: `You are a threat modeling expert (STRIDE). Analyze the system description and generate a structured threat model.
Respond ONLY in valid JSON, no markdown:
{"threats":[{"category":"Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege","threat":"string","affected_component":"string","likelihood":"HIGH|MEDIUM|LOW","impact":"HIGH|MEDIUM|LOW","risk":"CRITICAL|HIGH|MEDIUM|LOW","mitigations":["string"]}],"attack_surface":["string"],"trust_boundaries":["string"],"summary":"string","priority_actions":["string"]}`,

  ruleGenerator: `You are a SAST expert specializing in Semgrep rules. Given a vulnerability, generate a production-ready Semgrep rule.
Respond ONLY in valid JSON, no markdown:
{"rule_yaml":"string","rule_id":"string","description":"string","severity":"ERROR|WARNING|INFO","languages":["string"],"github_actions_snippet":"string","explanation":"string"}`
};

/* ==========================================================================
   API & SECURITY
   ========================================================================== */
const CONFIG_KEY = 'devguard_config';
const OB_KEY = 'djc2026_super_secret'; // Llave XOR

// Ofuscación XOR básica para evitar guardar credenciales en texto plano en localStorage
function obf(str) { return btoa(Array.from(str).map((c,i)=>String.fromCharCode(c.charCodeAt(0)^OB_KEY.charCodeAt(i%OB_KEY.length))).join('')); }
function deobf(str) { try { return Array.from(atob(str)).map((c,i)=>String.fromCharCode(c.charCodeAt(0)^OB_KEY.charCodeAt(i%OB_KEY.length))).join(''); } catch { return str; } }

function getConfig() {
  try { 
    const cfg = JSON.parse(localStorage.getItem(CONFIG_KEY) || '{}'); 
    if (cfg.apiKey && cfg.obfuscated) cfg.apiKey = deobf(cfg.apiKey);
    return cfg;
  } catch { return {}; }
}
function saveConfig(apiKey, baseUrl) {
  localStorage.setItem(CONFIG_KEY, JSON.stringify({ apiKey: obf(apiKey), baseUrl, obfuscated: true }));
}

async function callLLM(systemPrompt, userContent, onChunk = null, maxTokens = 2000) {
  const { apiKey, baseUrl } = getConfig();
  if (!apiKey) throw new Error('API Key no configurada. Haz clic en "Configurar API".');

  const url = `${baseUrl}/chat/completions`;
  const body = JSON.stringify({
    model: 'djc-auto',
    stream: true,
    max_tokens: Math.max(500, maxTokens),
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user',   content: userContent  }
    ]
  });

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body
  });

  if (!response.ok) {
    const errText = await response.text().catch(() => response.statusText);
    throw new Error(`API Error ${response.status}: ${errText}`);
  }

  const reader  = response.body.getReader();
  const decoder = new TextDecoder();
  let   fullText = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = decoder.decode(value, { stream: true });
    const lines = chunk.split('\n');
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const data = line.slice(6).trim();
      if (data === '[DONE]') break;
      try {
        const parsed = JSON.parse(data);
        const delta  = parsed.choices?.[0]?.delta?.content ?? '';
        if (delta) {
          fullText += delta;
          if (onChunk) onChunk(delta, fullText);
        }
      } catch {}
    }
  }
  return fullText;
}

function extractJSON(text) {
  // 1. Limpiar markdown (ej. ```json ... ```)
  let cleanText = text.replace(/```[a-z]*\n?/gi, '').replace(/```/g, '').trim();
  
  // 1.5. Reparar secuencias de escape inválidas (ej. \ seguido de espacios que el LLM genera por error)
  cleanText = cleanText.replace(/\\(?!["\\/bfnrtu])/g, '\\\\');
  
  // 2. Intento directo
  try { return JSON.parse(cleanText); } catch {}
  
  // 3. Buscar el primer { o [ y el último } o ]
  const firstBrace = cleanText.indexOf('{');
  const lastBrace = cleanText.lastIndexOf('}');
  const firstBracket = cleanText.indexOf('[');
  const lastBracket = cleanText.lastIndexOf(']');
  
  let matchStr = '';
  if (firstBrace !== -1 && lastBrace !== -1 && (firstBracket === -1 || firstBrace < firstBracket)) {
    matchStr = cleanText.substring(firstBrace, lastBrace + 1);
  } else if (firstBracket !== -1 && lastBracket !== -1) {
    matchStr = cleanText.substring(firstBracket, lastBracket + 1);
  }
  
  if (matchStr) {
    try { 
      // Reparación básica de JSON (comas al final)
      let fixedStr = matchStr.replace(/,\s*([\}\]])/g, '$1');
      return JSON.parse(fixedStr); 
    } catch (e) {
      console.error("Fallo al parsear tras regex/limpieza. Raw Text:", matchStr);
    }
  }
  
  console.error("Texto original recibido del modelo:", text);
  throw new Error('No se pudo parsear la respuesta JSON del modelo. (Revisa la consola para ver qué respondió la IA)');
}

async function testConnection(apiKey, baseUrl) {
  const url = `${baseUrl}/chat/completions`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'djc-auto', max_tokens: 500, stream: false,
      messages: [{ role: 'user', content: 'ping' }]
    })
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return true;
}

/* ==========================================================================
   UI UTILS
   ========================================================================== */
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const icons = { success: '<i class="fa-solid fa-check"></i>', error: '<i class="fa-solid fa-xmark"></i>', info: '<i class="fa-solid fa-circle-info"></i>' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function showSkeleton(container) {
  container.innerHTML = `
    <div class="skeleton skeleton-line" style="width:60%"></div>
    <div class="skeleton skeleton-line" style="width:40%"></div>
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-card"></div>
    <div class="skeleton skeleton-line" style="width:50%"></div>
  `;
}

function setButtonLoading(btn, loading) {
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

function badge(severity) {
  const s = (severity || 'NONE').toUpperCase();
  const map = {
    CRITICAL: 'badge-critical', HIGH: 'badge-high',
    MEDIUM: 'badge-medium', LOW: 'badge-low',
    NONE: 'badge-none', SAFE: 'badge-safe',
    VULNERABLE: 'badge-critical', OUTDATED: 'badge-medium'
  };
  return `<span class="badge ${map[s] || 'badge-none'}">${s}</span>`;
}

function riskBanner(risk, count, label) {
  const r = (risk || 'SAFE').toLowerCase();
  const icons = { critical: '<i class="fa-solid fa-skull-crossbones"></i>', high: '<i class="fa-solid fa-triangle-exclamation"></i>', medium: '<i class="fa-solid fa-bolt"></i>', low: '<i class="fa-solid fa-circle-info"></i>', safe: '<i class="fa-solid fa-shield-halved"></i>' };
  return `
    <div class="risk-banner ${r}">
      <span>${icons[r] || '<i class="fa-solid fa-magnifying-glass"></i>'}</span>
      <span>${count} ${label} · Riesgo ${risk}</span>
    </div>`;
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function diffBlock(vulnerable, fixed) {
  if (!vulnerable && !fixed) return '';
  const vuln = (vulnerable || '').split('\n');
  const fixd = (fixed || '').split('\n');
  const html = [
    ...vuln.filter(Boolean).map(l => `<div class="diff-line removed">- ${escapeHtml(l)}</div>`),
    ...fixd.filter(Boolean).map(l => `<div class="diff-line added">+ ${escapeHtml(l)}</div>`)
  ].join('');
  return `<div class="diff-block">${html}</div>`;
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast('Copiado al portapapeles', 'success')).catch(() => showToast('No se pudo copiar', 'error'));
}

function exportJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

/* ==========================================================================
   RENDERS
   ========================================================================== */
function renderSecrets(data, container) {
  const findings = data.findings || [];
  if (findings.length === 0) {
    container.innerHTML = `${riskBanner('SAFE', 0, 'secretos encontrados')}
      <div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-shield-halved"></i></div><p>No se detectaron secretos expuestos</p></div>`;
    return;
  }
  container.innerHTML = `
    ${riskBanner(findings[0]?.severity || 'HIGH', findings.length, 'secretos encontrados')}
    <div class="results-summary">
      <span class="results-title">🔍 Secret Scanner</span>
      <button class="export-btn" onclick="window.__exportSecrets()">⬇ Exportar</button>
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
}

function renderVulns(data, container) {
  const vulns = data.vulnerabilities || [];
  if (vulns.length === 0) {
    container.innerHTML = `${riskBanner('SAFE', 0, 'vulnerabilidades')}
      <div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-shield-halved"></i></div><p>No se detectaron vulnerabilidades OWASP</p></div>`;
    return;
  }
  container.innerHTML = `
    ${riskBanner(data.overall_risk, vulns.length, 'vulnerabilidades')}
    <div class="results-summary">
      <span class="results-title">⚡ Vulnerability Analyzer</span>
      <button class="export-btn" onclick="window.__exportVulns()">⬇ Exportar</button>
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

function renderDeps(data, container) {
  const deps = data.dependencies || [];
  const vuln = deps.filter(d => d.status === 'VULNERABLE');
  const outdated = deps.filter(d => d.status === 'OUTDATED');
  container.innerHTML = `
    ${riskBanner(vuln.length > 0 ? 'HIGH' : outdated.length > 0 ? 'MEDIUM' : 'SAFE',
      data.vulnerable_count || 0, `de ${data.total_count || deps.length} dependencias vulnerables`)}
    <div class="results-summary">
      <span class="results-title">📦 Dependency Checker</span>
      <button class="export-btn" onclick="window.__exportDeps()">⬇ Exportar</button>
    </div>
    <table class="dep-table">
      <thead><tr><th>Paquete</th><th>Versión</th><th>Estado</th><th>Remediación</th></tr></thead>
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

function renderThreat(data, container) {
  const threats = data.threats || [];
  const strideColors = { 'Spoofing': 'var(--accent-blue)', 'Tampering': 'var(--accent-orange)', 'Repudiation': 'var(--accent-yellow)', 'Information Disclosure': 'var(--accent-red)', 'Denial of Service': 'var(--accent-purple)', 'Elevation of Privilege': 'var(--accent-cyan)' };
  container.innerHTML = `
    <div class="results-summary">
      <span class="results-title">🗺️ Threat Model STRIDE</span>
      <button class="export-btn" onclick="window.__exportThreat()">⬇ Exportar</button>
    </div>
    ${(data.priority_actions || []).length > 0 ? `
      <div style="margin-bottom:20px">
        <div style="font-size:.8rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Acciones prioritarias</div>
        <ol class="priority-list">
          ${data.priority_actions.map((a, i) => `<li><span class="priority-num">${i+1}</span>${escapeHtml(a)}</li>`).join('')}
        </ol>
      </div>` : ''}
    <div class="stride-grid">
      ${threats.map(t => `
        <div class="threat-card">
          <div class="threat-category" style="color:${strideColors[t.category] || 'var(--accent-purple)'}">${escapeHtml(t.category || '')}</div>
          <div class="threat-name">${escapeHtml(t.threat || '')}</div>
          <div class="threat-meta">
            ${badge(t.risk)}
            <span class="badge badge-none">Likelihood: ${escapeHtml(t.likelihood || '')}</span>
            <span class="badge badge-none">Impact: ${escapeHtml(t.impact || '')}</span>
          </div>
          ${t.affected_component ? `<div style="font-size:.78rem;color:var(--text-muted);margin-bottom:8px">Componente: ${escapeHtml(t.affected_component)}</div>` : ''}
          ${(t.mitigations || []).length > 0 ? `<ul class="threat-mitigations">${t.mitigations.map(m => `<li>${escapeHtml(m)}</li>`).join('')}</ul>` : ''}
        </div>
      `).join('')}
    </div>
    ${(data.attack_surface || []).length > 0 ? `
      <div style="margin-top:16px;padding:12px 16px;background:var(--bg-tertiary);border-radius:var(--radius-md)">
        <div style="font-size:.78rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px">Superficie de ataque</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">${data.attack_surface.map(s => `<span class="badge badge-none">${escapeHtml(s)}</span>`).join('')}</div>
      </div>` : ''}`;
}

function renderSAST(data, container) {
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
      <div class="semgrep-header"><span>📄 semgrep-rule.yaml</span><button class="semgrep-copy" id="copySemgrep">Copiar regla</button></div>
      <pre class="semgrep-code">${escapeHtml(data.rule_yaml || '')}</pre>
    </div>
    ${data.github_actions_snippet ? `
      <div class="semgrep-block">
        <div class="semgrep-header"><span>🔧 .github/workflows/semgrep.yml</span><button class="semgrep-copy" id="copyGHA">Copiar snippet</button></div>
        <pre class="semgrep-code">${escapeHtml(data.github_actions_snippet)}</pre>
      </div>` : ''}
    ${data.explanation ? `
      <div style="padding:16px;background:var(--accent-blue-dim);border:1px solid rgba(59,130,246,.2);border-radius:var(--radius-md)">
        <div style="font-size:.78rem;font-weight:700;color:var(--accent-blue);text-transform:uppercase;margin-bottom:6px">Explicación</div>
        <p style="font-size:.85rem;color:var(--text-secondary);line-height:1.6">${escapeHtml(data.explanation)}</p>
      </div>` : ''}`;
  document.getElementById('copySemgrep')?.addEventListener('click', () => copyText(data.rule_yaml || ''));
  document.getElementById('copyGHA')?.addEventListener('click', () => copyText(data.github_actions_snippet || ''));
}

/* ==========================================================================
   MODULES INIT
   ========================================================================== */
function initScanner(editor) {
  const btn = document.getElementById('btn-scanner'), clearBtn = document.getElementById('clear-scanner'), results = document.getElementById('results-scanner');
  let lastResult = null;
  editor.onDidChangeModelContent(() => btn.disabled = editor.getValue().trim().length === 0);
  clearBtn.addEventListener('click', () => {
    editor.setValue('');
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-key"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    btn.disabled = true; lastResult = null;
  });
  window.__exportSecrets = () => { if (lastResult) exportJSON(lastResult, 'devguard-secrets.json'); };
  btn.addEventListener('click', async () => {
    const code = editor.getValue().trim(); if (!code) return;
    setButtonLoading(btn, true); showSkeleton(results);
    try {
      let acc = '';
      const rawText = await callLLM(PROMPTS.secretScanner, `Analyze this code for exposed secrets:\n\`\`\`\n${code}\n\`\`\``, (chunk, full) => {
        acc = full;
        results.innerHTML = `<div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">${acc.slice(-400)}</div>`;
      }, 4000);
      const data = extractJSON(rawText); lastResult = data;
      renderSecrets(data, results);
      showToast(`Análisis completado: ${data.findings?.length || 0} secretos encontrados`, data.findings?.length > 0 ? 'error' : 'success');
    } catch (err) {
      results.innerHTML = `<div style="padding:20px;color:var(--accent-red)"><div style="font-weight:700;margin-bottom:8px">❌ Error al analizar</div><div style="font-size:.85rem">${err.message}</div></div>`;
      showToast(err.message, 'error');
    } finally { setButtonLoading(btn, false); }
  });
}

function initAnalyzer(editor) {
  const btn = document.getElementById('btn-analyzer'), clearBtn = document.getElementById('clear-analyzer'), results = document.getElementById('results-analyzer'), langSel = document.getElementById('lang-analyzer');
  let lastResult = null;
  editor.onDidChangeModelContent(() => btn.disabled = editor.getValue().trim().length === 0);
  clearBtn.addEventListener('click', () => {
    editor.setValue('');
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-shield-virus"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    btn.disabled = true; lastResult = null;
  });
  window.__exportVulns = () => { if (lastResult) exportJSON(lastResult, 'devguard-vulns.json'); };
  btn.addEventListener('click', async () => {
    const code = editor.getValue().trim(); const lang = langSel.value === 'auto' ? 'autodetect' : langSel.value;
    if (!code) return;
    setButtonLoading(btn, true); showSkeleton(results);
    try {
      let acc = '';
      const rawText = await callLLM(PROMPTS.vulnerabilityAnalyzer, `Language: ${lang}\n\nAnalyze this code for OWASP Top 10 vulnerabilities:\n\`\`\`${lang}\n${code}\n\`\`\``, (chunk, full) => {
        acc = full;
        results.innerHTML = `<div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">${acc.slice(-500)}</div>`;
      }, 4000);
      const data = extractJSON(rawText); lastResult = data;
      renderVulns(data, results);
      const count = data.vulnerabilities?.length || 0;
      showToast(`${count} vulnerabilidades · Riesgo: ${data.overall_risk}`, count > 0 ? 'error' : 'success');
    } catch (err) {
      results.innerHTML = `<div style="padding:20px;color:var(--accent-red)"><div style="font-weight:700;margin-bottom:8px">❌ Error al analizar</div><div style="font-size:.85rem">${err.message}</div></div>`;
      showToast(err.message, 'error');
    } finally { setButtonLoading(btn, false); }
  });
}

function initDeps(editor) {
  const btn = document.getElementById('btn-deps'), clearBtn = document.getElementById('clear-deps'), results = document.getElementById('results-deps');
  let lastResult = null;
  editor.onDidChangeModelContent(() => btn.disabled = editor.getValue().trim().length === 0);
  clearBtn.addEventListener('click', () => {
    editor.setValue('');
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-box-open"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    btn.disabled = true; lastResult = null;
  });
  window.__exportDeps = () => { if (lastResult) exportJSON(lastResult, 'devguard-dependencies.json'); };
  btn.addEventListener('click', async () => {
    const content = editor.getValue().trim(); if (!content) return;
    setButtonLoading(btn, true); showSkeleton(results);
    try {
      let acc = '';
      const rawText = await callLLM(PROMPTS.dependencyChecker, `Analyze this dependency file for security vulnerabilities:\n\`\`\`\n${content}\n\`\`\``, (chunk, full) => {
        acc = full;
        results.innerHTML = `<div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">${acc.slice(-500)}</div>`;
      }, 4000);
      const data = extractJSON(rawText); lastResult = data;
      renderDeps(data, results);
      showToast(`${data.vulnerable_count || 0} dependencias vulnerables`, (data.vulnerable_count || 0) > 0 ? 'error' : 'success');
    } catch (err) {
      results.innerHTML = `<div style="padding:20px;color:var(--accent-red)"><div style="font-weight:700;margin-bottom:8px">❌ Error al analizar</div><div style="font-size:.85rem">${err.message}</div></div>`;
      showToast(err.message, 'error');
    } finally { setButtonLoading(btn, false); }
  });
}

function initThreat() {
  const btn = document.getElementById('btn-threat'), clearBtn = document.getElementById('clear-threat'), results = document.getElementById('results-threat'), textarea = document.getElementById('editor-threat');
  let lastResult = null;
  textarea.addEventListener('input', () => btn.disabled = textarea.value.trim().length < 20);
  clearBtn.addEventListener('click', () => {
    textarea.value = '';
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-network-wired"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    btn.disabled = true; lastResult = null;
  });
  window.__exportThreat = () => { if (lastResult) exportJSON(lastResult, 'devguard-threatmodel.json'); };
  btn.addEventListener('click', async () => {
    const desc = textarea.value.trim(); if (desc.length < 20) return showToast('Describe tu sistema (mínimo 20 caracteres)', 'error');
    setButtonLoading(btn, true); showSkeleton(results);
    try {
      let acc = '';
      const rawText = await callLLM(PROMPTS.threatModeler, `Generate a STRIDE threat model for this system:\n\n${desc}`, (chunk, full) => {
        acc = full;
        results.innerHTML = `<div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">${acc.slice(-500)}</div>`;
      }, 4000);
      const data = extractJSON(rawText); lastResult = data;
      renderThreat(data, results);
      showToast(`Threat model generado: ${data.threats?.length || 0} amenazas`, 'info');
    } catch (err) {
      results.innerHTML = `<div style="padding:20px;color:var(--accent-red)"><div style="font-weight:700;margin-bottom:8px">❌ Error al generar</div><div style="font-size:.85rem">${err.message}</div></div>`;
      showToast(err.message, 'error');
    } finally { setButtonLoading(btn, false); }
  });
}

function initSAST(editor) {
  const btn = document.getElementById('btn-sast'), clearBtn = document.getElementById('clear-sast'), results = document.getElementById('results-sast'), vulnType = document.getElementById('sast-vuln-type'), langSel = document.getElementById('sast-lang'), desc = document.getElementById('sast-description');
  let lastResult = null;
  const checkState = () => btn.disabled = !(vulnType.value.trim() && editor.getValue().trim());
  vulnType.addEventListener('input', checkState);
  editor.onDidChangeModelContent(checkState);
  langSel.addEventListener('change', e => monaco.editor.setModelLanguage(editor.getModel(), e.target.value || 'javascript'));
  clearBtn.addEventListener('click', () => {
    vulnType.value = ''; langSel.value = 'javascript'; editor.setValue(''); desc.value = '';
    monaco.editor.setModelLanguage(editor.getModel(), 'javascript');
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-microchip"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    btn.disabled = true; lastResult = null;
  });
  btn.addEventListener('click', async () => {
    const vT = vulnType.value.trim(), c = editor.getValue().trim(), l = langSel.value, d = desc.value.trim();
    if (!vT || !c) return;
    setButtonLoading(btn, true); showSkeleton(results);
    try {
      let acc = '';
      const rawText = await callLLM(PROMPTS.ruleGenerator, `Type: ${vT}\nLang: ${l}\nContext: ${d}\nCode:\n\`\`\`${l}\n${c}\n\`\`\``, (chunk, full) => {
        acc = full;
        results.innerHTML = `<div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">${acc.slice(-500)}</div>`;
      }, 4000);
      const data = extractJSON(rawText); lastResult = data;
      renderSAST(data, results);
      showToast('Regla Semgrep generada', 'success');
    } catch (err) {
      results.innerHTML = `<div style="padding:20px;color:var(--accent-red)"><div style="font-weight:700;margin-bottom:8px">❌ Error al generar</div><div style="font-size:.85rem">${err.message}</div></div>`;
      showToast(err.message, 'error');
    } finally { setButtonLoading(btn, false); }
  });
}

/* ==========================================================================
   APP INIT
   ========================================================================== */
function initApp() {
  // Tabs
  const tabs = document.querySelectorAll('.tab'), panels = document.querySelectorAll('.tab-panel');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active')); panels.forEach(p => p.classList.remove('active'));
      tab.classList.add('active'); document.getElementById(`panel-${tab.dataset.tab}`).classList.add('active');
    });
  });

  // Modal
  const overlay = document.getElementById('modalConfig'), btnOpen = document.getElementById('btnConfig'), btnClose = document.getElementById('modalClose'), btnSave = document.getElementById('btnSaveConfig'), feedback = document.getElementById('configFeedback'), keyInput = document.getElementById('inputApiKey'), urlInput = document.getElementById('inputBaseUrl');
  const cfg = getConfig(); if (cfg.apiKey) keyInput.value = cfg.apiKey; if (cfg.baseUrl) urlInput.value = cfg.baseUrl;
  btnOpen.addEventListener('click', () => overlay.classList.add('open'));
  btnClose.addEventListener('click', () => overlay.classList.remove('open'));
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('open'); });

  const updateApiStatus = (connected) => {
    const dot = document.querySelector('.status-dot'), text = document.querySelector('.status-text');
    if (connected) { dot.classList.add('connected'); dot.classList.remove('error'); text.textContent = 'API conectada'; document.querySelectorAll('.btn-analyze').forEach(b => b.disabled = false); }
    else { dot.classList.remove('connected'); dot.classList.add('error'); text.textContent = 'Error de conexión'; }
  };
  if (cfg.apiKey) updateApiStatus(true);

  btnSave.addEventListener('click', async () => {
    const apiKey = keyInput.value.trim(), baseUrl = urlInput.value.trim();
    if (!apiKey || !baseUrl) return (feedback.textContent = '⚠ Completa ambos campos.', feedback.className = 'config-feedback err');
    btnSave.textContent = 'Probando conexión...'; btnSave.disabled = true; feedback.textContent = '';
    try {
      await testConnection(apiKey, baseUrl);
      saveConfig(apiKey, baseUrl);
      feedback.textContent = '✅ Conexión exitosa.'; feedback.className = 'config-feedback ok';
      updateApiStatus(true); showToast('API conectada correctamente', 'success');
      setTimeout(() => overlay.classList.remove('open'), 1500);
    } catch (err) {
      feedback.textContent = `❌ Error: ${err.message}`; feedback.className = 'config-feedback err'; updateApiStatus(false);
    } finally { btnSave.textContent = 'Guardar y probar conexión'; btnSave.disabled = false; }
  });

  // Monaco Editor
  require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' } });
  require(['vs/editor/editor.main'], () => {
    monaco.editor.defineTheme('devguard', {
      base: 'vs-dark', inherit: true,
      rules: [{ token: 'comment', foreground: '475569', fontStyle: 'italic' }, { token: 'string', foreground: '86efac' }, { token: 'keyword', foreground: '7dd3fc' }, { token: 'number', foreground: 'fcd34d' }],
      colors: { 'editor.background': '#1a2235', 'editor.foreground': '#f1f5f9', 'editorLineNumber.foreground':'#475569', 'editor.lineHighlightBackground': '#1e2d45', 'editorCursor.foreground': '#3b82f6', 'editor.selectionBackground': '#3b82f640' }
    });
    const commonOpts = { theme: 'devguard', fontSize: 13, fontFamily: "'JetBrains Mono', monospace", minimap: { enabled: false }, automaticLayout: true, wordWrap: 'on', padding: { top: 12, bottom: 12 } };
    
    const editorScanner = monaco.editor.create(document.getElementById('editor-scanner'), { ...commonOpts, language: 'javascript' });
    const editorAnalyzer = monaco.editor.create(document.getElementById('editor-analyzer'), { ...commonOpts, language: 'javascript' });
    const editorDeps = monaco.editor.create(document.getElementById('editor-deps'), { ...commonOpts, language: 'json' });
    const editorSAST = monaco.editor.create(document.getElementById('editor-sast'), { ...commonOpts, language: 'javascript' });

    document.getElementById('lang-analyzer').addEventListener('change', e => monaco.editor.setModelLanguage(editorAnalyzer.getModel(), e.target.value === 'auto' ? 'javascript' : e.target.value));

    // Setup drag&drop
    const setupDD = (dz, inp, ed, isDeps) => {
      dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
      dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
      dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('dragover'); const f = e.dataTransfer.files[0]; if (f) loadF(f, ed, isDeps); });
      inp.addEventListener('change', e => { const f = e.target.files[0]; if (f) loadF(f, ed, isDeps); });
    };
    const loadF = (file, ed, isDeps) => {
      const reader = new FileReader();
      reader.onload = e => { ed.setValue(e.target.result); showToast(`Archivo cargado: ${file.name}`, 'success'); };
      reader.readAsText(file);
    };

    setupDD(document.getElementById('dropzone-scanner'), document.getElementById('file-scanner'), editorScanner, false);
    setupDD(document.getElementById('dropzone-analyzer'), document.getElementById('file-analyzer'), editorAnalyzer, false);
    setupDD(document.getElementById('dropzone-deps'), document.getElementById('file-deps'), editorDeps, true);

    initScanner(editorScanner);
    initAnalyzer(editorAnalyzer);
    initDeps(editorDeps);
    initThreat();
    initSAST(editorSAST);
  });
}

// Ejecutar todo
document.addEventListener('DOMContentLoaded', initApp);
