// js/analyzer.js — Módulo 2: Vulnerability Analyzer (OWASP Top 10)

import { callLLM, extractJSON } from './api.js';
import { showToast, showSkeleton, setButtonLoading, renderVulns, exportJSON } from './ui.js';
import { PROMPTS } from '../prompts/system.js';

export function initAnalyzer(editor) {
  const btn       = document.getElementById('btn-analyzer');
  const clearBtn  = document.getElementById('clear-analyzer');
  const results   = document.getElementById('results-analyzer');
  const dropzone  = document.getElementById('dropzone-analyzer');
  const fileInput = document.getElementById('file-analyzer');
  const langSel   = document.getElementById('lang-analyzer');

  let lastResult = null;

  editor.onDidChangeModelContent(() => {
    btn.disabled = editor.getValue().trim().length === 0;
  });

  // Drag & drop
  dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', e => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file, editor, langSel);
  });

  fileInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if (file) loadFile(file, editor, langSel);
  });

  clearBtn.addEventListener('click', () => {
    editor.setValue('');
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-shield-virus"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    lastResult = null;
    btn.disabled = true;
  });

  window.__exportVulns = () => {
    if (lastResult) exportJSON(lastResult, 'devguard-vulns.json');
  };

  btn.addEventListener('click', async () => {
    const code = editor.getValue().trim();
    const lang = langSel.value === 'auto' ? 'autodetect' : langSel.value;
    if (!code) return;

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      let accumulated = '';

      const rawText = await callLLM(
        PROMPTS.vulnerabilityAnalyzer,
        `Language: ${lang}\n\nAnalyze this code for OWASP Top 10 vulnerabilities:\n\`\`\`${lang}\n${code}\n\`\`\``,
        (chunk, full) => {
          accumulated = full;
          results.innerHTML = `
            <div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">
              ${accumulated.slice(-500)}
            </div>`;
        },
        2000
      );

      const data = extractJSON(rawText);
      lastResult = data;
      renderVulns(data, results);
      const count = data.vulnerabilities?.length || 0;
      showToast(
        `${count} vulnerabilidad${count !== 1 ? 'es' : ''} encontrada${count !== 1 ? 's' : ''} · Riesgo: ${data.overall_risk}`,
        count > 0 ? 'error' : 'success'
      );

    } catch (err) {
      results.innerHTML = `
        <div style="padding:20px;color:var(--accent-red)">
          <div style="font-weight:700;margin-bottom:8px">❌ Error al analizar</div>
          <div style="font-size:.85rem">${err.message}</div>
        </div>`;
      showToast(err.message, 'error');
    } finally {
      setButtonLoading(btn, false);
    }
  });
}

function loadFile(file, editor, langSel) {
  const reader = new FileReader();
  reader.onload = e => {
    editor.setValue(e.target.result);
    const ext = file.name.split('.').pop().toLowerCase();
    const langMap = {
      js: 'javascript', ts: 'typescript', py: 'python',
      java: 'java', php: 'php', go: 'go', rb: 'ruby', cs: 'csharp'
    };
    const lang = langMap[ext];
    if (lang) {
      langSel.value = lang;
      monaco.editor.setModelLanguage(editor.getModel(), lang);
    }
    showToast(`Archivo cargado: ${file.name}`, 'success');
  };
  reader.readAsText(file);
}
