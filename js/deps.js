// js/deps.js — Módulo 3: Dependency Checker

import { callLLM, extractJSON } from './api.js';
import { showToast, showSkeleton, setButtonLoading, renderDeps, exportJSON } from './ui.js';
import { PROMPTS } from '../prompts/system.js';

export function initDeps(editor) {
  const btn       = document.getElementById('btn-deps');
  const clearBtn  = document.getElementById('clear-deps');
  const results   = document.getElementById('results-deps');
  const dropzone  = document.getElementById('dropzone-deps');
  const fileInput = document.getElementById('file-deps');

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
    if (file) loadFile(file, editor);
  });

  fileInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if (file) loadFile(file, editor);
  });

  clearBtn.addEventListener('click', () => {
    editor.setValue('');
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-box-open"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    lastResult = null;
    btn.disabled = true;
  });

  window.__exportDeps = () => {
    if (lastResult) exportJSON(lastResult, 'devguard-dependencies.json');
  };

  btn.addEventListener('click', async () => {
    const content = editor.getValue().trim();
    if (!content) return;

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      let accumulated = '';

      const rawText = await callLLM(
        PROMPTS.dependencyChecker,
        `Analyze this dependency file for security vulnerabilities:\n\`\`\`\n${content}\n\`\`\``,
        (chunk, full) => {
          accumulated = full;
          results.innerHTML = `
            <div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">
              ${accumulated.slice(-500)}
            </div>`;
        },
        1500
      );

      const data = extractJSON(rawText);
      lastResult = data;
      renderDeps(data, results);
      showToast(
        `${data.vulnerable_count || 0} de ${data.total_count || 0} dependencias vulnerables`,
        (data.vulnerable_count || 0) > 0 ? 'error' : 'success'
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

function loadFile(file, editor) {
  const reader = new FileReader();
  reader.onload = e => {
    editor.setValue(e.target.result);
    const ext = file.name.split('.').pop().toLowerCase();
    const langMap = { json: 'json', xml: 'xml', toml: 'ini', mod: 'go', txt: 'plaintext', lock: 'plaintext' };
    const lang = langMap[ext] || 'plaintext';
    monaco.editor.setModelLanguage(editor.getModel(), lang);
    showToast(`Archivo cargado: ${file.name}`, 'success');
  };
  reader.readAsText(file);
}
