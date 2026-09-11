// js/scanner.js — Módulo 1: Secret Scanner

import { callLLM, extractJSON } from './api.js';
import { showToast, showSkeleton, setButtonLoading, renderSecrets, exportJSON } from './ui.js';
import { PROMPTS } from '../prompts/system.js';

export function initScanner(editor) {
  const btn       = document.getElementById('btn-scanner');
  const clearBtn  = document.getElementById('clear-scanner');
  const results   = document.getElementById('results-scanner');
  const dropzone  = document.getElementById('dropzone-scanner');
  const fileInput = document.getElementById('file-scanner');

  let lastResult = null;

  // Habilitar botón cuando hay contenido
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

  // Limpiar
  clearBtn.addEventListener('click', () => {
    editor.setValue('');
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-key"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    lastResult = null;
    btn.disabled = true;
  });

  // Exportar
  window.__exportSecrets = () => {
    if (lastResult) exportJSON(lastResult, 'devguard-secrets.json');
  };

  // Analizar
  btn.addEventListener('click', async () => {
    const code = editor.getValue().trim();
    if (!code) return;

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      let accumulated = '';

      const rawText = await callLLM(
        PROMPTS.secretScanner,
        `Analyze this code for exposed secrets:\n\`\`\`\n${code}\n\`\`\``,
        (chunk, full) => {
          accumulated = full;
          // Mostrar cursor de streaming en resultados
          results.innerHTML = `
            <div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">
              ${accumulated.slice(-400)}
            </div>`;
        },
        1500
      );

      const data = extractJSON(rawText);
      lastResult = data;
      renderSecrets(data, results);
      showToast(`Análisis completado: ${data.findings?.length || 0} secretos encontrados`, data.findings?.length > 0 ? 'error' : 'success');

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
    // Detectar lenguaje por extensión
    const ext = file.name.split('.').pop().toLowerCase();
    const langMap = {
      js: 'javascript', ts: 'typescript', py: 'python',
      java: 'java', php: 'php', go: 'go', rb: 'ruby',
      cs: 'csharp', json: 'json', yaml: 'yaml', yml: 'yaml',
      sh: 'shell', tf: 'hcl', env: 'ini'
    };
    const lang = langMap[ext] || 'plaintext';
    monaco.editor.setModelLanguage(editor.getModel(), lang);
    showToast(`Archivo cargado: ${file.name}`, 'success');
  };
  reader.readAsText(file);
}
