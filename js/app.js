// js/app.js — Orquestador principal de DevGuard AI

import { getConfig, saveConfig, testConnection } from './api.js';
import { showToast } from './ui.js';
import { initScanner }    from './scanner.js';
import { initAnalyzer }   from './analyzer.js';
import { initDeps }       from './deps.js';
import { initThreat }     from './threatmodel.js';
import { initSAST }       from './ruleGen.js';

export function initApp() {
  initTabs();
  initModal();
  initApiStatus();
  initMonaco();
}

/* ── TABS ── */
function initTabs() {
  const tabs   = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.tab-panel');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`panel-${tab.dataset.tab}`).classList.add('active');
    });
  });
}

/* ── MODAL CONFIG ── */
function initModal() {
  const overlay  = document.getElementById('modalConfig');
  const btnOpen  = document.getElementById('btnConfig');
  const btnClose = document.getElementById('modalClose');
  const btnSave  = document.getElementById('btnSaveConfig');
  const feedback = document.getElementById('configFeedback');
  const keyInput = document.getElementById('inputApiKey');
  const urlInput = document.getElementById('inputBaseUrl');

  // Pre-cargar config guardada
  const cfg = getConfig();
  if (cfg.apiKey) keyInput.value = cfg.apiKey;
  if (cfg.baseUrl) urlInput.value = cfg.baseUrl;

  btnOpen.addEventListener('click', () => overlay.classList.add('open'));
  btnClose.addEventListener('click', () => overlay.classList.remove('open'));
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('open'); });

  btnSave.addEventListener('click', async () => {
    const apiKey  = keyInput.value.trim();
    const baseUrl = urlInput.value.trim();

    if (!apiKey || !baseUrl) {
      feedback.textContent = '⚠ Completa ambos campos.';
      feedback.className = 'config-feedback err';
      return;
    }

    btnSave.textContent = 'Probando conexión...';
    btnSave.disabled = true;
    feedback.textContent = '';

    try {
      await testConnection(apiKey, baseUrl);
      saveConfig(apiKey, baseUrl);
      feedback.textContent = '✅ Conexión exitosa. Configuración guardada.';
      feedback.className = 'config-feedback ok';
      updateApiStatus(true);
      enableAllButtons();
      showToast('API conectada correctamente', 'success');
      setTimeout(() => overlay.classList.remove('open'), 1500);
    } catch (err) {
      feedback.textContent = `❌ Error: ${err.message}`;
      feedback.className = 'config-feedback err';
      updateApiStatus(false);
    } finally {
      btnSave.textContent = 'Guardar y probar conexión';
      btnSave.disabled = false;
    }
  });
}

/* ── API STATUS ── */
function initApiStatus() {
  const cfg = getConfig();
  if (cfg.apiKey) {
    updateApiStatus(true);
    enableAllButtons();
  }
}

function updateApiStatus(connected) {
  const dot  = document.querySelector('.status-dot');
  const text = document.querySelector('.status-text');
  if (connected) {
    dot.classList.add('connected');
    dot.classList.remove('error');
    text.textContent = 'API conectada';
  } else {
    dot.classList.remove('connected');
    dot.classList.add('error');
    text.textContent = 'Error de conexión';
  }
}

function enableAllButtons() {
  document.querySelectorAll('.btn-analyze').forEach(btn => {
    btn.disabled = false;
  });
}

/* ── MONACO EDITOR INIT ── */
function initMonaco() {
  require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' } });

  require(['vs/editor/editor.main'], () => {
    // Tema oscuro personalizado
    monaco.editor.defineTheme('devguard', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'comment', foreground: '475569', fontStyle: 'italic' },
        { token: 'string',  foreground: '86efac' },
        { token: 'keyword', foreground: '7dd3fc' },
        { token: 'number',  foreground: 'fcd34d' },
      ],
      colors: {
        'editor.background':          '#1a2235',
        'editor.foreground':          '#f1f5f9',
        'editorLineNumber.foreground':'#475569',
        'editor.lineHighlightBackground': '#1e2d45',
        'editorCursor.foreground':    '#3b82f6',
        'editor.selectionBackground': '#3b82f640',
      }
    });

    const commonOpts = {
      theme: 'devguard',
      fontSize: 13,
      fontFamily: "'JetBrains Mono', monospace",
      fontLigatures: true,
      minimap: { enabled: false },
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      automaticLayout: true,
      wordWrap: 'on',
      padding: { top: 12, bottom: 12 },
      scrollbar: { vertical: 'auto', horizontal: 'auto' },
    };

    // Editor Scanner
    const editorScanner = monaco.editor.create(
      document.getElementById('editor-scanner'),
      { ...commonOpts, language: 'javascript', placeholder: '// Pega tu código aquí...' }
    );

    // Editor Analyzer
    const editorAnalyzer = monaco.editor.create(
      document.getElementById('editor-analyzer'),
      { ...commonOpts, language: 'javascript' }
    );

    // Editor Deps
    const editorDeps = monaco.editor.create(
      document.getElementById('editor-deps'),
      { ...commonOpts, language: 'json' }
    );

    // Editor SAST
    const editorSAST = monaco.editor.create(
      document.getElementById('editor-sast'),
      { ...commonOpts, language: 'javascript' }
    );

    // Cambiar lenguaje según selector
    document.getElementById('lang-analyzer').addEventListener('change', e => {
      const lang = e.target.value === 'auto' ? 'javascript' : e.target.value;
      monaco.editor.setModelLanguage(editorAnalyzer.getModel(), lang);
    });

    // Inicializar módulos con los editores
    initScanner(editorScanner);
    initAnalyzer(editorAnalyzer);
    initDeps(editorDeps);
    initThreat();
    initSAST(editorSAST);
  });
}
