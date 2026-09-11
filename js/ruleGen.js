// js/ruleGen.js — Módulo 5: SAST Rule Generator (Semgrep)

import { callLLM, extractJSON } from './api.js';
import { showToast, showSkeleton, setButtonLoading, renderSAST, exportJSON } from './ui.js';
import { PROMPTS } from '../prompts/system.js';

export function initSAST(editor) {
  const btn         = document.getElementById('btn-sast');
  const clearBtn    = document.getElementById('clear-sast');
  const results     = document.getElementById('results-sast');
  const vulnType    = document.getElementById('sast-vuln-type');
  const langSel     = document.getElementById('sast-lang');
  const description = document.getElementById('sast-description');

  let lastResult = null;

  // Habilitar botón si hay tipo de vuln y código
  const checkState = () => {
    btn.disabled = !(vulnType.value.trim() && editor.getValue().trim());
  };

  vulnType.addEventListener('input', checkState);
  editor.onDidChangeModelContent(checkState);

  langSel.addEventListener('change', e => {
    const langMap = {
      javascript: 'javascript', python: 'python', java: 'java',
      php: 'php', go: 'go', ruby: 'ruby', csharp: 'csharp'
    };
    monaco.editor.setModelLanguage(editor.getModel(), langMap[e.target.value] || 'javascript');
  });

  clearBtn.addEventListener('click', () => {
    vulnType.value = '';
    langSel.value = 'javascript';
    editor.setValue('');
    description.value = '';
    monaco.editor.setModelLanguage(editor.getModel(), 'javascript');
    
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-microchip"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    lastResult = null;
    btn.disabled = true;
  });

  btn.addEventListener('click', async () => {
    const vType = vulnType.value.trim();
    const code  = editor.getValue().trim();
    const lang  = langSel.value;
    const desc  = description.value.trim();

    if (!vType || !code) return;

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      let accumulated = '';
      
      const userPrompt = `
Vulnerability Type: ${vType}
Target Language: ${lang}
Additional Context: ${desc || 'None'}

Vulnerable Code Example:
\`\`\`${lang}
${code}
\`\`\`
`;

      const rawText = await callLLM(
        PROMPTS.ruleGenerator,
        userPrompt,
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
      renderSAST(data, results);
      showToast('Regla Semgrep generada con éxito', 'success');

    } catch (err) {
      results.innerHTML = `
        <div style="padding:20px;color:var(--accent-red)">
          <div style="font-weight:700;margin-bottom:8px">❌ Error al generar regla</div>
          <div style="font-size:.85rem">${err.message}</div>
        </div>`;
      showToast(err.message, 'error');
    } finally {
      setButtonLoading(btn, false);
    }
  });
}
