// js/threatmodel.js — Módulo 4: Threat Modeler STRIDE

import { callLLM, extractJSON } from './api.js';
import { showToast, showSkeleton, setButtonLoading, renderThreat, exportJSON } from './ui.js';
import { PROMPTS } from '../prompts/system.js';

export function initThreat() {
  const btn      = document.getElementById('btn-threat');
  const clearBtn = document.getElementById('clear-threat');
  const results  = document.getElementById('results-threat');
  const textarea = document.getElementById('editor-threat');

  let lastResult = null;

  // Habilitar botón cuando hay contenido
  textarea.addEventListener('input', () => {
    btn.disabled = textarea.value.trim().length < 20;
  });

  clearBtn.addEventListener('click', () => {
    textarea.value = '';
    results.innerHTML = `<div class="results-placeholder"><div class="placeholder-icon"><i class="fa-solid fa-network-wired"></i></div><p>Los resultados aparecerán aquí</p></div>`;
    lastResult = null;
    btn.disabled = true;
  });

  window.__exportThreat = () => {
    if (lastResult) exportJSON(lastResult, 'devguard-threatmodel.json');
  };

  btn.addEventListener('click', async () => {
    const description = textarea.value.trim();
    if (description.length < 20) {
      showToast('Describe tu sistema con más detalle (mínimo 20 caracteres)', 'error');
      return;
    }

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      let accumulated = '';

      const rawText = await callLLM(
        PROMPTS.threatModeler,
        `Generate a STRIDE threat model for this system:\n\n${description}`,
        (chunk, full) => {
          accumulated = full;
          results.innerHTML = `
            <div style="padding:20px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-code);line-height:1.6;word-break:break-all" class="stream-cursor">
              ${accumulated.slice(-500)}
            </div>`;
        },
        2500
      );

      const data = extractJSON(rawText);
      lastResult = data;
      renderThreat(data, results);
      showToast(
        `Threat model generado: ${data.threats?.length || 0} amenazas identificadas`,
        'info'
      );

    } catch (err) {
      results.innerHTML = `
        <div style="padding:20px;color:var(--accent-red)">
          <div style="font-weight:700;margin-bottom:8px">❌ Error al generar el modelo</div>
          <div style="font-size:.85rem">${err.message}</div>
        </div>`;
      showToast(err.message, 'error');
    } finally {
      setButtonLoading(btn, false);
    }
  });
}
