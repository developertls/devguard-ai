// js/api.js — Módulo de comunicación con djc-auto vía llm.retoia.app
// Maneja streaming, errores y presupuesto de tokens

const CONFIG_KEY = 'devguard_config';

export function getConfig() {
  try {
    const config = JSON.parse(localStorage.getItem(CONFIG_KEY) || '{}');
    if (!config.apiKey) config.apiKey = 'sk-MWLwKIvzlsaTZdx6Ltlhrw';
    if (!config.baseUrl) config.baseUrl = 'https://llm.retoia.app/v1';
    return config;
  } catch {
    return {
      apiKey: 'sk-MWLwKIvzlsaTZdx6Ltlhrw',
      baseUrl: 'https://llm.retoia.app/v1'
    };
  }
}

export function saveConfig(apiKey, baseUrl) {
  localStorage.setItem(CONFIG_KEY, JSON.stringify({ apiKey, baseUrl }));
}

/**
 * Llama a djc-auto con streaming habilitado.
 * @param {string} systemPrompt - System prompt optimizado
 * @param {string} userContent  - Contenido del usuario
 * @param {function} onChunk   - Callback por cada chunk de texto recibido
 * @param {number} maxTokens   - Mínimo 500 (requerimiento del reto)
 * @returns {Promise<string>}  - Texto completo acumulado
 */
export async function callLLM(systemPrompt, userContent, onChunk = null, maxTokens = 2000) {
  const { apiKey, baseUrl } = getConfig();

  if (!apiKey) throw new Error('API Key no configurada. Haz clic en "Configurar API".');

  const url = `${baseUrl}/chat/completions`;

  const body = JSON.stringify({
    model: 'djc-auto',
    stream: true,                    // SIEMPRE streaming (requerimiento crítico)
    max_tokens: Math.max(500, maxTokens), // MÍNIMO 500 (requerimiento crítico)
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user',   content: userContent  }
    ]
  });

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type':  'application/json'
    },
    body
  });

  if (!response.ok) {
    const errText = await response.text().catch(() => response.statusText);
    throw new Error(`API Error ${response.status}: ${errText}`);
  }

  // Leer stream SSE
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
      } catch {
        // Ignorar líneas malformadas del stream
      }
    }
  }

  return fullText;
}

/**
 * Extrae el JSON de la respuesta del modelo (que puede venir con texto extra)
 */
export function extractJSON(text) {
  // Intentar parseo directo
  try { return JSON.parse(text.trim()); } catch {}

  // Extraer bloque JSON entre { }
  const match = text.match(/\{[\s\S]*\}/);
  if (match) {
    try { return JSON.parse(match[0]); } catch {}
  }

  throw new Error('No se pudo parsear la respuesta JSON del modelo.');
}

/**
 * Verifica la conexión con la API
 */
export async function testConnection(apiKey, baseUrl) {
  const url = `${baseUrl}/chat/completions`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type':  'application/json'
    },
    body: JSON.stringify({
      model: 'djc-auto',
      max_tokens: 500,
      stream: false,
      messages: [{ role: 'user', content: 'ping' }]
    })
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return true;
}
