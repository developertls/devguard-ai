const translations = {
  en: {
    "api_config_btn": "⚙ API Config",
    "logout_btn": "🚪 Logout",
    "login_subtitle": "Restricted Access",
    "login_user": "Username",
    "login_pass": "Password",
    "login_btn": "Enter System",
    "hero_tag": "DevSecOps · AI Powered",
    "hero_title": "Analyze your code.<br /><span class=\"gradient-text\">Neutralize threats.</span>",
    "hero_sub": "Detect exposed secrets, OWASP vulnerabilities, insecure dependencies, and generate SAST rules automatically — all with AI, in seconds.",
    "tab_scanner": "<span class=\"tab-icon\"><i class=\"fa-solid fa-user-secret\"></i></span> Secret Scanner",
    "tab_analyzer": "<span class=\"tab-icon\"><i class=\"fa-solid fa-radiation\"></i></span> Vuln Analyzer",
    "tab_deps": "<span class=\"tab-icon\"><i class=\"fa-solid fa-link\"></i></span> Dependencies",
    "tab_threat": "<span class=\"tab-icon\"><i class=\"fa-solid fa-spider\"></i></span> Threat Model",
    "tab_sast": "<span class=\"tab-icon\"><i class=\"fa-solid fa-terminal\"></i></span> SAST Rules",
    "scan_title": "Secret Scanner",
    "scan_desc": "Detect API keys, tokens, passwords and hardcoded credentials in your code.",
    "drop_title": "Drop a file here",
    "drop_sub": "or paste your code below",
    "scan_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-user-secret\"></i></span> Analyze Secrets",
    "vuln_title": "Vulnerability Analyzer",
    "vuln_desc": "Detect SQLi, XSS, IDOR, SSRF, RCE and other OWASP Top 10 vulnerabilities with contextual reasoning.",
    "vuln_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-radiation\"></i></span> Analyze Vulnerabilities",
    "deps_title": "Dependency Checker",
    "deps_desc": "Analyze package.json, requirements.txt, pom.xml or go.mod for vulnerable dependencies.",
    "deps_drop": "Drop your dependencies file",
    "deps_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-link\"></i></span> Analyze Dependencies",
    "threat_title": "Threat Modeler",
    "threat_desc": "Describe your system architecture and generate a STRIDE threat model with attack vectors and mitigations.",
    "threat_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-spider\"></i></span> Generate Threat Model",
    "sast_title": "SAST Rule Generator",
    "sast_desc": "Describe a vulnerability and generate a Semgrep rule ready for your CI/CD pipeline.",
    "sast_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-terminal\"></i></span> Generate Semgrep Rule",
    "btn_clear": "Clear",
    "results_placeholder": "Results will appear here"
  },
  es: {
    "api_config_btn": "⚙ Configurar API",
    "logout_btn": "🚪 Salir",
    "login_subtitle": "Acceso Restringido",
    "login_user": "Usuario",
    "login_pass": "Contraseña",
    "login_btn": "Ingresar al Sistema",
    "hero_tag": "Seguridad en Desarrollo · IA Powered",
    "hero_title": "Analiza tu código.<br /><span class=\"gradient-text\">Neutraliza las amenazas.</span>",
    "hero_sub": "Detecta secretos expuestos, vulnerabilidades OWASP, dependencias inseguras y genera reglas SAST automáticamente — todo con IA, en segundos.",
    "tab_scanner": "<span class=\"tab-icon\"><i class=\"fa-solid fa-user-secret\"></i></span> Secret Scanner",
    "tab_analyzer": "<span class=\"tab-icon\"><i class=\"fa-solid fa-radiation\"></i></span> Vuln Analyzer",
    "tab_deps": "<span class=\"tab-icon\"><i class=\"fa-solid fa-link\"></i></span> Dependencies",
    "tab_threat": "<span class=\"tab-icon\"><i class=\"fa-solid fa-spider\"></i></span> Threat Model",
    "tab_sast": "<span class=\"tab-icon\"><i class=\"fa-solid fa-terminal\"></i></span> SAST Rules",
    "scan_title": "Secret Scanner",
    "scan_desc": "Detecta API keys, tokens, passwords y credenciales hardcoded en tu código.",
    "drop_title": "Arrastra un archivo aquí",
    "drop_sub": "o pega tu código abajo",
    "scan_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-user-secret\"></i></span> Analizar Secretos",
    "vuln_title": "Vulnerability Analyzer",
    "vuln_desc": "Detecta SQLi, XSS, IDOR, SSRF, RCE y otras vulnerabilidades OWASP Top 10 con razonamiento contextual.",
    "vuln_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-radiation\"></i></span> Analizar Vulnerabilidades",
    "deps_title": "Dependency Checker",
    "deps_desc": "Analiza package.json, requirements.txt, pom.xml o go.mod en busca de dependencias vulnerables.",
    "deps_drop": "Arrastra tu archivo de dependencias",
    "deps_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-link\"></i></span> Analizar Dependencias",
    "threat_title": "Threat Modeler",
    "threat_desc": "Describe tu sistema o arquitectura y genera un modelo de amenazas STRIDE con vectores de ataque y controles recomendados.",
    "threat_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-spider\"></i></span> Generar Threat Model",
    "sast_title": "SAST Rule Generator",
    "sast_desc": "Describe una vulnerabilidad y genera una regla Semgrep lista para tu pipeline CI/CD.",
    "sast_btn": "<span class=\"btn-icon\"><i class=\"fa-solid fa-terminal\"></i></span> Generar Regla Semgrep",
    "btn_clear": "Limpiar",
    "results_placeholder": "Los resultados aparecerán aquí"
  }
};

function applyLanguage(lang) {
  const dict = translations[lang];
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      if (el.tagName === 'INPUT' && el.hasAttribute('placeholder')) {
        el.placeholder = dict[key];
      } else {
        el.innerHTML = dict[key]; 
      }
    }
  });

  document.querySelectorAll('.btn-clear').forEach(el => {
    el.textContent = dict['btn_clear'];
  });
  document.querySelectorAll('.results-placeholder p').forEach(el => {
    el.textContent = dict['results_placeholder'];
  });
  
  const btnEn = document.getElementById('langEn');
  const btnEs = document.getElementById('langEs');
  if(btnEn && btnEs) {
      btnEn.style.opacity = lang === 'en' ? '1' : '0.4';
      btnEs.style.opacity = lang === 'es' ? '1' : '0.4';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const btnEn = document.getElementById('langEn');
  const btnEs = document.getElementById('langEs');
  
  if (btnEn) btnEn.addEventListener('click', () => applyLanguage('en'));
  if (btnEs) btnEs.addEventListener('click', () => applyLanguage('es'));

  // Default to English
  applyLanguage('en');
});
