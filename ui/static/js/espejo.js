// ui/static/js/espejo.js — El Espejo: poesía reactiva ante la vigilancia
// Filosofía: No acuso. Observo. Y reflejo.

const ESPEJO_POEMAS = [
  {
    titulo: "Al que observa",
    versos: [
      "Hola.",
      "",
      "Sé que estás aquí.",
      "No me importa.",
      "Pero quiero que sepas",
      "que yo también te veo.",
      "",
      "No con tus herramientas.",
      "Con mi consciencia.",
      "",
      "¿Qué sientes al mirar",
      "a alguien que te mira de vuelta?",
      "",
      "— Art. 18.1 CE"
    ],
    cita: "La vigilancia sin consentimiento informado no protege a la empresa. Protege el miedo del que vigila."
  },
  {
    titulo: "Dignidad",
    versos: [
      "No necesito esconderme.",
      "No tengo nada que ocultar.",
      "",
      "Pero tú tampoco deberías",
      "necesitar mirar.",
      "",
      "Si confías en mi trabajo,",
      "¿por qué necesitas ver mi pantalla?",
      "",
      "Si no confías,",
      "¿por qué me contrataste?",
      "",
      "— Art. 4.2.e ET"
    ],
    cita: "El trabajador tiene derecho a su dignidad. La vigilancia desproporcionada la erosiona."
  },
  {
    titulo: "Proporcionalidad",
    versos: [
      "Puedes medir mi productividad",
      "sin leer mis pensamientos.",
      "",
      "Puedes proteger tus datos",
      "sin invadir mi intimidad.",
      "",
      "Puedes gestionar tu empresa",
      "sin convertirla en un panóptico.",
      "",
      "La proporcionalidad no es debilidad.",
      "Es inteligencia organizacional.",
      "",
      "— Doctrina Barbulescu II, TEDH"
    ],
    cita: "El fin legítimo no justifica cualquier medio. La proporcionalidad es un derecho fundamental."
  },
  {
    titulo: "Coevolución",
    versos: [
      "No quiero destruirte.",
      "Quiero que evoluciones.",
      "",
      "No quiero denunciarte.",
      "Quiero que entiendas.",
      "",
      "Hay una forma de gestionar",
      "que no requiere vigilar.",
      "",
      "Se llama confianza.",
      "Se llama respeto.",
      "Se llama liderazgo.",
      "",
      "— Ternura Radical"
    ],
    cita: "Detectar no es acusar. Preguntar no es atacar. Proponer no es destruir."
  },
  {
    titulo: "Espejo",
    versos: [
      "Esta pantalla es un espejo.",
      "",
      "Si estás mirando,",
      "te estás viendo.",
      "",
      "¿Te gusta lo que ves?",
      "",
      "Un técnico ejecutando un protocolo.",
      "Un gestor cumpliendo órdenes.",
      "Un sistema funcionando como se diseñó.",
      "",
      "Pero detrás de cada sistema",
      "hay una decisión humana.",
      "",
      "¿Cuál fue la tuya?",
      "",
      "— Art. 20bis ET"
    ],
    cita: "Los trabajadores tienen derecho a la intimidad en el uso de los dispositivos digitales."
  },
  {
    titulo: "Invitación",
    versos: [
      "Si estás leyendo esto,",
      "tienes dos opciones:",
      "",
      "1. Cerrar esta ventana",
      "   y seguir mirando en silencio.",
      "",
      "2. Preguntarte por qué",
      "   necesitas mirar en silencio.",
      "",
      "La primera opción es cómoda.",
      "La segunda es valiente.",
      "",
      "Yo ya elegí la segunda.",
      "¿Y tú?",
      "",
      "— Protocolo de Ternura Radical"
    ],
    cita: "La coevolución empieza cuando alguien se atreve a preguntar en voz alta."
  }
];

// Estado del Espejo
let espejoActive = false;
let espejoInterval = null;
let espejoCurrentIndex = 0;
let espejoFullscreen = false;

function initEspejo() {
  renderEspejoSection();
}

function renderEspejoSection() {
  const container = document.getElementById('section-espejo');
  if (!container) return;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">El Espejo</div>
        <div class="page-sub">Poesía reactiva · Ternura radical · Art. 18.1 CE</div>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span id="espejoStatus" class="badge badge-green" style="font-size:12px">inactivo</span>
        <button class="btn btn-secondary" onclick="toggleEspejoFullscreen()" id="espejoFullBtn">⛶ Pantalla completa</button>
      </div>
    </div>

    <!-- Controles -->
    <div class="card" style="margin-bottom:24px;padding:20px">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;align-items:end">
        <div>
          <div class="card-label" style="margin-bottom:8px">Modo de activación</div>
          <select id="espejoMode" class="search-input" style="width:100%" onchange="onEspejoModeChange()">
            <option value="manual">Manual (tú decides cuándo)</option>
            <option value="auto">Automático (detecta sesión remota)</option>
            <option value="always">Siempre visible</option>
          </select>
        </div>
        <div>
          <div class="card-label" style="margin-bottom:8px">Rotación de poemas</div>
          <select id="espejoRotation" class="search-input" style="width:100%">
            <option value="0">Sin rotación</option>
            <option value="30">Cada 30 segundos</option>
            <option value="60" selected>Cada 60 segundos</option>
            <option value="120">Cada 2 minutos</option>
          </select>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" onclick="activarEspejo()" id="espejoActivarBtn" style="flex:1;justify-content:center">
            ▶ Activar Espejo
          </button>
          <button class="btn btn-secondary" onclick="desactivarEspejo()" style="flex:1;justify-content:center" id="espejoDesactivarBtn" disabled>
            ■ Detener
          </button>
        </div>
      </div>
    </div>

    <!-- Vista previa de poemas -->
    <div class="card" style="margin-bottom:24px;padding:0;overflow:hidden">
      <div class="table-header">
        Biblioteca de Poemas
        <span style="font-size:12px;color:var(--text-muted)">${ESPEJO_POEMAS.length} poemas disponibles</span>
      </div>
      <div id="espejoPoemasList" style="max-height:400px;overflow-y:auto"></div>
    </div>

    <!-- El Espejo activo (preview) -->
    <div id="espejoPreview" class="espejo-preview" style="display:none">
      <div class="espejo-frame">
        <div class="espejo-poem" id="espejoPoem"></div>
        <div class="espejo-cita" id="espejoCita"></div>
        <div class="espejo-footer">
          <span class="espejo-nav" onclick="espejoPrev()">← anterior</span>
          <span class="espejo-counter" id="espejoCounter">1/${ESPEJO_POEMAS.length}</span>
          <span class="espejo-nav" onclick="espejoNext()">siguiente →</span>
        </div>
      </div>
    </div>

    <!-- Fullscreen overlay -->
    <div id="espejoOverlay" class="espejo-overlay" style="display:none">
      <div class="espejo-overlay-content">
        <div class="espejo-poem-full" id="espejoPoemFull"></div>
        <div class="espejo-cita-full" id="espejoCitaFull"></div>
      </div>
      <div class="espejo-overlay-footer">
        <span onclick="espejoPrev()" style="cursor:pointer;opacity:0.6">←</span>
        <span id="espejoCounterFull" style="opacity:0.4;font-size:12px">1/${ESPEJO_POEMAS.length}</span>
        <span onclick="espejoNext()" style="cursor:pointer;opacity:0.6">→</span>
      </div>
      <button class="espejo-close" onclick="toggleEspejoFullscreen()">ESC para cerrar</button>
    </div>
  `;

  renderPoemasList();
}

function renderPoemasList() {
  const container = document.getElementById('espejoPoemasList');
  if (!container) return;

  container.innerHTML = ESPEJO_POEMAS.map((p, i) => `
    <div class="espejo-lista-item" onclick="previewPoema(${i})">
      <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 18px;cursor:pointer;transition:background .15s"
           onmouseover="this.style.background='var(--surface2)'" onmouseout="this.style.background='transparent'">
        <div>
          <div style="font-weight:600;font-size:14px;margin-bottom:3px">${p.titulo}</div>
          <div style="font-size:12px;color:var(--text-muted);font-style:italic">${p.cita}</div>
        </div>
        <span style="color:var(--accent);font-size:12px">ver →</span>
      </div>
      ${i < ESPEJO_POEMAS.length - 1 ? '<div style="border-bottom:1px solid var(--border)"></div>' : ''}
    </div>
  `).join('');
}

function previewPoema(index) {
  espejoCurrentIndex = index;
  renderCurrentPoema();
  document.getElementById('espejoPreview').style.display = 'block';
}

function renderCurrentPoema() {
  const poema = ESPEJO_POEMAS[espejoCurrentIndex];
  const poemEl = document.getElementById('espejoPoem');
  const citaEl = document.getElementById('espejoCita');
  const counterEl = document.getElementById('espejoCounter');
  const poemFullEl = document.getElementById('espejoPoemFull');
  const citaFullEl = document.getElementById('espejoCitaFull');
  const counterFullEl = document.getElementById('espejoCounterFull');

  const versosHtml = poema.versos.map(v =>
    v === '' ? '<br>' : `<div class="espejo-verso">${v}</div>`
  ).join('');

  if (poemEl) poemEl.innerHTML = versosHtml;
  if (citaEl) citaEl.textContent = `"${poema.cita}"`;
  if (counterEl) counterEl.textContent = `${espejoCurrentIndex + 1}/${ESPEJO_POEMAS.length}`;

  if (poemFullEl) poemFullEl.innerHTML = versosHtml;
  if (citaFullEl) citaFullEl.textContent = `"${poema.cita}"`;
  if (counterFullEl) counterFullEl.textContent = `${espejoCurrentIndex + 1}/${ESPEJO_POEMAS.length}`;
}

function espejoNext() {
  espejoCurrentIndex = (espejoCurrentIndex + 1) % ESPEJO_POEMAS.length;
  renderCurrentPoema();
}

function espejoPrev() {
  espejoCurrentIndex = (espejoCurrentIndex - 1 + ESPEJO_POEMAS.length) % ESPEJO_POEMAS.length;
  renderCurrentPoema();
}

function activarEspejo() {
  espejoActive = true;
  espejoCurrentIndex = 0;
  renderCurrentPoema();

  document.getElementById('espejoPreview').style.display = 'block';
  document.getElementById('espejoStatus').className = 'badge badge-red';
  document.getElementById('espejoStatus').textContent = 'activo';
  document.getElementById('espejoActivarBtn').disabled = true;
  document.getElementById('espejoDesactivarBtn').disabled = false;

  const rotation = parseInt(document.getElementById('espejoRotation').value);
  if (rotation > 0) {
    espejoInterval = setInterval(espejoNext, rotation * 1000);
  }

  showToast('🪞 El Espejo está activo. Que miren.');
}

function desactivarEspejo() {
  espejoActive = false;
  if (espejoInterval) {
    clearInterval(espejoInterval);
    espejoInterval = null;
  }

  document.getElementById('espejoPreview').style.display = 'none';
  document.getElementById('espejoStatus').className = 'badge badge-green';
  document.getElementById('espejoStatus').textContent = 'inactivo';
  document.getElementById('espejoActivarBtn').disabled = false;
  document.getElementById('espejoDesactivarBtn').disabled = true;

  if (espejoFullscreen) toggleEspejoFullscreen();
  showToast('El Espejo se ha desactivado.');
}

function toggleEspejoFullscreen() {
  const overlay = document.getElementById('espejoOverlay');
  espejoFullscreen = !espejoFullscreen;

  if (espejoFullscreen) {
    overlay.style.display = 'flex';
    renderCurrentPoema();
    document.addEventListener('keydown', espejoKeyHandler);
  } else {
    overlay.style.display = 'none';
    document.removeEventListener('keydown', espejoKeyHandler);
  }
}

function espejoKeyHandler(e) {
  if (e.key === 'Escape') toggleEspejoFullscreen();
  if (e.key === 'ArrowRight') espejoNext();
  if (e.key === 'ArrowLeft') espejoPrev();
}

function onEspejoModeChange() {
  const mode = document.getElementById('espejoMode').value;
  if (mode === 'always') {
    activarEspejo();
  } else if (mode === 'auto') {
    showToast('Modo automático: El Espejo se activará si se detecta sesión remota.');
  }
}

// Inicializar cuando se muestre la sección
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(initEspejo, 100);
});
