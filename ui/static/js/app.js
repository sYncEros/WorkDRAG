// ui/static/js/app.js — entry point
let currentReport = null;
let currentFilename = null;
let pollInterval = null;

async function init() {
  const reports = await API.reports();
  const list = document.getElementById('reportList');
  list.innerHTML = '';

  if (!reports.length) {
    document.getElementById('emptyState').style.display = 'block';
    return;
  }

  reports.forEach((r, i) => {
    const btn = document.createElement('button');
    btn.className = 'report-item' + (i === 0 ? ' active' : '');
    btn.textContent = r.replace('audit_', '').replace('.json', '');
    btn.onclick = () => {
      document.querySelectorAll('.report-item')
        .forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      loadReport(r);
    };
    list.appendChild(btn);
  });

  loadReport(reports[0]);

  // Rellenar selectores de comparación
  const selA = document.getElementById('compareA');
  const selB = document.getElementById('compareB');
  if (selA && selB) {
    [selA, selB].forEach(sel => {
      sel.innerHTML = reports.map(r =>
        `<option value="${r}">${r.replace('audit_','').replace('.json','')}</option>`
      ).join('');
    });
    if (reports.length > 1) selB.selectedIndex = 1;
  }
}

async function loadReport(filename) {
  currentFilename = filename;
  currentReport = await API.report(filename);

  document.getElementById('emptyState').style.display = 'none';

  renderDashboard(currentReport, filename);
  renderFindings(currentReport.findings || []);
  renderLegal(currentReport.findings || []);
}

async function runAudit() {
  const btn = document.getElementById('runBtn');
  btn.innerHTML = '<span class="spinner"></span> Ejecutando...';
  btn.disabled = true;

  const recommendationMode =
    document.getElementById('recommendationMode')?.value || 'completo';
  const customCategoriesText =
    document.getElementById('customCategories')?.value || '';
  const customRisksText =
    document.getElementById('customRisks')?.value || '';
  const runSkillsText =
    document.getElementById('runSkills')?.value || '';

  const recommendation_categories = customCategoriesText
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  const recommendation_risks = customRisksText
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  const skills = runSkillsText
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  const payload = {
    recommendation_mode: recommendationMode,
  };

  if (skills.length) payload.skills = skills;
  if (recommendationMode === 'personalizado') {
    payload.recommendation_categories = recommendation_categories;
    payload.recommendation_risks = recommendation_risks;
  }

  showToast('Auditoría iniciada...');
  await API.runAudit(payload);
  startPolling(btn);
}

function onRecommendationModeChanged() {
  const mode = document.getElementById('recommendationMode')?.value || 'completo';
  const showCustom = mode === 'personalizado';
  const categories = document.getElementById('customCategories');
  const risks = document.getElementById('customRisks');
  if (categories) categories.style.display = showCustom ? 'block' : 'none';
  if (risks) risks.style.display = showCustom ? 'block' : 'none';
}

function startPolling(btn) {
  pollInterval = setInterval(async () => {
    const res = await fetch('/api/status');
    const { running } = await res.json();
    if (!running) {
      clearInterval(pollInterval);
      pollInterval = null;
      btn.innerHTML = '▶ Nueva Auditoría';
      btn.disabled = false;
      showToast('✅ Auditoría completada');
      await init();
    }
  }, 3000);
}

function downloadJson() {
  if (currentFilename) window.open(API.downloadUrl(currentFilename));
}

function downloadPdf() {
  if (currentFilename) {
    window.open(API.downloadUrl(currentFilename.replace('.json', '.pdf')));
  }
}

// ── Comparación de auditorías ────────────────────────────────────

async function runCompare() {
  const fileA = document.getElementById('compareA').value;
  const fileB = document.getElementById('compareB').value;
  const result = document.getElementById('compareResult');

  if (!fileA || !fileB) { showToast('Selecciona dos informes'); return; }
  if (fileA === fileB)   { showToast('Selecciona informes distintos'); return; }

  result.innerHTML = '<div style="color:var(--text-muted);padding:20px">Comparando...</div>';

  const data = await API.compare(fileA, fileB);
  if (data.error) {
    result.innerHTML = `<div class="empty">${data.error}</div>`;
    return;
  }

  result.innerHTML = `
    <div class="compare-summary">
      <div class="compare-stat">
        <div class="compare-stat-value" style="color:#f87171">${data.summary.new_findings}</div>
        <div class="compare-stat-label">Nuevos hallazgos</div>
      </div>
      <div class="compare-stat">
        <div class="compare-stat-value" style="color:#4ade80">${data.summary.resolved_findings}</div>
        <div class="compare-stat-label">Resueltos</div>
      </div>
      <div class="compare-stat">
        <div class="compare-stat-value" style="color:#fb923c">${data.summary.risk_increased}</div>
        <div class="compare-stat-label">Riesgo aumentó</div>
      </div>
      <div class="compare-stat">
        <div class="compare-stat-value" style="color:#60a5fa">${data.summary.risk_decreased}</div>
        <div class="compare-stat-label">Riesgo mejoró</div>
      </div>
    </div>

    ${data.new_in_b.length ? `
    <div class="compare-section">
      <div class="compare-section-title">🆕 Nuevos en ${fileB.replace('audit_','').replace('.json','')}</div>
      ${data.new_in_b.map(f => `
        <div class="compare-item new">
          <span>${f.title}</span>
          ${badge(f.risk_level)}
        </div>
      `).join('')}
    </div>` : ''}

    ${data.resolved_in_b.length ? `
    <div class="compare-section">
      <div class="compare-section-title">✅ Resueltos (ya no aparecen)</div>
      ${data.resolved_in_b.map(f => `
        <div class="compare-item resolved">
          <span>${f.title}</span>
          ${badge(f.risk_level)}
        </div>
      `).join('')}
    </div>` : ''}

    ${data.common.filter(c => c.risk_changed).length ? `
    <div class="compare-section">
      <div class="compare-section-title">📈 Cambios de nivel de riesgo</div>
      ${data.common.filter(c => c.risk_changed).map(c => `
        <div class="compare-item changed">
          <span>${c.title}</span>
          <span style="display:flex;align-items:center;gap:8px">
            ${badge(c.risk_a)}
            <span style="color:var(--text-muted)">→</span>
            ${badge(c.risk_b)}
          </span>
        </div>
      `).join('')}
    </div>` : ''}

    ${!data.new_in_b.length && !data.resolved_in_b.length &&
      !data.common.filter(c => c.risk_changed).length ? `
      <div class="empty" style="padding:40px">
        <div class="empty-title">Sin diferencias significativas</div>
        <p>Los dos informes presentan los mismos hallazgos y niveles de riesgo</p>
      </div>` : ''}
  `;
}

init();
