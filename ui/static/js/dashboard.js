// ui/static/js/dashboard.js
const RISK_LABELS = {
  green:  'Verde — Seguridad estándar',
  yellow: 'Amarillo — Telemetría relevante',
  orange: 'Naranja — Potencialmente intrusivo',
  red:    'Rojo — Altamente invasivo'
};

const RISK_FILLS = {
  green: '#2d9e6b', yellow: '#d4a017',
  orange: '#f06406', red: '#b31c1c'
};

const RISK_ORDER = ['green', 'yellow', 'orange', 'red'];

const SKILL_ICONS = {
  mdm_audit:              '🏢',
  surveillance_audit:     '👁️',
  persistence_audit:      '🔒',
  network_monitor:        '🌐',
  activity_monitor:       '📊',
  privacy_audit:          '🛡️',
  ai_telemetry_audit:     '🤖',
  cloud_sync_audit:       '☁️',
  browser_audit:          '🌍',
  hardening_audit:        '🔐',
  identity_audit:         '🪪',
  git_identity_audit:     '🔑',
  scheduled_tasks_audit:  '⏱️',
  usb_audit:              '🔌',
  email_audit:            '📧',
  third_party_apps_audit: '📦',
  user_behavior_audit:    '👤',
  data_exfiltration_audit:'📤',
  incident_response:      '🚨',
  event_viewer:           '🧾',
  rdp_log_exporter:       '🔓',
};

const SKILL_LABELS = {
  mdm_audit:              'MDM',
  surveillance_audit:     'Vigilancia',
  persistence_audit:      'Persistencia',
  network_monitor:        'Red',
  activity_monitor:       'Actividad',
  privacy_audit:          'Privacidad',
  ai_telemetry_audit:     'AI / Telemetría',
  cloud_sync_audit:       'Cloud Sync',
  browser_audit:          'Navegador',
  hardening_audit:        'Hardening',
  identity_audit:         'Identidad',
  git_identity_audit:     'Git Identity',
  scheduled_tasks_audit:  'Tareas Prog.',
  usb_audit:              'USB',
  email_audit:            'Email',
  third_party_apps_audit: 'Apps 3rd Party',
  user_behavior_audit:    'Comportamiento',
  data_exfiltration_audit:'Exfiltración',
  incident_response:      'IR Playbook',
  event_viewer:           'Event Viewer',
  rdp_log_exporter:       'RDP Logs',
};

let _donutChart = null;

function renderDashboard(report, filename) {
  const findings = report.findings || [];

  document.getElementById('reportName').textContent =
    filename.replace('audit_', '').replace('.json', '');
  document.getElementById('reportDate').textContent =
    'Generado: ' + (report.generated_at || '—').substring(0, 19).replace('T', ' ');
  document.getElementById('maxRisk').innerHTML = badge(report.max_risk);
  document.getElementById('totalFindings').textContent = report.total_findings || 0;
  document.getElementById('findingCount').textContent = `${findings.length} hallazgos`;

  renderSkillSummary(findings);
  renderRiskBars(findings);
  renderRiskDonut(findings);
  renderSummaryTable(findings);
}

// ── Donut de riesgo ──────────────────────────────────────────────

function renderRiskDonut(findings) {
  const counts = Object.fromEntries(RISK_ORDER.map(r => [r, 0]));
  findings.forEach(f => { if (counts[f.risk_level] !== undefined) counts[f.risk_level]++; });

  const labels = RISK_ORDER.filter(r => counts[r] > 0);
  const data   = labels.map(r => counts[r]);
  const colors = labels.map(r => RISK_FILLS[r]);

  const canvas = document.getElementById('riskDonut');
  if (!canvas) return;

  if (_donutChart) { _donutChart.destroy(); _donutChart = null; }

  if (findings.length === 0) {
    canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
    return;
  }

  _donutChart = new Chart(canvas, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      cutout: '68%',
      plugins: { legend: { display: false }, tooltip: {
        callbacks: {
          label: ctx => ` ${ctx.label}: ${ctx.raw} hallazgos`
        }
      }},
      animation: { duration: 500 },
    }
  });

  // Leyenda manual
  document.getElementById('donutLegend').innerHTML = labels.map((r, i) => `
    <div class="donut-legend-item">
      <div class="donut-dot" style="background:${colors[i]}"></div>
      <span style="color:var(--text-muted)">${r}</span>
      <span style="margin-left:auto;font-weight:600">${data[i]}</span>
    </div>
  `).join('');
}

// ── Barras de riesgo ─────────────────────────────────────────────

function renderRiskBars(findings) {
  const counts = Object.fromEntries(RISK_ORDER.map(r => [r, 0]));
  findings.forEach(f => { if (counts[f.risk_level] !== undefined) counts[f.risk_level]++; });
  const max = Math.max(...Object.values(counts), 1);

  document.getElementById('riskBars').innerHTML = `
    <div class="table-wrap" style="padding:20px;height:100%">
      <div style="font-size:13px;font-weight:600;margin-bottom:16px">Distribución de Riesgo</div>
      ${RISK_ORDER.filter(l => counts[l] > 0).map(level => `
        <div style="margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:5px">
            <span style="color:var(--text-muted)">${RISK_LABELS[level]}</span>
            <span style="font-weight:600">${counts[level]}</span>
          </div>
          <div class="risk-bar">
            <div class="risk-fill"
              style="width:${(counts[level]/max)*100}%;background:${RISK_FILLS[level]}">
            </div>
          </div>
        </div>
      `).join('')}
    </div>`;
}

// ── Tabla resumen ────────────────────────────────────────────────

function renderSummaryTable(findings) {
  document.getElementById('summaryTable').innerHTML = findings.map(f => `
    <tr onclick="goToFinding('${f.title.replace(/'/g,"\\'")}')" style="cursor:pointer">
      <td>
        <span style="margin-right:6px">${SKILL_ICONS[f.skill] || '🔍'}</span>
        <span class="td-skill">${(SKILL_LABELS[f.skill] || f.skill).replace(/_/g,' ')}</span>
      </td>
      <td>${f.title}</td>
      <td style="color:var(--text-muted);font-size:12px">
        ${f.category.replace(/_/g,' ')}
      </td>
      <td>${badge(f.risk_level)}</td>
    </tr>
  `).join('');
}

// ── Cards por skill ──────────────────────────────────────────────

function renderSkillSummary(findings) {
  const bySkill = {};
  findings.forEach(f => {
    if (!bySkill[f.skill]) bySkill[f.skill] = { findings: [], maxRisk: 'green' };
    bySkill[f.skill].findings.push(f);
    if (RISK_ORDER.indexOf(f.risk_level) > RISK_ORDER.indexOf(bySkill[f.skill].maxRisk)) {
      bySkill[f.skill].maxRisk = f.risk_level;
    }
  });

  const el = document.getElementById('skillSummary');
  if (!el) return;

  el.innerHTML = Object.entries(bySkill).map(([skill, data]) => `
    <div class="card" style="cursor:pointer;transition:transform .15s;padding:14px"
      onmouseover="this.style.transform='translateY(-2px)'"
      onmouseout="this.style.transform=''"
      onclick="filterBySkill('${skill}')">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div style="display:flex;align-items:center;gap:10px">
          <span style="font-size:20px">${SKILL_ICONS[skill] || '🔍'}</span>
          <div>
            <div class="card-label" style="margin-bottom:2px">
              ${SKILL_LABELS[skill] || skill}
            </div>
            <div style="font-size:18px;font-weight:700;line-height:1">
              ${data.findings.length}
              <span style="font-size:11px;font-weight:400;
                color:var(--text-muted)">hallazgos</span>
            </div>
          </div>
        </div>
        ${badge(data.maxRisk)}
      </div>
    </div>
  `).join('');
}

// ── Filtrar por skill ────────────────────────────────────────────

function filterBySkill(skill) {
  const btn = document.querySelector('.nav-btn[data-section="findings"]');
  showSection('findings', btn);
  setTimeout(() => {
    document.getElementById('findingsSearch').value = skill.replace(/_/g,' ');
    filterFindings(skill.replace(/_/g,' '));
  }, 100);
}
