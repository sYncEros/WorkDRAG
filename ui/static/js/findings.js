// ui/static/js/findings.js

function renderFindings(findings) {
  const container = document.getElementById('findingsDetail');

  if (!findings.length) {
    container.innerHTML = `
      <div class="empty">
        <div class="empty-title">Sin hallazgos</div>
      </div>`;
    return;
  }

  container.innerHTML = findings.map((f, i) => {
    const isAccountProfile = f.category === 'identity_suspicious_account';
    const isAccountSummary = f.category === 'identity_account_profiles';
    return `
      <div class="finding-card" id="finding-${i}">
        <div class="finding-header" onclick="toggleFinding(${i})">
          <div>
            <div class="finding-title">
              ${isAccountProfile ? '👤 ' : ''}${f.title}
            </div>
            <div class="finding-meta">
              ${f.skill} · ${f.category} · ${(f.timestamp||'').substring(0,16)}
            </div>
          </div>
          ${badge(f.risk_level)}
        </div>
        <div class="finding-body" id="fb-${i}">
          ${isAccountProfile
            ? renderAccountCard(f)
            : isAccountSummary
              ? renderAccountSummary(f)
              : renderStandardFinding(f)
          }
        </div>
      </div>
    `;
  }).join('');
}

function renderStandardFinding(f) {
  return `
    ${field('¿Qué es?', f.what_it_is || f.description)}
    ${field('¿Qué NO implica?', f.what_it_is_not, 'not')}
    ${field('Riesgo técnico', f.technical_risk)}
    ${field('Riesgo jurídico', f.legal_risk)}
    ${rawDataBlock(f)}
  `;
}

function renderAccountCard(f) {
  const raw = f.raw_data || {};
  const flags = raw.suspicion_flags || [];
  const groups = raw.groups || [];
  const services = raw.running_services || [];
  const events = raw.recent_events || [];
  const procs = raw.running_processes || [];
  const knownProcs = procs.filter(p => p.known);

  return `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;
      margin-bottom:16px">

      <div style="background:var(--surface2);border-radius:8px;padding:14px">
        <div style="font-size:11px;text-transform:uppercase;
          letter-spacing:.8px;color:var(--text-muted);margin-bottom:10px">
          Identidad
        </div>
        <div style="font-size:13px;margin-bottom:6px">
          <span style="color:var(--text-muted)">Estado:</span>
          <span style="color:${raw.enabled ? '#fb923c' : '#4ade80'};
            font-weight:600;margin-left:6px">
            ${raw.enabled ? '🔴 Habilitada' : '🟢 Deshabilitada'}
          </span>
        </div>
        <div style="font-size:13px;margin-bottom:6px">
          <span style="color:var(--text-muted)">Último acceso:</span>
          <span style="margin-left:6px">${
            (raw.last_logon || 'Nunca').substring(0, 19)
              .replace('T', ' ')
              .replace('/Date', '')
              .replace('(', '')
              .split('+')[0]
          }</span>
        </div>
        ${raw.description ? `
          <div style="font-size:13px">
            <span style="color:var(--text-muted)">Descripción:</span>
            <span style="margin-left:6px">${raw.description}</span>
          </div>` : ''}
      </div>

      <div style="background:var(--surface2);border-radius:8px;padding:14px">
        <div style="font-size:11px;text-transform:uppercase;
          letter-spacing:.8px;color:var(--text-muted);margin-bottom:10px">
          Grupos
        </div>
        ${groups.length
          ? groups.map(g => `
            <div style="display:inline-block;background:${
              ['administrators','administradores',
               'remote desktop users',
               'usuarios de escritorio remoto'].includes(g.toLowerCase())
                ? 'rgba(251,146,60,.15)' : 'var(--surface)'
            };border:1px solid ${
              ['administrators','administradores',
               'remote desktop users',
               'usuarios de escritorio remoto'].includes(g.toLowerCase())
                ? '#fb923c44' : 'var(--border)'
            };border-radius:5px;padding:3px 8px;
            font-size:11px;margin:2px">${g}</div>
          `).join('')
          : '<span style="color:var(--text-muted);font-size:12px">Sin grupos detectados</span>'
        }
      </div>
    </div>

    ${flags.length ? `
      <div style="background:rgba(251,146,60,.08);border:1px solid #fb923c44;
        border-radius:8px;padding:14px;margin-bottom:16px">
        <div style="font-size:11px;text-transform:uppercase;
          letter-spacing:.8px;color:#fb923c;margin-bottom:10px">
          ⚠️ Alertas de seguridad
        </div>
        ${flags.map(flag => `
          <div style="font-size:13px;padding:4px 0;
            border-bottom:1px solid rgba(251,146,60,.15)">
            ${flag}
          </div>
        `).join('')}
      </div>` : ''}

    ${services.length ? `
      <div style="background:var(--surface2);border-radius:8px;
        padding:14px;margin-bottom:16px">
        <div style="font-size:11px;text-transform:uppercase;
          letter-spacing:.8px;color:var(--text-muted);margin-bottom:10px">
          Servicios que ejecuta
        </div>
        ${services.map(s => `
          <div style="font-size:12px;padding:4px 0;
            border-bottom:1px solid var(--border);
            display:flex;justify-content:space-between">
            <span>${s.display || s.name}</span>
            <span style="color:${
              s.state === 'Running' ? '#4ade80' : 'var(--text-muted)'
            }">${s.state || ''}</span>
          </div>
        `).join('')}
      </div>` : ''}

    ${knownProcs.length ? `
      <div style="background:var(--surface2);border-radius:8px;
        padding:14px;margin-bottom:16px">
        <div style="font-size:11px;text-transform:uppercase;
          letter-spacing:.8px;color:var(--text-muted);margin-bottom:10px">
          Procesos relevantes activos
        </div>
        ${knownProcs.map(p => `
          <div style="font-size:12px;padding:4px 0;
            border-bottom:1px solid var(--border)">
            🔍 ${p.known}
          </div>
        `).join('')}
      </div>` : ''}

    ${events.length ? `
      <div style="background:var(--surface2);border-radius:8px;
        padding:14px;margin-bottom:16px">
        <div style="font-size:11px;text-transform:uppercase;
          letter-spacing:.8px;color:var(--text-muted);margin-bottom:10px">
          Últimos accesos registrados
        </div>
        ${events.map(e => `
          <div style="font-size:12px;padding:4px 0;
            border-bottom:1px solid var(--border)">
            ${(e.time || '').substring(0,19).replace('T',' ')}
            — Evento ${e.id || e.type}
          </div>
        `).join('')}
      </div>` : ''}

    ${field('Riesgo jurídico', f.legal_risk)}
  `;
}

function renderAccountSummary(f) {
  const raw = f.raw_data || {};
  const profiles = raw.profiles || [];

  return `
    <div style="margin-bottom:16px">
      <div style="display:grid;grid-template-columns:repeat(3,1fr);
        gap:12px;margin-bottom:16px">
        <div style="background:var(--surface2);border-radius:8px;
          padding:14px;text-align:center">
          <div style="font-size:24px;font-weight:700">
            ${raw.total_profiled || 0}
          </div>
          <div style="font-size:11px;color:var(--text-muted);
            text-transform:uppercase;letter-spacing:.8px">
            Perfiladas
          </div>
        </div>
        <div style="background:rgba(251,146,60,.08);
          border:1px solid #fb923c44;border-radius:8px;
          padding:14px;text-align:center">
          <div style="font-size:24px;font-weight:700;color:#fb923c">
            ${raw.suspicious_count || 0}
          </div>
          <div style="font-size:11px;color:var(--text-muted);
            text-transform:uppercase;letter-spacing:.8px">
            Con alertas
          </div>
        </div>
        <div style="background:rgba(248,113,113,.08);
          border:1px solid #f8717144;border-radius:8px;
          padding:14px;text-align:center">
          <div style="font-size:24px;font-weight:700;color:#f87171">
            ${raw.high_risk_count || 0}
          </div>
          <div style="font-size:11px;color:var(--text-muted);
            text-transform:uppercase;letter-spacing:.8px">
            Alto riesgo
          </div>
        </div>
      </div>

      ${profiles.map(p => `
        <div style="background:var(--surface2);border-radius:8px;
          padding:12px;margin-bottom:8px;
          border-left:3px solid ${
            p.risk === 'red' ? '#f87171' :
            p.risk === 'orange' ? '#fb923c' :
            p.risk === 'yellow' ? '#fbbf24' : '#4ade80'
          }">
          <div style="display:flex;justify-content:space-between;
            align-items:center;margin-bottom:6px">
            <div style="font-weight:600;font-size:13px">
              👤 ${p.name}
            </div>
            ${badge(p.risk)}
          </div>
          <div style="font-size:12px;color:var(--text-muted);
            margin-bottom:6px">${p.summary}</div>
          ${p.flags && p.flags.length ? `
            <div style="font-size:11px">
              ${p.flags.map(flag => `
                <span style="background:rgba(251,146,60,.1);
                  color:#fb923c;border-radius:4px;
                  padding:2px 6px;margin:2px;
                  display:inline-block">${flag}</span>
              `).join('')}
            </div>` : ''}
          ${p.groups && p.groups.length ? `
            <div style="font-size:11px;margin-top:6px;
              color:var(--text-muted)">
              Grupos: ${p.groups.join(', ')}
            </div>` : ''}
        </div>
      `).join('')}
    </div>

    ${field('Riesgo jurídico', f.legal_risk)}
  `;
}

function field(label, value, cls = '') {
  if (!value) return '';
  return `
    <div class="finding-field">
      <div class="finding-field-label">${label}</div>
      <div class="finding-field-value ${cls}">${value}</div>
    </div>`;
}

// ── Raw data expandible ──────────────────────────────────────────

function rawDataBlock(f) {
  if (!f.raw_data || Object.keys(f.raw_data).length === 0) return '';
  const id = `raw-${f.skill}-${f.category}`.replace(/[^a-z0-9-]/gi, '_');
  const json = JSON.stringify(f.raw_data, null, 2);
  const highlighted = syntaxHighlight(json);
  return `
    <button class="raw-toggle" onclick="toggleRaw('${id}')">
      🔬 Ver datos técnicos
    </button>
    <pre class="raw-data-block" id="${id}">${highlighted}</pre>
  `;
}

function toggleRaw(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

function syntaxHighlight(json) {
  return json.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
      match => {
        if (/^"/.test(match)) {
          return /:$/.test(match)
            ? `<span class="raw-key">${match}</span>`
            : `<span class="raw-str">${match}</span>`;
        }
        if (/true|false/.test(match)) return `<span class="raw-bool">${match}</span>`;
        if (/null/.test(match))        return `<span class="raw-null">${match}</span>`;
        return `<span class="raw-num">${match}</span>`;
      }
    );
}

// ── Filtro de hallazgos ──────────────────────────────────────────

function filterFindings(query) {
  const q = (typeof query === 'string' ? query : '').toLowerCase();
  const riskVal = document.getElementById('riskFilter')?.value || '';

  document.querySelectorAll('.finding-card').forEach(card => {
    const text = card.textContent.toLowerCase();
    const riskBadge = card.querySelector('.badge');
    const cardRisk = riskBadge ? riskBadge.className.replace('badge badge-','').trim() : '';

    const matchText = !q || text.includes(q);
    const matchRisk = !riskVal || cardRisk === riskVal;
    card.style.display = (matchText && matchRisk) ? '' : 'none';
  });
}