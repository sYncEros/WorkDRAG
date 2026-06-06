// ui/static/js/ui.js — helpers de interfaz

// ── Modo oscuro / claro ──────────────────────────────────────────

function toggleTheme() {
  const html = document.documentElement;
  const isDark = html.getAttribute('data-theme') === 'dark';
  html.setAttribute('data-theme', isDark ? 'light' : 'dark');
  document.getElementById('themeBtn').textContent =
    isDark ? '🌙 Modo oscuro' : '☀ Modo claro';
  localStorage.setItem('theme', isDark ? 'light' : 'dark');
}

// Restaurar tema guardado
(function() {
  const saved = localStorage.getItem('theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.getElementById('themeBtn');
    if (btn) btn.textContent = saved === 'light' ? '🌙 Modo oscuro' : '☀ Modo claro';
  }
})();

function showSection(name, callerBtn) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(`section-${name}`).classList.add('active');
  if (callerBtn) callerBtn.classList.add('active');
}

function toggleFinding(i) {
  document.getElementById(`fb-${i}`).classList.toggle('open');
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

function badge(level) {
  return `<span class="badge badge-${level}">${level.replace('_',' ')}</span>`;
}

function goToFinding(title) {
  const btn = document.querySelector('.nav-btn[data-section="findings"]');
  showSection('findings', btn);
  setTimeout(() => {
    document.querySelectorAll('.finding-card').forEach(c => {
      if (c.querySelector('.finding-title')?.textContent === title) {
        c.scrollIntoView({ behavior: 'smooth', block: 'center' });
        c.querySelector('.finding-body')?.classList.add('open');
      }
    });
  }, 100);
}