// ui/static/js/ui.js — helpers de interfaz (v2: Ternura Radical)

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

// ── Navegación por secciones ─────────────────────────────────────

function showSection(name, callerBtn) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

  const section = document.getElementById(`section-${name}`);
  if (section) section.classList.add('active');
  if (callerBtn) callerBtn.classList.add('active');

  // En móvil, cerrar sidebar al navegar
  if (window.innerWidth <= 768) {
    closeSidebar();
  }

  // Inicializar El Espejo si es la primera vez que se abre
  if (name === 'espejo' && typeof initEspejo === 'function') {
    initEspejo();
  }
}

// ── Sidebar móvil ────────────────────────────────────────────────

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  sidebar.classList.toggle('open');
  overlay.classList.toggle('open');
}

function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  sidebar.classList.remove('open');
  overlay.classList.remove('open');
}

// ── Findings toggle ──────────────────────────────────────────────

function toggleFinding(i) {
  document.getElementById(`fb-${i}`).classList.toggle('open');
}

// ── Toast notifications ──────────────────────────────────────────

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

// ── Badge helper ─────────────────────────────────────────────────

function badge(level) {
  const labels = {
    'red': 'crítico',
    'orange': 'alto',
    'yellow': 'medio',
    'green': 'bajo',
    'very_high': 'muy alto',
    'high': 'alto',
    'medium': 'medio',
    'medium-high': 'medio-alto',
    'low': 'bajo'
  };
  const label = labels[level] || level.replace('_', ' ');
  return `<span class="badge badge-${level}">${label}</span>`;
}

// ── Deep-link to finding ─────────────────────────────────────────

function goToFinding(title) {
  const btn = document.querySelector('.nav-btn[data-section="findings"]');
  showSection('findings', btn);
  setTimeout(() => {
    document.querySelectorAll('.finding-card').forEach(c => {
      if (c.querySelector('.finding-title')?.textContent === title) {
        c.scrollIntoView({ behavior: 'smooth', block: 'center' });
        c.querySelector('.finding-body')?.classList.add('open');
        // Highlight temporal
        c.style.borderColor = 'var(--accent)';
        setTimeout(() => c.style.borderColor = '', 2000);
      }
    });
  }, 100);
}

// ── Keyboard shortcuts ───────────────────────────────────────────

document.addEventListener('keydown', (e) => {
  // Alt+1..5 para navegar entre secciones
  if (e.altKey && e.key >= '1' && e.key <= '5') {
    e.preventDefault();
    const sections = ['dashboard', 'findings', 'legal', 'compare', 'espejo'];
    const idx = parseInt(e.key) - 1;
    if (sections[idx]) {
      const btn = document.querySelector(`.nav-btn[data-section="${sections[idx]}"]`);
      showSection(sections[idx], btn);
    }
  }
});
