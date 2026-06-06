// ui/static/js/api.js
const API = {
  async reports() {
    const r = await fetch('/api/reports');
    return r.json();
  },
  async report(filename) {
    const r = await fetch(`/api/report/${filename}`);
    return r.json();
  },
  async runAudit(options = {}) {
    return fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    });
  },
  async status() {
    const r = await fetch('/api/status');
    return r.json();
  },
  downloadUrl(filename) {
    return `/api/download/${filename}`;
  },
  async compare(fileA, fileB) {
    const r = await fetch(`/api/compare?a=${encodeURIComponent(fileA)}&b=${encodeURIComponent(fileB)}`);
    return r.json();
  },
  async skills() {
    const r = await fetch('/api/skills');
    return r.json();
  },
  async runAuditSkills(skills, options = {}) {
    return API.runAudit({ skills, ...options });
  },
};