# ui/server.py
"""
Worker Digital Rights Audit Agent — Dashboard UI
Servidor Flask local que sirve el dashboard
"""

import json
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from flask import Flask, jsonify, request, send_from_directory

EXPORTS_DIR = BASE_DIR / "exports"
EVIDENCE_DIR = BASE_DIR / "evidence"

app = Flask(__name__, static_folder=str(BASE_DIR / "ui" / "static"))

audit_status = {"running": False, "last_skills": None, "last_started": None}

# ── Utilidades ─────────────────────────────────────────────────────────────────

def _python_exe() -> str:
    """Devuelve el ejecutable Python a usar (portátil o venv)."""
    portable = BASE_DIR / "python_portable" / "python.exe"
    venv = BASE_DIR / ".venv" / "Scripts" / "python.exe"
    if portable.exists():
        return str(portable)
    if venv.exists():
        return str(venv)
    return sys.executable


def _resolve_report_path(filename: str) -> Path | None:
    """Resuelve una ruta de reporte relativa a exports con validación básica."""
    candidate = (EXPORTS_DIR / filename).resolve()
    try:
        candidate.relative_to(EXPORTS_DIR.resolve())
    except ValueError:
        return None
    return candidate


# ── Rutas estáticas ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR / "ui"), "index.html")


# ── API: estado y skills disponibles ──────────────────────────────────────────

@app.route("/api/status")
def status():
    return jsonify(audit_status)


@app.route("/api/skills")
def list_skills():
    """Devuelve la lista de skills disponibles."""
    skills = [
        "mdm", "surveillance", "persistence", "network", "activity",
        "privacy", "ai_telemetry", "cloud_sync", "browser", "hardening",
        "identity", "git_identity", "scheduled_tasks", "usb", "email",
        "third_party_apps", "user_behavior", "data_exfiltration",
        "incident_response", "event_viewer", "rdp",
    ]
    return jsonify(skills)


@app.route("/api/recommendation-modes")
def recommendation_modes():
    return jsonify(["urgente", "completo", "personalizado"])


# ── API: informes ──────────────────────────────────────────────────────────────

@app.route("/api/reports")
def list_reports():
    files = sorted(
        EXPORTS_DIR.glob("**/audit*.json"),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )
    return jsonify([
        str(f.relative_to(EXPORTS_DIR)).replace("\\", "/")
        for f in files
    ])


@app.route("/api/report/<path:filename>")
def get_report(filename):
    path = _resolve_report_path(filename)
    if not path or not path.exists() or not path.is_file():
        return jsonify({"error": "not found"}), 404
    return jsonify(json.loads(path.read_text(encoding="utf-8")))


# ── API: ejecutar auditoría ────────────────────────────────────────────────────

@app.route("/api/run", methods=["POST"])
def run_audit():
    """
    Ejecuta la auditoría. Acepta JSON body:
    { "skills": ["mdm", "network", ...] }  — skills específicos (opcional)
    """
    if audit_status["running"]:
        return jsonify({"status": "already_running"}), 409

    body = request.get_json(silent=True) or {}
    skills = body.get("skills") or []
    recommendation_mode = (body.get("recommendation_mode") or "completo").strip().lower()
    recommendation_categories = body.get("recommendation_categories") or []
    recommendation_risks = body.get("recommendation_risks") or []

    if recommendation_mode not in {"urgente", "completo", "personalizado"}:
        recommendation_mode = "completo"

    def execute():
        import datetime
        audit_status["running"] = True
        audit_status["last_skills"] = skills or "all"
        audit_status["last_started"] = datetime.datetime.now().isoformat()

        cmd = [_python_exe(), str(BASE_DIR / "main_auto.py")]
        if skills:
            cmd += ["--skills"] + skills
        cmd += ["--recommendation-mode", recommendation_mode]
        if recommendation_categories:
            cmd += ["--recommendation-categories"] + recommendation_categories
        if recommendation_risks:
            cmd += ["--recommendation-risks"] + recommendation_risks

        subprocess.run(cmd, cwd=str(BASE_DIR))
        audit_status["running"] = False

    threading.Thread(target=execute, daemon=True).start()
    return jsonify({
        "status": "started",
        "skills": skills or "all",
        "recommendation_mode": recommendation_mode,
        "recommendation_categories": recommendation_categories,
        "recommendation_risks": recommendation_risks,
    })


# ── API: comparar dos informes ─────────────────────────────────────────────────

@app.route("/api/compare")
def compare_reports():
    """
    Compara dos informes de auditoría.
    Query params: a=<filename>&b=<filename>
    """
    file_a = request.args.get("a")
    file_b = request.args.get("b")

    if not file_a or not file_b:
        return jsonify({"error": "Se requieren parámetros ?a=<file>&b=<file>"}), 400

    path_a = _resolve_report_path(file_a)
    path_b = _resolve_report_path(file_b)

    if not path_a or not path_a.exists() or not path_a.is_file():
        return jsonify({"error": f"Informe '{file_a}' no encontrado"}), 404
    if not path_b or not path_b.exists() or not path_b.is_file():
        return jsonify({"error": f"Informe '{file_b}' no encontrado"}), 404

    report_a = json.loads(path_a.read_text(encoding="utf-8"))
    report_b = json.loads(path_b.read_text(encoding="utf-8"))

    findings_a = {f["category"]: f for f in report_a.get("findings", [])}
    findings_b = {f["category"]: f for f in report_b.get("findings", [])}

    cats_a = set(findings_a.keys())
    cats_b = set(findings_b.keys())

    new_in_b = [findings_b[c] for c in cats_b - cats_a]
    resolved_in_b = [findings_a[c] for c in cats_a - cats_b]
    common = []

    for cat in cats_a & cats_b:
        fa = findings_a[cat]
        fb = findings_b[cat]
        risk_order = {"green": 0, "yellow": 1, "orange": 2, "red": 3}
        risk_change = (
            risk_order.get(fb["risk_level"], 0) - risk_order.get(fa["risk_level"], 0)
        )
        common.append({
            "category": cat,
            "title": fb["title"],
            "risk_a": fa["risk_level"],
            "risk_b": fb["risk_level"],
            "risk_delta": risk_change,
            "risk_changed": fa["risk_level"] != fb["risk_level"],
        })

    risk_order = {"green": 0, "yellow": 1, "orange": 2, "red": 3}

    return jsonify({
        "report_a": {"filename": file_a, "date": report_a.get("generated_at"),
                     "total": report_a.get("total_findings"),
                     "max_risk": report_a.get("max_risk")},
        "report_b": {"filename": file_b, "date": report_b.get("generated_at"),
                     "total": report_b.get("total_findings"),
                     "max_risk": report_b.get("max_risk")},
        "summary": {
            "new_findings": len(new_in_b),
            "resolved_findings": len(resolved_in_b),
            "risk_increased": sum(1 for c in common if c["risk_delta"] > 0),
            "risk_decreased": sum(1 for c in common if c["risk_delta"] < 0),
        },
        "new_in_b": sorted(new_in_b,
                           key=lambda x: risk_order.get(x["risk_level"], 0),
                           reverse=True),
        "resolved_in_b": sorted(resolved_in_b,
                                 key=lambda x: risk_order.get(x["risk_level"], 0),
                                 reverse=True),
        "common": sorted(common,
                         key=lambda x: abs(x["risk_delta"]),
                         reverse=True),
    })


# ── API: validación de esquema ─────────────────────────────────────────────────

@app.route("/api/validate/<path:filename>")
def validate_report(filename):
    """Valida el esquema JSON de un informe."""
    path = _resolve_report_path(filename)
    if not path or not path.exists() or not path.is_file():
        return jsonify({"error": "not found"}), 404

    from core.audit_engine import AuditEngine
    engine = AuditEngine.__new__(AuditEngine)  # instancia sin __init__
    engine.findings = []

    report = json.loads(path.read_text(encoding="utf-8"))
    errors = engine.validate_schema(report)

    return jsonify({
        "filename": filename,
        "valid": len(errors) == 0,
        "errors": errors,
        "findings_count": len(report.get("findings", [])),
    })


# ── API: descarga ──────────────────────────────────────────────────────────────

@app.route("/api/download/<path:filename>")
def download(filename):
    path = _resolve_report_path(filename)
    if not path or not path.exists() or not path.is_file():
        return jsonify({"error": "not found"}), 404
    rel_parent = path.parent.relative_to(EXPORTS_DIR)
    return send_from_directory(
        str(EXPORTS_DIR / rel_parent),
        path.name,
        as_attachment=True,
    )


# ── Arranque ───────────────────────────────────────────────────────────────────

def open_browser():
    import time
    time.sleep(1)
    webbrowser.open("http://localhost:5050")


if __name__ == "__main__":
    print("[UI] Dashboard disponible en http://localhost:5050")
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(port=5050, debug=False)
