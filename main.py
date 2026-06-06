# main.py
"""Punto de entrada del Worker Digital Rights Audit Agent — modo interactivo y CLI."""

import argparse
import datetime
import json
import sys
from dataclasses import asdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.audit_engine import AuditEngine
from skills.compliance_engine.legal_engine import LegalEngine

EXPORTS_PATH = Path("exports")

BANNER = """
╔══════════════════════════════════════════════════╗
║   Worker Digital Rights Audit Agent              ║
║   Herramienta de auditoría de derechos digitales ║
╚══════════════════════════════════════════════════╝

Este programa analiza tu dispositivo para detectar
capacidades de monitorización corporativa.

NO intercepta tráfico, NO escala privilegios,
NO exfiltra datos. Solo lee configuración local.
"""

ALL_SKILLS = [
    "mdm", "surveillance", "persistence", "network", "activity",
    "privacy", "ai_telemetry", "cloud_sync", "browser", "hardening",
    "identity", "git_identity", "scheduled_tasks", "usb", "email",
    "third_party_apps", "user_behavior", "data_exfiltration",
    "incident_response", "event_viewer",
]


def _default_output_prefix() -> str:
    now = datetime.datetime.now()
    day = now.strftime("%Y-%m-%d")
    hour = now.strftime("%Hh.%Mm")
    return str(Path(day) / hour / "audit")


def _latest_report_path() -> Path | None:
    files = sorted(
        EXPORTS_PATH.glob("**/audit*.json"),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )
    return files[0] if files else None


def _normalized_findings(findings: list[dict]) -> list[dict]:
    """Normaliza findings para comparación entre auditorías."""
    normalized = []
    for f in findings:
        item = dict(f)
        item.pop("timestamp", None)
        normalized.append(item)

    return sorted(
        normalized,
        key=lambda x: (
            x.get("skill", ""),
            x.get("category", ""),
            x.get("title", ""),
        )
    )


def _current_signature(engine: AuditEngine) -> dict:
    findings = [asdict(f) for f in engine.findings]
    return {
        "total_findings": len(findings),
        "max_risk": engine._compute_max_risk(),
        "findings": _normalized_findings(findings),
    }


def _saved_signature(report: dict) -> dict:
    return {
        "total_findings": report.get("total_findings", 0),
        "max_risk": report.get("max_risk", "green"),
        "findings": _normalized_findings(report.get("findings", [])),
    }


def _is_identical_to_latest(engine: AuditEngine) -> tuple[bool, Path | None]:
    latest = _latest_report_path()
    if not latest:
        return False, None

    try:
        report = json.loads(latest.read_text(encoding="utf-8"))
    except Exception:
        return False, latest

    return _current_signature(engine) == _saved_signature(report), latest


def run_audit(skills: list = None, no_pdf: bool = False,
              output: str = None, quiet: bool = False,
              no_interactive: bool = False,
              force_save: bool = False,
              recommendation_mode: str = "completo",
              recommendation_categories: list[str] | None = None,
              recommendation_risks: list[str] | None = None) -> tuple:
    engine = AuditEngine()
    engine.run_all_skills(skills=skills)

    if not quiet:
        print("\n")
        engine.summary()

    legal = LegalEngine(engine.findings)
    issues = legal.evaluate(
        recommendation_mode=recommendation_mode,
        custom_categories=recommendation_categories,
        custom_risks=recommendation_risks,
    )

    if not quiet:
        print("\n" + legal.summary_text())

    should_save = True
    is_identical, latest_path = _is_identical_to_latest(engine)
    if is_identical:
        if latest_path:
            print(
                "[=] Auditoría idéntica a la anterior: "
                f"{latest_path.relative_to(EXPORTS_PATH)}"
            )
        if force_save:
            should_save = True
            print("[=] --force-save activo: se guardarán JSON/PDF aunque sea idéntica.")
        elif no_interactive:
            should_save = False
            print("[=] Modo no interactivo: no se guardan JSON/PDF al ser idéntica.")
        else:
            ans = input("¿Deseas guardar igualmente JSON y PDF? [y/N]: ").strip().lower()
            should_save = ans in {"y", "yes", "s", "si", "sí"}

    if not should_save:
        if not quiet:
            print("[i] Informe no guardado por ser idéntico al último.")
        return engine.findings, issues, None

    prefix = output or _default_output_prefix()
    json_out = engine.export_json(filename=prefix)

    if not no_pdf:
        from core.pdf_exporter import export_pdf
        EXPORTS_PATH.mkdir(parents=True, exist_ok=True)
        pdf_out = EXPORTS_PATH / f"{prefix}.pdf"
        pdf_out.parent.mkdir(parents=True, exist_ok=True)
        export_pdf(
            engine.findings,
            issues,
            pdf_out,
            recommendation_context={
                "mode": recommendation_mode,
                "categories": recommendation_categories or [],
                "risks": recommendation_risks or [],
            },
        )
        if not quiet:
            print(f"[+] PDF guardado en: {pdf_out}")

    return engine.findings, issues, json_out


def main():
    parser = argparse.ArgumentParser(
        description="Worker Digital Rights Audit Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Skills disponibles: {', '.join(ALL_SKILLS)}"
    )
    parser.add_argument(
        "--skills", "-s",
        nargs="+", metavar="SKILL",
        choices=ALL_SKILLS + [None],  # None para modo interactivo
        help="Skills a ejecutar. Si se omite, se ejecutan todos.",
    )
    parser.add_argument(
        "--list-skills", "-l",
        action="store_true",
        help="Mostrar skills disponibles y salir.",
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="No generar exportación en PDF.",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PREFIX",
        help="Prefijo del archivo de salida (default: audit_FECHA)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Modo silencioso: no mostrar resumen en consola.",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="No pedir confirmación antes de iniciar.",
    )
    parser.add_argument(
        "--force-save",
        action="store_true",
        help="Guardar informe aunque sea idéntico al último.",
    )
    parser.add_argument(
        "--recommendation-mode",
        choices=["urgente", "completo", "personalizado"],
        default="completo",
        help=(
            "Modo de recomendaciones legales previo a exportar PDF: "
            "urgente, completo o personalizado."
        ),
    )
    parser.add_argument(
        "--recommendation-categories",
        nargs="+",
        metavar="CATEGORY",
        help="Categorías legales a incluir en modo personalizado.",
    )
    parser.add_argument(
        "--recommendation-risks",
        nargs="+",
        choices=["low", "medium", "medium-high", "high", "very_high"],
        metavar="RISK",
        help="Niveles de riesgo legal a incluir en modo personalizado.",
    )

    # Si se llama sin argumentos: modo interactivo original
    if len(sys.argv) == 1:
        print(BANNER)
        input("Pulsa ENTER para iniciar la auditoría...")
        run_audit()
        return

    args = parser.parse_args()

    if args.list_skills:
        print("Skills disponibles:")
        for s in ALL_SKILLS:
            print(f"  {s}")
        return

    if not args.no_interactive and not args.quiet:
        print(BANNER)
        skills_str = ", ".join(args.skills) if args.skills else "todos"
        print(f"Skills a ejecutar: {skills_str}")
        input("Pulsa ENTER para continuar o Ctrl+C para cancelar...")

    run_audit(
        skills=args.skills,
        no_pdf=args.no_pdf,
        output=args.output,
        quiet=args.quiet,
        no_interactive=args.no_interactive,
        force_save=args.force_save,
        recommendation_mode=args.recommendation_mode,
        recommendation_categories=args.recommendation_categories,
        recommendation_risks=args.recommendation_risks,
    )


if __name__ == "__main__":
    main()