# main_auto.py — versión sin interacción para la UI y CLI
import argparse
import datetime
import sys
import json as _json
from dataclasses import asdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.audit_engine import AuditEngine
from skills.compliance_engine.legal_engine import LegalEngine

EXPORTS_PATH = Path("exports")


def _default_output_prefix() -> str:
    now = datetime.datetime.now()
    day = now.strftime("%Y-%m-%d")
    hour = now.strftime("%Hh.%Mm")
    return str(Path(day) / hour / "audit")


def run(
    skills: list = None,
    output_prefix: str = None,
    recommendation_mode: str = "completo",
    recommendation_categories: list[str] | None = None,
    recommendation_risks: list[str] | None = None,
):
    """
    Ejecuta la auditoría y exporta los resultados.
    :param skills: lista de nombres de skills a ejecutar (None = todos)
    :param output_prefix: prefijo del nombre del archivo de exportación
    """
    engine = AuditEngine()
    engine.run_all_skills(skills=skills)

    legal = LegalEngine(engine.findings)
    issues = legal.evaluate(
        recommendation_mode=recommendation_mode,
        custom_categories=recommendation_categories,
        custom_risks=recommendation_risks,
    )

    prefix   = output_prefix or _default_output_prefix()
    json_out = engine.export_json(filename=prefix)
    _data    = _json.loads(json_out.read_text(encoding="utf-8"))

    # PDF Resumen — para el trabajador
    try:
        from core.pdf_trabajador import export_pdf_trabajador
        export_pdf_trabajador(
            findings=[asdict(f) for f in engine.findings],
            legal_issues=issues,
            output_path=json_out.parent / "audit_resumen.pdf",
            audit_hash=_data.get("integrity_hash", ""),
            generated_at=_data.get("generated_at", ""),
        )
    except Exception as e:
        print(f"[!] PDF Resumen: {e}")

    # PDF Completo — para sindicato
    try:
        from core.pdf_exporter import export_pdf
        export_pdf(
            engine.findings,
            issues,
            json_out.parent / "audit_completo.pdf",
            recommendation_context={
                "mode": recommendation_mode,
                "categories": recommendation_categories or [],
                "risks": recommendation_risks or [],
            },
        )
    except Exception as e:
        print(f"[!] PDF Completo: {e}")

    # Dossier ZIP — para abogado/perito
    try:
        from skills.evidence_packager.evidence_packager import EvidencePackager
        EvidencePackager().package(json_out.parent)
    except Exception as e:
        print(f"[!] Evidence packager: {e}")

    print(f"[+] Completado — {len(engine.findings)} hallazgos")
    print(f"[+] Exportado en: {json_out.parent}")
    return engine.findings, issues

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Worker Digital Rights Audit Agent — ejecución automática"
    )
    parser.add_argument(
        "--skills", "-s",
        nargs="+",
        metavar="SKILL",
        help="Skills a ejecutar (ej: --skills mdm surveillance network). "
             "Si se omite, se ejecutan todos (incluye event_viewer).",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PREFIX",
        help="Prefijo del archivo de salida (default: audit_FECHA)",
    )
    parser.add_argument(
        "--recommendation-mode",
        choices=["urgente", "completo", "personalizado"],
        default="completo",
        help="Modo de recomendaciones legales previo a exportar PDF.",
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
    args = parser.parse_args()
    run(
        skills=args.skills,
        output_prefix=args.output,
        recommendation_mode=args.recommendation_mode,
        recommendation_categories=args.recommendation_categories,
        recommendation_risks=args.recommendation_risks,
    )