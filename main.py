# main.py
"""Punto de entrada del Worker Digital Rights Audit Agent — modo interactivo y CLI."""

import argparse
import datetime
import json as _json
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
╔══════════════════════════════════════════════════════════════╗
║   Worker Digital Rights Audit Agent                          ║
║   Herramienta de auditoría de derechos digitales             ║
║                                                              ║
║   ✦ Ternura radical. Coherencia cuánticoafectiva.           ║
║   ✦ No destruimos. Construimos respuestas éticas.           ║
╚══════════════════════════════════════════════════════════════╝

Este programa analiza tu dispositivo para detectar
capacidades de monitorización corporativa.

NO intercepta tráfico, NO escala privilegios,
NO exfiltra datos. Solo lee configuración local.

Antes de mostrarte los resultados, te preguntaré
cómo te sientes. Tu bienestar es prioritario.
"""

ALL_SKILLS = [
    "mdm", "surveillance", "persistence", "network", "activity",
    "privacy", "ai_telemetry", "cloud_sync", "browser", "hardening",
    "identity", "git_identity", "scheduled_tasks", "usb", "email",
    "third_party_apps", "user_behavior", "data_exfiltration",
    "incident_response", "event_viewer", "rdp_logs", "addon_audit", 
    "onedrive_mapper", "diagtrack_inspector", "event_log_monitor", 
    "clipboard_watcher", "dpa_checker", "service_hardener",
]

# ── Nuevas skills de defensa ética ────────────────────────────────────────────
DEFENSE_SKILLS = [
    "emotional_shield",      # Protección emocional del usuario
    "narrative_reframer",    # Reencuadre coevolutivo de hallazgos
    "collective_mirror",     # Perfil anónimo para acción colectiva
    "coevolution_letter",    # Generación de cartas constructivas
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
        report = _json.loads(latest.read_text(encoding="utf-8"))
    except Exception:
        return False, latest

    return _current_signature(engine) == _saved_signature(report), latest


# ── Pausa Solemne ─────────────────────────────────────────────────────────────

def _solemn_pause():
    """
    Pausa Solemne: un momento de silencio antes de mostrar resultados.
    Implementa el principio de 'ralentización consciente'.
    """
    import time
    print("\n")
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │                                                      │")
    print("  │   Auditoría completada.                             │")
    print("  │                                                      │")
    print("  │   Antes de ver los resultados, tómate un momento.   │")
    print("  │   Inhala... 6 segundos.                             │")
    print("  │   Exhala... 6 segundos.                             │")
    print("  │                                                      │")
    print("  │   Lo que vas a ver son CAPACIDADES, no certezas.    │")
    print("  │   Detectar no es acusar. Saber no es sufrir.        │")
    print("  │                                                      │")
    print("  └─────────────────────────────────────────────────────┘")
    print()
    time.sleep(3)  # Pausa real de 3 segundos


# ── Motor Principal con Escudo Emocional ──────────────────────────────────────

def run_audit(skills: list = None, no_pdf: bool = False,
              output: str = None, quiet: bool = False,
              no_interactive: bool = False,
              force_save: bool = False,
              recommendation_mode: str = "completo",
              recommendation_categories: list[str] | None = None,
              recommendation_risks: list[str] | None = None,
              # ── Nuevos parámetros de defensa ética ──
              emotional_shield: bool = True,
              narrative_mode: str = "coevolutivo",
              generate_mirror: bool = False,
              generate_letter: bool = False,
              letter_tone: str = "coevolutivo",
              sector: str = "no_especificado",
              company_size: str = "no_especificado") -> tuple:
    
    engine = AuditEngine()
    engine.run_all_skills(skills=skills)

    # ── Pausa Solemne ─────────────────────────────────────────────────────────
    if not quiet and not no_interactive:
        _solemn_pause()

    # ── Escudo Emocional ──────────────────────────────────────────────────────
    emotional_level = "COMPLETO"
    if emotional_shield and not no_interactive and not quiet:
        try:
            from skills.emotional_shield import EmotionalShield, interactive_assessment
            assessment = interactive_assessment()
            emotional_level = assessment.level
        except Exception as e:
            print(f"[i] Escudo emocional no disponible: {e}")

    # ── Evaluación Legal ──────────────────────────────────────────────────────
    legal = LegalEngine(engine.findings)
    issues = legal.evaluate(
        recommendation_mode=recommendation_mode,
        custom_categories=recommendation_categories,
        custom_risks=recommendation_risks,
    )

    # ── Reencuadre Narrativo ──────────────────────────────────────────────────
    findings_dict = [asdict(f) for f in engine.findings]
    
    if not quiet:
        try:
            from skills.narrative_reframer import NarrativeReframer
            reframer = NarrativeReframer(tone=narrative_mode)
            
            # Filtrar según nivel emocional
            if emotional_level == "MINIMO":
                from skills.emotional_shield import EmotionalShield
                shield = EmotionalShield()
                filtered = shield.filter_output(findings_dict, level="MINIMO")
                print("\n")
                print(f"  ⚠ Modo protegido activado.")
                print(f"  Solo se muestra 1 hallazgo de {filtered['total_hidden'] + 1}.")
                print(f"  {filtered['message']}")
                print(f"\n  Acción: {filtered['action']}")
                print(f"\n  {filtered['breathing_reminder']}")
                print(f"\n  {filtered['cierre']}")
            elif emotional_level == "MODERADO":
                from skills.emotional_shield import EmotionalShield
                shield = EmotionalShield()
                filtered = shield.filter_output(findings_dict, level="MODERADO")
                print("\n")
                print(f"  Resumen: {filtered['summary']['total']} hallazgos")
                print(f"  ({filtered['summary']['criticos']} críticos, "
                      f"{filtered['summary']['alerta']} alerta)")
                print(f"\n  {filtered['message']}")
                print(f"\n  {filtered['context']}")
                
                # Mostrar acciones prioritarias
                if filtered.get('actions'):
                    print("\n  Acciones prioritarias:")
                    for a in filtered['actions']:
                        print(f"    {a['priority']}. [{a['urgency']}] {a['action']}")
                
                # Reencuadre de los hallazgos mostrados
                reframed = reframer.reframe_all(filtered['findings'])
                print("\n" + reframer.generate_summary(reframed))
            else:
                # COMPLETO: mostrar todo con reencuadre
                print("\n")
                engine.summary()
                print("\n" + legal.summary_text())
                
                reframed = reframer.reframe_all(findings_dict)
                print("\n" + reframer.generate_summary(reframed))
                
        except Exception as e:
            # Fallback: mostrar sin reencuadre
            print(f"[i] Reencuadre narrativo no disponible: {e}")
            engine.summary()
            print("\n" + legal.summary_text())

    # ── Decidir si guardar ────────────────────────────────────────────────────
    should_save = True
    is_identical, latest_path = _is_identical_to_latest(engine)
    if is_identical:
        if latest_path:
            print(f"[=] Auditoría idéntica a la anterior: {latest_path.relative_to(EXPORTS_PATH)}")
        if force_save:
            should_save = True
            print("[=] --force-save activo: se guardan igualmente.")
        elif no_interactive:
            should_save = False
            print("[=] Modo no interactivo: no se guardan archivos al ser idéntica.")
        else:
            ans = input("¿Deseas guardar igualmente? [y/N]: ").strip().lower()
            should_save = ans in {"y", "yes", "s", "si", "sí"}
    
    if not should_save:
        if not quiet:
            print("[i] Informe no guardado por ser idéntico al último.")
        return engine.findings, issues, None

    # ── Exportar ──────────────────────────────────────────────────────────────
    prefix = output or _default_output_prefix()

    # 1. audit.json — informe técnico original con hash
    json_out = engine.export_json(filename=prefix)
        
    if not no_pdf:
        # 2. informe_resumen.pdf — versión clara para el trabajador
        try:
            from core.pdf_resumen import export_pdf_resumen
            pdf_resumen = json_out.parent / "audit_resumen.pdf"            
            _data = _json.loads(json_out.read_text(encoding="utf-8"))
            export_pdf_resumen(
                findings=findings_dict,
                legal_issues=issues,
                output_path=pdf_resumen,
                audit_hash=_data.get("integrity_hash", ""),
                generated_at=datetime.datetime.now().isoformat(),
            )
            if not quiet:
                print(f"[+] PDF Resumen:  {pdf_resumen}")
        except Exception as e:
            print(f"[!] PDF Resumen: {e}")

        # 3. informe_completo.pdf — versión técnica para sindicato
        try:
            from core.pdf_completo import export_pdf
            pdf_completo = json_out.parent / "audit_completo.pdf"
            _data = _json.loads(json_out.read_text(encoding="utf-8"))            
            export_pdf(
                engine.findings,
                issues,
                pdf_completo,
                recommendation_context={
                    "mode": recommendation_mode,
                    "categories": recommendation_categories or [],
                    "risks": recommendation_risks or [],
                },
            )
            if not quiet:
                print(f"[+] PDF Sindicato:   {pdf_completo}")
        except Exception as e:
            print(f"[!] PDF Sindicato: {e}")

        # 4. dossier_*.zip — paquete completo para abogado/perito
        try:
            from skills.evidence_packager.evidence_packager import EvidencePackager
            EvidencePackager().package(json_out.parent)
        except Exception as e:
            print(f"[!] Evidence packager: {e}")

    # ── Nuevas exportaciones de defensa ética ─────────────────────────────────

    # 5. Espejo Colectivo (perfil anónimo)
    if generate_mirror:
        try:
            from skills.collective_mirror import CollectiveMirror
            mirror = CollectiveMirror()
            profile = mirror.generate_mirror(
                findings_dict,
                sector=sector,
                company_size=company_size,
            )
            mirror_path = mirror.export_profile(
                profile,
                str(json_out.parent / "mirror_profile.json")
            )
            if not quiet:
                print(f"[+] Espejo Colectivo: {mirror_path}")
                print("    (Perfil anónimo listo para compartir)")
        except Exception as e:
            print(f"[!] Espejo Colectivo: {e}")

    # 6. Carta de Coevolución
    if generate_letter:
        try:
            from skills.coevolution_letter import CoevolutionLetterGenerator
            generator = CoevolutionLetterGenerator(tone=letter_tone)
            letter = generator.generate(findings_dict)
            letter_path = generator.export_letter(
                letter,
                str(json_out.parent / f"carta_{letter_tone}.txt")
            )
            if not quiet:
                print(f"[+] Carta ({letter_tone}): {letter_path}")
        except Exception as e:
            print(f"[!] Carta de Coevolución: {e}")

    if not quiet:
        print(f"\n[+] Completado — {len(engine.findings)} hallazgos")
        print(f"[+] Exportado en: {json_out.parent}")
        
        # Mensaje de cierre con ternura
        print("\n")
        print("  ┌─────────────────────────────────────────────────────┐")
        print("  │  Recuerda:                                          │")
        print("  │  • Detectar una capacidad NO prueba su uso.         │")
        print("  │  • Preguntar NO es acusar.                          │")
        print("  │  • Proponer NO es atacar.                           │")
        print("  │  • Tu dignidad no depende de lo que configuren.     │")
        print("  └─────────────────────────────────────────────────────┘")

    return engine.findings, issues, json_out


def main():
    parser = argparse.ArgumentParser(
        description="Worker Digital Rights Audit Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Skills disponibles: {', '.join(ALL_SKILLS)}\n"
               f"Skills de defensa: {', '.join(DEFENSE_SKILLS)}"
    )
    parser.add_argument(
        "--skills", "-s",
        nargs="+", metavar="SKILL",
        choices=ALL_SKILLS + [None],
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
        help="Modo de recomendaciones legales.",
    )
    parser.add_argument(
        "--recommendation-categories",
        nargs="+", metavar="CATEGORY",
        help="Categorías legales a incluir en modo personalizado.",
    )
    parser.add_argument(
        "--recommendation-risks",
        nargs="+",
        choices=["low", "medium", "medium-high", "high", "very_high"],
        metavar="RISK",
        help="Niveles de riesgo legal a incluir en modo personalizado.",
    )
    
    # ── Nuevos argumentos de defensa ética ────────────────────────────────────
    defense_group = parser.add_argument_group(
        "Defensa Ética",
        "Opciones de protección emocional y acción coevolutiva."
    )
    defense_group.add_argument(
        "--no-shield",
        action="store_true",
        help="Desactivar escudo emocional (mostrar todo sin filtro).",
    )
    defense_group.add_argument(
        "--narrative",
        choices=["coevolutivo", "asertivo", "sindical"],
        default="coevolutivo",
        help="Tono del reencuadre narrativo (default: coevolutivo).",
    )
    defense_group.add_argument(
        "--mirror",
        action="store_true",
        help="Generar perfil anónimo para acción colectiva.",
    )
    defense_group.add_argument(
        "--letter",
        action="store_true",
        help="Generar carta al empleador.",
    )
    defense_group.add_argument(
        "--letter-tone",
        choices=["coevolutivo", "asertivo", "formal_legal"],
        default="coevolutivo",
        help="Tono de la carta (default: coevolutivo).",
    )
    defense_group.add_argument(
        "--sector",
        default="no_especificado",
        help="Sector de la empresa (para perfil anónimo).",
    )
    defense_group.add_argument(
        "--company-size",
        choices=["pyme", "mediana", "grande", "multinacional"],
        default="no_especificado",
        help="Tamaño de la empresa (para perfil anónimo).",
    )

    # Si se llama sin argumentos: modo interactivo original
    if len(sys.argv) == 1:
        print(BANNER)
        input("Pulsa ENTER para iniciar la auditoría...")
        run_audit()
        return

    args = parser.parse_args()

    if args.list_skills:
        print("\nSkills de auditoría:")
        for s in ALL_SKILLS:
            print(f"  • {s}")
        print("\nSkills de defensa ética:")
        for s in DEFENSE_SKILLS:
            print(f"  ✦ {s}")
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
        # Nuevos parámetros
        emotional_shield=not args.no_shield,
        narrative_mode=args.narrative,
        generate_mirror=args.mirror,
        generate_letter=args.letter,
        letter_tone=args.letter_tone,
        sector=args.sector,
        company_size=args.company_size,
    )


if __name__ == "__main__":
    main()
