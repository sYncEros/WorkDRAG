from pathlib import Path
import json
import sys
import datetime

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from core.audit_engine import AuditFinding
from skills.compliance_engine.legal_engine import LegalEngine


def main() -> int:
    exports = BASE / "exports"
    live_dir = BASE / "recomendaciones"
    live_dir.mkdir(parents=True, exist_ok=True)

    reports = sorted(
        exports.glob("**/audit*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not reports:
        print("No se encontraron informes JSON en exports.")
        return 1

    latest = reports[0]
    report = json.loads(latest.read_text(encoding="utf-8"))
    findings = [AuditFinding(**f) for f in report.get("findings", [])]
    issues = LegalEngine(findings).evaluate()

    risk_order = {
        "very_high": 0,
        "high": 1,
        "medium-high": 2,
        "medium": 3,
        "low": 4,
    }
    issues_sorted = sorted(
        issues,
        key=lambda x: (risk_order.get(x.get("legal_risk", "low"), 99), x.get("issue", "")),
    )

    lines = [
        "# Recomendaciones por vulneración detectada",
        "",
        f"- Documento actualizado: `{datetime.datetime.now().isoformat(timespec='seconds')}`",
        f"- Informe fuente: `{latest.relative_to(BASE)}`",
        f"- Vulneraciones con evaluación legal: **{len(issues_sorted)}**",
        "",
    ]

    if not issues_sorted:
        lines.append("No se han detectado vulneraciones con recomendaciones en el informe actual.")
    else:
        for idx, issue in enumerate(issues_sorted, 1):
            lines.extend([
                f"## {idx}. {issue.get('issue', '(sin título)')}",
                "",
                f"- Categoría: `{issue.get('category', '')}`",
                f"- Riesgo legal: **{issue.get('legal_risk', '').upper()}**",
                "",
                "### Motivo",
                "",
                issue.get("reason", "").strip(),
                "",
                "### Recomendaciones",
                "",
            ])

            recs = issue.get("recommendations") or []
            if recs:
                for rec in recs:
                    lines.append(f"- {rec}")
            else:
                lines.append("- (Sin recomendaciones específicas)")

            refs = issue.get("references") or []
            if refs:
                lines.extend(["", "### Referencias", ""])
                for ref in refs:
                    name = ref.get("name") or ref.get("id", "")
                    url = ref.get("url", "")
                    if url:
                        lines.append(f"- [{name}]({url})")
                    else:
                        lines.append(f"- {name}")

            lines.append("")

    md_path = live_dir / "recomendaciones_vulneraciones.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")

    # Limpieza de documentos legacy que quedaron junto a informes
    for old in exports.glob("**/recomendaciones_vulneraciones.md"):
        if old.resolve() != md_path.resolve():
            old.unlink(missing_ok=True)

    print(f"MD generado: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
