# core/pdf_exporter.py
"""
Exportador PDF forense — versión sindicato/técnica.
Dos secciones principales:
1. Hallazgos técnicos (sin repetir referencias legales en cada uno)
2. Evaluación legal consolidada al final (referencias + recomendaciones agrupadas)
"""

import hashlib
import datetime
from pathlib import Path
from dataclasses import asdict

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

# ── Paleta ─────────────────────────────────────────────────────────────────────

COLOR_PRIMARY    = colors.HexColor("#1a1a2e")
COLOR_GREEN      = colors.HexColor("#2d6a4f")
COLOR_YELLOW     = colors.HexColor("#b5830a")
COLOR_ORANGE     = colors.HexColor("#c9510c")
COLOR_RED        = colors.HexColor("#a61c00")
COLOR_LIGHT_GREY = colors.HexColor("#f5f5f5")
COLOR_MID_GREY   = colors.HexColor("#cccccc")
COLOR_WHITE      = colors.white

RISK_COLORS = {
    "green":  COLOR_GREEN,
    "yellow": COLOR_YELLOW,
    "orange": COLOR_ORANGE,
    "red":    COLOR_RED,
}

RISK_LABELS = {
    "green":  "VERDE — Seguridad corporativa estándar",
    "yellow": "AMARILLO — Telemetría relevante",
    "orange": "NARANJA — Vigilancia potencialmente intrusiva",
    "red":    "ROJO — Capacidad altamente invasiva",
}


# ── Estilos ────────────────────────────────────────────────────────────────────

def build_styles():
    return {
        "title": ParagraphStyle(
            "title", fontSize=22, leading=28,
            textColor=COLOR_PRIMARY, fontName="Helvetica-Bold",
            alignment=TA_LEFT, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontSize=11, leading=15,
            textColor=colors.HexColor("#555555"), fontName="Helvetica",
            alignment=TA_LEFT, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "section", fontSize=13, leading=18,
            textColor=COLOR_PRIMARY, fontName="Helvetica-Bold",
            spaceBefore=18, spaceAfter=6,
        ),
        "subsection": ParagraphStyle(
            "subsection", fontSize=11, leading=15,
            textColor=COLOR_PRIMARY, fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", fontSize=9, leading=14,
            textColor=colors.HexColor("#222222"), fontName="Helvetica",
            alignment=TA_JUSTIFY, spaceAfter=4,
        ),
        "body_bold": ParagraphStyle(
            "body_bold", fontSize=9, leading=14,
            textColor=COLOR_PRIMARY, fontName="Helvetica-Bold",
            spaceAfter=2,
        ),
        "small": ParagraphStyle(
            "small", fontSize=7.5, leading=11,
            textColor=colors.HexColor("#555555"), fontName="Helvetica",
            spaceAfter=2,
        ),
        "code": ParagraphStyle(
            "code", fontSize=7.5, leading=11,
            textColor=colors.HexColor("#1a1a1a"), fontName="Courier",
            backColor=COLOR_LIGHT_GREY, spaceAfter=4,
            leftIndent=8, rightIndent=8,
        ),
        "bullet": ParagraphStyle(
            "bullet", fontSize=9, leading=13,
            textColor=colors.HexColor("#222222"), fontName="Helvetica",
            leftIndent=12, spaceAfter=3,
        ),
        "legal_issue": ParagraphStyle(
            "legal_issue", fontSize=10, leading=14,
            textColor=COLOR_PRIMARY, fontName="Helvetica-Bold",
            spaceAfter=3,
        ),
        "ref_item": ParagraphStyle(
            "ref_item", fontSize=8, leading=12,
            textColor=colors.HexColor("#444444"), fontName="Helvetica",
            leftIndent=8, spaceAfter=2,
        ),
    }


# ── Utilidades ─────────────────────────────────────────────────────────────────

def hr(color=COLOR_MID_GREY, thickness=0.5):
    return HRFlowable(
        width="100%", thickness=thickness,
        color=color, spaceAfter=6, spaceBefore=4
    )


def risk_row_color(risk: str):
    return {
        "red":    colors.HexColor("#fdecea"),
        "orange": colors.HexColor("#fff3e0"),
        "yellow": colors.HexColor("#fffde7"),
        "green":  colors.HexColor("#f1f8e9"),
    }.get(risk, COLOR_LIGHT_GREY)


# ── Portada ────────────────────────────────────────────────────────────────────

def build_cover(styles, generated_at, max_risk, total_findings, session_hash):
    elements = []
    elements.append(Spacer(1, 1.5 * cm))

    header_data = [[Paragraph(
        "WORKER DIGITAL RIGHTS AUDIT",
        ParagraphStyle("h", fontSize=20, fontName="Helvetica-Bold",
                       textColor=COLOR_WHITE, alignment=TA_CENTER)
    )]]
    header_table = Table(header_data, colWidths=[17 * cm], rowHeights=[1.4 * cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_PRIMARY),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 0.4 * cm))
    elements.append(Paragraph(
        "Informe de Auditoría de Derechos Digitales del Trabajador",
        styles["subtitle"]
    ))
    elements.append(Paragraph(
        "Herramienta de auditoría técnica independiente — uso defensivo",
        styles["small"]
    ))
    elements.append(Spacer(1, 0.8 * cm))
    elements.append(hr(COLOR_PRIMARY, 1))
    elements.append(Spacer(1, 0.6 * cm))

    risk_label = RISK_LABELS.get(max_risk, max_risk.upper())
    meta_data = [
        ["Fecha de generación",       generated_at],
        ["Riesgo máximo detectado",   risk_label],
        ["Total de hallazgos",        str(total_findings)],
        ["Hash de sesión",            session_hash[:32] + "..."],
    ]
    meta_key_style = ParagraphStyle(
        "mk", fontSize=9, fontName="Helvetica-Bold", textColor=COLOR_PRIMARY
    )
    meta_val_style = ParagraphStyle(
        "mv", fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#333333")
    )
    formatted = [
        [Paragraph(k, meta_key_style), Paragraph(v, meta_val_style)]
        for k, v in meta_data
    ]
    meta_table = Table(formatted, colWidths=[5.5 * cm, 11.5 * cm])
    meta_table.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_LIGHT_GREY, COLOR_WHITE]),
        ("GRID",    (0, 0), (-1, -1), 0.3, COLOR_MID_GREY),
        ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 1 * cm))

    elements.append(Paragraph(
        "<b>AVISO:</b> Este informe describe <i>capacidades técnicas detectadas</i>, "
        "no confirma uso indebido. No intercepta tráfico, no escala privilegios, "
        "no exfiltra datos. Para valoración jurídica consulte con asesor laboral.",
        styles["small"]
    ))
    return elements


# ── Tabla resumen ──────────────────────────────────────────────────────────────

def build_summary_table(findings, styles):
    elements = []
    elements.append(Paragraph("Resumen de Hallazgos", styles["section"]))
    elements.append(hr())

    # Contadores por riesgo
    counts = {"red": 0, "orange": 0, "yellow": 0, "green": 0}
    for f in findings:
        r = f.risk_level if hasattr(f, "risk_level") else f.get("risk_level", "green")
        counts[r] = counts.get(r, 0) + 1

    count_data = [[
        Paragraph(f"🔴 Rojo: {counts['red']}", ParagraphStyle(
            "cr", fontSize=10, fontName="Helvetica-Bold", textColor=COLOR_RED, alignment=TA_CENTER
        )),
        Paragraph(f"🟠 Naranja: {counts['orange']}", ParagraphStyle(
            "co", fontSize=10, fontName="Helvetica-Bold", textColor=COLOR_ORANGE, alignment=TA_CENTER
        )),
        Paragraph(f"🟡 Amarillo: {counts['yellow']}", ParagraphStyle(
            "cy", fontSize=10, fontName="Helvetica-Bold", textColor=COLOR_YELLOW, alignment=TA_CENTER
        )),
        Paragraph(f"🟢 Verde: {counts['green']}", ParagraphStyle(
            "cg", fontSize=10, fontName="Helvetica-Bold", textColor=COLOR_GREEN, alignment=TA_CENTER
        )),
    ]]
    count_table = Table(count_data, colWidths=[4.25 * cm] * 4)
    count_table.setStyle(TableStyle([
        ("GRID",   (0, 0), (-1, -1), 0.5, COLOR_MID_GREY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_LIGHT_GREY),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(count_table)
    elements.append(Spacer(1, 0.4 * cm))

    # Tabla de hallazgos
    header_style = ParagraphStyle(
        "th", fontSize=8, fontName="Helvetica-Bold",
        textColor=COLOR_WHITE, alignment=TA_CENTER
    )
    cell_style = ParagraphStyle(
        "td", fontSize=8, fontName="Helvetica",
        textColor=colors.HexColor("#222222")
    )

    rows = [[
        Paragraph("Skill",     header_style),
        Paragraph("Hallazgo",  header_style),
        Paragraph("Categoría", header_style),
        Paragraph("Riesgo",    header_style),
    ]]

    for f in findings:
        risk  = f.risk_level if hasattr(f, "risk_level") else f.get("risk_level", "green")
        title = f.title      if hasattr(f, "title")      else f.get("title", "")
        skill = f.skill      if hasattr(f, "skill")      else f.get("skill", "")
        cat   = f.category   if hasattr(f, "category")   else f.get("category", "")

        risk_color = RISK_COLORS.get(risk, COLOR_MID_GREY)
        risk_para = Paragraph(risk.upper(), ParagraphStyle(
            "r", fontSize=8, fontName="Helvetica-Bold",
            textColor=risk_color, alignment=TA_CENTER
        ))
        rows.append([
            Paragraph(skill.replace("_", " "), cell_style),
            Paragraph(str(title)[:70],         cell_style),
            Paragraph(str(cat).replace("_", " "), cell_style),
            risk_para,
        ])

    col_widths = [3.5 * cm, 8 * cm, 3.5 * cm, 2 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), COLOR_PRIMARY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_LIGHT_GREY, COLOR_WHITE]),
        ("GRID",   (0, 0), (-1, -1), 0.3, COLOR_MID_GREY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    elements.append(table)
    return elements


# ── Detalle de hallazgos — SIN referencias legales ni recomendaciones ──────────

def build_findings_detail(findings, styles):
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph("Detalle Técnico de Hallazgos", styles["section"]))
    elements.append(Paragraph(
        "Descripción técnica de cada hallazgo. "
        "Las referencias legales y recomendaciones se consolidan en la sección siguiente.",
        styles["small"]
    ))
    elements.append(hr(COLOR_PRIMARY, 1))

    for i, f in enumerate(findings, 1):
        risk  = f.risk_level if hasattr(f, "risk_level") else f.get("risk_level", "green")
        title = f.title      if hasattr(f, "title")      else f.get("title", "")
        skill = f.skill      if hasattr(f, "skill")      else f.get("skill", "")
        cat   = f.category   if hasattr(f, "category")   else f.get("category", "")
        ts    = f.timestamp  if hasattr(f, "timestamp")  else f.get("timestamp", "")

        what_is     = f.what_it_is     if hasattr(f, "what_it_is")     else f.get("what_it_is", "")
        what_is_not = f.what_it_is_not if hasattr(f, "what_it_is_not") else f.get("what_it_is_not", "")
        tech_risk   = f.technical_risk if hasattr(f, "technical_risk") else f.get("technical_risk", "")

        risk_color = RISK_COLORS.get(risk, COLOR_MID_GREY)
        block = []

        # Encabezado
        title_data = [[
            Paragraph(f"#{i} — {title}", ParagraphStyle(
                "ft", fontSize=10, fontName="Helvetica-Bold", textColor=COLOR_WHITE
            )),
            Paragraph(risk.upper(), ParagraphStyle(
                "fr", fontSize=9, fontName="Helvetica-Bold",
                textColor=COLOR_WHITE, alignment=TA_CENTER
            )),
        ]]
        title_table = Table(
            title_data,
            colWidths=[13.5 * cm, 3.5 * cm],
            rowHeights=[0.75 * cm]
        )
        title_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), risk_color),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (0, 0),  8),
        ]))
        block.append(title_table)
        block.append(Spacer(1, 0.15 * cm))

        # Metadatos en una línea
        block.append(Paragraph(
            f"<b>Skill:</b> {skill}  ·  "
            f"<b>Categoría:</b> {cat}  ·  "
            f"<b>Fecha:</b> {str(ts)[:16].replace('T', ' ')}",
            styles["small"]
        ))
        block.append(Spacer(1, 0.15 * cm))

        # Solo campos técnicos — sin referencias ni recomendaciones
        for label, text in [
            ("Qué es",          what_is),
            ("Qué NO implica",  what_is_not),
            ("Riesgo técnico",  tech_risk),
        ]:
            if text:
                block.append(Paragraph(f"<b>{label}:</b>", styles["body_bold"]))
                block.append(Paragraph(str(text), styles["body"]))

        block.append(Spacer(1, 0.2 * cm))
        block.append(hr())
        elements.append(KeepTogether(block))

    return elements


# ── Evaluación legal consolidada ───────────────────────────────────────────────

def build_legal_section(legal_issues, styles, recommendation_context=None):
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph("Evaluación Legal", styles["section"]))
    elements.append(hr(COLOR_PRIMARY, 1))

    if not legal_issues:
        elements.append(Paragraph(
            "No se han detectado conflictos legales significativos.",
            styles["body"]
        ))
        return elements

    # Ordenar por riesgo
    risk_order = {"low": 0, "medium": 1, "medium-high": 2, "high": 3, "very_high": 4}
    sorted_issues = sorted(
        legal_issues,
        key=lambda x: risk_order.get(x.get("legal_risk", "low"), 0),
        reverse=True
    )

    # ── Issues ─────────────────────────────────────────────────────────────────
    elements.append(Paragraph("Conflictos detectados", styles["subsection"]))
    elements.append(Spacer(1, 0.2 * cm))

    for i, issue in enumerate(sorted_issues, 1):
        legal_risk = issue.get("legal_risk", "low")
        risk_color = {
            "low": COLOR_GREEN, "medium": COLOR_YELLOW,
            "medium-high": COLOR_ORANGE, "high": COLOR_RED,
            "very_high": COLOR_RED,
        }.get(legal_risk, COLOR_MID_GREY)

        block = []

        # Título issue
        title_data = [[
            Paragraph(f"{i}. {issue.get('issue', '')}", ParagraphStyle(
                "lt", fontSize=10, fontName="Helvetica-Bold", textColor=COLOR_WHITE
            )),
            Paragraph(legal_risk.upper(), ParagraphStyle(
                "lr", fontSize=8, fontName="Helvetica-Bold",
                textColor=COLOR_WHITE, alignment=TA_CENTER
            )),
        ]]
        title_table = Table(
            title_data,
            colWidths=[13.5 * cm, 3.5 * cm],
            rowHeights=[0.7 * cm]
        )
        title_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), risk_color),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (0, 0),  8),
        ]))
        block.append(title_table)
        block.append(Spacer(1, 0.15 * cm))
        block.append(Paragraph(str(issue.get("reason", "")), styles["body"]))
        block.append(Spacer(1, 0.2 * cm))
        block.append(hr())
        elements.append(KeepTogether(block))

    # ── Plan de acción consolidado ─────────────────────────────────────────────
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph("Plan de acción", styles["subsection"]))
    elements.append(Paragraph(
        "Recomendaciones agrupadas por destinatario. "
        "Envía las solicitudes por email y guarda copia.",
        styles["small"]
    ))
    elements.append(Spacer(1, 0.3 * cm))

    # Recoger todas las recomendaciones sin duplicados
    all_recs = []
    seen_recs = set()
    for issue in sorted_issues:
        for rec in issue.get("recommendations", []):
            if rec not in seen_recs:
                seen_recs.add(rec)
                all_recs.append(rec)

    # Clasificar por destinatario
    grupos = {
        "Al DPO (Delegado de Protección de Datos)": [],
        "A IT / Soporte técnico": [],
        "Al empleador / RRHH": [],
        "Al asesor laboral o sindicato": [],
        "Acción del trabajador": [],
    }
    for rec in all_recs:
        r = rec.lower()
        if any(k in r for k in ["dpo", "dpa", "rgpd", "dpia", "base legal", "registro de actividades", "subencargados"]):
            grupos["Al DPO (Delegado de Protección de Datos)"].append(rec)
        elif any(k in r for k in ["it ", "gpo", "bitlocker", "activar", "deshabilitar", "it que", "política gpo"]):
            grupos["A IT / Soporte técnico"].append(rec)
        elif any(k in r for k in ["empleador", "rrhh", "contrato", "convenio", "política de uso", "aup", "inventario"]):
            grupos["Al empleador / RRHH"].append(rec)
        elif any(k in r for k in ["asesor", "laboral", "sindicato", "aepd", "itss", "juzgado", "consultar"]):
            grupos["Al asesor laboral o sindicato"].append(rec)
        else:
            grupos["Acción del trabajador"].append(rec)

    for destinatario, recs in grupos.items():
        if not recs:
            continue
        elements.append(Paragraph(f"→ {destinatario}", styles["body_bold"]))
        for rec in recs:
            elements.append(Paragraph(f"• {rec}", styles["bullet"]))
        elements.append(Spacer(1, 0.3 * cm))

    # ── Referencias legales consolidadas ───────────────────────────────────────
    elements.append(PageBreak())
    elements.append(Paragraph("Referencias legales", styles["subsection"]))
    elements.append(hr())

    # Recoger referencias únicas
    refs_vistas = set()
    refs_unicas = []
    for issue in sorted_issues:
        for ref in issue.get("references", []):
            ref_id = ref.get("id", "")
            if ref_id and ref_id not in refs_vistas:
                refs_vistas.add(ref_id)
                refs_unicas.append(ref)

    if refs_unicas:
        ref_data = [[
            Paragraph("<b>Norma</b>", ParagraphStyle(
                "rh", fontSize=8, fontName="Helvetica-Bold", textColor=COLOR_WHITE
            )),
            Paragraph("<b>Descripción</b>", ParagraphStyle(
                "rd", fontSize=8, fontName="Helvetica-Bold", textColor=COLOR_WHITE
            )),
        ]]
        for ref in refs_unicas:
            name    = ref.get("name", ref.get("id", ""))
            summary = ref.get("summary", "")
            url     = ref.get("url", "")
            ref_data.append([
                Paragraph(name, styles["ref_item"]),
                Paragraph(
                    f"{summary}" + (f" <i>({url})</i>" if url else ""),
                    styles["ref_item"]
                ),
            ])

        ref_table = Table(ref_data, colWidths=[5.5 * cm, 11.5 * cm])
        ref_table.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), COLOR_PRIMARY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_LIGHT_GREY, COLOR_WHITE]),
            ("GRID",   (0, 0), (-1, -1), 0.3, COLOR_MID_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        elements.append(ref_table)

    return elements


# ── Pie de integridad ──────────────────────────────────────────────────────────

def build_integrity_footer(content_hash, styles):
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph("Integridad del Informe", styles["section"]))
    elements.append(hr(COLOR_PRIMARY, 1))
    elements.append(Paragraph(
        "Este informe incluye un hash SHA-256 que permite verificar "
        "que no ha sido modificado desde su generación.",
        styles["body"]
    ))
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph("<b>SHA-256:</b>", styles["body_bold"]))
    elements.append(Paragraph(content_hash, styles["code"]))
    elements.append(Spacer(1, 0.4 * cm))
    elements.append(Paragraph(
        "Para verificar en Windows: <b>certutil -hashfile audit.json SHA256</b><br/>"
        "Compara el resultado con el valor anterior.",
        styles["small"]
    ))
    return elements


# ── Función principal ──────────────────────────────────────────────────────────

def export_pdf(
    findings: list,
    legal_issues: list,
    out_path: Path,
    recommendation_context: dict | None = None,
) -> Path:
    """Genera el informe PDF técnico/sindicato."""
    styles = build_styles()

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_order   = ["green", "yellow", "orange", "red"]
    max_risk     = max(
        (f.risk_level if hasattr(f, "risk_level") else f.get("risk_level", "green")
         for f in findings),
        key=lambda x: risk_order.index(x) if x in risk_order else 0,
        default="green"
    )

    session_hash = hashlib.sha256(
        (generated_at + str(len(findings))).encode()
    ).hexdigest()

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm,  bottomMargin=2 * cm,
        title="Worker Digital Rights Audit Report",
        author="Worker Digital Rights Audit Agent",
    )

    story = []
    story += build_cover(styles, generated_at, max_risk, len(findings), session_hash)
    story.append(PageBreak())
    story += build_summary_table(findings, styles)
    story += build_findings_detail(findings, styles)
    story += build_legal_section(legal_issues, styles, recommendation_context)
    story += build_integrity_footer(session_hash, styles)

    doc.build(story)
    return out_path