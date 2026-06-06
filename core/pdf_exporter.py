# core/pdf_exporter.py
"""Exportador PDF forense para generar informes presentables."""

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
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

# ── Paleta de colores ──────────────────────────────────────────────────────────

COLOR_PRIMARY    = colors.HexColor("#1a1a2e")
COLOR_ACCENT     = colors.HexColor("#16213e")
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
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "title",
            fontSize=22, leading=28,
            textColor=COLOR_PRIMARY,
            fontName="Helvetica-Bold",
            alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontSize=11, leading=15,
            textColor=colors.HexColor("#555555"),
            fontName="Helvetica",
            alignment=TA_LEFT,
            spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "section",
            fontSize=13, leading=18,
            textColor=COLOR_PRIMARY,
            fontName="Helvetica-Bold",
            spaceBefore=18, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=9, leading=14,
            textColor=colors.HexColor("#222222"),
            fontName="Helvetica",
            alignment=TA_JUSTIFY,
            spaceAfter=4,
        ),
        "body_bold": ParagraphStyle(
            "body_bold",
            fontSize=9, leading=14,
            textColor=COLOR_PRIMARY,
            fontName="Helvetica-Bold",
            spaceAfter=2,
        ),
        "small": ParagraphStyle(
            "small",
            fontSize=7.5, leading=11,
            textColor=colors.HexColor("#555555"),
            fontName="Helvetica",
            spaceAfter=2,
        ),
        "code": ParagraphStyle(
            "code",
            fontSize=7.5, leading=11,
            textColor=colors.HexColor("#1a1a1a"),
            fontName="Courier",
            backColor=COLOR_LIGHT_GREY,
            spaceAfter=4,
            leftIndent=8, rightIndent=8,
        ),
        "risk_label": ParagraphStyle(
            "risk_label",
            fontSize=9, leading=12,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "finding_title": ParagraphStyle(
            "finding_title",
            fontSize=10, leading=14,
            textColor=COLOR_PRIMARY,
            fontName="Helvetica-Bold",
            spaceAfter=3,
        ),
        "tag": ParagraphStyle(
            "tag",
            fontSize=8, leading=10,
            fontName="Helvetica",
            textColor=colors.HexColor("#444444"),
            spaceAfter=2,
        ),
    }
    return styles


# ── Utilidades ─────────────────────────────────────────────────────────────────

def risk_badge(risk: str, styles: dict):
    color = RISK_COLORS.get(risk, COLOR_MID_GREY)
    label = risk.upper()
    style = ParagraphStyle(
        "badge",
        fontSize=8, leading=10,
        fontName="Helvetica-Bold",
        textColor=COLOR_WHITE,
        alignment=TA_CENTER,
    )
    data = [[Paragraph(label, style)]]
    t = Table(data, colWidths=[2.2 * cm], rowHeights=[0.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [4]),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def hr(color=COLOR_MID_GREY, thickness=0.5):
    return HRFlowable(
        width="100%", thickness=thickness,
        color=color, spaceAfter=6, spaceBefore=4
    )


# ── Secciones del PDF ──────────────────────────────────────────────────────────

def build_cover(styles, generated_at, max_risk, total_findings, machine_hash):
    elements = []

    elements.append(Spacer(1, 1.5 * cm))

    # Franja de color superior simulada con una tabla
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

    # Resumen ejecutivo en formato tabla
    risk_color = RISK_COLORS.get(max_risk, COLOR_MID_GREY)
    risk_label = RISK_LABELS.get(max_risk, max_risk.upper())

    meta_data = [
        ["Fecha de generación", generated_at],
        ["Riesgo máximo detectado", risk_label],
        ["Total de hallazgos", str(total_findings)],
        ["Hash de sesión (integridad)", machine_hash[:32] + "..."],
    ]

    meta_style_key = ParagraphStyle(
        "mk", fontSize=9, fontName="Helvetica-Bold",
        textColor=COLOR_PRIMARY
    )
    meta_style_val = ParagraphStyle(
        "mv", fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#333333")
    )

    formatted = [
        [Paragraph(k, meta_style_key), Paragraph(v, meta_style_val)]
        for k, v in meta_data
    ]

    meta_table = Table(formatted, colWidths=[5.5 * cm, 11.5 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), COLOR_LIGHT_GREY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [COLOR_LIGHT_GREY, COLOR_WHITE]),
        ("GRID",    (0, 0), (-1, -1), 0.3, COLOR_MID_GREY),
        ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 1 * cm))

    # Aviso legal
    disclaimer = (
        "<b>AVISO:</b> Este informe ha sido generado de forma automática mediante "
        "análisis de configuración local del sistema. No intercepta tráfico de red, "
        "no escala privilegios, no exfiltra datos ni compromete la infraestructura. "
        "Los hallazgos describen <i>capacidades técnicas detectadas</i>, "
        "no confirman uso indebido. Para valoración jurídica, consulte con "
        "asesor laboral especializado."
    )
    elements.append(Paragraph(disclaimer, styles["small"]))

    return elements


def build_summary_table(findings, styles):
    elements = []
    elements.append(Paragraph("Resumen de Hallazgos", styles["section"]))
    elements.append(hr())

    header_style = ParagraphStyle(
        "th", fontSize=8, fontName="Helvetica-Bold",
        textColor=COLOR_WHITE, alignment=TA_CENTER
    )
    cell_style = ParagraphStyle(
        "td", fontSize=8, fontName="Helvetica",
        textColor=colors.HexColor("#222222")
    )
    risk_cell = ParagraphStyle(
        "rc", fontSize=8, fontName="Helvetica-Bold",
        alignment=TA_CENTER
    )

    rows = [[
        Paragraph("Skill", header_style),
        Paragraph("Hallazgo", header_style),
        Paragraph("Categoría", header_style),
        Paragraph("Riesgo", header_style),
    ]]

    for f in findings:
        risk_color = RISK_COLORS.get(f.risk_level, COLOR_MID_GREY)
        risk_para = Paragraph(
            f.risk_level.upper(),
            ParagraphStyle("r", fontSize=8, fontName="Helvetica-Bold",
                           textColor=risk_color, alignment=TA_CENTER)
        )
        rows.append([
            Paragraph(f.skill.replace("_", " "), cell_style),
            Paragraph(f.title[:70], cell_style),
            Paragraph(f.category.replace("_", " "), cell_style),
            risk_para,
        ])

    col_widths = [3.5 * cm, 8 * cm, 3.5 * cm, 2 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), COLOR_PRIMARY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [COLOR_LIGHT_GREY, COLOR_WHITE]),
        ("GRID",   (0, 0), (-1, -1), 0.3, COLOR_MID_GREY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))

    elements.append(table)
    return elements


def build_findings_detail(findings, styles):
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph("Detalle de Hallazgos", styles["section"]))
    elements.append(hr(COLOR_PRIMARY, 1))

    for i, f in enumerate(findings, 1):
        risk_color = RISK_COLORS.get(f.risk_level, COLOR_MID_GREY)

        block = []

        # Encabezado del hallazgo
        title_data = [[
            Paragraph(f"#{i} — {f.title}", ParagraphStyle(
                "ft", fontSize=10, fontName="Helvetica-Bold",
                textColor=COLOR_WHITE
            )),
            Paragraph(f.risk_level.upper(), ParagraphStyle(
                "fr", fontSize=9, fontName="Helvetica-Bold",
                textColor=COLOR_WHITE, alignment=TA_CENTER
            )),
        ]]
        title_table = Table(
            title_data, colWidths=[13.5 * cm, 3.5 * cm],
            rowHeights=[0.75 * cm]
        )
        title_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), risk_color),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (0, 0),  8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        block.append(title_table)
        block.append(Spacer(1, 0.2 * cm))

        # Metadatos
        block.append(Paragraph(
            f"<b>Skill:</b> {f.skill}  |  "
            f"<b>Categoría:</b> {f.category}  |  "
            f"<b>Timestamp:</b> {f.timestamp}",
            styles["small"]
        ))
        block.append(Spacer(1, 0.15 * cm))

        # Campos explicativos
        fields = [
            ("Qué es", f.what_it_is),
            ("Qué NO implica", f.what_it_is_not),
            ("Riesgo técnico", f.technical_risk),
            ("Riesgo jurídico", f.legal_risk),
        ]
        for label, text in fields:
            if text:
                block.append(Paragraph(f"<b>{label}:</b>", styles["body_bold"]))
                block.append(Paragraph(text, styles["body"]))

        block.append(Spacer(1, 0.3 * cm))
        block.append(hr())

        elements.append(KeepTogether(block))

    return elements


def build_legal_section(legal_issues, styles, recommendation_context: dict | None = None):
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph("Evaluación Legal", styles["section"]))
    elements.append(hr(COLOR_PRIMARY, 1))

    mode = (recommendation_context or {}).get("mode", "completo")
    categories = (recommendation_context or {}).get("categories", [])
    risks = (recommendation_context or {}).get("risks", [])

    mode_text = (
        f"<b>Modo de recomendaciones:</b> {mode}. "
        f"<b>Filtros por categoría:</b> {', '.join(categories) if categories else '—'}. "
        f"<b>Filtros por riesgo:</b> {', '.join(risks) if risks else '—'}."
    )
    elements.append(Paragraph(mode_text, styles["small"]))
    elements.append(Spacer(1, 0.15 * cm))

    if not legal_issues:
        elements.append(Paragraph(
            "No se han detectado conflictos legales significativos. "
            "La configuración parece corresponder a seguridad corporativa "
            "estándar dentro de los límites habituales.",
            styles["body"]
        ))
        return elements

    risk_order = {"low": 0, "medium": 1, "medium-high": 2,
                  "high": 3, "very_high": 4}
    sorted_issues = sorted(
        legal_issues,
        key=lambda x: risk_order.get(x["legal_risk"], 0),
        reverse=True
    )

    for i, issue in enumerate(sorted_issues, 1):
        risk_color = {
            "low": COLOR_GREEN, "medium": COLOR_YELLOW,
            "medium-high": COLOR_ORANGE, "high": COLOR_RED,
            "very_high": COLOR_RED
        }.get(issue["legal_risk"], COLOR_MID_GREY)

        block = []

        # Título con badge de riesgo
        title_data = [[
            Paragraph(issue["issue"], ParagraphStyle(
                "lt", fontSize=10, fontName="Helvetica-Bold",
                textColor=COLOR_WHITE
            )),
            Paragraph(issue["legal_risk"].upper(), ParagraphStyle(
                "lr", fontSize=8, fontName="Helvetica-Bold",
                textColor=COLOR_WHITE, alignment=TA_CENTER
            )),
        ]]
        title_table = Table(
            title_data, colWidths=[13.5 * cm, 3.5 * cm],
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
        block.append(Spacer(1, 0.2 * cm))

        block.append(Paragraph(issue["reason"], styles["body"]))

        # Referencias legales
        if issue.get("references"):
            block.append(Spacer(1, 0.15 * cm))
            block.append(Paragraph("<b>Referencias legales:</b>", styles["body_bold"]))
            for ref in issue["references"]:
                name = ref.get("name", ref.get("id", ""))
                summary = ref.get("summary", "")
                if name:
                    block.append(Paragraph(
                        f"• <b>{name}:</b> {summary}", styles["small"]
                    ))

        # Recomendaciones
        if issue.get("recommendations"):
            block.append(Spacer(1, 0.15 * cm))
            block.append(Paragraph("<b>Recomendaciones:</b>", styles["body_bold"]))
            for rec in issue["recommendations"]:
                block.append(Paragraph(f"• {rec}", styles["body"]))

        block.append(Spacer(1, 0.3 * cm))
        block.append(hr())
        elements.append(KeepTogether(block))

    return elements


def build_integrity_footer(content_hash, styles):
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph("Integridad del Informe", styles["section"]))
    elements.append(hr(COLOR_PRIMARY, 1))
    elements.append(Paragraph(
        "Este informe incluye un hash SHA-256 de su contenido para "
        "verificar que no ha sido modificado desde su generación.",
        styles["body"]
    ))
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph(
        f"<b>SHA-256 del contenido:</b>", styles["body_bold"]
    ))
    elements.append(Paragraph(content_hash, styles["code"]))
    elements.append(Spacer(1, 0.5 * cm))
    elements.append(Paragraph(
        "Para verificar la integridad, recalcule el hash del archivo JSON "
        "exportado junto a este informe y compárelo con el valor anterior.",
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
    """
    Genera el informe PDF forense completo.
    """
    styles = build_styles()

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_order = ["green", "yellow", "orange", "red"]
    max_risk = max(
        (f.risk_level for f in findings),
        key=lambda x: risk_order.index(x) if x in risk_order else 0,
        default="green"
    )

    # Hash de sesión
    session_data = generated_at + str(len(findings))
    session_hash = hashlib.sha256(session_data.encode()).hexdigest()

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title="Worker Digital Rights Audit Report",
        author="Worker Digital Rights Audit Agent",
    )

    story = []
    story += build_cover(
        styles, generated_at, max_risk,
        len(findings), session_hash
    )
    story.append(PageBreak())
    story += build_summary_table(findings, styles)
    story += build_findings_detail(findings, styles)
    story += build_legal_section(legal_issues, styles, recommendation_context)
    story += build_integrity_footer(session_hash, styles)

    doc.build(story)
    return out_path