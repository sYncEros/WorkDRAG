# core/pdf_trabajador.py
"""
PDF Trabajador — versión para el trabajador sin conocimientos técnicos.
Una página por sección, lenguaje claro, semáforo visual, acciones concretas.
Sin repetición de referencias legales en cada hallazgo.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import Flowable
from pathlib import Path
from datetime import datetime
import hashlib
import json


# ── Paleta de colores ──────────────────────────────────────────────────────────

ROJO       = colors.HexColor("#C0392B")
NARANJA    = colors.HexColor("#E67E22")
AMARILLO   = colors.HexColor("#F1C40F")
VERDE      = colors.HexColor("#27AE60")
GRIS_DARK  = colors.HexColor("#2C3E50")
GRIS_MED   = colors.HexColor("#7F8C8D")
GRIS_LIGHT = colors.HexColor("#ECF0F1")
BLANCO     = colors.white
AZUL       = colors.HexColor("#2980B9")

W, H = A4  # 210 x 297 mm


# ── Estilos ────────────────────────────────────────────────────────────────────

def _styles():
    return {
        "titulo": ParagraphStyle(
            "titulo",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=GRIS_DARK,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "subtitulo": ParagraphStyle(
            "subtitulo",
            fontName="Helvetica",
            fontSize=11,
            textColor=GRIS_MED,
            alignment=TA_CENTER,
            spaceAfter=16,
        ),
        "seccion": ParagraphStyle(
            "seccion",
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=GRIS_DARK,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "hallazgo_titulo": ParagraphStyle(
            "hallazgo_titulo",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=GRIS_DARK,
            spaceAfter=2,
        ),
        "hallazgo_desc": ParagraphStyle(
            "hallazgo_desc",
            fontName="Helvetica",
            fontSize=9,
            textColor=GRIS_MED,
            spaceAfter=6,
            leading=13,
        ),
        "accion_titulo": ParagraphStyle(
            "accion_titulo",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=AZUL,
            spaceBefore=8,
            spaceAfter=3,
        ),
        "accion_item": ParagraphStyle(
            "accion_item",
            fontName="Helvetica",
            fontSize=9,
            textColor=GRIS_DARK,
            leftIndent=12,
            spaceAfter=3,
            leading=13,
        ),
        "pie": ParagraphStyle(
            "pie",
            fontName="Helvetica",
            fontSize=7,
            textColor=GRIS_MED,
            alignment=TA_CENTER,
        ),
        "nota": ParagraphStyle(
            "nota",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=GRIS_MED,
            alignment=TA_CENTER,
            spaceBefore=8,
        ),
        "numero_grande": ParagraphStyle(
            "numero_grande",
            fontName="Helvetica-Bold",
            fontSize=36,
            alignment=TA_CENTER,
        ),
        "etiqueta": ParagraphStyle(
            "etiqueta",
            fontName="Helvetica",
            fontSize=9,
            alignment=TA_CENTER,
            textColor=GRIS_MED,
        ),
    }


# ── Componentes visuales ───────────────────────────────────────────────────────

class SemaforoBloque(Flowable):
    """Semáforo visual grande con contadores."""

    def __init__(self, n_red, n_orange, n_yellow, n_green):
        super().__init__()
        self.n_red    = n_red
        self.n_orange = n_orange
        self.n_yellow = n_yellow
        self.n_green  = n_green
        self.width    = W - 40*mm
        self.height   = 38*mm

    def draw(self):
        c = self.canv
        col_w = self.width / 4
        items = [
            (ROJO,    self.n_red,    "ALTO"),
            (NARANJA, self.n_orange, "MEDIO-ALTO"),
            (AMARILLO,self.n_yellow, "MEDIO"),
            (VERDE,   self.n_green,  "INFORMATIVO"),
        ]
        for i, (color, count, label) in enumerate(items):
            x = i * col_w
            # Fondo
            c.setFillColor(color)
            c.setStrokeColor(colors.white)
            c.roundRect(x + 3*mm, 8*mm, col_w - 6*mm, 28*mm, 4*mm, fill=1)
            # Número
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 28)
            c.drawCentredString(x + col_w/2, 22*mm, str(count))
            # Etiqueta
            c.setFont("Helvetica", 7)
            c.drawCentredString(x + col_w/2, 10*mm, label)


class LineaDivisora(Flowable):
    def __init__(self, color=GRIS_LIGHT, width=None):
        super().__init__()
        self.color = color
        self.width = width or (W - 40*mm)
        self.height = 1

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(0.5)
        self.canv.line(0, 0, self.width, 0)


class BloqueHallazgo(Flowable):
    """Hallazgo compacto con indicador de color lateral."""

    def __init__(self, titulo, descripcion, accion, risk_level, styles):
        super().__init__()
        self.titulo      = titulo
        self.descripcion = descripcion
        self.accion      = accion
        self.risk_level  = risk_level
        self.styles      = styles
        self.width       = W - 40*mm
        self.height      = 26*mm

    def draw(self):
        c = self.canv
        color_map = {
            "red": ROJO, "orange": NARANJA,
            "yellow": AMARILLO, "green": VERDE,
        }
        color = color_map.get(self.risk_level, GRIS_MED)

        # Barra lateral
        c.setFillColor(color)
        c.rect(0, 0, 3*mm, self.height, fill=1, stroke=0)

        # Fondo bloque
        c.setFillColor(GRIS_LIGHT)
        c.rect(3*mm, 0, self.width - 3*mm, self.height, fill=1, stroke=0)

        # Título
        c.setFillColor(GRIS_DARK)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(6*mm, self.height - 7*mm, self.titulo[:80])

        # Descripción
        c.setFillColor(GRIS_MED)
        c.setFont("Helvetica", 8)
        desc = self.descripcion[:140] + "..." if len(self.descripcion) > 140 else self.descripcion
        c.drawString(6*mm, self.height - 13*mm, desc[:80])
        if len(desc) > 80:
            c.drawString(6*mm, self.height - 18*mm, desc[80:160])

        # Acción
        if self.accion:
            c.setFillColor(AZUL)
            c.setFont("Helvetica-Bold", 7.5)
            c.drawString(6*mm, 3*mm, f"→ {self.accion[:90]}")


# ── Lógica de traducción ───────────────────────────────────────────────────────

# Mapa de categorías técnicas a lenguaje humano
CATEGORIA_HUMANA = {
    "telemetry_windows_level":    ("Tu equipo envía datos a Microsoft continuamente",
                                   "Pide al DPO la base legal de esta transferencia"),
    "telemetry_services":         ("El servicio DiagTrack está activo enviando datos",
                                   "Pide a IT que lo desactive mediante política"),
    "cloud_sync_folder_redirect": ("Tus carpetas principales se sincronizan automáticamente con la nube corporativa",
                                   "No guardes archivos personales en Escritorio o Documentos"),
    "cloud_sync_policy":          ("No puedes desactivar la sincronización con OneDrive",
                                   "Solicita información sobre las políticas GPO activas"),
    "onedrive_folder_map":        ("7 carpetas de tu equipo están en la nube de tu empresa",
                                   "Usa C:\\TrabajoLocal para archivos personales"),
    "onedrive_kfm_block":         ("La empresa bloquea que puedas desactivar OneDrive",
                                   "Solicita al DPO justificación legal de este bloqueo"),
    "hardening_encryption":       ("Tu disco duro NO está cifrado — si te roban el equipo, todo es accesible",
                                   "Pide a IT que activen BitLocker inmediatamente"),
    "identity_remote_access":     ("El acceso remoto a tu equipo está habilitado",
                                   "Pide política de acceso remoto documentada por escrito"),
    "identity_suspicious_account":("Hay cuentas con privilegios elevados sin documentar",
                                   "Solicita inventario oficial de cuentas y su justificación"),
    "addon_office_capabilities":  ("Hay add-ins de Outlook con acceso completo a tus emails",
                                   "Pide listado de add-ins instalados y qué datos acceden"),
    "dpa_telemetry_noncompliant": ("El nivel de telemetría no cumple las recomendaciones de la AEPD",
                                   "Pide al DPO copia del DPA con Microsoft"),
    "hardener_gpo_blocked":       ("La empresa bloquea activamente que reduzcas la telemetría",
                                   "Documenta este bloqueo como evidencia forense"),
    "ssl_inspection":             ("Tu tráfico HTTPS puede ser descifrado por la empresa",
                                   "No uses el equipo corporativo para comunicaciones privadas"),
    "ps_scriptblock_logging":     ("Todos tus comandos en PowerShell quedan registrados",
                                   "Pide al DPO finalidad y retención de estos logs"),
    "behavior_logging_capabilities":("Tu actividad técnica se registra de forma centralizada",
                                   "Solicita DPIA si se usa para evaluar tu desempeño"),
    "identity_stored_credentials":("Hay 44 credenciales almacenadas accesibles para administradores",
                                   "No guardes contraseñas personales en el gestor del sistema"),
    "clipboard_rdp_shared":       ("El portapapeles es accesible durante sesiones remotas",
                                   "No copies contraseñas mientras haya sesiones RDP activas"),
    "dpa_additional_providers":   ("CrowdStrike y Zscaler están activos y requieren DPA propio",
                                   "Pide al DPO listado de todos los subencargados de tratamiento"),
    "ai_connected_experiences":   ("Office envía contenido de documentos a Microsoft para IA",
                                   "Pide al DPO el DPA con Microsoft y desactiva experiencias no necesarias"),
    "browser_forced_extensions":  ("Hay extensiones de navegador instaladas por la empresa que no puedes desinstalar",
                                   "Pide a IT la función exacta de cada extensión forzada"),
}

def _titulo_humano(finding: dict) -> tuple[str, str]:
    """Devuelve (título humano, acción concreta) para un hallazgo."""
    cat = finding.get("category", "")
    if cat in CATEGORIA_HUMANA:
        return CATEGORIA_HUMANA[cat]
    # Fallback: usar el título técnico simplificado
    titulo = finding.get("title", "Hallazgo detectado")
    # Quitar jerga técnica básica
    for term in ["detectado", "activo", "habilitado", "configurado"]:
        titulo = titulo.replace(f" — {term}", "").replace(f" ({term})", "")
    accion = ""
    recs = finding.get("recommendations", [])
    if recs:
        accion = recs[0] if isinstance(recs, list) else ""
    return titulo[:80], accion


# ── Generador del PDF ──────────────────────────────────────────────────────────

def export_pdf_trabajador(
    findings: list,
    legal_issues: list,
    output_path: Path,
    audit_hash: str = "",
    generated_at: str = "",
):
    """Genera el PDF versión trabajador."""

    st = _styles()
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm,
    )

    # Contadores
    n_red    = sum(1 for f in findings if f.get("risk_level") == "red")
    n_orange = sum(1 for f in findings if f.get("risk_level") == "orange")
    n_yellow = sum(1 for f in findings if f.get("risk_level") == "yellow")
    n_green  = sum(1 for f in findings if f.get("risk_level") == "green")

    fecha = generated_at[:10] if generated_at else datetime.now().strftime("%Y-%m-%d")
    story = []

    # ── PORTADA ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("Informe de Derechos Digitales", st["titulo"]))
    story.append(Paragraph(
        f"Auditoría realizada el {fecha} · WorkDRAG",
        st["subtitulo"]
    ))
    story.append(Spacer(1, 4*mm))

    # Semáforo
    story.append(SemaforoBloque(n_red, n_orange, n_yellow, n_green))
    story.append(Spacer(1, 6*mm))

    # Explicación del semáforo
    tabla_semaforo = Table(
        [[
            Paragraph("<b>ALTO</b><br/>Requiere acción inmediata", st["etiqueta"]),
            Paragraph("<b>MEDIO-ALTO</b><br/>Pide explicaciones por escrito", st["etiqueta"]),
            Paragraph("<b>MEDIO</b><br/>Ten en cuenta estas capacidades", st["etiqueta"]),
            Paragraph("<b>INFORMATIVO</b><br/>Sin riesgo relevante", st["etiqueta"]),
        ]],
        colWidths=[(W - 40*mm) / 4] * 4,
    )
    tabla_semaforo.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(tabla_semaforo)
    story.append(Spacer(1, 6*mm))
    story.append(LineaDivisora())

    # Nota introductoria
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        "Esta herramienta detecta <b>capacidades técnicas</b> de monitorización en tu equipo. "
        "No prueba que la empresa haya leído tus datos — pero sí que tiene la capacidad técnica para hacerlo. "
        "Tienes derecho a pedir explicaciones.",
        st["hallazgo_desc"]
    ))
    story.append(Spacer(1, 4*mm))

    # ── SECCIÓN 1: LO QUE DETECTAMOS ──────────────────────────────────────────
    story.append(Paragraph("Lo que hemos detectado en tu equipo", st["seccion"]))
    story.append(Spacer(1, 2*mm))

    # Solo hallazgos RED y ORANGE en lenguaje humano
    hallazgos_relevantes = [
        f for f in findings
        if f.get("risk_level") in ("red", "orange")
    ]

    # Eliminar duplicados por categoría
    seen_cats = set()
    hallazgos_unicos = []
    for f in hallazgos_relevantes:
        cat = f.get("category", "")
        if cat not in seen_cats:
            seen_cats.add(cat)
            hallazgos_unicos.append(f)

    # Agrupar RED primero, luego ORANGE
    rojos    = [f for f in hallazgos_unicos if f.get("risk_level") == "red"]
    naranjas = [f for f in hallazgos_unicos if f.get("risk_level") == "orange"]

    if rojos:
        story.append(Paragraph("🔴 Atención inmediata", st["hallazgo_titulo"]))
        story.append(Spacer(1, 2*mm))
        for f in rojos[:8]:  # máximo 8 para no saturar
            titulo_h, accion_h = _titulo_humano(f)
            story.append(BloqueHallazgo(
                titulo_h,
                f.get("description", "")[:200],
                accion_h,
                "red",
                st,
            ))
            story.append(Spacer(1, 2*mm))

    if naranjas:
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("🟠 Ten en cuenta", st["hallazgo_titulo"]))
        story.append(Spacer(1, 2*mm))
        for f in naranjas[:8]:
            titulo_h, accion_h = _titulo_humano(f)
            story.append(BloqueHallazgo(
                titulo_h,
                f.get("description", "")[:200],
                accion_h,
                "orange",
                st,
            ))
            story.append(Spacer(1, 2*mm))

    # ── SECCIÓN 2: QUÉ PUEDES PEDIR ───────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Qué puedes pedir por escrito", st["seccion"]))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "Estos son tus derechos. Puedes ejercerlos enviando un email al DPO "
        "(Delegado de Protección de Datos) de tu empresa. Guarda siempre copia.",
        st["hallazgo_desc"]
    ))
    story.append(Spacer(1, 4*mm))

    acciones = [
        ("Al DPO de tu empresa", [
            "Solicita la base legal del nivel de telemetría de Windows (RGPD art. 6)",
            "Pide copia del DPA vigente con Microsoft",
            "Pregunta quién tiene acceso a tus archivos de OneDrive y bajo qué condiciones",
            "Solicita si existe DPIA para el ScriptBlock Logging de PowerShell",
            "Pide el listado de subencargados del tratamiento (Microsoft, CrowdStrike, Zscaler)",
        ]),
        ("A IT / Soporte técnico", [
            "Solicita la activación de BitLocker en tu equipo — es obligatorio por RGPD art. 32",
            "Pide información sobre las cuentas con acceso administrativo a tu equipo",
            "Solicita la política de acceso remoto documentada",
            "Pide el listado de add-ins de Outlook instalados y su función",
        ]),
        ("A RRHH o tu responsable", [
            "Solicita la política de monitorización de empleados por escrito",
            "Pregunta si existe cláusula de monitorización en tu contrato o convenio",
            "Pide la política de uso aceptable (AUP) del equipo corporativo",
        ]),
    ]

    for destinatario, items in acciones:
        story.append(Paragraph(f"→ {destinatario}", st["accion_titulo"]))
        for item in items:
            story.append(Paragraph(f"• {item}", st["accion_item"]))
        story.append(Spacer(1, 3*mm))

    # ── SECCIÓN 3: SI NO RESPONDEN ─────────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(LineaDivisora())
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Si no responden en 30 días", st["seccion"]))

    escalada = Table(
        [
            ["Día 31", "Reenvía el email con asunto: RECORDATORIO — Art. 12 RGPD"],
            ["Día 45", "Presenta reclamación en la AEPD: sedeagpd.gob.es"],
            ["Cuando quieras", "Contacta con tu delegado sindical o comité de empresa"],
        ],
        colWidths=[28*mm, (W - 40*mm - 28*mm)],
    )
    escalada.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",  (0, 0), (0, -1), AZUL),
        ("TEXTCOLOR",  (1, 0), (1, -1), GRIS_DARK),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [GRIS_LIGHT, colors.white]),
        ("LINEBELOW",  (0, -1), (-1, -1), 0.5, GRIS_LIGHT),
    ]))
    story.append(escalada)

    # ── PIE ────────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 6*mm))
    story.append(LineaDivisora(GRIS_LIGHT))
    story.append(Spacer(1, 3*mm))

    hash_display = audit_hash[:32] + "..." if len(audit_hash) > 32 else audit_hash
    story.append(Paragraph(
        f"Generado por WorkDRAG · {fecha} · "
        f"SHA-256: {hash_display}",
        st["pie"]
    ))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "Este informe detecta capacidades técnicas, no prueba uso indebido. "
        "No sustituye asesoramiento jurídico profesional.",
        st["nota"]
    ))

    doc.build(story)
    print(f"[PDF Trabajador] Generado: {output_path}")
    return output_path


# ── CLI para prueba ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json
    from pathlib import Path

    if len(sys.argv) < 2:
        print("Uso: python pdf_trabajador.py <audit.json> [output.pdf]")
        sys.exit(1)

    audit_path = Path(sys.argv[1])
    data = json.loads(audit_path.read_text(encoding="utf-8"))

    output = Path(sys.argv[2]) if len(sys.argv) > 2 else audit_path.parent / "informe_trabajador.pdf"

    export_pdf_trabajador(
        findings=data.get("findings", []),
        legal_issues=[],
        output_path=output,
        audit_hash=data.get("integrity_hash", ""),
        generated_at=data.get("generated_at", ""),
    )