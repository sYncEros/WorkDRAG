# skills/coevolution_letter/coevolution_letter.py
"""
Skill — Carta de Coevolución (Coevolution Letter)

Genera comunicaciones al empleador basadas en:
- Datos objetivos (hallazgos de auditoría)
- Derechos legales (RGPD, LOPDGDD, ET)
- Propuestas constructivas (beneficio mutuo)

Principio: "No acuso. Propongo. Y tengo datos."

Tonos disponibles:
- "coevolutivo": Propositivo, busca diálogo.
- "asertivo": Directo, centrado en derechos.
- "formal_legal": Para abogado o sindicato.

Cada carta incluye:
1. Observación (qué se ha detectado, sin juicio)
2. Pregunta (qué necesito saber, con base legal)
3. Propuesta (qué podemos hacer juntos)
4. Plazo (cuándo espero respuesta, según ley)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ── Plantillas de Carta ───────────────────────────────────────────────────────

HEADER_COEVOLUTIVO = """
Estimado/a responsable de protección de datos:

Le escribo como trabajador/a de esta organización con el objetivo de
contribuir a una mejor gestión de la privacidad y la seguridad digital
en nuestro entorno laboral.

He realizado un análisis técnico de mi equipo de trabajo y me gustaría
compartir algunas observaciones que considero relevantes para ambas partes.
Mi intención no es acusar ni señalar, sino proponer mejoras que beneficien
tanto a la organización como a los trabajadores.
"""

HEADER_ASERTIVO = """
Estimado/a Delegado/a de Protección de Datos:

En ejercicio de mis derechos reconocidos en el Reglamento General de
Protección de Datos (RGPD) y la Ley Orgánica de Protección de Datos
(LOPDGDD), me dirijo a usted para solicitar información sobre el
tratamiento de mis datos personales en el entorno laboral.
"""

HEADER_FORMAL = """
A la atención del/la Delegado/a de Protección de Datos
[Nombre de la empresa]

ASUNTO: Ejercicio de derechos ARCO-POL (Acceso, Rectificación,
Cancelación, Oposición, Portabilidad, Olvido, Limitación)

Ref: RGPD Arts. 15-22 | LOPDGDD Arts. 12-18

Quien suscribe, trabajador/a de esta organización, ejercita por medio
del presente escrito los siguientes derechos:
"""

FOOTER_COEVOLUTIVO = """
Quedo a su disposición para mantener una reunión donde podamos explorar
estas propuestas conjuntamente. Creo firmemente que la transparencia
en materia de privacidad digital fortalece la confianza y el compromiso
de todo el equipo.

Agradezco su atención y quedo a la espera de su respuesta.

Atentamente,
[Nombre del trabajador/a]
"""

FOOTER_ASERTIVO = """
De conformidad con el artículo 12.3 del RGPD, solicito respuesta en
el plazo máximo de un mes desde la recepción de esta comunicación.

En caso de no recibir respuesta satisfactoria en dicho plazo, me reservo
el derecho de presentar reclamación ante la Agencia Española de Protección
de Datos (AEPD).

Atentamente,
[Nombre del trabajador/a]
"""

FOOTER_FORMAL = """
PLAZO DE RESPUESTA: Un mes desde la recepción (RGPD Art. 12.3).
CONSECUENCIA DE INCUMPLIMIENTO: Reclamación ante la AEPD (RGPD Art. 77).

Se adjunta como Anexo I el informe técnico que sustenta esta solicitud.

Firmado digitalmente / En [Ciudad], a [Fecha].
[Nombre del trabajador/a]
DNI: [A completar]
"""


# ── Estructura de Carta ───────────────────────────────────────────────────────

@dataclass
class CoevolutionLetter:
    """Una carta generada para el empleador."""
    tone: str
    subject: str
    header: str
    observations: list
    questions: list
    proposals: list
    legal_basis: list
    deadline: str
    footer: str
    generated: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_text(self) -> str:
        """Genera el texto completo de la carta."""
        lines = []
        lines.append(self.header.strip())
        lines.append("")
        
        # Observaciones
        lines.append("OBSERVACIONES:")
        lines.append("-" * 40)
        for i, obs in enumerate(self.observations, 1):
            lines.append(f"{i}. {obs}")
        lines.append("")
        
        # Preguntas
        lines.append("SOLICITUD DE INFORMACIÓN:")
        lines.append("-" * 40)
        for i, q in enumerate(self.questions, 1):
            lines.append(f"{i}. {q}")
        lines.append("")
        
        # Propuestas (solo en tono coevolutivo)
        if self.proposals:
            lines.append("PROPUESTAS DE MEJORA:")
            lines.append("-" * 40)
            for i, p in enumerate(self.proposals, 1):
                lines.append(f"{i}. {p}")
            lines.append("")
        
        # Base legal
        lines.append("BASE LEGAL:")
        lines.append("-" * 40)
        for basis in self.legal_basis:
            lines.append(f"• {basis}")
        lines.append("")
        
        # Plazo
        lines.append(f"PLAZO DE RESPUESTA: {self.deadline}")
        lines.append("")
        
        # Footer
        lines.append(self.footer.strip())
        
        return "\n".join(lines)


# ── Motor de Generación ───────────────────────────────────────────────────────

class CoevolutionLetterGenerator:
    """
    Genera cartas al empleador basadas en hallazgos de auditoría.
    
    Uso:
        generator = CoevolutionLetterGenerator(tone="coevolutivo")
        letter = generator.generate(findings)
        letter.to_text()  # Texto completo de la carta
    """

    def __init__(self, tone: str = "coevolutivo"):
        self.tone = tone

    def generate(self, findings: list, 
                 include_proposals: bool = True) -> CoevolutionLetter:
        """
        Genera una carta basada en los hallazgos de auditoría.
        
        Args:
            findings: Lista de hallazgos (dicts o AuditFinding).
            include_proposals: Si incluir propuestas de mejora.
        
        Returns:
            CoevolutionLetter lista para exportar.
        """
        # Seleccionar header/footer según tono
        header = self._select_header()
        footer = self._select_footer()
        
        # Generar contenido
        observations = self._generate_observations(findings)
        questions = self._generate_questions(findings)
        proposals = self._generate_proposals(findings) if include_proposals else []
        legal_basis = self._extract_legal_basis(findings)
        deadline = self._calculate_deadline()
        
        return CoevolutionLetter(
            tone=self.tone,
            subject=self._generate_subject(findings),
            header=header,
            observations=observations,
            questions=questions,
            proposals=proposals,
            legal_basis=legal_basis,
            deadline=deadline,
            footer=footer,
        )

    def export_letter(self, letter: CoevolutionLetter, 
                      output_path: Optional[str] = None) -> Path:
        """Exporta la carta a un archivo de texto."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            output_path = Path("exports") / f"carta_{self.tone}_{timestamp}.txt"
        else:
            output_path = Path(output_path)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(letter.to_text(), encoding="utf-8")
        
        return output_path

    # ── Generación de Contenido ───────────────────────────────────────────────

    def _generate_subject(self, findings: list) -> str:
        """Genera el asunto de la carta."""
        red_count = sum(1 for f in findings if self._get_risk(f) == "red")
        total = len(findings)
        
        if self.tone == "coevolutivo":
            return (
                f"Propuesta de mejora en gestión de privacidad digital "
                f"({total} observaciones, {red_count} prioritarias)"
            )
        elif self.tone == "asertivo":
            return (
                f"Ejercicio del derecho de acceso — "
                f"Tratamiento de datos en equipo de trabajo"
            )
        else:
            return (
                f"Solicitud formal de información — RGPD Arts. 15-22 — "
                f"{red_count} incumplimientos potenciales detectados"
            )

    def _generate_observations(self, findings: list) -> list:
        """Genera observaciones objetivas (sin juicio)."""
        observations = []
        
        # Agrupar por categoría
        categories = {}
        for f in findings:
            cat = self._get_category(f)
            risk = self._get_risk(f)
            if cat not in categories:
                categories[cat] = {"count": 0, "max_risk": "green"}
            categories[cat]["count"] += 1
            if self._risk_level(risk) > self._risk_level(categories[cat]["max_risk"]):
                categories[cat]["max_risk"] = risk
        
        # Generar observaciones para categorías de riesgo alto
        risk_order = ["red", "orange", "yellow", "green"]
        sorted_cats = sorted(
            categories.items(),
            key=lambda x: self._risk_level(x[1]["max_risk"]),
            reverse=True
        )
        
        for cat, info in sorted_cats[:7]:  # Máximo 7 observaciones
            if info["max_risk"] in ("red", "orange"):
                obs = self._category_to_observation(cat, info["count"])
                if obs:
                    observations.append(obs)
        
        return observations

    def _generate_questions(self, findings: list) -> list:
        """Genera preguntas basadas en hallazgos."""
        questions = []
        categories_seen = set()
        
        for f in findings:
            cat = self._get_category(f)
            risk = self._get_risk(f)
            
            if cat in categories_seen or risk not in ("red", "orange"):
                continue
            categories_seen.add(cat)
            
            q = self._category_to_question(cat)
            if q:
                questions.append(q)
        
        # Pregunta genérica siempre incluida
        questions.append(
            "¿Se ha realizado una Evaluación de Impacto en Protección de Datos "
            "(DPIA) que contemple las herramientas de monitorización desplegadas?"
        )
        
        return questions[:8]  # Máximo 8 preguntas

    def _generate_proposals(self, findings: list) -> list:
        """Genera propuestas de mejora (solo tono coevolutivo)."""
        proposals = []
        categories_seen = set()
        
        for f in findings:
            cat = self._get_category(f)
            if cat in categories_seen:
                continue
            categories_seen.add(cat)
            
            p = self._category_to_proposal(cat)
            if p:
                proposals.append(p)
        
        # Propuesta genérica
        proposals.append(
            "Establecer un canal de comunicación periódico (trimestral) "
            "entre IT, RRHH y representantes de los trabajadores para revisar "
            "las políticas de monitorización y privacidad digital."
        )
        
        return proposals[:6]

    def _extract_legal_basis(self, findings: list) -> list:
        """Extrae base legal relevante."""
        basis = set()
        
        basis.add("RGPD Art. 13 — Derecho a ser informado del tratamiento")
        basis.add("RGPD Art. 15 — Derecho de acceso a datos personales")
        
        categories = set(self._get_category(f) for f in findings)
        
        if "identity_remote_access" in categories:
            basis.add("ET Art. 20bis — Derecho a la intimidad en uso de dispositivos digitales")
        if "ssl_inspection" in categories:
            basis.add("RGPD Art. 5.1.c — Principio de minimización de datos")
        if "exfiltration_dlp_monitoring" in categories:
            basis.add("RGPD Art. 35 — Obligación de realizar DPIA")
        if "ai_copilot" in categories:
            basis.add("RGPD Art. 22 — Decisiones automatizadas y elaboración de perfiles")
        if any("hardening" in c for c in categories):
            basis.add("RGPD Art. 32 — Obligación de medidas técnicas de seguridad")
        
        basis.add("LOPDGDD Art. 87 — Derecho a la intimidad en dispositivos digitales")
        
        return sorted(basis)

    def _calculate_deadline(self) -> str:
        """Calcula plazo legal de respuesta."""
        deadline_date = datetime.now() + timedelta(days=30)
        return (
            f"30 días naturales desde la recepción "
            f"(fecha límite: {deadline_date.strftime('%d/%m/%Y')}). "
            f"RGPD Art. 12.3."
        )

    # ── Mapeo de Categorías a Texto ───────────────────────────────────────────

    def _category_to_observation(self, category: str, count: int) -> Optional[str]:
        """Convierte categoría en observación objetiva."""
        mapping = {
            "identity_remote_access": (
                f"Se ha detectado que {count} configuración(es) permiten "
                "acceso remoto al equipo de trabajo."
            ),
            "ssl_inspection": (
                "El tráfico HTTPS del equipo pasa por un proxy de inspección "
                "que tiene capacidad de leer contenido cifrado."
            ),
            "exfiltration_dlp_monitoring": (
                "Existe un sistema DLP que inspecciona el contenido de archivos "
                "y comunicaciones del equipo."
            ),
            "cloud_sync_folder_redirect": (
                "Las carpetas del sistema (Escritorio, Documentos) están "
                "redirigidas a almacenamiento en la nube sin opción de exclusión."
            ),
            "ai_copilot": (
                "Se detectan herramientas de IA (Copilot/similares) que procesan "
                "actividad laboral del equipo."
            ),
            "hardening_missing": (
                f"Se han identificado {count} carencia(s) en medidas de seguridad "
                "básicas del equipo (hardening)."
            ),
        }
        return mapping.get(category)

    def _category_to_question(self, category: str) -> Optional[str]:
        """Convierte categoría en pregunta legítima."""
        mapping = {
            "identity_remote_access": (
                "¿Qué cuentas tienen acceso remoto a mi equipo, con qué finalidad "
                "y en qué horarios se ha utilizado esta capacidad?"
            ),
            "ssl_inspection": (
                "¿Qué categorías de tráfico web se inspeccionan? "
                "¿Se excluyen comunicaciones sindicales, médicas y bancarias?"
            ),
            "exfiltration_dlp_monitoring": (
                "¿Qué patrones busca el sistema DLP? ¿Se analiza contenido libre "
                "o solo patrones predefinidos? ¿Quién recibe las alertas?"
            ),
            "cloud_sync_folder_redirect": (
                "¿Es posible excluir carpetas personales de la sincronización forzada? "
                "¿Quién tiene acceso a los archivos sincronizados?"
            ),
            "ai_copilot": (
                "¿Qué datos de mi actividad procesa la IA corporativa? "
                "¿Se usan para evaluaciones de rendimiento? ¿Puedo optar por no participar?"
            ),
            "hardening_missing": (
                "¿Existe un plan de remediación para las carencias de seguridad "
                "detectadas en los equipos de trabajo?"
            ),
        }
        return mapping.get(category)

    def _category_to_proposal(self, category: str) -> Optional[str]:
        """Convierte categoría en propuesta constructiva."""
        mapping = {
            "identity_remote_access": (
                "Implementar notificación previa al trabajador antes de "
                "cualquier acceso remoto no urgente."
            ),
            "ssl_inspection": (
                "Publicar lista de categorías excluidas de inspección TLS "
                "y excluir explícitamente: salud, banca, sindicatos."
            ),
            "exfiltration_dlp_monitoring": (
                "Documentar públicamente qué patrones busca el DLP "
                "y notificar al trabajador cuando se active una alerta."
            ),
            "cloud_sync_folder_redirect": (
                "Permitir al trabajador excluir al menos una carpeta personal "
                "de la sincronización forzada."
            ),
            "ai_copilot": (
                "Realizar DPIA específica para herramientas de IA y "
                "permitir opt-out de análisis de productividad."
            ),
            "hardening_missing": (
                "Establecer calendario de remediación de seguridad "
                "con priorización por riesgo."
            ),
        }
        return mapping.get(category)

    # ── Selección de Plantillas ───────────────────────────────────────────────

    def _select_header(self) -> str:
        if self.tone == "coevolutivo":
            return HEADER_COEVOLUTIVO
        elif self.tone == "asertivo":
            return HEADER_ASERTIVO
        return HEADER_FORMAL

    def _select_footer(self) -> str:
        if self.tone == "coevolutivo":
            return FOOTER_COEVOLUTIVO
        elif self.tone == "asertivo":
            return FOOTER_ASERTIVO
        return FOOTER_FORMAL

    # ── Utilidades ────────────────────────────────────────────────────────────

    @staticmethod
    def _get_category(finding) -> str:
        if isinstance(finding, dict):
            return finding.get("category", "")
        return getattr(finding, "category", "")

    @staticmethod
    def _get_risk(finding) -> str:
        if isinstance(finding, dict):
            return finding.get("risk_level", "green")
        return getattr(finding, "risk_level", "green")

    @staticmethod
    def _risk_level(risk: str) -> int:
        return {"red": 4, "orange": 3, "yellow": 2, "green": 1}.get(risk, 0)


# ── Interfaz CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Carta de Coevolución — Generador de Comunicaciones")
    print("  " + "─" * 50)
    print("  Tonos disponibles: coevolutivo, asertivo, formal_legal")
    print("  Uso: importar desde main.py o ejecutar con datos de auditoría.")
