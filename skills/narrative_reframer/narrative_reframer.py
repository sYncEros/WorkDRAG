# skills/narrative_reframer/narrative_reframer.py
"""
Skill — Reencuadre Narrativo (Narrative Reframer)

Traduce hallazgos técnicos a lenguaje humano y coevolutivo.
No minimiza. No dramatiza. Contextualiza.

Principios:
1. No usar palabras que activen lucha/huida:
   "ataque", "espionaje", "invasión" → "observación", "acceso", "capacidad"
2. Siempre incluir la PREGUNTA que el trabajador puede hacer.
3. Siempre incluir el DERECHO que ampara esa pregunta.
4. Nunca asumir intención maliciosa: describir CAPACIDAD, no USO.
5. Ofrecer siempre una lectura COEVOLUTIVA: beneficio mutuo.

Filosofía: "No digo que hagas algo mal.
Digo que podemos hacerlo mejor. Y aquí están los datos."
"""

from dataclasses import dataclass
from typing import Optional


# ── Estructura de Reencuadre ──────────────────────────────────────────────────

@dataclass
class ReframedFinding:
    """Un hallazgo traducido a lenguaje humano y coevolutivo."""
    original_title: str
    original_category: str
    original_risk: str
    
    # Narrativa humana
    human_description: str      # Lo que significa en lenguaje claro
    emotional_impact: str       # Cómo puede hacer sentir al trabajador
    
    # Acción constructiva
    question_for_employer: str  # Pregunta que puedes hacer (no acusación)
    legal_right: str            # Derecho que ampara la pregunta
    
    # Perspectiva coevolutiva
    coevolutive_reading: str    # Por qué la transparencia beneficia a ambos
    proposal: str               # Propuesta concreta de mejora
    
    # Contexto
    is_standard: bool           # ¿Es configuración estándar en empresas?
    requires_action: bool       # ¿Requiere acción inmediata?


# ── Base de Conocimiento de Reencuadres ───────────────────────────────────────

REFRAME_DATABASE = {
    # ── Identidad y Acceso ────────────────────────────────────────────────────
    "identity_remote_access": {
        "human": (
            "Tu espacio de trabajo digital puede ser accedido remotamente. "
            "Esto significa que alguien puede ver tu pantalla, mover tu ratón "
            "o acceder a tus archivos sin que estés presente."
        ),
        "emotional_impact": (
            "Puede generar sensación de vigilancia constante y falta de privacidad. "
            "Es normal sentir incomodidad ante esto."
        ),
        "question": (
            "¿Puedo conocer qué cuentas tienen acceso remoto a mi equipo, "
            "con qué finalidad y en qué horarios se ha utilizado esta capacidad?"
        ),
        "right": "RGPD Art. 15 (derecho de acceso) + ET Art. 20bis (intimidad digital)",
        "coevolutive": (
            "La transparencia sobre accesos remotos beneficia a ambas partes: "
            "reduce el riesgo legal para la empresa (cumplimiento RGPD Art. 13) "
            "y la ansiedad del trabajador. Un protocolo de notificación previa "
            "es una solución sencilla y de bajo coste."
        ),
        "proposal": (
            "Notificación previa de acceso remoto salvo urgencia documentada. "
            "Registro de accesos consultable por el trabajador."
        ),
        "is_standard": True,
        "requires_action": False,
    },
    
    # ── Cloud Sync ────────────────────────────────────────────────────────────
    "cloud_sync_folder_redirect": {
        "human": (
            "Tus carpetas personales (Escritorio, Documentos, Imágenes) se copian "
            "automáticamente a la nube corporativa. Esto incluye capturas de pantalla, "
            "documentos personales y cualquier archivo que guardes en esas ubicaciones."
        ),
        "emotional_impact": (
            "Puede sentirse como una invasión del espacio personal. "
            "Es comprensible sentir que tu escritorio ya no es 'tuyo'."
        ),
        "question": (
            "¿Es posible excluir carpetas personales de la sincronización forzada? "
            "¿Qué política justifica la redirección de carpetas del sistema? "
            "¿Quién tiene acceso a los archivos sincronizados?"
        ),
        "right": "LOPDGDD Art. 87 (intimidad en dispositivos digitales)",
        "coevolutive": (
            "Una política de exclusión de carpetas personales protege a la empresa "
            "de responsabilidad sobre datos privados del trabajador. Si un documento "
            "personal sensible se sincroniza sin consentimiento, la empresa podría "
            "estar tratando datos sin base legal."
        ),
        "proposal": (
            "Permitir al trabajador excluir al menos una carpeta de la sincronización. "
            "Informar claramente qué carpetas se sincronizan y con qué retención."
        ),
        "is_standard": True,
        "requires_action": True,
    },
    
    # ── SSL/TLS Inspection ────────────────────────────────────────────────────
    "ssl_inspection": {
        "human": (
            "El tráfico web cifrado (HTTPS) pasa por un intermediario corporativo "
            "que tiene la capacidad técnica de leer su contenido. Esto incluye "
            "páginas web visitadas, formularios rellenados y comunicaciones."
        ),
        "emotional_impact": (
            "Puede generar la sensación de que 'alguien lee por encima del hombro'. "
            "Es una de las capacidades más invasivas, aunque también una de las más comunes."
        ),
        "question": (
            "¿Está habilitada la inspección de tráfico HTTPS en mi equipo? "
            "¿Qué categorías de sitios se inspeccionan y cuáles se excluyen? "
            "¿Se registra el contenido de las comunicaciones o solo los metadatos?"
        ),
        "right": (
            "RGPD Art. 5.1.c (minimización de datos) + "
            "TEDH Barbulescu v. Rumanía (proporcionalidad en monitorización)"
        ),
        "coevolutive": (
            "La inspección TLS tiene un propósito legítimo (seguridad), pero su alcance "
            "debe ser proporcional. Excluir categorías sensibles (salud, sindicatos, "
            "banca personal) reduce el riesgo legal y demuestra buena fe."
        ),
        "proposal": (
            "Publicar lista de categorías excluidas de inspección. "
            "Excluir explícitamente: salud, banca, sindicatos, comunicaciones personales. "
            "Informar al trabajador de la existencia de la inspección."
        ),
        "is_standard": True,
        "requires_action": False,
    },
    
    # ── DLP ───────────────────────────────────────────────────────────────────
    "exfiltration_dlp_monitoring": {
        "human": (
            "Existe un sistema de Prevención de Pérdida de Datos (DLP) que puede "
            "inspeccionar el contenido de archivos, bloquear transferencias y "
            "registrar intentos de envío de información fuera de la organización."
        ),
        "emotional_impact": (
            "Puede sentirse como desconfianza institucionalizada. "
            "Como si cada acción fuera sospechosa hasta que se demuestre lo contrario."
        ),
        "question": (
            "¿Qué tipos de contenido inspecciona el DLP? "
            "¿Se analizan solo patrones (números de tarjeta, DNI) o también contenido libre? "
            "¿Quién recibe las alertas y cómo se gestionan?"
        ),
        "right": "RGPD Art. 35 (evaluación de impacto) + Art. 13 (información al interesado)",
        "coevolutive": (
            "El DLP protege datos de clientes y propiedad intelectual, lo cual es legítimo. "
            "Pero si su alcance no está documentado ni comunicado, genera desconfianza "
            "y puede vulnerar derechos. La transparencia sobre su alcance es un win-win."
        ),
        "proposal": (
            "Documentar públicamente qué patrones busca el DLP. "
            "Excluir contenido personal identificado. "
            "Notificar al trabajador cuando se active una alerta sobre su actividad."
        ),
        "is_standard": True,
        "requires_action": False,
    },
    
    # ── EDR/XDR ───────────────────────────────────────────────────────────────
    "edr_xdr": {
        "human": (
            "Hay un sistema de detección y respuesta (EDR/XDR) que monitoriza "
            "procesos, archivos y conexiones de red en tiempo real. "
            "Su propósito principal es la seguridad, pero tiene capacidad "
            "de registrar toda la actividad del equipo."
        ),
        "emotional_impact": (
            "Puede sentirse como un 'ojo que todo lo ve'. "
            "Pero es importante distinguir: su función principal es detectar malware, "
            "no vigilar al trabajador."
        ),
        "question": (
            "¿El EDR/XDR genera perfiles de comportamiento del usuario? "
            "¿Se utilizan sus datos para evaluaciones de productividad? "
            "¿Cuánto tiempo se retienen los logs de actividad?"
        ),
        "right": "RGPD Art. 5.1.b (limitación de finalidad)",
        "coevolutive": (
            "El EDR es necesario para la seguridad. El problema surge cuando sus datos "
            "se usan para fines distintos (productividad, disciplina). "
            "Separar claramente seguridad de RRHH protege a la empresa de demandas "
            "y al trabajador de vigilancia encubierta."
        ),
        "proposal": (
            "Declarar por escrito que los datos del EDR no se usan para "
            "evaluaciones de rendimiento ni procedimientos disciplinarios. "
            "Establecer retención máxima de logs."
        ),
        "is_standard": True,
        "requires_action": False,
    },
    
    # ── Hardening ausente ─────────────────────────────────────────────────────
    "hardening_missing": {
        "human": (
            "Tu equipo carece de protecciones de seguridad básicas. "
            "Esto significa que tus datos (y los de la empresa) están más expuestos "
            "a ataques externos de lo que deberían."
        ),
        "emotional_impact": (
            "Esto puede generar una paradoja frustrante: te vigilan mucho, "
            "pero no te protegen bien. La vigilancia sin protección es negligencia."
        ),
        "question": (
            "¿Por qué mi equipo no tiene habilitadas protecciones estándar "
            "como BitLocker, Secure Boot o Firewall? "
            "¿Existe un plan de remediación?"
        ),
        "right": "RGPD Art. 32 (seguridad del tratamiento)",
        "coevolutive": (
            "Este hallazgo es especialmente poderoso porque no es una queja de privacidad: "
            "es un riesgo real para la empresa. Si hay una brecha, la falta de hardening "
            "es negligencia demostrable. Señalarlo es un acto de responsabilidad, no de rebeldía."
        ),
        "proposal": (
            "Solicitar plan de hardening con calendario. "
            "Documentar el estado actual como evidencia de diligencia propia."
        ),
        "is_standard": False,
        "requires_action": True,
    },
    
    # ── AI / Copilot ──────────────────────────────────────────────────────────
    "ai_copilot": {
        "human": (
            "Hay herramientas de inteligencia artificial (como Copilot) que procesan "
            "tu actividad laboral: documentos, emails, chats, código. "
            "Estas herramientas aprenden de tu trabajo y pueden generar resúmenes "
            "o análisis accesibles para otros."
        ),
        "emotional_impact": (
            "Puede sentirse como si tu trabajo fuera 'digerido' por una máquina "
            "sin tu consentimiento explícito. Es una forma nueva de extracción."
        ),
        "question": (
            "¿Qué datos de mi actividad procesa Copilot? "
            "¿Dónde se almacenan los prompts y respuestas? "
            "¿Se usan para entrenar modelos? "
            "¿Quién puede ver los resúmenes generados sobre mi trabajo?"
        ),
        "right": (
            "RGPD Art. 22 (decisiones automatizadas) + "
            "Art. 13 (información sobre lógica aplicada)"
        ),
        "coevolutive": (
            "La IA en el trabajo puede ser una herramienta de empoderamiento o de extracción. "
            "La diferencia está en la transparencia. Si el trabajador sabe qué procesa la IA "
            "y puede optar por no participar en ciertos análisis, la adopción será más sana."
        ),
        "proposal": (
            "Informar qué datos procesa Copilot por usuario. "
            "Permitir opt-out de análisis de productividad basados en IA. "
            "Realizar DPIA específica para herramientas de IA."
        ),
        "is_standard": False,
        "requires_action": True,
    },
    
    # ── Credenciales almacenadas ──────────────────────────────────────────────
    "identity_stored_credentials": {
        "human": (
            "Tu equipo almacena credenciales (contraseñas, tokens) que un proceso "
            "con privilegios de administrador podría extraer. Esto incluye "
            "credenciales personales si las has usado en este equipo."
        ),
        "emotional_impact": (
            "Puede generar urgencia por cambiar contraseñas. "
            "Es una reacción sana: hazlo desde un dispositivo personal."
        ),
        "question": (
            "¿Qué medidas existen para proteger las credenciales almacenadas "
            "en equipos corporativos? ¿Se realiza rotación periódica?"
        ),
        "right": "RGPD Art. 32 (medidas técnicas de seguridad)",
        "coevolutive": (
            "Proteger credenciales es interés mutuo. Una brecha que exponga "
            "credenciales de empleados es un incidente de seguridad reportable. "
            "Implementar protección adicional (Credential Guard, MFA) beneficia a todos."
        ),
        "proposal": (
            "Habilitar Credential Guard. Implementar MFA en todos los accesos. "
            "Informar al trabajador de qué credenciales están almacenadas."
        ),
        "is_standard": True,
        "requires_action": True,
    },
}


# ── Motor de Reencuadre ───────────────────────────────────────────────────────

class NarrativeReframer:
    """
    Traduce hallazgos técnicos a narrativa humana y coevolutiva.
    
    Uso:
        reframer = NarrativeReframer()
        reframed = reframer.reframe(finding)
        # reframed es un ReframedFinding con lenguaje humano
    """

    def __init__(self, tone: str = "coevolutivo"):
        """
        Args:
            tone: Tono de la narrativa.
                  - "coevolutivo": Propositivo, busca beneficio mutuo.
                  - "asertivo": Más directo, centrado en derechos.
                  - "sindical": Técnico-legal para representantes.
        """
        self.tone = tone

    def reframe(self, finding) -> ReframedFinding:
        """
        Reencuadra un hallazgo individual.
        
        Args:
            finding: AuditFinding o dict con al menos 'category' y 'title'.
        
        Returns:
            ReframedFinding con narrativa humana completa.
        """
        category = self._get_field(finding, "category")
        title = self._get_field(finding, "title")
        risk = self._get_field(finding, "risk_level")
        
        # Buscar en la base de datos de reencuadres
        template = REFRAME_DATABASE.get(category)
        
        if template:
            return ReframedFinding(
                original_title=title,
                original_category=category,
                original_risk=risk,
                human_description=template["human"],
                emotional_impact=template["emotional_impact"],
                question_for_employer=template["question"],
                legal_right=template["right"],
                coevolutive_reading=template["coevolutive"],
                proposal=template["proposal"],
                is_standard=template["is_standard"],
                requires_action=template["requires_action"],
            )
        else:
            # Generar reencuadre genérico
            return self._generic_reframe(title, category, risk)

    def reframe_all(self, findings: list) -> list:
        """Reencuadra todos los hallazgos de una auditoría."""
        return [self.reframe(f) for f in findings]

    def generate_summary(self, reframed: list) -> str:
        """Genera un resumen narrativo de todos los reencuadres."""
        standard = [r for r in reframed if r.is_standard]
        non_standard = [r for r in reframed if not r.is_standard]
        action_needed = [r for r in reframed if r.requires_action]
        
        lines = []
        lines.append("=" * 60)
        lines.append("  RESUMEN DE TU ENTORNO DIGITAL")
        lines.append("  (Lectura coevolutiva)")
        lines.append("=" * 60)
        lines.append("")
        
        lines.append(f"  Se han analizado {len(reframed)} aspectos de tu entorno.")
        lines.append(f"  • {len(standard)} son configuraciones estándar en empresas.")
        lines.append(f"  • {len(non_standard)} requieren atención especial.")
        lines.append(f"  • {len(action_needed)} sugieren una acción por tu parte.")
        lines.append("")
        
        if action_needed:
            lines.append("  ACCIONES SUGERIDAS (por orden de prioridad):")
            lines.append("  " + "─" * 50)
            for i, r in enumerate(action_needed[:5], 1):
                lines.append(f"  {i}. {r.proposal}")
                lines.append(f"     Pregunta: {r.question_for_employer}")
                lines.append(f"     Derecho: {r.legal_right}")
                lines.append("")
        
        lines.append("  " + "─" * 50)
        lines.append("  Recuerda: detectar una capacidad NO prueba su uso.")
        lines.append("  Preguntar NO es acusar. Proponer NO es atacar.")
        lines.append("=" * 60)
        
        return "\n".join(lines)

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _generic_reframe(self, title: str, category: str, risk: str) -> ReframedFinding:
        """Genera un reencuadre genérico cuando no hay template específico."""
        return ReframedFinding(
            original_title=title,
            original_category=category,
            original_risk=risk,
            human_description=(
                f"Se ha detectado la capacidad técnica '{title}' en tu entorno. "
                f"Esto no significa necesariamente que se esté usando activamente."
            ),
            emotional_impact=(
                "Es normal sentir inquietud al descubrir capacidades de monitorización. "
                "Tómate un momento antes de decidir qué hacer con esta información."
            ),
            question_for_employer=(
                f"¿Puede informarme sobre la finalidad y alcance de '{title}' "
                f"en mi equipo de trabajo?"
            ),
            legal_right="RGPD Art. 13 (derecho a ser informado)",
            coevolutive_reading=(
                "La transparencia sobre las herramientas desplegadas genera confianza. "
                "Un trabajador informado es un trabajador más comprometido."
            ),
            proposal=(
                f"Incluir '{title}' en la política de privacidad laboral "
                f"y comunicar su existencia a los trabajadores."
            ),
            is_standard=(risk in ("green", "yellow")),
            requires_action=(risk in ("orange", "red")),
        )

    @staticmethod
    def _get_field(finding, field: str) -> str:
        """Extrae un campo de un finding (objeto o dict)."""
        if isinstance(finding, dict):
            return finding.get(field, "")
        return getattr(finding, field, "")


# ── Interfaz CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Demo con hallazgo de ejemplo
    example = {
        "category": "identity_remote_access",
        "title": "RDP habilitado con 16 cuentas de acceso",
        "risk_level": "red",
    }
    
    reframer = NarrativeReframer()
    result = reframer.reframe(example)
    
    print(f"\n  Hallazgo original: {result.original_title}")
    print(f"  Riesgo: {result.original_risk}")
    print(f"\n  Lectura humana: {result.human_description}")
    print(f"\n  Impacto emocional: {result.emotional_impact}")
    print(f"\n  Pregunta: {result.question_for_employer}")
    print(f"\n  Derecho: {result.legal_right}")
    print(f"\n  Lectura coevolutiva: {result.coevolutive_reading}")
    print(f"\n  Propuesta: {result.proposal}")
