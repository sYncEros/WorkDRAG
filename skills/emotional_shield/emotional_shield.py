# skills/emotional_shield/emotional_shield.py
"""
Skill — Escudo Emocional (Emotional Shield)

Evalúa la capacidad emocional del usuario antes de mostrar resultados.
Dosifica la información según el estado actual.
No oculta nada. Solo cuida el ritmo de entrega.

Principio: "Tienes derecho a saber. Y tienes derecho a descansar."

Este módulo implementa la filosofía de 'ternura radical':
la defensa más poderosa no es la que grita más fuerte,
sino la que respira más profundo.
"""

import json
import random
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Frases de Anclaje ─────────────────────────────────────────────────────────

FRASES_ANCLAJE = [
    "Tienes derecho a saber. Y tienes derecho a descansar.",
    "Esta información no te define. Te protege.",
    "No tienes que hacer nada ahora. Solo saber.",
    "El sistema observa. Tú también. Eso ya es poder.",
    "Respira. La evidencia no caduca hoy.",
    "Tu dignidad no depende de lo que ellos configuren.",
    "Cada dato que guardas es un acto de soberanía.",
    "No estás sola. Esto le pasa a millones. Y ahora tienes pruebas.",
    "La calma es tu mejor herramienta. El tiempo juega a tu favor.",
    "Observar sin reaccionar es la forma más alta de inteligencia.",
]

FRASES_CIERRE = [
    "Cuando estés lista, vuelve. La evidencia estará aquí.",
    "Guarda este archivo en un lugar seguro. No hagas nada más hoy.",
    "Mañana es otro día. Y seguirás teniendo derechos.",
    "Descansa. El sistema no va a cambiar esta noche, pero tú sí puedes recuperarte.",
]


# ── Niveles de Capacidad ──────────────────────────────────────────────────────

@dataclass
class CapacityAssessment:
    """Resultado de la evaluación de capacidad emocional."""
    level: str              # MINIMO, MODERADO, COMPLETO
    score: int              # 1-5
    has_support: bool       # ¿Tiene apoyo cerca?
    is_safe: bool           # ¿Está en lugar seguro?
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    frase_anclaje: str = ""
    frase_cierre: str = ""

    def __post_init__(self):
        if not self.frase_anclaje:
            self.frase_anclaje = random.choice(FRASES_ANCLAJE)
        if not self.frase_cierre:
            self.frase_cierre = random.choice(FRASES_CIERRE)


# ── Motor Principal ───────────────────────────────────────────────────────────

class EmotionalShield:
    """
    Escudo Emocional: protege a quien usa WorkDRAG.
    
    Antes de mostrar resultados, evalúa:
    - ¿Cómo te sientes ahora? (1-5)
    - ¿Tienes apoyo cerca? (sí/no)
    - ¿Estás en un lugar seguro? (sí/no)
    
    Según las respuestas, ajusta la salida:
    - Nivel MINIMO (crisis):    Solo UNA acción + frase de anclaje.
    - Nivel MODERADO (alerta):  Resumen ejecutivo + 3 acciones prioritarias.
    - Nivel COMPLETO (estable): Informe completo con contexto legal.
    """

    def __init__(self):
        self.assessment: Optional[CapacityAssessment] = None
        self.log_path = Path("exports") / "emotional_log.json"

    # ── Evaluación ────────────────────────────────────────────────────────────

    def evaluate_capacity(self, estado: int = 3, apoyo: bool = True, 
                          segura: bool = True) -> CapacityAssessment:
        """
        Determina el nivel de información que el usuario puede procesar.
        
        Args:
            estado: Escala 1-5 (1=crisis, 5=estable)
            apoyo: ¿Tiene apoyo emocional cerca?
            segura: ¿Está en un lugar seguro (no equipo corporativo)?
        
        Returns:
            CapacityAssessment con nivel y frases de acompañamiento.
        """
        # Lógica de evaluación
        if estado <= 2 or not segura:
            level = "MINIMO"
        elif estado == 3 or not apoyo:
            level = "MODERADO"
        else:
            level = "COMPLETO"

        self.assessment = CapacityAssessment(
            level=level,
            score=estado,
            has_support=apoyo,
            is_safe=segura,
        )
        
        self._log_assessment()
        return self.assessment

    # ── Filtrado de Resultados ────────────────────────────────────────────────

    def filter_output(self, findings: list, level: Optional[str] = None) -> dict:
        """
        Filtra hallazgos según capacidad emocional.
        
        Args:
            findings: Lista de AuditFinding (o dicts con 'risk_level').
            level: Nivel de filtrado. Si None, usa el último assessment.
        
        Returns:
            Dict con hallazgos filtrados, mensajes y acciones.
        """
        if level is None:
            level = self.assessment.level if self.assessment else "COMPLETO"

        if level == "MINIMO":
            return self._output_minimo(findings)
        elif level == "MODERADO":
            return self._output_moderado(findings)
        else:
            return self._output_completo(findings)

    def _output_minimo(self, findings: list) -> dict:
        """Solo lo esencial. Una acción. Una frase. Nada más."""
        red_findings = [f for f in findings if self._get_risk(f) == "red"]
        most_urgent = red_findings[:1] if red_findings else findings[:1]
        
        return {
            "level": "MINIMO",
            "findings": most_urgent,
            "total_hidden": len(findings) - len(most_urgent),
            "message": random.choice(FRASES_ANCLAJE),
            "action": (
                "Guarda este archivo en un lugar seguro (USB personal o móvil). "
                "No hagas nada más hoy. La evidencia no caduca."
            ),
            "next_step": "Cuando estés lista, ejecuta de nuevo con --full para ver todo.",
            "cierre": random.choice(FRASES_CIERRE),
            "breathing_reminder": (
                "Si sientes presión ahora mismo: "
                "Inhala 6 segundos. Exhala 6 segundos. Repite 3 veces. "
                "Luego decide si quieres seguir leyendo."
            ),
        }

    def _output_moderado(self, findings: list) -> dict:
        """Resumen ejecutivo + 3 acciones prioritarias."""
        red_findings = [f for f in findings if self._get_risk(f) == "red"]
        orange_findings = [f for f in findings if self._get_risk(f) == "orange"]
        
        priority = (red_findings + orange_findings)[:5]
        
        return {
            "level": "MODERADO",
            "findings": priority,
            "total_hidden": len(findings) - len(priority),
            "summary": {
                "total": len(findings),
                "criticos": len(red_findings),
                "alerta": len(orange_findings),
                "informativos": len(findings) - len(red_findings) - len(orange_findings),
            },
            "actions": self._top_3_actions(red_findings),
            "message": random.choice(FRASES_ANCLAJE),
            "context": (
                "Estás viendo solo los hallazgos más relevantes. "
                "El informe completo está guardado y disponible cuando lo necesites."
            ),
        }

    def _output_completo(self, findings: list) -> dict:
        """Todo el informe, sin filtro, pero con contexto humano."""
        return {
            "level": "COMPLETO",
            "findings": findings,
            "total_hidden": 0,
            "message": (
                "Aquí tienes el informe completo. "
                "Recuerda: detectar una CAPACIDAD no prueba su USO. "
                "Tómate el tiempo que necesites para procesarlo."
            ),
            "full": True,
        }

    # ── Acciones Prioritarias ─────────────────────────────────────────────────

    def _top_3_actions(self, critical_findings: list) -> list:
        """Genera las 3 acciones más importantes basadas en hallazgos críticos."""
        actions = []
        
        categories_found = set()
        for f in critical_findings:
            cat = self._get_category(f)
            if cat:
                categories_found.add(cat)

        if "identity_remote_access" in categories_found:
            actions.append({
                "priority": 1,
                "action": "Solicita por escrito al DPO la lista de cuentas con acceso remoto a tu equipo.",
                "template": "m365_access_request",
                "urgency": "Esta semana",
            })
        
        if "ssl_inspection" in categories_found or "exfiltration_dlp_monitoring" in categories_found:
            actions.append({
                "priority": 2,
                "action": "No uses el equipo corporativo para comunicaciones personales o sindicales.",
                "template": None,
                "urgency": "Inmediato",
            })
        
        if "cloud_sync_folder_redirect" in categories_found:
            actions.append({
                "priority": 3,
                "action": "Mueve documentos personales fuera de Escritorio/Documentos (están sincronizándose a la nube).",
                "template": None,
                "urgency": "Hoy",
            })

        # Si no hay acciones específicas, dar una genérica
        if not actions:
            actions.append({
                "priority": 1,
                "action": "Guarda una copia del informe en un dispositivo personal.",
                "template": None,
                "urgency": "Hoy",
            })

        return actions[:3]

    # ── Utilidades ────────────────────────────────────────────────────────────

    @staticmethod
    def _get_risk(finding) -> str:
        """Extrae nivel de riesgo de un finding (objeto o dict)."""
        if isinstance(finding, dict):
            return finding.get("risk_level", "green")
        return getattr(finding, "risk_level", "green")

    @staticmethod
    def _get_category(finding) -> str:
        """Extrae categoría de un finding (objeto o dict)."""
        if isinstance(finding, dict):
            return finding.get("category", "")
        return getattr(finding, "category", "")

    def _log_assessment(self):
        """Registra la evaluación emocional (para tracking personal, no corporativo)."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            
            log_entry = {
                "timestamp": self.assessment.timestamp,
                "level": self.assessment.level,
                "score": self.assessment.score,
            }
            
            # Append al log existente
            if self.log_path.exists():
                data = json.loads(self.log_path.read_text(encoding="utf-8"))
            else:
                data = {"entries": []}
            
            data["entries"].append(log_entry)
            self.log_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception:
            pass  # El log emocional nunca debe romper la ejecución


# ── Interfaz CLI ──────────────────────────────────────────────────────────────

def interactive_assessment() -> CapacityAssessment:
    """Evaluación interactiva para uso en terminal."""
    print("\n")
    print("  ┌─────────────────────────────────────────────────┐")
    print("  │  Escudo Emocional — Evaluación de Capacidad     │")
    print("  │                                                  │")
    print("  │  Antes de mostrarte los resultados,             │")
    print("  │  necesito saber cómo estás.                     │")
    print("  └─────────────────────────────────────────────────┘")
    print("\n")
    
    try:
        estado = int(input("  ¿Cómo te sientes ahora? (1=muy mal, 5=bien): ") or "3")
        estado = max(1, min(5, estado))
    except (ValueError, EOFError):
        estado = 3
    
    try:
        apoyo_str = input("  ¿Tienes apoyo emocional cerca? (s/n): ").strip().lower()
        apoyo = apoyo_str in ("s", "si", "sí", "y", "yes")
    except EOFError:
        apoyo = True
    
    try:
        segura_str = input("  ¿Estás en un lugar seguro (no equipo corporativo)? (s/n): ").strip().lower()
        segura = segura_str in ("s", "si", "sí", "y", "yes")
    except EOFError:
        segura = True
    
    shield = EmotionalShield()
    assessment = shield.evaluate_capacity(estado=estado, apoyo=apoyo, segura=segura)
    
    print(f"\n  → Nivel de información: {assessment.level}")
    print(f"  → {assessment.frase_anclaje}")
    print()
    
    return assessment


if __name__ == "__main__":
    interactive_assessment()
