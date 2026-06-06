# skills/incident_response/playbook_generator.py
"""
Skill — Generador de Playbook de Respuesta a Incidentes
Genera un playbook específico para el trabajador basado en los hallazgos
de la auditoría: pasos inmediatos, evidencia a preservar, canales de
denuncia, y acciones legales recomendadas.
"""

from datetime import datetime


class IncidentResponsePlaybook:
    SKILL_NAME = "incident_response"

    # Niveles de acción por riesgo detectado
    RISK_PLAYBOOKS = {
        "very_high": {
            "urgency": "INMEDIATA (< 24 horas)",
            "priority": 1,
            "immediate_actions": [
                "No usar el equipo para comunicaciones personales hasta aclarar la situación.",
                "Hacer una captura de pantalla del informe de auditoría completo.",
                "Anotar la fecha y hora exacta de este análisis.",
                "Contactar con un asesor laboral o sindicato antes de tomar cualquier acción.",
                "No borrar ni modificar ningún archivo del equipo (puede ser evidencia).",
            ],
        },
        "high": {
            "urgency": "URGENTE (< 48 horas)",
            "priority": 2,
            "immediate_actions": [
                "Guardar este informe como evidencia digital (PDF y JSON).",
                "Anotar la fecha de la auditoría y los hallazgos más relevantes.",
                "Considerar consultar con asesor laboral o representante sindical.",
                "Separar uso personal del profesional en el equipo corporativo.",
            ],
        },
        "orange": {
            "urgency": "PRÓXIMAS 2 SEMANAS",
            "priority": 3,
            "immediate_actions": [
                "Guardar este informe como evidencia.",
                "Solicitar información al DPO de la empresa sobre los hallazgos.",
                "Revisar el contrato y política de uso aceptable de dispositivos.",
            ],
        },
    }

    # Acciones de preservación de evidencia
    EVIDENCE_PRESERVATION = [
        {
            "step": "1. Exportar este informe",
            "detail": "Descargar el informe completo en formato PDF y JSON. "
                      "Guardar copias en almacenamiento personal (no corporativo).",
            "tools": ["Botón 'Exportar PDF' y 'Exportar JSON' de esta herramienta"],
        },
        {
            "step": "2. Captura de pantalla del estado del sistema",
            "detail": "Hacer capturas de pantalla del Administrador de Tareas, "
                      "Servicios activos, y Herramientas de administración.",
            "tools": ["Win+Print Screen", "Snipping Tool"],
        },
        {
            "step": "3. Registro de conexiones de red actuales",
            "detail": "Ejecutar 'netstat -ano' desde CMD y guardar la salida. "
                      "Documenta conexiones activas en el momento de la auditoría.",
            "tools": ["CMD > netstat -ano > conexiones.txt"],
        },
        {
            "step": "4. Inventario de software instalado",
            "detail": "Exportar la lista de programas instalados como evidencia "
                      "del estado del equipo en este momento.",
            "tools": [
                "Panel de Control > Programas > Exportar",
                "PowerShell: Get-ItemProperty ... | Export-Csv",
            ],
        },
        {
            "step": "5. Hash del informe de auditoría",
            "detail": "El informe JSON incluye un hash de integridad SHA-256. "
                      "Este hash demuestra que el informe no fue modificado "
                      "tras su generación.",
            "tools": ["Campo 'integrity_hash' del JSON exportado"],
        },
    ]

    # Canales de denuncia en España
    COMPLAINT_CHANNELS = [
        {
            "channel": "AEPD — Agencia Española de Protección de Datos",
            "description": "Organismo competente para denuncias de vulneraciones de RGPD y LOPDGDD.",
            "url": "https://www.aepd.es/derechos-y-deberes/cumple-tus-derechos",
            "procedure": "Formulario online o carta. Plazo: sin plazo legal específico, "
                         "pero cuanto antes mejor.",
            "cost": "Gratuito",
            "for_what": "Monitorización sin información, tratamiento de datos sin base legal, "
                        "keylogging, capturas de pantalla, geolocalización.",
        },
        {
            "channel": "Inspección de Trabajo y Seguridad Social (ITSS)",
            "description": "Organismo que vela por el cumplimiento de la normativa laboral.",
            "url": "https://www.mites.gob.es/itss/web/Atencion_al_Ciudadano/",
            "procedure": "Denuncia presencial o telemática en la sede territorial.",
            "cost": "Gratuito",
            "for_what": "Vulneraciones del ET art. 20bis, monitorización excesiva, "
                        "despidos relacionados con datos de vigilancia.",
        },
        {
            "channel": "Representación sindical / Delegados de personal",
            "description": "Los representantes de los trabajadores tienen derecho a ser "
                           "informados sobre sistemas de control. Pueden actuar como mediadores.",
            "url": None,
            "procedure": "Contactar directamente con el delegado sindical de la empresa.",
            "cost": "Gratuito",
            "for_what": "Negociación colectiva, información sobre sistemas de control, "
                        "apoyo en conflictos laborales.",
        },
        {
            "channel": "Defensor del Pueblo",
            "description": "Puede intervenir cuando la AEPD o ITSS no actúan correctamente.",
            "url": "https://www.defensordelpueblo.es",
            "procedure": "Queja escrita o formulario online.",
            "cost": "Gratuito",
            "for_what": "Inactividad de organismos públicos de control.",
        },
        {
            "channel": "Juzgado de lo Social",
            "description": "Vía judicial para reclamaciones laborales relacionadas "
                           "con derechos digitales.",
            "url": None,
            "procedure": "Demanda laboral con asistencia letrada. "
                         "Previa conciliación en el SMAC.",
            "cost": "Asistencia jurídica gratuita si se cumplen requisitos de renta",
            "for_what": "Despidos relacionados con vigilancia, daños y perjuicios, "
                        "restauración de derechos vulnerados.",
        },
    ]

    # Derechos ejercitables ante el empleador
    WORKER_RIGHTS_REQUESTS = [
        {
            "right": "Derecho de información (RGPD art. 13)",
            "action": "Solicitar al DPO de la empresa información detallada sobre "
                      "qué datos personales se tratan, con qué finalidad, "
                      "base legal, período de conservación y destinatarios.",
            "template": "Solicitud de información sobre tratamiento de datos (RGPD art. 13/15)",
        },
        {
            "right": "Derecho de acceso (RGPD art. 15)",
            "action": "Solicitar al DPO copia de todos los datos personales del trabajador "
                      "que se encuentran en el sistema de la empresa, incluyendo logs "
                      "de actividad, registros de acceso y datos de monitorización.",
            "template": "Solicitud de acceso a datos personales (RGPD art. 15)",
        },
        {
            "right": "Derecho a la intimidad (ET art. 20bis + LOPDGDD art. 87)",
            "action": "Solicitar por escrito al empleador la política de uso de "
                      "dispositivos digitales y los criterios de uso aceptable, "
                      "que deben estar documentados y accesibles.",
            "template": "Solicitud de política de uso de dispositivos digitales",
        },
        {
            "right": "Información sobre control empresarial (ET art. 64.5)",
            "action": "Solicitar a través de los representantes de trabajadores "
                      "información sobre los sistemas de control y sus características. "
                      "Los representantes tienen derecho a esta información.",
            "template": "Solicitud de información a representantes de trabajadores",
        },
        {
            "right": "DPIA (RGPD art. 35)",
            "action": "Solicitar al DPO la evaluación de impacto (DPIA) si existe, "
                      "especialmente para sistemas de videovigilancia, "
                      "monitorización de productividad o análisis de comportamiento.",
            "template": "Solicitud de DPIA al DPO",
        },
    ]

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[IncidentResponse] Generando playbook de respuesta...")
        max_risk = self._get_max_risk()
        self._generate_worker_playbook(max_risk)
        self._generate_evidence_checklist()
        self._generate_rights_guide()
        print("[IncidentResponse] Playbook generado.")

    def _get_max_risk(self) -> str:
        order = {"green": 0, "yellow": 1, "orange": 2, "red": 3}
        if not self.engine.findings:
            return "green"
        return max(
            self.engine.findings,
            key=lambda f: order.get(f.risk_level, 0)
        ).risk_level

    # ── Playbook principal adaptado al riesgo ──────────────────────

    def _generate_worker_playbook(self, max_risk: str):
        from core.audit_engine import AuditFinding

        # Categorías de hallazgos detectados
        detected_categories = {f.category for f in self.engine.findings}

        # Construir pasos específicos según hallazgos
        specific_steps = self._build_specific_steps(detected_categories)

        # Determinar urgencia
        if max_risk == "red":
            urgency_key = "very_high"
        elif max_risk == "orange":
            urgency_key = "high"
        else:
            urgency_key = "orange"

        playbook = self.RISK_PLAYBOOKS.get(urgency_key, self.RISK_PLAYBOOKS["orange"])

        risk_summary = {
            "green": "Sin hallazgos significativos — configuración dentro de lo habitual.",
            "yellow": "Hallazgos de riesgo bajo-medio — monitorización corporativa estándar.",
            "orange": "Hallazgos de riesgo medio-alto — capacidades de vigilancia avanzadas.",
            "red": "Hallazgos de riesgo muy alto — vigilancia específica de empleados detectada.",
        }

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="incident_response_playbook",
            title=f"Playbook de respuesta al trabajador — Urgencia: {playbook['urgency']}",
            description=(
                f"Resumen de situación: {risk_summary.get(max_risk, '')} "
                f"Hallazgos activos: {len(self.engine.findings)}. "
                f"Categorías detectadas: {len(detected_categories)}."
            ),
            risk_level=max_risk if max_risk != "green" else "yellow",
            technical_risk=(
                "Este playbook sintetiza los hallazgos técnicos de todos los "
                "skills de auditoría ejecutados y los traduce en pasos de acción "
                "concretos para el trabajador."
            ),
            legal_risk=(
                "Las recomendaciones están basadas en RGPD, LOPDGDD, ET art. 20bis "
                "y la doctrina Barbulescu II del TEDH. "
                "No sustituyen al asesoramiento jurídico profesional."
            ),
            what_it_is=(
                "Guía de acción paso a paso para el trabajador, adaptada "
                "específicamente a los hallazgos de esta auditoría."
            ),
            what_it_is_not=(
                "No es asesoramiento jurídico profesional. Para casos graves, "
                "consultar con abogado laboralista o sindicato."
            ),
            raw_data={
                "max_risk": max_risk,
                "urgency": playbook["urgency"],
                "immediate_actions": playbook["immediate_actions"],
                "specific_steps": specific_steps,
                "complaint_channels": self.COMPLAINT_CHANNELS,
                "worker_rights": self.WORKER_RIGHTS_REQUESTS,
                "detected_categories": sorted(detected_categories),
                "total_findings": len(self.engine.findings),
                "generated_at": datetime.now().isoformat(),
            }
        ))

    def _build_specific_steps(self, categories: set) -> list[dict]:
        steps = []

        if any("keylog" in c or "input_hook" in c for c in categories):
            steps.append({
                "priority": "CRÍTICO",
                "finding": "Keylogger o hook de entrada detectado",
                "action": "Dejar de usar el equipo para cualquier comunicación privada. "
                          "No introducir contraseñas personales. "
                          "Consultar con asesor laboral de inmediato. "
                          "Presentar denuncia ante AEPD.",
            })

        if any("screenshot" in c or "screen_record" in c or
               "recall" in c or "behavior_monitoring" in c for c in categories):
            steps.append({
                "priority": "CRÍTICO",
                "finding": "Software de captura de pantalla o employee monitoring",
                "action": "No usar el equipo para asuntos personales. "
                          "Solicitar al DPO información sobre qué capturas se realizan. "
                          "Consultar con asesor laboral sobre CP art. 197.",
            })

        if any("forwarding" in c or "email" in c for c in categories):
            steps.append({
                "priority": "ALTO",
                "finding": "Configuración de email con posible supervisión",
                "action": "Revisar las reglas de Outlook (Inicio > Reglas). "
                          "No usar el email corporativo para asuntos personales. "
                          "Solicitar al DPO información sobre archivado de emails.",
            })

        if any("usb" in c for c in categories):
            steps.append({
                "priority": "MEDIO",
                "finding": "Políticas o software de control de USB detectado",
                "action": "Asumir que los dispositivos USB conectados son registrados. "
                          "Solicitar al DPO la política de dispositivos.",
            })

        if any("remote_access" in c or "rdp" in c for c in categories):
            steps.append({
                "priority": "ALTO",
                "finding": "Acceso remoto habilitado al equipo",
                "action": "Solicitar al empleador política de acceso remoto documentada. "
                          "Exigir notificación previa de cualquier acceso. "
                          "Verificar el log de eventos para accesos recientes.",
            })

        if any("teams_compliance" in c for c in categories):
            steps.append({
                "priority": "ALTO",
                "finding": "Teams con capacidades de supervisión corporativa",
                "action": "No usar Teams para comunicaciones privadas. "
                          "Solicitar al DPO si Communication Compliance está activo. "
                          "Verificar política de retención de mensajes.",
            })

        return steps

    # ── Checklist de evidencia ─────────────────────────────────────

    def _generate_evidence_checklist(self):
        from core.audit_engine import AuditFinding

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="incident_response_evidence",
            title="Checklist de preservación de evidencia digital",
            description=(
                "Pasos para preservar correctamente la evidencia de esta "
                "auditoría como prueba legal válida."
            ),
            risk_level="yellow",
            technical_risk=(
                "La evidencia digital tiene valor probatorio solo si se "
                "preserva correctamente con cadena de custodia documentada."
            ),
            legal_risk=(
                "La evidencia correctamente preservada puede ser aceptada "
                "en procedimientos ante la AEPD, Inspección de Trabajo "
                "o Juzgado de lo Social."
            ),
            what_it_is=(
                "Guía paso a paso para preservar este informe como evidencia "
                "digital con valor legal."
            ),
            what_it_is_not=(
                "No garantiza la admisibilidad judicial sin peritaje técnico. "
                "Para procedimientos judiciales, contactar con perito informático."
            ),
            raw_data={
                "evidence_steps": self.EVIDENCE_PRESERVATION,
                "note": (
                    "El hash SHA-256 del informe JSON generado por esta herramienta "
                    "permite verificar que no fue alterado. Guarda el valor del "
                    "campo 'integrity_hash' junto con el informe."
                )
            }
        ))

    # ── Guía de derechos ejercitables ──────────────────────────────

    def _generate_rights_guide(self):
        from core.audit_engine import AuditFinding

        high_risk_findings = [
            f for f in self.engine.findings
            if f.risk_level in ("red", "orange")
        ]

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="incident_response_rights",
            title=f"Guía de derechos y canales de denuncia "
                  f"({len(high_risk_findings)} hallazgos de riesgo alto/muy alto)",
            description=(
                "Resumen de los derechos del trabajador ejercitables ante "
                "los hallazgos de esta auditoría, y canales oficiales de denuncia."
            ),
            risk_level="yellow",
            technical_risk=(
                "Los hallazgos técnicos de alto riesgo tienen implicaciones "
                "legales que el trabajador puede defender ejerciendo sus derechos."
            ),
            legal_risk=(
                "El no ejercer estos derechos no implica consentimiento. "
                "La prescripción de las infracciones RGPD es de 3 años. "
                "Infracciones graves: hasta 20 millones € o 4% facturación global."
            ),
            what_it_is=(
                "Resumen de los derechos reconocidos en RGPD, LOPDGDD y ET "
                "aplicables a la situación detectada en esta auditoría."
            ),
            what_it_is_not=(
                "No es asesoramiento jurídico profesional. "
                "Para casos específicos, consultar con abogado laboralista."
            ),
            raw_data={
                "rights_to_exercise": self.WORKER_RIGHTS_REQUESTS,
                "complaint_channels": self.COMPLAINT_CHANNELS,
                "high_risk_findings_count": len(high_risk_findings),
                "legal_framework": {
                    "rgpd": "Reglamento (UE) 2016/679",
                    "lopdgdd": "Ley Orgánica 3/2018",
                    "et_20bis": "Estatuto de los Trabajadores art. 20 bis",
                    "barbulescu": "TEDH Gran Sala — Barbulescu II (2017)",
                    "aepd_guia": "Guía AEPD Relaciones Laborales (2021)",
                }
            }
        ))
