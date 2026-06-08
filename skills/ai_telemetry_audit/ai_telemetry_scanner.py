# skills/ai_telemetry_audit/ai_telemetry_scanner.py
"""
Skill 7 — AI & Telemetry Data Collection Audit
Detecta recopilación de datos por sistemas de IA integrados,
telemetría de Microsoft/OpenAI, Copilot, Windows Recall,
y endpoints de exfiltración de datos en segundo plano.
"""

import winreg
import subprocess
import json
import psutil
import os
import time
from pathlib import Path


# Endpoints de telemetría conocidos de Microsoft
MICROSOFT_TELEMETRY_ENDPOINTS = {
    "vortex.data.microsoft.com":      "Windows Telemetry (Vortex)",
    "telemetry.microsoft.com":        "Windows Telemetry",
    "settings-win.data.microsoft.com":"Windows Settings Telemetry",
    "watson.telemetry.microsoft.com": "Watson Crash Reporter",
    "oca.telemetry.microsoft.com":    "Office Crash Analytics",
    "mobile.pipe.aria.microsoft.com": "Microsoft ARIA Pipeline",
    "pipe.aria.microsoft.com":        "Microsoft ARIA Pipeline",
    "browser.pipe.aria.microsoft.com":"Edge ARIA Telemetry",
    "self.events.data.microsoft.com": "Microsoft Events Pipeline",
    "officeclienttelemetry.microsoft.com": "Office Client Telemetry",
    "europe.configsvc1.live.com.akadns.net": "Config Service Telemetry",
}

# Endpoints de OpenAI/Copilot
AI_ENDPOINTS = {
    "api.openai.com":               "OpenAI API",
    "copilot.microsoft.com":        "Microsoft Copilot",
    "substrate.office.com":         "Microsoft 365 Substrate (AI)",
    "augloop.office.com":           "Office Augmentation Loop (AI)",
    "designerapp.officeapps.live.com": "Microsoft Designer AI",
    "bing.com/chat":                "Bing Chat/Copilot",
    "sydney.bing.com":              "Bing Copilot Backend",
    "edgeservices.bing.com":        "Edge Copilot Services",
    "ntp.msn.com":                  "MSN/Copilot News Feed",
}

# Claves de registro de telemetría de Windows
TELEMETRY_REGISTRY_KEYS = {
    r"SOFTWARE\Policies\Microsoft\Windows\DataCollection": {
        "AllowTelemetry": {
            0: ("Desactivada por política", "green"),
            1: ("Básica", "yellow"),
            2: ("Mejorada", "orange"),
            3: ("Completa", "red"),
        }
    },
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection": {
        "AllowTelemetry": {
            0: ("Desactivada", "green"),
            1: ("Básica", "yellow"),
            2: ("Mejorada", "orange"),
            3: ("Completa — incluye contenido de documentos", "red"),
        }
    },
}

# Servicios de telemetría de Windows
TELEMETRY_SERVICES = {
    "DiagTrack":         "Connected User Experiences and Telemetry (telemetría completa)",
    "dmwappushservice":  "WAP Push Message Routing (telemetría móvil)",
    "WerSvc":            "Windows Error Reporting",
    "PcaSvc":            "Program Compatibility Assistant",
    "CDPSvc":            "Connected Devices Platform",
    "OneSyncSvc":        "Sync Host (sincronización de datos)",
}

# Procesos de Copilot y AI
AI_PROCESSES = {
    "copilot":           "Microsoft Copilot",
    "copilotruntime":    "Copilot Runtime",
    "aihost":            "Windows AI Host",
    "windowscopilot":    "Windows Copilot",
    "aisvc":             "AI Service",
    "cortana":           "Cortana (AI Assistant)",
    "searchapp":         "Windows Search (con AI)",
    "phi":               "Microsoft Phi (LLM local)",
    "openai":            "OpenAI local client",
    "openai-agent":      "OpenAI local agent",
    "anthropic":         "Anthropic local client",
    "claude":            "Anthropic Claude",
    "ollama":            "Ollama local model runner",
    "ollamadrive":       "Ollama runtime",
    "axet":              "Axet corporate AI client",
    "gaia":              "Gaia corporate AI client",
    "oasis":             "Oasis corporate AI client",
}

# Servicios de cliente/servicio de IA locales
AI_SERVICES = {
    "OpenAI":    "OpenAI local service",
    "Anthropic": "Anthropic local service",
    "Ollama":    "Ollama local model service",
    "Axet":      "Axet corporate AI service",
    "Gaia":      "Gaia corporate AI service",
    "Oasis":     "Oasis corporate AI service",
}


class AITelemetryAudit:
    SKILL_NAME = "ai_telemetry_audit"

    def __init__(self, engine):
        self.engine = engine
        self.running_procs = self._get_processes()

    def run(self):
        print("[AI/Telemetry] Iniciando auditoría de telemetría e IA...")
        self._check_windows_telemetry_level()
        self._check_telemetry_services()
        self._check_copilot_recall()
        self._check_ai_services()
        self._check_ai_processes()
        self._check_office_telemetry()
        self._check_diagnostic_data_export()
        self._check_connected_experiences()

    def _get_processes(self) -> set:
        procs = set()
        for p in psutil.process_iter(["name"]):
            try:
                procs.add(p.info["name"].lower().replace(".exe", ""))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    # ── Nivel de telemetría de Windows ────────────────────────────

    def _check_windows_telemetry_level(self):
        from core.audit_engine import AuditFinding

        telemetry_level = None
        telemetry_label = "Desconocido"
        risk = "yellow"
        source = ""

        for reg_path, values in TELEMETRY_REGISTRY_KEYS.items():
            for value_name, levels in values.items():
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        reg_path, 0, winreg.KEY_READ
                    )
                    val, _ = winreg.QueryValueEx(key, value_name)
                    winreg.CloseKey(key)
                    if val in levels:
                        telemetry_label, risk = levels[val]
                        telemetry_level = val
                        source = reg_path
                        break
                except (FileNotFoundError, PermissionError, OSError):
                    pass
            if telemetry_level is not None:
                break

        # Si no hay política, Windows usa nivel 3 por defecto
        if telemetry_level is None:
            telemetry_label = "Completa (por defecto, sin política restrictiva)"
            risk = "red"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="telemetry_windows_level",
            title=f"Nivel de telemetría de Windows: {telemetry_label}",
            description=(
                f"Windows está configurado para enviar telemetría "
                f"en nivel: {telemetry_label}. "
                f"{'Política aplicada en: ' + source if source else 'Sin política restrictiva aplicada.'}"
            ),
            risk_level=risk,
            technical_risk=(
                "Nivel Completo (3): Microsoft recopila contenido de documentos, "
                "historial de navegación, uso de aplicaciones, búsquedas, "
                "voz, tinta digital y diagnósticos detallados del sistema. "
                "Nivel Básico (1): hardware, crashes, compatibilidad. "
                "Nivel Mejorado (2): uso de apps y rendimiento."
            ),
            legal_risk=(
                "La telemetría de nivel completo transfiere datos personales "
                "a Microsoft fuera del EEE sin control explícito del trabajador. "
                "Requiere análisis bajo RGPD capítulo V (transferencias internacionales) "
                "y base legal bajo art. 6 RGPD."
            ),
            what_it_is=(
                "Windows envía datos de uso, diagnóstico y en niveles altos "
                "contenido de documentos y actividad del usuario a servidores "
                "de Microsoft en EEUU."
            ),
            what_it_is_not=(
                "No todo dato enviado es ilegal. La base legal puede ser "
                "interés legítimo o contrato de servicio. "
                "El problema es la falta de transparencia y control."
            ),
            raw_data={
                "telemetry_level": telemetry_level,
                "label": telemetry_label,
                "source": source
            }
        ))
        print(f"[AI/Telemetry] Telemetría Windows: {telemetry_label} — {risk.upper()}")

    # ── Servicios de telemetría ────────────────────────────────────

    def _check_telemetry_services(self):
        from core.audit_engine import AuditFinding

        active_services = {}
        for svc_name, description in TELEMETRY_SERVICES.items():
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-Service -Name '{svc_name}' "
                     f"-ErrorAction SilentlyContinue).Status"],
                    capture_output=True, text=True, timeout=8
                )
                status = result.stdout.strip()
                if status == "Running":
                    active_services[svc_name] = description
            except Exception:
                pass

        if active_services:
            # DiagTrack es el más invasivo
            risk = "red" if "DiagTrack" in active_services else "orange"
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="telemetry_services",
                title=f"Servicios de telemetría activos "
                      f"({len(active_services)} en ejecución)",
                description=(
                    "Servicios de Windows activos dedicados a recopilar "
                    "y enviar datos de uso y diagnóstico a Microsoft."
                ),
                risk_level=risk,
                technical_risk=(
                    "DiagTrack (Connected User Experiences) es el servicio "
                    "principal de telemetría. Recopila continuamente datos "
                    "de actividad y los envía a Microsoft. "
                    "No se puede desactivar completamente en Windows 11 Home."
                ),
                legal_risk=(
                    "Los servicios de telemetría operan como tratamiento "
                    "continuo de datos personales. En equipos corporativos "
                    "el empleador es corresponsable del tratamiento "
                    "bajo RGPD art. 26."
                ),
                what_it_is=(
                    "Servicios de Windows que recopilan y transmiten "
                    "datos de uso, errores y diagnóstico a Microsoft."
                ),
                what_it_is_not=(
                    "No todos los datos son personales en sentido estricto. "
                    "Muchos son datos técnicos de hardware y estabilidad."
                ),
                raw_data={"active_telemetry_services": active_services}
            ))

    # ── Copilot y Windows Recall ───────────────────────────────────

    def _check_copilot_recall(self):
        from core.audit_engine import AuditFinding

        recall_status = self._get_recall_status()
        copilot_status = self._get_copilot_status()

        if recall_status["enabled"]:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ai_windows_recall",
                title="Windows Recall activo — IA indexando toda tu actividad",
                description=(
                    "Windows Recall está habilitado y capturando "
                    "snapshots continuos de la pantalla para análisis "
                    "mediante IA local."
                ),
                risk_level="red",
                technical_risk=(
                    "Recall captura una imagen de la pantalla cada pocos segundos, "
                    "la procesa con un modelo de IA local (NPU) y la indexa "
                    "en una base de datos SQLite local. "
                    "Incluye: documentos abiertos, correos leídos, "
                    "webs visitadas, conversaciones, contraseñas visibles, "
                    "datos bancarios en pantalla."
                ),
                legal_risk=(
                    "Recall crea un perfil temporal completo de la actividad "
                    "del trabajador. En equipos corporativos, "
                    "el empleador podría acceder a esta base de datos. "
                    "Riesgo muy alto bajo LOPDGDD art. 87, RGPD art. 5 "
                    "y posiblemente art. 89 LOPDGDD (videovigilancia análoga)."
                ),
                what_it_is=(
                    "Windows Recall es una función de Windows 11 que usa IA "
                    "para indexar todo lo que aparece en pantalla, "
                    "permitiendo búsquedas de actividad pasada."
                ),
                what_it_is_not=(
                    "Microsoft afirma que los datos no salen del dispositivo. "
                    "Sin embargo, la base de datos local es accesible "
                    "para cualquier proceso con privilegios suficientes."
                ),
                raw_data=recall_status
            ))

        if copilot_status["enabled"]:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ai_copilot",
                title="Microsoft Copilot habilitado — IA con acceso al contexto",
                description=(
                    "Microsoft Copilot está activo y puede acceder "
                    "al contenido de documentos, correos y actividad "
                    "para generar respuestas."
                ),
                risk_level="orange",
                technical_risk=(
                    "Copilot accede a: contenido de emails (Outlook), "
                    "documentos (Word, Excel, Teams), historial de reuniones, "
                    "mensajes de Teams, y actividad de Microsoft 365. "
                    "Estos datos se procesan en servidores de Microsoft."
                ),
                legal_risk=(
                    "El procesamiento de comunicaciones laborales "
                    "mediante IA requiere base legal explícita, "
                    "evaluación de impacto (DPIA) y en muchos casos "
                    "consulta previa a representantes de trabajadores. "
                    "Ver RGPD art. 35 y GT29/EDPB."
                ),
                what_it_is=(
                    "IA integrada en Microsoft 365 que analiza el contenido "
                    "de trabajo para generar sugerencias, resúmenes "
                    "y automatizaciones."
                ),
                what_it_is_not=(
                    "Microsoft afirma que los datos de Copilot "
                    "no se usan para entrenar modelos globales. "
                    "Esta afirmación tiene matices importantes en los ToS."
                ),
                raw_data=copilot_status
            ))

    def _get_recall_status(self) -> dict:
        status = {"enabled": False, "database_found": False, "path": ""}
        try:
            # Busca la base de datos de Recall
            recall_db = Path.home() / "AppData" / "Local" / "CoreAIPlatform.00" / "UKP"
            if recall_db.exists():
                status["enabled"] = True
                status["database_found"] = True
                status["path"] = str(recall_db)
                return status

            # Verifica política de registro
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
                0, winreg.KEY_READ
            )
            try:
                val, _ = winreg.QueryValueEx(key, "DisableAIDataAnalysis")
                status["enabled"] = (val == 0)
            except (FileNotFoundError, OSError):
                status["enabled"] = True  # Por defecto activo
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return status

    def _get_copilot_status(self) -> dict:
        status = {"enabled": False, "sources": []}
        try:
            # Proceso activo
            if any("copilot" in p for p in self.running_procs):
                status["enabled"] = True
                status["sources"].append("process_running")

            # Política de Edge/Windows Copilot
            copilot_keys = [
                r"SOFTWARE\Policies\Microsoft\Edge\HubsSidebarEnabled",
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
            ]
            for reg_path in copilot_keys:
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        reg_path, 0, winreg.KEY_READ
                    )
                    winreg.CloseKey(key)
                    status["enabled"] = True
                    status["sources"].append(reg_path)
                except (FileNotFoundError, PermissionError, OSError):
                    pass
        except Exception:
            pass
        return status

    # ── Procesos de IA ─────────────────────────────────────────────

    def _check_ai_processes(self):
        from core.audit_engine import AuditFinding

        found = {
            name: desc for name, desc in AI_PROCESSES.items()
            if name in self.running_procs
        }

        if found:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ai_processes",
                title=f"Procesos de IA activos en segundo plano "
                      f"({len(found)})",
                description=(
                    "Se han detectado procesos de inteligencia artificial "
                    "ejecutándose en segundo plano."
                ),
                risk_level="orange",
                technical_risk=(
                    "Los procesos de IA pueden procesar contenido local "
                    "(documentos, pantalla, voz) y enviarlo a APIs externas "
                    "para inferencia en la nube."
                ),
                legal_risk=(
                    "El procesamiento de datos laborales mediante IA "
                    "requiere transparencia y base legal bajo RGPD art. 22 "
                    "si involucra decisiones automatizadas."
                ),
                what_it_is=(
                    "Procesos que ejecutan modelos de IA o se comunican "
                    "con servicios de IA en la nube."
                ),
                what_it_is_not=(
                    "No toda IA es invasiva. Muchas funciones de IA "
                    "son locales y no transmiten datos personales."
                ),
                raw_data={"ai_processes": found}
            ))

    # ── Servicios de IA locales ─────────────────────────────────────

    def _check_ai_services(self):
        from core.audit_engine import AuditFinding

        active_services = {}
        for svc_name, description in AI_SERVICES.items():
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-Service -Name '{svc_name}' -ErrorAction SilentlyContinue).Status"],
                    capture_output=True, text=True, timeout=8
                )
                status = result.stdout.strip()
                if status == "Running":
                    active_services[svc_name] = description
            except Exception:
                pass

        if active_services:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ai_services",
                title=f"Servicios de IA locales activos ({len(active_services)})",
                description=(
                    "Se han detectado servicios locales de inteligencia artificial "
                    "activos en el sistema."
                ),
                risk_level="orange",
                technical_risk=(
                    "Los servicios de IA locales pueden procesar contenido del equipo "
                    "y trasladarlo a motores de inferencia locales o remotos."
                ),
                legal_risk=(
                    "El uso de servicios de IA locales en entornos de trabajo puede "
                    "implicar tratamiento de datos personales y propiedad intelectual."
                ),
                what_it_is=(
                    "Servicios locales que ejecutan o coordinan clientes de IA "
                    "como OpenAI, Anthropic, Ollama o herramientas corporativas."
                ),
                what_it_is_not=(
                    "No indica necesariamente que los datos se envíen fuera del dispositivo. "
                    "Es un indicador de exposición de IA local.") ,
                raw_data={"ai_services": active_services}
            ))

    # ── Telemetría de Office ───────────────────────────────────────

    def _check_office_telemetry(self):
        from core.audit_engine import AuditFinding

        office_telemetry = {}

        office_keys = [
            r"SOFTWARE\Policies\Microsoft\Office\16.0\Common\Privacy",
            r"SOFTWARE\Microsoft\Office\16.0\Common\Privacy",
        ]

        privacy_settings = {
            "ControllerConnectedServicesEnabled": "Servicios conectados de Office",
            "SendTelemetry":                      "Nivel de telemetría de Office",
            "UserContentDisabled":                "Contenido de usuario en telemetría",
            "DownloadContentDisabled":            "Descarga de contenido conectado",
        }

        for reg_path in office_keys:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    reg_path, 0, winreg.KEY_READ
                )
                for setting, label in privacy_settings.items():
                    try:
                        val, _ = winreg.QueryValueEx(key, setting)
                        office_telemetry[label] = val
                    except (FileNotFoundError, OSError):
                        pass
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        # Si no hay restricciones de política, Office envía telemetría completa
        if not office_telemetry:
            office_telemetry["estado"] = (
                "Sin política restrictiva — telemetría completa por defecto"
            )
            risk = "orange"
        else:
            risk = "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="telemetry_office",
            title="Telemetría de Microsoft Office/365",
            description=(
                "Microsoft Office recopila datos de uso de documentos, "
                "funciones utilizadas y en configuración por defecto "
                "fragmentos de contenido para mejora del producto."
            ),
            risk_level=risk,
            technical_risk=(
                "Office 365 puede enviar: nombres de archivos, "
                "tipos de contenido, funciones usadas, errores, "
                "y con servicios conectados activos: "
                "fragmentos de texto para traducción, corrección "
                "y sugerencias de IA."
            ),
            legal_risk=(
                "El envío de contenido de documentos laborales "
                "a Microsoft puede incluir datos personales de terceros "
                "(clientes, empleados) sin base legal adecuada. "
                "Responsabilidad del empleador como responsable del tratamiento."
            ),
            what_it_is=(
                "Sistema de telemetría de Microsoft Office que recopila "
                "datos de uso y en algunos casos contenido de documentos."
            ),
            what_it_is_not=(
                "Microsoft afirma que el contenido de documentos "
                "no se usa sin consentimiento. "
                "Los Terms of Service tienen excepciones amplias."
            ),
            raw_data={"office_privacy_settings": office_telemetry}
        ))

    # ── Diagnóstico y exportación de datos ────────────────────────

    def _check_diagnostic_data_export(self):
        from core.audit_engine import AuditFinding

        diagnostic_path = (
            Path.home() / "AppData" / "Local" /
            "Microsoft" / "Windows" / "DiagnosticData"
        )

        findings = {}

        if diagnostic_path.exists():
            try:
                # Escaneo acotado para evitar bloqueos largos
                scan_start = time.monotonic()
                max_scan_seconds = 5.0
                max_files = 5000

                db_count = 0
                json_count = 0
                scanned_files = 0
                total_size_bytes = 0
                truncated = False

                for root, _, files in os.walk(diagnostic_path):
                    for file_name in files:
                        scanned_files += 1
                        if scanned_files > max_files or (
                            time.monotonic() - scan_start
                        ) > max_scan_seconds:
                            truncated = True
                            break

                        file_path = Path(root) / file_name
                        suffix = file_path.suffix.lower()
                        if suffix == ".db":
                            db_count += 1
                        elif suffix == ".json":
                            json_count += 1

                        try:
                            total_size_bytes += file_path.stat().st_size
                        except OSError:
                            pass

                    if truncated:
                        break

                findings["diagnostic_db_count"] = db_count
                findings["diagnostic_json_count"] = json_count
                findings["path"] = str(diagnostic_path)
                findings["total_size_mb"] = round(total_size_bytes / 1024 / 1024, 2)
                findings["scanned_files"] = scanned_files
                findings["scan_truncated"] = truncated
            except Exception:
                pass

        if findings:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="telemetry_diagnostic_cache",
                title=f"Caché de datos diagnósticos local "
                      f"({findings.get('total_size_mb', '?')} MB)",
                description=(
                    "Windows mantiene localmente una base de datos "
                    "de datos diagnósticos antes de enviarlos a Microsoft."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Esta caché contiene datos de actividad reciente "
                    "pendientes de envío a Microsoft. "
                    "Accesible para procesos con privilegios de administrador."
                ),
                legal_risk=(
                    "La existencia de esta caché local es evidencia "
                    "de la recopilación continua de datos de actividad."
                ),
                what_it_is=(
                    "Almacén local de datos de telemetría de Windows "
                    "pendientes de envío a servidores de Microsoft."
                ),
                what_it_is_not=(
                    "No contiene datos personales en formato legible directamente. "
                    "Son datos estructurados de diagnóstico del sistema."
                ),
                raw_data=findings
            ))

    # ── Experiencias conectadas ────────────────────────────────────

    def _check_connected_experiences(self):
        from core.audit_engine import AuditFinding

        connected_exp = {}

        exp_keys = {
            r"SOFTWARE\Policies\Microsoft\Office\16.0\Common\Privacy\DisconnectedState":
                "Estado desconectado de Office",
            r"SOFTWARE\Microsoft\Office\16.0\Common\PrivacyLogs":
                "Logs de privacidad de Office",
        }

        # Verifica si las experiencias conectadas están habilitadas
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ItemProperty "
                 "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0"
                 "\\Common\\Privacy' "
                 "-ErrorAction SilentlyContinue | "
                 "Select-Object ControllerConnectedServicesEnabled, "
                 "SendTelemetry | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if data:
                    connected_exp = data
        except Exception:
            pass

        # Si no hay política desactivándolas, están activas por defecto
        controller_enabled = connected_exp.get(
            "ControllerConnectedServicesEnabled"
        )
        if controller_enabled is None or controller_enabled == 1:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="ai_connected_experiences",
                title="Experiencias conectadas de Office activas — "
                      "contenido enviado a Microsoft",
                description=(
                    "Las 'experiencias conectadas' de Microsoft 365 están "
                    "activas. Esto permite a Office analizar contenido "
                    "de documentos para ofrecer funciones de IA y nube."
                ),
                risk_level="orange",
                technical_risk=(
                    "Las experiencias conectadas incluyen: "
                    "traducción automática de documentos, "
                    "sugerencias de escritura con IA (Editor), "
                    "búsqueda inteligente (contenido enviado a Bing), "
                    "PowerPoint Designer (imágenes y contenido de diapositivas), "
                    "y análisis de datos en Excel con IA."
                ),
                legal_risk=(
                    "El contenido de documentos laborales que se envía "
                    "a Microsoft para procesamiento de IA puede incluir "
                    "datos personales de clientes o empleados. "
                    "El empleador debe tener DPA con Microsoft "
                    "y base legal bajo RGPD art. 6 y 28."
                ),
                what_it_is=(
                    "Funciones de Microsoft 365 que requieren enviar "
                    "contenido a servidores de Microsoft para funcionar: "
                    "traducción, diseño, sugerencias de IA."
                ),
                what_it_is_not=(
                    "No es espionaje directo. Es el modelo de negocio "
                    "de SaaS: el servicio requiere acceso al contenido "
                    "para funcionar. El problema es la transparencia "
                    "y el control del usuario."
                ),
                raw_data={
                    "connected_experiences_policy": connected_exp,
                    "enabled_by_default": controller_enabled is None
                }
            ))

        print("[AI/Telemetry] Completado")