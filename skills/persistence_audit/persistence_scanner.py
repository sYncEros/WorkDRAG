# skills/persistence_audit/persistence_scanner.py
"""
Skill 3 — Auditoría de Persistencia e Infraestructura Oculta
Detecta persistencia en registro, tareas, drivers, WMI y certificados
"""

import winreg
import subprocess
import hashlib
import json
from pathlib import Path
from datetime import datetime
from core.capability_intel import (
    get_sources,
    gpresult_summary,
    certutil_root_summary,
    fltmc_summary,
    confidence_from_evidence,
)


class PersistenceAudit:
    SKILL_NAME = "persistence_audit"

    # Claves de autorun conocidas
    AUTORUN_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]

    # Servicios que son señales de monitorización
    MONITORING_SERVICE_KEYWORDS = [
        "monitor", "agent", "telemetry", "track", "log",
        "audit", "watch", "sensor", "insight", "collect",
        "record", "capture", "observe"
    ]

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[Persistence] Iniciando auditoría de persistencia...")
        self._check_autorun_entries()
        self._check_suspicious_services()
        self._check_scheduled_tasks()
        self._check_wmi_persistence()
        self._check_drivers()
        self._check_dll_hijacking_vectors()
        self._check_untrusted_root_certs()

    # ── Autorun del registro ───────────────────────────────────────

    def _check_autorun_entries(self):
        from core.audit_engine import AuditFinding

        all_entries = []

        for hive, path in self.AUTORUN_KEYS:
            hive_name = (
                "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            )
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        all_entries.append({
                            "hive": hive_name,
                            "path": path,
                            "name": name,
                            "value": str(value),
                            "suspicious": self._is_suspicious_autorun(
                                name, str(value)
                            )
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        suspicious = [e for e in all_entries if e["suspicious"]]

        if suspicious:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="persistence_registry",
                title=f"Entradas de autorun sospechosas en registro "
                      f"({len(suspicious)} encontradas)",
                description=(
                    "Se han detectado entradas de inicio automático en el "
                    "registro con características de software de monitorización."
                ),
                risk_level="orange",
                technical_risk=(
                    "Estas entradas ejecutan software automáticamente al "
                    "iniciar sesión. Pueden incluir agentes de monitorización."
                ),
                legal_risk=(
                    "Si el software ejecutado monitoriza al trabajador sin "
                    "conocimiento, puede vulnerar LOPDGDD y ET art. 20bis."
                ),
                what_it_is=(
                    "Claves de registro que inician programas automáticamente "
                    "cuando el usuario inicia sesión en Windows."
                ),
                what_it_is_not=(
                    "No todo autorun es malicioso. Muchos son software "
                    "legítimo: antivirus, actualizadores, drivers."
                ),
                raw_data={
                    "all_entries": len(all_entries),
                    "suspicious": suspicious
                }
            ))
            for s in suspicious:
                print(
                    f"[Persistence] Autorun sospechoso: "
                    f"{s['name']} → {s['value'][:60]}"
                )

    def _is_suspicious_autorun(self, name: str, value: str) -> bool:
        keywords = self.MONITORING_SERVICE_KEYWORDS + [
            "edr", "dlp", "xdr", "falcon", "sentinel",
            "tanium", "netskope", "zscaler", "activtrak",
            "teramind", "hubstaff", "veriato"
        ]
        combined = (name + value).lower()
        return any(k in combined for k in keywords)

    # ── Servicios sospechosos ──────────────────────────────────────

    def _check_suspicious_services(self):
        from core.audit_engine import AuditFinding

        suspicious_services = []
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(key, idx)
                    if self._is_monitoring_service(svc_name):
                        info = self._get_service_info(svc_name)
                        if info:
                            suspicious_services.append(info)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as e:
            print(f"[Persistence] Error leyendo servicios: {e}")

        if suspicious_services:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="persistence_services",
                title=f"Servicios con características de monitorización "
                      f"({len(suspicious_services)} detectados)",
                description=(
                    "Se han encontrado servicios de Windows con nombres o "
                    "descripciones relacionadas con telemetría o monitorización."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Los servicios de Windows se ejecutan en segundo plano "
                    "con privilegios elevados y pueden monitorizar el sistema."
                ),
                legal_risk=(
                    "Depende de la funcionalidad real. "
                    "Requiere análisis individual de cada servicio."
                ),
                what_it_is=(
                    "Servicios de Windows que se ejecutan continuamente "
                    "en segundo plano."
                ),
                what_it_is_not=(
                    "No todo servicio con estas palabras es espionaje. "
                    "Windows incluye muchos servicios de telemetría propios."
                ),
                raw_data={"services": suspicious_services}
            ))

    def _is_monitoring_service(self, name: str) -> bool:
        return any(
            k in name.lower()
            for k in self.MONITORING_SERVICE_KEYWORDS
        )

    def _get_service_info(self, svc_name: str) -> dict | None:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                0, winreg.KEY_READ
            )
            info = {"name": svc_name}
            for field in ["DisplayName", "Description", "ImagePath", "Start"]:
                try:
                    val, _ = winreg.QueryValueEx(key, field)
                    info[field.lower()] = str(val)
                except (FileNotFoundError, PermissionError, OSError):
                    pass
            winreg.CloseKey(key)
            return info
        except Exception:
            return None

    # ── Tareas programadas ─────────────────────────────────────────

    def _check_scheduled_tasks(self):
        from core.audit_engine import AuditFinding

        suspicious_tasks = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ScheduledTask | Where-Object { "
                 "$_.TaskPath -notlike '\\Microsoft\\*' } | "
                 "Select-Object TaskName, TaskPath, State | "
                 "ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=45
            )
            if result.returncode == 0 and result.stdout.strip():
                tasks = json.loads(result.stdout)
                if isinstance(tasks, dict):
                    tasks = [tasks]
                for task in tasks:
                    name = task.get("TaskName", "").lower()
                    if any(
                        k in name for k in self.MONITORING_SERVICE_KEYWORDS
                    ):
                        suspicious_tasks.append(task)
        except Exception as e:
            print(f"[Persistence] Error leyendo tareas: {e}")

        if suspicious_tasks:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="persistence_tasks",
                title=f"Tareas programadas con indicadores de monitorización "
                      f"({len(suspicious_tasks)})",
                description=(
                    "Tareas programadas fuera del espacio Microsoft con "
                    "nombres relacionados con monitorización o telemetría."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Las tareas programadas pueden ejecutar software "
                    "periódicamente para recopilar o enviar datos."
                ),
                legal_risk=(
                    "Requiere análisis del contenido de cada tarea. "
                    "Por sí solas no implican ilegalidad."
                ),
                what_it_is=(
                    "Tareas de Windows Task Scheduler que se ejecutan "
                    "automáticamente según un calendario definido."
                ),
                what_it_is_not=(
                    "No todo es vigilancia. Las tareas pueden ser "
                    "actualizaciones, backups o mantenimiento."
                ),
                raw_data={"tasks": suspicious_tasks}
            ))

    # ── Persistencia WMI ───────────────────────────────────────────

    def _check_wmi_persistence(self):
        from core.audit_engine import AuditFinding

        wmi_findings = []
        queries = [
            ("EventFilter",
             "SELECT * FROM __EventFilter WHERE Name != '__TimerEvent'"),
            ("EventConsumer",
             "SELECT * FROM __EventConsumer"),
        ]

        for class_name, query in queries:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"Get-WMIObject -Namespace root\\subscription "
                     f"-Class {class_name} | "
                     f"Select-Object Name, Query | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if data:
                        if isinstance(data, dict):
                            data = [data]
                        wmi_findings.extend([
                            {**item, "_class": class_name}
                            for item in data
                        ])
            except Exception:
                pass

        if wmi_findings:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="persistence_wmi",
                title=f"Persistencia WMI detectada ({len(wmi_findings)} objetos)",
                description=(
                    "Se han encontrado suscripciones WMI activas fuera de "
                    "las predeterminadas del sistema."
                ),
                risk_level="orange",
                technical_risk=(
                    "La persistencia WMI es una técnica avanzada que permite "
                    "ejecutar código de forma oculta ante eventos del sistema. "
                    "Difícil de detectar para usuarios estándar."
                ),
                legal_risk=(
                    "Su uso para monitorización encubierta sería especialmente "
                    "grave desde el punto de vista legal."
                ),
                what_it_is=(
                    "WMI Event Subscriptions permiten ejecutar código "
                    "cuando ocurren eventos del sistema (inicio, login, etc.)."
                ),
                what_it_is_not=(
                    "Algunos productos legítimos usan WMI. "
                    "No es malicioso por definición."
                ),
                raw_data={"wmi_objects": wmi_findings}
            ))

    # ── Controladores ───────────────────────────────────────────────

    def _check_drivers(self):
        from core.audit_engine import AuditFinding

        monitoring_drivers = []
        driver_keywords = [
            "monitor", "agent", "sensor", "filter",
            "capture", "hook", "intercept", "inspect"
        ]

        known_vendor_drivers = [
            "csagent",      # CrowdStrike
            "sentinelle",   # SentinelOne
            "mfefirek",     # McAfee
            "aswsnx",       # Avast
            "klflt",        # Kaspersky
        ]

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject Win32_SystemDriver | "
                 "Select-Object Name, DisplayName, State, PathName | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=45
            )
            if result.returncode == 0 and result.stdout.strip():
                drivers = json.loads(result.stdout)
                if isinstance(drivers, dict):
                    drivers = [drivers]
                for drv in drivers:
                    name = drv.get("Name", "").lower()
                    display = drv.get("DisplayName", "").lower()
                    if (
                        any(k in name or k in display for k in driver_keywords)
                        or name in known_vendor_drivers
                    ):
                        monitoring_drivers.append({
                            "name": drv.get("Name"),
                            "display": drv.get("DisplayName"),
                            "state": drv.get("State"),
                            "path": drv.get("PathName"),
                        })
        except Exception as e:
            print(f"[Persistence] Error leyendo drivers: {e}")

        if monitoring_drivers:
            sources = get_sources(
                "endpoint_monitoring_capabilities",
                "worker_rights_and_surveillance_context",
            )
            triangulation = {
                "fltmc_filters": fltmc_summary(),
                "gpresult": gpresult_summary(),
            }
            confidence = confidence_from_evidence(
                sources,
                triangulation,
                direct_indicators_count=len(monitoring_drivers),
            )
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="persistence_drivers",
                title=f"Drivers con características de monitorización "
                      f"({len(monitoring_drivers)})",
                description=(
                    "Drivers de kernel con nombres o funciones relacionadas "
                    "con captura o filtrado de datos."
                ),
                risk_level="yellow",
                technical_risk=(
                    "Los drivers de kernel tienen acceso privilegiado "
                    "a todo el sistema: red, ficheros, procesos, entrada."
                ),
                legal_risk=(
                    "Depende del fabricante y función. "
                    "EDR/antivirus usan drivers legítimamente."
                ),
                what_it_is=(
                    "Drivers de Windows que operan a nivel de kernel "
                    "para interceptar o filtrar actividad del sistema."
                ),
                what_it_is_not=(
                    "La mayoría son componentes de seguridad legítimos "
                    "(antivirus, EDR). No implican espionaje por definición."
                ),
                raw_data={
                    "drivers": monitoring_drivers,
                    "independent_sources": sources,
                    "triangulation": triangulation,
                    "confidence": confidence,
                }
            ))

        print(
            f"[Persistence] Completado — "
            f"Drivers relevantes: {len(monitoring_drivers)}"
        )

    # ── DLL Hijacking (rutas de búsqueda conocidas) ────────────────

    def _check_dll_hijacking_vectors(self):
        from core.audit_engine import AuditFinding
        from pathlib import Path

        hijack_risks = []

        # Comprobar si CWD (directorio actual) tiene prioridad en DLL search order
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                0, winreg.KEY_READ
            )
            try:
                safe_mode, _ = winreg.QueryValueEx(key, "SafeDllSearchMode")
                if int(safe_mode) == 0:
                    hijack_risks.append({
                        "vector": "SafeDllSearchMode deshabilitado",
                        "registry": r"HKLM\SYSTEM\...\Session Manager\SafeDllSearchMode=0",
                        "severity": "high",
                        "detail": (
                            "Con SafeDllSearchMode=0, Windows busca DLLs en el "
                            "directorio actual ANTES que en System32. Esto facilita "
                            "el DLL hijacking: un atacante puede colocar una DLL "
                            "maliciosa en el directorio de trabajo."
                        ),
                    })
            except (FileNotFoundError, PermissionError, OSError):
                pass
            winreg.CloseKey(key)
        except Exception:
            pass

        # Comprobar Known DLLs — si hay entradas no estándar pueden indicar hijacking
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
                0, winreg.KEY_READ
            )
            standard_known_dlls = {
                "advapi32", "clbcatq", "com", "comdlg32", "difxapi",
                "gdi32", "imagehlp", "imm32", "iertutil", "kernel32",
                "msctf", "msvcrt", "normaliz", "nsi", "ntdll", "ole32",
                "oleaut32", "psapi", "rpcrt4", "sechost", "setupapi",
                "shell32", "shlwapi", "user32", "usp10", "wldap32",
                "wow64", "wow64cpu", "wow64win",
            }
            idx = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, idx)
                    dll_base = name.lower().replace(".dll", "")
                    if dll_base not in standard_known_dlls:
                        hijack_risks.append({
                            "vector": "KnownDLL no estándar",
                            "dll": name,
                            "value": str(value),
                            "severity": "medium",
                            "detail": (
                                f"La DLL '{name}' aparece en KnownDLLs pero no es "
                                f"estándar de Windows. Puede haber sido añadida para "
                                f"interceptar llamadas a esta librería."
                            ),
                        })
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

        # Comprobar directorios en PATH del sistema con permisos de escritura para usuarios
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "$paths = $env:PATH -split ';'; "
                 "foreach ($p in $paths) { "
                 "  if (Test-Path $p) { "
                 "    $acl = Get-Acl $p -ErrorAction SilentlyContinue; "
                 "    $writable = $acl.Access | Where-Object { "
                 "      ($_.IdentityReference -match 'Users|Everyone|Authenticated') -and "
                 "      ($_.FileSystemRights -match 'Write|FullControl|Modify') -and "
                 "      ($_.AccessControlType -eq 'Allow') "
                 "    }; "
                 "    if ($writable) { "
                 "      @{ Path=$p; WriteAccess=$true } | ConvertTo-Json "
                 "    } "
                 "  } "
                 "}"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                # Output can be multiple JSON objects
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            data = json.loads(line)
                            path_val = data.get("Path", "")
                            if path_val and "system32" not in path_val.lower():
                                hijack_risks.append({
                                    "vector": "Directorio PATH escribible por usuarios",
                                    "path": path_val,
                                    "severity": "medium",
                                    "detail": (
                                        f"El directorio '{path_val}' está en el PATH del "
                                        f"sistema y tiene permisos de escritura para usuarios "
                                        f"estándar. Permite DLL hijacking para aplicaciones "
                                        f"que carguen DLLs sin ruta absoluta."
                                    ),
                                })
                        except (json.JSONDecodeError, ValueError):
                            pass
        except Exception:
            pass

        if not hijack_risks:
            return

        high_severity = [r for r in hijack_risks if r.get("severity") == "high"]
        risk = "orange" if high_severity else "yellow"

        sources = get_sources(
            "endpoint_monitoring_capabilities",
            "event_and_logging_capabilities",
        )
        triangulation = {
            "fltmc_filters": fltmc_summary(),
            "gpresult": gpresult_summary(),
        }
        confidence = confidence_from_evidence(
            sources,
            triangulation,
            direct_indicators_count=len(hijack_risks),
        )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="persistence_dll_hijacking",
            title=f"Vectores de DLL hijacking detectados ({len(hijack_risks)})",
            description=(
                "Se han detectado condiciones en el sistema que facilitan "
                "el DLL hijacking: SafeDllSearchMode deshabilitado, "
                "KnownDLLs no estándar o directorios PATH escribibles."
            ),
            risk_level=risk,
            technical_risk=(
                "El DLL hijacking permite a código malicioso o a software de "
                "monitorización interceptar las llamadas a librerías del sistema "
                "sin necesidad de modificar el ejecutable original. "
                "Es una técnica difícil de detectar por el usuario."
            ),
            legal_risk=(
                "Si hay software corporativo que usa DLL hijacking para "
                "monitorizar aplicaciones, es especialmente problemático "
                "desde el punto de vista legal: opera de forma encubierta "
                "y puede interceptar datos de cualquier aplicación."
            ),
            what_it_is=(
                "Vectores técnicos en la configuración del sistema que "
                "permiten cargar DLLs alternativas en lugar de las originales, "
                "potencialmente interceptando el comportamiento de las apps."
            ),
            what_it_is_not=(
                "No toda condición de hijacking está siendo explotada. "
                "Son debilidades de configuración que aumentan el riesgo."
            ),
            raw_data={
                "hijack_vectors": hijack_risks,
                "independent_sources": sources,
                "triangulation": triangulation,
                "confidence": confidence,
            }
        ))

    # ── Certificados raíz no confiables / no estándar ─────────────

    def _check_untrusted_root_certs(self):
        from core.audit_engine import AuditFinding

        standard_cas = {
            "microsoft", "digicert", "comodo", "sectigo", "globalsign",
            "entrust", "usertrust", "verisign", "amazon", "google",
            "baltimore", "starfield", "thawte", "geotrust", "rapid ssl",
            "identrust", "isrg", "let's encrypt", "certum", "secom",
            "network solutions", "godaddy", "ssl.com",
        }

        suspicious_certs = []
        all_root_certs = []

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ChildItem Cert:\\LocalMachine\\Root | "
                 "Select-Object Subject, Issuer, Thumbprint, NotAfter, NotBefore | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                certs = json.loads(result.stdout)
                if isinstance(certs, dict):
                    certs = [certs]

                for cert in certs:
                    subject = str(cert.get("Subject", "")).lower()
                    issuer = str(cert.get("Issuer", "")).lower()
                    combined = subject + issuer

                    is_standard = any(ca in combined for ca in standard_cas)
                    cert_info = {
                        "subject": cert.get("Subject"),
                        "issuer": cert.get("Issuer"),
                        "thumbprint": cert.get("Thumbprint"),
                        "not_after": cert.get("NotAfter"),
                        "not_before": cert.get("NotBefore"),
                        "standard": is_standard,
                    }
                    all_root_certs.append(cert_info)

                    if not is_standard:
                        # Verificar si podría ser un certificado de inspección SSL
                        ssl_inspection_keywords = [
                            "proxy", "inspection", "intercept", "ssl",
                            "tls", "forcepoint", "bluecoat", "symantec",
                            "zscaler", "netskope", "barracuda", "cisco",
                            "sophos", "checkpoint", "palo alto", "fortinet",
                        ]
                        is_ssl_inspection = any(
                            k in combined for k in ssl_inspection_keywords
                        )
                        cert_info["ssl_inspection_indicator"] = is_ssl_inspection
                        suspicious_certs.append(cert_info)
        except Exception as e:
            print(f"[Persistence] Error leyendo certificados raíz: {e}")
            return

        if not suspicious_certs:
            return

        ssl_inspection_certs = [c for c in suspicious_certs
                                 if c.get("ssl_inspection_indicator")]
        risk = "orange" if ssl_inspection_certs else "yellow"

        sources = get_sources(
            "endpoint_monitoring_capabilities",
            "worker_rights_and_surveillance_context",
        )
        triangulation = {
            "certutil_root": certutil_root_summary(),
            "gpresult": gpresult_summary(),
        }
        confidence = confidence_from_evidence(
            sources,
            triangulation,
            direct_indicators_count=len(suspicious_certs),
        )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="persistence_untrusted_certs",
            title=f"Certificados raíz no estándar en el almacén del sistema "
                  f"({len(suspicious_certs)}"
                  f"{', posible SSL inspection' if ssl_inspection_certs else ''})",
            description=(
                "Se han encontrado certificados de autoridad raíz que no "
                "pertenecen a CAs públicas estándar. Pueden ser certificados "
                "corporativos para inspección SSL o de aplicaciones internas."
            ),
            risk_level=risk,
            technical_risk=(
                "Certificados raíz corporativos permiten al empleador realizar "
                "inspección SSL (Man-in-the-Middle) del tráfico HTTPS. "
                "Con estos certificados, el proxy corporativo puede descifrar "
                "y leer toda la comunicación cifrada del navegador."
            ),
            legal_risk=(
                "La inspección SSL con certificados raíz corporativos es "
                "una práctica que el TEDH (Barbulescu II) exige comunicar "
                "previamente al trabajador con detalle sobre su alcance. "
                "Sin información puede vulnerar el secreto de las comunicaciones."
            ),
            what_it_is=(
                "Certificados de autoridad de certificación instalados en el "
                "almacén de confianza del sistema, emitidos por entidades "
                "corporativas o desconocidas en lugar de CAs públicas estándar."
            ),
            what_it_is_not=(
                "No todo certificado corporativo es para inspección SSL. "
                "Las empresas instalan certificados propios para aplicaciones "
                "internas, VPN y servicios corporativos."
            ),
            raw_data={
                "non_standard_certs": suspicious_certs,
                "ssl_inspection_suspects": ssl_inspection_certs,
                "total_root_certs": len(all_root_certs),
                    "independent_sources": sources,
                    "triangulation": triangulation,
                    "confidence": confidence,
            }
        ))