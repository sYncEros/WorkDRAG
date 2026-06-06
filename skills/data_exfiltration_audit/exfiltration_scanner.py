# skills/data_exfiltration_audit/exfiltration_scanner.py
"""
Skill — Detección de Exfiltración de Datos
Detecta herramientas instaladas con capacidad de transferir datos al exterior,
conexiones de red activas a destinos sospechosos, herramientas DLP del empleador
y capacidades de monitoreo de tráfico saliente activas en el equipo.
"""

import winreg
import subprocess
import json
from pathlib import Path


class DataExfiltrationAudit:
    SKILL_NAME = "data_exfiltration_audit"

    # Herramientas de transferencia de archivos que pueden usarse para exfiltración
    TRANSFER_TOOLS = [
        ("WinSCP", ["winscp"]),
        ("FileZilla", ["filezilla"]),
        ("Cyberduck", ["cyberduck"]),
        ("rclone", ["rclone"]),
        ("Mega", ["megasync", "mega desktop"]),
        ("Dropbox", ["dropbox"]),
        ("Box Drive", ["box drive", "box sync"]),
        ("Google Drive (Desktop)", ["googledrivefs", "google drive"]),
        ("Putty/PSCP", ["putty", "pscp", "psftp"]),
        ("7-Zip", ["7-zip"]),  # solo es indicador, no riesgo en sí
        ("BitTorrent/uTorrent", ["bittorrent", "utorrent", "qbittorrent"]),
        ("Resilio Sync", ["resilio"]),
        ("Syncthing", ["syncthing"]),
        ("WeTransfer Desktop", ["wetransfer"]),
        ("AnyDesk", ["anydesk"]),
        ("TeamViewer", ["teamviewer"]),
        ("Ammyy Admin", ["ammyy"]),
        ("RemotePC", ["remotepc"]),
    ]

    # Destinos de red asociados con exfiltración o servicios de almacenamiento no corporativo
    CLOUD_STORAGE_ENDPOINTS = [
        "mega.nz", "mega.co.nz", "dropbox.com", "api.dropboxapi.com",
        "dl.dropboxusercontent.com", "box.com", "api.box.com",
        "paste.ee", "pastebin.com", "transfer.sh",
        "wetransfer.com", "sendspace.com", "zippyshare.com",
        "temp.sh", "gofile.io", "anonfiles.com",
    ]

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[DataExfiltration] Iniciando detección de vectores de exfiltración...")
        self._check_transfer_tools()
        self._check_network_connections()
        self._check_dlp_monitoring()
        self._check_recent_large_transfers()
        self._check_cloud_cli_tools()
        print("[DataExfiltration] Completado.")

    # ── Herramientas de transferencia instaladas ───────────────────

    def _check_transfer_tools(self):
        from core.audit_engine import AuditFinding

        found = []
        uninstall_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        installed_names = []
        for hive, path in uninstall_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(key, idx)
                        sub = winreg.OpenKey(key, sub_name, 0, winreg.KEY_READ)
                        try:
                            name, _ = winreg.QueryValueEx(sub, "DisplayName")
                            installed_names.append(str(name))
                        except (FileNotFoundError, PermissionError, OSError):
                            pass
                        winreg.CloseKey(sub)
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        for sw_name, patterns in self.TRANSFER_TOOLS:
            for installed in installed_names:
                if any(p in installed.lower() for p in patterns):
                    found.append({
                        "product": sw_name,
                        "installed_name": installed,
                    })
                    break

        if not found:
            return

        high_risk = [f for f in found if any(
            p in f["product"].lower()
            for p in ["rclone", "mega", "anydesk", "teamviewer",
                      "resilio", "syncthing", "ammyy"]
        )]
        risk = "orange" if high_risk else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="exfiltration_transfer_tools",
            title=f"Herramientas de transferencia de datos instaladas ({len(found)})",
            description=(
                "Se han detectado herramientas que pueden usarse para transferir "
                "datos fuera del entorno corporativo: clientes FTP/SFTP, "
                "herramientas de sincronización en nube y acceso remoto."
            ),
            risk_level=risk,
            technical_risk=(
                "Estas herramientas permiten copiar archivos a destinos externos "
                "sin pasar por los controles DLP corporativos. "
                "Algunas (AnyDesk, TeamViewer) permiten acceso remoto completo."
            ),
            legal_risk=(
                "Si la empresa monitoriza el uso de estas herramientas sin informar, "
                "puede vulnerar LOPDGDD art. 87. Desde el punto de vista del trabajador, "
                "su uso puede violar políticas de uso aceptable corporativas."
            ),
            what_it_is=(
                "Software instalado con capacidad de transferir archivos a "
                "destinos externos: servidores FTP, almacenamiento en nube "
                "personal y acceso remoto."
            ),
            what_it_is_not=(
                "La presencia de estas herramientas no implica exfiltración. "
                "Pueden ser herramientas de trabajo legítimas."
            ),
            raw_data={"tools": found, "high_risk": high_risk}
        ))

    # ── Conexiones de red activas a destinos sospechosos ──────────

    def _check_network_connections(self):
        from core.audit_engine import AuditFinding

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetTCPConnection -State Established | "
                 "Select-Object LocalAddress, LocalPort, RemoteAddress, "
                 "RemotePort, State, OwningProcess | ConvertTo-Json"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0 or not result.stdout.strip():
                return

            connections = json.loads(result.stdout)
            if isinstance(connections, dict):
                connections = [connections]

            # Obtener nombres de procesos para las conexiones
            proc_map = {}
            try:
                proc_result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-Process | Select-Object Id, Name | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=10
                )
                if proc_result.returncode == 0 and proc_result.stdout.strip():
                    procs = json.loads(proc_result.stdout)
                    if isinstance(procs, dict):
                        procs = [procs]
                    proc_map = {str(p.get("Id")): p.get("Name") for p in procs}
            except Exception:
                pass

            suspicious_connections = []
            large_port_transfers = []

            for conn in connections:
                remote_ip = conn.get("RemoteAddress", "")
                remote_port = conn.get("RemotePort", 0)
                pid = str(conn.get("OwningProcess", ""))
                proc_name = proc_map.get(pid, "unknown")

                # Puertos de transferencia conocidos
                transfer_ports = {21: "FTP", 22: "SSH/SFTP", 69: "TFTP",
                                   115: "SFTP", 8080: "HTTP-alt", 989: "FTPS",
                                   990: "FTPS"}

                if remote_port in transfer_ports and remote_ip not in (
                    "127.0.0.1", "::1", ""
                ):
                    large_port_transfers.append({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "protocol": transfer_ports[remote_port],
                        "process": proc_name,
                        "pid": pid,
                    })

            all_suspicious = suspicious_connections + large_port_transfers
            if not all_suspicious:
                return

            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="exfiltration_network_connections",
                title=f"Conexiones activas en puertos de transferencia "
                      f"({len(all_suspicious)})",
                description=(
                    "Se han detectado conexiones TCP activas en puertos "
                    "asociados con protocolos de transferencia de archivos."
                ),
                risk_level="orange",
                technical_risk=(
                    "Conexiones FTP, SSH/SFTP activas pueden indicar "
                    "transferencia de datos en curso. Dependiendo del destino, "
                    "puede ser una operación legítima o una exfiltración."
                ),
                legal_risk=(
                    "Si la empresa monitoriza estas conexiones sin informar, "
                    "puede vulnerar LOPDGDD art. 87. Desde el punto de vista "
                    "corporativo, pueden violar políticas de DLP."
                ),
                what_it_is=(
                    "Conexiones TCP activas en el momento de la auditoría "
                    "usando puertos típicos de transferencia de archivos."
                ),
                what_it_is_not=(
                    "No toda conexión en estos puertos es exfiltración. "
                    "SSH se usa para administración remota legítima."
                ),
                raw_data={"suspicious_connections": all_suspicious}
            ))

        except Exception as e:
            print(f"[DataExfiltration] Error analizando conexiones: {e}")

    # ── Monitorización DLP del empleador ──────────────────────────

    def _check_dlp_monitoring(self):
        from core.audit_engine import AuditFinding

        dlp_indicators = []

        # Productos DLP conocidos para monitorización de salida de datos
        dlp_products = [
            ("Symantec/Broadcom DLP", ["symantec dlp", "vontu"]),
            ("Forcepoint DLP", ["forcepoint dlp", "websense"]),
            ("Digital Guardian", ["digital guardian"]),
            ("McAfee DLP", ["mcafee dlp", "skyhigh dlp"]),
            ("Microsoft Purview DLP", ["microsoft purview", "azure information protection", "mip"]),
            ("Varonis", ["varonis"]),
            ("Nightfall", ["nightfall"]),
            ("CoSoSys Endpoint Protector", ["endpoint protector", "cososys"]),
            ("Zscaler DLP", ["zscaler"]),
            ("Netskope DLP", ["netskope"]),
            ("Code42 Incydr", ["code42", "incydr"]),
        ]

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\"
                 "CurrentVersion\\Uninstall\\*, "
                 "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\"
                 "CurrentVersion\\Uninstall\\* "
                 "-ErrorAction SilentlyContinue "
                 "| Select-Object DisplayName, Publisher | ConvertTo-Json"],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0 and result.stdout.strip():
                installed = json.loads(result.stdout)
                if isinstance(installed, dict):
                    installed = [installed]
                for app in installed:
                    name = str(app.get("DisplayName") or "").lower()
                    publisher = str(app.get("Publisher") or "").lower()
                    for product_name, patterns in dlp_products:
                        if any(p in name or p in publisher for p in patterns):
                            dlp_indicators.append({
                                "product": product_name,
                                "installed_name": app.get("DisplayName"),
                                "publisher": app.get("Publisher"),
                            })
        except Exception as e:
            print(f"[DataExfiltration] Error buscando DLP: {e}")

        # Comprobar agentes DLP en procesos activos
        running_dlp = []
        dlp_process_names = [
            "dfmservice", "vontu", "sdcservice",  # Symantec DLP
            "dgsentry", "dgagent",  # Digital Guardian
            "mfetp", "mcshield",  # McAfee
            "zscaler", "zscalertunnel",  # Zscaler
            "stAgentSvc", "netskopeclient",  # Netskope
            "Code42Service",  # Code42
        ]
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Process | Select-Object Name, Company | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                procs = json.loads(result.stdout)
                if isinstance(procs, dict):
                    procs = [procs]
                for proc in procs:
                    pname = str(proc.get("Name") or "").lower()
                    if any(dp.lower() in pname for dp in dlp_process_names):
                        running_dlp.append({
                            "process": proc.get("Name"),
                            "company": proc.get("Company"),
                        })
        except Exception:
            pass

        if not dlp_indicators and not running_dlp:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="exfiltration_dlp_monitoring",
            title=f"Software DLP del empleador activo "
                  f"({len(dlp_indicators)} instalado, {len(running_dlp)} en ejecución)",
            description=(
                "Se ha detectado software DLP corporativo que monitoriza "
                "la transferencia de datos desde el equipo. "
                "Puede inspeccionar archivos, emails y tráfico de red."
            ),
            risk_level="orange",
            technical_risk=(
                "El DLP corporativo puede: inspeccionar el contenido de archivos "
                "antes de transferirlos, bloquear transferencias no autorizadas, "
                "registrar intentos de exfiltración, inspeccionar tráfico cifrado "
                "y enviar alertas al equipo de seguridad."
            ),
            legal_risk=(
                "El DLP que inspecciona el contenido de archivos personales "
                "del trabajador puede vulnerar el secreto de las comunicaciones "
                "y LOPDGDD art. 87. Requiere información previa del alcance."
            ),
            what_it_is=(
                "Software de prevención de pérdida de datos que controla "
                "qué información puede salir del equipo corporativo y cómo."
            ),
            what_it_is_not=(
                "El DLP es una herramienta de seguridad corporativa estándar. "
                "No está diseñado para vigilar al empleado sino para proteger "
                "la información de la empresa."
            ),
            raw_data={
                "dlp_products": dlp_indicators,
                "running_processes": running_dlp
            }
        ))

    # ── Transferencias recientes de archivos grandes ───────────────

    def _check_recent_large_transfers(self):
        from core.audit_engine import AuditFinding

        # Comprobar historial reciente de downloads/archivos grandes
        download_paths = [
            Path.home() / "Downloads",
            Path.home() / "Desktop",
        ]

        large_files = []
        threshold_mb = 50  # archivos > 50 MB

        for base_path in download_paths:
            if not base_path.exists():
                continue
            try:
                for f in base_path.iterdir():
                    if f.is_file():
                        size_mb = f.stat().st_size / (1024 * 1024)
                        if size_mb > threshold_mb:
                            large_files.append({
                                "path": str(f),
                                "name": f.name,
                                "size_mb": round(size_mb, 1),
                                "location": str(base_path),
                            })
            except PermissionError:
                pass

        # Comprobar archivos comprimidos recientes (posibles archivos de exfiltración)
        compressed_extensions = {".zip", ".rar", ".7z", ".tar", ".gz", ".tar.gz"}
        compressed_files = [f for f in large_files
                            if Path(f["path"]).suffix.lower() in compressed_extensions]

        if not large_files:
            return

        risk = "yellow" if not compressed_files else "orange"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="exfiltration_large_files",
            title=f"Archivos grandes en Downloads/Desktop "
                  f"({len(large_files)} > {threshold_mb} MB)",
            description=(
                f"Se han detectado {len(large_files)} archivos de más de "
                f"{threshold_mb} MB en carpetas de descarga y escritorio. "
                f"Incluye {len(compressed_files)} archivos comprimidos."
            ),
            risk_level=risk,
            technical_risk=(
                "Archivos comprimidos grandes en Downloads pueden ser "
                "preparativos para exfiltración de datos corporativos. "
                "Son un indicador forense de actividad de insider."
            ),
            legal_risk=(
                "Si la empresa monitoriza el contenido de estas carpetas "
                "sin informar, puede vulnerar LOPDGDD art. 87. "
                "Desde el punto de vista corporativo, pueden violar DLP."
            ),
            what_it_is=(
                "Archivos de gran tamaño presentes en carpetas de acceso "
                "frecuente del usuario. Pueden ser documentos de trabajo, "
                "instaladores o archivos personales."
            ),
            what_it_is_not=(
                "La presencia de archivos grandes no implica exfiltración. "
                "Pueden ser instaladores, backups o proyectos legítimos."
            ),
            raw_data={
                "large_files": large_files[:20],
                "compressed_files": compressed_files[:10],
                "threshold_mb": threshold_mb
            }
        ))

    # ── Herramientas de CLI en nube ────────────────────────────────

    def _check_cloud_cli_tools(self):
        from core.audit_engine import AuditFinding

        cli_tools = []
        cli_paths = [
            Path.home() / "AppData" / "Local" / "Programs" / "rclone",
            Path("C:/Program Files/rclone"),
            Path("C:/rclone"),
            Path.home() / ".aws",  # AWS CLI config
            Path.home() / ".azure",  # Azure CLI config
            Path.home() / ".config" / "gcloud",  # GCP CLI
            Path.home() / "AppData" / "Roaming" / "rclone",
        ]

        cli_definitions = [
            ("rclone", [
                Path.home() / "AppData/Local/Programs/rclone",
                Path("C:/Program Files/rclone"),
                Path("C:/rclone"),
                Path.home() / "AppData/Roaming/rclone",
            ]),
            ("AWS CLI (~/.aws config)", [Path.home() / ".aws"]),
            ("Azure CLI (~/.azure config)", [Path.home() / ".azure"]),
            ("Google Cloud CLI (~/.config/gcloud)", [Path.home() / ".config/gcloud"]),
        ]

        for tool_name, paths in cli_definitions:
            for p in paths:
                if p.exists():
                    cli_tools.append({
                        "tool": tool_name,
                        "path": str(p),
                        "has_config": (p / "credentials").exists()
                        or (p / "config").exists()
                        or any(p.glob("*.conf"))
                    })
                    break

        if not cli_tools:
            return

        configured = [t for t in cli_tools if t.get("has_config")]

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="exfiltration_cloud_cli",
            title=f"Herramientas CLI de nube instaladas "
                  f"({len(cli_tools)}, {len(configured)} con credenciales)",
            description=(
                "Se han detectado herramientas de línea de comandos para "
                "acceso a servicios en nube: rclone, AWS CLI, Azure CLI, "
                "Google Cloud CLI. Con credenciales configuradas pueden "
                "transferir datos masivamente."
            ),
            risk_level="orange" if configured else "yellow",
            technical_risk=(
                "Herramientas como rclone pueden transferir terabytes de datos "
                "a cualquier proveedor de nube con una sola línea de comandos. "
                "Si tienen credenciales preconfiguradas, el riesgo es mayor."
            ),
            legal_risk=(
                "Desde el punto de vista del trabajador, su uso puede violar "
                "políticas de DLP corporativas. Desde el empleador, si se "
                "monitoriza el uso de estas herramientas, requiere base legal."
            ),
            what_it_is=(
                "Interfaces de línea de comandos para interactuar con "
                "servicios de almacenamiento en nube de AWS, Azure, GCP o "
                "cualquier proveedor compatible con rclone."
            ),
            what_it_is_not=(
                "Son herramientas de trabajo legítimas para DevOps y administración. "
                "Su presencia no implica exfiltración de datos."
            ),
            raw_data={"cli_tools": cli_tools, "configured": configured}
        ))
