# skills/usb_audit/usb_scanner.py
"""
Skill — Auditoría de USB y Periféricos
Detecta dispositivos USB conectados históricamente, dispositivos actualmente
conectados, políticas de bloqueo DLP y restricciones GPO de almacenamiento
extraíble.
"""

import winreg
import subprocess
import json
from datetime import datetime


class USBAudit:
    SKILL_NAME = "usb_audit"

    # Claves de registro con historial de USB
    USB_HISTORY_KEYS = [
        r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
        r"SYSTEM\CurrentControlSet\Enum\USB",
    ]

    # Claves de políticas de restricción de USB
    USB_POLICY_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS\DisallowEncryptionOnRemovableStorage"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Services\USBSTOR"),
    ]

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[USB] Iniciando auditoría de USB y periféricos...")
        self._check_usb_history()
        self._check_currently_connected()
        self._check_usb_policies()
        self._check_dlp_policies()
        print("[USB] Completado.")

    # ── Historial de dispositivos USB conectados ───────────────────

    def _check_usb_history(self):
        from core.audit_engine import AuditFinding

        devices = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self.USB_HISTORY_KEYS[0],
                0, winreg.KEY_READ
            )
            idx = 0
            while True:
                try:
                    device_class = winreg.EnumKey(key, idx)
                    sub_key = winreg.OpenKey(key, device_class, 0, winreg.KEY_READ)
                    sub_idx = 0
                    while True:
                        try:
                            instance = winreg.EnumKey(sub_key, sub_idx)
                            info = self._get_usb_device_info(
                                self.USB_HISTORY_KEYS[0], device_class, instance
                            )
                            if info:
                                devices.append(info)
                            sub_idx += 1
                        except OSError:
                            break
                    winreg.CloseKey(sub_key)
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError) as e:
            print(f"[USB] Sin acceso a historial USBSTOR: {e}")

        if not devices:
            return

        storage = [d for d in devices if "stor" in d.get("device_class", "").lower()]
        other = [d for d in devices if d not in storage]

        if storage:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="usb_storage_history",
                title=f"Historial de almacenamiento USB ({len(storage)} dispositivos)",
                description=(
                    "Se han detectado dispositivos de almacenamiento USB que "
                    "han sido conectados al equipo anteriormente. "
                    "El registro de Windows conserva este historial."
                ),
                risk_level="yellow",
                technical_risk=(
                    "El historial de USB es evidencia forense de qué dispositivos "
                    "de almacenamiento han sido conectados. Puede indicar exfiltración "
                    "de datos o uso de almacenamiento no autorizado."
                ),
                legal_risk=(
                    "Si la empresa tiene política de DLP que prohíbe USB y el "
                    "empleado los ha conectado, puede haber implicaciones disciplinarias. "
                    "Si la empresa monitoriza este historial sin informar, "
                    "puede vulnerar LOPDGDD art. 87."
                ),
                what_it_is=(
                    "Registro de Windows que almacena información sobre dispositivos "
                    "USB de almacenamiento que han sido conectados al equipo."
                ),
                what_it_is_not=(
                    "No implica que se haya copiado información. "
                    "Puede incluir ratones, teclados y adaptadores USB."
                ),
                raw_data={"storage_devices": storage, "total": len(storage)}
            ))

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="usb_full_history",
            title=f"Historial completo de dispositivos USB ({len(devices)} registros)",
            description=(
                "Inventario completo de todos los dispositivos USB conectados "
                "históricamente, incluyendo almacenamiento, adaptadores y periféricos."
            ),
            risk_level="green",
            technical_risk=(
                "Información de inventario. Útil como referencia forense "
                "para identificar dispositivos no autorizados."
            ),
            legal_risk=(
                "La información de historial USB es datos técnicos del dispositivo. "
                "Su acceso por el empleador puede requerir base legal bajo RGPD."
            ),
            what_it_is=(
                "Registro completo de todos los tipos de dispositivos USB conectados: "
                "almacenamiento, HID (teclados/ratones), red, audio, etc."
            ),
            what_it_is_not=(
                "No incluye contenido de los dispositivos ni archivos transferidos."
            ),
            raw_data={"all_devices": devices, "total": len(devices)}
        ))

    def _get_usb_device_info(self, base_key: str, device_class: str, instance: str) -> dict | None:
        try:
            path = f"{base_key}\\{device_class}\\{instance}"
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ
            )
            info = {
                "device_class": device_class,
                "instance_id": instance,
            }
            for field in ["FriendlyName", "DeviceDesc", "Mfg", "LocationInformation"]:
                try:
                    val, _ = winreg.QueryValueEx(key, field)
                    info[field.lower()] = str(val)
                except (FileNotFoundError, PermissionError, OSError):
                    pass
            winreg.CloseKey(key)
            return info
        except Exception:
            return None

    # ── Dispositivos actualmente conectados ────────────────────────

    def _check_currently_connected(self):
        from core.audit_engine import AuditFinding

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-PnpDevice -Class USB -Status OK | "
                 "Select-Object FriendlyName, DeviceID, Class | "
                 "ConvertTo-Json -Depth 2"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0 or not result.stdout.strip():
                return

            devices = json.loads(result.stdout)
            if isinstance(devices, dict):
                devices = [devices]

            if not devices:
                return

            # Filtrar dispositivos que no son HID estándar
            non_standard = [
                d for d in devices
                if d.get("FriendlyName") and not any(
                    term in str(d.get("FriendlyName", "")).lower()
                    for term in ["composite", "hub", "root hub", "hid-compliant"]
                )
            ]

            if non_standard:
                self.engine.add_finding(AuditFinding(
                    skill=self.SKILL_NAME,
                    category="usb_connected_now",
                    title=f"Dispositivos USB actualmente conectados ({len(non_standard)})",
                    description=(
                        "Dispositivos USB activos en este momento, "
                        "excluyendo hubs y HID estándar."
                    ),
                    risk_level="green",
                    technical_risk=(
                        "Inventario de dispositivos activos. Útil para detectar "
                        "dispositivos de captura de red, grabación o almacenamiento activos."
                    ),
                    legal_risk=(
                        "Bajo si son periféricos estándar. Mayor si incluye "
                        "dispositivos de captura o almacenamiento no autorizados."
                    ),
                    what_it_is=(
                        "Dispositivos USB reconocidos por Windows como activos "
                        "en el momento de la auditoría."
                    ),
                    what_it_is_not=(
                        "No incluye dispositivos desconectados previamente, "
                        "solo los presentes en el momento actual."
                    ),
                    raw_data={"connected_devices": non_standard}
                ))
        except Exception as e:
            print(f"[USB] Error obteniendo dispositivos activos: {e}")

    # ── Políticas de restricción de USB ────────────────────────────

    def _check_usb_policies(self):
        from core.audit_engine import AuditFinding

        policies_found = []

        # Comprobar si USBSTOR está deshabilitado (Start=4 significa deshabilitado)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                0, winreg.KEY_READ
            )
            try:
                start_val, _ = winreg.QueryValueEx(key, "Start")
                if int(start_val) == 4:
                    policies_found.append({
                        "policy": "USBSTOR deshabilitado globalmente",
                        "key": r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                        "value": "Start=4",
                        "severity": "high",
                        "description": "El servicio USBSTOR está deshabilitado, "
                                       "bloqueando todo almacenamiento USB en el equipo."
                    })
                elif int(start_val) == 3:
                    policies_found.append({
                        "policy": "USBSTOR en modo manual (no bloqueado)",
                        "key": r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                        "value": "Start=3",
                        "severity": "low",
                        "description": "El servicio USBSTOR está en modo manual. "
                                       "El almacenamiento USB puede usarse bajo demanda."
                    })
            except (FileNotFoundError, PermissionError, OSError):
                pass
            winreg.CloseKey(key)
        except Exception:
            pass

        # Comprobar políticas GPO de almacenamiento extraíble
        removable_policy_keys = [
            (r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
             winreg.HKEY_LOCAL_MACHINE, "Deny_All"),
            (r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}",
             winreg.HKEY_LOCAL_MACHINE, "Deny_Write"),
            (r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}",
             winreg.HKEY_LOCAL_MACHINE, "Deny_Read"),
        ]

        for reg_path, hive, value_name in removable_policy_keys:
            try:
                key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                try:
                    val, _ = winreg.QueryValueEx(key, value_name)
                    if int(val) == 1:
                        policies_found.append({
                            "policy": f"GPO RemovableStorage: {value_name}=1",
                            "key": reg_path,
                            "value": f"{value_name}=1",
                            "severity": "high",
                            "description": f"Política GPO activa que restringe "
                                           f"el acceso a almacenamiento extraíble ({value_name})."
                        })
                except (FileNotFoundError, PermissionError, OSError):
                    pass
                winreg.CloseKey(key)
            except Exception:
                pass

        if not policies_found:
            return

        high_severity = [p for p in policies_found if p["severity"] == "high"]
        risk = "orange" if high_severity else "yellow"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="usb_dlp_policies",
            title=f"Políticas de restricción de USB/almacenamiento extraíble ({len(policies_found)})",
            description=(
                "Se han detectado políticas corporativas que restringen o bloquean "
                "el uso de almacenamiento USB o dispositivos extraíbles."
            ),
            risk_level=risk,
            technical_risk=(
                "Las políticas DLP de USB limitan la capacidad del trabajador "
                "de copiar información. Si son monitorizadas, la empresa puede "
                "tener registro de intentos de uso de USB."
            ),
            legal_risk=(
                "Las restricciones de USB son medidas DLP legítimas si se informan. "
                "Sin embargo, si los intentos de uso se registran y analizan "
                "sin base legal, pueden vulnerar LOPDGDD art. 87."
            ),
            what_it_is=(
                "Políticas de Windows o GPO corporativas que controlan el acceso "
                "a dispositivos de almacenamiento USB y extraíble."
            ),
            what_it_is_not=(
                "No toda restricción de USB es ilegítima. Es una medida de "
                "seguridad estándar en entornos corporativos para prevenir DLP."
            ),
            raw_data={"policies": policies_found}
        ))

    # ── Políticas DLP de dispositivos ──────────────────────────────

    def _check_dlp_policies(self):
        from core.audit_engine import AuditFinding

        dlp_indicators = []

        # Buscar software DLP conocido relacionado con USB
        dlp_software = [
            "Symantec DLP", "Forcepoint DLP", "Digital Guardian",
            "CoSoSys Endpoint Protector", "DeviceLock", "SafeGuard",
            "Check Point DLP", "McAfee DLP", "Trend Micro DLP",
        ]

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                 "| Select-Object DisplayName, Publisher | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                installed = json.loads(result.stdout)
                if isinstance(installed, dict):
                    installed = [installed]
                for app in installed:
                    name = str(app.get("DisplayName") or "").lower()
                    publisher = str(app.get("Publisher") or "").lower()
                    for dlp in dlp_software:
                        if dlp.lower() in name or dlp.lower() in publisher:
                            dlp_indicators.append({
                                "software": app.get("DisplayName"),
                                "publisher": app.get("Publisher"),
                                "matched": dlp
                            })
        except Exception as e:
            print(f"[USB] Error buscando software DLP: {e}")

        if not dlp_indicators:
            return

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="usb_dlp_software",
            title=f"Software DLP de dispositivos detectado ({len(dlp_indicators)})",
            description=(
                "Se ha detectado software de prevención de pérdida de datos (DLP) "
                "especializado en control de dispositivos USB y periféricos."
            ),
            risk_level="orange",
            technical_risk=(
                "El software DLP puede monitorizar qué dispositivos se conectan, "
                "bloquear transferencias de archivos, registrar intentos de copia "
                "y enviar alertas al equipo de seguridad corporativo."
            ),
            legal_risk=(
                "La monitorización de dispositivos USB mediante DLP requiere "
                "información previa al trabajador bajo LOPDGDD art. 87 "
                "y RGPD art. 13. Sin información puede vulnerar ET art. 20bis."
            ),
            what_it_is=(
                "Software especializado en controlar y registrar el uso de "
                "dispositivos de almacenamiento extraíble y periféricos USB."
            ),
            what_it_is_not=(
                "No todo DLP es vigilancia del trabajador. Su función principal "
                "es prevenir fuga de datos corporativos, no espiar al empleado."
            ),
            raw_data={"dlp_software": dlp_indicators}
        ))
