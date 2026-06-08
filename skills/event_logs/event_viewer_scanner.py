"""
Skill — Event Viewer Audit (visor de eventos)
Analiza logs de eventos de Windows relevantes para vigilancia,
acceso remoto, cambios de políticas y persistencia.

REFACTOR: el volcado masivo (_export_full_logs_report) ahora está ACOTADO
(ventana temporal + tope por log + timeout), escribe UTF-8 SIN BOM, usa
timestamps ISO 8601 y calcula SHA-256 por fichero (cadena de custodia).
Además está OFF por defecto: activarlo era lo que generaba el archivo de
~40.000 registros y la espera de 45 minutos.
"""

from __future__ import annotations

import datetime
import json
import subprocess
from pathlib import Path
from skills.event_logs.log_query import EventQueryResult, query_log


class EventViewerAudit:
    SKILL_NAME = "event_viewer_audit"

    # --- Escaneo dirigido (vía _query_log) ---
    # 'recent' acota por ventana; 'full' recorre desde el inicio del registro
    # y es lo que provocaba esperas larguísimas. Por eso el valor seguro es
    # 'recent'. (Aun en 'full', _query_log sólo trae los IDs de la allow-list.)
    SCAN_SCOPE = "recent"
    HOURS_BACK = 17520          # 720 días
    MAX_EVENTS = 2000           # tope de seguridad para el escaneo dirigido
    DETAILED_EXPORT = False     # volcado forense masivo: OPT-IN y siempre acotado

    # --- Parámetros del volcado forense (sólo si DETAILED_EXPORT = True) ---
    EXPORT_DAYS_BACK = 90       # ventana del volcado (0 = todo el histórico; NO recomendado)
    EXPORT_MAX_PER_LOG = 5000   # tope de eventos por log (0 = sin tope; NO recomendado)
    EXPORT_TIMEOUT = 180        # segundos; si se supera, NO cuelga: corta y avisa

    # Eventos relevantes (Windows Event IDs)
    SECURITY_IDS = [4624, 4625, 4648, 4672, 4688, 4698, 4702, 4719]
    SYSTEM_IDS = [7045, 7036]
    TASK_IDS = [106, 140, 141]
    POWERSHELL_IDS = [4103, 4104]

    CRITICAL_IDS = {
        4698: "Tarea programada creada",
        4702: "Tarea programada modificada",
        4719: "Política de auditoría cambiada",
        7045: "Nuevo servicio instalado",
        4104: "Script block de PowerShell",
    }

    def __init__(self, engine):
        self.engine = engine
        self.query_errors: dict[str, str] = {}

    def run(self):
        scope_label = (
            "histórico completo"
            if self.SCAN_SCOPE == "full"
            else f"últimas {self.HOURS_BACK}h"
        )
        print(f"[EventViewer] Iniciando visor de eventos ({scope_label})...")

        security = self._query_log("Security", self.SECURITY_IDS, "security")
        system = self._query_log("System", self.SYSTEM_IDS, "system")
        task = self._query_log(
            "Microsoft-Windows-TaskScheduler/Operational", self.TASK_IDS, "task_scheduler"
        )
        powershell = self._query_log("Windows PowerShell", self.POWERSHELL_IDS, "powershell")

        self._add_collection_status_finding(security, system, task, powershell)
        self._add_correlation_finding(security, system, task, powershell)
        self._add_powershell_finding(powershell)
        self._add_remote_access_finding(security)
        if self.DETAILED_EXPORT:
            self._export_full_logs_report()

        print("[EventViewer] Completado")

    def _query_log(self, log_name: str, event_ids: list[int], source_label: str) -> EventQueryResult | None:
        res = query_log(
            log_name,
            event_ids,
            source_label,
            scan_scope=self.SCAN_SCOPE,
            hours_back=self.HOURS_BACK,
            max_events=self.MAX_EVENTS,
            timeout=45,
        )
        if not res.accessible and res.error:
            self.query_errors[source_label] = res.error
        return res

    def _export_full_logs_report(self):
        from core.audit_engine import AuditFinding

        repo_root = Path(__file__).resolve().parents[2]
        now = datetime.datetime.now()
        # Las evidencias forenses viven en evidence/ (con hash), no en exports/.
        out_dir = (
            repo_root / "evidence" / "event_viewer"
            / now.strftime("%Y-%m-%d") / now.strftime("%Hh.%Mm.%Ss")
        )
        logs_dir = out_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = out_dir / "manifest.json"
        suspicious_path = out_dir / "suspicious_summary.json"

        logs_dest_ps = str(logs_dir.resolve()).replace("'", "''")
        manifest_ps = str(manifest_path.resolve()).replace("'", "''")
        suspicious_ps = str(suspicious_path.resolve()).replace("'", "''")

        keyword_regex = (
            r"(?i)(keylog|keystroke|screen.?captur|screenshot|monitor|surveil|"
            r"remote\s+control|rdp|dlp|purview|teramind|hubstaff|activtrak|"
            r"zscaler|netskope|crowdstrike|sentinelone|nexthink|proxy|ssl inspection|"
            r"diagtrack|telemetry|recall|inspecci[oó]n|vigilancia)"
        )
        keyword_regex_ps = keyword_regex.replace("'", "''")

        ps = "\n".join([
            "$ErrorActionPreference='Stop'",
            f"$logsDest = '{logs_dest_ps}'",
            f"$manifestPath = '{manifest_ps}'",
            f"$suspiciousPath = '{suspicious_ps}'",
            f"$keywordRegex = '{keyword_regex_ps}'",
            f"$daysBack = {int(self.EXPORT_DAYS_BACK)}",
            f"$cap = {int(self.EXPORT_MAX_PER_LOG)}",
            "$since = if ($daysBack -gt 0) { (Get-Date).AddDays(-$daysBack) } else { $null }",
            "$null = New-Item -ItemType Directory -Path $logsDest -Force",
            "$enc = New-Object System.Text.UTF8Encoding($false)",
            "$manifest = New-Object System.Collections.Generic.List[object]",
            "$suspiciousSamples = New-Object System.Collections.Generic.List[object]",
            "$boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime",
            "$allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled -eq $true -and $_.RecordCount -gt 0 } | Sort-Object LogName",
            "foreach ($log in $allLogs) {",
            "  $writer = $null",
            "  $entry = [ordered]@{ log_name=$log.LogName; record_count=[int64]$log.RecordCount; exported_events=0; suspicious_events=0; file=$null; sha256=$null; accessible=$true; error='' }",
            "  try {",
            "    $safe = ($log.LogName -replace '[\\/:*?\"<>| ]','_')",
            "    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'log_' + [guid]::NewGuid().ToString('N') }",
            "    $outFile = Join-Path $logsDest ($safe + '.ndjson')",
            "    $writer = New-Object System.IO.StreamWriter($outFile, $false, $enc)",
            "    $filter = @{ LogName = $log.LogName }",
            "    if ($since) { $filter['StartTime'] = $since }",
            "    $events = $null",
            "    try {",
            "      if ($cap -gt 0) { $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $cap -ErrorAction Stop }",
            "      else            { $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop }",
            "    } catch { if ($_.Exception.Message -match 'No events were found') { $events=@() } else { throw } }",
            "    foreach ($evt in $events) {",
            "      $msg=''; try { $msg=[string]$evt.Message } catch { $msg='' }",
            "      $obj=[ordered]@{",
            "        record_id=$evt.RecordId",
            "        time_created= if ($evt.TimeCreated) { $evt.TimeCreated.ToString('o') } else { $null }",
            "        event_id=$evt.Id; level=$evt.LevelDisplayName; provider=$evt.ProviderName",
            "        log_name=$evt.LogName; machine=$evt.MachineName; task=$evt.TaskDisplayName",
            "        opcode=$evt.OpcodeDisplayName; keywords=$evt.KeywordsDisplayNames",
            "        user_sid= if ($evt.UserId) { $evt.UserId.Value } else { $null }",
            "        message=$msg",
            "      }",
            "      $writer.WriteLine(($obj | ConvertTo-Json -Compress -Depth 6))",
            "      $entry.exported_events++",
            "      $text = (([string]$evt.ProviderName)+' '+([string]$evt.LogName)+' '+$msg)",
            "      if ($text -match $keywordRegex) {",
            "        $entry.suspicious_events++",
            "        if ($suspiciousSamples.Count -lt 300) {",
            "          $short = $msg -replace '\\s+',' '",
            "          if ($short.Length -gt 280) { $short = $short.Substring(0,280) }",
            "          $suspiciousSamples.Add([pscustomobject]@{ log_name=$evt.LogName; event_id=$evt.Id; provider=$evt.ProviderName; time_created= if($evt.TimeCreated){$evt.TimeCreated.ToString('o')} else {$null}; record_id=$evt.RecordId; message=$short })",
            "        }",
            "      }",
            "    }",
            "    $writer.Close(); $writer=$null",
            "    if ($entry.exported_events -gt 0) {",
            "      $entry.file = [System.IO.Path]::GetFileName($outFile)",
            "      $entry.sha256 = (Get-FileHash -Algorithm SHA256 -Path $outFile).Hash",
            "    } else { Remove-Item $outFile -ErrorAction SilentlyContinue }",
            "  } catch {",
            "    if ($writer) { try { $writer.Close() } catch {} }",
            "    $entry.accessible=$false; $entry.error=$_.Exception.Message",
            "  }",
            "  $manifest.Add([pscustomobject]$entry)",
            "}",
            "$sumEvents = ($manifest | Measure-Object -Property exported_events -Sum).Sum; if ($null -eq $sumEvents) { $sumEvents = 0 }",
            "$sumSuspicious = ($manifest | Measure-Object -Property suspicious_events -Sum).Sum; if ($null -eq $sumSuspicious) { $sumSuspicious = 0 }",
            "$manifestObj = [ordered]@{ generated_at=(Get-Date).ToString('o'); boot_time=$boot; scope='bounded'; window_days=$daysBack; max_per_log=$cap; total_logs=@($manifest).Count; total_events_exported=[int64]$sumEvents; total_suspicious_matches=[int64]$sumSuspicious; logs=$manifest }",
            "[System.IO.File]::WriteAllText($manifestPath, ($manifestObj | ConvertTo-Json -Depth 8), $enc)",
            "$suspiciousObj = [ordered]@{ generated_at=(Get-Date).ToString('o'); suspicious_keyword_regex=$keywordRegex; total_samples=@($suspiciousSamples).Count; samples=$suspiciousSamples }",
            "[System.IO.File]::WriteAllText($suspiciousPath, ($suspiciousObj | ConvertTo-Json -Depth 8), $enc)",
            "$summaryOut = [ordered]@{ generated_at=(Get-Date).ToString('o'); scope='bounded'; window_days=$daysBack; total_logs=@($manifest).Count; accessible_logs=@($manifest | Where-Object { $_.accessible }).Count; inaccessible_logs=@($manifest | Where-Object { -not $_.accessible }).Count; total_events_exported=[int64]$sumEvents; total_suspicious_matches=[int64]$sumSuspicious; manifest_path=$manifestPath; suspicious_samples_path=$suspiciousPath; logs_dir=$logsDest }",
            "$summaryOut | ConvertTo-Json -Depth 8",
        ])

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=self.EXPORT_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="event_viewer_full_logs_export_timeout",
                title=f"Volcado de logs interrumpido por timeout ({self.EXPORT_TIMEOUT}s)",
                description=(
                    "El volcado forense superó el tiempo límite y se detuvo de forma "
                    "controlada. Reduce EXPORT_DAYS_BACK o EXPORT_MAX_PER_LOG."
                ),
                risk_level="yellow",
                technical_risk="El volcado completo no terminó; la cobertura puede ser parcial.",
                legal_risk="La evidencia preservada puede ser incompleta para esta ventana.",
                what_it_is="Corte controlado del exportador de Event Viewer por tiempo.",
                what_it_is_not="No implica actividad maliciosa en el equipo.",
                raw_data={"output_dir": str(out_dir), "timeout_s": self.EXPORT_TIMEOUT},
            ))
            return
        except Exception as e:
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="event_viewer_full_logs_export_error",
                title="Error interno al generar informe detallado de logs",
                description="Se produjo una excepción durante el volcado de Event Viewer.",
                risk_level="yellow",
                technical_risk="Sin export completo, parte del análisis histórico puede quedar sin cubrir.",
                legal_risk="Puede dificultar la documentación integral de evidencia técnica.",
                what_it_is="Fallo técnico del exportador de logs detallados.",
                what_it_is_not="No prueba por sí mismo una vulneración.",
                raw_data={"output_dir": str(out_dir), "error": str(e)},
            ))
            return

        if result.returncode != 0 or not result.stdout.strip():
            err = (result.stderr or "sin salida").strip()[:1200]
            self.engine.add_finding(AuditFinding(
                skill=self.SKILL_NAME,
                category="event_viewer_full_logs_export_error",
                title="No se pudo generar el informe detallado completo de logs",
                description="Falló la exportación de registros de eventos. Se incluye error técnico.",
                risk_level="yellow",
                technical_risk="Sin volcado no se puede revisar la trazabilidad de la ventana.",
                legal_risk="La falta de exportación puede limitar la preservación de evidencia.",
                what_it_is="Error de ejecución del exportador detallado de Event Viewer.",
                what_it_is_not="No implica por sí mismo actividad maliciosa en el equipo.",
                raw_data={"output_dir": str(out_dir), "error": err},
            ))
            return

        summary = json.loads(result.stdout)
        suspicious = int(summary.get("total_suspicious_matches", 0) or 0)
        risk = "yellow" if suspicious > 0 else "green"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="event_viewer_full_logs_export",
            title=(
                "Evidencia de logs preservada "
                f"({summary.get('total_logs', 0)} logs, "
                f"{summary.get('total_events_exported', 0)} eventos, ventana {summary.get('window_days')} días)"
            ),
            description=(
                "Volcado ACOTADO de los registros habilitados en formato NDJSON "
                "(UTF-8 sin BOM, timestamps ISO) con manifest y SHA-256 por fichero "
                "para cadena de custodia."
            ),
            risk_level=risk,
            technical_risk="Permite auditoría reproducible de la ventana exportada con integridad verificable.",
            legal_risk="Facilita preservar evidencia para analizar posibles vulneraciones de derechos digitales.",
            what_it_is="Export forense de Event Viewer + manifest con hashes.",
            what_it_is_not="No determina culpabilidad; requiere análisis y contraste con políticas internas.",
            raw_data={
                "scope": "bounded",
                "window_days": summary.get("window_days"),
                "output_dir": str(out_dir),
                "manifest_path": summary.get("manifest_path", str(manifest_path)),
                "suspicious_samples_path": summary.get("suspicious_samples_path", str(suspicious_path)),
                "total_logs": summary.get("total_logs", 0),
                "accessible_logs": summary.get("accessible_logs", 0),
                "inaccessible_logs": summary.get("inaccessible_logs", 0),
                "total_events_exported": summary.get("total_events_exported", 0),
                "total_suspicious_matches": suspicious,
                "boot_time": summary.get("boot_time"),
            },
        ))

    def _add_collection_status_finding(
        self,
        security: EventQueryResult | None,
        system: EventQueryResult | None,
        task: EventQueryResult | None,
        powershell: EventQueryResult | None,
    ):
        from core.audit_engine import AuditFinding

        datasets = [x for x in [security, system, task, powershell] if x is not None]
        if not datasets:
            return

        logs = []
        total_events = 0
        total_matches = 0
        inaccessible = []

        for ds in datasets:
            matches = sum(ds.by_id.values())
            total_events += ds.total
            total_matches += matches
            logs.append({
                "source": ds.source_label,
                "log_name": ds.log_name,
                "accessible": ds.accessible,
                "matched_events": matches,
                "events_scanned": ds.total,
                "by_id": ds.by_id,
                "error": ds.error,
            })
            if not ds.accessible:
                inaccessible.append(ds.log_name)

        if inaccessible:
            risk = "yellow"
            title = (
                "Event Viewer audit parcial: logs no accesibles "
                f"({len(inaccessible)}/{len(datasets)})"
            )
            description = (
                "Algunos registros de eventos no pudieron consultarse. "
                "Suele deberse a permisos (Security requiere admin) o a que la "
                "política de auditoría no está activada. Se incluye detalle técnico."
            )
            legal_risk = (
                "La falta de acceso puede limitar la cobertura de evidencia "
                "forense en el informe."
            )
        elif total_matches == 0:
            risk = "green"
            scope_text = (
                "histórico completo" if self.SCAN_SCOPE == "full" else f"{self.HOURS_BACK}h"
            )
            title = f"Event Viewer audit sin coincidencias críticas ({scope_text})"
            description = (
                "Se revisaron los registros configurados y no se detectaron "
                "coincidencias en los IDs críticos definidos para este skill."
            )
            legal_risk = (
                "No se identifican indicadores críticos en la ventana analizada, "
                "sin perjuicio de revisiones con mayor profundidad temporal."
            )
        else:
            risk = "yellow"
            title = (
                "Event Viewer audit con actividad relevante "
                f"({total_matches} coincidencias)"
            )
            description = (
                "Se detectaron coincidencias sobre IDs monitoreados y se han "
                "generado hallazgos específicos adicionales cuando aplica."
            )
            legal_risk = (
                "La actividad observada debe contrastarse con políticas internas "
                "de monitorización y mantenimiento."
            )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="event_viewer_collection_status",
            title=title,
            description=description,
            risk_level=risk,
            technical_risk=(
                "Resumen de cobertura del scanner de Event Viewer, útil para "
                "entender qué logs se pudieron inspeccionar y qué volumen se procesó."
            ),
            legal_risk=legal_risk,
            what_it_is=(
                "Hallazgo de estado del escaneo de logs (cobertura, acceso y "
                "volumen de eventos evaluados)."
            ),
            what_it_is_not=(
                "No es prueba de intrusión por sí sola; es un resumen técnico "
                "de la ejecución del skill."
            ),
            raw_data={
                "scan_scope": self.SCAN_SCOPE,
                "hours_back": self.HOURS_BACK if self.SCAN_SCOPE != "full" else None,
                "max_events": self.MAX_EVENTS,
                "total_events_scanned": total_events,
                "total_matches": total_matches,
                "inaccessible_logs": inaccessible,
                "logs": logs,
            },
        ))

    def _add_correlation_finding(
        self,
        security: EventQueryResult | None,
        system: EventQueryResult | None,
        task: EventQueryResult | None,
        powershell: EventQueryResult | None,
    ):
        from core.audit_engine import AuditFinding

        datasets = [x for x in [security, system, task, powershell] if x is not None]
        if not datasets:
            return

        critical_hits = []
        for ds in datasets:
            for event_id, count in ds.by_id.items():
                if event_id in self.CRITICAL_IDS and count > 0:
                    critical_hits.append({
                        "log": ds.log_name,
                        "event_id": event_id,
                        "event_name": self.CRITICAL_IDS[event_id],
                        "count": count,
                    })

        if not critical_hits:
            return

        scope_text = (
            "histórico completo" if self.SCAN_SCOPE == "full" else f"{self.HOURS_BACK}h"
        )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="event_viewer_sensitive_events",
            title=(
                "Eventos sensibles en visor de eventos "
                f"({len(critical_hits)} tipos en {scope_text})"
            ),
            description=(
                "Se detectaron eventos de alto interés forense (tareas, servicios, "
                "cambios de política o ejecución de script blocks) en los registros "
                "de Windows Event Viewer."
            ),
            risk_level="orange",
            technical_risk=(
                "Estos eventos pueden evidenciar despliegues recientes de agentes, "
                "automatizaciones de vigilancia o cambios de auditoría."
            ),
            legal_risk=(
                "Son indicadores relevantes para justificar solicitud de información "
                "al DPO y preservación de evidencia en conflictos laborales."
            ),
            what_it_is=(
                "Correlación de eventos críticos en Security/System/Task "
                "Scheduler/PowerShell."
            ),
            what_it_is_not=(
                "No prueba por sí solo uso ilegítimo; requiere correlación con "
                "políticas internas y contexto operativo."
            ),
            raw_data={
                "scan_scope": self.SCAN_SCOPE,
                "hours_back": self.HOURS_BACK if self.SCAN_SCOPE != "full" else None,
                "max_events": self.MAX_EVENTS,
                "critical_hits": sorted(
                    critical_hits, key=lambda x: (x["count"], x["event_id"]), reverse=True
                ),
                "sources": {
                    ds.log_name: {"total": ds.total, "by_id": ds.by_id, "samples": ds.samples}
                    for ds in datasets
                },
            },
        ))

    def _add_powershell_finding(self, powershell: EventQueryResult | None):
        from core.audit_engine import AuditFinding

        if not powershell:
            return

        script_blocks = powershell.by_id.get(4104, 0)
        module_logs = powershell.by_id.get(4103, 0)
        if script_blocks + module_logs == 0:
            return

        risk = "yellow" if script_blocks < 10 else "orange"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="event_viewer_powershell_audit",
            title=(
                "Trazas de PowerShell en Event Viewer "
                f"(4104={script_blocks}, 4103={module_logs})"
            ),
            description=(
                "Se detectaron eventos de auditoría de PowerShell que permiten "
                "reconstruir comandos o bloques ejecutados recientemente."
            ),
            risk_level=risk,
            technical_risk=(
                "La auditoría de script blocks aporta trazabilidad completa de la "
                "actividad PowerShell y puede usarse para supervisión detallada."
            ),
            legal_risk=(
                "Si se usa para perfilado de actividad del trabajador, requiere "
                "información previa y proporcionalidad."
            ),
            what_it_is=(
                "Registro de eventos de PowerShell en visor de eventos (IDs 4103/4104)."
            ),
            what_it_is_not=(
                "No implica por sí mismo intrusión: puede corresponder a controles "
                "de seguridad estándar."
            ),
            raw_data={
                "scan_scope": self.SCAN_SCOPE,
                "hours_back": self.HOURS_BACK if self.SCAN_SCOPE != "full" else None,
                "max_events": self.MAX_EVENTS,
                "event_counts": {"4104_script_block": script_blocks, "4103_module": module_logs},
                "samples": powershell.samples,
            },
        ))

    def _add_remote_access_finding(self, security: EventQueryResult | None):
        from core.audit_engine import AuditFinding

        if not security:
            return

        explicit_creds = security.by_id.get(4648, 0)
        admin_logons = security.by_id.get(4672, 0)
        if explicit_creds == 0 and admin_logons == 0:
            return

        risk = "yellow"
        if explicit_creds >= 5 or admin_logons >= 5:
            risk = "orange"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="event_viewer_remote_access_patterns",
            title=(
                "Patrones de acceso privilegiado en Security log "
                f"(4648={explicit_creds}, 4672={admin_logons})"
            ),
            description=(
                "Se observaron inicios con credenciales explícitas y/o logons con "
                "privilegios especiales en la ventana auditada."
            ),
            risk_level=risk,
            technical_risk=(
                "Pueden indicar operaciones administrativas o accesos remotos con "
                "privilegios elevados en el equipo."
            ),
            legal_risk=(
                "En contexto laboral, conviene documentar estos accesos y verificar "
                "si existe política de notificación previa."
            ),
            what_it_is=(
                "Indicadores de autenticación privilegiada en el log Security "
                "(IDs 4648 y 4672)."
            ),
            what_it_is_not=(
                "No demuestra por sí solo acceso indebido; requiere contraste con "
                "roles autorizados y ventanas de mantenimiento."
            ),
            raw_data={
                "scan_scope": self.SCAN_SCOPE,
                "hours_back": self.HOURS_BACK if self.SCAN_SCOPE != "full" else None,
                "max_events": self.MAX_EVENTS,
                "event_counts": {
                    "4648_explicit_credentials": explicit_creds,
                    "4672_special_privileges": admin_logons,
                },
                "samples": security.samples,
            },
        ))
