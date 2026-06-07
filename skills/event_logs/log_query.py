"""
Infraestructura compartida para consultas de Event Viewer.

Se usa desde skills que necesitan leer logs de Windows de forma robusta,
con salida JSON normalizada y control de timeout/errores.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass
class EventQueryResult:
    log_name: str
    total: int
    by_id: dict[int, int]
    samples: list[dict]
    source_label: str = ""
    accessible: bool = True
    error: str = ""


def query_log(
    log_name: str,
    event_ids: list[int],
    source_label: str,
    *,
    scan_scope: str = "recent",
    hours_back: int = 168,
    max_events: int = 2000,
    timeout: int = 45,
) -> EventQueryResult:
    """Consulta un log de Event Viewer devolviendo resultado estructurado."""
    ids_ps = ",".join(str(i) for i in event_ids)
    log_ps = log_name.replace("'", "''")
    filter_expr = (
        f"@{{LogName='{log_ps}'; Id=@({ids_ps})}}"
        if scan_scope == "full"
        else f"@{{LogName='{log_ps}'; Id=@({ids_ps}); StartTime=(Get-Date).AddHours(-{hours_back})}}"
    )

    if max_events and max_events > 0:
        events_expr = (
            f"$events=Get-WinEvent -FilterHashtable {filter_expr} "
            f"-MaxEvents {int(max_events)} -ErrorAction Stop; "
        )
    else:
        events_expr = (
            f"$events=Get-WinEvent -FilterHashtable {filter_expr} -ErrorAction Stop; "
        )

    ps = "".join([
        "$ErrorActionPreference='Stop'; ",
        "try { ",
        events_expr,
        "} catch { if ($_.Exception.Message -match 'No events were found') { $events=@() } else { throw } } ",
        "$group=$events | Group-Object Id | Sort-Object Name; ",
        "$by=@{}; foreach($g in $group){ $by[$g.Name] = $g.Count }; ",
        "$samples=$events | Select-Object -First 20 ",
        "@{N='TimeCreated';E={ if($_.TimeCreated){$_.TimeCreated.ToString('o')} else {$null} }}, ",
        "Id, ProviderName, MachineName, LevelDisplayName, Message; ",
        "$result=[ordered]@{",
        f" source='{source_label}';",
        f" log_name='{log_ps}';",
        " total=@($events).Count;",
        " by_id=$by;",
        " samples=$samples",
        " }; ",
        "$result | ConvertTo-Json -Depth 6",
    ])

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 or not result.stdout.strip():
            err = (result.stderr or "sin salida").strip()[:500]
            return EventQueryResult(
                log_name,
                0,
                {},
                [],
                source_label,
                accessible=False,
                error=err,
            )

        payload = json.loads(result.stdout)
        by_id: dict[int, int] = {}
        for k, v in (payload.get("by_id") or {}).items():
            try:
                by_id[int(k)] = int(v)
            except Exception:
                continue

        samples = payload.get("samples") or []
        if isinstance(samples, dict):
            samples = [samples]

        return EventQueryResult(
            payload.get("log_name", log_name),
            int(payload.get("total", 0) or 0),
            by_id,
            samples,
            source_label,
            accessible=True,
            error="",
        )
    except subprocess.TimeoutExpired:
        return EventQueryResult(
            log_name,
            0,
            {},
            [],
            source_label,
            accessible=False,
            error=f"timeout ({timeout}s) consultando {log_name}",
        )
    except Exception as e:
        return EventQueryResult(
            log_name,
            0,
            {},
            [],
            source_label,
            accessible=False,
            error=str(e)[:500],
        )
