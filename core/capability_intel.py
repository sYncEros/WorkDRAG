"""Utilidades de inteligencia forense por capacidades.

Objetivo:
- Centralizar fuentes externas citables (MITRE, LOLDrivers, Microsoft, Sysinternals, EFF, Access Now).
- Exponer probes ligeros de triangulación técnica (gpresult, certutil, fltmc).
"""

from __future__ import annotations

import re
import subprocess
from typing import Any


SOURCE_INDEX: dict[str, list[dict[str, str]]] = {
    "endpoint_monitoring_capabilities": [
        {
            "name": "MITRE ATT&CK Enterprise",
            "url": "https://attack.mitre.org/",
            "type": "threat-framework",
        },
        {
            "name": "LOLDrivers Project",
            "url": "https://www.loldrivers.io/",
            "type": "driver-intel",
        },
        {
            "name": "Sysinternals Autoruns",
            "url": "https://learn.microsoft.com/sysinternals/downloads/autoruns",
            "type": "forensic-tool",
        },
    ],
    "event_and_logging_capabilities": [
        {
            "name": "Microsoft Event IDs (Security Auditing)",
            "url": "https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-logon-events",
            "type": "vendor-doc",
        },
        {
            "name": "Windows Event Forwarding guidance",
            "url": "https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection",
            "type": "vendor-doc",
        },
    ],
    "worker_rights_and_surveillance_context": [
        {
            "name": "EFF Surveillance Self-Defense",
            "url": "https://ssd.eff.org/",
            "type": "civil-society",
        },
        {
            "name": "Access Now Digital Security Helpline",
            "url": "https://www.accessnow.org/help/",
            "type": "civil-society",
        },
    ],
}


def get_sources(*keys: str) -> dict[str, list[dict[str, str]]]:
    """Devuelve fuentes citables para las capacidades indicadas."""
    out: dict[str, list[dict[str, str]]] = {}
    for key in keys:
        if key in SOURCE_INDEX:
            out[key] = SOURCE_INDEX[key]
    return out


def _safe_run(command: list[str], timeout: int = 20) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
        }
    except Exception as e:  # pragma: no cover
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
        }


def gpresult_summary(timeout: int = 25) -> dict[str, Any]:
    """Triangulación básica de políticas GPO aplicadas (sin parse complejo)."""
    data = _safe_run(["gpresult", "/r"], timeout=timeout)
    text = f"{data.get('stdout', '')}\n{data.get('stderr', '')}".strip()

    has_applied = bool(re.search(r"(Applied Group Policy Objects|Objetos de directiva de grupo aplicados)", text, re.I))

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return {
        "ok": data["ok"],
        "returncode": data["returncode"],
        "has_applied_gpo_section": has_applied,
        "snippet": lines[:40],
    }


def certutil_root_summary(timeout: int = 25) -> dict[str, Any]:
    """Resumen de almacén raíz para contraste de inspección TLS/certs."""
    data = _safe_run(["certutil", "-store", "Root"], timeout=timeout)
    text = f"{data.get('stdout', '')}\n{data.get('stderr', '')}".strip()

    hashes = re.findall(r"Cert Hash\(sha1\):", text, re.I)
    suspicious_keywords = [
        "zscaler", "netskope", "proxy", "inspection", "intercept", "ssl", "tls",
    ]
    lower = text.lower()
    hits = [k for k in suspicious_keywords if k in lower]

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return {
        "ok": data["ok"],
        "returncode": data["returncode"],
        "root_cert_count_estimate": len(hashes),
        "keyword_hits": sorted(set(hits)),
        "snippet": lines[:40],
    }


def fltmc_summary(timeout: int = 15) -> dict[str, Any]:
    """Resumen rápido de minifiltros (driver/filter altitude) vía fltmc."""
    data = _safe_run(["fltmc", "filters"], timeout=timeout)
    text = f"{data.get('stdout', '')}\n{data.get('stderr', '')}".strip()
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]

    # Mantener parse defensivo: sólo muestras de tabla para trazabilidad.
    return {
        "ok": data["ok"],
        "returncode": data["returncode"],
        "line_count": len(lines),
        "snippet": lines[:40],
    }


def confidence_from_evidence(
    independent_sources: dict[str, list[dict[str, str]]] | None,
    triangulation: dict[str, Any] | None,
    direct_indicators_count: int = 0,
) -> dict[str, Any]:
    """Calcula puntuación de confianza forense (0-100) y nivel textual.

    Criterios:
    - Evidencia directa observada en el endpoint.
    - Número de fuentes independientes citadas.
    - Triangulación técnica exitosa (probes con ok=True).
    """
    sources_count = 0
    if independent_sources:
        for _, entries in independent_sources.items():
            sources_count += len(entries or [])

    triang_ok = 0
    triang_total = 0
    if triangulation:
        for _, probe in triangulation.items():
            triang_total += 1
            if isinstance(probe, dict) and probe.get("ok") is True:
                triang_ok += 1

    # Score ponderado defensivo
    score = 0
    score += min(50, max(0, int(direct_indicators_count)) * 6)
    score += min(25, sources_count * 3)
    score += min(25, triang_ok * 8)
    score = max(0, min(100, score))

    if score >= 80:
        level = "alta"
    elif score >= 50:
        level = "media"
    else:
        level = "baja"

    return {
        "score": score,
        "level": level,
        "factors": {
            "direct_indicators_count": int(direct_indicators_count),
            "independent_sources_count": sources_count,
            "triangulation_ok": triang_ok,
            "triangulation_total": triang_total,
        },
    }
