"""
event_log_summary — consumidor robusto de los NDJSON que exporta el skill.

Convierte un volcado de Event Viewer (1 evento por línea) en un resumen
pequeño y con señal, apto para alimentar el informe PDF/JSON SIN incrustar
miles de eventos crudos.

  * Streaming (no carga el fichero en memoria).
  * Tolera BOM (utf-8-sig) y líneas truncadas/corruptas (try/except por línea).
  * Entiende timestamps ISO 8601 y el viejo formato /Date(ms±off)/.
  * Descarta como "timeline" los timestamps imposibles (p. ej. SPP -> 2126).
  * Filtra a una allow-list de IDs/proveedores en vez de regex de keywords.
  * SHA-256 del origen para la cadena de custodia.

Uso CLI:   python3 event_log_summary.py /ruta/al/log.ndjson
Uso API:   from event_log_summary import summarize, summarize_dir
"""

from __future__ import annotations

import collections
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_DATE_RE = re.compile(r"/Date\((\d+)([+-]\d{4})?\)/")

SECURITY_EVENT_IDS = {
    1102: "Registro de auditoría de SEGURIDAD borrado",
    104:  "Registro de eventos borrado",
    4624: "Inicio de sesión correcto",
    4625: "Inicio de sesión fallido",
    4648: "Inicio de sesión con credenciales explícitas",
    4672: "Privilegios especiales asignados al iniciar sesión",
    4688: "Nuevo proceso creado",
    4698: "Tarea programada creada",
    4699: "Tarea programada eliminada",
    4702: "Tarea programada modificada",
    4719: "Política de auditoría cambiada",
    4720: "Cuenta de usuario creada",
    4724: "Intento de restablecer contraseña",
    4728: "Miembro añadido a grupo con privilegios",
    7045: "Nuevo servicio instalado",
    7040: "Cambio en tipo de inicio de servicio",
    4104: "PowerShell: bloque de script ejecutado",
    1149: "RDP: autenticación de usuario correcta",
    21:   "RDP: inicio de sesión correcto",
    24:   "RDP: sesión desconectada",
    25:   "RDP: reconexión de sesión",
}

MSI_IDS = {
    1033:  "Instalación de software completada",
    1034:  "Software desinstalado",
    11707: "Producto instalado (MSI)",
    11708: "Instalación fallida o cancelada (MSI)",
    11724: "Producto eliminado (MSI)",
}

MONITORING_AGENTS = [
    "nexthink", "crowdstrike", "sentinelone", "carbon black", "cb defense",
    "tanium", "netskope", "zscaler", "forcepoint", "teramind", "activtrak",
    "hubstaff", "veriato", "purview", "information protection",
    "digital guardian", "code42", "microsoft monitoring", "log analytics",
    "defender for endpoint",
]

_NOW = datetime.now(tz=timezone.utc).timestamp()
_PLAUSIBLE_MIN = datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp()


def _parse_ts(s):
    """Acepta ISO 8601 o /Date(ms±off)/. Devuelve epoch segundos o None."""
    if not isinstance(s, str) or not s:
        return None
    m = _DATE_RE.search(s)
    if m:
        return int(m.group(1)) / 1000.0
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _clip(msg, n=160):
    if not isinstance(msg, str):
        return msg
    msg = " ".join(msg.split())
    return msg if len(msg) <= n else msg[:n] + "…"


def _sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def summarize(path, max_samples=3):
    total = parsed = failed = future_ts = 0
    levels = collections.Counter()
    providers = collections.Counter()
    by_eid = collections.Counter()
    tmin = tmax = None

    agents = collections.defaultdict(lambda: {"count": 0, "levels": collections.Counter(), "samples": []})
    sec = collections.defaultdict(lambda: {"label": "", "count": 0, "samples": []})
    software = collections.defaultdict(lambda: {"label": "", "count": 0, "samples": []})

    with open(path, "r", encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                r = json.loads(line)
            except Exception:
                failed += 1
                continue
            parsed += 1

            lvl = r.get("level")
            prov = r.get("provider") or "(sin proveedor)"
            eid = r.get("event_id")
            msg = _clip(r.get("message"))
            levels[lvl] += 1
            providers[prov] += 1
            by_eid[(prov, eid)] += 1

            ts = _parse_ts(r.get("time_created"))
            if ts is not None:
                if _PLAUSIBLE_MIN <= ts <= _NOW + 86400:
                    tmin = ts if tmin is None else min(tmin, ts)
                    tmax = ts if tmax is None else max(tmax, ts)
                elif ts > _NOW + 86400:
                    future_ts += 1

            prov_l = prov.lower()
            hit = next((a for a in MONITORING_AGENTS if a in prov_l), None)
            if hit:
                b = agents[prov]
                b["count"] += 1
                b["levels"][lvl] += 1
                if len(b["samples"]) < max_samples and msg:
                    b["samples"].append({"event_id": eid, "level": lvl, "message": msg})

            if eid in SECURITY_EVENT_IDS:
                s = sec[eid]
                s["label"] = SECURITY_EVENT_IDS[eid]
                s["count"] += 1
                if len(s["samples"]) < max_samples and msg:
                    s["samples"].append({"provider": prov, "message": msg})

            if prov == "MsiInstaller" and eid in MSI_IDS:
                s = software[eid]
                s["label"] = MSI_IDS[eid]
                s["count"] += 1
                if len(s["samples"]) < max_samples and msg:
                    s["samples"].append(msg)

    fmt = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else None
    return {
        "source_file": str(path),
        "sha256": _sha256_of(path),
        "counts": {
            "lines_total": total,
            "parsed_ok": parsed,
            "parse_failures": failed,
            "implausible_future_timestamps": future_ts,
        },
        "timeline_plausible": {"first": fmt(tmin), "last": fmt(tmax)},
        "levels": dict(levels.most_common()),
        "top_providers": dict(providers.most_common(12)),
        "top_event_ids": [
            {"provider": p, "event_id": e, "count": c} for (p, e), c in by_eid.most_common(15)
        ],
        "relevant": {
            "monitoring_agents": {
                k: {"count": v["count"], "levels": dict(v["levels"]), "samples": v["samples"]}
                for k, v in sorted(agents.items(), key=lambda kv: -kv[1]["count"])
            },
            "security_events": {str(k): v for k, v in sorted(sec.items(), key=lambda kv: -kv[1]["count"])},
            "software_changes": {str(k): v for k, v in sorted(software.items(), key=lambda kv: -kv[1]["count"])},
        },
    }


def summarize_dir(directory):
    """Resume todos los *.ndjson de un directorio (p. ej. evidence/.../logs)."""
    directory = Path(directory)
    per_log = {}
    for f in sorted(directory.glob("*.ndjson")):
        try:
            per_log[f.name] = summarize(str(f))
        except Exception as e:
            per_log[f.name] = {"error": str(e)[:300]}
    return per_log


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "Application.ndjson"
    data = summarize(src)
    c = data["counts"]
    print(f"OK  {c['parsed_ok']}/{c['lines_total']} leídos "
          f"({c['parse_failures']} corrupta(s), {c['implausible_future_timestamps']} timestamps basura)")
    print(f"Rango fiable: {data['timeline_plausible']['first']} -> {data['timeline_plausible']['last']}")
    ag = data["relevant"]["monitoring_agents"]
    if ag:
        print("Agentes de monitorización:")
        for name, v in ag.items():
            print(f"  · {name}: {v['count']}")
    out = re.sub(r"\.(ndjson|jsonl|json)$", "", Path(src).name) + ".summary.json"
    Path(out).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"-> {out}")
