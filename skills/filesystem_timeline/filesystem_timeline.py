# skills/filesystem_timeline/filesystem_timeline.py
"""
Skill — Filesystem Timeline
Arqueología forense del sistema de archivos: detecta artefactos en rutas
no convencionales, archivos con timestamps anómalos, carpetas no estándar
y correlaciona actividad de filesystem con fechas de eventos relevantes.

Casos específicos documentados en investigación WorkDRAG:
- Carpetas en raíz C:\ no pertenecientes al sistema
- ProgramData con herramientas no documentadas (LogMeIn, dbg, etc.)
- Timestamps anómalos por cambio manual de reloj (2028, 2032)
- Archivos creados en fechas correlacionadas con eventos de riesgo

Operación: solo lectura, sin elevación de privilegios.
Fuentes: os.scandir, Path.stat(), filesystem metadata.
"""

import os
import re
import json
import hashlib
import datetime
import subprocess
from pathlib import Path
from typing import Optional
from collections import defaultdict


# ── Configuración ─────────────────────────────────────────────────────────────

# Año actual para detectar timestamps futuros
CURRENT_YEAR = datetime.datetime.now().year
FUTURE_THRESHOLD = CURRENT_YEAR + 1  # Timestamps con año > este son anómalos
PAST_THRESHOLD = 2019  # Timestamps anteriores a este son sospechosos en Windows 10

# Rutas estándar del sistema — su contenido no se alerta salvo anomalías
SYSTEM_STANDARD_NAMES = {
    "windows", "users", "program files", "program files (x86)",
    "programdata", "recovery", "system volume information",
    "$recycle.bin", "perflogs", "boot", "workdrag",
}

# Nombres conocidos de carpetas en ProgramData legítimas
PROGRAMDATA_KNOWN = {
    "microsoft", "adobe", "intel", "dell", "qualys", "zscaler",
    "crowdstrike", "nexthink", "snow software", "package cache",
    "ssh", "chocolatey", "mozilla", "google", "windows",
    "regid.1991-06.com.microsoft", "softwaredistribution",
    "usoprivate", "usoshared", "waves", "cisco", "containers",
    "dftmp", "nttalm", "nttdata",
}

# Rutas sensibles a auditar en profundidad
SENSITIVE_PATHS = [
    Path(r"C:\\"),
    Path(r"C:\ProgramData"),
    Path(r"C:\Windows\Temp"),
    Path(os.path.expandvars(r"%TEMP%")),
    Path(os.path.expandvars(r"%APPDATA%")),
    Path(os.path.expandvars(r"%LOCALAPPDATA%")),
]

# Extensiones de alto interés forense
HIGH_INTEREST_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".wsf", ".msi", ".inf", ".reg", ".log", ".dat",
}

# Fechas de eventos clave documentados en la investigación
# (se pueden añadir dinámicamente desde audit DB)
KEY_DATES = {
    "xguest_session":          "2025-03-07",
    "npcap_install":           "2024-08-29",
    "npcap_reconfig_insecure": "2026-03-05",
    "emealit_pwd_change":      "2026-04-25",
    "paperqueen_tasks":        "2026-04-21",
    "logmein_install":         "2026-01-22",
    "logmein_last_session":    "2026-06-01",
    "xguest_pwd_change":       "2026-06-08",
}

# Ventana de correlación en días
CORRELATION_WINDOW_DAYS = 1


# ── Utilidades ────────────────────────────────────────────────────────────────

def _file_hash(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _safe_stat(path: Path) -> Optional[dict]:
    """Lee metadatos de un archivo de forma segura."""
    try:
        stat = path.stat()
        ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        return {
            "path": str(path),
            "size_bytes": stat.st_size,
            "created": ctime.isoformat(),
            "modified": mtime.isoformat(),
            "created_year": ctime.year,
            "modified_year": mtime.year,
            "is_dir": path.is_dir(),
            "extension": path.suffix.lower() if not path.is_dir() else None,
        }
    except Exception:
        return None


def _is_anomalous_timestamp(year: int) -> bool:
    return year > FUTURE_THRESHOLD or year < PAST_THRESHOLD


def _correlates_with_key_date(date_str: str) -> list[str]:
    """
    Comprueba si una fecha está dentro de la ventana de correlación
    de algún evento clave documentado.
    """
    matches = []
    try:
        target = datetime.datetime.fromisoformat(date_str[:10]).date()
        for event_name, event_date_str in KEY_DATES.items():
            event_date = datetime.datetime.strptime(
                event_date_str, "%Y-%m-%d"
            ).date()
            delta = abs((target - event_date).days)
            if delta <= CORRELATION_WINDOW_DAYS:
                matches.append(
                    f"{event_name} ({event_date_str}, Δ{delta}d)"
                )
    except Exception:
        pass
    return matches


def _scan_dir_shallow(path: Path, max_items: int = 200) -> list[dict]:
    """
    Escaneo superficial de un directorio — solo primer nivel.
    Devuelve metadatos de cada entrada.
    """
    items = []
    try:
        for i, entry in enumerate(path.iterdir()):
            if i >= max_items:
                break
            meta = _safe_stat(entry)
            if meta:
                items.append(meta)
    except PermissionError:
        pass
    except Exception:
        pass
    return items


def _scan_for_recent_files(
    path: Path, days_back: int = 30, max_items: int = 100
) -> list[dict]:
    """
    Busca archivos modificados recientemente en una ruta.
    No recursivo para evitar timeouts.
    """
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days_back)
    recent = []
    try:
        for entry in path.iterdir():
            try:
                stat = entry.stat()
                mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
                if mtime >= cutoff:
                    meta = _safe_stat(entry)
                    if meta:
                        meta["days_ago"] = (
                            datetime.datetime.now() - mtime
                        ).days
                        recent.append(meta)
            except Exception:
                continue
            if len(recent) >= max_items:
                break
    except Exception:
        pass
    return sorted(recent, key=lambda x: x.get("modified", ""), reverse=True)


# ── Detección de no estándar ──────────────────────────────────────────────────

def _find_non_standard_root_items() -> tuple[list[dict], list[dict]]:
    """
    Detecta carpetas y archivos no estándar en la raíz C:\\.
    Devuelve (non_standard_dirs, non_standard_files).
    """
    root = Path("C:\\")
    non_std_dirs = []
    non_std_files = []

    try:
        for entry in root.iterdir():
            name_lower = entry.name.lower().strip("$")
            if name_lower in SYSTEM_STANDARD_NAMES:
                continue
            if entry.name.startswith("$"):
                continue

            meta = _safe_stat(entry)
            if not meta:
                continue

            # Correlacionar con eventos clave
            correlations = []
            if meta.get("created"):
                correlations.extend(
                    _correlates_with_key_date(meta["created"])
                )
            if meta.get("modified"):
                correlations.extend(
                    _correlates_with_key_date(meta["modified"])
                )

            meta["correlations"] = correlations
            meta["name"] = entry.name

            if entry.is_dir():
                # Contar contenido
                try:
                    children = list(entry.iterdir())
                    meta["child_count"] = len(children)
                    meta["has_content"] = len(children) > 0
                except Exception:
                    meta["child_count"] = -1
                    meta["has_content"] = None
                non_std_dirs.append(meta)
            else:
                non_std_files.append(meta)

    except Exception:
        pass

    return non_std_dirs, non_std_files


def _find_non_standard_programdata() -> list[dict]:
    """
    Detecta carpetas en C:\\ProgramData no pertenecientes a software conocido.
    """
    programdata = Path(r"C:\ProgramData")
    non_standard = []

    try:
        for entry in programdata.iterdir():
            if not entry.is_dir():
                continue
            name_lower = entry.name.lower()
            if any(known in name_lower for known in PROGRAMDATA_KNOWN):
                continue

            meta = _safe_stat(entry)
            if not meta:
                continue

            meta["name"] = entry.name

            # Contenido superficial
            children = _scan_dir_shallow(entry, max_items=20)
            meta["child_count"] = len(children)
            meta["children_sample"] = [
                {
                    "name": Path(c["path"]).name,
                    "size_bytes": c["size_bytes"],
                    "modified": c["modified"],
                }
                for c in children[:10]
            ]

            # Correlaciones con eventos clave
            correlations = []
            if meta.get("created"):
                correlations.extend(
                    _correlates_with_key_date(meta["created"])
                )
            if meta.get("modified"):
                correlations.extend(
                    _correlates_with_key_date(meta["modified"])
                )
            meta["correlations"] = correlations

            non_standard.append(meta)

    except Exception:
        pass

    return non_standard


def _find_anomalous_timestamps(paths: list[Path]) -> list[dict]:
    """
    Busca archivos y carpetas con timestamps anómalos (futuros o muy antiguos)
    en las rutas especificadas.
    """
    anomalous = []

    for base_path in paths:
        try:
            for entry in base_path.iterdir():
                meta = _safe_stat(entry)
                if not meta:
                    continue

                c_year = meta.get("created_year", CURRENT_YEAR)
                m_year = meta.get("modified_year", CURRENT_YEAR)

                if _is_anomalous_timestamp(c_year) or \
                   _is_anomalous_timestamp(m_year):
                    meta["name"] = entry.name
                    meta["anomaly"] = []
                    if _is_anomalous_timestamp(c_year):
                        meta["anomaly"].append(
                            f"created_year={c_year} "
                            f"({'futuro' if c_year > FUTURE_THRESHOLD else 'muy antiguo'})"
                        )
                    if _is_anomalous_timestamp(m_year):
                        meta["anomaly"].append(
                            f"modified_year={m_year} "
                            f"({'futuro' if m_year > FUTURE_THRESHOLD else 'muy antiguo'})"
                        )
                    anomalous.append(meta)
        except Exception:
            continue

    return anomalous


def _find_files_on_key_dates(paths: list[Path]) -> list[dict]:
    """
    Busca archivos creados o modificados en fechas de eventos clave.
    """
    findings = []

    for base_path in paths:
        try:
            for entry in base_path.iterdir():
                meta = _safe_stat(entry)
                if not meta:
                    continue

                correlations = []
                if meta.get("created"):
                    correlations.extend(
                        _correlates_with_key_date(meta["created"])
                    )
                if meta.get("modified") and meta["modified"] != meta["created"]:
                    correlations.extend(
                        _correlates_with_key_date(meta["modified"])
                    )

                if correlations:
                    meta["name"] = entry.name
                    meta["correlations"] = correlations
                    findings.append(meta)
        except Exception:
            continue

    return findings


# ── Skill principal ───────────────────────────────────────────────────────────

class FilesystemTimeline:
    SKILL_NAME = "filesystem_timeline"

    def __init__(self, engine):
        self.engine = engine

    def run(self):
        print("[FilesystemTimeline] Iniciando arqueología de filesystem...")

        # 1. Raíz C:\
        print("[FilesystemTimeline] Escaneando raíz C:\\...")
        non_std_dirs, non_std_files = _find_non_standard_root_items()

        # 2. ProgramData no estándar
        print("[FilesystemTimeline] Escaneando ProgramData...")
        non_std_programdata = _find_non_standard_programdata()

        # 3. Timestamps anómalos
        print("[FilesystemTimeline] Buscando timestamps anómalos...")
        anomalous_ts = _find_anomalous_timestamps(SENSITIVE_PATHS[:3])

        # 4. Archivos en fechas de eventos clave
        print("[FilesystemTimeline] Correlacionando con fechas de eventos...")
        key_date_files = _find_files_on_key_dates(SENSITIVE_PATHS[:4])

        # 5. Archivos recientes en rutas sensibles
        print("[FilesystemTimeline] Buscando actividad reciente...")
        temp_recent = _scan_for_recent_files(
            Path(r"C:\Windows\Temp"), days_back=14
        )
        programdata_recent = _scan_for_recent_files(
            Path(r"C:\ProgramData"), days_back=7
        )

        print(
            f"[FilesystemTimeline] "
            f"Dirs no estándar: {len(non_std_dirs)} | "
            f"ProgramData no estándar: {len(non_std_programdata)} | "
            f"Timestamps anómalos: {len(anomalous_ts)} | "
            f"Correlaciones: {len(key_date_files)}"
        )

        # Generar hallazgos
        self._report_non_standard_root(non_std_dirs, non_std_files)
        self._report_non_standard_programdata(non_std_programdata)
        self._report_anomalous_timestamps(anomalous_ts)
        self._report_key_date_correlations(key_date_files)
        self._report_recent_activity(temp_recent, programdata_recent)

        print("[FilesystemTimeline] Completado")

    # ── Hallazgos ─────────────────────────────────────────────────────────────

    def _report_non_standard_root(
        self, dirs: list[dict], files: list[dict]
    ):
        """Hallazgo: carpetas y archivos no estándar en raíz C:\\."""
        from core.audit_engine import AuditFinding

        if not dirs and not files:
            return

        # Separar carpetas vacías de las que tienen contenido
        with_content = [d for d in dirs if d.get("has_content")]
        empty_or_unknown = [d for d in dirs if not d.get("has_content")]

        # Determinar riesgo
        risk = "yellow"
        correlated = [
            d for d in dirs + files if d.get("correlations")
        ]
        if correlated:
            risk = "orange"

        flags = []
        for d in with_content:
            label = (
                f"carpeta con contenido: {d['name']} "
                f"({d.get('child_count', '?')} items, "
                f"creada {d.get('created', '?')[:10]})"
            )
            if d.get("correlations"):
                label += f" [correlación: {'; '.join(d['correlations'])}]"
            flags.append(label)

        for d in empty_or_unknown:
            flags.append(
                f"carpeta vacía o inaccesible: {d['name']} "
                f"(creada {d.get('created', '?')[:10]})"
            )

        for f in files:
            flags.append(
                f"archivo suelto: {f['name']} "
                f"({f.get('size_bytes', 0)} bytes)"
            )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="filesystem_non_standard_root",
            title=(
                f"Raíz C:\\: {len(dirs)} carpeta(s) y {len(files)} "
                "archivo(s) no estándar detectados"
            ),
            description=(
                f"Se han detectado {len(dirs)} carpeta(s) y {len(files)} "
                "archivo(s) en la raíz de C:\\ que no pertenecen al "
                "sistema operativo estándar de Windows. "
                + (
                    f"{len(correlated)} elemento(s) correlacionados "
                    "con fechas de eventos de riesgo documentados."
                    if correlated else ""
                )
            ),
            risk_level=risk,
            technical_risk=(
                "La raíz de C:\\ es una ubicación privilegiada. "
                "Software legítimo raramente crea carpetas directamente "
                "en C:\\. Su presencia puede indicar herramientas instaladas "
                "fuera del proceso estándar de instalación."
            ),
            legal_risk=(
                "Herramientas no documentadas en la raíz del disco pueden "
                "estar relacionadas con capacidades de monitorización no "
                "informadas al trabajador — RGPD art. 13, LOPDGDD art. 87."
            ),
            what_it_is=(
                "Carpetas y archivos en la raíz C:\\ que no son parte "
                "del sistema operativo Windows ni de software instalado "
                "por rutas estándar."
            ),
            what_it_is_not=(
                "No implica actividad maliciosa. Puede ser software "
                "legítimo con instalación no convencional, como WorkDRAG "
                "o herramientas de desarrollo."
            ),
            raw_data={
                "non_standard_dirs": dirs,
                "non_standard_files": files,
                "correlated_items": correlated,
                "flags": flags,
                "counts": {
                    "dirs_with_content": len(with_content),
                    "dirs_empty": len(empty_or_unknown),
                    "files": len(files),
                    "correlated": len(correlated),
                },
            },
        ))

    def _report_non_standard_programdata(self, items: list[dict]):
        """Hallazgo: carpetas no estándar en ProgramData."""
        from core.audit_engine import AuditFinding

        if not items:
            return

        correlated = [i for i in items if i.get("correlations")]
        risk = "orange" if correlated else "yellow"

        known_risky = []
        for item in items:
            name_lower = item["name"].lower()
            # Detectar herramientas de acceso remoto o monitorización
            if any(k in name_lower for k in [
                "logmein", "teamviewer", "anydesk", "rescue",
                "remote", "vnc", "rdp"
            ]):
                known_risky.append(item)
                risk = "red"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="filesystem_non_standard_programdata",
            title=(
                f"ProgramData: {len(items)} carpeta(s) no estándar"
                + (" — herramientas de acceso remoto detectadas"
                   if known_risky else "")
                + (f" — {len(correlated)} correlacionada(s) con eventos"
                   if correlated else "")
            ),
            description=(
                f"Se han detectado {len(items)} carpeta(s) en "
                "C:\\ProgramData que no corresponden a software conocido "
                "del sistema. "
                + (
                    f"Carpetas destacadas: "
                    f"{', '.join(i['name'] for i in items[:8])}."
                )
            ),
            risk_level=risk,
            technical_risk=(
                "ProgramData alberga datos de aplicaciones instaladas "
                "a nivel de sistema. Carpetas no identificadas pueden "
                "pertenecer a herramientas instaladas sin documentar."
            ),
            legal_risk=(
                "Las herramientas instaladas que almacenan datos en "
                "ProgramData operan a nivel de sistema y pueden procesar "
                "datos del trabajador — RGPD art. 13, LOPDGDD art. 87."
            ),
            what_it_is=(
                "Inventario de carpetas en ProgramData que no corresponden "
                "a software estándar conocido."
            ),
            what_it_is_not=(
                "No implica que sean maliciosas. Puede incluir software "
                "legítimo instalado por el administrador del sistema."
            ),
            raw_data={
                "non_standard_items": [
                    {
                        "name": i["name"],
                        "created": i.get("created"),
                        "modified": i.get("modified"),
                        "child_count": i.get("child_count"),
                        "children_sample": i.get("children_sample", []),
                        "correlations": i.get("correlations", []),
                    }
                    for i in items
                ],
                "known_risky": [i["name"] for i in known_risky],
                "correlated": [i["name"] for i in correlated],
            },
        ))

    def _report_anomalous_timestamps(self, items: list[dict]):
        """Hallazgo: archivos y carpetas con timestamps anómalos."""
        from core.audit_engine import AuditFinding

        if not items:
            return

        future_items = [
            i for i in items
            if any("futuro" in a for a in i.get("anomaly", []))
        ]

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="filesystem_anomalous_timestamps",
            title=(
                f"Timestamps anómalos: {len(items)} elemento(s) con "
                "fechas fuera de rango"
                + (f" ({len(future_items)} con fecha futura)"
                   if future_items else "")
            ),
            description=(
                f"Se han detectado {len(items)} elemento(s) con timestamps "
                f"anómalos (año < {PAST_THRESHOLD} o > {FUTURE_THRESHOLD}). "
                + (
                    f"{len(future_items)} con fecha futura — "
                    "puede indicar cambio manual del reloj del sistema "
                    "durante operaciones de auditoría o administración."
                    if future_items else ""
                )
            ),
            risk_level="yellow",
            technical_risk=(
                "Los timestamps anómalos pueden ser artefactos de cambios "
                "manuales del reloj del sistema. Deben documentarse para "
                "preservar la integridad de la cadena de custodia forense. "
                "Los archivos con fecha futura no aparecen en búsquedas "
                "de rango temporal estándar."
            ),
            legal_risk=(
                "Los timestamps anómalos deben declararse en documentación "
                "forense para evitar cuestionar la integridad de la evidencia. "
                "Su origen debe explicarse en el informe pericial."
            ),
            what_it_is=(
                "Archivos o carpetas cuyas fechas de creación o modificación "
                "están fuera del rango esperado para el sistema. "
                "Típicamente causados por cambio manual del reloj del sistema."
            ),
            what_it_is_not=(
                "No implica manipulación maliciosa de evidencias. "
                "Documentar la causa conocida (cambio de reloj) es "
                "suficiente para preservar la validez forense."
            ),
            raw_data={
                "anomalous_items": [
                    {
                        "name": i.get("name"),
                        "path": i.get("path"),
                        "created": i.get("created"),
                        "modified": i.get("modified"),
                        "anomaly": i.get("anomaly"),
                    }
                    for i in items[:30]
                ],
                "future_count": len(future_items),
                "total": len(items),
                "year_thresholds": {
                    "past": PAST_THRESHOLD,
                    "future": FUTURE_THRESHOLD,
                },
            },
        ))

    def _report_key_date_correlations(self, items: list[dict]):
        """Hallazgo: archivos correlacionados con fechas de eventos clave."""
        from core.audit_engine import AuditFinding

        if not items:
            return

        # Agrupar por evento
        by_event = defaultdict(list)
        for item in items:
            for corr in item.get("correlations", []):
                event_name = corr.split(" (")[0]
                by_event[event_name].append({
                    "name": item.get("name"),
                    "path": item.get("path"),
                    "created": item.get("created"),
                    "modified": item.get("modified"),
                    "size_bytes": item.get("size_bytes"),
                    "correlation": corr,
                })

        risk = "orange" if by_event else "yellow"

        # Flag especial si hay correlación con cambio de contraseña de XGuest
        xguest_related = by_event.get("xguest_pwd_change", [])
        if xguest_related:
            risk = "red"

        event_summary = []
        for event, files in by_event.items():
            event_summary.append(
                f"{event}: {len(files)} archivo(s) — "
                f"{', '.join(f['name'] for f in files[:3])}"
            )

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="filesystem_key_date_correlations",
            title=(
                f"Timeline: {len(items)} artefacto(s) correlacionados "
                f"con {len(by_event)} evento(s) de riesgo documentados"
            ),
            description=(
                f"Se han encontrado {len(items)} artefactos de filesystem "
                "cuyas fechas coinciden (±1 día) con eventos de riesgo "
                "documentados en la investigación. "
                + "; ".join(event_summary[:5])
            ),
            risk_level=risk,
            technical_risk=(
                "La correlación temporal entre artefactos de filesystem "
                "y eventos documentados fortalece la cadena de evidencia. "
                "Permite establecer qué actividad de filesystem ocurrió "
                "coincidiendo con cada evento de riesgo."
            ),
            legal_risk=(
                "Las correlaciones temporales son evidencia forense "
                "relevante para establecer causalidad entre eventos. "
                "Especialmente relevante si hay correlación con accesos "
                "remotos o cambios de cuenta no autorizados."
            ),
            what_it_is=(
                "Cruce entre timestamps de artefactos de filesystem y "
                "fechas de eventos documentados (sesiones LogMeIn, "
                "reconfiguración npcap, cambios de contraseña, etc.)."
            ),
            what_it_is_not=(
                "Correlación temporal no implica causalidad. "
                "Documenta coincidencia que puede tener explicación "
                "inocente o relevancia forense según el contexto."
            ),
            raw_data={
                "correlations_by_event": dict(by_event),
                "xguest_related_files": xguest_related,
                "total_correlated": len(items),
                "events_matched": list(by_event.keys()),
                "key_dates_reference": KEY_DATES,
            },
        ))

    def _report_recent_activity(
        self, temp_items: list[dict], programdata_items: list[dict]
    ):
        """Hallazgo: actividad reciente en rutas sensibles."""
        from core.audit_engine import AuditFinding

        all_recent = temp_items + programdata_items
        if not all_recent:
            return

        # Filtrar solo los de interés (extensiones relevantes o tamaño > 0)
        interesting = [
            i for i in all_recent
            if i.get("extension") in HIGH_INTEREST_EXTENSIONS
            or i.get("size_bytes", 0) > 100_000
        ]

        risk = "yellow" if not interesting else "orange"

        self.engine.add_finding(AuditFinding(
            skill=self.SKILL_NAME,
            category="filesystem_recent_activity",
            title=(
                f"Actividad reciente: {len(temp_items)} en Temp, "
                f"{len(programdata_items)} en ProgramData (últimos 14 días)"
            ),
            description=(
                f"Se han detectado {len(temp_items)} elemento(s) recientes "
                "en Windows\\Temp y "
                f"{len(programdata_items)} en ProgramData "
                f"en los últimos 14 días. "
                + (
                    f"{len(interesting)} con extensión de alto interés "
                    "forense o tamaño significativo."
                    if interesting else ""
                )
            ),
            risk_level=risk,
            technical_risk=(
                "La actividad reciente en Temp y ProgramData puede "
                "evidenciar instalaciones recientes, actualizaciones "
                "de agentes de monitorización o ejecución de scripts."
            ),
            legal_risk=(
                "Actividad de filesystem en fechas coincidentes con "
                "eventos de riesgo puede ser evidencia forense relevante "
                "para la investigación."
            ),
            what_it_is=(
                "Snapshot de actividad reciente de filesystem en rutas "
                "sensibles del sistema."
            ),
            what_it_is_not=(
                "No implica actividad maliciosa. La actividad normal "
                "del sistema genera constantemente archivos en Temp."
            ),
            raw_data={
                "temp_recent": temp_items[:20],
                "programdata_recent": programdata_items[:20],
                "high_interest_items": interesting[:15],
                "counts": {
                    "temp": len(temp_items),
                    "programdata": len(programdata_items),
                    "high_interest": len(interesting),
                },
            },
        ))