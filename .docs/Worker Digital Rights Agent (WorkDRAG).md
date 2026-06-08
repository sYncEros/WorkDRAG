# Worker Digital Rights Agent (WorkDRAG)



## Objetivo

Crear una herramienta local, transparente y auditable para trabajadores, sindicatos o peritos técnicos que permita:

* Entender qué capacidades de monitorización existen en un equipo.
* Diferenciar seguridad corporativa legítima de vigilancia potencialmente excesiva.
* Preservar evidencias técnicas.
* Generar informes comprensibles.
* Reducir paranoia y aumentar transparencia.

La herramienta debe pedir permiso previo al usuario si requiere acceder a información sensible, y explicar claramente qué se va a analizar y qué no:

* Interceptar tráfico corporativo.
* Saltarse medidas de seguridad.
* Escalar privilegios.
* Exfiltrar datos.
* Comprometer infraestructura empresarial.
* Ejecutar técnicas ofensivas.

---

## Arquitectura General

```text
┌──────────────────────────┐
│ Dashboard UI             │
│ React + Tauri            │
└────────────┬─────────────┘
             │
┌────────────▼─────────────┐
│ Core Audit Engine        │
│ Python / PowerShell      │
└────────────┬─────────────┘
             │
 ┌───────────┼───────────┐
 │           │           │
 ▼           ▼           ▼
Skills    Monitor      Legal Engine
```

---

## Stack recomendado

## Backend

* Python 3.12
* PowerShell
* SQLite
* psutil
* pywin32
* wmi
* watchdog

## Frontend

* Tauri
* React
* Tailwind
* Chart.js

## Exportación

* JSON
* PDF
* CSV

---

## Skills principales

---

## Skill 1 — MDM & Corporate Control Audit

### Objetivo del skill 1

Detectar nivel de gestión corporativa.

### Analiza el skill 1

* Microsoft Intune
* Azure AD
* MDM enrollment
* AppLocker
* Windows Hello for Business
* Defender policies
* DeviceCompliance
* Certificates

### Fuentes

```text
MDMDiagnosticTool
Registry
certmgr.msc
Event Viewer
```

### Indicadores relevantes

* ManagedBy
* Tenant ID
* Enrollment state
* AllowManualMDMUnenrollment
* Corporate certificates
* Policy CSPs

### Salida ejemplo

```json
{
  "mdm_enrolled": true,
  "managed_by": "NTT DATA EMEAL",
  "risk_level": "medium",
  "flags": [
    "manual_unenrollment_disabled",
    "corporate_root_certificates_present"
  ]
}
```

---

## Skill 2 — Surveillance Surface Audit

### Objetivo del skill 2

Detectar capacidades de monitorización o telemetría avanzada.

### Categorías

* EDR/XDR
* DLP
* Productivity Monitoring
* SSL Inspection
* Remote Support
* Browser Inspection

### Detecta

* Processes
* Services
* Drivers
* Browser extensions
* Root certificates
* Scheduled tasks
* WMI persistence
* ETW providers

### Productos conocidos

* CrowdStrike
* SentinelOne
* Tanium
* Netskope
* Zscaler
* Forcepoint
* Microsoft Purview
* ActivTrak
* Teramind
* Hubstaff
* Veriato

### Ejemplo de salida

```json
{
  "ssl_inspection": true,
  "input_monitoring": false,
  "screen_capture_capability": "unknown",
  "browser_forced_extensions": true,
  "risk_level": "medium"
}
```

---

## Skill 3 — Background Activity Monitor

### Objetivo del skill 3

Visualizar actividad persistente y cambios relevantes.

### Monitoriza

* Procesos persistentes
* Nuevas conexiones salientes
* Servicios creados
* Drivers nuevos
* Acceso webcam/micro
* Clipboard access
* Screenshot APIs
* Input hooks
* Scheduled task changes

### Tecnologías

* ETW
* Windows Event Logs
* Sysmon opcional
* psutil

### Dashboard

Timeline vivo:

```text
14:22 - Nuevo proceso persistente
14:24 - Nueva conexión TLS externa
14:25 - Modificación policy CSP
```

---

## Skill 4 — Persistence & Hidden Infrastructure Audit

### Objetivo del skill 4

Detectar persistencia avanzada y ubicaciones menos visibles.

### Analiza el skill 4

#### Registry

```text
HKLM\SYSTEM\CurrentControlSet\Services
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

#### Tasks

```text
C:\Windows\System32\Tasks
```

#### Drivers

```text
C:\Windows\System32\drivers
```

#### WMI

* Event Filters
* Event Consumers
* Bindings

#### Browser Policies

```text
HKLM\Software\Policies\Google\Chrome
HKLM\Software\Policies\Microsoft\Edge
```

#### Certificates

* Trusted Root Certification Authorities
* Enterprise certificates

### Objetivo de detección

No detectar “archivos raros”.

Detectar:

* persistencia,
* privilegios,
* inspección,
* capacidades reales.

---

## Skill 5 — Rights & Compliance Engine

### Objetivo del skill 5

Cruzar hallazgos técnicos con legislación española.

### Referencias

* RGPD
* LOPDGDD
* Estatuto de los Trabajadores
* Jurisprudencia TEDH
* Doctrina Barbulescu

### Evalúa

* proporcionalidad
* transparencia
* consentimiento
* minimización
* vigilancia fuera de horario
* BYOD

### Ejemplo

```json
{
  "issue": "continuous productivity tracking",
  "legal_risk": "high",
  "reason": "possible proportionality conflict under LOPDGDD"
}
```

---

## Sistema de Riesgo

## Niveles

| Nivel    | Significado                         |
| -------- | ----------------------------------- |
| Verde    | Seguridad corporativa estándar      |
| Amarillo | Telemetría relevante                |
| Naranja  | Vigilancia potencialmente intrusiva |
| Rojo     | Capacidad altamente invasiva        |

---

## Capability Mapping

| Capacidad             | Riesgo     |
| --------------------- | ---------- |
| MDM                   | Bajo       |
| EDR/XDR               | Bajo-Medio |
| DLP                   | Medio      |
| SSL Inspection        | Medio-Alto |
| Productivity Tracking | Medio-Alto |
| Screenshot Capture    | Alto       |
| Keyboard Hooks        | Muy Alto   |
| Webcam Persistence    | Muy Alto   |

---

## Dashboard recomendado

## Vista General

* Gestión corporativa
* Riesgo técnico
* Riesgo jurídico
* Capacidades detectadas

---

## Timeline

* cambios de políticas
* nuevas conexiones
* nuevos procesos
* reinicios de servicios
* alteraciones de logs

---

## Explainability Panel

Cada hallazgo debe explicar:

* qué es,
* qué capacidad tiene,
* qué NO implica,
* riesgo técnico,
* riesgo jurídico aproximado.

Ejemplo:

> “Existe un certificado raíz corporativo que permite inspección HTTPS corporativa. Esto no demuestra espionaje ilegal, pero sí capacidad de inspección de tráfico cifrado.”

---

## Modo Forense

### Objetivo del modo forense

Preservar evidencia reproducible.

### Funciones

* Hashes SHA256
* Snapshots
* Export JSON
* Export PDF
* Timeline firmado
* Integridad de logs

### NO debe incluir

* bypasses
* explotación
* intrusión
* dumping de credenciales
* sniffing ilegal

---

## Estructura del Proyecto

```text
worker-rights-agent/
│
├── core/
│   ├── audit_engine.py
│   ├── registry_scan.py
│   ├── process_monitor.py
│   ├── network_monitor.py
│   ├── certificate_audit.py
│   └── legal_engine.py
│
├── skills/
│   ├── mdm_audit/
│   ├── surveillance_audit/
│   ├── persistence_audit/
│   ├── activity_monitor/
│   └── compliance_engine/
│
├── ui/
│   ├── dashboard/
│   └── components/
│
├── exports/
│
└── evidence/
```

---

## Filosofía del proyecto

La herramienta debe:

* favorecer transparencia,
* evitar paranoia,
* explicar contexto,
* proteger derechos,
* permitir auditoría independiente,
* generar confianza técnica.

No debe convertirse en:

* software ofensivo,
* contraespionaje corporativo,
* herramienta de sabotaje,
* sistema conspirativo.

La credibilidad jurídica y técnica es el activo principal del proyecto.
