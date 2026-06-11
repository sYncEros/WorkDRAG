# Worker Digital Rights Audit Agent

Herramienta local de auditoría técnica y legal orientada a detectar capacidades de gestión corporativa, monitorización y persistencia en equipos Windows.

El objetivo del proyecto es ofrecer una visión clara y auditable de **qué capacidades existen en el dispositivo**, diferenciando entre:

- seguridad corporativa legítima,
- monitorización potencialmente intrusiva,
- y elementos de persistencia o control oculto.

> Nota importante: la aplicación está pensada para análisis local y defensivo. No intercepta tráfico, no eleva privilegios y no exfiltra datos.

---

## Qué hace

El flujo principal ejecuta varios módulos de auditoría y consolida los hallazgos en un informe técnico/legal.

### Módulos principales

- `main.py` — punto de entrada de la aplicación.
- `main_auto.py` — modo automático para la UI y ejecución sin interacción.
- `mini_console.pyw` — mini consola gráfica sin ventana de terminal.
- `core/audit_engine.py` — orquesta los análisis, guarda hallazgos y exporta resultados.
- `core/pdf_exporter.py` — genera informe PDF forense a partir de hallazgos y evaluación legal.
- `skills/mdm_audit/mdm_scanner.py` — detecta gestión corporativa y MDM.
- `skills/surveillance_audit/surveillance_scanner.py` — busca herramientas de monitorización, proxy, DLP, soporte remoto y señales de inspección.
- `skills/persistence_audit/persistence_scanner.py` — revisa persistencia en registro, servicios, tareas, WMI y drivers.
- `skills/compliance_engine/legal_engine.py` — cruza hallazgos técnicos con normativa española y europea.
- `ui/server.py` — servidor web para visualizar resultados en interfaz HTML y en el espacio "El Espejo".

---

## Arquitectura

La solución está organizada en dos capas principales:

1. **Capa de auditoría técnica**
   - Examina el sistema local.
   - Detecta indicadores de software corporativo o de vigilancia.
   - Genera hallazgos con nivel de riesgo.

2. **Capa de evaluación legal**
   - Relaciona los hallazgos con normas como RGPD, LOPDGDD, Estatuto de los Trabajadores y doctrina Barbulescu.
   - Ofrece una lectura comprensible del impacto legal.

Además del modo consola, el proyecto incluye una interfaz web básica en `ui/` para visualización de resultados.

---

## Requisitos

### Sistema operativo

- Windows

### Dependencias

- Python 3.12 o superior recomendado
- PowerShell
- SQLite (incluido con Python)
- Paquetes Python:
  - `psutil`
  - `rich`
  - `reportlab`
  - `flask`

### Observaciones

Algunas comprobaciones usan componentes nativos de Windows como:

- `winreg`
- `dsregcmd`
- claves del registro
- tareas programadas
- certificados locales

Por eso el proyecto no está pensado para ejecutarse tal cual en Linux o macOS.

---

## Instalación

El proyecto incluye `requirements.txt` con las dependencias necesarias.

Se recomienda:

1. Crear y activar un entorno virtual.
2. Instalar dependencias desde `requirements.txt`.

```bash
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt 
```

### Modo portátil (sin Python del sistema)

El repositorio incluye `python_portable/` y scripts para ejecutarlo sin depender
de una instalación local de Python.

1. Ejecuta `scripts\portable\run.bat` desde la raíz del proyecto.
2. El lanzador llama a `scripts\portable\bootstrap.bat`, que:
   - instala `pip` en `python_portable` (si no existe),
   - instala dependencias de `requirements.txt` (si faltan),
   - y arranca `main.py` con `python_portable\python.exe`.

Notas:

- Requiere conexión a Internet la primera vez (para descargar `get-pip.py` y paquetes).
- Después de la primera instalación, puede ejecutarse de forma local con el runtime portable.

### Mini consola portable (sin terminal visible)

Si la persona usuaria no quiere abrir PowerShell o no sabe usar comandos, hay una
mini consola gráfica pensada para doble clic:

1. Ejecuta `scripts\build_mini_console_exe.bat` para generar `release\WorkDRAG_Mini.exe`.
2. Copia `release\WorkDRAG_Mini.exe` junto con la carpeta del proyecto si quieres llevarlo en USB.
3. Abre `mini_console.pyw` directamente o usa `scripts\portable\start_mini_console.vbs` si prefieres el arranque silencioso desde la carpeta completa.

La mini consola permite:

- iniciar la auditoría completa sin terminal visible,
- abrir el dashboard web,
- acceder a `El Espejo`,
- y guardar resultados en `exports/`.

> Para el uso diario no técnico, la vía más simple es: abrir la mini consola o
> abrir el dashboard web.

---

## Cómo se ejecuta

### Inicio rápido desde consola (PowerShell)

Desde la raíz del proyecto:

```powershell
cd C:\worker-rights-agent
```

> En PowerShell, usa siempre la ruta explícita del lanzador portable.

Auditoría completa:

```powershell
& .\scripts\run.bat --no-interactive --quiet
```

Variantes útiles:

```powershell
# Forzar guardado aunque sea idéntica a la anterior
& .\scripts\run.bat --no-interactive --quiet --force-save

# Ejecutar solo algunas skills
& .\scripts\run.bat --skills mdm surveillance --no-interactive --quiet

# Ver skills disponibles
& .\scripts\run.bat --list-skills

# Solo JSON (sin PDF)
& .\scripts\run.bat --no-interactive --quiet --no-pdf

# Abrir la mini consola portátil (sin terminal visible)
Start-Process .\mini_console.pyw

# Generar el EXE portable de la mini consola
& .\scripts\build_mini_console_exe.bat
```

### Modo dashboard web

Si prefieres una interfaz visual local:

```powershell
& .\scripts\run.bat --no-interactive --quiet
& .\python_portable\python.exe .\ui\server.py
```

El dashboard incluye:

- resumen ejecutivo,
- hallazgos detallados,
- evaluación legal,
- comparación de informes,
- y `El Espejo`, pensado para devolver el contexto colectivo de forma anónima.

Para listar resultados:

```powershell
Get-ChildItem .\exports -Recurse -File
```

### Modo consola (auditoría completa)

1. Abre una terminal en la raíz del proyecto, o usa la mini consola si prefieres no ver la terminal.
2. Ejecuta `scripts\run.bat` con las opciones deseadas.
3. En modo interactivo, confirma cuando se solicite.

Durante la ejecución:

- se lanzan los skills disponibles,
- se imprimen hallazgos en consola,
- se genera un resumen,
- se evalúa el impacto legal,
- y se exportan informes JSON y PDF.

### Modo interfaz web (opcional)

- Inicia `ui/server.py` para levantar la interfaz local.
- Abre `ui/index.html` o la ruta servida por el backend para consultar resultados.

### Ejemplo de uso en consola

Salida esperada (resumen):

```text
[*] Ejecutando skill: mdm
[MDM] Iniciando auditoría de gestión corporativa...
[MDM] Completado — Riesgo: YELLOW | Flags: ['mdm_enrolled']
[*] Ejecutando skill: surveillance
[Surveillance] Iniciando auditoría de superficie de vigilancia...
[*] Ejecutando skill: persistence
[Persistence] Iniciando auditoría de persistencia...

Worker Digital Rights Audit — Resultados
Total hallazgos: 6 | Riesgo máximo: ORANGE

=== EVALUACIÓN LEGAL ===
1. [HIGH] Monitorización continua de productividad
    ...
[+] PDF guardado en: exports\YYYY-MM-DD\HHh.MMm\audit.pdf
```

### Ejemplo de salida JSON

```json
{
   "generated_at": "2026-05-19T10:20:14.120001",
   "total_findings": 6,
   "max_risk": "orange",
   "findings": [
      {
         "skill": "surveillance_audit",
         "category": "ssl_inspection",
         "title": "Certificado raíz de inspección SSL/TLS detectado",
         "risk_level": "orange"
      }
   ],
   "integrity_hash": "..."
}
```

---

## Qué analiza cada skill

### 1. MDM / gestión corporativa

Revisa si el dispositivo está enrolado en administración corporativa y si hay señales como:

- Intune,
- Azure AD join,
- AppLocker,
- restricción de desinscripción manual,
- certificados raíz corporativos.

### 2. Superficie de monitorización

Busca productos y capacidades asociadas a:

- EDR/XDR,
- DLP,
- inspección de red o HTTPS,
- monitorización de productividad,
- soporte remoto,
- extensiones de navegador con acceso a contenido.

### 3. Persistencia y infraestructura oculta

Inspecciona mecanismos que permiten mantener software activo tras reinicios o sesiones:

- claves `Run` y `RunOnce`,
- servicios,
- tareas programadas,
- WMI,
- drivers,
- certificados sospechosos.

### 4. Evaluación legal

Relaciona los hallazgos con referencias como:

- RGPD,
- LOPDGDD,
- Estatuto de los Trabajadores,
- doctrina Barbulescu,
- guía de relaciones laborales de la AEPD.

---

## Salidas generadas

### Base de datos interna

`evidence/audit.db`

Guarda:

- hallazgos individuales,
- sesiones de auditoría,
- hashes de integridad.

### Exportación JSON

`exports/YYYY-MM-DD/HHh.MMm/audit.json`

Incluye:

- fecha de generación,
- total de hallazgos,
- nivel de riesgo máximo,
- lista completa de hallazgos,
- hash de integridad.

### Exportación PDF

`exports/YYYY-MM-DD/HHh.MMm/audit.pdf`

Incluye:

- portada ejecutiva,
- resumen por skill,
- detalle de hallazgos,
- evaluación legal,
- bloque de integridad del informe.

> Si se proporciona `--output`, se respeta el prefijo personalizado y no se aplica
> automáticamente esta estructura por fecha/hora.

---

## Estructura del proyecto

```bash
worker-rights-agent/
├── main.py
├── requirements.txt
├── CONTRIBUTING.md
├── core/
│   ├── audit_engine.py
│   └── pdf_exporter.py
├── skills/
│   ├── compliance_engine/
│   │   └── legal_engine.py
│   ├── mdm_audit/
│   │   └── mdm_scanner.py
│   ├── persistence_audit/
│   │   └── persistence_scanner.py
│   └── surveillance_audit/
│       └── surveillance_scanner.py
├── evidence/
├── exports/
├── ui/
│   ├── server.py
│   ├── index.html
│   └── static/
│       └── js/
└── .docs/
```

---

## Limitaciones conocidas

- Está orientado a Windows.
- Parte del análisis depende de permisos de lectura sobre registro, servicios y certificados.
- La detección se basa en indicadores y heurísticas, no en pruebas forenses concluyentes.
- La interfaz web está en estado funcional básico y puede evolucionar en diseño/cobertura.

---

## Buenas prácticas

- Ejecutar siempre con conocimiento del usuario del equipo.
- Revisar el informe antes de compartirlo.
- No interpretar un hallazgo aislado como prueba definitiva de vigilancia.
- Combinar la salida técnica con documentación interna y políticas corporativas.

---

## Documentación adicional

La carpeta `.docs/` contiene una especificación más amplia del proyecto:

- `.docs/Worker Digital Rights Audit Agent.md`
- `.docs/README.md` (índice general de documentación)
- `.docs/folders/FOLDERS.md` (documentación unificada por carpetas)
- `.docs/modules/MODULES.md` (documentación unificada por módulos)

Esa documentación profundiza en la visión del producto, la arquitectura propuesta y los tipos de análisis previstos.
