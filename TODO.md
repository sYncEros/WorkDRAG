# TODO

## Prioridades inmediatas

**AI/Telemetry** — solo mide Windows, falta detección de clientes IA locales.
Añadiremos procesos/servicios de OpenAI, Anthropic, Ollama y Gemini, y herramientas corporativas como Axet, Gaia, Oasis como nuevo skill o extensión del existente.

## Mejoras

- **Email Client Audit** — Qdetección explícita de delegaciones de buzón (SendAs / FullAccess / SendOnBehalf).

- **Third Party Apps Audit** — ampliar el mapeo de permisos por app/extensión/add-in y añadir tests por perfiles simulados.

- **User Behavior Analysis** — ampliar pruebas funcionales con datos simulados (eventos de horario/anomalía y objetos sensibles) para robustecer evidencia reproducible.

- **Data Exfiltration Detection** — correlación de flujos reales en producción.

- **Persistence Mechanisms** — tests funcionales con datos simulados para DLL hijacking y WMI.

- **Incident Response Playbook** — ajustar severidad/urgencia con reglas de proporcionalidad y añadir tests funcionales por escenarios.

- **MDM / gestión corporativa** — añadir detección de políticas de restricción de USB, DLP de dispositivos, bloqueo de instalación de software

- **Superficie de monitorización** — ampliar detección a herramientas de análisis de comportamiento, monitoreo de red, extensiones de navegador con acceso a contenido

- **Persistencia e infraestructura oculta** — añadir análisis de DLL hijacking, drivers sospechosos, certificados raíz no confiables, WMI persistente

- **Evaluación legal** — incorporar referencias a doctrina Barbulescu, guía de relaciones laborales de la AEPD, y casos legales relevantes

---

🔧 Pendiente — skill `diagtrack_inspector`

- Consultar qué datos concretos envía DiagTrack (endpoints destino)
- Medir frecuencia de envío via logs de eventos
- Exportar lista de endpoints de telemetría activos
- Comparar nivel configurado vs nivel real transmitido
- Extraer logs de DiagTrack de Event Viewer (canal ETW)
- Documentar últimas transmisiones: timestamp, destino, volumen
- Exportar como evidencia con hash SHA-256

🔧 Pendiente — skill `dpa_checker`

- Verificar si existe DPA con Microsoft en el registro/políticas
- Comparar nivel de telemetría con lo declarado en el DPA
- Generar evidencia de discrepancia si existe
- Verificar si el DPA empresa-Microsoft cubre el procesamiento de IA
- Comprobar si existe DPIA para experiencias conectadas
- Verificar si hay proxy activo en la red actual
- Detectar si el tráfico HTTPS está siendo descifrado (test de certificado)
- Documentar qué certificados raíz corporativos están instalados con thumbprint
- Verificar nivel de telemetría real de Office via registro
- Detectar si hay Add-ins que envían datos adicionales
- Comparar configuración actual con configuración mínima recomendada AEPD

🔧 Pendiente — skill `service_hardener`

- Intentar deshabilitar DiagTrack si no hay política que lo impida
  · Si falla (bloqueado por GPO), documentar el bloqueo como evidencia
  · Registrar intento + resultado en el informe forense con el motivo (sin permisos, bloqueado por GPO)
- Verificar si TPM está disponible para activar BitLocker
  · Si no hay permisos, generar solicitud formal documentada a IT
  · Registrar el intento y resultado como evidencia
- Para cada configuración ausente, intentar activarla automáticamente

🔧 Pendiente — skill `onedrive_mapper`

- Listar contenido de cada carpeta redirigida (solo metadatos: nombres, fechas, tamaños)
- Crear automáticamente `C:\TrabajoLocal\` fuera de OneDrive
- Generar script de migración segura para el usuario
- Documentar qué hay en nube que no debería estar
- Documentar exactamente qué carpetas están en KFM
- Calcular volumen total de datos sincronizados a Microsoft
- Detectar si hay archivos personales ya en OneDrive corporativo
- Generar evidencia de que la desactivación está bloqueada por GPO
- Calcular volumen total de datos sincronizados
- Detectar si hay archivos personales en la nube corporativa
- Generar lista de archivos en OneDrive con metadatos (no contenido)
- Verificar a qué tenant/región van los datos

🔧 Pendiente — skill `rdp_log_exporter`

- Extraer log completo de accesos RDP históricos (Event ID 4624, 4778, 4779)
- Para cada acceso: usuario, IP origen, timestamp, duración
- Detectar accesos fuera de horario laboral
- Exportar como evidencia con hash SHA-256
- Alertar si hay IPs externas que hayan accedido

🔧 Pendiente — skill `clipboard_watcher`

- Monitorizar en tiempo real qué procesos leen el portapapeles
- Registrar: proceso, PID, timestamp, frecuencia de acceso
- Ejecutar durante 5 minutos y generar informe de actividad
- Detectar si algún proceso envía datos de portapapeles a red

🔧 Pendiente — skill `addon_audit`

- Clasificar cada credencial: corporativa vs personal vs desconocida
- Detectar credenciales de servicios externos no corporativos
- Alertar si hay credenciales personales (banco, email privado) almacenadas
- Listar qué experiencias conectadas específicas están activas
- Detectar si Editor IA, PowerPoint Designer, Traducción automática están enviando datos
- Intentar desactivar experiencias no esenciales via registro si hay permisos
- Detectar si la extensión tiene acceso a `webRequest` (puede interceptar tráfico)
- Verificar si la extensión envía datos a servidores externos
- Comparar con base de datos de extensiones de monitorización conocidas
- Extraer listado completo de todas las políticas activas con su valor
- Identificar cuáles afectan a privacidad vs cuáles son de seguridad
- Detectar si hay URLBlocklist que impida acceso a sindicatos o recursos laborales
- Exportar como evidencia el volcado completo de `chrome://policy`
- Para cada extensión forzada: nombre, editor, versión, permisos completos
  · Para Teams: detectar si Compliance Recording está activo
  · Para VSCode: listar extensiones instaladas y detectar time trackers
  · Para Zoom: detectar si hay grabación automática o transcripción activa
  · Para JetBrains: detectar si hay plugins de monitorización de actividad
- Documentar configuración de privacidad de cada app
- Detectar qué tipos de datos inspecciona el DLP (emails, archivos, USB)
- Verificar si el DLP tiene acceso a contenido de documentos personales
- Detectar si hay reglas DLP que registren intentos de envío de datos
- Listar todas las extensiones de VSCode instaladas
- Clasificar: productividad, time tracking, corporativas, personales
- Detectar extensiones conocidas de monitorización (WakaTime, CodeTime, etc.)
- Verificar si hay extensiones forzadas via `settings.json` corporativo
- Verificar si las credenciales configuradas son personales o corporativas
- Detectar si hay tokens de acceso personal (PAT) almacenados
- Alertar si hay herramientas de transferencia masiva no autorizadas
- Detectar qué módulos específicos de CrowdStrike están activos
- Verificar si el módulo de Identity Protection está habilitado
- Documentar capacidades reales vs capacidades activadas

🔧 Pendiente — `account_profiler` (mejorar existente)

- Añadir historial de accesos de los últimos 30 días por cuenta
- Detectar si alguna cuenta accedió y si envia datos fuera de horario laboral
- Cruzar con logs RDP para ver si alguna entró remotamente
- Generar ficha individual exportable por cuenta sospechosa
- Para cada agente SYSTEM: listar endpoints de red a los que se conecta
- Monitorización temporal: detectar si alguna cuenta nueva aparece entre auditorías
- Cruzar con el catálogo de surveillance para evaluar capacidades reales
- Alertar si una cuenta deshabilitada se habilita entre dos auditorías
- Detectar cuándo fue creada cada cuenta (registro de creación)
- Comparar con fecha de incorporación del trabajador
- Alertar si hay cuentas creadas después del inicio de una disputa laboral
- Para cada cuenta de servicio: qué recursos de red accede
- Detectar si alguna cuenta de servicio tiene acceso a datos del usuario

🔧 Pendiente — skill `rdp_log_exporter`

- Para cada admin: ¿ha accedido remotamente alguna vez?
- Exportar historial de accesos por cuenta de admin
- Detectar accesos de admins fuera de horario laboral

🔧 Pendiente — skill `event_log_monitor`

- Extraer log de intentos de conexión USB (Event ID 2003, 2100)
- Para cada intento: dispositivo, timestamp, usuario, resultado
- Detectar si RRHH tiene acceso a estos logs
- Exportar como evidencia
- Detectar si WEF está activo y a qué servidor reenvía los logs
- Detectar si PowerShell Transcription está habilitada y dónde guarda los transcripts
- Si hay transcripts locales: contar cuántos, período que cubren
- Detectar si los transcripts incluyen actividad personal del usuario
- Intentar deshabilitar si no hay GPO que lo bloquee
- Si hay GPO: documentar que la empresa registra toda la actividad PowerShell

🔧 Pendiente

- Consolidar en el mismo hallazgo para evitar duplicidad en el informe
- Unificar hallazgos de políticas de navegador para evitar duplicidad

---
## Nuevas Skills

**Remote Access Audit**:

- Detectar LogMeIn Rescue, TeamViewer, AnyDesk, Zoho Assist
- Leer metadatos de sesiones (fechas, duración)
- Verificar si fue instalado via Intune (sin consentimiento explícito)
- Flag: sesiones en horario inusual (antes 7h, después 22h, fines de semana)

**Network Capture Audit**:

- Detectar npcap, WinPcap, RawCap
- Leer parámetros: AdminOnly, LoopbackSupport
- Verificar origen (Zscaler, Wireshark, herramienta desconocida)
- Flag: AdminOnly=0 como configuración insegura
- Leer NPFInstall.log para historial de cambios

**Scheduled Tasks Deep Audit**:

- Listar todas las tareas no-Microsoft
- Verificar si el ejecutable existe en disco
- Flag: tareas apuntando a rutas inexistentes
- Flag: tareas protegidas (acceso denegado a usuario estándar)
- Registrar timestamps de creación

**DNS & Network Forensics**:

- Volcar DNS cache completo
- Identificar dominios internos vs externos
- ARP cache — dispositivos activos en subred
- Correlacionar con procesos activos

**Filesystem Timeline**:

- Archivos creados/modificados en fechas clave
- Búsqueda en rutas no convencionales (raíz C:\, carpetas ocultas)
- Detección de carpetas con nombre sospechoso sin contenido
- ProgramData no-estándar

## Mejoras a largo plazo (pueden quedar para versión 2.0 o posteriores)

A. Profundizar en el equipo actual
   — Análisis forense de los 4 admins locales
   — Timeline de accesos con Local-Admin, Local-Ad, XGuest,  y EMEAL-IT
   — Extracción forense de logs de eventos con timestamps
   — Análisis de drivers con firma sospechosa

B. Nuevas capacidades de detección
   — Kernel callbacks y filter drivers (nivel rootkit)
   — ETW session enumeration (qué está escuchando)
   — Named pipes y comunicación entre procesos
   — Análisis de memoria de procesos sospechosos

C. Documentación pericial formal
   — Estructura de informe pericial según estándares judiciales
   — Cadena de custodia reforzada con timestamps firmados
   — Metodología defendible en juicio
   — Referencias a estándares ISO 27037 / RFC 3227

## Others Functions & Features

**Backend**:

- **Ejecutar skills específicos** — opción para ejecutar solo un skill o categoría de skills, con resultados acumulativos
- **Modo vigilancia** — monitorización en tiempo real de aspectos críticos (tareas programadas, conexiones USB, etc.) con alertas inmediatas

- **Temporización de auditorías** — programar auditorías periódicas automáticas con notificaciones de resultados
- **Comparación entre auditorías** — ver diferencias entre dos informes(ya parcialmente presente con varios informes en la barra lateral)

- **Incorporar validación de esquema** para salidas JSON.
- **Añadir ejemplos anonimizados completos** en `.docs/examples/` para demo.
- **Añadir tests automáticos** (unidad/integración) para skills y exportadores.
- **Configurar CI** para lint + validación de documentación.
- **Versión CLI** — opción para ejecutar auditorías desde línea de comandos sin interfaz gráfica

**UI**:

- **Comparación visual** existe en versión básica; aún puede mejorarse el diff por campos y la UX.
- **Vista detalle de raw_data** — expandir los datos técnicos por hallazgo + búsqueda
- **Gráfico de riesgo** — visualización tipo donut con Chart.js
- **Exportación avanzada** — opciones para incluir/excluir secciones, personalizar formato de exportación
- **Dashboard de tendencias** — mostrar tendencias a lo largo del tiempo con múltiples auditorías
- **Comparación visual** — comparar dos auditorías lado a lado con diferencias resaltadas
- **Integración con herramientas de análisis** — exportar a formatos compatibles con herramientas como Jupyter, Excel, etc.
- **Modo oscuro** — opción de tema oscuro para la interfaz
- **Notificaciones** — alertas visuales o sonoras para hallazgos críticos

**Distribución**:

- **Empaquetado** — script de instalación para distribuir a técnicos o sindicatos
- **Integración con SIEM** — exportar resultados en formato compatible para ingestión en sistemas SIEM corporativos
- **Divulgación** — crear materiales de divulgación para sindicatos y trabajadores sobre la importancia de la auditoría de seguridad interna y cómo usar la herramienta

⏳ Refactorización de skills grandes
⏳ Modo portable — PyInstaller .exe para USB

### SINDICATOS

⏳ Mejora del PDF para presentación sindical
⏳ collective_pattern_aggregator — variante local y servidor
⏳ m365_access_request_builder  — solicitud formal al DPO
⏳ policy_vs_reality_diff        — compara política declarada vs real
⏳ Script de instalación portable — para técnicos sindicales
