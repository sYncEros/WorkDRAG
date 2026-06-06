# TODO

## Skills & Knowledge Areas

- **Scheduled Tasks Deep Audit** — análisis profundo de tareas programadas: quién las creó, cuándo, qué ejecutan, si tienen firmas válidas

- **USB & Peripheral Audit** — dispositivos conectados históricamente, políticas de bloqueo de USB, DLP de dispositivos

- **Email Client Audit** — Outlook con add-ins corporativos, reglas de reenvío automático, acceso de terceros al buzón

- **Third Party Apps Audit** — apps instaladas con telemetría propia: Slack, Zoom, Teams, VSCode, con sus endpoints y permisos

- **User Behavior Analysis** — patrones de uso inusuales, como horas de actividad, acceso a recursos sensibles, uso de herramientas de administración

- **Data Exfiltration Detection** — monitoreo de tráfico saliente, uso de herramientas de transferencia de archivos, análisis de logs de red

- **Persistence Mechanisms** — análisis de mecanismos de persistencia comunes: Run keys, servicios, WMI, tareas programadas, DLL hijacking

- **Incident Response Playbook** — desarrollo de un playbook específico para incidentes de insider

### Mejora de skills existentes

- **MDM / gestión corporativa** — añadir detección de políticas de restricción de USB, DLP de dispositivos, bloqueo de instalación de software

- **Superficie de monitorización** — ampliar detección a herramientas de análisis de comportamiento, monitoreo de red, extensiones de navegador con acceso a contenido

- **Persistencia e infraestructura oculta** — añadir análisis de DLL hijacking, drivers sospechosos, certificados raíz no confiables, WMI persistente

- **Evaluación legal** — incorporar referencias a doctrina Barbulescu, guía de relaciones laborales de la AEPD, y casos legales relevantes

## Others Functions & Features

**Backend**:

- **Ejecutar skills específicos** — opción para ejecutar solo un skill o categoría de skills, con resultados acumulativos

- **Modo vigilancia** — monitorización en tiempo real de aspectos críticos (tareas programadas, conexiones USB, etc.) con alertas inmediatas

- **Temporización de auditorías** — programar auditorías periódicas automáticas con notificaciones de resultados

- **Comparación entre auditorías** — ver diferencias entre dos informes(ya parcialmente presente con varios informes en la barra lateral)

- **Incorporar validación de esquema** para salidas JSON.
- **Añadir ejemplos anonimizados completos**
 en `.docs/examples/` para demo.
- **Añadir tests automáticos** (unidad/integración) para skills y exportadores.
- **Configurar CI** para lint + validación de documentación.
- **Versión CLI** — opción para ejecutar auditorías desde línea de comandos sin interfaz gráfica

**UI**:

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
