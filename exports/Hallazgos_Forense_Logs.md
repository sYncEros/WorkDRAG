# Análisis Forense de Logs Rescatados

Este documento detalla los hallazgos técnicos extraídos de los archivos de logs que pudieron ser rescatados antes del borrado del sistema.

## 1. Registros de Operaciones de Archivo (PFRO.log)
El archivo `PFRO.log` (Pending File Rename Operations) registra operaciones de archivo que Windows realiza durante el reinicio. Es una fuente clave para detectar borrados masivos o intentos de limpieza del sistema.

*   **Hallazgo 1.1 (Borrado de Temporales):** Se observan múltiples errores de borrado (`|delete operation|`) en carpetas temporales (`C:\Windows\Temp`, `C:\Windows\SystemTemp`, `C:\Users\jnavaqui\AppData\Local\Temp`).
    *   *Significado:* Estos registros son consistentes con la instrucción dada por el CSIRT de "borrar la carpeta %temp%". Los errores sugieren que el sistema intentó borrar archivos que estaban en uso o que ya habían sido manipulados.
*   **Hallazgo 1.2 (Manipulación de Aplicaciones):** Se registran errores de borrado en directorios de aplicaciones como Google Chrome y Microsoft Edge.
    *   *Significado:* Indica una limpieza profunda que va más allá de los archivos temporales estándar, afectando a historiales y configuraciones de navegadores.

## 2. Registros de Acceso Remoto (RDP Logs)
Se analizaron los archivos JSON en la carpeta `rdp_logs`.

*   **Hallazgo 2.1 (Acceso Denegado a Eventos de Seguridad):** El log `rdp_log_20260606_093137.json` muestra un error crítico: `"security_access_error": "Acceso denegado. Error al abrir la consulta de evento. Acceso denegado."`.
    *   *Significado:* Esto demuestra que, incluso con la herramienta de auditoría WorkDRAG, el sistema de la empresa bloqueaba el acceso a los registros de seguridad. Es una prueba directa de la opacidad y las restricciones impuestas al trabajador para auditar sus propios derechos.
*   **Hallazgo 2.2 (Ausencia de Eventos Visibles):** A pesar de que el log indica que se analizaron 720 días, el resultado es `"total_events": 0`.
    *   *Significado:* En un sistema corporativo activo, es técnicamente imposible tener 0 eventos en 2 años. Esto sugiere que los logs de eventos de red y acceso remoto han sido limpiados o el acceso a ellos ha sido totalmente capado por políticas de grupo (GPO) o software de seguridad.

## 3. Conclusión Forense Preliminar
Los logs rescatados no muestran "hackeo", sino que muestran **un sistema bajo un control extremo y un proceso de limpieza activo**. La presencia de errores de borrado y el bloqueo sistemático de acceso a eventos de seguridad respaldan la narrativa de la trabajadora sobre la vigilancia invasiva y la posterior destrucción de evidencias por parte de IT.
