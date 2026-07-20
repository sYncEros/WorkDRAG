# Hallazgos adicionales de capturas (.img.rar)

## Resumen provisional
Se han analizado varias capturas nuevas que aportan indicios complementarios sobre redirección de archivos, actividad de sesiones locales, conexiones internas persistentes y configuración de componentes del sistema.

| Evidencia | Hallazgo observado | Posible significado |
|---|---|---|
| `Evidence - CarpetasOneDrive.png` | En OneDrive aparecen archivos personales y sensibles como `DNI`, `Movimientos de Tarjeta`, anexos y carpetas de trabajo, visibles en el entorno sincronizado. | Refuerza la hipótesis de **redirección/sincronización corporativa de carpetas** con exposición de documentación personal dentro del ecosistema sincronizado. |
| `Historial - Apps.png` | En el historial de aplicaciones figuran `msrdc.exe`, `wslhost.exe`, `dllhost.exe`, además de una ventana WSL con configuración automática y una IP visible terminada en `10.255.255.254`. | Sugiere uso de **WSL**, presencia de componentes de acceso remoto (`msrdc.exe`) y configuración de red/proxy o pasarela interna gestionada. |
| `netstat y tasklist.png` | Se observan múltiples conexiones `ESTABLISHED` entre `127.0.0.1` y el host `NTTD-90G6TV3` en distintos puertos altos. | Indica **múltiples conexiones locales persistentes** asociadas al propio host/equipo, compatibles con túneles locales, agentes, proxys locales o servicios corporativos residentes. |
| `DCOM - Aplicaciones.jpg` | Se muestran aplicaciones COM+/DCOM del sistema, con activación local y roles ligados a sistema local/usuario interactivo. | No prueba por sí sola una intrusión, pero sí documenta la existencia de **componentes de automatización/ejecución distribuida** que conviene conservar como contexto técnico. |
| `Driver - CoreChip.png` | Se registra un dispositivo `CoreChip USB CD-ROM USB Device`, configurado e iniciado el `31/05/2026 22:26:14`. | Aporta rastro de **dispositivo USB virtual o físico tipo CD-ROM**; puede ser inocuo, pero también merece conservarse por si se correlaciona con instalaciones, montaje de imágenes o utilidades externas. |

## Observación metodológica
Estos hallazgos deben tratarse como **indicios técnicos contextualizadores**, no como prueba concluyente aislada. Su valor aumenta al cruzarlos con los logs ya rescatados, las capturas de conexión remota, los cambios de proxy en WSL y la evidencia de rollback programado en WinREAgent.

## Próximo paso sugerido
Continuar con el análisis del resto de capturas del paquete y, después, incorporar únicamente los hallazgos más sólidos al sumario principal y al repositorio.


| Evidencia | Hallazgo observado | Posible significado |
|---|---|---|
| `netstat y tasklist (fullScreen).png` | En el escritorio se ve un archivo abierto: `Diagnostic.log`. En la barra de tareas, múltiples iconos de apps de comunicación y desarrollo. | Confirma que la trabajadora estaba realizando **labores de diagnóstico activo** y documentando hallazgos (`Diagnostic.log`) en el momento de la captura. |
| `WSL - Instalaciones.png` | En el menú de inicio aparecen "Recomendaciones" con apps agregadas recientemente: `Sourceforge DI Deac-ams`, `Sweet Home 3D`, `Boom 3D`, `Openbank Clientes`. También un aviso de **BitLocker** pidiendo desbloquear la unidad F:. | Indica actividad reciente de instalación de software y la existencia de una **unidad cifrada con BitLocker (F:)** bloqueada, lo que añade una capa de seguridad/privacidad gestionada por el usuario o el sistema. |
| `Audit.png` | Se muestra un PDF (`audit_resumen.pdf`) con hallazgos de riesgo muy alto: vigilancia específica de empleados, add-ins de Outlook con acceso total, carpetas en la nube corporativa, descifrado de tráfico HTTPS. | Es la **prueba del resultado de la auditoría WorkDRAG**. El documento advierte explícitamente sobre la capacidad de la empresa para interceptar tráfico HTTPS y acceder a datos privados. |

## Conclusión de este bloque
La captura `Audit.png` es fundamental, ya que muestra el **contenido exacto del informe de auditoría** que la trabajadora menciona haber compartido. Los hallazgos descritos en ese PDF justifican plenamente la necesidad de la auditoría desde una perspectiva de derechos digitales y privacidad.
