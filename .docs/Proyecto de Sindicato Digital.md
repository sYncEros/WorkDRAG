# Proyecto de Sindicato Digital

## Contexto

En el entorno laboral actual, la digitalización ha traído consigo nuevas formas de vigilancia y control por parte de las empresas. Desde la monitorización de actividades en línea hasta la inspección de archivos personales, los trabajadores se enfrentan a desafíos inéditos en cuanto a su privacidad y derechos digitales. En este contexto, surge la necesidad de un “sindicato digital” que defienda los intereses de los trabajadores en el ámbito tecnológico. Para ello, es fundamental contar con herramientas y habilidades que permitan a los trabajadores recopilar evidencias, analizar políticas corporativas y negociar condiciones laborales en el entorno digital.

## Arquitectura

Se propone una arquitectura modular basada en diferentes “modos” de operación, cada uno orientado a un público y objetivo específico:

- **Modo trabajador**: lectura local, lenguaje claro, semáforo, “qué significa / qué no significa”, acciones prudentes.

- **Modo sindicato**: informes anonimizados, agregación colectiva, gráficos de patrón, exportación para comité.

- **Modo jurídico/pericial**: evidencias, hashes, timeline, anexos técnicos, trazabilidad, versiones de schema.

- **Modo negociación**: cláusulas, preguntas al DPO, propuestas de minimización, exigencias de transparencia.

El corazón sería un rights_graph, cada hallazgo apunta a:

- datos afectados,
- capacidad técnica,
- posible base legal,
- pregunta al DPO,
- evidencia necesaria,
- riesgo colectivo,
- medida sindical negociable.

## Prioridades

Primero haría estas cuatro, porque dan poder rápido y reducen riesgo:

- redactor_sindical
- evidence_packager
- collective_pattern_aggregator
- m365_access_request_builder

Después ya vienen las skills de bisturí:

- remote_access_timeline,
- onedrive_kfm_deep_dive,
- browser_policy_loupe,
- dlp_scope_mapper.

Y la regla de oro, grabada en piedra y con purpurina jurídica: *no romper nada, no ocultar nada, no desactivar nada, no tocar logs*.

La liamos, sí, pero con acta, hash, registro de entrada y cara de *“solo estoy ejerciendo derechos”*.

## Skills para el Sindicato Digital

Lo bonito aquí no es *“hackear la máquina”*, es construir una imprenta sindical de evidencias:

- local,
- verificable,
- legible para currantes,
- DPOs,
- comité,
- ITSS
- AEPD.

Nada de tocar MDM, nada de apagar EDR, nada de robar credenciales, nada de borrar logs. El propio informe va por esa línea: auditoría defensiva, sin interceptar tráfico, sin escalar privilegios y sin exfiltrar datos; además recalca que detecta capacidades técnicas, no prueba automáticamente uso indebido.

 🧷 La estrategia ganadora es convertir *“me están mirando raro el portátil”* en:
*"aquí está el hallazgo,*
 *aquí el impacto,*
 *aquí la base legal que pido que me expliquen,*
 *aquí el hash*
 *y aquí el plazo”*.

### 1. evidence_packager

La skill reina. Coge PDF, JSON, capturas, netstat, inventario de software y estado de políticas, y genera un paquete probatorio con manifiesto, SHA-256, fecha, hora, versión de la herramienta y checklist de cadena de custodia.

Tu informe ya incluye checklist de preservación y avisa que la evidencia digital tiene valor si se preserva correctamente; también recomienda no borrar ni modificar archivos porque pueden ser evidencia.

Salida ideal: dossier.zip, manifest.json, timeline.md, hashes.txt, readme_para_abogado.md.

### 2. redactor_sindical

Antes de compartir nada con sindicato o comité, esta skill limpia nombres de usuario, emails, hostnames, IPs internas, rutas personales, tokens, IDs de tenant y datos de clientes.

Es clave porque el propio informe contiene nombres de usuario, rutas locales, cuentas, servicios y credenciales referenciadas. Compartir el JSON “en bruto” sería como ir a una mani con el DNI grapado en la frente

Salida ideal: informe anonimizado con tres niveles: público, sindicato, abogado/perito.

### 3. collective_pattern_aggregator

La más sindical de todas. Permite que 20, 50 o 200 personas suban informes anonimizados y genera estadísticas colectivas:

“83% tiene OneDrive/KFM forzado”, “61% tiene RDP habilitado”, “72% tiene certificados de inspección SSL”, “40% no tiene BitLocker”, “X% tiene DLP inspeccionando transferencias”.

Esto transforma casos individuales en patrón organizativo. Mucho más difícil de despachar como “incidencia aislada”.

### 4. policy_vs_reality_diff

La skill cuchillo-de-mantequilla: no pincha sistemas, pero corta excusas.

Compara lo que dice la política corporativa, contrato, onboarding, AUP, DPIA o aviso de privacidad contra lo que aparece realmente en el equipo. Ejemplo:

“Política dice: no se accede a contenido personal.”
“Realidad técnica: carpetas Escritorio/Documentos/Capturas redirigidas a OneDrive corporativo y KFM forzado.”

El informe ya marca como rojo la redirección de 7 carpetas del sistema a OneDrive/SharePoint y señala que KFMBlockOptOut impide desactivar la sincronización de Escritorio y Documentos.

### 5. onedrive_kfm_deep_dive

Una lupa específica para OneDrive, SharePoint y Known Folder Move.

Debe sacar:

qué carpetas están redirigidas, qué política lo fuerza, si el usuario puede desactivarlo, qué rutas afectan a capturas, escritorio, documentos e imágenes, y qué tipo de datos personales o sindicales podrían acabar sincronizados.

Esto es oro, porque tu informe dice que todo archivo guardado en esas carpetas se sincroniza automáticamente y puede incluir documentos personales, capturas y comunicaciones privadas.

### 6. remote_access_timeline

P habilitado”. Hay que saber cuándo, quién, cómo y si hubo aviso.

Esta skill debería analizar eventos de inicio de sesión, sesiones RDP, servicios remotos, herramientas tipo Quick Assist/RMM, conexiones activas, grupos “Remote Desktop Users” y cuentas locales con privilegios.

Tu informe detecta RDP habilitado y explica que un administrador podría ver o controlar el escritorio; también marca Credential Manager con 44 credenciales almacenadas.

Salida ideal: línea temporal de accesos remotos, con “capacidad”, “evidencia de uso” y “lagunas por falta de permisos”.

### 7. privileged_accounts_explainer

Skill para traducir el jeroglífico de cuentas locales, SIDs raros y grupos administrativos a lenguaje humano.

Debe responder:

quién tiene admin local, quién tiene acceso remoto, cuándo inició sesión, si la cuenta está habilitada, si parece cuenta de soporte, si está documentada y qué pregunta exacta hay que hacer al DPO/IT.

En tu caso, el informe detecta administradores locales, acceso remoto y cuentas como EMEAL-IT, Local-Admin y SIDs no resueltos; también dice que el trabajador tiene derecho a saber qué cuentas tienen acceso administrativo y con qué finalidad.

### 8. browser_policy_loupe

Chrome, Edge y Firefox son la aduana del alma digital. Esta skill revisaría:

Tu informe ya marca extensiones forzadas y avisa que pueden tener acceso a contenido de páginas, formularios, historial, cookies y contraseñas introducidas.

### 9. tls_inspection_truth_meter

No intercepta tráfico. Solo comprueba si al visitar dominios de prueba aparece una cadena de certificados corporativa o pública, y genera explicación sencilla:

El informe detecta certificados raíz de inspección SSL/TLS y certificados no estándar, indicando capacidad técnica para descifrar tráfico HTTPS, aunque no prueba lectura activa.

La gracia: diferenciar capacidad técnica, política declarada y uso observado.

### 10. dlp_scope_mapper

DLP no es malo por existir. Lo feo es no saber si mira nombres de archivo, contenido, emails, USB, nubes personales, capturas, portapapeles o tráfico cifrado.

Esta skill mapearía productos, procesos, drivers, add-ins, integraciones Office, políticas USB, Zscaler/Purview/AIP y explicaría qué puede inspeccionarse y qué pedir por escrito.

Tu informe detecta DLP corporativo instalado y dice que puede inspeccionar contenido de archivos, bloquear transferencias, registrar intentos, inspeccionar tráfico cifrado y enviar alertas.

### 11. m365_access_request_builder

Generador de solicitud de acceso al DPO, pero quirúrgico. No “quiero mis datos” en genérico, sino:

“Solicito logs de acceso a mis archivos de OneDrive/SharePoint, eventos de eDiscovery, auditoría de Teams, accesos administrativos, sesiones remotas, alertas DLP, logs Zscaler, registros Purview, reglas de retención, políticas aplicadas a mi usuario y grupos que me afectan.”

La AEPD explica que el derecho de acceso permite saber si se tratan tus datos y obtener copia, fines, categorías, destinatarios, plazos de conservación, información sobre decisiones automatizadas y garantías en transferencias internacionales.

### 12. deadline_watchdog

Un mini gestor de plazos. Registras: “envié solicitud al DPO el día X”, y te calcula recordatorios, vencimientos, prórrogas y siguiente acción.

La AEPD indica que el responsable debe responder al ejercicio de derechos en un mes, prorrogable dos meses si es necesario por complejidad o número de solicitudes.

Esto para sindicato es precioso: convierte derechos en calendario. Un calendario muerde más que un cabreo.

### 13. dpiA_need_scorer

Evalúa si el conjunto de tratamientos parece requerir evaluación de impacto: monitorización sistemática, logs centralizados, comportamiento del trabajador, DLP, inspección HTTPS, decisiones automatizadas, productividad, comunicaciones.

Tu informe ya relaciona la centralización de logs y análisis de comportamiento con posible DPIA bajo RGPD art. 35.

Salida ideal: “Solicitar DPIA o, si alegan confidencialidad, al menos resumen ejecutivo, riesgos evaluados, medidas de mitigación y consulta a representantes”.

### 14. comite_info_request_generator

Genera escritos para comité de empresa/delegados sindicales. No solo DPO. El enfoque sindical pide:

sistemas de control existentes, finalidad, métricas utilizadas, destinatarios, acceso por RRHH, conservación, subencargados, criterios disciplinarios, participación de representantes y medidas de minimización.

El Estatuto de los Trabajadores reconoce el derecho a la intimidad en el uso de dispositivos digitales puestos a disposición por el empleador, junto con desconexión digital e intimidad frente a videovigilancia y geolocalización.

### 15. negotiation_clause_generator

Esta es de trinchera elegante. Redacta cláusulas para convenio, acuerdo de empresa o política interna:

notificación previa de acceso remoto salvo urgencia documentada, prohibición de revisar contenido personal salvo procedimiento garantista, logs consultables por el trabajador, minimización de telemetría, retención limitada, transparencia DLP, exclusión de carpetas sindicales/personales, información previa sobre inspección TLS, auditorías periódicas con representantes.

La LOPDGDD recoge el derecho a la intimidad en el uso de dispositivos digitales en el ámbito laboral y exige criterios de uso e información a trabajadores y representantes.

### 16. hardening_accountability_dashboard

La vuelta de tuerca: no solo “la empresa vigila”, sino “encima no protege”.

Dashboard colectivo de BitLocker, Secure Boot, Firewall, Defender, auditoría, ransomware protection, exploit protection, cifrado, logs, RDP encryption.

Tu informe marca configuraciones de seguridad ausentes como riesgo rojo, incluyendo BitLocker, Secure Boot, Firewall, Defender en tiempo real, auditoría y otras protecciones.

Esto pega fuerte porque no es una queja abstracta de privacidad: es riesgo real para datos de trabajadores, clientes y empresa.

### 17. credential_safety_checker

Importante: no extrae contraseñas. Solo enumera referencias seguras y avisa de exposición potencial.

Detecta credenciales personales/corporativas en Credential Manager, Git, VS Code, Azure CLI, navegadores, SSH config, tokens de dev tools y clientes. Marca “cambiar desde dispositivo personal” cuando proceda.

Tu informe detecta 44 credenciales almacenadas y advierte que un proceso con privilegios de administrador podría extraerlas usando herramientas estándar.

### 18. developer_privacy_audit

Para perfiles técnicos: VS Code, extensiones, Git, GitHub, Azure DevOps, Bitbucket, tokens, Live Share, Copilot/Codex/IA, telemetría, terminal, historial, repos clonados, credenciales.

No para acusar al trabajador. Para saber qué parte del trabajo de desarrollo puede estar siendo observada, sincronizada o enviada a terceros.

El informe ya detecta extensiones de VSCode y señala que estas pueden leer archivos, ejecutar comandos y comunicarse con servidores externos, aunque en ese caso no marca indicadores de telemetría sospechosa.

### 19. outlook_teams_compliance_mapper

Outlook y Teams son la sala de reuniones, el pasillo y media cabeza del trabajador.

Skill para revisar add-ins, reglas, archivado, retención, etiquetas Purview, grabaciones, transcripciones, eDiscovery, Communication Compliance, buzones compartidos, permisos delegados y exportabilidad de chats.

Tu informe dice que los add-ins de Outlook tienen acceso a emails, contactos, calendarios y adjuntos, aunque en el análisis concreto no encontró indicadores de monitorización en esos add-ins.

### 20. complaint_packet_builder

No presenta denuncias automáticamente. Construye un paquete:

relato de hechos, tabla de hallazgos, evidencias, anexos, preguntas previas al DPO, derechos ejercidos, falta de respuesta, impacto, peticiones concretas, y versión para AEPD/ITSS/comité/abogado.

La AEPD indica que, si hay pruebas o indicios de vulneración del derecho a la protección de datos, se puede presentar reclamación a través de su sede electrónica.
