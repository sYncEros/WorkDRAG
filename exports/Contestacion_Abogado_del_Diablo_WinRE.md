# Contestación técnica al informe de refutación sobre WinRE y CSIRT

*Informe para revisión del letrado de Móstoles — conocido en estas actuaciones como «el cabrero»— y del equipo de defensa.*

## 1. Objeto

Este documento valora críticamente los argumentos incorporados al repositorio sobre:

- la actividad de `WinREAgent` y el posible rollback o limpieza del sistema;
- la alerta del CSIRT y los comandos atribuidos a la trabajadora;
- las instrucciones de borrado posteriores;
- la correlación temporal entre la respuesta de la trabajadora y los cambios observados en el equipo.

Su finalidad no es descartar la tesis de la trabajadora, sino formularla de manera técnicamente defendible y difícil de desmontar.

## 2. Conclusión principal

La actividad de `WinREAgent` no permite afirmar, por sí sola, que la empresa ejecutara un rollback para destruir pruebas. Windows Update puede utilizar el entorno de recuperación, preparar imágenes WIM y ejecutar operaciones de mantenimiento o limpieza.

Sin embargo, esa explicación genérica tampoco resuelve automáticamente el caso. Si se acredita que las operaciones ocurrieron inmediatamente después de la respuesta al CSIRT, dentro de una ventana en la que hubo acceso o control remoto, pérdida de archivos y órdenes expresas de limpieza, el conjunto puede constituir un indicio técnico relevante que exige explicación documental de la empresa.

La formulación correcta no es «el XML demuestra el sabotaje», sino:

> La proximidad temporal entre la respuesta de la trabajadora, la intervención observada, las instrucciones de eliminación y las operaciones posteriores del sistema constituye un conjunto de indicios técnicos concordantes que no queda explicado por la mera invocación abstracta de Windows Update.

## 3. El símil de la pistola limpiada

El razonamiento puede expresarse así:

Encontrar una pistola limpia no demuestra quién disparó. Pero si existe una amenaza previa, una presencia en el lugar, un disparo, una limpieza inmediatamente posterior y desaparición de residuos relevantes, la explicación de «era una limpieza rutinaria» deja de bastar por sí sola.

Aplicado al caso, la actividad de WinRE es compatible con mantenimiento ordinario, pero su significado cambia si coincide de forma precisa con:

1. la comunicación del CSIRT;
2. el vencimiento del plazo concedido;
3. la respuesta de la trabajadora;
4. una conexión remota o intervención efectiva;
5. la desaparición o alteración de archivos concretos;
6. instrucciones expresas para eliminar temporales, historial, cachés o archivos descargados.

La fuerza del argumento depende de probar esa cronología con horas, archivos y registros originales, no solo mediante conclusiones redactadas después.

## 4. La alerta del CSIRT

La comunicación indica que CrowdStrike bloqueó una ejecución por argumentos considerados maliciosos mediante análisis de comportamiento con confianza media. Una alerta de «medium confidence» acredita una detección preventiva, no demuestra por sí misma malware, daño, intención delictiva ni acceso no autorizado.

Tres de los comandos atribuidos tienen una función diagnóstica clara:

```text
tasklist /svc | findstr /i zsa
Get-Process *zsa*
Get-Service *zsa*
```

Los tres consultan procesos y servicios relacionados con Zscaler. No borran archivos, no detienen servicios, no modifican políticas y no establecen persistencia.

Además, el repositorio contiene auditorías anteriores a la alerta que ya examinaban Zscaler, CrowdStrike, certificados corporativos, servicios y drivers. Este dato respalda que existía una finalidad técnica previa y no una explicación creada únicamente después del conflicto.

## 5. El comando `certutil`

La captura recoge de forma incompleta:

```text
certutil.exe -urlcache -split -f https...
```

Este comando puede recuperar un recurso desde una URL, por lo que no debe calificarse automáticamente como inocuo. Pero tampoco puede calificarse como malicioso sin conocer, al menos:

- URL completa;
- archivo de destino;
- hash del archivo;
- proceso padre;
- usuario y nivel de privilegios;
- código de salida;
- eventual ejecución posterior;
- conexión o daño producido.

Si el propio informe del CSIRT corta la URL, la empresa deberá aportar la telemetría original y completa. Una captura resumida no sustituye al registro íntegro del EDR.

## 6. Las instrucciones de borrado

La petición de borrar archivos, limpiar DNS, vaciar `%temp%` y restablecer cookies o historial puede formar parte de una remediación de seguridad. Por tanto, no demuestra automáticamente destrucción dolosa de pruebas.

Pero plantea una cuestión probatoria decisiva:

> ¿Qué evidencia preservó el CSIRT antes de ordenar su eliminación?

Si la empresa basa posteriormente un despido disciplinario en esos mismos hechos, debe conservar y poder aportar:

- alerta original del EDR;
- árbol completo de procesos;
- línea de comandos sin truncar;
- archivo o artefacto detectado;
- hashes;
- telemetría de red;
- usuario, host y timestamps;
- medidas de contención ejecutadas;
- cadena de custodia.

Ordenar la limpieza sin preservar previamente esos elementos debilitaría la reconstrucción empresarial de los hechos y justificaría solicitar su exhibición.

## 7. Qué demuestra realmente el log de Zscaler

Los registros disponibles acreditan que Zscaler estaba instalado y activo, recibía políticas, establecía túneles, aplicaba cambios de proxy, realizaba comprobaciones de postura, mantenía protección contra manipulaciones e instalaba certificados en Firefox.

Eso ofrece un contexto técnico sólido para justificar por qué la trabajadora buscaba procesos y servicios `zsa`.

No obstante:

- un servidor RPC local no demuestra por sí mismo que hubiera un operador humano conectado;
- un evento `BROADCAST_PROXY_CHANGE` no identifica por sí solo una orden manual;
- la instalación de un certificado acredita capacidad de inspección, no lectura efectiva de comunicaciones concretas;
- una diferencia de zona horaria no identifica automáticamente la ubicación de un administrador remoto.

Estos elementos son contexto o indicios y deben correlacionarse con registros independientes.

## 8. Problema de fechas que debe corregirse

El log de Zscaler citado en el repositorio está fechado el 29 de mayo de 2026. Por tanto, sus operaciones de rotación o limpieza interna no pueden presentarse como realizadas el 19 de junio sin aportar un registro distinto de esa fecha.

El mensaje `logCleanUp` parece compatible con la rotación ordinaria de archivos al alcanzar un tamaño máximo. Sirve para demostrar el funcionamiento del agente, pero no prueba por sí solo una limpieza coordinada con WinRE semanas después.

Mantener ambas fechas como si fueran simultáneas permitiría a la empresa desacreditar el resto de la correlación. Deben separarse claramente:

- 29 de mayo: actividad documentada de Zscaler;
- 15–19 de junio: incidente CSIRT, respuesta y supuesta intervención;
- fecha y hora exactas de WinRE: deben extraerse de metadatos o registros originales.

## 9. WinRE y la carga explicativa de la empresa

Los archivos de WinRE muestran operaciones reales: preparación y copia de imágenes, sesión programada, backup, `CleanupScratch` y operaciones pendientes. Su origen puede ser una actualización del sistema.

El argumento defensivo gana fuerza si se acredita:

- que no existía una actualización normal programada o instalada en esa ventana;
- que la operación fue iniciada mediante gestión corporativa;
- que hubo una sesión administrativa o remota coincidente;
- que desaparecieron archivos individualizados justo después;
- que los archivos desaparecidos eran relevantes para responder al CSIRT;
- que la empresa conserva los logs administrativos que permitirían identificar al iniciador.

Por ello, deben solicitarse registros de MDM, SCCM/Intune o herramienta equivalente, EDR, soporte remoto, Windows Update, reinicios, tareas programadas y cambios de políticas.

## 10. Formulación recomendada para la defensa

Debe evitarse la expresión «prueba estadística irrefutable», ya que no se aporta un análisis estadístico verificable. También debe evitarse afirmar que se ha identificado ya a una persona concreta como autora del borrado.

La formulación propuesta es:

> Existen indicios técnicos y temporales concordantes de que, después de la respuesta de la trabajadora al CSIRT, el dispositivo experimentó actuaciones administrativas, operaciones de limpieza y pérdida de información potencialmente relevante. Aunque algunos mecanismos empleados pueden formar parte del mantenimiento ordinario de Windows y de las herramientas de seguridad corporativas, su proximidad temporal con el incidente y las instrucciones de eliminación justifican requerir a la empresa la aportación íntegra de los registros de EDR, MDM, soporte remoto, Windows Update y cadena de custodia, a fin de determinar el origen, autoría, finalidad y alcance de las operaciones realizadas.

## 11. Pruebas prioritarias que faltan

Para convertir el indicio en una conclusión pericial más fuerte deben reunirse:

1. Hora exacta de la respuesta al CSIRT.
2. Fecha y hora completas de la captura `[Remote computer connected]`.
3. Aplicación que mostró ese mensaje y significado técnico documentado.
4. Registro de sesiones remotas o herramienta de soporte.
5. Timestamps originales de los archivos de WinRE.
6. Eventos de Windows Update correspondientes a esa ventana.
7. Lista de archivos existentes antes y ausentes después.
8. Hashes o copias anteriores de los archivos desaparecidos.
9. Telemetría original de CrowdStrike, no solo la captura de Teams.
10. Política y protocolo interno de respuesta a incidentes aplicado.

## 12. Dictamen final del abogado del diablo

La respuesta del «cabrero» mejora correctamente la tesis al abandonar la idea de que un archivo aislado sea prueba absoluta y centrarse en la correlación temporal y circunstancial.

La defensa técnica contra la acusación de comandos maliciosos es sólida respecto de `tasklist`, `Get-Process` y `Get-Service`. La acusación basada en `certutil` necesita la línea completa y sus resultados. Las instrucciones de borrado son relevantes y obligan a preguntar qué preservó la empresa antes de ordenar la limpieza.

Respecto de WinRE, existe un indicio que merece investigación, pero todavía no una atribución técnica concluyente. La explicación de «Windows Update rutinario» es posible; lo que no es aceptable es utilizarla como respuesta automática sin reconstruir la cronología completa.

En términos cabreros: la pistola puede limpiarse todos los domingos, pero si aparece recién limpia al lado del cadáver, alguien tendrá que enseñar el calendario, las huellas y el registro de entrada.