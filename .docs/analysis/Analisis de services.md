# Analisis de services.txt

Perfecto 👌 — vamos a por rendimiento + privacidad sin comprometer la estabilidad.
Te lo explico en dos bloques: primero lo que significa tu archivo y los tipos de servicios, luego la lista práctica para optimizar.

## 🧩 1️⃣ Qué estás viendo en services.txt

Ese archivo muestra todos los servicios de Windows, activos y desactivados.
Cada uno es un “programita” que se ejecuta en segundo plano y hace algo del sistema o de una aplicación.

Los grupos básicos son:

| Tipo de servicio | Ejemplos | ¿Necesario? | Comentario |
|-----------------|----------|-------------|------------|
| 🧠 Sistema básico | Windows Audio, WinDefend, Plug and Play, RpcSs | ✅ Imprescindibles | No tocar, mantienen el SO vivo |
| 🌐 Red y conectividad | Dhcp, WlanSvc, NlaSvc, Dnscache | ✅ Necesarios si usas Wi-Fi o Ethernet | Mantener en automático |
| 💻 Experiencia / interfaz | Themes, ShellHWDetection, SysMain, TabletInputService | ⚙️ Opcional | Se pueden poner en manual si no los usas |
| 🧱 Telemetría y diagnósticos | DiagTrack, dmwappushservice, Connected User Experiences, RetailDemo, MapsBroker | ❌ Puedes desactivarlos | Mandan datos de uso a Microsoft |
| 📦 Actualizaciones y Store | wuauserv, BITS, DoSvc, InstallService, ClipSVC | ⚠️ Mantener activo para actualizaciones, pero se puede poner en manual (trigger) | 
| 🎮 Multimedia / dispositivos | Bluetooth Support, CameraFrameServer, Xbox Services, Print Spooler | ⚙️ Opcional | Solo activos si usas esos periféricos |
| 🧰 Fabricante (Lenovo, NVIDIA, AMD) | LenovoVantage, NvDisplay.ContainerLocalSystem, AMD Crash Defender | ⚙️ Opcional | Si no usas sus apps, se pueden desactivar |

## 🧹 2️⃣ Lista práctica: lo que puedes desactivar o poner en manual

Estos servicios no afectan al arranque ni a la estabilidad si los pones en “Inicio manual” o deshabilitados:

| Servicio   | Estado recomendado | Motivo   |
| ---------- | ------------------ | -------- |
| DiagTrack (Connected User Experiences) | Deshabilitado | Telemetría |
| dmwappushservice | Deshabilitado | Envío de datos de diagnóstico |
| RetailDemo | Deshabilitado | Modo demo de tiendas |
| MapsBroker | Manual | Solo sirve para apps de mapas |
| SysMain (antes Superfetch) | Manual | Puede consumir disco, acelera poco con SSD |
| Fax | Deshabilitado | Obsoleto |
| Print Spooler | Manual | Solo si no imprimes |
| Windows Search | Manual | Ahorra CPU si no usas buscador interno |
| Windows Error Reporting Service | Manual | Solo útil para depuración |
| Xbox Accessory Management Service | Deshabilitado | Solo para mandos Xbox |
| Xbox Live Auth Manager, Xbox Live Game Save, Xbox NetAPI | Deshabilitado | Xbox |
| OneSyncSvc, Contact Data, MessagingService | Deshabilitado | Sincronización de apps de contacto |
| Remote Registry | Deshabilitado | Riesgo de seguridad si no administras remotamente |
| Downloaded Maps Manager | Manual | Solo útil para mapas offline |
| Geolocation Service | Manual | Ubicación, puedes apagarlo |
| Windows Insider Service | Deshabilitado | Solo si no estás en programa Insider |
| Parental Controls, Phone Service | Deshabilitado | No necesarios |
| NVIDIA Telemetry Container | Deshabilitado | No afecta a drivers, solo reporta datos |

## 🧰 3️⃣ Cómo aplicarlo sin romper nada

*Pulsa Win + R*, escribe *services.msc → Enter*
*Doble clic* en el servicio *→ pestaña Tipo de inicio*
Elige *Manual o Deshabilitado* según la tabla
*Acepta y reinicia*

## 💡 Consejo

Haz primero los Manual, observa 1-2 días que todo funcione, y luego pasa algunos a Deshabilitado si no notas efectos. Así evitas sorpresas y mantienes el control.

## 🧠 4️⃣ Extra: los que deben quedarse siempre activos

| Servicio  | Motivo   |
| --------- | -------- |
| RpcSs (Remote Procedure Call) | Base del sistema |
| WinDefend | Defender |
| Plug and Play | Reconoce hardware |
| Dhcp, WlanSvc, Dnscache, NlaSvc | Conectividad |
| CryptSvc, EventLog, Security Center, Windows Update | Seguridad e integridad |
| AudioSrv, AudioEndpointBuilder | Sonido |
| TimeBrokerSvc | Sincronización de tareas y apps |
| ShellHWDetection, UserManager | Detección de dispositivos y cuentas |
| Power | Gestión de energía |
| SENS | Notificaciones de eventos del sistema |