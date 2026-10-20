Integración de Wazuh con VirusTotal y respuesta activa automatizada
1. Introducción

El presente documento describe la implementación de un flujo de detección, enriquecimiento y respuesta ante amenazas en un entorno de laboratorio, utilizando Wazuh como plataforma SIEM/XDR. El esquema contempla el monitoreo de integridad de archivos (FIM) en un servidor Windows, la consulta automática de la reputación de cada archivo mediante la API de VirusTotal y la eliminación automática de aquellos clasificados como maliciosos.

2. Objetivo

Automatizar el ciclo completo de detección, enriquecimiento con inteligencia de amenazas (CTI) y respuesta, reproduciendo a escala reducida un procedimiento habitual en un centro de operaciones de seguridad (SOC).

3. Entorno
Componente	Detalle
Wazuh Manager	Despliegue oficial single-node en Docker, sobre Kali Linux
Endpoint	Windows Server con agente Wazuh
Inteligencia de amenazas	API de VirusTotal (cuenta gratuita)
Archivo de prueba	EICAR, archivo estándar de prueba para antivirus, no dañino
4. Desarrollo
4.1 Configuración de la integración con VirusTotal

En el manager se incorporó un bloque <integration> con el nombre virustotal, la clave de API y el grupo syscheck. De este modo, cada alerta generada por el monitoreo de integridad de archivos provoca una consulta del hash correspondiente en VirusTotal.

Durante esta etapa se identificó un inconveniente: las modificaciones realizadas sobre el archivo ossec.conf dentro del volumen de Docker se perdían al reiniciar el contenedor, y el registro del manager indicaba Remote integrations not configured.

La causa se ubicó en el archivo docker-compose.yml, que monta config/wazuh_cluster/wazuh_manager.conf sobre el ossec.conf del contenedor en cada arranque, sobrescribiendo los cambios realizados en el volumen. La corrección consistió en modificar el archivo de origen del montaje. Tras reiniciar el contenedor, el registro confirmó la habilitación de la integración.

<img width="940" height="202" alt="Captura de pantalla 2026-10-19 211010" src="https://github.com/user-attachments/assets/2f8a2d52-5e0e-4cba-bb33-c800e837a23b" />


4.2 Verificación de conectividad

Desde el contenedor se verificó la salida a internet mediante una consulta con curl hacia VirusTotal, obteniéndose una respuesta HTTP/2 405. Dicho código no representa una falla: indica que la conexión se estableció correctamente y que el servidor rechazó únicamente el método HEAD utilizado por la opción -I.


<img width="724" height="359" alt="Captura de pantalla 2026-10-20 004539" src="https://github.com/user-attachments/assets/32d4fe94-4b42-4144-85a0-68704d4da80d" />


4.3 Monitoreo de integridad de archivos en tiempo real

Se conectó el agente Windows al manager y se configuró el monitoreo de la carpeta Downloads:


 <syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
  <directories realtime="yes" check_all="yes">C:\Users\Administrador\Downloads</directories>
</syscheck>

La opción realtime="yes" permite detectar los cambios de forma inmediata, sin esperar al escaneo periódico. Previamente, las únicas alertas disponibles correspondían al propio manager, por lo que la integración no se activaba: esta responde exclusivamente a alertas de FIM.


<img width="797" height="207" alt="Captura de pantalla 2026-10-12 184730" src="https://github.com/user-attachments/assets/bf333e89-f792-4f92-9fc3-b04dfa10ac59" />




4.4 Pruebas de la integración

La creación de un archivo de texto genérico generó la alerta 87103 (No records in VirusTotal database), resultado esperado dado que su hash nunca fue registrado en VirusTotal.

La creación del archivo EICAR generó la alerta 87105, de nivel 12, con 63 de 67 motores de detección, asociada a la técnica T1203 de MITRE ATT&CK. Para esta prueba se excluyó la carpeta del análisis de Windows Defender, dado que de otro modo el antivirus eliminaba el archivo antes de su procesamiento por Wazuh. Esta exclusión solo es admisible en un entorno de laboratorio.

La secuencia verificada fue: detección por syscheck (alerta 554), consulta a VirusTotal y generación de la alerta 87105.


<img width="1142" height="264" alt="Captura de pantalla 2026-10-12 202526" src="https://github.com/user-attachments/assets/e51abbae-2185-4042-84c2-6fa3c4675abc" />



4.5 Respuesta activa (Active Response)

En el manager se definieron un comando y una respuesta activa asociados a la regla 87105, con location en local, de modo que el script se ejecute en el agente que originó la alerta. Se seleccionó la regla 87105 y no la 87103 para evitar la eliminación de archivos que VirusTotal simplemente no conoce.


<command>
  <name>remove-threat</name>
  <executable>remove-threat.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>


<img width="1012" height="297" alt="Captura de pantalla 2026-10-19 210747" src="https://github.com/user-attachments/assets/6fc280db-f4ea-497f-a4ed-94a027c88738" />



En esta etapa se presentaron dos inconvenientes:

Bloques fuera de </ossec_config>. La configuración se había ubicado después de la etiqueta de cierre y no era cargada. Se reubicó dentro del bloque principal y se validó la sintaxis con xmllint --noout.
Ejecutable inexistente en el agente. Las alertas 554 y 87105 se generaban, pero el archivo no se eliminaba. El ossec.log del agente registraba Active response command not present: 'active-response/bin/remove-threat.exe'. El agente instalado no incluía dicho ejecutable: la carpeta contenía únicamente netsh.exe, restart-wazuh.exe y route-null.exe.

Como solución se desarrolló un script propio, compuesto por dos archivos ubicados en C:\Program Files (x86)\ossec-agent\active-response\bin\:

remove-threat.cmd, que invoca a PowerShell:

bat
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0remove-threat.ps1"

remove-threat.ps1, que lee por entrada estándar el JSON de la alerta, obtiene la ruta del campo data.virustotal.source.file, elimina el archivo y registra el resultado en active-responses.log:

powershell
$logfile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$inputJson = [Console]::In.ReadLine() | ConvertFrom-Json
$file = $inputJson.parameters.alert.data.virustotal.source.file

function Log($msg) {
  Add-Content -Path $logfile -Value "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') remove-threat: $msg"
}

if ($file -and (Test-Path -LiteralPath $file)) {
  try {
    Remove-Item -LiteralPath $file -Force -ErrorAction Stop
    Log "Successfully removed threat: $file"
  } catch {
    Log "Error removing threat: $file - $($_.Exception.Message)"
  }
} else {
  Log "File already removed or not found: $file"
}

Posteriormente se actualizó el campo <executable> del manager a remove-threat.cmd, se reiniciaron el contenedor y el agente, y se repitió la prueba con un nuevo archivo EICAR. El archivo fue eliminado a los pocos segundos.


<img width="957" height="86" alt="Captura de pantalla 2026-10-19 210711" src="https://github.com/user-attachments/assets/370446e6-22d6-4a28-941a-55dc0fe76e5a" />




El registro también evidenció una segunda ejecución con el mensaje de archivo no encontrado. No constituye un error: la regla puede activarse más de una vez para un mismo archivo; la primera ejecución lo elimina y la segunda ya no lo localiza.

5. Resultado

Se logró un flujo completamente automatizado: la aparición de un archivo en la carpeta monitoreada es detectada en tiempo real, su hash es evaluado por VirusTotal y, si resulta clasificado como malicioso, el agente lo elimina sin intervención manual.

6. Limitaciones
Eliminación sin cuarentena. Un falso positivo de VirusTotal implicaría la pérdida de un archivo legítimo. En un entorno productivo corresponde aplicar un umbral mínimo de detecciones o mover el archivo a cuarentena.
Cobertura reducida. Solo se monitorea la carpeta Downloads.
Consulta por hash. El malware nuevo o modificado devuelve resultados sin registros.
Cuota de la API gratuita. Se limita a 4 consultas por minuto.
Confirmación en el dashboard. La eliminación se comprueba en el registro del agente, pero no se configuró una alerta propia en el dashboard que la confirme.
7. Conclusiones
Se comprendió el comportamiento de Wazuh sobre Docker con montajes de archivos, y la razón por la cual las modificaciones directas en el volumen no persisten.
El diagnóstico requirió el análisis de los registros en ambos extremos: manager y agente.
Se diferenciaron los resultados de reputación desconocida (87103) y maliciosa (87105).
La ausencia del ejecutable remove-threat.exe resultó de asumir su existencia sin verificarlo previamente en el agente.
Se evidenciaron los riesgos de automatizar respuestas destructivas sin umbrales ni cuarentena.
8. Mejoras propuestas
Mover los archivos a cuarentena en lugar de eliminarlos.
Exigir un mínimo de detecciones antes de ejecutar la respuesta.
Incorporar una regla propia que registre la eliminación como alerta en el dashboard.
Incorporar Sysmon para detectar también ejecuciones, además de la creación de archivos.
