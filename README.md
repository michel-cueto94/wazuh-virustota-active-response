
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

Salida del comando sudo docker exec -it single-node-wazuh.manager-1 grep -iE "integrat|virustotal" /var/ossec/logs/ossec.log, donde se observe la línea Remote integrations not configured. Clean exit.

La causa se ubicó en el archivo docker-compose.yml, que monta config/wazuh_cluster/wazuh_manager.conf sobre el ossec.conf del contenedor en cada arranque, sobrescribiendo los cambios realizados en el volumen. La corrección consistió en modificar el archivo de origen del montaje. Tras reiniciar el contenedor, el registro confirmó la habilitación de la integración.

CAPTURA 2 (la solución): terminal con el comando grep -n -A6 "<integration>" mostrando el bloque cargado en el ossec.conf del contenedor (con la clave de API oculta) y, a continuación, las líneas wazuh-integratord: INFO: Started y Enabling integration for: 'virustotal'.
<img width="1058" height="566" alt="Captura de pantalla 2026-10-12 192033" src="https://github.com/user-attachments/assets/a47acd67-ce3b-4bfa-bc9d-31a4be1786a2" />

4.2 Verificación de conectividad

Desde el contenedor se verificó la salida a internet mediante una consulta con curl hacia VirusTotal, obteniéndose una respuesta HTTP/2 405. Dicho código no representa una falla: indica que la conexión se estableció correctamente y que el servidor rechazó únicamente el método HEAD utilizado por la opción -I.

Comando sudo docker exec -it single-node-wazuh.manager-1 curl -sI https://www.virustotal.com | head -1 con la respuesta HTTP/2 405.

<img width="1590" height="645" alt="Captura de pantalla 2026-10-12 192421" src="https://github.com/user-attachments/assets/9fe105b4-4bc3-4237-a5cc-90030edda05b" />


4.3 Monitoreo de integridad de archivos en tiempo real

Se conectó el agente Windows al manager y se configuró el monitoreo de la carpeta Downloads:

xml
<directories realtime="yes" check_all="yes">C:\Users\Administrador\Downloads</directories>

La opción realtime="yes" permite detectar los cambios de forma inmediata, sin esperar al escaneo periódico. Previamente, las únicas alertas disponibles correspondían al propio manager, por lo que la integración no se activaba: esta responde exclusivamente a alertas de FIM.

CAPTURA 4: salida de agent_control -l con el agente windowser en estado Active.

Archivo ossec.conf del agente Windows con el bloque <syscheck> y la línea <directories realtime="yes" ...> visibles.

<img width="729" height="61" alt="Captura de pantalla 2026-10-12 184157" src="https://github.com/user-attachments/assets/2ff5b0b7-88a0-491b-9740-19a3850adb36" />


4.4 Pruebas de la integración

Archivo de texto sin antecedentes. La creación de un archivo de texto genérico generó la alerta 87103 (No records in VirusTotal database). Es el resultado esperado, dado que el hash del archivo nunca fue registrado en VirusTotal.

CAPTURA 6: alerta del dashboard con rule.id: 87103 y data.virustotal.source.file correspondiente a prueba1.txt.

Archivo EICAR. Su creación generó la alerta 87105, de nivel 12, con 63 de 67 motores de detección, asociada a la técnica T1203 de MITRE ATT&CK. Para esta prueba se excluyó la carpeta del análisis de Windows Defender, dado que de otro modo el antivirus eliminaba el archivo antes de su procesamiento por Wazuh. Esta exclusión solo es admisible en un entorno de laboratorio.

CAPTURA 7: alerta rule.id: 87105 expandida, con data.virustotal.positives: 63, data.virustotal.total: 67, data.virustotal.source.file (eicar) y la técnica MITRE T1203.



<img width="1122" height="309" alt="Captura de pantalla 2026-10-12 202504" src="https://github.com/user-attachments/assets/26cf0c85-e5f2-49e6-869e-6504976df1fa" />

CAPTURA 8: alerta rule.id: 554 (File added to the system) del mismo archivo, como primer eslabón de la cadena.

<img width="1142" height="264" alt="Captura de pantalla 2026-10-12 202526" src="https://github.com/user-attachments/assets/79f9bd4f-db11-48f5-9aac-ae52afaf003c" />


La secuencia verificada fue: detección por syscheck (alerta 554), consulta a VirusTotal y generación de la alerta 87105.

4.5 Respuesta activa (Active Response)

En el manager se definieron un <command> y un <active-response> asociados a la regla 87105, con location en local, de modo que el script se ejecute en el agente que originó la alerta. Se seleccionó la regla 87105 y no la 87103 para evitar la eliminación de archivos que VirusTotal simplemente no conoce.



En esta etapa se presentaron dos inconvenientes:

Bloques fuera de </ossec_config>. La configuración se había ubicado después de la etiqueta de cierre y no era cargada. Se reubicó dentro del bloque principal y se validó la sintaxis con xmllint --noout.

Ejecutable inexistente en el agente. Las alertas 554 y 87105 se generaban, pero el archivo no se eliminaba. El ossec.log del agente registraba Active response command not present: 'active-response/bin/remove-threat.exe'. El agente instalado no incluía dicho ejecutable: la carpeta contenía únicamente netsh.exe, restart-wazuh.exe y route-null.exe.



Como solución se desarrolló un script propio, compuesto por dos archivos:

remove-threat.cmd: invoca a PowerShell.
remove-threat.ps1: lee por entrada estándar el JSON de la alerta, obtiene la ruta del campo data.virustotal.source.file, elimina el archivo y registra el resultado en active-responses.log.



Posteriormente se actualizó el campo <executable> del manager a remove-threat.cmd, se reiniciaron el contenedor y el agente, y se repitió la prueba con un nuevo archivo EICAR. El archivo fue eliminado a los pocos segundos y el registro del agente lo confirmó.



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
Índice de capturas
N°	Contenido	Sección
1	Remote integrations not configured en el log	4.1
2	Bloque <integration> cargado y Enabling integration for: 'virustotal' (clave oculta)	4.1
3	curl con HTTP/2 405	4.2
4	agent_control -l con windowser activo	4.3
5	<syscheck> con realtime="yes" en el agente	4.3
6	Alerta 87103 (prueba1.txt)	4.4
7	Alerta 87105 (63/67, T1203)	4.4
8	Alerta 554 del mismo archivo	4.4
9	<command> y <active-response> cargados en el contenedor	4.5
10	not present: remove-threat.exe y carpeta bin sin el ejecutable	4.5
11	Carpeta bin con .cmd y .ps1	4.5
12	Test-Path en False y registro Successfully removed threat	4.5

Antes de publicar las capturas, conviene ocultar la clave de API (capturas 2 y 9) y las direcciones IP o nombres de equipo que no deban exponerse. La clave de VirusTotal debe regenerarse, ya que quedó visible en varias ocasiones durante el laboratorio.
