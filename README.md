# Protocolo forense de contención y análisis post-incidente ante ransomware (ISO/IEC 27001:2022 + Wazuh)

Repositorio de soporte técnico del trabajo de grado del Diplomado en Ciberseguridad (1ra versión), Universidad Mayor de San Simón, Facultad de Ciencias y Tecnología:

**"Diseño de un protocolo forense de contención y análisis post-incidente ante ransomware bajo el estándar ISO/IEC 27001:2022: Correlación de eventos mediante Wazuh en infraestructura virtualizada."**

Autor: Mauricio Alba Claros

## Objetivo del proyecto

Diseñar y validar, sobre un laboratorio real de infraestructura virtualizada, un protocolo forense de tres fases (contención, preservación de evidencia y análisis post-incidente) que correlaciona eventos de seguridad mediante Wazuh en tres capas: hipervisor, sistema operativo y red. El protocolo se ancla en los controles de gestión de incidentes del Anexo A de la ISO/IEC 27001:2022 (A.5.24–A.5.28), en el orden de volatilidad del RFC 3227, y en los lineamientos de cadena de custodia de la ISO/IEC 27037.

## Arquitectura del laboratorio

Un host Proxmox aloja dos VMs: un stack completo de Wazuh (manager, indexer, dashboard) y un servidor de archivos víctima con un recurso Samba compartido. Un router MikroTik segmenta una Red Víctima (`203.0.113.0/24`, rango de documentación RFC 5737) de una Red Atacante (`198.51.100.0/24`), simulando un origen externo. Tres agentes/mecanismos alimentan la correlación en Wazuh: el agente en la VM víctima (sistema operativo), el agente en el host Proxmox (hipervisor), y el reenvío syslog del MikroTik (red).

## Resultados de la validación

La simulación controlada del incidente, ejecutada el 24/07/2026, confirmó las tres dimensiones exigidas por el protocolo con datos reales, sin resultados forzados ni fabricados:

- **Detección temprana:** las 5 reglas de correlación dispararon en la secuencia esperada (tráfico de red, acceso SSH externo, fuerza bruta, cifrado individual y cifrado masivo), reconstruida en una línea de tiempo completa de menos de un minuto y medio.
- **Contención:** suspensión real de la VM comprometida desde Proxmox y bloqueo efectivo del tráfico entre redes en el MikroTik, confirmado con un intento de conexión SSH real rechazado.
- **Preservación:** hash SHA-256 del disco calculado desde el hipervisor y snapshot con 1.78 GiB de estado de memoria, ambos sin instalar herramientas forenses dentro de la VM comprometida.

Detalles completos en `docs/evidencia.md` y en el capítulo IV del documento de tesis.

## Licencia y alcance

Este repositorio se comparte con fines académicos, como evidencia técnica del trabajo de grado. Las direcciones IP utilizadas pertenecen al rango de documentación reservado por la IANA (RFC 5737) y no corresponden a infraestructura real de ninguna organización.
