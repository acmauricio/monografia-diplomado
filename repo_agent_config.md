# Configuración de FIM (File Integrity Monitoring) — agente víctima

Archivo desplegado en el manager de Wazuh: `/var/ossec/etc/shared/default/agent.conf`. Se distribuye automáticamente al agente `victima` (ID 001) al reiniciar el servicio.

## Propósito

Extiende la vigilancia de integridad de archivos del módulo `syscheck` más allá de las rutas genéricas del sistema operativo, cubriendo en tiempo real el recurso compartido Samba que representa el activo crítico de la VM víctima: `/srv/samba/compartido`. Es la base técnica de las reglas 100012 y 100013 (detección de cifrado individual y masivo de archivos).

## Configuración

```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" realtime="yes">/srv/samba/compartido</directories>
  </syscheck>
</agent_config>
```

## Verificación real

Confirmado en `ossec.log` de la VM víctima tras el reinicio del agente:

```
Directory set for real time monitoring: '/srv/samba/compartido'.
Real-time file integrity monitoring started.
```

## Nota sobre la capa de hipervisor

En el host Proxmox se evaluó extender esta misma vigilancia a rutas de configuración propias del hipervisor, como `/etc/pve/qemu-server`. Esa ruta corresponde a `pmxcfs`, un sistema de archivos FUSE y no un directorio convencional, por lo que el monitoreo en tiempo real basado en `inotify` no se comporta de forma confiable sobre ella. Por esa razón, cualquier vigilancia FIM sobre esa ruta debería configurarse como escaneo programado en lugar de tiempo real, evitando que la protección falle de forma silenciosa.