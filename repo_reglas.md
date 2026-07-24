# Evidencia de la fase de preservación

Generada el 24/07/2026, tras confirmar la contención del incidente simulado (VM víctima suspendida, tráfico de la Red Atacante bloqueado en el MikroTik). Ambos artefactos se generaron **desde el host Proxmox, fuera de la VM comprometida**, siguiendo el orden de volatilidad del RFC 3227 y evitando instalar cualquier herramienta dentro del sistema bajo investigación.

## 1. Hash del disco de la VM víctima

Calculado directamente sobre el volumen LVM-thin que respalda el disco de la VM (`vm-100-disk-0`), sin montarlo ni copiarlo:

```bash
sha256sum /dev/pve/vm-100-disk-0
```

```
f89c3c6effcc79f01a59e20b06f917521d92f52ca2115d31e90c7165ea8db50a  /dev/pve/vm-100-disk-0
```

Este hash funciona como ancla de integridad: cualquier análisis posterior sobre una copia de este disco puede verificarse contra este valor para confirmar que no fue alterado desde el momento de la contención.

## 2. Snapshot forense (disco + estado de memoria)

Tomado con la VM ya suspendida, incluyendo el volcado completo de RAM mediante el mecanismo nativo de QEMU/Proxmox (`--vmstate 1`):

```bash
qm snapshot 100 incidente_20260724 --vmstate 1 --description "Snapshot forense post-incidente, VM suspendida tras contencion"
```

Resultado real:

```
saving VM state and RAM using storage 'local-lvm'
completed saving the VM state in 10s, saved 1.78 GiB
snapshotting 'drive-scsi0' (local-lvm:vm-100-disk-0)
  Logical volume "snap_vm-100-disk-0_incidente_20260724" created.
```

Listado del snapshot:

```
`-> incidente_20260724          2026-07-24 15:59:05     Snapshot forense post-incidente, VM suspendida tras contencion
 `-> current
```

## Interpretación

El snapshot preserva 1.78 GiB de memoria RAM y el estado del disco en el momento exacto de la contención, sin requerir LiME, FTK Imager ni ninguna otra herramienta instalada dentro de la VM comprometida. Esto satisface el control A.5.28 (recopilación de evidencias) del Anexo A de la ISO/IEC 27001:2022 usando únicamente las capacidades nativas del hipervisor.