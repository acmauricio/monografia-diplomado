# Configuración del MikroTik (RouterOS 6.49.10)

Router: RB941-2nD · Red Víctima: `203.0.113.0/24` (ether2) · Red Atacante: `198.51.100.0/24` (ether3)

## 1. Reenvío de logs hacia el manager de Wazuh

El manager de Wazuh (`203.0.113.20`) recibe los logs del MikroTik vía syslog remoto. La acción de reenvío se define una sola vez y se referencia desde varias reglas de logging:

```
/system logging action
add bsd-syslog=yes name=wazuhremote remote=203.0.113.20 target=remote
```

**Nota técnica:** la configuración inicial agrupaba varios `topics` separados por coma en una sola regla (`topics=firewall,critical,error,warning,info`). RouterOS interpreta esa lista como una condición que exige la presencia simultánea de todos los topics en un mismo evento, no de cualquiera de ellos. Como ningún evento real combina todos esos topics a la vez, la regla quedaba inerte pese a estar aparentemente bien configurada. La solución fue declarar una regla independiente por cada topic, todas apuntando a la misma acción `wazuhremote`:

```
/system logging
add action=wazuhremote topics=firewall
add action=wazuhremote topics=critical
add action=wazuhremote topics=error
add action=wazuhremote topics=warning
add action=wazuhremote topics=info
```

## 2. Registro de tráfico SSH desde la Red Atacante (capa de red)

Esta regla no bloquea nada (acción `log`); únicamente genera el evento que el decoder `mikrotik` y la regla 100015 de Wazuh correlacionan como capa de red del protocolo.

```
/ip firewall filter
add action=log chain=forward dst-address=203.0.113.0/24 dst-port=22 log-prefix=ATAQUE-SSH protocol=tcp src-address=198.51.100.0/24
```

## 3. Regla de contención (bloqueo de la Red Atacante)

Se activa manualmente como respuesta a una alerta confirmada (ver Tabla 10 y Tabla 11 del Capítulo 4). Se mantiene `disabled=yes` por defecto: no debe operar de forma permanente, solo como respuesta puntual ante un incidente detectado.

```
/ip firewall filter
add action=drop chain=forward disabled=yes dst-address=203.0.113.0/24 src-address=198.51.100.0/24
```

**Lección operativa:** al activarse, esta regla bloquea todo el tráfico entre ambas redes, incluyendo el acceso administrativo del propio analista si su conexión pasa por la misma ruta (Red Atacante → Red Víctima). Este laboratorio no cuenta con una red de gestión fuera de banda (out-of-band), por lo que la contención total deja momentáneamente sin acceso de gestión al propio Proxmox. Se documenta como una limitación de diseño a considerar en un despliegue real.

## 4. Exports completos verificados en el equipo

<details>
<summary>/system logging export</summary>

```
# jul/24/2026 16:01:28 by RouterOS 6.49.10
# software id = CXZF-AGVW
#
# model = RB941-2nD
# serial number = HFB09073BP5
/system logging action
add bsd-syslog=yes name=wazuhremote remote=203.0.113.20 target=remote
/system logging
add action=wazuhremote topics=firewall
add action=wazuhremote topics=critical
add action=wazuhremote topics=error
add action=wazuhremote topics=warning
add action=wazuhremote topics=info
```

</details>

<details>
<summary>/ip firewall filter export</summary>

```
# jul/24/2026 16:01:34 by RouterOS 6.49.10
# software id = CXZF-AGVW
#
# model = RB941-2nD
# serial number = HFB09073BP5
/ip firewall filter
add action=drop chain=forward disabled=yes dst-address=203.0.113.0/24 src-address=198.51.100.0/24
add action=log chain=forward dst-address=203.0.113.0/24 dst-port=22 log-prefix=ATAQUE-SSH protocol=tcp src-address=198.51.100.0/24
```

</details>