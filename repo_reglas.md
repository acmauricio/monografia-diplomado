# Reglas de correlación personalizadas (Wazuh)

Archivo desplegado en el manager: `/var/ossec/etc/rules/local_rules.xml`. Cinco reglas, cubriendo las tres capas de la infraestructura: red (MikroTik), sistema operativo (agente víctima), y visibilidad nativa en el hipervisor (agente pve, sin regla dedicada).

| ID | Capa | Condición | Descripción | MITRE |
|---|---|---|---|---|
| 100015 | Red (MikroTik, vía syslog en el manager) | Tráfico TCP con bandera SYN hacia el puerto 22 de la Red Víctima, origen en 198.51.100.0/24 | Detecta el inicio de una conexión desde la Red Atacante hacia el servicio SSH expuesto | T1078 |
| 100011 | Sistema operativo (agente víctima) | Acceso SSH desde una IP fuera de 203.0.113.0/24 | Detecta un origen ajeno a la Red Víctima | T1078 |
| 100010 | Sistema operativo (agente víctima) | 3 accesos SSH desde la misma IP externa en 120 segundos, correlacionando sobre la regla 100011 | Detecta un posible ataque de fuerza bruta | T1110 |
| 100012 | Sistema operativo (agente víctima, FIM) | Archivo con extensión `.locked` detectado por FIM | Detecta un archivo individual cifrado, posible ransomware en curso | T1486 |
| 100013 | Sistema operativo (agente víctima, FIM) | 5 o más archivos `.locked` en 60 segundos, correlacionando sobre la regla 100012 | Detecta cifrado masivo, activa la decisión de contener | T1486 |

## Notas técnicas relevantes

**Regla 100010 (fuerza bruta):** originalmente contaba fallos de autenticación consecutivos mediante una regla intermedia propia. Se rediseñó para correlacionar directamente sobre la 100011, después de confirmar con `wazuh-logtest` y con `alerts.log` real que Wazuh no genera una alerta independiente para una regla de menor nivel cuando otra regla de mayor nivel coincide con el mismo evento. El alcance de la regla pasó de "3 fallos" a "3 accesos externos" (exitosos o fallidos), documentado como limitación en el capítulo de resultados.

**Regla 100015 (capa de red):** requiere el decoder personalizado `mikrotik` (ver `local_decoders.xml`). Su condición `decoded_as` apunta a `mikrotik`, no a `mikrotik-firewall`, porque en Wazuh un decoder hijo hereda por defecto el nombre de su decoder padre.

## Contenido completo

```xml
<!-- Local rules -->
<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<group name="local,syslog,sshd,">

  <!-- Regla 2: alerta cuando el origen SSH no pertenece a la Red Víctima -->
  <rule id="100011" level="12">
    <if_sid>5700</if_sid>
    <srcip negate="yes">203.0.113.0/24</srcip>
    <description>Acceso SSH desde una IP fuera de la Red Víctima (origen simulado extranjero, Red Atacante 198.51.100.0/24).</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>

  <!-- Regla 1: alerta al tercer intento de acceso SSH desde la misma IP externa en poco tiempo -->
  <rule id="100010" level="10" frequency="3" timeframe="120">
    <if_matched_sid>100011</if_matched_sid>
    <same_source_ip />
    <description>Múltiples intentos de acceso SSH desde la misma IP externa en 120 segundos (posible fuerza bruta).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>

</group>

<group name="local,syscheck,ransomware,">

  <!-- Regla 3: detecta un archivo cifrado por el script de simulación (extensión .locked) -->
  <rule id="100012" level="12">
    <if_group>syscheck</if_group>
    <field name="file" type="pcre2">\.locked$</field>
    <description>Posible actividad de ransomware: archivo cifrado detectado en $(file).</description>
    <mitre>
      <id>T1486</id>
    </mitre>
    <group>ransomware,</group>
  </rule>

  <!-- Regla 4: cifrado masivo, varios archivos .locked en poco tiempo -->
  <rule id="100013" level="15" frequency="5" timeframe="60">
    <if_matched_sid>100012</if_matched_sid>
    <description>Cifrado masivo de archivos detectado: 5 o más archivos cifrados en 60 segundos, compatible con un ataque de ransomware en curso.</description>
    <mitre>
      <id>T1486</id>
    </mitre>
    <group>ransomware,</group>
  </rule>

</group>

<group name="local,firewall,mikrotik,">

  <!-- Regla 5: tráfico de red desde la Red Atacante hacia el puerto SSH de la Red Víctima (capa de red) -->
  <rule id="100015" level="7">
    <decoded_as>mikrotik</decoded_as>
    <srcip>198.51.100.0/24</srcip>
    <dstport>22</dstport>
    <match>SYN</match>
    <description>Tráfico de red hacia el puerto SSH de la Red Víctima originado en la Red Atacante (correlación en capa de red, MikroTik).</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>network_scan,</group>
  </rule>

</group>
```
