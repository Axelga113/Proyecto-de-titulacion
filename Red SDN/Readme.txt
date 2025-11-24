############################################################################
#############       Mitigación de ataques DDoS en Redes SDN      #############
############################################################################


===============================
 Requisitos previos y dependencias
===============================

Dependencias principales  
*Se adjuntan los comandos de instalación de cada dependencia.*


-----------------------------------------
 Mininet (≥ 2.3.0)
-----------------------------------------

Instalación oficial:

git clone https://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -a


-----------------------------------------
 Open vSwitch (OVS)
-----------------------------------------

sudo apt install openvswitch-switch openvswitch-testcontroller


-----------------------------------------
 Controlador SDN: Ryu
-----------------------------------------

Instalación desde repositorios:

sudo apt install python3-ryu

Instalación desde GitHub:

git clone https://github.com/faucetsdn/ryu
cd ryu
sudo pip3 install . --break-system-packages

Para iniciarlo:

ryu-manager --ofp-tcp-listen-port 6653 ryu.app.simple_switch_13

*Ryu debe ejecutarse en una terminal distinta de donde se ejecuta Mininet.*


-----------------------------------------
 Utilidades del sistema
-----------------------------------------

sudo apt install python3-pip iperf iperf3 net-tools psmisc iptables

*psmisc es necesario para killall.*


-----------------------------------------
 Paquetes Python requeridos
-----------------------------------------

sudo pip3 install numpy


-----------------------------------------
 Instalación de Python
-----------------------------------------

Python 3:

sudo apt update
sudo apt install -y python3 python3-pip python3-venv

Python 2 (solo si fuese estrictamente necesario):

sudo apt update
sudo apt install -y python2

Instalar pip para Python 2:

curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py


-----------------------------------------
 Verificación de dependencias
-----------------------------------------

mn --version  
ovs-vsctl --version  
ryu-manager --version  
iperf --version  
python3 --version  
pip3 --version  

Opcional:

python2 --version  
pip2 --version  


-----------------------------------------
 Documentación oficial
-----------------------------------------

https://github.com/mininet/mininet/wiki/Documentation  
https://ryu.readthedocs.io




############################################################################
#              Experimento DDoS en Red SDN (Mininet)
############################################################################

##### Nota: Documento continuación del experimento en Red Convencional.
#####       Se omiten explicaciones ya cubiertas previamente.



==================================
 1. Descripción general del proyecto
==================================

Este repositorio contiene un experimento completo que demuestra cómo una red SDN puede detectar,
controlar y mitigar ataques DDoS mediante decisiones dinámicas implementadas desde el plano
de control.

A diferencia del experimento de red convencional, aquí se integra:

- Controlador remoto Ryu (plano de control centralizado)
- Switches OVSKernelSwitch (compatible con OpenFlow 1.3)
- Múltiples técnicas de mitigación aplicadas automáticamente:
  * Umbral (Threshold)
  * Límite de tasa (Rate Limiting con meters OpenFlow)
  * BAN temporal de IPs atacantes
- Manejo dinámico de whitelist para separar tráfico legítimo/atacante

El entorno es completamente reproducible y permite estudiar escenarios realistas de ataque/defensa.



==================================
 2. Finalidad del proyecto
==================================

El experimento ejecuta varias fases:

- NORMAL – sin ataque  
- SIN_MITIGACIÓN – ataque sin defensas  
- SOLO_UMBRAL – defensa por bloqueo de flujos  
- SOLO_LIMITE_TASA – defensa mediante meter OpenFlow  
- SOLO_BAN – bloqueo total temporal  
- TODAS_LAS_MITIGACIONES – combinación de técnicas activas según banderas



==================================
 3. Tecnologías clave
==================================

- OVSKernelSwitch (Open vSwitch modo kernel)
- OpenFlow 1.3
- Meters para rate limiting
- Reglas drop de alta prioridad
- Controlador Ryu remoto autodetectado (puertos 6653/6633)
- Whitelist dinámica

Cada fase prepara:

- Flujos iniciales
- Fail-mode secure/standalone
- Tablas ARP precargadas
- Verificación TCP/UDP



==================================
 4. Detección del ataque
==================================

Detector híbrido basado en:

- 3 timeouts consecutivos  
- o latencia ≥ 500 ms  

Además:

- Pre-chequeo inicial de 3 pings
- Registro de causa exacta:
  * PROCESOS_ATAQUE_CAIDOS
  * PING_FALLIDOS
  * IPERF_ACTIVO
  * CRITERIO_BAN_PRECHEQUEO



==================================
 5. Archivos generados
==================================

En “resultados_ddos_sdn/”:

- ping.txt — resultados de latencias por fase  
- ataque.txt — whitelist + IPs atacantes  
- ataque_log.txt — log detallado  
- resumen_fases.txt — estadísticas (prom, mediana, p95, min, max)



############################################################################
##############     ÍNICIO DE LA EXPLICACIÓN DEL CÓDIGO     ################
############################################################################


==================================
 1. Logging seguro y uso de locks
==================================

Uso de locks para evitar condiciones de carrera:

_BLOQUEOS_HOST   = defaultdict(threading.Lock)  
_BLOQUEOS_SWITCH = defaultdict(threading.Lock)

def comando_host(h, cmd): ...
def comando_switch(sw, cmd): ...

Registros con timestamps usando:

- escribir_log()
- sobrescribir_archivos_log()

Documentación:
https://realpython.com/intro-to-python-threading/
https://docs.python.org/3/library/threading.html



==================================
 2. Detección de ataque: iperf + pings malos
==================================

Un ping se considera “malo” si:

- timeout  
- o >= 500 ms  

Funciones:

- ataque_sigue_activo(...)
- hilo_monitor_ping(...)
- detectar_ataque(...)
- prechequeo_fase(...)

El hilo de ping incrementa un contador de fallos consecutivos y
activa eventos cuando se supera el umbral.



==================================
 3. Whitelist e identificación de atacantes
==================================

Funciones:

- construir_whitelist(...)
- recopilar_ips_atacantes(...)

Incluye:

- IP del host cliente
- IPs de servidores
- Todo lo demás se marca como atacante

Se agrupan por cluster (útil para mitigaciones segmentadas).



==================================
 4. Mitigación UMBRAL (Threshold)
==================================

Objetivo: 
Reducir el impacto del ataque bloqueando por completo a los hosts de un
cluster específico una vez que se detecta degradación severa
(timeouts/latencias muy altas) hacia el servidor.

En el script esta mitigación se aplica , solo al cluster 4
(`ID_CLUSTER_UMBRAL = 4`), sobre su switch hoja `sLeaf4`.  
Cuando se activa, se instalan reglas OpenFlow de mayor prioridad
(`PRIO_UMBRAL = 310`) que descartan todo el tráfico TCP/UDP desde las IPs
atacantes de ese cluster hacia el servidor objetivo.

Ejemplo de regla que se genera:

    ovs-ofctl -O OpenFlow13 add-flow sLeaf4 \
      "priority=310,tcp,nw_src=<IP_ATACANTE>,nw_dst=<IP_SERVIDOR>,actions=drop"

    ovs-ofctl -O OpenFlow13 add-flow sLeaf4 \
      "priority=310,udp,nw_src=<IP_ATACANTE>,nw_dst=<IP_SERVIDOR>,actions=drop"

**Cuándo se activa en el experimento**

- El script realiza pings periódicos desde `host_pinger` al servidor.
- Cada ping se clasifica como:
  - “malo” si:
    - hay `timeout`, o
    - la latencia ≥ `UMBRAL_LATENCIA_BAN_MS` (por defecto 500 ms),
  - “bueno” en caso contrario.
- Si se observan al menos `UMBRAL_TIMEOUTS_PING_CONSECUTIVOS` pings malos
  consecutivos (por defecto 3), se considera que el ataque ya está
  afectando fuertemente la calidad de servicio y se disparan las mitigaciones.

En el caso de SOLO_UMBRAL, una vez que se cumple el criterio anterior,
el script llama a:

    aplicar_mitigacion_umbral(red, ips_cluster4, ip_servidor)

bloqueando todo el tráfico de los hosts del cluster 4 hacia el servidor.

Efecto esperado

- Antes de activar la mitigación: latencias crecientes y/o timeouts altos.
- Después de activar UMBRAL: latencias vuelven a valores cercanos a la fase
  NORMAL, a costa de **sacrificar por completo a los hosts del cluster 4**
  (no pueden seguir accediendo al servidor).
- Es una mitigación **reactiva y muy agresiva**: cuando se decide actuar,
  se corta de raíz el tráfico sospechoso.

En la fase `TODAS_LAS_MITIGACIONES`, UMBRAL se combina con las otras técnicas
para observar el efecto de aplicar múltiples defensas simultáneamente.

Documentación (ejemplos de reglas drop y flows OpenFlow)

- Guía de configuración de flows/ACL con sintaxis tipo OVS (`ovs-ofctl`):  
  https://docs.commscope.com/bundle/fastiron-08030-sdnguide/page/GUID-031030CA-62EC-4009-A516-5510238EF8F4.html
- Ejemplo de reglas OpenFlow para descartar tráfico con `actions=drop` (OVS + Ryu, OpenFlow 1.3):  
  https://hepia.infolibre.ch/Virtualisation-Reseaux/sdn_with_openflow1.3_ovswitch_and_ryu.pdf


==================================
 5. Mitigación LÍMITE DE TASA
    (Rate Limiting con Meters OpenFlow)
==================================

Objetivo:  
No bloquear completamente a los atacantes, sino limitar el ancho de
banda por host para evitar la saturación del servidor y del plano de
datos.

En el código se usan meters OpenFlow 1.3 en cada switch hoja, uno por
cluster. Cada meter actúa como un “balde de tokens” (token bucket) que
marca y descarta tráfico cuando se excede una tasa configurada.

Para cada cluster `id_cluster`:

1. Se crea un meter con ID `1000 + id_cluster`:

       ovs-ofctl -O OpenFlow13 add-meter sLeafX \
         "meter=<id>,kbps,band=type=drop,rate=<limite_kbps>"

   En el script, el límite se calcula a partir de:

       LIMITE_TASA_Mbps_POR_ATACANTE = 0.5
       LIMITE_TASA_kbps = int(LIMITE_TASA_Mbps_POR_ATACANTE * 1000)

   Es decir, ~0,5 Mbps por host atacante.

2. Se instalan reglas para cada IP atacante del cluster que aplican ese
   meter y luego siguen con `actions=NORMAL`:

       ovs-ofctl -O OpenFlow13 add-flow sLeafX \
         "priority=200,tcp,nw_src=<IP_ATACANTE>,nw_dst=<IP_SERVIDOR>,actions=meter:<id>,NORMAL"

       ovs-ofctl -O OpenFlow13 add-flow sLeafX \
         "priority=200,udp,nw_src=<IP_ATACANTE>,nw_dst=<IP_SERVIDOR>,actions=meter:<id>,NORMAL"

Comportamiento

- Mientras el tráfico de un host se mantiene dentro del límite configurado,  
  el tráfico fluye normalmente.
- Cuando el host intenta enviar mucho más (como en un ataque DDoS
  volumétrico), el meter comienza a descartar paquetes excedentes,
  manteniendo controlada la tasa efectiva que llega al servidor.
- Se mitiga la congestión sin cortar del todo la conectividad: los
  atacantes “gritan” pero el switch los estrangula a un caudal fijo.

Esta mitigación se activa en las fases:

- `SOLO_LIMITE_TASA` (solo rate limiting),
- `TODAS_LAS_MITIGACIONES` (combinada con UMBRAL y/o BAN, según las banderas).

Ventajas

- Mantiene cierta equidad: los clientes legítimos siguen teniendo acceso.
- Útil cuando no se quiere o no se puede identificar con certeza quién es
  atacante, pero sí limitar el daño que pueden causar.

Documentación (meters y rate limiting)

- Especificación oficial de OpenFlow 1.3 (sección de meters y band=drop):  
  https://opennetworking.org/wp-content/uploads/2013/04/openflow-spec-v1.3.1.pdf
- Ejemplo práctico de `ovs-ofctl add-meter` con `kbps` y `band=type=drop`:  
  https://pica8-fs.atlassian.net/wiki/spaces/PicOS443sp/pages/10478023/ovs-ofctl%2Badd-meter%2Bbridge%2Bmeter%2Bid%2Bmeter-parameter


==================================
 6. Mitigación BAN: bloqueo temporal
==================================

Objetivo:  
Aplicar un bloqueo total y temporal a los hosts que están participando
en el ataque, de forma que el servidor recupere rápidamente la estabilidad,
pero permitiendo que pasado un tiempo la red vuelva a su estado normal.

El BAN se implementa como reglas de mayor prioridad (`PRIO_BAN = 300`)
en los switches hoja, que descartan todo el tráfico TCP/UDP desde las IPs
atacantes hacia el servidor:

    ovs-ofctl -O OpenFlow13 add-flow sLeafX \
      "priority=300,tcp,nw_src=<IP_ATACANTE>,nw_dst=<IP_SERVIDOR>,actions=drop"

    ovs-ofctl -O OpenFlow13 add-flow sLeafX \
      "priority=300,udp,nw_src=<IP_ATACANTE>,nw_dst=<IP_SERVIDOR>,actions=drop"

Estas reglas se instalan sobre todos los clusters marcados como atacantes
(`recopilar_ips_atacantes`), excluyendo las IPs legítimas que están en la
whitelist (servidores, `cc`, host pinger, etc.).

Duración y expiración automática

El bloqueo no es permanente:

- El script llama a `aplicar_mitigacion_ban(...)` con una duración:

      DURACION_BAN_SEGUNDOS = 60

- Internamente se lanza un hilo (`threading.Thread`) que:
  - hace `time.sleep(DURACION_BAN_SEGUNDOS)`, y luego
  - ejecuta `remover_mitigacion_ban(...)`, que elimina las reglas de BAN
    (`del-flows` con `priority=PRIO_BAN`).

De esta forma, el BAN funciona como un “corte de emergencia”:
se sacrifica momentáneamente a todos los hosts marcados como atacantes para
restablecer la calidad de servicio del servidor, y después se les devuelve
la posibilidad de transmitir, permitiendo que el experimento observe la
recuperación de la red.

Relación con las fases

- `SOLO_BAN`: se evalúa el impacto de usar únicamente BAN como defensa.
- `TODAS_LAS_MITIGACIONES`: BAN se combina con UMBRAL y/o rate limiting,
  mostrando cómo el bloqueo temporal, sumado a técnicas más finas, puede
  mejorar aún más la estabilidad durante el ataque.

Documentación (flows drop y comandos de procesos)

- Manual de `ovs-ofctl` (gestión de flows, prioridades y acción `drop`):  
  https://manpages.ubuntu.com/manpages/xenial/man8/ovs-ofctl.8.html
- Ejemplo de reglas OpenFlow con `actions=drop` en OVS (match por `nw_src`/`nw_dst`):  
  https://hepia.infolibre.ch/Virtualisation-Reseaux/sdn_with_openflow1.3_ovswitch_and_ryu.pdf
- Comando `killall` para terminar procesos (por nombre) como `iperf` durante la limpieza del ataque:  
  https://man7.org/linux/man-pages/man1/killall.1.html
- Comando `pkill` para enviar señales a procesos que coincidan con un patrón (alternativa a `killall`):  
  https://ss64.com/bash/pkill.html

==================================
 7. Limpieza de mitigaciones
==================================

def limpiar_todas_las_mitigaciones(...)

Elimina:

- Reglas UMBRAL  
- Reglas y meters Rate Limit  
- Reglas BAN  

Se ejecuta antes y después de cada fase.



==================================
 8. Ejecución de fases con ataque
==================================

Flujo:

1. Limpia procesos iperf  
2. Limpia mitigaciones  
3. Lanza ataque TCP + UDP  
4. Pre-chequeo  
5. Crea hilo monitor  
6. Ejecuta pings  
7. Activa mitigaciones si se cumplen los criterios  
8. Registra estadísticas  
9. Detiene hilo  
10. Limpia mitigaciones  



==================================
 9. Resumen de resultados
==================================

resumen_fases.txt contiene:

- n muestras  
- promedio  
- mediana  
- p95  
- mínimo  
- máximo  

p95 indica el valor bajo el cual cae el 95% de las muestras.  
Es útil para determinar estabilidad y picos de latencia.



==================================
 10. Modificar parámetros del experimento
==================================

- CICLOS  
- DURACION_FASE_ATAQUE  
- UMBRAL_TIMEOUTS_PING_CONSECUTIVOS  
- UMBRAL_LATENCIA_BAN_MS  

Activación de defensas:
- UMBRAL_ACTIVADO  
- LIMITE_TASA_ACTIVADO  
- BAN_ACTIVADO  

Rate limiting:
- LIMITE_TASA_Mbps_POR_ATACANTE  


-----------------------------------------
 PRECAUCIÓN
-----------------------------------------

La mitigación BAN puede impedir que los hosts atacantes se
reconecten. Se recomienda usar:

CICLOS = 1

para evitar que el segundo ciclo quede sin tráfico que medir.












