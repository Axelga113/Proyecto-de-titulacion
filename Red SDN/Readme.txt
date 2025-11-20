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

Aplicada al cluster 4, crea reglas OpenFlow drop:

ovs-ofctl -O OpenFlow13 add-flow sLeaf4 \
 'priority=310,tcp,nw_src=<IP>,nw_dst=<SERV>,actions=drop'

Documentación:
https://docs.commscope.com/bundle/fastiron-08030-sdnguide/page/GUID-031030CA-62EC-4009-A516-5510238EF8F4.html



==================================
 5. Mitigación LÍMITE DE TASA (Rate Limiting con Meters)
==================================

Se crean meters por cluster:

ovs-ofctl add-meter \
  'meter=<id>,kbps,band=type=drop,rate=<limite>'

Luego reglas que aplican el meter a cada IP atacante.

Documentación:
https://opennetworking.org/wp-content/uploads/2013/04/openflow-spec-v1.3.1.pdf
https://floodlight.atlassian.net/wiki/.../OpenFlow+Meters



==================================
 6. Mitigación BAN: bloqueo temporal
==================================

Bloqueo total de IPs atacantes:

ovs-ofctl add-flow \
 'priority=300,tcp,nw_src=<IP>,nw_dst=<SERV>,actions=drop'

Se elimina automáticamente tras DURACION_BAN_SEGUNDOS mediante threading.



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












