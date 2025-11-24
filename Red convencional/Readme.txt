############################################################################
#############       Mitigación de ataques DDoS en redes SDN    #############
############################################################################

# Experimento DDoS en Red Convencional (Mininet)

Este repositorio contiene un script en Python para evaluar el comportamiento de una red convencional (sin SDN, sin controladores y sin mitigaciones) bajo un ataque DDoS, este, esta en formato ".py", además, se tiene otro archivo de extensión ".mn", este corresponde a la topología de la red, este, corresponde al uso de MiniEdit.

El objetivo principal es comparar este escenario con una red SDN en experimentos posteriores, midiendo diferencias en estabilidad, latencia, saturación y capacidad de respuesta.

El código está implementado utilizando Mininet, iperf y herramientas estándar de Linux para simular:
- topologías de red,
- generación de tráfico benigno,
- ataques DDoS volumétricos TCP y UDP,
- captura de métricas de rendimiento.

---------------------------------------------------------------------------

# Características principales del script

### Red convencional (sin SDN)
Se utiliza "OVSBridge", un switch Open vSwitch en modo bridge, donde:
- no hay plano de control,
- no hay reglas OpenFlow,
- no existen mecanismos de mitigación,
- el forwarding es completamente básico.

### Ataques DDoS simulados con iperf
Se generan ataques de alto volumen desde 50 hosts atacantes, distribuidos en 5 clústeres.

El ataque puede ser:
- TCP saturado, usando conexiones paralelas (`-P`)
- UDP volumétrico, usando tasa fija (`-b 80M`)

### Mediciones de latencia con ping
Se evalúa:
- fase NORMAL (sin ataque)
- fase SIN_MITIGACION (ataque activo sin defensa)

todo esto repetido "CICLOS" veces.

Los resultados se almacenan en archivos `.txt`.

### Registros completos en tiempo real
El script genera:
- `ping_convencional.txt`: resultados detallados de latencias  
- `ataque_convencional_log.txt`: log completo del experimento  
- `resumen_convencional.txt`: métricas resumen (Promedio, Mediana, p95, Min, Max)

---------------------------------------------------------------------------

# Requisitos del entorno

- **Mininet** (probado en 2.3.0 — repos Ubuntu)  
  https://github.com/mininet/mininet

- **iperf** o **iperf2**

- Python 3.6+

- Linux (Mininet no funciona en Windows sin virtualización)

---------------------------------------------------------------------------

# Instalación rápida

```bash
git clone <este repositorio>
cd <repo>
sudo python3 experimento_convencional.py
```

---------------------------------------------------------------------------

# Mininet: Simulación de Topologías

Documentación oficial:  
https://github.com/mininet/mininet/wiki/Documentation

- `Mininet()`: crea la red  
- `TCLink`: permite especificar ancho de banda, delay, cola máxima  
- `OVSBridge`: switch sin OpenFlow  
- `.addHost()`, `.addSwitch()`, `.addLink()`: construcción de topología  

Mininet permite simular redes completas en un solo PC, incluyendo cientos de hosts virtuales.

---------------------------------------------------------------------------

## OVSBridge vs. Switch OpenFlow

### Uso:
```python
from mininet.node import OVSBridge
```

Porque:
- No se necesita un controlador SDN
- Es forwarding clásico
- Representa una red convencional para comparar contra la SDN

Documentación oficial:  
https://github.com/mininet/mininet/wiki/FAQ#switches

---------------------------------------------------------------------------

# Uso de iperf para ataques y servidores

Documentación oficial:  
https://iperf.fr/iperf-doc.php  
https://github.com/esnet/iperf

### Servidor TCP y UDP:
- TCP: `iperf -c <IP> -p 5001 -t 600 -P 8`  
- UDP: `iperf -c <IP> -u -p 5002 -t 600 -b 80M`

### Parámetros explicados

`-c <IP>`  
Actúa como cliente enviando tráfico al servidor víctima.

`-p <puerto>`  
5001 (TCP), 5002 (UDP).

`-t <segundos>`  
Duración del tráfico (ataque).

`-P <hilos>`  
Conexiones paralelas por host (8 en este experimento).

---------------------------------------------------------------------------

# Análisis de latencia con ping

Documentación oficial:  
https://linux.die.net/man/8/ping

El script extrae la latencia usando:
```python
re.search(r"time[=<]\s*([\d\.]+)\s*ms", out)
```

Permite capturar:
- `time=12.3 ms`
- `time<1 ms`

---------------------------------------------------------------------------

# Logging y manejo de errores

Documentación oficial (killall):  
https://man7.org/linux/man-pages/man1/killall.1.html

El logging:
- usa timestamps (`time.strftime`)
- guarda eventos en `ataque_convencional_log.txt`
- detiene iperf con `killall -9 iperf`

---------------------------------------------------------------------------

# Flujo del experimento

La función principal ejecuta:

1. Limpieza de logs  
2. Construcción de topología  
3. Inicio de servidores iperf  
4. Prueba de conectividad  
5. CICLOS de:
   - **FASE NORMAL**
   - **FASE SIN_MITIGACION**
6. Registro y guardado de resultados  
7. Resumen estadístico final  

