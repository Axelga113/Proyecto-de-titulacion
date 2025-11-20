#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

import os, time, re, socket, traceback, threading
from collections import defaultdict

# ==========================================================
# DICCIONARIO DE FASES DEL EXPERIMENTO (para la tesis)
# ==========================================================
#   NORMAL                -> Trafico normal sin ataque.
#   SIN_MITIGACION        -> Ataque DDoS activo sin ningun mecanismo de defensa.
#   SOLO_UMBRAL           -> Ataque DDoS + mitigacion por umbral (THRESHOLD).
#   SOLO_LIMITE_TASA      -> Ataque DDoS + mitigacion de limite de tasa (RATE LIMITING).
#   SOLO_BAN              -> Ataque DDoS + mitigacion BAN solamente.
#   TODAS_LAS_MITIGACIONES-> Ataque DDoS + umbral + limite de tasa (+ BAN si esta activado).
#
# DICCIONARIO DE RAZONES DEL DETECTOR DE ATAQUE
#   PROCESOS_ATAQUE_CAIDOS -> No se observan procesos iperf de ataque activos.
#   PING_FALLIDOS          -> Se alcanzo el umbral de timeouts de ping consecutivos.
#   IPERF_ACTIVO           -> Hay procesos iperf de ataque activos, pero sin disparar PING_FALLIDOS.

# ==========================================================
# CONFIGURACION GENERAL
# ==========================================================
DIRECTORIO_RESULTADOS   = "resultados_ddos_sdn_corrected"
ARCHIVO_PING            = os.path.join(DIRECTORIO_RESULTADOS, "ping.txt")
ARCHIVO_ATAQUE          = os.path.join(DIRECTORIO_RESULTADOS, "ataque.txt")
ARCHIVO_LOG             = os.path.join(DIRECTORIO_RESULTADOS, "ataque_log.txt")
ARCHIVO_RESUMEN         = os.path.join(DIRECTORIO_RESULTADOS, "resumen_fases.txt")

CICLOS = 1
DESCANSO_ENTRE_FASES_SEG  = 5
DESCANSO_ENTRE_CICLOS_SEG = 8
CONSOLA_DETALLADA = True

# Ataque por fase: se deja largo para que no termine durante los 40 pings
DURACION_FASE_ATAQUE = 600  # segundos (10 minutos)

# Topologia
ANCHO_BANDA_HOST      = 100      # Mbps por host
ANCHO_BANDA_SWITCHES  = 1000     # Mbps
ANCHO_BANDA_NUCLEO    = 10000    # Mbps
DELAY                 = "2ms"
TAMANO_MAX_COLA       = 1000

NUM_CLUSTERS      = 5
HOSTS_POR_CLUSTER = 10  # 50 atacantes en total

IP_BASE_SERV    = "10.0.0."
IP_BASE_ATAQUE  = "10.0.0."

TCP_PORT        = 5001
UDP_PORT        = 5002
IPERF_PARALELO  = 8
ANCHO_BANDA_UDP = "80M"

CANTIDAD_PINGS      = 40
RETARDO_ENTRE_PINGS = 0.2

RYU_HOST  = "127.0.0.1"
RYU_PORTS = (6653, 6633)

# Mecanismo de seguridad basado en pings fallidos
UMBRAL_TIMEOUTS_PING_CONSECUTIVOS = 3

# Umbral de latencia (ms) para considerar ping "malo" en SOLO_BAN
UMBRAL_LATENCIA_BAN_MS = 500.0

# ==========================================================
# FLAGS PARA ACTIVAR/DESACTIVAR MITIGACIONES
# ==========================================================
# Para hacer experimentos separados:
#  - Solo BAN:
#       UMBRAL_ACTIVADO       = 0
#       LIMITE_TASA_ACTIVADO  = 0
#       BAN_ACTIVADO          = 1
#  - Umbral + Limite de tasa, SIN BAN:
#       UMBRAL_ACTIVADO       = 1
#       LIMITE_TASA_ACTIVADO  = 1
#       BAN_ACTIVADO          = 0
UMBRAL_ACTIVADO       = 0  # 0 = desactiva mitigacion UMBRAL
LIMITE_TASA_ACTIVADO  = 0  # 0 = desactiva mitigacion LIMITE DE TASA
BAN_ACTIVADO          = 1  # 0 = desactivado, 1 = activado (mitigacion BAN)

# Parametros de mitigaciones
ID_CLUSTER_UMBRAL             = 4   # cluster sobre el que se aplica umbral
LIMITE_TASA_Mbps_POR_ATACANTE = 0.5
LIMITE_TASA_kbps              = int(LIMITE_TASA_Mbps_POR_ATACANTE * 1000)

# BAN: duracion del baneo en segundos
DURACION_BAN_SEGUNDOS = 60

# Prioridades de reglas OpenFlow
PRIO_ICMP        = 250
PRIO_NORMAL      = 100
PRIO_LIMITE_TASA = 200
PRIO_UMBRAL      = 310
PRIO_BAN         = 300

# ==========================================================
# Locks para comandos a hosts/switches
# ==========================================================
_BLOQUEOS_HOST   = defaultdict(threading.Lock)
_BLOQUEOS_SWITCH = defaultdict(threading.Lock)


def comando_host(h, cmd):
    """Ejecuta un comando en un host de forma segura (protegido por lock)."""
    with _BLOQUEOS_HOST[id(h)]:
        return h.cmd(cmd)


def popen_host(h, cmd, **kw):
    """Ejecuta un comando en un host usando popen, protegido por lock."""
    with _BLOQUEOS_HOST[id(h)]:
        return h.popen(cmd, **kw)


def comando_switch(sw, cmd):
    """Ejecuta un comando en un switch de forma segura (protegido por lock)."""
    with _BLOQUEOS_SWITCH[id(sw)]:
        return sw.cmd(cmd)


# ==========================================================
# Logging
# ==========================================================
def asegurar_directorio_resultados():
    if not os.path.exists(DIRECTORIO_RESULTADOS):
        os.makedirs(DIRECTORIO_RESULTADOS)


def _marca_tiempo():
    return time.strftime("%H:%M:%S")


def escribir_log(msg):
    asegurar_directorio_resultados()
    with open(ARCHIVO_LOG, "a", encoding="utf-8") as f:
        f.write("[{}] {}\n".format(_marca_tiempo(), msg))
    if CONSOLA_DETALLADA:
        print("[{}] {}".format(_marca_tiempo(), msg), flush=True)


def sobrescribir_archivos_log():
    asegurar_directorio_resultados()
    for p in (ARCHIVO_PING, ARCHIVO_ATAQUE, ARCHIVO_LOG, ARCHIVO_RESUMEN):
        open(p, "w", encoding="utf-8").close()


# ==========================================================
# Controlador / OpenFlow
# ==========================================================
def verificar_ryu_en_ejecucion(host="127.0.0.1", ports=(6653, 6633), timeout=1.0):
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.close()
            return True, port
        except:
            pass
    return False, None


def configurar_controlador_y_protocolo(red, ip_ctrl, puerto_ctrl, hay_controlador):
    for sw in red.switches:
        comando_switch(sw, "ovs-vsctl set Bridge {} protocols=OpenFlow13".format(sw.name))
        comando_switch(sw, "ovs-ofctl -O OpenFlow13 del-flows {}".format(sw.name))

    if hay_controlador:
        for sw in red.switches:
            comando_switch(sw, "ovs-vsctl set-controller {} tcp:{}:{}".format(sw.name, ip_ctrl, puerto_ctrl))
            comando_switch(sw, "ovs-vsctl set-fail-mode {} secure".format(sw.name))
    else:
        for sw in red.switches:
            comando_switch(sw, "ovs-vsctl del-controller {}".format(sw.name))
            comando_switch(sw, "ovs-vsctl set-fail-mode {} standalone".format(sw.name))

    if not hay_controlador:
        escribir_log("Modo sin controlador: standalone")
        return True

    deadline = time.time() + 20
    pendientes = {sw.name for sw in red.switches}

    while time.time() < deadline and pendientes:
        ok = set()
        for sw in red.switches:
            out = comando_switch(sw, "ovs-vsctl show | grep -A5 'Bridge {}' | grep is_connected".format(sw.name))
            if "true" in out:
                ok.add(sw.name)
        pendientes -= ok
        if pendientes:
            time.sleep(0.5)

    if pendientes:
        escribir_log("ADVERTENCIA: switches sin conexion: {}".format(sorted(list(pendientes))))
    else:
        escribir_log("OK: todos los switches conectados al controlador")

    return True


def instalar_flows_iniciales(red):
    for s in red.switches:
        comando_switch(s, "ovs-ofctl -O OpenFlow13 del-flows {}".format(s.name))
        comando_switch(s, "ovs-ofctl -O OpenFlow13 add-flow {} 'priority=200,arp,actions=FLOOD'".format(s.name))
        comando_switch(s, "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},icmp,actions=NORMAL'".format(s.name, PRIO_ICMP))
        comando_switch(s, "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},ip,actions=NORMAL'".format(s.name, PRIO_NORMAL))

    escribir_log("Reglas iniciales instaladas (ARP/ICMP/IP)")


# ==========================================================
# Ataque vivo o no
# ==========================================================
def ataque_sigue_activo(clusters):
    """Revisa si los procesos iperf del ataque siguen activos."""
    hosts_muestra = [c[0] for c in clusters if c]
    total_procesos = 0
    hosts_con_procesos = 0

    for h in hosts_muestra:
        out = comando_host(h, "ps aux | grep 'iperf -c' | grep -v grep | wc -l")
        try:
            n = int(out.strip())
        except:
            n = 0
        total_procesos += n
        if n > 0:
            hosts_con_procesos += 1

    if hosts_con_procesos == 0 or total_procesos == 0:
        return False, total_procesos, hosts_con_procesos

    return True, total_procesos, hosts_con_procesos


# ==========================================================
# Deteccion de ataque
# ==========================================================
def detectar_ataque(clusters, evento_ping_fallidos):
    """Determina si hay ataque basado en procesos iperf y el mecanismo de ping fallidos."""
    vivo, total_procesos, hosts_con_procesos = ataque_sigue_activo(clusters)

    if not vivo:
        escribir_log("DETECTOR: procesos de ataque caidos (total_procesos={}, hosts_con_procesos={})".format(
            total_procesos, hosts_con_procesos))
        return False, "PROCESOS_ATAQUE_CAIDOS"

    if evento_ping_fallidos is not None and evento_ping_fallidos.is_set():
        escribir_log("DETECTOR: mecanismo de pings fallidos activo (timeouts consecutivos) con {} procesos iperf".format(
            total_procesos))
        return True, "PING_FALLIDOS"

    escribir_log("DETECTOR: iperf activo ({} procesos, {} hosts) pero sin activar mecanismo de pings fallidos".format(
        total_procesos, hosts_con_procesos))
    return True, "IPERF_ACTIVO"


# ==========================================================
# UMBRAL
# ==========================================================
def aplicar_mitigacion_umbral(red, ips_cluster4, ip_servidor):
    """Aplica mitigacion tipo UMBRAL a las IPs de un cluster especifico."""
    leaf4 = next((s for s in red.switches if s.name == "sLeaf4"), None)
    if not leaf4:
        escribir_log("UMBRAL: sLeaf4 no encontrado")
        return 0

    bloqueadas = 0
    for ip in ips_cluster4:
        comando_switch(leaf4, "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},tcp,nw_src={},nw_dst={},actions=drop'".format(
            leaf4.name, PRIO_UMBRAL, ip, ip_servidor))
        comando_switch(leaf4, "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},udp,nw_src={},nw_dst={},actions=drop'".format(
            leaf4.name, PRIO_UMBRAL, ip, ip_servidor))
        bloqueadas += 1

    escribir_log("UMBRAL: bloqueadas {} IPs del cluster 4".format(bloqueadas))
    return bloqueadas


def remover_mitigacion_umbral(red, ips_cluster4, ip_servidor):
    """Elimina la mitigacion de tipo UMBRAL previamente aplicada."""
    leaf4 = next((s for s in red.switches if s.name == "sLeaf4"), None)
    if not leaf4:
        return
    for ip in ips_cluster4:
        comando_switch(leaf4, "ovs-ofctl -O OpenFlow13 del-flows {} 'priority={},tcp,nw_src={},nw_dst={}'".format(
            leaf4.name, PRIO_UMBRAL, ip, ip_servidor))
        comando_switch(leaf4, "ovs-ofctl -O OpenFlow13 del-flows {} 'priority={},udp,nw_src={},nw_dst={}'".format(
            leaf4.name, PRIO_UMBRAL, ip, ip_servidor))
    escribir_log("UMBRAL: reglas eliminadas")


# ==========================================================
# LIMITE DE TASA
# ==========================================================
def aplicar_mitigacion_limite_tasa(red, ips_atacantes, switches_hoja, ip_servidor):
    """Aplica mitigacion de LIMITE DE TASA por cluster usando medidores OpenFlow."""
    aplicadas = 0
    for id_cluster, sw_hoja in switches_hoja.items():
        id_medidor_tasa = 1000 + id_cluster
        comando_switch(
            sw_hoja,
            "ovs-ofctl -O OpenFlow13 add-meter {} 'meter={},kbps,band=type=drop,rate={}'".format(
                sw_hoja.name, id_medidor_tasa, LIMITE_TASA_kbps)
        )

        host_inicio = 50 + (id_cluster - 1) * HOSTS_POR_CLUSTER + 1
        host_fin    = host_inicio + HOSTS_POR_CLUSTER - 1
        ips_cluster = [ip for ip in ips_atacantes
                       if host_inicio <= int(ip.split('.')[-1]) <= host_fin]

        for ip in ips_cluster:
            comando_switch(
                sw_hoja,
                "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},tcp,nw_src={},nw_dst={},actions=meter:{},NORMAL'".format(
                    sw_hoja.name, PRIO_LIMITE_TASA, ip, ip_servidor, id_medidor_tasa)
            )
            comando_switch(
                sw_hoja,
                "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},udp,nw_src={},nw_dst={},actions=meter:{},NORMAL'".format(
                    sw_hoja.name, PRIO_LIMITE_TASA, ip, ip_servidor, id_medidor_tasa)
            )
            aplicadas += 1

    escribir_log("LIMITE DE TASA: aplicado a {} atacantes a {:.1f} Mbps/host (~{:.1f} Mbps total)".format(
        aplicadas, LIMITE_TASA_Mbps_POR_ATACANTE, aplicadas * LIMITE_TASA_Mbps_POR_ATACANTE))
    return aplicadas


def remover_mitigacion_limite_tasa(red, ips_atacantes, switches_hoja, ip_servidor):
    """Elimina la mitigacion de LIMITE DE TASA y sus medidores."""
    for id_cluster, sw_hoja in switches_hoja.items():
        id_medidor_tasa = 1000 + id_cluster
        comando_switch(sw_hoja, "ovs-ofctl -O OpenFlow13 del-flows {} 'priority={}'".format(
            sw_hoja.name, PRIO_LIMITE_TASA))
        comando_switch(sw_hoja, "ovs-ofctl -O OpenFlow13 del-meters {} 'meter={}'".format(
            sw_hoja.name, id_medidor_tasa))
    escribir_log("LIMITE DE TASA: reglas eliminadas")


# ==========================================================
# BAN (BLOQUEO TEMPORAL)
# ==========================================================
def aplicar_mitigacion_ban(red, ips_atacantes, switches_hoja, ip_servidor, duracion_seg):
    """Aplica un BAN temporal (bloqueo total) a las IPs atacantes."""
    baneadas = 0
    for id_cluster, sw_hoja in switches_hoja.items():
        host_inicio = 50 + (id_cluster - 1) * HOSTS_POR_CLUSTER + 1
        host_fin    = host_inicio + HOSTS_POR_CLUSTER - 1
        ips_cluster = [ip for ip in ips_atacantes
                       if host_inicio <= int(ip.split('.')[-1]) <= host_fin]

        for ip in ips_cluster:
            comando_switch(
                sw_hoja,
                "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},tcp,nw_src={},nw_dst={},actions=drop'".format(
                    sw_hoja.name, PRIO_BAN, ip, ip_servidor)
            )
            comando_switch(
                sw_hoja,
                "ovs-ofctl -O OpenFlow13 add-flow {} 'priority={},udp,nw_src={},nw_dst={},actions=drop'".format(
                    sw_hoja.name, PRIO_BAN, ip, ip_servidor)
            )
            baneadas += 1

    escribir_log("BAN: bloqueadas {} IPs atacantes por {} segundos".format(baneadas, duracion_seg))

    def remover_despues():
        time.sleep(duracion_seg)
        remover_mitigacion_ban(red, ips_atacantes, switches_hoja, ip_servidor)
        escribir_log("BAN: expirado despues de {} segundos".format(duracion_seg))

    threading.Thread(target=remover_despues, daemon=True).start()
    return baneadas


def remover_mitigacion_ban(red, ips_atacantes, switches_hoja, ip_servidor):
    """Elimina las reglas de BAN aplicadas."""
    for id_cluster, sw_hoja in switches_hoja.items():
        comando_switch(sw_hoja, "ovs-ofctl -O OpenFlow13 del-flows {} 'priority={}'".format(
            sw_hoja.name, PRIO_BAN))
    escribir_log("BAN: reglas eliminadas")


# ==========================================================
# Limpiar mitigaciones
# ==========================================================
def limpiar_todas_las_mitigaciones(red, ips_atacantes, ips_cluster4, switches_hoja, ip_servidor):
    """Elimina todas las mitigaciones (umbral + limite de tasa + ban)."""
    escribir_log("Limpiando todas las mitigaciones (umbral + limite de tasa + ban)...")
    remover_mitigacion_umbral(red, ips_cluster4, ip_servidor)
    remover_mitigacion_limite_tasa(red, ips_atacantes, switches_hoja, ip_servidor)
    remover_mitigacion_ban(red, ips_atacantes, switches_hoja, ip_servidor)
    escribir_log("Mitigaciones limpiadas")


# ==========================================================
# Ping / monitor
# ==========================================================
def parsear_salida_ping(out):
    """Extrae la latencia en ms desde la salida de ping."""
    m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", out, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except:
            return None
    return None


def ejecutar_prueba_ping(host_origen, ip_destino, cantidad, retardo_entre, etiqueta=""):
    """Ejecuta N pings y devuelve lista de resultados y cantidad de timeouts."""
    resultados = []
    timeouts   = 0

    for i in range(cantidad):
        try:
            out = comando_host(host_origen, "ping -c 1 -W 2 {}".format(ip_destino))
            lat = parsear_salida_ping(out)
            if lat is None:
                resultados.append("timeout")
                timeouts += 1
            else:
                resultados.append(lat)
        except Exception as e:
            resultados.append("error")
            timeouts += 1
            escribir_log("Error en ping: {}".format(repr(e)))

        if etiqueta and ((i + 1) % 10 == 0):
            escribir_log("PING {}: {}/{} (ultimo={})".format(etiqueta, i + 1, cantidad, resultados[-1]))

        time.sleep(retardo_entre)

    return resultados, timeouts


def hilo_monitor_ping(evento_detener, evento_ping_fallidos, host_origen, ip_destino):
    """Hilo que monitoriza la conectividad por ping y activa el evento de pings fallidos."""
    timeouts_consecutivos = 0
    while not evento_detener.is_set():
        try:
            out = comando_host(host_origen, "ping -c 1 -W 1 {}".format(ip_destino))
            lat = parsear_salida_ping(out)
            if lat is None:
                timeouts_consecutivos += 1
                if timeouts_consecutivos >= UMBRAL_TIMEOUTS_PING_CONSECUTIVOS:
                    if not evento_ping_fallidos.is_set():
                        evento_ping_fallidos.set()
                        escribir_log("PING_FALLIDOS: {} timeouts consecutivos de ping".format(
                            timeouts_consecutivos))
            else:
                timeouts_consecutivos = 0
        except Exception as e:
            escribir_log("Error en monitor de ping: {}".format(repr(e)))

        evento_detener.wait(1.0)


# ==========================================================
# Pre-check de fase con 3 pings + detector
# ==========================================================
def prechequeo_fase(nombre_fase, espera_ataque, host_pinger, ip_servidor, clusters):
    """Realiza 3 pings de prueba y llama al detector de ataque antes de cada fase."""
    escribir_log("PRECHEQUEO {}: iniciando 3 pings de verificacion (espera_ataque={})".format(
        nombre_fase, espera_ataque))

    # 3 pings de prueba
    resultados, timeouts = ejecutar_prueba_ping(
        host_pinger, ip_servidor, 3, RETARDO_ENTRE_PINGS, etiqueta=nombre_fase + "_PRE"
    )

    # ================================
    # Prechequeo:
    # "malo" = timeout o latencia >= UMBRAL_LATENCIA_BAN_MS
    # Se activa si hay UMBRAL_TIMEOUTS_PING_CONSECUTIVOS malos seguidos
    # ================================
    consecutivos_malos = 0
    se_activo_criterio_ban = False

    for r in resultados:
        if r == "timeout":
            es_malo = True
        elif isinstance(r, (int, float)) and r >= UMBRAL_LATENCIA_BAN_MS:
            es_malo = True
        else:
            es_malo = False

        if es_malo:
            consecutivos_malos += 1
        else:
            consecutivos_malos = 0

        if consecutivos_malos >= UMBRAL_TIMEOUTS_PING_CONSECUTIVOS:
            se_activo_criterio_ban = True
            break

    # Estado de procesos de ataque
    vivo, total_procesos, hosts_con_procesos = ataque_sigue_activo(clusters)

    if se_activo_criterio_ban:
        ataque_detectado = True
        razon = "CRITERIO_BAN_PRECHEQUEO"
        escribir_log("PRECHEQUEO {}: criterio BAN activado ({} pings malos consecutivos)".format(
            nombre_fase, consecutivos_malos))
    else:
        # Si no se activa el criterio BAN, usamos el detector normal
        ataque_detectado, razon = detectar_ataque(clusters, None)

    escribir_log("PRECHEQUEO {}: resultados={} timeouts={} vivo={} procesos={} hosts={} ataque_detectado={} razon={}".format(
        nombre_fase, resultados, timeouts, vivo, total_procesos, hosts_con_procesos, ataque_detectado, razon
    ))

    return ataque_detectado



# ==========================================================
# Servidores iperf
# ==========================================================
def iniciar_servidores_iperf(host):
    """Inicia servidores iperf TCP y UDP en el host servidor."""
    comando_host(host, "pkill -f '^iperf -s' || true")
    comando_host(host, "ulimit -n 65535; nohup iperf -s -p {} > /tmp/iperf_tcp.log 2>&1 &".format(TCP_PORT))
    comando_host(host, "ulimit -n 65535; nohup iperf -s -u -p {} > /tmp/iperf_udp.log 2>&1 &".format(UDP_PORT))
    time.sleep(2)

    out = comando_host(host, "netstat -tuln | egrep ':{}|:{}'".format(TCP_PORT, UDP_PORT))
    tcp_ok = ":{}".format(TCP_PORT) in out
    udp_ok = ":{}".format(UDP_PORT) in out

    if tcp_ok and udp_ok:
        escribir_log("Servidores iperf TCP/UDP iniciados")
        return True
    else:
        escribir_log("ERROR: servidores iperf no estan escuchando")
        return False


# ==========================================================
# Lanzar y detener DDoS (por fase)
# ==========================================================
def lanzar_ataque_ddos(clusters, ip_destino, duracion_seg, usar_udp=False):
    """Lanza el ataque DDoS (TCP o UDP) desde todos los atacantes."""
    mapa_procesos = {}
    mapa_comandos = {}
    modo = "UDP" if usar_udp else "TCP"

    escribir_log("Lanzando ataque {} para la fase: {} hosts x {} conexiones = {} conexiones totales (t={}s)".format(
        modo, len(clusters) * len(clusters[0]), IPERF_PARALELO,
        len(clusters) * len(clusters[0]) * IPERF_PARALELO, duracion_seg))

    exitosos = 0
    fallidos = 0

    for cluster in clusters:
        for h in cluster:
            if usar_udp:
                cmd = "iperf -c {} -u -p {} -t {} -P {} -b {} >> /tmp/{}_udp.log 2>&1 &".format(
                    ip_destino, UDP_PORT, duracion_seg, IPERF_PARALELO, ANCHO_BANDA_UDP, h.name)
            else:
                cmd = "iperf -c {} -p {} -t {} -P {} >> /tmp/{}_tcp.log 2>&1 &".format(
                    ip_destino, TCP_PORT, duracion_seg, IPERF_PARALELO, h.name)
            mapa_comandos[h.name] = cmd
            try:
                comando_host(h, cmd)
                mapa_procesos[h.name] = True
                exitosos += 1
            except Exception as e:
                mapa_procesos[h.name] = None
                fallidos += 1
                escribir_log("Error iniciando ataque en {}: {}".format(h.name, repr(e)))

    escribir_log("Ataque {} iniciado: {} OK, {} errores".format(modo, exitosos, fallidos))

    time.sleep(0.5)
    host_muestra = clusters[0][0]
    ps_out = comando_host(host_muestra, "ps aux | grep iperf | grep -v grep")
    corriendo = len([l for l in ps_out.splitlines() if 'iperf -c' in l])
    escribir_log("Revision: {} procesos iperf en {}".format(corriendo, host_muestra.name))

    return mapa_procesos, mapa_comandos


def detener_ataque_ddos(clusters):
    """Detiene todos los procesos iperf de los hosts atacantes."""
    for cluster in clusters:
        for h in cluster:
            comando_host(h, "killall -9 iperf 2>/dev/null || true")
            comando_host(
                h,
                "ps aux | grep 'iperf -c' | grep -v grep | "
                "awk '{print $2}' | xargs -r kill -9 2>/dev/null || true"
            )

    escribir_log("Ataque DDoS detenido (killall iperf en todos los hosts atacantes)")


# ==========================================================
# Topologia
# ==========================================================
def construir_topologia_universidad(ip_controlador=RYU_HOST, puerto_controlador=6653, hay_controlador=True):
    """Construye la topologia SDN de la universidad con controlador remoto opcional."""
    red = Mininet(controller=None, link=TCLink, switch=OVSKernelSwitch, build=False)

    if hay_controlador:
        red.addController("c0", controller=RemoteController, ip=ip_controlador, port=puerto_controlador)

    s1         = red.addSwitch("s1", protocols="OpenFlow13")
    s2         = red.addSwitch("s2", protocols="OpenFlow13")
    s3         = red.addSwitch("s3", protocols="OpenFlow13")
    sCORE_CC1  = red.addSwitch("sCORE_CC1", protocols="OpenFlow13")
    sConst2    = red.addSwitch("sConst2", protocols="OpenFlow13")
    sFIN3      = red.addSwitch("sFIN3", protocols="OpenFlow13")
    s4         = red.addSwitch("s4", protocols="OpenFlow13")
    s5         = red.addSwitch("s5", protocols="OpenFlow13")
    s6         = red.addSwitch("s6", protocols="OpenFlow13")
    sLab4      = red.addSwitch("sLab4",  protocols="OpenFlow13")
    sServ5     = red.addSwitch("sServ5", protocols="OpenFlow13")
    sSecr6     = red.addSwitch("sSecr6", protocols="OpenFlow13")

    red.addLink(s2, s1,        bw=ANCHO_BANDA_SWITCHES, delay=DELAY, max_queue_size=TAMANO_MAX_COLA)
    red.addLink(s3, s1,        bw=ANCHO_BANDA_SWITCHES, delay=DELAY, max_queue_size=TAMANO_MAX_COLA)
    red.addLink(s1, sCORE_CC1, bw=ANCHO_BANDA_SWITCHES, delay=DELAY, max_queue_size=TAMANO_MAX_COLA)
    red.addLink(sCORE_CC1, sConst2, bw=ANCHO_BANDA_SWITCHES, delay=DELAY, max_queue_size=TAMANO_MAX_COLA)
    red.addLink(sCORE_CC1, sFIN3,   bw=ANCHO_BANDA_NUCLEO,  delay="1ms", max_queue_size=TAMANO_MAX_COLA)
    red.addLink(sCORE_CC1, s4,      bw=ANCHO_BANDA_SWITCHES, delay=DELAY, max_queue_size=TAMANO_MAX_COLA)
    red.addLink(sCORE_CC1, s5,      bw=ANCHO_BANDA_SWITCHES, delay=DELAY, max_queue_size=TAMANO_MAX_COLA)
    red.addLink(sCORE_CC1, s6,      bw=ANCHO_BANDA_SWITCHES, delay=DELAY, max_queue_size=TAMANO_MAX_COLA)

    red.addLink(sFIN3, sLab4,  bw=ANCHO_BANDA_SWITCHES, delay="1ms", max_queue_size=TAMANO_MAX_COLA)
    red.addLink(sFIN3, sServ5, bw=ANCHO_BANDA_NUCLEO,   delay="1ms", max_queue_size=TAMANO_MAX_COLA)
    red.addLink(sFIN3, sSecr6, bw=ANCHO_BANDA_SWITCHES, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    cc = red.addHost("cc", ip="{}150/24".format(IP_BASE_SERV))
    red.addLink(cc, sCORE_CC1, bw=ANCHO_BANDA_HOST, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    serv1 = red.addHost("Serv_1", ip="{}10/24".format(IP_BASE_SERV))
    red.addLink(serv1, sServ5, bw=ANCHO_BANDA_NUCLEO, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    serv2 = red.addHost("Serv_2", ip="{}11/24".format(IP_BASE_SERV))
    red.addLink(serv2, sServ5, bw=ANCHO_BANDA_NUCLEO, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    maestro = red.addHost("maestro", ip="{}200/24".format(IP_BASE_SERV))
    red.addLink(maestro, sLab4, bw=ANCHO_BANDA_HOST, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    switches_por_cluster = {
        1: sCORE_CC1,
        2: sConst2,
        3: sFIN3,
        4: sLab4,
        5: s6
    }

    clusters       = []
    switches_hoja  = {}

    for id_cluster in range(1, NUM_CLUSTERS + 1):
        nombre_hoja = "sLeaf{}".format(id_cluster)
        sw_hoja = red.addSwitch(nombre_hoja, protocols="OpenFlow13")
        switches_hoja[id_cluster] = sw_hoja

        sw_troncal = switches_por_cluster[id_cluster]
        red.addLink(
            sw_hoja,
            sw_troncal,
            bw=ANCHO_BANDA_SWITCHES,
            delay=DELAY,
            max_queue_size=TAMANO_MAX_COLA
        )

        hosts_cluster = []
        for num_host in range(1, HOSTS_POR_CLUSTER + 1):
            ip_num = 50 + (id_cluster - 1) * HOSTS_POR_CLUSTER + num_host
            host = red.addHost(
                "atk{}_{}".format(id_cluster, num_host),
                ip="{}{}/24".format(IP_BASE_ATAQUE, ip_num)
            )
            red.addLink(
                host,
                sw_hoja,
                bw=ANCHO_BANDA_HOST,
                delay="1ms",
                max_queue_size=TAMANO_MAX_COLA
            )
            hosts_cluster.append(host)

        clusters.append(hosts_cluster)

    red.build()
    red.start()

    escribir_log("Topologia construida: {} clusters x {} hosts = {} atacantes".format(
        NUM_CLUSTERS, HOSTS_POR_CLUSTER, NUM_CLUSTERS * HOSTS_POR_CLUSTER))

    return red, cc, [serv1, serv2], clusters, switches_hoja

# ==========================================================
# WHITELIST DE IPs LEGITIMAS
# ==========================================================
def construir_whitelist(host_pinger, servidores):
    """
    Construye una whitelist de IPs consideradas legitimas (no se tratan como atacantes).
    """
    ips_whitelist = set()

    if host_pinger is not None:
        ip_hp = host_pinger.IP()
        if ip_hp:
            ips_whitelist.add(ip_hp)

    for serv in servidores:
        ip_serv = serv.IP()
        if ip_serv:
            ips_whitelist.add(ip_serv)

    escribir_log(
        "WHITELIST construida con {} IPs legitimas: {}".format(
            len(ips_whitelist),
            ", ".join(sorted(ips_whitelist)) if ips_whitelist else "(vacia)"
        )
    )
    return ips_whitelist

# ==========================================================
# IPs atacantes (todo lo que NO esta en la whitelist)
# ==========================================================
def recopilar_ips_atacantes(clusters, ips_whitelist):
    """
    Recolecta las IPs consideradas atacantes y las agrupa por cluster.
    Aqui se asume que:
      - La whitelist contiene solo IPs legitimas (cc, servidores, etc.).
      - Ningun host de los clusters ni el maestro esta en la whitelist.
    Por claridad, si alguna IP de cluster aparece en la whitelist, se excluye.
    """
    todas_las_ips    = []
    mapa_ips_cluster = {}

    for id_cluster, hosts_cluster in enumerate(clusters, start=1):
        ips_cluster = []
        for h in hosts_cluster:
            ip = h.IP()
            if not ip:
                continue

            if ip in ips_whitelist:
                # Por diseño no deberia ocurrir, pero lo registramos si pasa
                escribir_log(
                    "WHITELIST: IP {} del cluster {} marcada como legitima, se excluye de atacantes".format(
                        ip, id_cluster
                    )
                )
                continue

            todas_las_ips.append(ip)
            ips_cluster.append(ip)

        mapa_ips_cluster[id_cluster] = ips_cluster

    escribir_log(
        "Se recopilaron {} IPs atacantes ({} clusters) usando whitelist ({} IPs legitimas)".format(
            len(todas_las_ips), len(clusters), len(ips_whitelist))
    )

    asegurar_directorio_resultados()
    with open(ARCHIVO_ATAQUE, "a", encoding="utf-8") as f:
        f.write("\n=== WHITELIST (IPs legitimas) ===\n")
        if ips_whitelist:
            f.write(", ".join(sorted(ips_whitelist)) + "\n")
        else:
            f.write("(vacia)\n")

        f.write("\n=== IPs ATACANTES POR CLUSTER (excluyendo whitelist) ===\n")
        for id_cluster, ips in mapa_ips_cluster.items():
            linea_ips = ", ".join(ips) if ips else "(sin IPs marcadas)"
            f.write("Cluster {}: {}\n".format(id_cluster, linea_ips))
        f.write("\n")

    return todas_las_ips, mapa_ips_cluster



# ==========================================================
# Primeo de rutas
# ==========================================================
def inicializar_rutas_red(red, host_pinger, servidores, clusters):
    """Envia pings iniciales para poblar ARP y tablas de enrutamiento."""
    escribir_log("Inicializando rutas...")

    for serv in servidores:
        comando_host(host_pinger, "ping -c 2 -W 1 {} > /dev/null 2>&1".format(serv.IP()))

    for cluster in clusters[:3]:
        for h in cluster[:3]:
            for serv in servidores:
                comando_host(h, "ping -c 1 -W 1 {} > /dev/null 2>&1".format(serv.IP()))

    time.sleep(2)

    todo_ok = True
    for serv in servidores:
        out = comando_host(host_pinger, "ping -c 2 -W 2 {}".format(serv.IP()))
        if "2 received" in out or "2 packets received" in out:
            escribir_log("Conectividad OK: {} -> {}".format(host_pinger.name, serv.IP()))
        else:
            escribir_log("ADVERTENCIA: conectividad limitada {} -> {}".format(host_pinger.name, serv.IP()))
            todo_ok = False

    return todo_ok


# ==========================================================
# Guardar resultados
# ==========================================================
def guardar_resultados_ping(log_ping):
    """Guarda el log de pings en CSV simple."""
    asegurar_directorio_resultados()
    with open(ARCHIVO_PING, "w", encoding="utf-8") as f:
        f.write("FASE,CICLO,INTENTO,PING_NUM,LATENCIA\n")
        for linea in log_ping:
            f.write(linea + "\n")
    escribir_log("Resultados de ping guardados en {}".format(ARCHIVO_PING))


def generar_resumen(log_ping):
    """Genera un resumen estadistico de latencias por fase."""
    from collections import defaultdict
    datos_fases = defaultdict(list)

    for linea in log_ping:
        partes = linea.strip().split(",")
        if len(partes) < 5:
            continue
        fase     = partes[0]
        latencia = partes[4]
        try:
            lat_val = float(latencia)
            datos_fases[fase].append(lat_val)
        except:
            pass

    lineas_resumen = []
    orden_fases = ["NORMAL", "SIN_MITIGACION", "SOLO_UMBRAL", "SOLO_LIMITE_TASA", "SOLO_BAN", "TODAS_LAS_MITIGACIONES"]

    for fase in orden_fases:
        valores = datos_fases.get(fase, [])
        if valores:
            ordenados = sorted(valores)
            n         = len(ordenados)
            promedio  = sum(valores) / n
            mediana   = ordenados[n // 2]
            p95       = ordenados[int(0.95 * n) - 1] if n >= 20 else max(ordenados)
            minimo    = min(ordenados)
            maximo    = max(ordenados)
            lineas_resumen.append(
                "{}: n={}, prom={:.2f}ms, mediana={:.2f}ms, p95={:.2f}ms, min={:.2f}ms, max={:.2f}ms".format(
                    fase, n, promedio, mediana, p95, minimo, maximo
                )
            )
        else:
            lineas_resumen.append("{}: sin datos".format(fase))

    with open(ARCHIVO_RESUMEN, "w", encoding="utf-8") as f:
        for linea in lineas_resumen:
            f.write(linea + "\n")

    escribir_log("\n=== RESUMEN FINAL ===")
    for linea in lineas_resumen:
        escribir_log(linea)
    escribir_log("=====================\n")


# ==========================================================
# Experimento principal
# ==========================================================
def ejecutar_experimento():
    sobrescribir_archivos_log()

    escribir_log("=" * 70)
    escribir_log("EXPERIMENTO SDN DDoS - MITIGACIONES (ATAQUE POR FASE, BANDERAS DE MITIGACION)")
    escribir_log("=" * 70)
    escribir_log("Configuracion:")
    escribir_log("  - Ciclos: {}".format(CICLOS))
    escribir_log("  - Clusters: {} x {} hosts = {} atacantes".format(
        NUM_CLUSTERS, HOSTS_POR_CLUSTER, NUM_CLUSTERS * HOSTS_POR_CLUSTER))
    escribir_log("  - Iperf: {} conexiones/host, UDP {}".format(IPERF_PARALELO, ANCHO_BANDA_UDP))
    escribir_log("  - Deteccion: umbral {} timeouts de ping + procesos iperf".format(
        UMBRAL_TIMEOUTS_PING_CONSECUTIVOS))
    escribir_log("  - Duracion fase de ataque: {} s".format(DURACION_FASE_ATAQUE))
    escribir_log("  - BANDERAS DE MITIGACION:")
    escribir_log("      UMBRAL_ACTIVADO       = {}".format(UMBRAL_ACTIVADO))
    escribir_log("      LIMITE_TASA_ACTIVADO  = {}".format(LIMITE_TASA_ACTIVADO))
    escribir_log("      BAN_ACTIVADO          = {} (DURACION_BAN_SEGUNDOS = {})".format(
        BAN_ACTIVADO, DURACION_BAN_SEGUNDOS))
    escribir_log("=" * 70)

    red = None
    try:
        hay_ctrl, puerto_usado = verificar_ryu_en_ejecucion(RYU_HOST, RYU_PORTS)
        if hay_ctrl:
            escribir_log("Controlador Ryu detectado en el puerto {}".format(puerto_usado))
        else:
            escribir_log("No se detecto controlador Ryu, usando modo standalone")
            puerto_usado = 6653

        red, host_pinger, servidores, clusters, switches_hoja = construir_topologia_universidad(
            ip_controlador=RYU_HOST,
            puerto_controlador=puerto_usado,
            hay_controlador=hay_ctrl
        )

        configurar_controlador_y_protocolo(red, RYU_HOST, puerto_usado, hay_ctrl)
        instalar_flows_iniciales(red)
        time.sleep(2)

        servidor_objetivo = servidores[0]
        ip_servidor = servidor_objetivo.IP()
        escribir_log("Servidor objetivo: {} ({})".format(servidor_objetivo.name, ip_servidor))

        if not inicializar_rutas_red(red, host_pinger, servidores, clusters):
            escribir_log("ADVERTENCIA: conectividad no perfecta, se continua de todas formas")

        escribir_log("\n=== VERIFICACION DE CONECTIVIDAD ===")
        atacante_prueba = clusters[0][0]
        escribir_log("Verificacion desde {} hacia {}".format(atacante_prueba.name, ip_servidor))

        out_prueba = comando_host(
            atacante_prueba,
            "timeout 3 iperf -c {} -p {} -t 1 2>&1".format(ip_servidor, TCP_PORT)
        )
        if "connected" in out_prueba.lower() or "bits/sec" in out_prueba.lower():
            escribir_log("  TCP: OK")
        else:
            escribir_log("  TCP: FALLO - {}".format(out_prueba[:200]))

        out_prueba = comando_host(
            atacante_prueba,
            "timeout 3 iperf -c {} -u -p {} -t 1 -b 10M 2>&1".format(ip_servidor, UDP_PORT)
        )
        if "connected" in out_prueba.lower() or "bits/sec" in out_prueba.lower():
            escribir_log("  UDP: OK")
        else:
            escribir_log("  UDP: FALLO - {}".format(out_prueba[:200]))
        escribir_log("================================\n")

        if not iniciar_servidores_iperf(servidor_objetivo):
            escribir_log("ERROR: no se pudieron iniciar los servidores iperf")
            return

        # Construir whitelist (cc + servidores; NO clusters, NO maestro)
        ips_whitelist = construir_whitelist(host_pinger, servidores)

        # IPs "atacantes" = todos los hosts de clusters que NO estan en la whitelist
        ips_atacantes, mapa_ips_cluster = recopilar_ips_atacantes(clusters, ips_whitelist)

        # Para la mitigacion por UMBRAL seguimos usando el cluster 4
        ips_cluster4 = mapa_ips_cluster.get(ID_CLUSTER_UMBRAL, [])

        escribir_log("\nIniciando experimento con {} ciclo(s)...\n".format(CICLOS))

        log_ping       = []
        intento_global = 1

        # --------------------------------------------------
        # Helper interno: ejecuta una fase con ataque
        # --------------------------------------------------
        def ejecutar_fase_con_ataque(nombre_fase, usar_umbral, usar_limite_tasa, usar_ban):
            nonlocal intento_global

            escribir_log("\n--- FASE: {} ---".format(nombre_fase))

            # Asegurar limpieza total antes de comenzar
            detener_ataque_ddos(clusters)
            limpiar_todas_las_mitigaciones(red, ips_atacantes, ips_cluster4, switches_hoja, ip_servidor)
            time.sleep(1.0)

            # Lanzar ataque TCP + UDP para esta fase
            lanzar_ataque_ddos(clusters, ip_servidor, DURACION_FASE_ATAQUE, usar_udp=False)
            lanzar_ataque_ddos(clusters, ip_servidor, DURACION_FASE_ATAQUE, usar_udp=True)

            # Prechequeo previo (3 pings)
            ataque_detectado = prechequeo_fase(
                nombre_fase,
                espera_ataque=True,
                host_pinger=host_pinger,
                ip_servidor=ip_servidor,
                clusters=clusters
            )
            escribir_log("PRECHEQUEO {}: ataque_detectado={}".format(nombre_fase, ataque_detectado))

            # Hilo de monitor de ping (para logging del detector clasico)
            evento_ping_fallidos = threading.Event()
            evento_detener_mp    = threading.Event()
            hilo_mp = threading.Thread(
                target=hilo_monitor_ping,
                args=(evento_detener_mp, evento_ping_fallidos, host_pinger, ip_servidor),
                daemon=True
            )
            hilo_mp.start()

            # Dejar que el ataque cargue
            time.sleep(4)

            # ============================================
            # CRITERIO UNICO DE ACTIVACION (tipo BAN):
            #   "malo" = timeout o latencia >= UMBRAL_LATENCIA_BAN_MS
            #   activar mitigaciones al tener UMBRAL_TIMEOUTS_PING_CONSECUTIVOS malos
            # ============================================
            resultados          = []
            timeouts_totales    = 0
            consecutivos_malos  = 0
            mitigacion_aplicada = False

            for num_ping in range(1, CANTIDAD_PINGS + 1):
                try:
                    out = comando_host(host_pinger, "ping -c 1 -W 2 {}".format(ip_servidor))
                    lat = parsear_salida_ping(out)
                except Exception as e:
                    escribir_log("Error en ping {}: {}".format(nombre_fase, repr(e)))
                    lat = None

                if lat is None:
                    resultados.append("timeout")
                    es_malo = True
                    timeouts_totales += 1
                else:
                    resultados.append(lat)
                    es_malo = (lat >= UMBRAL_LATENCIA_BAN_MS)

                if es_malo:
                    consecutivos_malos += 1
                else:
                    consecutivos_malos = 0

                # Activar mitigaciones cuando se cumpla el criterio
                if (not mitigacion_aplicada) and consecutivos_malos >= UMBRAL_TIMEOUTS_PING_CONSECUTIVOS:
                    escribir_log(
                        "{}: se ACTIVAN mitigaciones por {} pings malos consecutivos (umbral={} ms)".format(
                            nombre_fase, UMBRAL_TIMEOUTS_PING_CONSECUTIVOS, UMBRAL_LATENCIA_BAN_MS
                        )
                    )

                    if usar_umbral and UMBRAL_ACTIVADO:
                        aplicar_mitigacion_umbral(red, ips_cluster4, ip_servidor)
                    if usar_limite_tasa and LIMITE_TASA_ACTIVADO:
                        aplicar_mitigacion_limite_tasa(red, ips_atacantes, switches_hoja, ip_servidor)
                    if usar_ban and BAN_ACTIVADO:
                        aplicar_mitigacion_ban(red, ips_atacantes, switches_hoja, ip_servidor, DURACION_BAN_SEGUNDOS)

                    mitigacion_aplicada = True
                    time.sleep(2)

                if (num_ping % 10) == 0:
                    escribir_log("PING {}: {}/{} (ultimo={})".format(
                        nombre_fase, num_ping, CANTIDAD_PINGS, resultados[-1]
                    ))

                time.sleep(RETARDO_ENTRE_PINGS)

            # =============================
            # Log y guardado por fase
            # =============================
            latencias_validas = [r for r in resultados if isinstance(r, (int, float))]
            if latencias_validas:
                promedio = sum(latencias_validas) / len(latencias_validas)
                escribir_log("{}: prom={:.2f}ms, timeouts={}/{}".format(
                    nombre_fase, promedio, timeouts_totales, len(resultados)))
            else:
                escribir_log("{}: TODOS TIMEOUTS ({}/{})".format(
                    nombre_fase, timeouts_totales, len(resultados)))

            vivo_despues, procesos_despues, hosts_despues = ataque_sigue_activo(clusters)
            escribir_log("{} DESPUES DE PINGS: ataque_activo={} procesos={} hosts={}".format(
                nombre_fase, vivo_despues, procesos_despues, hosts_despues))

            for i, lat in enumerate(resultados, 1):
                log_ping.append("{},{},{},{},{}".format(
                    nombre_fase, ciclo, intento_global, i, lat))

            intento_global += 1

            # Limpiar al final de la fase
            evento_detener_mp.set()
            hilo_mp.join(timeout=1)

            detener_ataque_ddos(clusters)
            limpiar_todas_las_mitigaciones(red, ips_atacantes, ips_cluster4, switches_hoja, ip_servidor)

            time.sleep(DESCANSO_ENTRE_FASES_SEG)

        # =====================================
        # Ciclos
        # =====================================
        for ciclo in range(1, CICLOS + 1):
            escribir_log("\n" + "=" * 70)
            escribir_log("CICLO {}/{}".format(ciclo, CICLOS))
            escribir_log("=" * 70 + "\n")

            # FASE NORMAL (sin ataque)
            escribir_log("\n--- FASE: NORMAL (sin ataque) ---")

            detener_ataque_ddos(clusters)
            limpiar_todas_las_mitigaciones(red, ips_atacantes, ips_cluster4, switches_hoja, ip_servidor)
            time.sleep(1.0)

            ataque_detectado_normal = prechequeo_fase(
                "NORMAL",
                espera_ataque=False,
                host_pinger=host_pinger,
                ip_servidor=ip_servidor,
                clusters=clusters
            )
            if ataque_detectado_normal:
                escribir_log("ADVERTENCIA: ataque detectado durante prechequeo NORMAL, forzando limpieza extra...")
                for intento in range(1, 4):
                    detener_ataque_ddos(clusters)
                    time.sleep(1.0)
                    vivo_despues, procesos_despues, hosts_despues = ataque_sigue_activo(clusters)
                    escribir_log(
                        "POST-NORMAL-LIMPIEZA intento {}: activo={} procesos={} hosts={}".format(
                            intento, vivo_despues, procesos_despues, hosts_despues
                        )
                    )
                    if not vivo_despues:
                        break

            resultados, timeouts = ejecutar_prueba_ping(
                host_pinger, ip_servidor, CANTIDAD_PINGS, RETARDO_ENTRE_PINGS, "NORMAL"
            )
            latencias_validas = [r for r in resultados if isinstance(r, (int, float))]
            if latencias_validas:
                promedio = sum(latencias_validas) / len(latencias_validas)
                escribir_log("NORMAL: prom={:.2f}ms, timeouts={}/{}".format(
                    promedio, timeouts, CANTIDAD_PINGS))

            for i, lat in enumerate(resultados, 1):
                log_ping.append("NORMAL,{},{},{},{}".format(ciclo, intento_global, i, lat))
            intento_global += 1

            time.sleep(3)

            # Fases con ataque

            # SIN_MITIGACION: siempre se ejecuta
            ejecutar_fase_con_ataque(
                "SIN_MITIGACION",
                usar_umbral=False,
                usar_limite_tasa=False,
                usar_ban=False
            )

            # SOLO_UMBRAL
            if UMBRAL_ACTIVADO:
                ejecutar_fase_con_ataque(
                    "SOLO_UMBRAL",
                    usar_umbral=True,
                    usar_limite_tasa=False,
                    usar_ban=False
                )
            else:
                escribir_log("FASE SOLO_UMBRAL omitida porque UMBRAL_ACTIVADO = 0")

            # SOLO_LIMITE_TASA
            if LIMITE_TASA_ACTIVADO:
                ejecutar_fase_con_ataque(
                    "SOLO_LIMITE_TASA",
                    usar_umbral=False,
                    usar_limite_tasa=True,
                    usar_ban=False
                )
            else:
                escribir_log("FASE SOLO_LIMITE_TASA omitida porque LIMITE_TASA_ACTIVADO = 0")

            # SOLO_BAN
            if BAN_ACTIVADO:
                ejecutar_fase_con_ataque(
                    "SOLO_BAN",
                    usar_umbral=False,
                    usar_limite_tasa=False,
                    usar_ban=True
                )
            else:
                escribir_log("FASE SOLO_BAN omitida porque BAN_ACTIVADO = 0")

            # TODAS_LAS_MITIGACIONES (si hay al menos 2 activas)
            cantidad_activas = int(bool(UMBRAL_ACTIVADO)) + int(bool(LIMITE_TASA_ACTIVADO)) + int(bool(BAN_ACTIVADO))
            usar_umbral_todas      = bool(UMBRAL_ACTIVADO)
            usar_limite_tasa_todas = bool(LIMITE_TASA_ACTIVADO)
            usar_ban_todas         = bool(BAN_ACTIVADO)

            if cantidad_activas >= 2:
                ejecutar_fase_con_ataque(
                    "TODAS_LAS_MITIGACIONES",
                    usar_umbral=usar_umbral_todas,
                    usar_limite_tasa=usar_limite_tasa_todas,
                    usar_ban=usar_ban_todas
                )
            else:
                escribir_log("FASE TODAS_LAS_MITIGACIONES omitida porque menos de dos mitigaciones estan activadas")

            escribir_log("\n" + "=" * 70)
            escribir_log("FIN CICLO {}/{}".format(ciclo, CICLOS))
            escribir_log("=" * 70 + "\n")

            if ciclo < CICLOS:
                time.sleep(DESCANSO_ENTRE_CICLOS_SEG)

        guardar_resultados_ping(log_ping)
        generar_resumen(log_ping)

        escribir_log("\n" + "=" * 70)
        escribir_log("EXPERIMENTO COMPLETADO")
        escribir_log("Resultados en: {}".format(DIRECTORIO_RESULTADOS))
        escribir_log("=" * 70)

    except Exception:
        escribir_log("ERROR EN EXPERIMENTO: {}".format(traceback.format_exc()))

    finally:
        if red:
            escribir_log("\nDeteniendo red...")
            try:
                red.stop()
            except:
                pass

# ==========================================================
# MAIN
# ==========================================================
if __name__ == "__main__":
    setLogLevel("info")
    ejecutar_experimento()