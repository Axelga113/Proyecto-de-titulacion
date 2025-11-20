#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import OVSBridge      # <- switch en modo bridge, NO OpenFlow
from mininet.link import TCLink
from mininet.log import setLogLevel, info

import os, time, re, traceback

# ==========================================================
# CONFIGURACION GENERAL - EXPERIMENTO RED CONVENCIONAL
# ==========================================================
DIRECTORIO_RESULTADOS   = "resultados_ddos_convencional"
ARCHIVO_PING            = os.path.join(DIRECTORIO_RESULTADOS, "ping_convencional.txt")
ARCHIVO_LOG             = os.path.join(DIRECTORIO_RESULTADOS, "ataque_convencional_log.txt")
ARCHIVO_RESUMEN         = os.path.join(DIRECTORIO_RESULTADOS, "resumen_convencional.txt")

CICLOS = 2 # Cambiar a la cantidad de repeticiones del script deseadas 


# Espera para acabar los procesos

DESCANSO_ENTRE_FASES_SEG  = 5
DESCANSO_ENTRE_CICLOS_SEG = 8
CONSOLA_DETALLADA = True

# Ataque por fase
DURACION_FASE_ATAQUE = 600  # segundos

# Topologia (mismos parametros que en la red SDN para comparar)
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
IPERF_PARALELO  = 8 # Atacantes en paralelo, requiere mejor CPU
ANCHO_BANDA_UDP = "80M" # Ancho volumetríco del ataque

CANTIDAD_PINGS      = 40
RETARDO_ENTRE_PINGS = 0.2


# ==========================================================
# Utilidades de logging
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
    for p in (ARCHIVO_PING, ARCHIVO_LOG, ARCHIVO_RESUMEN):
        open(p, "w", encoding="utf-8").close()


# ==========================================================
# Parseo de salida de ping
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
            out = host_origen.cmd("ping -c 1 -W 2 {}".format(ip_destino))
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


# ==========================================================
# Servidores iperf
# ==========================================================
def iniciar_servidores_iperf(host):
    """Inicia servidores iperf TCP y UDP en el host servidor."""
    host.cmd("pkill -f '^iperf -s' || true")
    host.cmd("ulimit -n 65535; nohup iperf -s -p {} > /tmp/iperf_tcp.log 2>&1 &".format(TCP_PORT))
    host.cmd("ulimit -n 65535; nohup iperf -s -u -p {} > /tmp/iperf_udp.log 2>&1 &".format(UDP_PORT))
    time.sleep(2)

    out = host.cmd("netstat -tuln | egrep ':{}|:{}'".format(TCP_PORT, UDP_PORT))
    tcp_ok = ":{}".format(TCP_PORT) in out
    udp_ok = ":{}".format(UDP_PORT) in out

    if tcp_ok and udp_ok:
        escribir_log("Servidores iperf TCP/UDP iniciados")
        return True
    else:
        escribir_log("ERROR: servidores iperf no estan escuchando")
        return False


# ==========================================================
# Lanzar y detener ataque DDoS
# ==========================================================
def lanzar_ataque_ddos(clusters, ip_destino, duracion_seg, usar_udp=False):
    """Lanza el ataque DDoS (TCP o UDP) desde todos los atacantes."""
    modo = "UDP" if usar_udp else "TCP"

    total_hosts = sum(len(c) for c in clusters)
    escribir_log("Lanzando ataque {}: {} hosts x {} conexiones = {} conexiones totales (t={}s)".format(
        modo, total_hosts, IPERF_PARALELO, total_hosts * IPERF_PARALELO, duracion_seg))

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
            try:
                h.cmd(cmd)
                exitosos += 1
            except Exception as e:
                fallidos += 1
                escribir_log("Error iniciando ataque en {}: {}".format(h.name, repr(e)))

    escribir_log("Ataque {} iniciado: {} hosts OK, {} errores".format(modo, exitosos, fallidos))

    time.sleep(0.5)
    host_muestra = clusters[0][0]
    ps_out = host_muestra.cmd("ps aux | grep iperf | grep -v grep")
    corriendo = len([l for l in ps_out.splitlines() if 'iperf -c' in l])
    escribir_log("Revision: {} procesos iperf en {}".format(corriendo, host_muestra.name))


def detener_ataque_ddos(clusters):
    """Detiene todos los procesos iperf de los hosts atacantes."""
    for cluster in clusters:
        for h in cluster:
            h.cmd("killall -9 iperf 2>/dev/null || true")
            h.cmd(
                "ps aux | grep 'iperf -c' | grep -v grep | "
                "awk '{print $2}' | xargs -r kill -9 2>/dev/null || true"
            )
    escribir_log("Ataque DDoS detenido (killall iperf en todos los hosts atacantes)")


# ==========================================================
# Topologia CONVENCIONAL SIMPLE (sin bucles)
# ==========================================================
def construir_topologia_convencional_simple():
    """
    Topologia convencional simplificada (sin bucles):
      - s100: switch nucleo.
      - s101: switch de servidores, conectado a s100.
      - Serv_1, Serv_2 y cc colgados de s101.
      - 5 switches hoja (sLeaf1..sLeaf5) conectados a s100, con 10 atacantes cada uno.
    Sin controlador, sin OpenFlow, solo switches de aprendizaje (OVSBridge).
    """
    red = Mininet(controller=None, link=TCLink, switch=OVSBridge, build=False)

    # Switch nucleo y switch de servidores
    sCORE = red.addSwitch("s100")
    sServ = red.addSwitch("s101")

    # Enlace entre nucleo y switch de servidores
    red.addLink(sCORE, sServ, bw=ANCHO_BANDA_NUCLEO, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    # Host cliente (cc)
    cc = red.addHost("cc", ip="{}150/24".format(IP_BASE_SERV))
    red.addLink(cc, sServ, bw=ANCHO_BANDA_HOST, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    # Servidores
    serv1 = red.addHost("Serv_1", ip="{}10/24".format(IP_BASE_SERV))
    red.addLink(serv1, sServ, bw=ANCHO_BANDA_NUCLEO, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    serv2 = red.addHost("Serv_2", ip="{}11/24".format(IP_BASE_SERV))
    red.addLink(serv2, sServ, bw=ANCHO_BANDA_NUCLEO, delay="1ms", max_queue_size=TAMANO_MAX_COLA)

    # Switches hoja y atacantes
    clusters = []

    for id_cluster in range(1, NUM_CLUSTERS + 1):
        nombre_hoja = "sLeaf{}".format(id_cluster)
        sw_hoja = red.addSwitch(nombre_hoja)

        # Conectar hoja al nucleo
        red.addLink(
            sw_hoja,
            sCORE,
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

    escribir_log("Topologia CONVENCIONAL SIMPLE construida: {} clusters x {} hosts = {} atacantes".format(
        NUM_CLUSTERS, HOSTS_POR_CLUSTER, NUM_CLUSTERS * HOSTS_POR_CLUSTER))

    return red, cc, [serv1, serv2], clusters


# ==========================================================
# Chequeo de conectividad basica
# ==========================================================
def probar_conectividad_basica(cc, servidor, clusters):
    """
    Hace pings basicos de conectividad:
      - cc -> servidor
      - atk1_1 -> servidor

    Si no se recibe ningun ping correcto en cualquiera de los dos, retorna False
    y el experimento NO continua.
    """
    ip_serv = servidor.IP()
    escribir_log("Probando conectividad basica...")

    # cc -> servidor
    out_cc = cc.cmd("ping -c 3 -W 1 {}".format(ip_serv))
    escribir_log("PING BASICO cc -> {}:\n{}".format(ip_serv, out_cc.strip()[:200]))

    ok_cc = ("3 received" in out_cc) or ("3 packets received" in out_cc) or ("1 received" in out_cc)

    # atk1_1 -> servidor
    atacante_prueba = clusters[0][0]
    out_atk = atacante_prueba.cmd("ping -c 3 -W 1 {}".format(ip_serv))
    escribir_log("PING BASICO {} -> {}:\n{}".format(atacante_prueba.name, ip_serv, out_atk.strip()[:200]))

    ok_atk = ("3 received" in out_atk) or ("3 packets received" in out_atk) or ("1 received" in out_atk)

    if not ok_cc or not ok_atk:
        escribir_log("ERROR: conectividad basica fallida (ok_cc={}, ok_atk={}), ABORTANDO experimento".format(
            ok_cc, ok_atk))
        return False

    escribir_log("Conectividad basica OK (cc y {} alcanzan al servidor)".format(atacante_prueba.name))
    return True


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
    orden_fases = ["NORMAL", "SIN_MITIGACION"]

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

    escribir_log("\n=== RESUMEN FINAL CONVENCIONAL ===")
    for linea in lineas_resumen:
        escribir_log(linea)
    escribir_log("==================================\n")


# ==========================================================
# Experimento principal - RED CONVENCIONAL
# ==========================================================
def ejecutar_experimento_convencional():
    sobrescribir_archivos_log()

    escribir_log("=" * 70)
    escribir_log("EXPERIMENTO DDoS EN RED CONVENCIONAL SIMPLE (SIN SDN, SIN MITIGACIONES)")
    escribir_log("=" * 70)
    escribir_log("Configuracion:")
    escribir_log("  - Ciclos: {}".format(CICLOS))
    escribir_log("  - Clusters: {} x {} hosts = {} atacantes".format(
        NUM_CLUSTERS, HOSTS_POR_CLUSTER, NUM_CLUSTERS * HOSTS_POR_CLUSTER))
    escribir_log("  - Iperf: {} conexiones/host, UDP {}".format(IPERF_PARALELO, ANCHO_BANDA_UDP))
    escribir_log("  - Duracion fase de ataque: {} s".format(DURACION_FASE_ATAQUE))
    escribir_log("=" * 70)

    red = None
    try:
        red, host_pinger, servidores, clusters = construir_topologia_convencional_simple()

        servidor_objetivo = servidores[0]
        ip_servidor = servidor_objetivo.IP()
        escribir_log("Servidor objetivo: {} ({})".format(servidor_objetivo.name, ip_servidor))

        # Servidores iperf ANTES de probar nada
        if not iniciar_servidores_iperf(servidor_objetivo):
            escribir_log("ERROR: no se pudieron iniciar los servidores iperf")
            return

        # PINGS BASICOS: si fallan, NO seguimos con el experimento
        if not probar_conectividad_basica(host_pinger, servidor_objetivo, clusters):
            escribir_log("Experimento detenido por falta de conectividad basica.")
            return

        escribir_log("\nIniciando experimento CONVENCIONAL con {} ciclo(s)...\n".format(CICLOS))

        log_ping       = []
        intento_global = 1

        for ciclo in range(1, CICLOS + 1):
            escribir_log("\n" + "=" * 70)
            escribir_log("CICLO {}/{}".format(ciclo, CICLOS))
            escribir_log("=" * 70 + "\n")

            # --------------------------------------------------
            # FASE NORMAL (sin ataque)
            # --------------------------------------------------
            escribir_log("\n--- FASE: NORMAL (sin ataque) ---")

            detener_ataque_ddos(clusters)
            time.sleep(1.0)

            resultados, timeouts = ejecutar_prueba_ping(
                host_pinger, ip_servidor, CANTIDAD_PINGS, RETARDO_ENTRE_PINGS, "NORMAL"
            )
            latencias_validas = [r for r in resultados if isinstance(r, (int, float))]
            if latencias_validas:
                promedio = sum(latencias_validas) / len(latencias_validas)
                escribir_log("NORMAL: prom={:.2f}ms, timeouts={}/{}".format(
                    promedio, timeouts, CANTIDAD_PINGS))
            else:
                escribir_log("NORMAL: TODOS TIMEOUTS ({}/{})".format(
                    timeouts, CANTIDAD_PINGS))

            for i, lat in enumerate(resultados, 1):
                log_ping.append("NORMAL,{},{},{},{}".format(ciclo, intento_global, i, lat))
            intento_global += 1

            time.sleep(DESCANSO_ENTRE_FASES_SEG)

            # --------------------------------------------------
            # FASE SIN_MITIGACION (ataque activo, red convencional)
            # --------------------------------------------------
            nombre_fase = "SIN_MITIGACION"
            escribir_log("\n--- FASE: {} (ataque DDoS, sin mitigaciones) ---".format(nombre_fase))

            detener_ataque_ddos(clusters)
            time.sleep(1.0)

            lanzar_ataque_ddos(clusters, ip_servidor, DURACION_FASE_ATAQUE, usar_udp=False)
            lanzar_ataque_ddos(clusters, ip_servidor, DURACION_FASE_ATAQUE, usar_udp=True)

            time.sleep(4)

            resultados, timeouts = ejecutar_prueba_ping(
                host_pinger, ip_servidor, CANTIDAD_PINGS, RETARDO_ENTRE_PINGS, nombre_fase
            )
            latencias_validas = [r for r in resultados if isinstance(r, (int, float))]
            if latencias_validas:
                promedio = sum(latencias_validas) / len(latencias_validas)
                escribir_log("{}: prom={:.2f}ms, timeouts={}/{}".format(
                    nombre_fase, promedio, timeouts, CANTIDAD_PINGS))
            else:
                escribir_log("{}: TODOS TIMEOUTS ({}/{})".format(
                    nombre_fase, timeouts, CANTIDAD_PINGS))

            for i, lat in enumerate(resultados, 1):
                log_ping.append("{},{},{},{},{}".format(nombre_fase, ciclo, intento_global, i, lat))
            intento_global += 1

            detener_ataque_ddos(clusters)

            escribir_log("\n" + "=" * 70)
            escribir_log("FIN CICLO {}/{}".format(ciclo, CICLOS))
            escribir_log("=" * 70 + "\n")

            if ciclo < CICLOS:
                time.sleep(DESCANSO_ENTRE_CICLOS_SEG)

        guardar_resultados_ping(log_ping)
        generar_resumen(log_ping)

        escribir_log("\n" + "=" * 70)
        escribir_log("EXPERIMENTO CONVENCIONAL COMPLETADO")
        escribir_log("Resultados en: {}".format(DIRECTORIO_RESULTADOS))
        escribir_log("=" * 70)

    except Exception:
        escribir_log("ERROR EN EXPERIMENTO CONVENCIONAL: {}".format(traceback.format_exc()))

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
    ejecutar_experimento_convencional()