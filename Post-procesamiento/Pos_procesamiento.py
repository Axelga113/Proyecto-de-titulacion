#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Grafica resultados NORMAL vs DDoS usando ping.txt como entrada
# Elimina unicode, usa solo "#" en comentarios y mejora la documentación

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

def cargar_datos_ping():
    # Carga el archivo ping.txt y lo convierte en un DataFrame con columnas:
    #   fase, ciclo, intento, ping_numero, latencia_ms
    # Convierte "timeout" en None. Ignora líneas mal formadas.

    script_dir = Path(__file__).parent
    ping_path = script_dir / "ping.txt"
    
    if not ping_path.exists():
        print("No se encontro ping.txt en:", ping_path)
        return None
    
    print("Cargando datos desde:", ping_path)
    
    datos = []
    with open(ping_path, 'r') as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                # Ignorar lineas en blanco
                continue
                
            partes = linea.split(',')
            if len(partes) < 5:
                # Ignorar lineas incompletas
                continue

            try:
                fase = partes[0]
                ciclo = int(partes[1])
                intento = int(partes[2])
                ping_numero = int(partes[3])
                
                # Convertir "timeout" en None
                if partes[4] == "timeout":
                    latencia = None
                else:
                    latencia = float(partes[4])
                
                datos.append({
                    'fase': fase,
                    'ciclo': ciclo,
                    'intento': intento,
                    'ping_numero': ping_numero,
                    'latencia_ms': latencia
                })
            except:
                # Cualquier error en conversion se ignora por seguridad
                continue
    
    return pd.DataFrame(datos)

def graficar_promedios_lineas_continuas(df):
    # Genera la grafica principal:
    #   - Secuencia continua NORMAL -> DDoS
    #   - Promedios por numero de ping
    #   - Bandas de desviacion estandar
    #   - Anotaciones con promedios globales

    # Filtrar datos validos (sin timeouts)
    df_valido = df[df['latencia_ms'].notna()].copy()
    
    # Promedios por ping
    normal_promedio = df_valido[df_valido['fase'] == 'NORMAL'].groupby('ping_numero')['latencia_ms'].mean()
    ddos_promedio = df_valido[df_valido['fase'] == 'DDoS_COORD'].groupby('ping_numero')['latencia_ms'].mean()
    
    # Construir secuencia continua en el eje X
    x_normal = range(len(normal_promedio))
    x_ddos = range(len(normal_promedio), len(normal_promedio) + len(ddos_promedio))
    
    # Crear figura
    plt.figure(figsize=(14, 8))
    
    # Lineas promedio
    plt.plot(x_normal, normal_promedio.values, color='green', linewidth=3, label='NORMAL (promedio)')
    plt.plot(x_ddos, ddos_promedio.values, color='red', linewidth=3, label='DDoS (promedio)')
    
    # Linea de transicion
    separacion_x = len(normal_promedio) - 0.5
    plt.axvline(x=separacion_x, color='blue', linestyle='--', alpha=0.7, linewidth=2, label='Transicion')
    
    # Desviaciones estandar
    std_normal = df_valido[df_valido['fase'] == 'NORMAL'].groupby('ping_numero')['latencia_ms'].std().fillna(0)
    std_ddos = df_valido[df_valido['fase'] == 'DDoS_COORD'].groupby('ping_numero')['latencia_ms'].std().fillna(0)

    plt.fill_between(x_normal, normal_promedio - std_normal, normal_promedio + std_normal,
                     alpha=0.2, color='green', label='Desviacion NORMAL')
    plt.fill_between(x_ddos, ddos_promedio - std_ddos, ddos_promedio + std_ddos,
                     alpha=0.2, color='red', label='Desviacion DDoS')
    
    # Promedios globales
    promedio_normal = normal_promedio.mean()
    promedio_ddos = ddos_promedio.mean()

    # Lineas horizontales
    plt.axhline(promedio_normal, color='green', linestyle=':', alpha=0.5)
    plt.axhline(promedio_ddos, color='red', linestyle=':', alpha=0.5)

    # Anotaciones
    plt.annotate(
        'Promedio NORMAL: {:.2f} ms'.format(promedio_normal),
        xy=(len(normal_promedio) / 2, promedio_normal),
        xytext=(0, 15), textcoords='offset points',
        ha='center',
        bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgreen', alpha=0.8),
        fontsize=10
    )

    plt.annotate(
        'Promedio DDoS: {:.2f} ms'.format(promedio_ddos),
        xy=(len(normal_promedio) + len(ddos_promedio) / 2, promedio_ddos),
        xytext=(0, 15), textcoords='offset points',
        ha='center',
        bbox=dict(boxstyle='round,pad=0.3', facecolor='lightcoral', alpha=0.8),
        fontsize=10
    )
    
    # Configuracion general del grafico
    plt.xlabel('Numero de ping en secuencia')
    plt.ylabel('Latencia (ms)')
    plt.title('Evolucion de latencia: NORMAL -> DDoS (promedio sobre ciclos)')
    plt.legend()
    plt.grid(True, alpha=0.3)

    # Etiquetas del eje X
    xticks = [0, len(normal_promedio) - 1, len(normal_promedio), len(normal_promedio) + len(ddos_promedio) - 1]
    xticklabels = ['Inicio NORMAL', 'Fin NORMAL', 'Inicio DDoS', 'Fin DDoS']
    plt.xticks(xticks, xticklabels)

    # Ajuste dinamico del eje Y
    y_min = min(normal_promedio.min(), ddos_promedio.min()) * 0.8
    y_max = max(normal_promedio.max(), ddos_promedio.max()) * 1.2
    plt.ylim(y_min, y_max)

    # Estadisticas en consola
    print("ESTADISTICAS:")
    print("  NORMAL: {:.2f} ms +/- {:.2f}".format(promedio_normal, std_normal.mean()))
    print("  DDoS:   {:.2f} ms +/- {:.2f}".format(promedio_ddos, std_ddos.mean()))
    incremento = ((promedio_ddos - promedio_normal) / promedio_normal * 100)
    print("  Incremento relativo: {:.1f}%".format(incremento))

    return plt

def graficar_comparacion_simple(df):
    # Genera un grafico simplificado:
    #   - solo curvas de promedio
    #   - sin bandas de desviacion
    #   - con linea de transicion NORMAL -> DDoS

    df_valido = df[df['latencia_ms'].notna()].copy()
    
    normal_promedio = df_valido[df_valido['fase'] == 'NORMAL'].groupby('ping_numero')['latencia_ms'].mean()
    ddos_promedio = df_valido[df_valido['fase'] == 'DDoS_COORD'].groupby('ping_numero')['latencia_ms'].mean()
    
    x_normal = range(len(normal_promedio))
    x_ddos = range(len(normal_promedio), len(normal_promedio) + len(ddos_promedio))
    
    plt.figure(figsize=(14, 8))
    
    plt.plot(x_normal, normal_promedio.values, color='green', linewidth=4, label='NORMAL (promedio)')
    plt.plot(x_ddos, ddos_promedio.values, color='red', linewidth=4, label='DDoS (promedio)')
    
    separacion_x = len(normal_promedio) - 0.5
    plt.axvline(separacion_x, color='blue', linestyle='--', alpha=0.8, linewidth=2,
                label='Transicion NORMAL -> DDoS')
    
    plt.xlabel('Secuencia de pings')
    plt.ylabel('Latencia (ms)')
    plt.title('Comparacion simplificada: NORMAL vs DDoS')
    plt.legend()
    plt.grid(True, alpha=0.3)

    plt.xticks([0, separacion_x, len(normal_promedio) + len(ddos_promedio) - 1],
               ['Inicio NORMAL', 'Transicion', 'Fin DDoS'])

    return plt

def main():
    # Funcion principal:
    #   - Carga datos desde ping.txt
    #   - Genera dos graficos
    #   - Guarda los archivos PNG

    print("GRAFICADOR DE SECUENCIA NORMAL -> DDoS")
    print("-------------------------------------------------------")
    
    df = cargar_datos_ping()
    if df is None or df.empty:
        print("No se pudieron cargar datos.")
        return
    
    print("Datos cargados:", len(df))
    print("Ciclos NORMAL:", df[df['fase'] == 'NORMAL']['ciclo'].nunique())
    print("Ciclos DDoS:", df[df['fase'] == 'DDoS_COORD']['ciclo'].nunique())
    
    print("\nGenerando graficos...")

    plt1 = graficar_promedios_lineas_continuas(df)
    plt1.savefig('secuencia_espanol_completo.png', dpi=300, bbox_inches='tight')
    print("Guardado: secuencia_espanol_completo.png")
    
    plt2 = graficar_comparacion_simple(df)
    plt2.savefig('secuencia_espanol_simple.png', dpi=300, bbox_inches='tight')
    print("Guardado: secuencia_espanol_simple.png")
    
    plt.show()

if __name__ == "__main__":
    main()
