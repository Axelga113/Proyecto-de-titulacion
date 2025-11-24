#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
graficar_promedios_espanol.py - Grafica promedios NORMAL y DDoS en español
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

def cargar_datos_ping():
    """Carga datos de ping.txt desde la misma carpeta del script"""
    script_dir = Path(__file__).parent
    ping_path = script_dir / "ping.txt"
    
    if not ping_path.exists():
        print(f"❌ No se encontró ping.txt en: {ping_path}")
        return None
    
    print(f"📁 Cargando datos desde: {ping_path}")
    
    datos = []
    with open(ping_path, 'r') as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
                
            partes = linea.split(',')
            if len(partes) >= 5:
                try:
                    fase = partes[0]
                    ciclo = int(partes[1])
                    intento = int(partes[2])
                    ping_numero = int(partes[3])
                    
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
                except ValueError:
                    continue
    
    return pd.DataFrame(datos)

def graficar_promedios_lineas_continuas(df):
    """Grafica promedios con líneas continuas en español"""
    
    # Filtrar datos válidos
    df_valido = df[df['latencia_ms'].notna()].copy()
    
    # Calcular promedios por número de ping para cada fase
    normal_promedio = df_valido[df_valido['fase'] == 'NORMAL'].groupby('ping_numero')['latencia_ms'].mean()
    ddos_promedio = df_valido[df_valido['fase'] == 'DDoS_COORD'].groupby('ping_numero')['latencia_ms'].mean()
    
    # Crear secuencia continua
    x_normal = range(len(normal_promedio))
    x_ddos = range(len(normal_promedio), len(normal_promedio) + len(ddos_promedio))
    
    # Crear gráfico
    plt.figure(figsize=(14, 8))
    
    # Graficar líneas continuas
    linea_normal, = plt.plot(x_normal, normal_promedio.values, 
                             color='green', linewidth=3, label='NORMAL (promedio)')
    linea_ddos, = plt.plot(x_ddos, ddos_promedio.values, 
                           color='red', linewidth=3, label='DDoS (promedio)')
    
    # Línea vertical de separación
    separacion_x = len(normal_promedio) - 0.5
    plt.axvline(x=separacion_x, color='blue', linestyle='--', 
                alpha=0.7, linewidth=2, label='Transición')
    
    # Calcular estadísticas
    promedio_normal = normal_promedio.mean()
    promedio_ddos = ddos_promedio.mean()
    std_normal = df_valido[df_valido['fase'] == 'NORMAL'].groupby('ping_numero')['latencia_ms'].std().fillna(0)
    std_ddos = df_valido[df_valido['fase'] == 'DDoS_COORD'].groupby('ping_numero')['latencia_ms'].std().fillna(0)
    
    # Añadir áreas de desviación estándar
    plt.fill_between(x_normal, 
                    normal_promedio - std_normal, 
                    normal_promedio + std_normal, 
                    alpha=0.2, color='green', label='±1σ NORMAL')
    
    plt.fill_between(x_ddos, 
                    ddos_promedio - std_ddos, 
                    ddos_promedio + std_ddos, 
                    alpha=0.2, color='red', label='±1σ DDoS')
    
    # Añadir líneas horizontales para los promedios generales
    plt.axhline(y=promedio_normal, color='green', linestyle=':', alpha=0.5, linewidth=1)
    plt.axhline(y=promedio_ddos, color='red', linestyle=':', alpha=0.5, linewidth=1)
    
    # Añadir anotaciones en español
    plt.annotate(f'Promedio NORMAL: {promedio_normal:.2f} ms', 
                xy=(len(normal_promedio)/2, promedio_normal), 
                xytext=(0, 15), textcoords='offset points',
                ha='center',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgreen', alpha=0.8),
                fontsize=11, fontweight='bold')
    
    plt.annotate(f'Promedio DDoS: {promedio_ddos:.2f} ms', 
                xy=(len(normal_promedio) + len(ddos_promedio)/2, promedio_ddos), 
                xytext=(0, 15), textcoords='offset points',
                ha='center',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='lightcoral', alpha=0.8),
                fontsize=11, fontweight='bold')
    
    # Configurar el gráfico en español
    plt.xlabel('Número de Ping en Secuencia', fontsize=12, fontweight='bold')
    plt.ylabel('Latencia (milisegundos)', fontsize=12, fontweight='bold')
    plt.title('Evolución de Latencia: Promedio NORMAL → DDoS\n(Todos los Ciclos Combinados)', 
              fontsize=14, fontweight='bold', pad=20)
    
    plt.legend(fontsize=11, loc='upper right')
    plt.grid(True, alpha=0.3)
    
    # Configurar eje X más limpio
    xticks = [0, len(normal_promedio)-1, len(normal_promedio), len(normal_promedio) + len(ddos_promedio)-1]
    xticklabels = ['Inicio\nNORMAL', 'Fin\nNORMAL', 'Inicio\nDDoS', 'Fin\nDDoS']
    plt.xticks(xticks, xticklabels, fontsize=10)
    
    # Ajustar límites del eje Y para mejor visualización
    y_min = min(normal_promedio.min(), ddos_promedio.min()) * 0.8
    y_max = max(normal_promedio.max(), ddos_promedio.max()) * 1.2
    plt.ylim(y_min, y_max)
    
    # Mostrar estadísticas en consola
    print(f"📊 ESTADÍSTICAS:")
    print(f"   NORMAL: {promedio_normal:.2f} ± {std_normal.mean():.2f} ms")
    print(f"   DDoS:   {promedio_ddos:.2f} ± {std_ddos.mean():.2f} ms")
    incremento = ((promedio_ddos - promedio_normal) / promedio_normal * 100)
    print(f"   Incremento: {incremento:+.1f}%")
    
    return plt

def graficar_comparacion_simple(df):
    """Gráfico más simple sin áreas sombreadas"""
    
    df_valido = df[df['latencia_ms'].notna()].copy()
    
    normal_promedio = df_valido[df_valido['fase'] == 'NORMAL'].groupby('ping_numero')['latencia_ms'].mean()
    ddos_promedio = df_valido[df_valido['fase'] == 'DDoS_COORD'].groupby('ping_numero')['latencia_ms'].mean()
    
    x_normal = range(len(normal_promedio))
    x_ddos = range(len(normal_promedio), len(normal_promedio) + len(ddos_promedio))
    
    plt.figure(figsize=(14, 8))
    
    # Líneas continuas y suaves
    plt.plot(x_normal, normal_promedio.values, 
             color='green', linewidth=4, label='NORMAL (promedio)')
    plt.plot(x_ddos, ddos_promedio.values, 
             color='red', linewidth=4, label='DDoS (promedio)')
    
    # Línea de transición
    separacion_x = len(normal_promedio) - 0.5
    plt.axvline(x=separacion_x, color='blue', linestyle='--', 
                alpha=0.8, linewidth=2, label='Transición NORMAL → DDoS')
    
    # Configuración en español
    plt.xlabel('Secuencia de Mediciones de Ping', fontsize=12, fontweight='bold')
    plt.ylabel('Latencia (ms)', fontsize=12, fontweight='bold')
    plt.title('Comparación de Latencia: Fase Normal vs Ataque DDoS', 
              fontsize=14, fontweight='bold', pad=20)
    
    plt.legend(fontsize=11)
    plt.grid(True, alpha=0.3)
    
    # Eje X simplificado
    plt.xticks([0, separacion_x, len(x_normal) + len(x_ddos) - 1], 
               ['Inicio\nNORMAL', 'Transición', 'Fin\nDDoS'], 
               fontsize=10)
    
    return plt

def main():
    """Función principal"""
    print("📈 GRAFICADOR DE SECUENCIA NORMAL → DDoS (ESPAÑOL)")
    print("=" * 55)
    
    # Cargar datos
    df = cargar_datos_ping()
    if df is None or df.empty:
        print("❌ No se pudieron cargar datos")
        return
    
    print(f"✅ Datos cargados: {len(df)} registros")
    print(f"🔄 Ciclos NORMAL: {df[df['fase'] == 'NORMAL']['ciclo'].nunique()}")
    print(f"🔥 Ciclos DDoS: {df[df['fase'] == 'DDoS_COORD']['ciclo'].nunique()}")
    
    # Generar gráficos
    print("\n🎨 Generando gráficos en español...")
    
    # Gráfico 1: Con áreas de desviación
    plt1 = graficar_promedios_lineas_continuas(df)
    plt1.savefig('secuencia_espanol_completo.png', dpi=300, bbox_inches='tight')
    print("✅ Guardado: secuencia_espanol_completo.png")
    
    # Gráfico 2: Versión simple
    plt2 = graficar_comparacion_simple(df)
    plt2.savefig('secuencia_espanol_simple.png', dpi=300, bbox_inches='tight')
    print("✅ Guardado: secuencia_espanol_simple.png")
    
    # Mostrar gráficos
    plt.show()

if __name__ == "__main__":
    main()