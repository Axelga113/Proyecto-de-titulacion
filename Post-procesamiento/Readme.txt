# Graficador de latencias NORMAL vs DDoS (ping.txt)

Este script en Python toma el archivo `ping.txt` generado por el experimento de la red SDN y produce dos graficos comparando la latencia en fase **NORMAL** vs fase **DDoS** (`DDoS_COORD`).

Sirve para el análisis estadístico de resultados en la tesis.

---

Instalación numpy:

pip install pandas matplotlib numpy
---

## 1. Entradas y formato de datos

El script espera un archivo:

- `ping.txt`

Formato esperado:

FASE,CICLO,INTENTO,PING_NUM,LATENCIA

Ejemplos:

NORMAL,1,1,1,18.5
NORMAL,1,1,2,19.1
DDoS_COORD,1,2,1,450.3
DDoS_COORD,1,2,2,timeout


Significado de cada campo:

- `FASE`  
  Nombre de la fase (ej: `NORMAL`, `DDoS_COORD`).

- `CICLO`  
  Número de ciclo experimental (entero).

- `INTENTO`  
  Identificador interno de medición (entero).

- `PING_NUM`  
  Número de ping dentro del intento (entero).

- `LATENCIA`  
  - valor numérico en milisegundos, o  
  - `timeout` si no hubo respuesta.

El script convierte `timeout` en `None` y lo excluye del promedio general.

---

## 2. Archivos de salida generados

El script produce dos imágenes:

### 1) `secuencia_espanol_completo.png`

Contiene:

- línea de promedio por número de ping,
- bandas de desviación estándar ±1σ,
- promedio global de cada fase,
- anotaciones visuales,
- transición marcada entre NORMAL → DDoS.

### 2) `secuencia_espanol_simple.png`

Versión simplificada:

- promedio NORMAL,
- promedio DDoS,
- línea de transición,
- sin bandas ni anotaciones complejas.

Útil para presentaciones.

---

## 3. Dependencias

### Software necesario:

- Python 3.x

### Bibliotecas requeridas:

- `pandas`
- `matplotlib`
- `numpy`
- `pathlib` (incluida en Python estándar)

GRAFICADOR DE SECUENCIA NORMAL -> DDoS

Cargando datos desde: ./ping.txt
Datos cargados: XXX registros
Ciclos NORMAL: N
Ciclos DDoS: M

Generando graficos...
Guardado: secuencia_espanol_completo.png
Guardado: secuencia_espanol_simple.png


---

## 5. Estructura del código

### 5.1. `cargar_datos_ping()`

- Lee `ping.txt`.
- Divide por comas.
- Convierte valores numéricos.
- Reemplaza `timeout` por `None`.
- Devuelve un `DataFrame` con:

fase
ciclo
intento
ping_numero
latencia_ms

---

### 5.2. `graficar_promedios_lineas_continuas(df)`

- Calcula promedios por número de ping.
- Calcula desviación estándar por ping.
- Produce un gráfico continuo:

NORMAL → DDoS


Incluye:

- líneas gruesas,
- bandas ±1σ,
- límites automáticos,
- anotaciones con promedio,
- línea de transición.

Imprime en consola:

- promedio de latencias,
- desviaciones estándar medias,
- porcentaje de incremento entre NORMAL y DDoS.

---

### 5.3. `graficar_comparacion_simple(df)`

Versión más limpia:

- curva NORMAL,
- curva DDoS,
- transición marcada,
- sin bandas de desviación.

Recomendado para diapositivas.

---

### 5.4. `main()`

Realiza:

1. Carga de datos.
2. Reporte básico en consola.
3. Generación de:
   - `secuencia_espanol_completo.png`
   - `secuencia_espanol_simple.png`
4. Llamado a `plt.show()` para ver las figuras.

---

## 6. Uso en la tesis

Este script permite:

- Visualizar la degradación de latencia provocada por un DDoS.
- Comparar la estabilidad temporal del ping.
- Mostrar el aumento de dispersión bajo ataque.
- Servir como base para comparar mitigaciones (UMBRAL, RATE LIMIT, BAN).
- Integrarlo en anexos o análisis estadístico del capítulo de resultados.

---

## 7. Referencias técnicas de las librerías

- Pandas:  
  https://pandas.pydata.org/docs/

- Matplotlib:  
  https://matplotlib.org/stable/users/index.html

- Numpy:  
  https://numpy.org/doc/

- Pathlib (documentación Python):  
  https://docs.python.org/3/library/pathlib.html

