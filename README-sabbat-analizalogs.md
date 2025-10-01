# 📊 `sabbat-analizalogs` - Analizador de Logs Avanzado

> **"Tus logs tienen una historia que contar. `sabbat-analizalogs` la descifra por ti."**

Este proyecto es un **analizador avanzado de logs** escrito en Python 3. Permite procesar archivos de logs (normales o comprimidos en `.gz`) y generar estadísticas útiles como:

- Conteo de errores y advertencias.
- Top IPs con geolocalización (requiere base de datos GeoIP).
- Métodos HTTP y códigos de estado más frecuentes.
- URLs más solicitadas.
- Principales *User-Agents*.
- Detección de actividad sospechosa (SQL Injection, XSS, Path Traversal).
- Rango temporal de los eventos del log.
- Exportación de resultados en texto o JSON.

---

## Características principales

- Soporte de logs comprimidos (`.gz`).
- Lectura desde **stdin** (`-`) para usar en pipelines.
- Filtros temporales con `--since` y `--until`.
- Vista en columnas o en lista (`--vista-lista`).
- Salida en JSON (`--json`) para integración con otras herramientas.
- Guardado en archivo (`--output`).
- Detección básica de intentos de ataque comunes.
- Uso opcional de **GeoIP2** para geolocalizar IPs.

---

## Requisitos

- Python 3.7+
- Librerías:
  ```bash
  pip install -r requirements.txt
  ```
- Base de datos GeoIP (ejemplo: `GeoLite2-Country.mmdb` de MaxMind) en `/var/lib/GeoIP/` o ruta especificada con `--geoip-db`.

---

## Instalación

Clona este repositorio:

```bash
git clone https://github.com/sabbat-cloud/sabbat-utilidades
```

Instala las dependencias:

```bash
pip install -r requirements.txt
```

---

## Uso

### Ejemplos básicos

```bash
# Análisis completo en vista columnas
python3 sabbat-analizalogs access.log

# Análisis completo en vista lista
python3 sabbat-analizalogs access.log --vista-lista

# Búsqueda de un patrón específico
python3 sabbat-analizalogs error.log -p "Timeout" -c 50

# Salida JSON
python3 sabbat-analizalogs app.log --json

# Guardar salida en archivo JSON
python3 sabbat-analizalogsy app.log --json --output resultado.json

# Filtrar logs por fechas
python3 sabbat-analizalogs access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# Usar en un pipeline (leer de stdin)
zcat access.log.gz | python3 sabbat-analizalogs - --json
```

---

## Opciones disponibles

```text
archivo                 Archivo de log a analizar (puede ser .gz o '-' para stdin)

-p, --patron            Patrón específico a buscar
-c, --contar            Número de resultados a mostrar (por defecto 10)
--json                  Muestra la salida en formato JSON
--output                Archivo de salida para guardar resultados
--vista-lista           Muestra resultados como lista en lugar de columnas
--since                 Filtrar logs desde esta fecha (YYYY-MM-DD o 'YYYY-MM-DD HH:MM:SS')
--until                 Filtrar logs hasta esta fecha (YYYY-MM-DD o 'YYYY-MM-DD HH:MM:SS')
--max-ips               Límite opcional de IPs únicas a rastrear
--max-errors            Límite opcional de errores únicos a rastrear
--geoip-db              Ruta alternativa a la base de datos GeoIP
-v, --verbose           Habilita logging verbose para debugging
```

---

## Ejemplo de salida

### Vista en columnas
```
=== ESTADÍSTICAS DEL LOG ===
Líneas totales: 123,456
Errores: 120 | Advertencias: 45
Periodo: De 2024-01-01 00:00:00 a 2024-01-31 23:59:59

Alertas de Seguridad Detectadas:
SQL Injection (5) | Xss Attempt (2)

--------------------------------------------------------------------------------
Códigos de Estado HTTP:
  - Código 200: 102345 veces
  - Código 404: 1234 veces
  Resumen por rangos:
    - 2xx: 102345 peticiones
    - 4xx: 1234 peticiones

Top 5 URLs Solicitadas:
  - (/index.html)
  - (/login)

Top 10 IPs con Geolocalización:
VECES   IP                 PAÍS
-----   ------------------ ------
234     203.0.113.5        United States
...
```

### JSON
```json
{
  "generated_at": "2024-02-01T10:30:00Z",
  "resumen": {
    "archivo": "access.log",
    "lineas_totales": 123456,
    "total_errores": 120,
    "total_warnings": 45,
    "periodo": {
      "desde": "2024-01-01 00:00:00",
      "hasta": "2024-01-31 23:59:59"
    }
  },
  "alertas_seguridad": {"sql_injection": 5, "xss_attempt": 2},
  "metodos_http": {"GET": 100000, "POST": 20000},
  "codigos_estado_http": {"200": 102345, "404": 1234},
  "top_urls": [["/index.html", 5000], ["/login", 4000]],
  "top_user_agents": [["Mozilla/5.0 ...", 60000]],
  "top_errores": [["Timeout <NUM>", 50]],
  "top_ips": [{"ip": "203.0.113.5", "count": 234, "pais": "United States"}]
}
```

---

## requirements.txt

El proyecto incluye un fichero `requirements.txt` para instalar las dependencias:

```text
geoip2>=4.6.0
```

(Opcionalmente puedes añadir `pytest` u otras librerías si deseas tests o utilidades extra).

---

## Licencia

Este proyecto se distribuye bajo la licencia MIT.
