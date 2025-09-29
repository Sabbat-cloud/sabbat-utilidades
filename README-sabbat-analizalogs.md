# 📊 `sabbat-analizalogs` - Analizador de Logs Avanzado

> **"Tus logs tienen una historia que contar. `sabbat-analizalogs` la descifra por ti."**

`sabbat-analizalogs` es una herramienta de línea de comandos de alto rendimiento para el análisis de logs. Combina la funcionalidad de `grep`, `sort`, `uniq -c`, `awk` y herramientas de geolocalización en una única utilidad potente, diseñada para ofrecer una visión completa de la actividad de un sistema a través de sus logs.

## Características

  - **Análisis de Alto Rendimiento**: Procesa archivos de log de cualquier tamaño (incluyendo **archivos `.gz` comprimidos**) línea por línea, manteniendo un bajo consumo de memoria.
  - **Estadísticas Enriquecidas**: Genera un panel de control completo en la terminal:
      - **Top IPs** con **geolocalización** por país.
      - **Top Errores** específicos y URLs más solicitadas.
      - Resumen de **códigos de estado HTTP** (individuales y agrupados por rangos `2xx`, `4xx`, etc.).
      - Conteo de **User-Agents** y métodos HTTP.
  - **Filtrado Avanzado**: Permite acotar el análisis a un **rango de fechas y horas** específico con las opciones `--since` y `--until`.
  - **Salida Flexible**:
      - **Modo Texto**: Informe claro y legible para humanos, con colores para una mejor visualización.
      - **Modo JSON**: Salida estructurada ideal para la integración con otros scripts, herramientas de monitoreo o pipelines de CI/CD.
  - **Robusto y Configurable**:
      - **Gestión de memoria**: Opciones `--max-ips` y `--max-errors` para controlar el uso de recursos en archivos masivos.
      - **Salida a archivo**: Guarda los resultados directamente con la opción `--output`.
      - **Modo Verbose**: Ofrece información de debugging para un análisis más profundo.

## Instalación

```bash
# Clona el repositorio (si aún no lo has hecho)
git clone https://github.com/sababt-cloud/sabbat-utilidades.git
cd sabbat-utilidades

# Hazlo ejecutable y enlázalo en tu PATH
sudo cp sabbat-analizalogs /usr/local/bin/
sudo chmod +x /usr/local/bin/sabbat-analizalogs

# Instala la dependencia necesaria para la geolocalización de IPs
pip3 install geoip2-database

# Nota: El script necesita una base de datos de GeoIP. 
# La buscará por defecto en /var/lib/GeoIP/GeoLite2-Country.mmdb.
# Puedes usar --geoip-db para especificar otra ruta.
```

## Uso

Aquí tienes algunos ejemplos prácticos de cómo usar `sabbat-analiza`:

#### 1\. Análisis general de un log de acceso

```bash
sabbat-analizalogs /var/log/access.log
```

#### 2\. Buscar un patrón específico y mostrar las 50 primeras coincidencias

```bash
sabbat-analizalogs error.log -p "Connection timed out" -c 50
```

#### 3\. Analizar un log, filtrar por fecha y guardar el resultado en JSON

```bash
sabbat-analizalogs huge_access.log.gz --since 2025-09-28 --until "2025-09-29 12:00:00" --json --output report.json
```

#### 4\. Analizar un log muy grande limitando el uso de memoria

```bash
sabbat-analizalogs massive.log --max-ips 5000 --max-errors 1000
```
