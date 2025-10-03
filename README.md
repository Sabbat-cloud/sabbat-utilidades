---

# 🧰 sabbat-utilidades — CLI toolbox

Colección de utilidades de sistema y seguridad.
Collection of system & security command-line tools.

* ✅ Bilingual (auto/en/es) where applicable
* ✅ Safe-by-default, production-ready
* ✅ Designed for automation (clean JSON modes)

---

## 📑 Índice / Table of Contents

* [Instalación / Installation](#-instalación--installation)
* [Requisitos / Requirements](#-requisitos--requirements)
* [Comandos / Commands](#-comandos--commands)

  * [📊 sabbat-loganalyce — Advanced Log Analyzer](#-sabbat-loganalyce--advanced-log-analyzer)
  * [🕵️ sabbat-fileinspect — File Inspector](#-sabbat-fileinspect--file-inspector)
* [✅ Buenas prácticas / Best Practices](#-buenas-prácticas--best-practices)
* [🧪 Pruebas rápidas / Quick Tests](#-pruebas-rápidas--quick-tests)
* [🛠️ Contribuir / Contributing](#️-contribuir--contributing)
* [📜 Licencia / License](#-licencia--license)

---

## 🚀 Instalación / Installation

```bash
git clone https://github.com/sabbat-cloud/sabbat-utilidades
cd sabbat-utilidades

# Dependencias base
pip install -r requirements.txt

# O instalación del paquete (expone los CLIs en PATH)
pip install .
```

> Tras `pip install .` tendrás los comandos `sabbat-loganalyce` y `sabbat-fileinspect` en tu PATH.
> After `pip install .`, CLIs are available on PATH.

---

## 🧱 Requisitos / Requirements

* **Python** 3.8+
* **Opcional / Optional (recomendado)**

  * `regex` (endurecimiento ReDoS para sabbat-loganalyce)
  * `geoip2` + base MaxMind (GeoLite2-Country.mmdb)
  * `python-magic` o `file(1)` (detección MIME en sabbat-fileinspect)
  * `Pillow` (metadatos de imagen en sabbat-fileinspect)
  * `chardet` (detección de encoding en sabbat-fileinspect)

---

# 🧭 Comandos / Commands

## 📊 sabbat-loganalyce — Advanced Log Analyzer

> *“Your logs have a story to tell. sabbat-loganalyce deciphers it for you.”*
> *“Tus logs tienen una historia que contar. sabbat-loganalyce la descifra por ti.”*

`sabbat-loganalyce` es un analizador de logs listo para producción. Lee ficheros estándar o `.gz`, soporta `stdin`, muestra estadísticas ricas, señales de seguridad y salida JSON.
`sabbat-loganalyce` is production-ready: reads plain or `.gz`, supports `stdin`, emits rich stats, security signals, and JSON.

### 🌍 Idioma / Language

* Auto: `--lang auto` (por defecto) / Default
* Forzar / Force: `--lang {en|es}`

### ✨ Highlights

* **Seguridad**: salida confinada al CWD; sanitiza ANSI; hardening ReDoS (`--hardened-regex`)
* **Rendimiento**: multihilo para estadísticas (`--threads`, `--batch-size`), *pipeline* acotado
* **UX**: columnas o lista; *tops* configurables; JSON enriquecido
* **Pre-aviso de logs grandes**: escaneo rápido de líneas **antes** de procesar (umbral ajustable)

### 📦 Ejemplos / Examples

```bash
# Análisis completo (columnas)
sabbat-loganalyce access.log

# Vista lista
sabbat-loganalyce access.log --list-view

# Búsqueda de patrón (primeras 50, ordenadas)
sabbat-loganalyce error.log -p "Timeout|Exception" -c 50

# Salida JSON
sabbat-loganalyce app.log --json

# Guardar JSON (confinado al CWD)
sabbat-loganalyce app.log --json --output reports/result.json

# Filtro temporal (UTC)
sabbat-loganalyce access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# stdin
zcat access.log.gz | sabbat-loganalyce - --json
```

### ⚙️ Opciones principales / Main options

| Opción / Option                             | Descripción (ES) / Description (EN)                                       |
| ------------------------------------------- | ------------------------------------------------------------------------- |
| `file / -`                                  | Fichero de log o `-` para stdin / Log file or `-` for stdin               |
| `--lang {auto,en,es}`                       | Idioma / Interface language                                               |
| `-p, --pattern REGEX`                       | Búsqueda regex (ordenada, monohilo) / Ordered, single-thread regex search |
| `-c, --count N`                             | Nº de coincidencias a mostrar / Matched lines to show                     |
| `--json`                                    | Salida JSON / JSON output                                                 |
| `--output PATH` `--force` `--unsafe-output` | Confinamiento de salida / Safe output controls                            |
| `--list-view`                               | Vista de lista / List layout                                              |
| `--since/--until`                           | Filtro temporal UTC / UTC time filter                                     |
| `--max-ips / --max-errors`                  | Limitar cardinalidad / Cap cardinality                                    |
| `--geoip-db PATH`                           | Ruta GeoIP / GeoIP DB path                                                |
| `-v, --verbose`                             | Logging detallado / Verbose logging                                       |
| **Rendimiento**                             |                                                                           |
| `--threads N`                               | Hilos de trabajo / Worker threads                                         |
| `--batch-size N`                            | Líneas por lote / Lines per batch                                         |
| `--encoding ENC`                            | Codificación entrada (o `auto`) / Input encoding                          |
| `--max-line-chars N` `--max-bytes N`        | Límites de seguridad / Safety limits                                      |
| `--deny-stdin`                              | Rechazar stdin / Deny stdin                                               |
| `--hardened-regex`                          | Motor endurecido si disponible / Hardened regex engine                    |
| **Pre-scan**                                |                                                                           |
| `--large-threshold N`                       | Avisar de log grande **antes** de analizar / Early large-log warning      |

> Salida con código `2` si se detectan alertas de seguridad.
> Exits with code `2` when security alerts are found.

---

## 🕵️ sabbat-fileinspect — File Inspector

Inspector de ficheros con foco en seguridad y portabilidad.
Security-focused, portable file inspector.

* **i18n**: `--lang {auto,en,es}`
* **MIME robusto**: `python-magic` → `file(1)` (con *timeout*) → `mimetypes`
* **Hashes**: `--hash sha256,sha1,md5` (por defecto `sha256`) o `--no-hash`
* **Secret scanning**: patrones comunes + **entropía alta** (base64/hex), límites configurables
* **Imágenes**: `Image.verify()` (si `Pillow`) y metadatos seguros
* **Binarios**: detección por cabecera (ELF/PE/Mach-O) + `readelf` opcional
* **Fechas**: `--utc` (ISO 8601)
* **Respeta `NO_COLOR`** y tiene salida JSON limpia

### 📦 Ejemplos / Examples

```bash
# Inspección básica (auto idioma)
sabbat-fileinspect /etc/passwd

# Forzar español + UTC + hashes múltiples + JSON
sabbat-fileinspect --lang es --utc --hash sha256,sha1 --json /etc/hosts

# Sin hashes, sin seguir symlinks
sabbat-fileinspect --no-hash --nofollow /ruta/al/enlace

# Límite de escaneo de secretos
sabbat-fileinspect --max-secret-bytes 262144 --max-secret-lines 300 app.env
```

### ⚙️ Opciones principales / Main options

| Opción / Option        | Descripción (ES) / Description (EN)            |
| ---------------------- | ---------------------------------------------- |
| `--lang {auto,en,es}`  | Idioma / Interface language                    |
| `--json`               | Salida JSON / JSON output                      |
| `--nofollow`           | No seguir symlinks / Do not follow symlinks    |
| `--utc`                | Fechas en UTC (ISO 8601) / UTC timestamps      |
| **Tamaño / Size**      | `-b/--bytes`, `-k/--kb`, `-m/--mb`, `-g/--gb`  |
| **Hashes**             | `--no-hash` o `--hash sha256,sha1,md5`         |
| **Secretos / Secrets** | `--max-secret-bytes N`, `--max-secret-lines N` |

**Salida (humana) / Human output**

* Fichero / File, Realpath, Symlink
* Tipo MIME / MIME type
* Tamaño formateado / Formatted size
* Permisos (`stat.filemode`) e inodo / Permissions & inode
* Propietario / Owner
* Fechas / Dates
* Detalles contextuales / Context details (texto, imagen, binario)
* Alertas de seguridad / Security alerts
* Integridad (hashes) / Integrity (hashes)

**Salida JSON / JSON output**

* Claves estables aptas para pipelines → perfectas para automatización.

---

## ✅ Buenas prácticas / Best Practices

* **Logs enormes**: usa `--large-threshold` (loganalyce) y `--max-bytes`.
* **ReDoS**: activa `--hardened-regex` si instalas `regex`.
* **GeoIP**: descarga y configura `GeoLite2-Country.mmdb` si quieres países.
* **Secretos**: ajusta `--max-secret-bytes/lines` para no procesar archivos gigantes.
* **Color**: exporta `NO_COLOR=1` en ambientes CI.

---

## 🧪 Pruebas rápidas / Quick Tests

```bash
# sabbat-loganalyce — multihilo + endurecido + límites
sabbat-loganalyce access.log \
  --threads 8 --batch-size 5000 --hardened-regex \
  --max-line-chars 4096 --max-bytes 500000000 \
  --top-urls 10 --top-uas 10 --top-ips 50

# sabbat-fileinspect — JSON + secretos + hashes múltiples
sabbat-fileinspect --lang es --utc \
  --hash sha256,sha1 \
  --max-secret-bytes 262144 --max-secret-lines 400 \
  --json ./config/.env
```

---

## 🛠️ Contribuir / Contributing

* Issues y PRs bienvenidos.
* Mantén el estilo: *safe-by-default, robust tests, clear UX*.
* Sugerencia: añade nuevos comandos como secciones independientes en este README.

---

## 📜 Licencia / License

MIT

**Repo:** [https://github.com/sabbat-cloud/sabbat-utilidades](https://github.com/sabbat-cloud/sabbat-utilidades)

---

