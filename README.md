````markdown
# 📊 sabbat-analizalogs — Advanced Log Analyzer / Analizador Avanzado de Logs

> *“Your logs have a story to tell. sabbat-analizalogs deciphers it for you.”*  
> *“Tus logs tienen una historia que contar. sabbat-analizalogs la descifra por ti.”*

`sabbat-analizalogs` is a production-ready Python 3 log analyzer. It reads standard or compressed logs (`.gz`), supports `stdin`, and outputs rich statistics, security signals, and JSON reports.  
`sabbat-analizalogs` es un analizador de logs en Python 3 listo para producción. Lee logs estándar o comprimidos (`.gz`), admite `stdin` y genera estadísticas útiles, señales de seguridad y reportes JSON.

---

## 🌍 Language / Idioma

- Auto-detects console language (`LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, `LANG`).  
  Detecta automáticamente el idioma de la consola (`LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, `LANG`).
- Force with / Forzar con: `--lang {auto|en|es}` (default / por defecto: `auto`).

---

## ✨ Highlights / Novedades

**Security & Robustness / Seguridad y Robustez**
- ✅ **Safe output confinement**: `--output` restricted to CWD; `--unsafe-output` to bypass; `--force` to overwrite.  
  **Confinamiento de salida**: `--output` restringido al directorio actual; `--unsafe-output` para permitirlo; `--force` para sobrescribir.
- ✅ **ANSI sanitization** by default. / **Sanitización ANSI** por defecto.
- ✅ **ReDoS mitigation**: hardened patterns (no `.*` peligrosos), optional **hardened engine** with `--hardened-regex` (uses `regex` if installed).  
  **Mitigación ReDoS**: patrones acotados (sin `.*` peligrosos), motor endurecido opcional con `--hardened-regex` (usa `regex` si está instalado).
- ✅ **Input validation**: `--max-line-chars` (default 4096), `--max-bytes`, `--deny-stdin`, configurable `--encoding` (uses `surrogateescape`, not `ignore`).  
  **Validación de entrada**: `--max-line-chars` (4096 por defecto), `--max-bytes`, `--deny-stdin`, `--encoding` configurable (con `surrogateescape`, no `ignore`).
- ✅ **GeoIP LRU cache** to cap memory. / **Caché LRU** de GeoIP para limitar memoria.

**Performance & UX / Rendimiento y UX**
- ✅ **Multi-threaded analysis** for statistics (`--threads`, `--batch-size`).  
  **Análisis multihilo** para estadísticas (`--threads`, `--batch-size`).
- ✅ Two layouts: columns (default) and list (`--list-view`). / Dos vistas: columnas y lista (`--list-view`).
- ✅ Tunable tops: `--top-urls`, `--top-uas`, `--top-ips`. / Tops configurables.
- ✅ JSON enriched: `schema_version`, `lang`, `parameters_used`, `truncated_lines`, `bytes_read`.  
  JSON enriquecido: `schema_version`, `lang`, `parameters_used`, `truncated_lines`, `bytes_read`.

> ℹ️ Pattern search (`-p/--pattern`) remains **ordered & single-threaded** to preserve the first N matches.  
> ℹ️ La búsqueda por patrón (`-p/--pattern`) sigue **ordenada y monohilo** para preservar las primeras N coincidencias.

---

## 📦 Requirements / Requisitos

- **Python** 3.8+ (3.7 works with limited `fromisoformat`).  
- **Dependencies / Dependencias**
  ```txt
  geoip2>=4.6.0
````

* **Optional / Opcional**

  ```txt
  regex>=2024.5.15   # enables --hardened-regex / activa --hardened-regex
  # re2>=0.3.3       # optional non-backtracking engine / motor alternativo (opcional)
  ```
* **GeoIP DB (optional) / Base GeoIP (opcional)**: MaxMind **GeoLite2-Country.mmdb** (e.g., `/var/lib/GeoIP/`), or set `--geoip-db`.
  MaxMind **GeoLite2-Country.mmdb** (p. ej., `/var/lib/GeoIP/`), o indica ruta con `--geoip-db`.

---

## 🚀 Installation / Instalación

```bash
git clone https://github.com/sabbat-cloud/sabbat-utilidades
cd sabbat-utilidades
pip install -r requirements.txt
# or / o
pip install .
```

If installed with `pip install .`, the CLI `sabbat-analizalogs` is available on PATH.
Si instalas con `pip install .`, tendrás el CLI `sabbat-analizalogs` en tu PATH.

---

## 🧭 Usage / Uso

```bash
# Full analysis (columns) / Análisis completo (columnas)
sabbat-analizalogs access.log

# List view / Vista lista
sabbat-analizalogs access.log --list-view

# Pattern search (first 50) / Búsqueda de patrón (primeras 50)
sabbat-analizalogs error.log -p "Timeout|Exception" -c 50

# JSON output / Salida JSON
sabbat-analizalogs app.log --json

# Save JSON (confined to CWD) / Guardar JSON (confinado al CWD)
sabbat-analizalogs app.log --json --output reports/result.json

# Time filter (UTC) / Filtro temporal (UTC)
sabbat-analizalogs access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# Pipeline (stdin) / Pipeline (stdin)
zcat access.log.gz | sabbat-analizalogs - --json
```

---

## ⚙️ Options / Opciones

| Option / Opción                                    | Description (EN) / Descripción (ES)                                                                                     |   |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | - |
| `file / fichero`                                   | Log file (`.gz` or `-` for stdin) / Fichero de log (`.gz` o `-` para stdin)                                             |   |
| `--lang {auto,en,es}`                              | Interface language (default: `auto`) / Idioma de la interfaz (por defecto: `auto`)                                      |   |
| `-p, --pattern REGEX`                              | Regex to search (ordered, single-thread) / Patrón regex a buscar (ordenado, monohilo)                                   |   |
| `-c, --count N`                                    | Matched lines to show (default: 10) / Nº de coincidencias a mostrar (defecto: 10)                                       |   |
| `--json`                                           | Output JSON / Salida JSON                                                                                               |   |
| `--output PATH`                                    | Save results (confined to CWD unless `--unsafe-output`) / Guardar resultados (confinado al CWD salvo `--unsafe-output`) |   |
| `--force`                                          | Overwrite output file / Sobrescribir fichero de salida                                                                  |   |
| `--unsafe-output`                                  | Allow writing **outside** CWD (dangerous) / Permitir escribir **fuera** del CWD (peligroso)                             |   |
| `--list-view`                                      | List layout / Vista de lista                                                                                            |   |
| `--since DATETIME`                                 | Filter from this UTC datetime / Filtrar desde esta fecha/hora UTC                                                       |   |
| `--until DATETIME`                                 | Filter up to this UTC datetime / Filtrar hasta esta fecha/hora UTC                                                      |   |
| `--max-ips N`                                      | Cap unique IPs tracked / Límite de IPs únicas a registrar                                                               |   |
| `--max-errors N`                                   | Cap unique error messages / Límite de errores únicos a registrar                                                        |   |
| `--geoip-db PATH`                                  | Alternate GeoIP DB path / Ruta alternativa a la base GeoIP                                                              |   |
| `-v, --verbose`                                    | Verbose logging / Logging detallado                                                                                     |   |
| `--no-sanitize-ansi`                               | Do **not** strip ANSI escapes / **No** sanitizar códigos ANSI                                                           |   |
| `--top-urls N`                                     | Top URLs to display (default: 5) / Nº de URLs top (defecto: 5)                                                          |   |
| `--top-uas N`                                      | Top User-Agents to display (default: 5) / Nº de User-Agents top (defecto: 5)                                            |   |
| `--top-ips N`                                      | Top IPs to display (default: 20) / Nº de IPs top (defecto: 20)                                                          |   |
| **Performance & Safety / Rendimiento y Seguridad** |                                                                                                                         |   |
| `--threads N`                                      | Worker threads for stats (default: CPU count) / Hilos de trabajo para estadísticas (por defecto: núm. CPUs)             |   |
| `--batch-size N`                                   | Lines per worker batch (default: 2000) / Líneas por lote (defecto: 2000)                                                |   |
| `--encoding ENC`                                   | Input encoding (default: `utf-8`; `auto` tries utf-8 then latin-1) / Codificación de entrada (por defecto `utf-8`)      |   |
| `--max-line-chars N`                               | Max characters per input line (default: 4096) / Máx. caracteres por línea (defecto: 4096)                               |   |
| `--max-bytes N`                                    | Stop after N bytes read / Detener tras N bytes leídos                                                                   |   |
| `--deny-stdin`                                     | Refuse reading from stdin / Rechazar lectura desde stdin                                                                |   |
| `--hardened-regex`                                 | Use hardened regex engine if available / Usar motor regex endurecido si está disponible                                 |   |

---

## 🔐 Security Notes / Notas de Seguridad

* **Output confinement** blocks `../../` tricks unless `--unsafe-output` is set.
  **Confinamiento de salida** bloquea intentos tipo `../../` salvo `--unsafe-output`.
* **ReDoS**: patterns avoid catastrophic backtracking; `--hardened-regex` adds atomic/possessive constructs (via `regex`).
  **ReDoS**: patrones acotados; `--hardened-regex` añade grupos atómicos/cuantificadores posesivos (con `regex`).
* **Input validation**: line length, total bytes, optional stdin denial; `surrogateescape` preserves bytes for review.
  **Validación de entrada**: longitud por línea, bytes totales, denegar stdin; `surrogateescape` preserva bytes.

---

## 🧪 Test Examples / Ejemplos de Pruebas

```bash
# 1) Multi-threaded analysis (auto CPU), hardened regex, recommended caps
#    Análisis multihilo (auto CPU), regex endurecida y topes recomendados
sabbat-analizalogs access.log \
  --threads 8 --batch-size 5000 --hardened-regex \
  --max-line-chars 4096 --max-bytes 500000000 \
  --top-urls 10 --top-uas 10 --top-ips 50

# 2) Ordered, single-thread pattern search in safe mode
#    Búsqueda de patrón (ordenada, monohilo) en modo seguro
sabbat-analizalogs error.log -p "timeout|exception" -c 50 --lang es

# 3) JSON output + confinement (within CWD)
#    Salida JSON + confinamiento (dentro de CWD)
sabbat-analizalogs app.log --json --output reports/result.json
```

Additional stress ideas / Ideas de estrés:

* Huge `.gz` via pipeline (if policy allows) / `.gz` gigante por pipeline (si la política lo permite):
  `zcat huge.log.gz | sabbat-analizalogs - --json --max-line-chars 4096 --max-bytes 200000000`
* ReDoS probes / Sondeos ReDoS: include long UNION…SELECT lines with noise and ensure no CPU spikes.
  Incluir líneas largas con UNION…SELECT + ruido y verificar que no sube la CPU.

---

## 📑 Example Output / Ejemplo de Salida

### Columns (EN/ES)

```
=== LOG STATISTICS === / === ESTADÍSTICAS DEL LOG ===
Total lines: 123,456 / Líneas totales: 123,456
Errors: 120 | Warnings: 45 / Errores: 120 | Avisos: 45
Period: From 2024-01-01 00:00:00 to 2024-01-31 23:59:59
Periodo: De 2024-01-01 00:00:00 a 2024-01-31 23:59:59
...
```

### JSON (excerpt / extracto)

```json
{
  "schema_version": "1.3.0",
  "generated_at": "2025-10-02T12:34:56Z",
  "lang": "en",
  "summary": { "file": "access.log", "total_lines": 123456, "total_errors": 120, "total_warnings": 45,
               "period": { "from": "2024-01-01 00:00:00", "to": "2024-01-31 23:59:59" } },
  "parameters_used": {
    "max_ips": null, "max_errors": null,
    "top_urls": 5, "top_uas": 5, "top_ips": 20,
    "threads": 8, "batch_size": 5000,
    "encoding": "utf-8", "max_line_chars": 4096, "max_bytes": 500000000,
    "hardened_regex": true
  },
  "security_alerts": { "sql_injection": 5, "xss_attempt": 2, "path_traversal": 3 },
  "truncated_lines": 42,
  "bytes_read": 987654321
}
```

---

## 🗺️ Changelog (since 1.2.0) / Cambios (desde 1.2.0)

* **1.3.0**

  * Multithreaded statistics (`--threads`, `--batch-size`).
  * ReDoS mitigation & `--hardened-regex` (optional `regex` engine).
  * Input validation: `--max-line-chars`, `--max-bytes`, `--deny-stdin`, `--encoding`.
  * GeoIP **LRU cache**; capped UA/URL lengths.
  * JSON metrics: `truncated_lines`, `bytes_read`.

---
## Credits / Créditos 
— Architecture, integration and maintenance by Óscar Giménez Blasco. Drafting and refactoring assisted by generative AI tools; final design decisions, testing and operational safeguards by Óscar Giménez Blasco.

## CHANGELOG

Added multithreading, hardened-regex option, input limits, safe-output confinement, and LRU cache. Benchmarked and stress-tested prior to release.

## 📜 License / Licencia

MIT

**Repo:** [https://github.com/sabbat-cloud/sabbat-utilidades](https://github.com/sabbat-cloud/sabbat-utilidades)

```
```
