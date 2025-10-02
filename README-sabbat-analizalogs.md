````markdown
# 📊 sabbat-analizalogs — Advanced Log Analyzer / Analizador Avanzado de Logs

> *“Your logs have a story to tell. sabbat-analizalogs deciphers it for you.”*  
> *“Tus logs tienen una historia que contar. sabbat-analizalogs la descifra por ti.”*

`sabbat-analizalogs` is a production-ready Python 3 log analyzer. It reads standard or compressed logs (`.gz`), supports streaming from `stdin`, and outputs rich statistics, security signals, and JSON reports.  
`sabbat-analizalogs` es un analizador de logs en Python 3 listo para producción. Lee logs estándar o comprimidos (`.gz`), admite `stdin` y genera estadísticas útiles, señales de seguridad y reportes JSON.

---

## 🌍 Language / Idioma

- Auto-detects console language: `LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, `LANG`.  
  Detecta automáticamente el idioma de la consola: `LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, `LANG`.
- Force with / Forzar con: `--lang {auto|en|es}` (default / por defecto: `auto`).

---

## ✨ Highlights / Novedades

**Security & Correctness / Seguridad y Corrección**
- ✅ **Safe output confinement**: `--output` restricted to current working directory (CWD). Use `--unsafe-output` to write outside CWD; `--force` to overwrite.  
  **Confinamiento de salida**: `--output` restringido al directorio actual. Usa `--unsafe-output` para escribir fuera; `--force` para sobrescribir.
- ✅ **ANSI sanitization** (default) to prevent terminal escape injection.  
  **Sanitización ANSI** por defecto para evitar inyecciones en terminal.
- ✅ **Hardened regex** for SQLi, path traversal, and XSS.  
  **Regex endurecidas** para SQLi, traversal y XSS.
- ✅ **Bias-free caps** for `--max-ips` / `--max-errors` (existing keys keep counting).  
  **Límites sin sesgo**: las claves ya vistas siguen contando.
- ✅ **UTC time filtering** with robust ISO/Apache parsing and TZ normalization.  
  **Filtrado en UTC** con parseo ISO/Apache y normalización de zona horaria.

**Usability / Usabilidad**
- ✅ Bilingual help & output (`--lang` + auto-detect).  
  Ayuda y salida bilingüe (`--lang` + autodetección).
- ✅ Two layouts: columns (default) and list (`--list-view`).  
  Dos vistas: columnas (por defecto) y lista (`--list-view`).
- ✅ Tunable tops: `--top-urls`, `--top-uas`, `--top-ips`.  
  Tops configurables: `--top-urls`, `--top-uas`, `--top-ips`.
- ✅ JSON enriched with `schema_version`, selected `lang`, and `parameters_used`.  
  JSON enriquecido con `schema_version`, `lang` y `parameters_used`.

---

## 📦 Requirements / Requisitos

- **Python** 3.8+ (3.7 works with limited `fromisoformat`).  
  **Python** 3.8+ (3.7 funciona con limitaciones en `fromisoformat`).
- **Dependencies / Dependencias**
  ```txt
  geoip2>=4.6.0
````

* **GeoIP DB (optional) / Base GeoIP (opcional)**: MaxMind **GeoLite2-Country.mmdb** (e.g., `/var/lib/GeoIP/`), or `--geoip-db` path.
  MaxMind **GeoLite2-Country.mmdb** (p. ej., `/var/lib/GeoIP/`) o ruta con `--geoip-db`.

---

## 🚀 Installation / Instalación

```bash
git clone https://github.com/sabbat-cloud/sabbat-utilidades
cd sabbat-utilidades
pip install -r requirements.txt
# or / o
pip install .
```

If installed via `pip install .`, the CLI `sabbat-analizalogs` is available on PATH.
Si instalas con `pip install .`, tendrás el CLI `sabbat-analizalogs` en tu PATH.

---

## 🧭 Usage / Uso

```bash
# Full analysis (columns) / Análisis completo (columnas)
sabbat-analizalogs access.log

# List view / Vista lista
sabbat-analizalogs access.log --list-view

# Pattern search (first 50) / Búsqueda de patrón (primeras 50)
sabbat-analizalogs error.log -p "Timeout" -c 50

# JSON output / Salida JSON
sabbat-analizalogs app.log --json

# Save JSON (confined to CWD) / Guardar JSON (confinado al CWD)
sabbat-analizalogs app.log --json --output reports/result.json

# Time filter (UTC) / Filtro temporal (UTC)
sabbat-analizalogs access.log --since 2024-01-01 --until "2024-01-31 23:59:59"

# Pipeline (stdin) / Pipeline (stdin)
zcat access.log.gz | sabbat-analizalogs - --json

# Force language / Forzar idioma
sabbat-analizalogs access.log --lang en
sabbat-analizalogs access.log --lang es
```

---

## ⚙️ Options / Opciones

| Option / Opción       | Description (EN) / Descripción (ES)                                                                                     |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `file / fichero`      | Log file (`.gz` or `-` for stdin) / Fichero de log (`.gz` o `-` para stdin)                                             |
| `--lang {auto,en,es}` | Interface language (default: `auto`) / Idioma de la interfaz (por defecto: `auto`)                                      |
| `-p, --pattern REGEX` | Regex to search / Patrón regex a buscar                                                                                 |
| `-c, --count N`       | Matched lines to show (default: 10) / Nº de coincidencias a mostrar (defecto: 10)                                       |
| `--json`              | Output JSON / Salida JSON                                                                                               |
| `--output PATH`       | Save results (confined to CWD unless `--unsafe-output`) / Guardar resultados (confinado al CWD salvo `--unsafe-output`) |
| `--force`             | Overwrite output file / Sobrescribir fichero de salida                                                                  |
| `--unsafe-output`     | Allow writing **outside** CWD (dangerous) / Permitir escribir **fuera** del CWD (peligroso)                             |
| `--list-view`         | List layout / Vista de lista                                                                                            |
| `--since DATETIME`    | Filter from this UTC datetime / Filtrar desde esta fecha/hora UTC                                                       |
| `--until DATETIME`    | Filter up to this UTC datetime / Filtrar hasta esta fecha/hora UTC                                                      |
| `--max-ips N`         | Cap unique IPs tracked / Límite de IPs únicas a registrar                                                               |
| `--max-errors N`      | Cap unique error messages / Límite de errores únicos a registrar                                                        |
| `--geoip-db PATH`     | Alternate GeoIP DB path / Ruta alternativa a la base GeoIP                                                              |
| `-v, --verbose`       | Verbose logging / Logging detallado                                                                                     |
| `--no-sanitize-ansi`  | Do **not** strip ANSI escapes / **No** sanitizar códigos ANSI                                                           |
| `--top-urls N`        | Top URLs to display (default: 5) / Nº de URLs top (defecto: 5)                                                          |
| `--top-uas N`         | Top User-Agents to display (default: 5) / Nº de User-Agents top (defecto: 5)                                            |
| `--top-ips N`         | Top IPs to display (default: 20) / Nº de IPs top (defecto: 20)                                                          |

---

## 🔐 Security Notes / Notas de Seguridad

* **Output confinement** blocks `../../` tricks unless `--unsafe-output` is set.
  **Confinamiento de salida** bloquea intentos tipo `../../` salvo `--unsafe-output`.
* **ANSI sanitization** is ON by default.
  **Sanitización ANSI** activada por defecto.
* **Hardened patterns** for SQLi / traversal / XSS.
  **Patrones endurecidos** para SQLi / traversal / XSS.
* **UTC normalization** ensures reliable time filtering.
  **Normalización a UTC** asegura un filtrado temporal fiable.

---

## 📑 Example Output / Ejemplo de Salida

### Columns (EN) / Columnas (ES)

```
=== LOG STATISTICS === / === ESTADÍSTICAS DEL LOG ===
Total lines: 123,456 / Líneas totales: 123,456
Errors: 120 | Warnings: 45 / Errores: 120 | Avisos: 45
Period: From 2024-01-01 00:00:00 to 2024-01-31 23:59:59
Periodo: De 2024-01-01 00:00:00 a 2024-01-31 23:59:59

Detected Security Alerts: / Alertas de seguridad detectadas:
SQL Injection (5) | Xss Attempt (2)

--------------------------------------------------------------------------------
HTTP Status Codes: / Códigos de estado HTTP:
  - Code 200: 102345 times
  - Code 404: 1234 times
  Summary by range: / Resumen por rangos:
    - 2xx: 102345 requests
    - 4xx: 1234 requests

Top 5 Requested URLs: / Top 5 URLs solicitadas:
  - (5000) /index.html
  - (4000) /login

Top 10 IPs with Geolocation: / Top 10 IPs con geolocalización:
COUNT/CUENTA   IP                 COUNTRY/PAÍS
-----          ------------------ -----------------
234            203.0.113.5        United States
...
```

---

## 🧾 JSON Schema (excerpt) / Esquema JSON (extracto)

```json
{
  "schema_version": "1.2.0",
  "generated_at": "2025-10-02T12:34:56Z",
  "lang": "en",
  "summary": {
    "file": "access.log",
    "total_lines": 123456,
    "total_errors": 120,
    "total_warnings": 45,
    "period": { "from": "2024-01-01 00:00:00", "to": "2024-01-31 23:59:59" }
  },
  "parameters_used": { "max_ips": null, "max_errors": null, "top_urls": 5, "top_uas": 5, "top_ips": 20 },
  "security_alerts": { "sql_injection": 5, "xss_attempt": 2 }
}
```

> The JSON includes `schema_version`, `lang`, and `parameters_used` for better auditability.
> El JSON incluye `schema_version`, `lang` y `parameters_used` para mejor trazabilidad.

---

## 🧪 Testing Tips / Consejos de Pruebas

* Large files: `zcat huge.log.gz | sabbat-analizalogs - --json`
  Ficheros grandes: `zcat huge.log.gz | sabbat-analizalogs - --json`
* GeoIP on/off to test graceful degradation.
  GeoIP presente/ausente para verificar degradación elegante.
* Edge cases: malformed timestamps, long UAs (>200 chars), ANSI in logs.
  Casos límite: timestamps corruptos, UAs largas (>200), ANSI en líneas.

---

## 🗺️ Roadmap (suggestions) / Hoja de ruta (sugerencias)

* NDJSON streaming output for massive pipelines. / Salida NDJSON para pipelines masivos.
* Pluggable detection rules (YAML). / Reglas de detección enchufables (YAML).
* `pyproject.toml` console script & CI release workflow. / Script de consola y workflow de releases en CI.

---

## 📜 License / Licencia

MIT

---

**Repo:** [https://github.com/sabbat-cloud/sabbat-utilidades](https://github.com/sabbat-cloud/sabbat-utilidades)

```
```

