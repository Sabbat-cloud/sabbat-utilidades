#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sabbat-fileinspect.py — Inspector de ficheros con foco en seguridad, portabilidad y buenas prácticas.
Incluye i18n (es/en) con autodetección o --lang.

Novedades clave:
- i18n completo (mensajes, etiquetas, ayuda, avisos).
- Portabilidad: funciona sin pwd/grp (Windows).
- MIME robusto: python-magic > file(1) con timeout > mimetypes.
- Symlinks: muestra realpath, destino y trata enlaces rotos claramente.
- Hashes: --no-hash o --hash sha256,sha1,md5 (por defecto sha256), mmap si procede.
- Secretos: patrones ampliados + alta entropía (base64/hex) con límites configurables.
- Imágenes: verificación segura (Pillow opcional).
- Ejecutables: ELF/PE/Mach-O por cabecera; readelf opcional con timeout.
- Tiempo: --utc para fechas ISO 8601, respeta NO_COLOR.
"""

import argparse
import os
import sys
import subprocess
import stat
import math
import hashlib
import json
import re
import mimetypes
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple

# --- Dependencias opcionales ---
try:
    import pwd, grp  # Unix only
    HAVE_PWD_GRP = True
except Exception:
    HAVE_PWD_GRP = False

try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    import magic  # from python-magic
    MAGIC_AVAILABLE = True
except Exception:
    MAGIC_AVAILABLE = False

# =========================
# i18n
# =========================
def detect_console_lang() -> str:
    for var in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        v = os.environ.get(var)
        if not v:
            continue
        first = v.split(":")[0]
        code = first.split(".")[0].lower()
        if code.startswith("es"):
            return "es"
        if code.startswith("en"):
            return "en"
    return "en"

def choose_lang(cli_lang: Optional[str]) -> str:
    if not cli_lang or cli_lang == "auto":
        return detect_console_lang()
    return cli_lang if cli_lang in ("en", "es") else "en"

I18N = {
    "en": {
        "usage": """Usage: {prog} [options] <file>

Show detailed information about a file with a security focus.

Size:
  -b, --bytes      Show exact size in bytes
  -k, --kb         Show size in KB (decimal)
  -m, --mb         Show size in MB (decimal)
  -g, --gb         Show size in GB (decimal)

Hashes:
  --no-hash        Do not compute hashes
  --hash ALGOS     Comma-separated (sha256,sha1,md5,...) — default: sha256

Other:
  --nofollow       Do not follow symbolic links
  --utc            Timestamps in UTC (ISO 8601)
  --json           JSON output
  --lang L         Interface language: auto (default), en, es
  --max-secret-bytes N   Max bytes to scan for secrets (text files)
  --max-secret-lines N   Max lines to scan for secrets (text files)
""",
        "arg_json": "JSON output.",
        "arg_nofollow": "Do not follow symbolic links.",
        "arg_utc": "Timestamps in UTC (ISO 8601).",
        "arg_hash": "Comma-separated algorithms (e.g., sha256,sha1,md5). Default: sha256",
        "arg_nohash": "Do not compute hashes.",
        "arg_msbytes": "Max bytes to scan for secrets (text).",
        "arg_mslines": "Max lines to scan for secrets (text).",
        "arg_lang": "Interface language: auto (default), en, es",
        "file_not_found": "File '{f}' does not exist.",
        "unexpected_error": "Unexpected error",
        "file": "File:",
        "realpath": "Realpath:",
        "symlink": "Symlink:",
        "mime": "MIME type:",
        "size": "Size:",
        "perms": "Permissions:",
        "owner": "Owner:",
        "modified": "Modified:",
        "accessed": "Accessed:",
        "created": "Created:",
        "integrity": "Integrity:",
        "alerts": "Security Alerts:",
        "details_arrow": "→",
        "lines": "{n} lines",
        "cant_count_lines": "Could not count lines",
        "pillow_missing": "Pillow not installed to analyze images.",
        "img_meta_error": "Could not read image metadata (possible corrupt image)",
        "exec_file": "Executable file ({k})",
        "compiler": "Compiler:",
        "encoding": "Encoding: {enc} ({conf:.1f}% conf.)",
        "hash_invalid_algo": "ERROR (invalid algorithm)",
        "hash_read_error": "ERROR (could not read)",
        "error_prefix": "Error:",
        "warn_prefix": "Warning:",
        "owner_fmt_unknown": "{uid}:{gid}",
        "perm_777": "🚨 777 permissions — extremely dangerous",
        "perm_world_writable": "🔓 World-writable",
        "suid": "⚠️ SUID bit — high risk if not required",
        "sgid": "⚠️ SGID bit — potential risk",
        "sensitive_name": "🔍 Potentially sensitive name",
        "secret_password": "Password in plaintext",
        "secret_api_key": "API key",
        "secret_secret": "Generic secret",
        "secret_privkey": "Private key",
        "secret_aws_ak": "AWS Access Key",
        "secret_aws_sk": "AWS Secret Key",
        "secret_github": "GitHub token",
        "secret_card": "Possible credit card number",
        "secret_b64_entropy": "High-entropy base64 string (possible secret)",
        "secret_hex_entropy": "High-entropy hex string (possible secret)",
        "img_dim": "Dimensions: {w}x{h}",
        "img_fmt": "Format: {fmt}",
        "img_mode": "Mode: {mode}",
        "img_bitdepth": "{bd}-bit",
        "img_interlaced": "interlaced",
        "img_non_interlaced": "non-interlaced",
    },
    "es": {
        "usage": """Uso: {prog} [opciones] <fichero>

Muestra información detallada de un fichero con foco en seguridad.

Tamaño:
  -b, --bytes      Mostrar tamaño exacto en bytes
  -k, --kb         Mostrar tamaño en KB (decimal)
  -m, --mb         Mostrar tamaño en MB (decimal)
  -g, --gb         Mostrar tamaño en GB (decimal)

Hashes:
  --no-hash        No calcular hashes
  --hash ALGOS     Lista separada por comas (sha256,sha1,md5,...) — por defecto: sha256

Otras:
  --nofollow       No seguir enlaces simbólicos
  --utc            Fechas en UTC (ISO 8601)
  --json           Salida JSON
  --lang L         Idioma de la interfaz: auto (por defecto), en, es
  --max-secret-bytes N   Máx. bytes a escanear en búsqueda de secretos (texto)
  --max-secret-lines N   Máx. líneas a escanear en búsqueda de secretos (texto)
""",
        "arg_json": "Salida en formato JSON.",
        "arg_nofollow": "No seguir enlaces simbólicos.",
        "arg_utc": "Fechas en UTC (ISO 8601).",
        "arg_hash": "Algoritmos separados por comas (p. ej., sha256,sha1,md5). Por defecto: sha256",
        "arg_nohash": "No calcular hashes.",
        "arg_msbytes": "Máximo de bytes para escaneo de secretos (texto).",
        "arg_mslines": "Máximo de líneas para escaneo de secretos (texto).",
        "arg_lang": "Idioma de la interfaz: auto (por defecto), en, es",
        "file_not_found": "El fichero '{f}' no existe.",
        "unexpected_error": "Error inesperado",
        "file": "Fichero:",
        "realpath": "Realpath:",
        "symlink": "Enlace:",
        "mime": "Tipo MIME:",
        "size": "Tamaño:",
        "perms": "Permisos:",
        "owner": "Propietario:",
        "modified": "Modificado:",
        "accessed": "Accedido:",
        "created": "Creado:",
        "integrity": "Integridad:",
        "alerts": "Alertas de seguridad:",
        "details_arrow": "→",
        "lines": "{n} líneas",
        "cant_count_lines": "No se pudo contar las líneas",
        "pillow_missing": "Pillow no está instalado para analizar imágenes.",
        "img_meta_error": "No se pudieron leer metadatos de la imagen (posible imagen corrupta)",
        "exec_file": "Fichero ejecutable ({k})",
        "compiler": "Compilador:",
        "encoding": "Encoding: {enc} ({conf:.1f}% conf.)",
        "hash_invalid_algo": "ERROR (algoritmo no válido)",
        "hash_read_error": "ERROR (no se pudo leer)",
        "error_prefix": "Error:",
        "warn_prefix": "Aviso:",
        "owner_fmt_unknown": "{uid}:{gid}",
        "perm_777": "🚨 Permisos 777 — extremadamente peligroso",
        "perm_world_writable": "🔓 Escribible por otros (world-writable)",
        "suid": "⚠️ Bit SUID — riesgo elevado si no es necesario",
        "sgid": "⚠️ Bit SGID — riesgo potencial",
        "sensitive_name": "🔍 Nombre potencialmente sensible",
        "secret_password": "Contraseña en texto claro",
        "secret_api_key": "Clave de API",
        "secret_secret": "Secreto genérico",
        "secret_privkey": "Clave privada",
        "secret_aws_ak": "AWS Access Key",
        "secret_aws_sk": "AWS Secret Key",
        "secret_github": "Token de GitHub",
        "secret_card": "Posible nº de tarjeta",
        "secret_b64_entropy": "Cadena base64 de alta entropía (posible secreto)",
        "secret_hex_entropy": "Cadena hex de alta entropía (posible secreto)",
        "img_dim": "Dimensiones: {w}x{h}",
        "img_fmt": "Formato: {fmt}",
        "img_mode": "Modo: {mode}",
        "img_bitdepth": "{bd}-bit",
        "img_interlaced": "interlaced",
        "img_non_interlaced": "non-interlaced",
    },
}

# Se asigna tras parsear --lang
T = I18N["en"]

# =========================
# Config por defecto
# =========================
DEFAULT_HASHES = ("sha256",)
ANSI = sys.stdout.isatty() and not os.getenv("NO_COLOR")

def c(s, code):
    if not ANSI:
        return s
    return f"\033[{code}m{s}\033[0m"

def warn(s):  # stderr
    print(c(s, "1;33"), file=sys.stderr)

def err(s):
    print(c(s, "1;31"), file=sys.stderr)

# =========================
# Utilidades
# =========================
def safe_owner_group(st) -> str:
    if HAVE_PWD_GRP:
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)
        return f"{owner}:{group}"
    return T["owner_fmt_unknown"].format(uid=getattr(st, "st_uid", "?"), gid=getattr(st, "st_gid", "?"))

def format_size_iec(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    units = ["KiB","MiB","GiB","TiB","PiB","EiB"]
    e = int(math.log(n, 1024))
    e = min(e, len(units))
    val = n / (1024 ** e)
    return f"{val:.2f} {units[e-1]}"

def format_permissions(mode: int) -> str:
    return stat.filemode(mode)

def detect_magic_mime(path: Path) -> Optional[str]:
    if MAGIC_AVAILABLE:
        try:
            m = magic.Magic(mime=True)
            return m.from_file(str(path))
        except Exception:
            return None
    return None

def shutil_which(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None

def detect_file_mime(path: Path, timeout=2) -> Optional[str]:
    if not shutil_which("file"):
        return None
    try:
        out = subprocess.run(["file","--mime-type","-b",str(path)],
                             capture_output=True, text=True, timeout=timeout, check=True)
        mt = out.stdout.strip()
        return mt or None
    except Exception:
        return None

def best_mime(path: Path) -> str:
    mt = detect_magic_mime(path)
    if mt:
        return mt
    mt = detect_file_mime(path)
    if mt:
        return mt
    guess, _ = mimetypes.guess_type(str(path))
    return guess or "application/octet-stream"

def is_executable_magic(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            head = f.read(8)
        if head.startswith(b"\x7fELF"):
            return "ELF"
        if head[:2] == b"MZ":
            return "PE"
        if head in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            return "Mach-O"
    except Exception:
        pass
    return None

def run_readelf_comment(path: Path, timeout=2) -> Optional[str]:
    if not shutil_which("readelf"):
        return None
    try:
        out = subprocess.run(["readelf","-p",".comment",str(path)],
                             capture_output=True, text=True, timeout=timeout, check=True)
        txt = out.stdout
        if "GCC:" in txt:
            line = txt.split("GCC:",1)[1].strip().splitlines()[0]
            return f"GCC {line}"
    except Exception:
        pass
    return None

# =========================
# Secret scanning
# =========================
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r'password\s*[:=]\s*["\']?[^"\']{4,}', "secret_password"),
    (r'api[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9._\-]{10,}', "secret_api_key"),
    (r'secret\s*[:=]\s*["\']?[^"\']{6,}', "secret_secret"),
    (r'-----BEGIN [A-Z ]+PRIVATE KEY-----', "secret_privkey"),
    (r'aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?[A-Z0-9]{20}', "secret_aws_ak"),
    (r'aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}', "secret_aws_sk"),
    (r'(ghp|github_pat)_[A-Za-z0-9]{20,}', "secret_github"),
    (r'[\d]{4}[\s-]?[\d]{4}[\s-]?[\d]{4}[\s-]?[\d]{4}', "secret_card"),
]
BASE64_RE = re.compile(r'\b[A-Za-z0-9+/]{24,}={0,2}\b')
HEX_RE    = re.compile(r'\b[0-9a-fA-F]{32,}\b')

def shannon_entropy(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum((c/len(s)) * log2(c/len(s)) for c in counts.values())

def detectar_secretos_en_texto(file_path: Path,
                               max_bytes: int = 1024*1024,
                               max_lines: int = 800,
                               encoding: str = "utf-8") -> List[str]:
    secretos = []
    try:
        if file_path.stat().st_size > max_bytes:
            return secretos
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line)
            contenido = ''.join(lines)
    except Exception:
        return secretos

    for patron, key in SECRET_PATTERNS:
        if re.search(patron, contenido, re.IGNORECASE | re.MULTILINE):
            secretos.append("🔑 " + T[key])

    for m in BASE64_RE.findall(contenido):
        if shannon_entropy(m) >= 4.5:
            secretos.append("🔑 " + T["secret_b64_entropy"])
            break
    for m in HEX_RE.findall(contenido):
        if shannon_entropy(m) >= 3.5:
            secretos.append("🔑 " + T["secret_hex_entropy"])
            break
    return secretos

# =========================
# Hashes
# =========================
def calcular_hashes(file_path: Path, algos: Tuple[str, ...]) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    try:
        import mmap
        use_mmap = True
    except Exception:
        use_mmap = False

    for algo in algos:
        try:
            hasher = hashlib.new(algo)
        except ValueError:
            hashes[algo] = T["hash_invalid_algo"]
            continue
        try:
            with open(file_path, "rb") as f:
                if use_mmap:
                    try:
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            hasher.update(mm)
                    except Exception:
                        f.seek(0)
                        for chunk in iter(lambda: f.read(1<<20), b""):
                            hasher.update(chunk)
                else:
                    for chunk in iter(lambda: f.read(1<<20), b""):
                        hasher.update(chunk)
            hashes[algo] = hasher.hexdigest()
        except (OSError, IOError):
            hashes[algo] = T["hash_read_error"]
    return hashes

# =========================
# Seguridad de permisos y nombres
# =========================
NOMBRES_RIESGO = ['.ssh', '.pem', 'id_rsa', 'password', 'secret', '.env', '.bak', '.tmp', '~']

def analizar_riesgos_seguridad(path: Path, st, is_symlink=False) -> List[str]:
    alertas = []
    mode = st.st_mode
    if not is_symlink:
        if mode & stat.S_ISUID:
            alertas.append(T["suid"])
        if mode & stat.S_ISGID:
            alertas.append(T["sgid"])
        if (mode & 0o777) == 0o777:
            alertas.append(T["perm_777"])
        elif (mode & stat.S_IWOTH):
            alertas.append(T["perm_world_writable"])
    if any(r in str(path).lower() for r in NOMBRES_RIESGO):
        alertas.append(T["sensitive_name"])
    return alertas

# =========================
# Núcleo
# =========================
def get_file_info(file_path_str: str,
                  follow_symlinks: bool = True,
                  utc_times: bool = False,
                  secret_limits: Tuple[int,int] = (1024*1024, 800)) -> Dict:
    file_path = Path(file_path_str)
    if not file_path.exists():
        raise FileNotFoundError(T["file_not_found"].format(f=file_path))

    is_symlink = file_path.is_symlink()
    real_path = None
    symlink_target = None
    lstat_obj = file_path.lstat() if is_symlink else None

    if is_symlink:
        try:
            symlink_target = os.readlink(file_path)
        except OSError:
            symlink_target = "ERROR (broken symlink)" if T is I18N["en"] else "ERROR (enlace roto)"
        if follow_symlinks:
            try:
                real_path = file_path.resolve(strict=True)
            except Exception:
                real_path = None

    st = file_path.stat() if (not is_symlink or follow_symlinks) else lstat_obj
    mime = best_mime(file_path if (not is_symlink or follow_symlinks) else file_path)

    def fmt_ts(ts: float) -> str:
        if utc_times:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    info = {
        "lang": "en" if T is I18N["en"] else "es",
        "nombre": str(file_path),
        "realpath": str(real_path) if real_path else None,
        "tipo_mime": mime,
        "tamaño_bytes": st.st_size,
        "permisos": format_permissions(st.st_mode),
        "propietario": safe_owner_group(st),
        "fecha_mod": fmt_ts(st.st_mtime),
        "fecha_acc": fmt_ts(st.st_atime),
        "fecha_cre": fmt_ts(st.st_ctime),
        "inodo": getattr(st, "st_ino", None),
        "es_symlink": is_symlink,
        "destino_symlink": symlink_target,
        "detalles_contextuales": [],
        "alertas_seguridad": analizar_riesgos_seguridad(file_path, st, is_symlink),
    }

    if is_symlink and not follow_symlinks:
        info["detalles_contextuales"].append(f"Symlink → {symlink_target}")
    else:
        if mime.startswith("text/"):
            encoding_hint = "utf-8"
            if CHARDET_AVAILABLE:
                try:
                    with open(file_path, "rb") as f:
                        raw = f.read(4096)
                    det = chardet.detect(raw)
                    if det.get("encoding") and det.get("confidence",0) > 0.5:
                        encoding_hint = det["encoding"]
                        info["detalles_contextuales"].append(T["encoding"].format(enc=encoding_hint, conf=det["confidence"]*100))
                except Exception:
                    pass
            try:
                with open(file_path, "r", encoding=encoding_hint, errors="ignore") as f:
                    num_lineas = sum(1 for _ in f)
                info["detalles_contextuales"].append(T["lines"].format(n=num_lineas))
            except Exception:
                info["detalles_contextuales"].append(T["cant_count_lines"])
            max_b, max_l = secret_limits
            secretos = detectar_secretos_en_texto(file_path, max_bytes=max_b, max_lines=max_l, encoding=encoding_hint)
            info["alertas_seguridad"].extend(secretos)

        elif mime.startswith("image/"):
            if PILLOW_AVAILABLE:
                try:
                    with Image.open(file_path) as img:
                        img.verify()
                    with Image.open(file_path) as img2:
                        w, h = img2.size
                        fmt = img2.format
                        mode = img2.mode
                        detl = [
                            T["img_dim"].format(w=w, h=h),
                            T["img_fmt"].format(fmt=fmt),
                            T["img_mode"].format(mode=mode),
                        ]
                        if "bitdepth" in img2.info:
                            detl.append(T["img_bitdepth"].format(bd=img2.info["bitdepth"]))
                        if "interlace" in img2.info:
                            detl.append(T["img_interlaced"] if img2.info["interlace"] else T["img_non_interlaced"])
                        info["detalles_contextuales"].append(", ".join(detl))
                except Exception:
                    info["detalles_contextuales"].append(T["img_meta_error"])
            else:
                info["detalles_contextuales"].append(T["pillow_missing"])

        else:
            kind = is_executable_magic(file_path)
            if kind:
                info["detalles_contextuales"].append(T["exec_file"].format(k=kind))
                if kind == "ELF":
                    comp = run_readelf_comment(file_path)
                    if comp:
                        info["detalles_contextuales"].append(f"{T['compiler']} {comp}")

    return info

# =========================
# CLI
# =========================
def parse_algos(s: str) -> Tuple[str, ...]:
    parts = [p.strip().lower() for p in s.split(",") if p.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("Empty algorithm list")
    return tuple(parts)

def main():
    global T
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--json", action="store_true", help=None)  # help tras T
    parser.add_argument("--nofollow", action="store_true", help=None)
    parser.add_argument("--utc", action="store_true", help=None)
    parser.add_argument("--lang", choices=["auto","en","es"], default="auto", help=None)

    size_group = parser.add_mutually_exclusive_group()
    size_group.add_argument("-b", "--bytes", action="store_true")
    size_group.add_argument("-k", "--kb", action="store_true")
    size_group.add_argument("-m", "--mb", action="store_true")
    size_group.add_argument("-g", "--gb", action="store_true")

    parser.add_argument("--no-hash", action="store_true", help=None)
    parser.add_argument("--hash", type=parse_algos, default=DEFAULT_HASHES, help=None)

    parser.add_argument("--max-secret-bytes", type=int, default=1024*1024, help=None)
    parser.add_argument("--max-secret-lines", type=int, default=800, help=None)

    parser.add_argument("fichero", nargs='?')
    args = parser.parse_args()

    # idioma
    lang = choose_lang(args.lang)
    T = I18N[lang]

    # completa helps localizados
    parser._actions[1].help = T["arg_json"]
    parser._actions[2].help = T["arg_nofollow"]
    parser._actions[3].help = T["arg_utc"]
    parser._actions[4].help = T["arg_lang"]
    parser._actions[10].help = T["arg_nohash"]
    parser._actions[11].help = T["arg_hash"]
    parser._actions[12].help = T["arg_msbytes"]
    parser._actions[13].help = T["arg_mslines"]

    if args.help or not args.fichero:
        if not args.json:
            print(T["usage"].format(prog=Path(sys.argv[0]).name))
        sys.exit(0)

    size_opt = "auto"
    if args.bytes: size_opt = "bytes"
    elif args.kb:  size_opt = "kb"
    elif args.mb:  size_opt = "mb"
    elif args.gb:  size_opt = "gb"

    try:
        info = get_file_info(
            args.fichero,
            follow_symlinks=not args.nofollow,
            utc_times=args.utc,
            secret_limits=(args.max_secret_bytes, args.max_secret_lines),
        )

        size_bytes = info["tamaño_bytes"]
        if size_opt == "bytes":
            size_fmt = f"{size_bytes:,} B"
        elif size_opt == "kb":
            size_fmt = f"{size_bytes/1000:.2f} KB"
        elif size_opt == "mb":
            size_fmt = f"{size_bytes/1_000_000:.2f} MB"
        elif size_opt == "gb":
            size_fmt = f"{size_bytes/1_000_000_000:.2f} GB"
        else:
            size_fmt = format_size_iec(size_bytes)
        info["tamaño_formateado"] = size_fmt

        if not args.no_hash:
            info["hashes"] = calcular_hashes(Path(args.fichero), args.hash)
        else:
            info["hashes"] = {}

        if args.json:
            out = {
                "lang": info["lang"],
                "nombre": info["nombre"],
                "realpath": info["realpath"],
                "tipo_mime": info["tipo_mime"],
                "tamaño_bytes": info["tamaño_bytes"],
                "tamaño_formateado": info["tamaño_formateado"],
                "permisos": info["permisos"],
                "propietario": info["propietario"],
                "inodo": info["inodo"],
                "es_symlink": info["es_symlink"],
                "destino_symlink": info["destino_symlink"],
                "fechas": {
                    "modificacion": info["fecha_mod"],
                    "acceso": info["fecha_acc"],
                    "cambio_metadatos": info["fecha_cre"],
                },
                "detalles_contextuales": info["detalles_contextuales"],
                "alertas_seguridad": info["alertas_seguridad"],
                "hashes": info["hashes"],
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            print(c(T["file"], "1;36"), f"     {info['nombre']}")
            if info.get("realpath") and info["realpath"] != info["nombre"]:
                print(c(T["realpath"], "1;36"), f"   {info['realpath']}")
            if info['es_symlink']:
                print(c(T["symlink"], "1;36"), f"    {T['details_arrow']} {info['destino_symlink']}")
            print(c(T["mime"], "1;36"), f" {info['tipo_mime']}")
            print(c(T["size"], "1;36"), f"    {info['tamaño_formateado']}")
            print("-"*40)
            print(c(T["perms"], "1;36"), f" {info['permisos']} (Inodo: {info['inodo']})")
            print(c(T["owner"], "1;36"), f" {info['propietario']}")
            if info['alertas_seguridad']:
                print(c(T["alerts"], "1;33"))
                for a in info['alertas_seguridad']:
                    print(f"  - {a}")
            print("-"*40)
            print(c(T["modified"], "1;36"), f"  {info['fecha_mod']}")
            print(c(T["accessed"], "1;36"), f"  {info['fecha_acc']}")
            print(c(T["created"], "1;36"), f"  {info['fecha_cre']}")
            if info['detalles_contextuales']:
                print("-"*40)
                for d in info['detalles_contextuales']:
                    print(c(T["details_arrow"], "1;32"), d)
            print("-"*40)
            print(c(T["integrity"], "1;36"))
            for algo, h in info["hashes"].items():
                print(f"  {algo.upper()}: {h}")

    except FileNotFoundError as e:
        if args.json:
            print(json.dumps({"error": str(e)}, indent=2, ensure_ascii=False))
        else:
            err(f"{T['error_prefix']} {e}")
        sys.exit(1)
    except Exception as e:
        if args.json:
            print(json.dumps({"error": f"{T['unexpected_error']}: {str(e)}"}, indent=2, ensure_ascii=False))
        else:
            err(f"{T['unexpected_error']}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
