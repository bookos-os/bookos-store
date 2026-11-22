#!/usr/bin/env python3
"""Herramienta CLI para validar, compilar en contenedor aislado, auditar y firmar
aplicaciones comunitarias de BookOS Store sin modificar la infraestructura de bookos.es.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import posixpath
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{1,62}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z.]+)?$")
EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")

ALLOWED_CATEGORIES = {
    "Productividad",
    "Utilidades",
    "Internet",
    "Multimedia",
    "Oficina",
    "Gráficos",
    "Desarrollo",
    "Educación",
    "Juegos",
    "Ciencia",
    "Sistema",
}

ALLOWED_BUILD_SYSTEMS = {
    "tauri",
    "cargo",
    "meson",
    "cmake",
    "make",
    "python",
    "node",
    "custom",
}

RESERVED_PKGS = {
    "apt",
    "apt-get",
    "archlinux-keyring",
    "base",
    "base-devel",
    "bash",
    "binutils",
    "bwrap",
    "bubblewrap",
    "ca-certificates",
    "chromium",
    "coreutils",
    "curl",
    "dash",
    "dbus",
    "dnf",
    "docker",
    "dpkg",
    "efibootmgr",
    "filesystem",
    "firefox",
    "flatpak",
    "gcc",
    "glibc",
    "gnupg",
    "google-chrome",
    "gpg",
    "grub",
    "gtk3",
    "kernel",
    "libc6",
    "linux",
    "linux-firmware",
    "linux-lts",
    "mesa",
    "networkmanager",
    "openssh",
    "openssl",
    "pacman",
    "pam",
    "pipewire",
    "podman",
    "polkit",
    "pulseaudio",
    "python",
    "python3",
    "rpm",
    "rust",
    "cargo",
    "sh",
    "shadow",
    "snapd",
    "sudo",
    "systemd",
    "tar",
    "thunderbird",
    "udev",
    "util-linux",
    "wayland",
    "wget",
    "xdg-desktop-portal",
    "xorg-server",
    "yum",
    "zsh",
}

DANGEROUS_SVG_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"\son[a-z]+\s*=", re.IGNORECASE),
    re.compile(r"<foreignobject\b", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"(?:href|xlink:href|src)\s*=\s*[\"']\s*https?://", re.IGNORECASE),
]

SHELL_META_RE = re.compile(r"(?:[;|&`><]|\$\()")


class ReviewError(Exception):
    """Error controlado de validación, auditoría o firma."""


def valid_https_url(url: str, max_len: int = 256) -> bool:
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > max_len:
        return False
    if any(ch.isspace() or ord(ch) < 32 or ch in "\"'<>`\\" for ch in url):
        return False
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or "@" in parsed.netloc:
        return False
    host = parsed.hostname or ""
    return "." in host and not host.startswith(".") and not host.endswith(".") and ".." not in host


def valid_rel_media_path(val: str) -> bool:
    if valid_https_url(val, max_len=256):
        return True
    if not isinstance(val, str) or not val or len(val) > 256:
        return False
    if val.startswith("/") or "\\" in val or any(ord(c) < 32 for c in val):
        return False
    parts = val.split("/")
    return not any(p in ("", ".", "..") for p in parts)


def validate_manifest(data: Any, catalog_path: Path | None = None) -> list[str]:
    """Valida la estructura y reglas de seguridad de submission.json."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["El manifiesto raíz debe ser un objeto JSON."]

    required_top = {
        "schema_version",
        "pkg",
        "label",
        "subtitle",
        "description",
        "category",
        "author",
        "contact_email",
        "license",
        "version",
        "notes",
        "source",
        "urls",
        "media",
        "privacy",
        "review",
    }
    optional_top = {"label_en", "description_en", "notes_en"}
    missing = sorted(required_top - set(data.keys()))
    if missing:
        errors.append(f"Faltan campos obligatorios: {', '.join(missing)}")
    extra = sorted(set(data.keys()) - required_top - optional_top)
    if extra:
        errors.append(f"Campos no permitidos en raíz: {', '.join(extra)}")

    if data.get("schema_version") != 1:
        errors.append("schema_version debe ser exactamente 1.")

    pkg = data.get("pkg", "")
    if not isinstance(pkg, str) or not PKG_RE.match(pkg):
        errors.append("pkg inválido (use 2-63 caracteres minúsculos [a-z0-9+._-]).")
    else:
        if pkg.startswith("bookos-"):
            errors.append("El prefijo 'bookos-' está reservado para paquetes oficiales.")
        if pkg in RESERVED_PKGS:
            errors.append(f"El nombre de paquete '{pkg}' está reservado por el sistema.")

    def check_str(key: str, min_l: int, max_l: int, req: bool = True) -> None:
        v = data.get(key)
        if v is None and not req:
            return
        if not isinstance(v, str) or not (min_l <= len(v.strip()) <= max_l):
            errors.append(f"'{key}' debe ser texto de {min_l} a {max_l} caracteres.")

    check_str("label", 2, 40)
    check_str("label_en", 1, 40, req=False)
    check_str("subtitle", 4, 60)
    check_str("description", 15, 2000)
    check_str("description_en", 1, 2000, req=False)
    check_str("author", 2, 80)
    check_str("license", 2, 64)
    check_str("notes", 3, 2000)
    check_str("notes_en", 1, 2000, req=False)

    if data.get("category") not in ALLOWED_CATEGORIES:
        errors.append(f"Categoría inválida. Permitidas: {', '.join(sorted(ALLOWED_CATEGORIES))}")

    email = data.get("contact_email", "")
    if not isinstance(email, str) or len(email) > 160 or not EMAIL_RE.match(email):
        errors.append("contact_email no es un correo válido.")

    ver = data.get("version", "")
    if not isinstance(ver, str) or len(ver) > 32 or not VERSION_RE.match(ver):
        errors.append("version inválida (formato esperado: X.Y o X.Y.Z).")

    src = data.get("source")
    if not isinstance(src, dict):
        errors.append("'source' debe ser un objeto.")
    else:
        extra_s = set(src.keys()) - {"git_url", "commit", "tag", "build_system", "build_subdir", "binary_name"}
        if extra_s:
            errors.append(f"Campos desconocidos en source: {', '.join(sorted(extra_s))}")
        if not valid_https_url(src.get("git_url", "")):
            errors.append("source.git_url debe empezar por https:// y ser una URL válida.")
        if not isinstance(src.get("commit"), str) or not COMMIT_RE.match(src["commit"]):
            errors.append("source.commit debe ser un hash SHA-1 de 40 caracteres hexadecimales minúsculos.")
        if src.get("build_system") not in ALLOWED_BUILD_SYSTEMS:
            errors.append(f"source.build_system inválido: {src.get('build_system')}")
        if "build_subdir" in src and not valid_rel_media_path(src["build_subdir"]):
            errors.append("source.build_subdir debe ser una ruta relativa segura.")
        if "binary_name" in src:
            bn = src["binary_name"]
            if not isinstance(bn, str) or not PKG_RE.match(bn):
                errors.append("source.binary_name inválido.")

    urls = data.get("urls")
    if not isinstance(urls, dict):
        errors.append("'urls' debe ser un objeto.")
    else:
        for k in ("homepage", "support", "privacy"):
            if not valid_https_url(urls.get(k, "")):
                errors.append(f"urls.{k} debe ser una URL https:// válida.")

    media = data.get("media")
    if not isinstance(media, dict):
        errors.append("'media' debe ser un objeto.")
    else:
        if not valid_rel_media_path(media.get("icon_path", "")):
            errors.append("media.icon_path inválido.")
        shots = media.get("screenshots")
        if not isinstance(shots, list) or not (1 <= len(shots) <= 5):
            errors.append("media.screenshots debe tener entre 1 y 5 capturas.")
        elif any(not valid_rel_media_path(s) for s in shots):
            errors.append("Alguna entrada de media.screenshots no es una ruta relativa o URL https:// válida.")

    priv = data.get("privacy")
    if not isinstance(priv, dict):
        errors.append("'privacy' debe ser un objeto.")
    else:
        for bk in ("collects_data", "tracking", "network"):
            if not isinstance(priv.get(bk), bool):
                errors.append(f"privacy.{bk} debe ser booleano.")
        dt_list = priv.get("data_types")
        if not isinstance(dt_list, list) or len(dt_list) > 16 or any(
            not isinstance(x, str) or not (2 <= len(x.strip()) <= 48) for x in dt_list
        ):
            errors.append("privacy.data_types debe ser una lista de cadenas (máx. 16).")
        elif priv.get("collects_data") is False and len(dt_list) > 0:
            errors.append("Si privacy.collects_data es false, privacy.data_types debe estar vacío.")
        if "policy_url" in priv and not valid_https_url(priv["policy_url"]):
            errors.append("privacy.policy_url debe ser https:// válida.")

    rev = data.get("review")
    if not isinstance(rev, dict):
        errors.append("'review' debe ser un objeto.")
    else:
        if not isinstance(rev.get("requires_account"), bool):
            errors.append("review.requires_account debe ser booleano.")
        for rk in ("demo_notes", "permissions_rationale"):
            rv = rev.get(rk)
            if not isinstance(rv, str) or len(rv) > 1000:
                errors.append(f"review.{rk} debe ser texto de hasta 1000 caracteres.")

    if catalog_path is not None and isinstance(pkg, str) and PKG_RE.match(pkg):
        try:
            cat = json.loads(catalog_path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"No se pudo leer el catálogo {catalog_path}: {exc}")
            return errors
        for app in cat.get("apps", []):
            if app.get("pkg") == pkg:
                trust = (app.get("trust") or "official").lower()
                if trust != "community":
                    errors.append(
                        f"El paquete '{pkg}' ya existe como app oficial en el catálogo y no puede sobrescribirse."
                    )
                elif app.get("author") and data.get("author") and app["author"] != data["author"]:
                    errors.append(
                        f"Autoría no coincide para '{pkg}': catálogo='{app['author']}', solicitud='{data['author']}'."
                    )
                break

    return errors


def allowed_file_path(norm_path: str, pkg: str) -> bool:
    """Lista blanca estricta de rutas finales permitidas para un paquete comunitario."""
    if norm_path == f"/usr/bin/{pkg}":
        return True
    for prefix in (
        f"/usr/lib/{pkg}/",
        f"/usr/libexec/{pkg}/",
        f"/opt/{pkg}/",
        f"/usr/share/licenses/{pkg}/",
        f"/usr/share/doc/{pkg}/",
        f"/usr/share/{pkg}/",
    ):
        if norm_path.startswith(prefix):
            return True
    if norm_path == f"/usr/share/applications/{pkg}.desktop":
        return True
    if norm_path == f"/usr/share/pixmaps/{pkg}.png":
        return True
    if re.fullmatch(
        rf"/usr/share/icons/hicolor/(\d+x\d+|scalable)/apps/{re.escape(pkg)}\.(png|svg)",
        norm_path,
    ):
        return True
    if re.fullmatch(
        rf"/usr/share/(metainfo|appdata)/{re.escape(pkg)}(\.[A-Za-z0-9_.-]+)?\.xml",
        norm_path,
    ):
        return True
    return False


def allowed_dir_path(norm_dir: str, pkg: str) -> bool:
    """Directorios estándar permitidos para alojar rutas de la lista blanca."""
    clean = norm_dir.rstrip("/") or "/"
    static_parents = {
        "/",
        "/usr",
        "/usr/bin",
        "/usr/lib",
        "/usr/libexec",
        "/usr/share",
        "/usr/share/applications",
        "/usr/share/pixmaps",
        "/usr/share/icons",
        "/usr/share/icons/hicolor",
        "/usr/share/licenses",
        "/usr/share/doc",
        "/usr/share/metainfo",
        "/usr/share/appdata",
        "/opt",
    }
    if clean in static_parents:
        return True
    if re.fullmatch(r"/usr/share/icons/hicolor/(\d+x\d+|scalable)(/apps)?", clean):
        return True
    for root in (
        f"/usr/lib/{pkg}",
        f"/usr/libexec/{pkg}",
        f"/opt/{pkg}",
        f"/usr/share/licenses/{pkg}",
        f"/usr/share/doc/{pkg}",
        f"/usr/share/{pkg}",
    ):
        if clean == root or clean.startswith(root + "/"):
            return True
    return False


def normalize_pkg_member_path(raw: str) -> str:
    p = raw.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    if p in ("", "."):
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"


def check_desktop_content(raw_bytes: bytes, pkg: str) -> list[str]:
    issues: list[str] = []
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return ["El archivo .desktop no es UTF-8 válido."]
    has_exec = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("Exec="):
            has_exec = True
            cmd = s[5:].strip()
            if not cmd or SHELL_META_RE.search(cmd):
                issues.append(f".desktop contiene metacaracteres de shell prohibidos en Exec=: {cmd!r}")
                continue
            try:
                first = shlex.split(cmd)[0]
            except ValueError:
                issues.append(f".desktop Exec= con comillas inválidas: {cmd!r}")
                continue
            if not (first == pkg or first == f"/usr/bin/{pkg}" or first.startswith(f"/opt/{pkg}/")):
                issues.append(f".desktop Exec= apunta fuera del paquete: {first!r}")
    if not has_exec:
        issues.append("El archivo .desktop no declara Exec=.")
    return issues


def check_svg_content(raw_bytes: bytes) -> list[str]:
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ["No se pudo decodificar el archivo SVG."]
    issues: list[str] = []
    for pat in DANGEROUS_SVG_PATTERNS:
        if pat.search(text):
            issues.append(f"SVG rechazado por patrón potencialmente activo/externo ({pat.pattern}).")
    return issues


def parse_cpio_newc(data: bytes) -> list[dict[str, Any]]:
    """Lector puro de archivos cpio formato SVR4/newc (salida estándar de rpm2cpio)."""
    entries: list[dict[str, Any]] = []
    pos = 0
    total_len = len(data)
    while pos + 110 <= total_len:
        hdr = data[pos : pos + 110]
        magic = hdr[:6]
        if magic not in (b"070701", b"070702"):
            raise ReviewError("Flujo CPIO inválido dentro del paquete RPM.")
        mode = int(hdr[14:22], 16)
        filesize = int(hdr[54:62], 16)
        namesize = int(hdr[94:102], 16)
        pos += 110
        name_raw = data[pos : pos + namesize]
        name = name_raw.rstrip(b"\x00").decode("utf-8", errors="surrogateescape")
        pos += namesize
        pos = (pos + 3) & ~3
        file_bytes = data[pos : pos + filesize]
        pos += filesize
        pos = (pos + 3) & ~3
        if name == "TRAILER!!!":
            break
        entries.append({"name": name, "mode": mode, "size": filesize, "bytes": file_bytes})
    return entries


def audit_entries(
    entries: list[dict[str, Any]],
    pkg: str,
    max_uncompressed_bytes: int,
    max_files: int,
) -> list[str]:
    """Audita todos los miembros del sistema de archivos de un paquete."""
    errors: list[str] = []
    if len(entries) > max_files:
        errors.append(f"Demasiados ficheros en el paquete ({len(entries)} > {max_files}).")
        return errors

    total_size = 0
    for ent in entries:
        raw_name = ent["name"]
        mode = ent["mode"]
        size = ent["size"]
        kind = ent["kind"]  # "dir", "reg", "sym", "lnk", "other"
        linkname = ent.get("linkname", "")
        content = ent.get("bytes", b"")

        total_size += size
        if total_size > max_uncompressed_bytes:
            errors.append(
                f"Tamaño descomprimido excede el límite ({total_size} > {max_uncompressed_bytes} bytes)."
            )
            return errors

        parts = [p for p in raw_name.replace("\\", "/").split("/") if p not in ("", ".")]
        if ".." in parts:
            errors.append(f"Path traversal ('..') prohibido en entrada: {raw_name}")
            continue
        norm = normalize_pkg_member_path(raw_name)

        if kind == "other":
            errors.append(f"Tipo de nodo especial prohibido (dispositivo/FIFO): {norm}")
            continue

        if mode & (stat.S_ISUID | stat.S_ISGID):
            errors.append(f"Bit SUID/SGID prohibido en {norm} (modo {oct(mode)})")
        if kind != "sym" and (mode & stat.S_IWOTH):
            errors.append(f"Permisos world-writable prohibidos en {norm} (modo {oct(mode)})")

        if kind == "dir":
            if not allowed_dir_path(norm, pkg):
                errors.append(f"Directorio fuera de la lista blanca: {norm}")
            continue

        if not allowed_file_path(norm, pkg):
            errors.append(f"Ruta de fichero fuera de la lista blanca: {norm}")
            continue

        if kind in ("sym", "lnk"):
            if not linkname:
                errors.append(f"Enlace sin destino: {norm}")
                continue
            if kind == "lnk":
                target = normalize_pkg_member_path(linkname)
            elif linkname.startswith("/"):
                target = posixpath.normpath(linkname)
            else:
                target = posixpath.normpath(posixpath.join(posixpath.dirname(norm), linkname))
            if ".." in target.split("/") or (
                not allowed_file_path(target, pkg) and not allowed_dir_path(target, pkg)
            ):
                errors.append(f"Enlace apunta fuera de las rutas permitidas: {norm} -> {linkname} ({target})")
            continue

        # Regular file content checks
        if norm.endswith(".desktop"):
            errors.extend(check_desktop_content(content, pkg))
        elif norm.endswith(".svg"):
            errors.extend(check_svg_content(content))

    return errors


def strip_dot_slash(raw: str) -> str:
    clean = raw
    while clean.startswith("./"):
        clean = clean[2:]
    return clean.lstrip("/")


def extract_tar_entries(tf: tarfile.TarFile, pkg: str, ignore_meta: set[str] | None = None) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    entries: list[dict[str, Any]] = []
    meta_files: dict[str, bytes] = {}
    ignore_meta = ignore_meta or set()
    for member in tf:
        clean = strip_dot_slash(member.name)
        if clean in ignore_meta:
            fobj = tf.extractfile(member)
            if fobj is not None:
                meta_files[clean] = fobj.read(512 * 1024)
            else:
                meta_files[clean] = b""
            continue
        if member.isdir():
            kind = "dir"
        elif member.issym():
            kind = "sym"
        elif member.islnk():
            kind = "lnk"
        elif member.isreg():
            kind = "reg"
        else:
            kind = "other"
        raw_bytes = b""
        if kind == "reg":
            norm = normalize_pkg_member_path(member.name)
            if norm.endswith(".desktop") or norm.endswith(".svg"):
                fobj = tf.extractfile(member)
                if fobj is not None:
                    raw_bytes = fobj.read(2 * 1024 * 1024)
        entries.append(
            {
                "name": member.name,
                "mode": member.mode,
                "size": member.size,
                "kind": kind,
                "linkname": member.linkname,
                "bytes": raw_bytes,
            }
        )
    return entries, meta_files


def audit_pkg(pkg_path: Path, pkg: str, max_mb: int = 200) -> dict[str, Any]:
    """Audita un paquete .pkg.tar.zst, .rpm o .deb sin instalarlo jamás."""
    if not pkg_path.is_file():
        return {"ok": False, "pkg": pkg, "file": str(pkg_path), "errors": ["El archivo no existe."], "warnings": []}

    file_size = pkg_path.stat().st_size
    max_bytes = max_mb * 1024 * 1024
    max_uncompressed = max_mb * 3 * 1024 * 1024
    max_files = 5000
    errors: list[str] = []
    warnings: list[str] = []

    if file_size > max_bytes:
        errors.append(f"El paquete supera el límite de {max_mb} MB ({file_size} bytes).")

    name = pkg_path.name.lower()
    entries: list[dict[str, Any]] = []

    if name.endswith(".pkg.tar.zst"):
        zstd = shutil.which("zstd")
        if not zstd:
            errors.append("Falta 'zstd' en el sistema para auditar paquetes .pkg.tar.zst.")
        else:
            meta: dict[str, bytes] = {}
            with subprocess.Popen([zstd, "-dc", str(pkg_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
                try:
                    assert proc.stdout is not None
                    with tarfile.open(fileobj=proc.stdout, mode="r|*") as tf:
                        entries, meta = extract_tar_entries(
                            tf, pkg, ignore_meta={".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"}
                        )
                except Exception as exc:
                    errors.append(f"Error leyendo tar.zst: {exc}")
                finally:
                    proc.wait()
                if proc.returncode != 0:
                    stderr_txt = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
                    errors.append(f"zstd devolvió error ({proc.returncode}): {stderr_txt.strip()}")
            if ".INSTALL" in meta:
                errors.append("Contiene script de instalación .INSTALL (ejecución como root prohibida).")
            pkginfo = meta.get(".PKGINFO", b"").decode("utf-8", errors="replace")
            if pkginfo:
                found_pkgname = None
                for line in pkginfo.splitlines():
                    if "=" not in line or line.strip().startswith("#"):
                        continue
                    k, v = [x.strip() for x in line.split("=", 1)]
                    if k == "pkgname":
                        found_pkgname = v
                    elif k in ("conflict", "replaces"):
                        errors.append(f"Relación peligrosa prohibida en .PKGINFO ({k} = {v}).")
                    elif k == "provides":
                        prov_name = v.split("=")[0].strip()
                        if prov_name != pkg:
                            errors.append(f"Provides ajeno prohibido en .PKGINFO: {v}")
                if found_pkgname and found_pkgname != pkg:
                    errors.append(f".PKGINFO declara pkgname='{found_pkgname}' pero se esperaba '{pkg}'.")
            else:
                errors.append("El paquete Arch no contiene .PKGINFO.")

    elif name.endswith(".deb"):
        dpkg_deb = shutil.which("dpkg-deb")
        if not dpkg_deb:
            errors.append("Falta 'dpkg-deb' para auditar paquetes .deb.")
        else:
            meta_out = subprocess.run([dpkg_deb, "-f", str(pkg_path)], capture_output=True, text=True)
            if meta_out.returncode != 0:
                errors.append(f"dpkg-deb -f falló: {meta_out.stderr.strip()}")
            else:
                declared_pkg = None
                for line in meta_out.stdout.splitlines():
                    if ":" not in line or line.startswith((" ", "\t")):
                        continue
                    field, val = [x.strip() for x in line.split(":", 1)]
                    fl = field.lower()
                    if fl == "package":
                        declared_pkg = val
                    elif fl in ("conflicts", "replaces", "breaks") and val:
                        errors.append(f"Cabecera peligrosa prohibida en control .deb ({field}: {val}).")
                    elif fl == "provides" and val:
                        provs = [p.strip().split()[0] for p in val.split(",") if p.strip()]
                        foreign = [p for p in provs if p != pkg]
                        if foreign:
                            errors.append(f"Provides ajeno prohibido en .deb: {', '.join(foreign)}")
                if declared_pkg and declared_pkg != pkg:
                    errors.append(f"El .deb declara Package: {declared_pkg} pero se esperaba {pkg}.")

            with subprocess.Popen([dpkg_deb, "--ctrl-tarfile", str(pkg_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ctrl_proc:
                try:
                    assert ctrl_proc.stdout is not None
                    with tarfile.open(fileobj=ctrl_proc.stdout, mode="r|*") as ctf:
                        for cm in ctf:
                            base = posixpath.basename(strip_dot_slash(cm.name))
                            if base in {"preinst", "postinst", "prerm", "postrm", "config", "triggers"}:
                                errors.append(f"Script de mantenedor prohibido en .deb: {base}")
                except Exception as exc:
                    errors.append(f"Error inspeccionando control tar de .deb: {exc}")
                finally:
                    ctrl_proc.wait()

            with subprocess.Popen([dpkg_deb, "--fsys-tarfile", str(pkg_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as fsys_proc:
                try:
                    assert fsys_proc.stdout is not None
                    with tarfile.open(fileobj=fsys_proc.stdout, mode="r|*") as ftf:
                        entries, _ = extract_tar_entries(ftf, pkg)
                except Exception as exc:
                    errors.append(f"Error inspeccionando contenido de .deb: {exc}")
                finally:
                    fsys_proc.wait()

    elif name.endswith(".rpm"):
        rpm_bin = shutil.which("rpm")
        rpm2cpio = shutil.which("rpm2cpio")
        if not rpm_bin or not rpm2cpio:
            errors.append("Faltan 'rpm' o 'rpm2cpio' para auditar paquetes .rpm.")
        else:
            q_name = subprocess.run([rpm_bin, "-qp", "--qf", "%{NAME}\n", str(pkg_path)], capture_output=True, text=True)
            if q_name.returncode == 0 and q_name.stdout.strip() != pkg:
                errors.append(f"RPM declara Name='{q_name.stdout.strip()}' pero se esperaba '{pkg}'.")

            scripts = subprocess.run([rpm_bin, "-qp", "--scripts", "--triggers", str(pkg_path)], capture_output=True, text=True)
            if scripts.returncode != 0:
                errors.append(f"No se pudieron consultar scripts del RPM: {scripts.stderr.strip()}")
            elif scripts.stdout.strip():
                errors.append("El RPM contiene scriptlets/triggers (ejecución como root prohibida).")

            for flag, label in (("--conflicts", "Conflicts"), ("--obsoletes", "Obsoletes")):
                rel = subprocess.run([rpm_bin, "-qp", flag, str(pkg_path)], capture_output=True, text=True)
                if rel.returncode == 0 and rel.stdout.strip():
                    errors.append(f"Relación peligrosa prohibida en RPM ({label}): {rel.stdout.strip()}")

            prov = subprocess.run([rpm_bin, "-qp", "--provides", str(pkg_path)], capture_output=True, text=True)
            if prov.returncode == 0:
                for pline in prov.stdout.splitlines():
                    p = pline.strip()
                    if not p:
                        continue
                    head = re.split(r"[=(\s]", p, maxsplit=1)[0]
                    if head != pkg:
                        errors.append(f"Provides ajeno prohibido en RPM: {p}")

            c_res = subprocess.run([rpm2cpio, str(pkg_path)], capture_output=True)
            if c_res.returncode != 0:
                errors.append(f"rpm2cpio falló: {c_res.stderr.decode('utf-8', errors='replace').strip()}")
            else:
                try:
                    cpio_items = parse_cpio_newc(c_res.stdout)
                    for item in cpio_items:
                        m = item["mode"]
                        ftype = stat.S_IFMT(m)
                        if ftype == stat.S_IFDIR:
                            kind, linkname = "dir", ""
                        elif ftype == stat.S_IFLNK:
                            kind, linkname = "sym", item["bytes"].decode("utf-8", errors="replace")
                        elif ftype == stat.S_IFREG:
                            kind, linkname = "reg", ""
                        else:
                            kind, linkname = "other", ""
                        entries.append(
                            {
                                "name": item["name"],
                                "mode": m,
                                "size": item["size"],
                                "kind": kind,
                                "linkname": linkname,
                                "bytes": item["bytes"] if kind == "reg" else b"",
                            }
                        )
                except ReviewError as exc:
                    errors.append(str(exc))
    else:
        errors.append("Extensión de paquete no soportada (usa .pkg.tar.zst, .rpm o .deb).")

    if entries:
        errors.extend(audit_entries(entries, pkg, max_uncompressed, max_files))
    elif not errors:
        errors.append("El paquete no contiene ficheros.")

    clamscan = shutil.which("clamscan")
    if clamscan:
        av = subprocess.run([clamscan, "--no-summary", str(pkg_path)], capture_output=True, text=True)
        if av.returncode == 1:
            errors.append(f"ClamAV detectó malware: {av.stdout.strip()}")
        elif av.returncode not in (0,):
            warnings.append(f"ClamAV devolvió código {av.returncode} (no concluyente).")
    else:
        warnings.append("clamscan no está instalado; se omitió escaneo antivirus.")

    return {
        "ok": len(errors) == 0,
        "pkg": pkg,
        "file": pkg_path.name,
        "size": file_size,
        "entries": len(entries),
        "errors": errors,
        "warnings": warnings,
    }


def sanitize_image(src: Path, dst: Path, max_dim: int = 1920) -> None:
    magick = shutil.which("magick") or shutil.which("convert")
    if not magick:
        raise ReviewError("Falta ImageMagick ('magick') para sanitizar imágenes.")
    if dst.suffix.lower() not in (".png", ".webp"):
        raise ReviewError("La salida sanitizada debe ser .png o .webp.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        [magick, f"{src}[0]", "-auto-orient", "-strip", "-resize", f"{max_dim}x{max_dim}>", str(dst)],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise ReviewError(f"Error sanitizando imagen {src}: {res.stderr.strip()}")


def init_key(out_dir: Path, embed_pubkey: bool = False) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if not openssl:
        raise ReviewError("Falta 'openssl' para generar el par de claves Ed25519.")
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    priv = out_dir / "catalog-priv.pem"
    pub = out_dir / "catalog-pub.pem"
    if priv.exists() or pub.exists():
        raise ReviewError(f"Ya existe una clave en {out_dir}. Muévela o usa otra ruta para no sobrescribirla.")
    r1 = subprocess.run([openssl, "genpkey", "-algorithm", "Ed25519", "-out", str(priv)], capture_output=True, text=True)
    if r1.returncode != 0:
        raise ReviewError(f"Error generando clave privada: {r1.stderr.strip()}")
    os.chmod(priv, 0o600)
    r2 = subprocess.run([openssl, "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], capture_output=True, text=True)
    if r2.returncode != 0:
        raise ReviewError(f"Error extrayendo clave pública: {r2.stderr.strip()}")
    if embed_pubkey:
        repo_pub = Path(__file__).resolve().parents[2] / "src-tauri" / "keys" / "catalog-pub.pem"
        repo_pub.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pub, repo_pub)
    return priv, pub


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise ReviewError(f"No se encuentra {label}: {path}")


def parse_generated_at(val: Any) -> int:
    if val is None or val == "":
        return 0
    if isinstance(val, (int, float)):
        return max(0, int(val))
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return 0
        if s.isdigit():
            return int(s)
        try:
            parsed = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReviewError(f"Formato inválido de generated_at: {val!r}") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return max(0, int(parsed.timestamp()))
    raise ReviewError(f"Tipo inválido de generated_at: {type(val).__name__}")


def format_generated_at(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat()


def sign_catalog(catalog_path: Path, key_path: Path, out_sig: Path | None = None, stamp: bool = False) -> Path:
    require_file(catalog_path, "el catálogo")
    require_file(key_path, "la clave privada")
    openssl = shutil.which("openssl")
    if not openssl:
        raise ReviewError("Falta 'openssl' para firmar el catálogo.")
    if stamp:
        doc = json.loads(catalog_path.read_text(encoding="utf-8"))
        now = int(time.time())
        prev = parse_generated_at(doc.get("generated_at"))
        next_ts = max(now, prev + 1) if prev else now
        doc["generated_at"] = format_generated_at(next_ts)
        catalog_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    sig_dest = out_sig or Path(f"{catalog_path}.sig")
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tmp_raw = Path(tf.name)
    try:
        res = subprocess.run(
            [openssl, "pkeyutl", "-sign", "-inkey", str(key_path), "-rawin", "-in", str(catalog_path), "-out", str(tmp_raw)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise ReviewError(f"Error firmando catálogo: {res.stderr.strip()}")
        raw_sig = tmp_raw.read_bytes()
        if len(raw_sig) != 64:
            raise ReviewError(f"Longitud inesperada de firma Ed25519: {len(raw_sig)} bytes.")
        sig_dest.write_text(base64.b64encode(raw_sig).decode("ascii") + "\n", encoding="utf-8")
    finally:
        tmp_raw.unlink(missing_ok=True)
    return sig_dest


def verify_catalog(catalog_path: Path, sig_path: Path, pubkey_path: Path) -> None:
    require_file(catalog_path, "el catálogo")
    require_file(sig_path, "el archivo de firma")
    require_file(pubkey_path, "la clave pública")
    openssl = shutil.which("openssl")
    if not openssl:
        raise ReviewError("Falta 'openssl' para verificar la firma.")
    raw = sig_path.read_bytes()
    if len(raw) == 64:
        sig_bytes = raw
    else:
        try:
            sig_bytes = base64.b64decode(raw.decode("utf-8").strip(), validate=True)
        except Exception as exc:
            raise ReviewError(f"Firma base64 inválida: {exc}") from exc
    if len(sig_bytes) != 64:
        raise ReviewError("Longitud de firma Ed25519 inválida.")
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tmp_raw = Path(tf.name)
    tmp_raw.write_bytes(sig_bytes)
    try:
        res = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pubkey_path), "-rawin", "-in", str(catalog_path), "-sigfile", str(tmp_raw)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise ReviewError("Verificación criptográfica fallida: la firma no corresponde al catálogo o clave pública.")
    finally:
        tmp_raw.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_isolated(
    submission_path: Path,
    out_dir: Path,
    runtime: str | None = None,
    image: str = "docker.io/library/archlinux:latest",
) -> None:
    submission = json.loads(submission_path.read_text(encoding="utf-8"))
    errs = validate_manifest(submission)
    if errs:
        raise ReviewError("Manifiesto inválido:\n- " + "\n- ".join(errs))

    rt = runtime or ("podman" if shutil.which("podman") else ("docker" if shutil.which("docker") else None))
    if not rt:
        raise ReviewError("No se encontró 'podman' ni 'docker' para la compilación aislada.")

    out_dir.mkdir(parents=True, exist_ok=True)
    src = submission["source"]
    pkg = submission["pkg"]
    ver = submission["version"]
    bin_name = src.get("binary_name") or pkg
    subdir = src.get("build_subdir", "")
    build_sys = src["build_system"]

    # Script ejecutado dentro del contenedor efímero sin privilegios.
    inner_script = f"""set -euo pipefail
umask 022
git clone --filter=blob:none --no-checkout {shlex.quote(src['git_url'])} /work/src
cd /work/src
git fetch --depth 1 origin {shlex.quote(src['commit'])}
git checkout --detach {shlex.quote(src['commit'])}
ACTUAL=$(git rev-parse HEAD)
if [ "$ACTUAL" != {shlex.quote(src['commit'])} ]; then
  echo "ERROR: commit obtenido ($ACTUAL) distinto al esperado" >&2
  exit 1
fi
{f"cd {shlex.quote(subdir)}" if subdir else ""}
case {shlex.quote(build_sys)} in
  cargo)
    cargo build --release --locked
    install -Dm755 "target/release/{bin_name}" "/work/stage/usr/bin/{pkg}"
    ;;
  meson)
    meson setup /work/b --prefix=/usr
    meson compile -C /work/b
    DESTDIR=/work/stage meson install -C /work/b
    ;;
  cmake)
    cmake -B /work/b -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release
    cmake --build /work/b -j"$(nproc)"
    DESTDIR=/work/stage cmake --install /work/b
    ;;
  make)
    make -j"$(nproc)"
    DESTDIR=/work/stage PREFIX=/usr make install
    ;;
  *)
    echo "build_system '{build_sys}' requiere paso de empaquetado dedicado (p. ej. PKGBUILD/nfpm)." >&2
    exit 2
    ;;
esac
if command -v nfpm >/dev/null 2>&1; then
  cat >/work/nfpm.yaml <<EOF
name: "{pkg}"
arch: "amd64"
platform: "linux"
version: "{ver}"
maintainer: "{submission['author']}"
description: "{submission['subtitle']}"
homepage: "{submission['urls']['homepage']}"
license: "{submission['license']}"
contents:
  - src: /work/stage/usr/
    dst: /usr/
EOF
  nfpm pkg --config /work/nfpm.yaml --packager archlinux --target /out/
  nfpm pkg --config /work/nfpm.yaml --packager rpm --target /out/
  nfpm pkg --config /work/nfpm.yaml --packager deb --target /out/
else
  echo "AVISO: nfpm no está instalado en la imagen {image}; artefactos en /work/stage" >&2
fi
"""
    cmd = [
        rt,
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=4g",
        "-v",
        f"{out_dir.resolve()}:/out:Z",
        image,
        "bash",
        "-c",
        inner_script,
    ]
    res = subprocess.run(cmd)
    if res.returncode != 0:
        raise ReviewError(f"La compilación aislada falló con código {res.returncode}.")

    pkgs = [p for p in out_dir.iterdir() if p.name.endswith((".pkg.tar.zst", ".rpm", ".deb"))]
    if not pkgs:
        raise ReviewError(f"No se generaron paquetes en {out_dir}.")
    for p in pkgs:
        report = audit_pkg(p, pkg)
        if not report["ok"]:
            raise ReviewError(f"Auditoría fallida para {p.name}:\n- " + "\n- ".join(report["errors"]))


def merge_catalog(
    catalog_path: Path,
    submission_path: Path,
    pkg_dir: Path,
    base_url: str,
    out_path: Path,
    icon_url: str | None = None,
    screenshots: list[str] | None = None,
) -> Path:
    if not base_url.startswith("https://bookos.es/"):
        raise ReviewError("--base-url debe pertenecer a https://bookos.es/")

    submission = json.loads(submission_path.read_text(encoding="utf-8"))
    errs = validate_manifest(submission, catalog_path=catalog_path if catalog_path.exists() else None)
    if errs:
        raise ReviewError("Manifiesto inválido:\n- " + "\n- ".join(errs))

    pkg = submission["pkg"]
    pkg_files = sorted(
        p for p in pkg_dir.iterdir()
        if p.is_file() and p.name.endswith((".pkg.tar.zst", ".rpm", ".deb"))
    )
    if not pkg_files:
        raise ReviewError(f"No hay paquetes (.pkg.tar.zst/.rpm/.deb) en {pkg_dir}.")

    assets: list[dict[str, Any]] = []
    for pf in pkg_files:
        rep = audit_pkg(pf, pkg)
        if not rep["ok"]:
            raise ReviewError(f"Auditoría bloqueada para {pf.name}:\n- " + "\n- ".join(rep["errors"]))
        kind = "pacman" if pf.name.endswith(".pkg.tar.zst") else ("dnf" if pf.name.endswith(".rpm") else "apt")
        assets.append(
            {
                "name": pf.name,
                "kind": kind,
                "browser_download_url": f"{base_url.rstrip('/')}/{pf.name}",
                "sha256": sha256_file(pf),
                "size": pf.stat().st_size,
            }
        )

    if catalog_path.exists():
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    else:
        catalog = {"apps": []}

    today = dt.date.today().isoformat()
    now = int(time.time())
    prev_gen = parse_generated_at(catalog.get("generated_at"))
    catalog["generated_at"] = format_generated_at(max(now, prev_gen + 1) if prev_gen else now)

    apps: list[dict[str, Any]] = list(catalog.get("apps", []))
    existing = next((a for a in apps if a.get("pkg") == pkg), None)
    if existing and (existing.get("trust") or "official").lower() != "community":
        raise ReviewError(f"No se puede sobrescribir la app oficial '{pkg}'.")

    prev_releases = list(existing.get("releases", [])) if existing else []
    new_rel: dict[str, Any] = {
        "version": submission["version"],
        "released": today,
        "channel": "community",
        "notes": submission["notes"],
    }
    if submission.get("notes_en"):
        new_rel["notes_en"] = submission["notes_en"]
    releases = [new_rel] + [r for r in prev_releases if r.get("version") != submission["version"]]

    priv_in = submission["privacy"]
    priv_out = {
        "collects_data": bool(priv_in["collects_data"]),
        "tracking": bool(priv_in["tracking"]),
        "network": bool(priv_in["network"]),
        "data_types": list(priv_in["data_types"]),
        "policy_url": priv_in.get("policy_url") or submission["urls"]["privacy"],
    }

    entry: dict[str, Any] = {
        "pkg": pkg,
        "trust": "community",
        "label": submission["label"],
        "subtitle": submission["subtitle"],
        "description": submission["description"],
        "category": submission["category"],
        "author": submission["author"],
        "license": submission["license"],
        "available": submission["version"],
        "released": today,
        "notes": submission["notes"],
        "html_url": submission["urls"]["homepage"],
        "source_url": submission["source"]["git_url"],
        "support_url": submission["urls"]["support"],
        "privacy_url": submission["urls"]["privacy"],
        "privacy": priv_out,
        "assets": assets,
        "releases": releases[:15],
    }
    if submission.get("label_en"):
        entry["label_en"] = submission["label_en"]
    if submission.get("description_en"):
        entry["description_en"] = submission["description_en"]
    if submission.get("notes_en"):
        entry["notes_en"] = submission["notes_en"]
    if icon_url:
        if not icon_url.startswith("https://bookos.es/"):
            raise ReviewError("--icon-url debe alojarse en https://bookos.es/")
        entry["icon_url"] = icon_url
    if screenshots:
        for s in screenshots:
            if not s.startswith("https://bookos.es/"):
                raise ReviewError(f"Las capturas deben alojarse en https://bookos.es/: {s}")
        entry["screenshots"] = screenshots

    new_apps = [a for a in apps if a.get("pkg") != pkg]
    new_apps.append(entry)
    catalog["apps"] = new_apps

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BookOS Store — Auditoría, compilación aislada y firma offline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init-key", help="Genera par de claves Ed25519 para firmar store.json")
    p_init.add_argument("--out-dir", type=Path, default=Path.home() / ".config" / "bookos-signing")
    p_init.add_argument("--embed-pubkey", action="store_true", help="Copia la clave pública en src-tauri/keys/catalog-pub.pem")

    p_val = sub.add_parser("validate-manifest", help="Valida un submission.json")
    p_val.add_argument("manifest", type=Path)
    p_val.add_argument("--catalog", type=Path, default=None)

    p_aud = sub.add_parser("audit-pkg", help="Audita un paquete .pkg.tar.zst, .rpm o .deb sin instalarlo")
    p_aud.add_argument("package", type=Path)
    p_aud.add_argument("--pkg", required=True)
    p_aud.add_argument("--max-mb", type=int, default=200)
    p_aud.add_argument("--json", action="store_true")

    p_img = sub.add_parser("sanitize-image", help="Elimina metadatos EXIF y recodifica imagen a PNG/WebP")
    p_img.add_argument("input", type=Path)
    p_img.add_argument("output", type=Path)
    p_img.add_argument("--max-dim", type=int, default=1920)

    p_bld = sub.add_parser("build-isolated", help="Clona, compila y audita en contenedor desechable")
    p_bld.add_argument("manifest", type=Path)
    p_bld.add_argument("--out-dir", type=Path, required=True)
    p_bld.add_argument("--runtime", choices=["podman", "docker"], default=None)
    p_bld.add_argument("--image", default="docker.io/library/archlinux:latest")

    p_mrg = sub.add_parser("merge-catalog", help="Audita paquetes y añade app comunitaria al catálogo")
    p_mrg.add_argument("catalog", type=Path)
    p_mrg.add_argument("--submission", type=Path, required=True)
    p_mrg.add_argument("--pkg-dir", type=Path, required=True)
    p_mrg.add_argument("--base-url", required=True)
    p_mrg.add_argument("--out", type=Path, required=True)
    p_mrg.add_argument("--icon-url", default=None)
    p_mrg.add_argument("--screenshots", nargs="*", default=None)

    p_sig = sub.add_parser("sign-catalog", help="Firma store.json con Ed25519")
    p_sig.add_argument("catalog", type=Path)
    p_sig.add_argument("--key", type=Path, required=True)
    p_sig.add_argument("--out", type=Path, default=None)
    p_sig.add_argument("--stamp", action="store_true", help="Actualiza generated_at antes de firmar")

    p_ver = sub.add_parser("verify-catalog", help="Verifica store.json contra store.json.sig")
    p_ver.add_argument("catalog", type=Path)
    p_ver.add_argument("--sig", type=Path, required=True)
    p_ver.add_argument("--pubkey", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "init-key":
            priv, pub = init_key(args.out_dir, embed_pubkey=args.embed_pubkey)
            print(f"Clave privada (NO compartir): {priv}\nClave pública: {pub}")
            return 0
        if args.cmd == "validate-manifest":
            require_file(args.manifest, "el manifiesto")
            if args.catalog is not None:
                require_file(args.catalog, "el catálogo")
            data = json.loads(args.manifest.read_text(encoding="utf-8"))
            errs = validate_manifest(data, catalog_path=args.catalog)
            if errs:
                for e in errs:
                    print(f"ERROR: {e}", file=sys.stderr)
                return 1
            print(f"OK: {args.manifest} es válido para '{data['pkg']}'.")
            return 0
        if args.cmd == "audit-pkg":
            rep = audit_pkg(args.package, args.pkg, max_mb=args.max_mb)
            if args.json:
                print(json.dumps(rep, indent=2, ensure_ascii=False))
            else:
                print(f"[{'OK' if rep['ok'] else 'RECHAZADO'}] {rep['file']} ({rep['entries']} entradas, {rep['size']} B)")
                for w in rep["warnings"]:
                    print(f"  AVISO: {w}")
                for e in rep["errors"]:
                    print(f"  ERROR: {e}", file=sys.stderr)
            return 0 if rep["ok"] else 1
        if args.cmd == "sanitize-image":
            sanitize_image(args.input, args.output, max_dim=args.max_dim)
            print(f"OK: imagen sanitizada en {args.output}")
            return 0
        if args.cmd == "build-isolated":
            build_isolated(args.manifest, args.out_dir, runtime=args.runtime, image=args.image)
            print(f"OK: paquetes compilados y auditados en {args.out_dir}")
            return 0
        if args.cmd == "merge-catalog":
            out = merge_catalog(
                args.catalog,
                args.submission,
                args.pkg_dir,
                args.base_url,
                args.out,
                icon_url=args.icon_url,
                screenshots=args.screenshots,
            )
            print(f"OK: catálogo actualizado en {out}")
            return 0
        if args.cmd == "sign-catalog":
            sig = sign_catalog(args.catalog, args.key, out_sig=args.out, stamp=args.stamp)
            print(f"OK: firma generada en {sig}")
            return 0
        if args.cmd == "verify-catalog":
            verify_catalog(args.catalog, args.sig, args.pubkey)
            print("OK: firma válida.")
            return 0
    except ReviewError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
