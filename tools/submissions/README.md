# Sistema de envío, auditoría y publicación segura de apps en BookOS Store

Flujo diseñado para abrir **BookOS Store** a desarrolladores externos sin modificar la infraestructura actual (`bookos.es` con Apache/PHP), sin depender de GitHub y manteniendo la clave de firma **100% offline**.

## Resumen del flujo

1. **Envío sin binarios (`https://developer.bookos.es/submit/`):** el autor rellena el formulario web de solo texto (`tools/submissions/web/`) con metadatos, enlace al repositorio + commit exacto y bloque de privacidad estilo App Store. PHP valida, aplica *rate limit* y reenvía el JSON al correo privado del equipo sin guardar archivos ni base de datos.
2. **Compilación aislada y auditoría (`bookos-review.py`):** en tu equipo de mantenimiento, compilas el commit exacto dentro de un contenedor efímero sin privilegios y ejecutas el auditor automático de paquetes (`.pkg.tar.zst`, `.rpm`, `.deb`).
3. **Publicación estática y firma offline:** fusionas la app como `"trust": "community"` en `store.json`, firmas `store.json` → `store.json.sig` con Ed25519 offline y subes los artefactos estáticos a `bookos.es`.

---

## 1. Generar la clave Ed25519 (una sola vez)

```bash
./tools/submissions/bookos-review.py init-key --embed-pubkey
```

- Guarda la clave privada en `~/.config/bookos-signing/catalog-priv.pem` (permisos `600`, **nunca la subas al repositorio ni a `bookos.es`**).
- Copia la clave pública a `src-tauri/keys/catalog-pub.pem`. Este repositorio **ya tiene la clave pública activa embebida**, por lo que las compilaciones nuevas exigirán `store.json.sig` válido en cada descarga (modo *fail-closed*). Asegúrate de subir `store.json.sig` a `bookos.es/api/` antes de distribuir el nuevo binario.

---

## 2. Desplegar el formulario web en `developer.bookos.es/submit/`

1. Copia el contenido de `tools/submissions/web/` al directorio `/submit/` del VirtualHost `developer.bookos.es`.
2. Copia `config.example.php` a `config.php` y configura:
   - `recipient_email` (`apps@bookos.es`) y `from_email`.
   - `hmac_secret`: genera un secreto aleatorio largo (p. ej. `openssl rand -hex 32`).
   - `rate_limit_dir`: ruta fuera de `public_html`, p. ej. `/var/tmp/bookos-submit-rl`.
3. Verifica que `.htaccess` bloquea cualquier petición HTTP directa a `config.php` y `config.example.php`.

---

## 3. Cuenta SFTP restringida en `bookos.es` (recomendado)

Para subir paquetes y catálogos sin exponer todo el servidor:
- Crea una cuenta SFTP dedicada con `ChrootDirectory` apuntando únicamente a `/store-files/community/` y al directorio de `/api/store.json` + `/api/store.json.sig`.
- Sin acceso a shell (`ForceCommand internal-sftp`) ni permisos de escritura sobre `/store-files/official/` o scripts `.php`.

---

## 4. Flujo diario para revisar y publicar una app

Guarda el JSON recibido por correo como `solicitud.json` y ejecuta:

```bash
# 1. Validar esquema, nombre no reservado y autoría
./tools/submissions/bookos-review.py validate-manifest solicitud.json --catalog store.json

# 2. Compilar el commit exacto en contenedor desechable y auditar paquetes
./tools/submissions/bookos-review.py build-isolated solicitud.json --out-dir ./build-out

# 3. Sanitizar icono y capturas (elimina EXIF y recodifica limpio a PNG/WebP)
./tools/submissions/bookos-review.py sanitize-image raw-icon.png ./media/icon.png --max-dim 512
./tools/submissions/bookos-review.py sanitize-image raw-shot1.png ./media/shot1.webp --max-dim 1920

# 4. Integrar en store.json (auditando todos los paquetes otra vez)
./tools/submissions/bookos-review.py merge-catalog store.json \
  --submission solicitud.json \
  --pkg-dir ./build-out \
  --base-url "https://bookos.es/store-files/community/<pkg>" \
  --icon-url "https://bookos.es/store-files/community/<pkg>/icon.png" \
  --screenshots "https://bookos.es/store-files/community/<pkg>/shot1.webp" \
  --out store.json

# 5. Firmar offline y verificar antes de subir
./tools/submissions/bookos-review.py sign-catalog store.json \
  --key ~/.config/bookos-signing/catalog-priv.pem --stamp
./tools/submissions/bookos-review.py verify-catalog store.json \
  --sig store.json.sig \
  --pubkey src-tauri/keys/catalog-pub.pem
```

Después sube por SFTP los paquetes, imágenes sanitizadas, `store.json` y `store.json.sig`.

> **Nota si `/api/store.json` viene de `store.json.php`:** para que la firma Ed25519 siga siendo válida en cada petición, el endpoint sin `?app=` debe servir el archivo estático firmado sin regenerar `generated_at` al vuelo. Por ejemplo, al principio de `store.json.php`:
> ```php
> if (empty($_GET['app']) && is_file(__DIR__ . '/store.json') && is_file(__DIR__ . '/store.json.sig')) {
>     header('Content-Type: application/json; charset=UTF-8');
>     readfile(__DIR__ . '/store.json');
>     exit;
> }
> ```
