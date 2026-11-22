<?php
declare(strict_types=1);

$configPath = __DIR__ . '/config.php';
$config = file_exists($configPath) ? require $configPath : require __DIR__ . '/config.example.php';

$ts = (string) time();
$token = hash_hmac('sha256', $ts, (string) ($config['hmac_secret'] ?? 'dev'));
$categories = ['Productividad', 'Utilidades', 'Internet', 'Multimedia', 'Oficina', 'Gráficos', 'Desarrollo', 'Educación', 'Juegos', 'Ciencia', 'Sistema'];
$buildSystems = ['tauri', 'cargo', 'meson', 'cmake', 'make', 'python', 'node', 'custom'];
$dataTypes = [
    'contact_info' => 'Información de contacto',
    'location'     => 'Ubicación',
    'identifiers'  => 'Identificadores de usuario/dispositivo',
    'usage_data'   => 'Datos de uso',
    'diagnostics'  => 'Diagnósticos / fallos',
    'user_content' => 'Contenido del usuario',
    'financial'    => 'Información financiera',
    'other'        => 'Otros datos',
];
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Publicar app — BookOS Store</title>
<style>
:root{--bg:#f2f2f7;--card:#fff;--sbg:rgba(0,0,0,.06);--tx:#000;--tx2:#6e6e73;--brd:rgba(0,0,0,.1);--blue:#007aff}
@media(prefers-color-scheme:dark){:root{--bg:#000;--card:#1c1c1e;--sbg:rgba(255,255,255,.09);--tx:#fff;--tx2:#98989d;--brd:rgba(255,255,255,.12);--blue:#0a84ff}}
*{box-sizing:border-box}
body{margin:0;padding:32px 16px;background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.5}
main{max-width:740px;margin:0 auto}
h1{font-size:28px;margin:0 0 8px}
p.lead{color:var(--tx2);margin:0 0 24px}
section{background:var(--card);border:1px solid var(--brd);border-radius:20px;padding:20px;margin-bottom:16px}
h2{font-size:16px;margin:0 0 14px}
label{display:block;font-size:13px;font-weight:600;margin:12px 0 6px}
input[type=text],input[type=email],input[type=url],textarea,select{width:100%;padding:10px 12px;border-radius:12px;border:1px solid var(--brd);background:var(--sbg);color:var(--tx);font:inherit;font-size:14px}
textarea{min-height:88px;resize:vertical}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
.checks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
.chk{display:flex;align-items:center;gap:8px;font-weight:400;margin:4px 0}
.hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
button{background:var(--blue);color:#fff;border:0;border-radius:14px;padding:12px 24px;font-size:15px;font-weight:600;cursor:pointer}
small{color:var(--tx2);font-size:12px}
</style>
</head>
<body>
<main>
  <h1>Publicar app en BookOS Store</h1>
  <p class="lead">Envío de código abierto sin subida de binarios: BookOS compila desde tu commit exacto, audita los paquetes y firma el catálogo offline.</p>

  <form method="post" action="submit.php">
    <input type="hidden" name="form_ts" value="<?= htmlspecialchars($ts, ENT_QUOTES, 'UTF-8') ?>">
    <input type="hidden" name="form_token" value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">
    <div class="hp" aria-hidden="true">
      <label for="website_hp">Dejar vacío</label>
      <input type="text" id="website_hp" name="website_hp" tabindex="-1" autocomplete="off">
    </div>

    <section>
      <h2>1. Identidad de la aplicación</h2>
      <div class="grid">
        <div>
          <label for="pkg">ID de paquete (pkg)*</label>
          <input type="text" id="pkg" name="pkg" required pattern="[a-z0-9][a-z0-9+._-]{1,62}" placeholder="cuaderno-ligero">
          <small>Minúsculas, sin prefijo bookos-.</small>
        </div>
        <div>
          <label for="version">Versión*</label>
          <input type="text" id="version" name="version" required placeholder="1.0.0">
        </div>
      </div>
      <div class="grid">
        <div>
          <label for="label">Nombre visible (ES)*</label>
          <input type="text" id="label" name="label" required maxlength="40">
        </div>
        <div>
          <label for="label_en">Nombre visible (EN)</label>
          <input type="text" id="label_en" name="label_en" maxlength="40">
        </div>
      </div>
      <label for="subtitle">Subtítulo breve*</label>
      <input type="text" id="subtitle" name="subtitle" required minlength="4" maxlength="60">
      <label for="description">Descripción (ES)*</label>
      <textarea id="description" name="description" required minlength="15" maxlength="2000"></textarea>
      <label for="description_en">Descripción (EN)</label>
      <textarea id="description_en" name="description_en" maxlength="2000"></textarea>
      <div class="grid">
        <div>
          <label for="category">Categoría*</label>
          <select id="category" name="category" required>
            <?php foreach ($categories as $c): ?>
              <option value="<?= htmlspecialchars($c, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($c, ENT_QUOTES, 'UTF-8') ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <label for="license">Licencia (SPDX)*</label>
          <input type="text" id="license" name="license" required maxlength="64" placeholder="MIT / GPL-3.0-or-later">
        </div>
      </div>
      <div class="grid">
        <div>
          <label for="author">Autor o mantenedor*</label>
          <input type="text" id="author" name="author" required minlength="2" maxlength="80">
        </div>
        <div>
          <label for="contact_email">Email de contacto (privado para revisión)*</label>
          <input type="email" id="contact_email" name="contact_email" required maxlength="160">
        </div>
      </div>
      <label for="notes">Notas de la versión (ES)*</label>
      <textarea id="notes" name="notes" required minlength="3" maxlength="2000"></textarea>
    </section>

    <section>
      <h2>2. Código fuente reproducible y medios</h2>
      <label for="git_url">Repositorio Git (HTTPS)*</label>
      <input type="url" id="git_url" name="git_url" required placeholder="https://codeberg.org/usuario/mi-app.git">
      <div class="grid">
        <div>
          <label for="commit">Hash de commit SHA-1 (40 hex)*</label>
          <input type="text" id="commit" name="commit" required pattern="[0-9a-f]{40}" placeholder="0123456789abcdef0123456789abcdef01234567">
        </div>
        <div>
          <label for="build_system">Sistema de compilación*</label>
          <select id="build_system" name="build_system" required>
            <?php foreach ($buildSystems as $bs): ?>
              <option value="<?= htmlspecialchars($bs, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($bs, ENT_QUOTES, 'UTF-8') ?></option>
            <?php endforeach; ?>
          </select>
        </div>
      </div>
      <div class="grid">
        <div>
          <label for="icon_path">Ruta relativa del icono en el repo*</label>
          <input type="text" id="icon_path" name="icon_path" required placeholder="assets/icon.png">
        </div>
        <div>
          <label for="screenshots">Capturas (1–5 rutas relativas o URLs HTTPS, una por línea)*</label>
          <textarea id="screenshots" name="screenshots" required placeholder="assets/screenshot-1.png"></textarea>
        </div>
      </div>
    </section>

    <section>
      <h2>3. Enlaces y etiquetas de privacidad (estilo App Store)</h2>
      <div class="grid">
        <div>
          <label for="homepage">Web del proyecto (HTTPS)*</label>
          <input type="url" id="homepage" name="homepage" required>
        </div>
        <div>
          <label for="support">URL de soporte (HTTPS)*</label>
          <input type="url" id="support" name="support" required>
        </div>
      </div>
      <label for="privacy_url">URL de política de privacidad (HTTPS)*</label>
      <input type="url" id="privacy_url" name="privacy_url" required>

      <label class="chk"><input type="checkbox" name="collects_data" value="1"> La app recopila o envía datos del usuario</label>
      <label class="chk"><input type="checkbox" name="tracking" value="1"> Usa datos para rastrear entre apps o webs</label>
      <label class="chk"><input type="checkbox" name="network" value="1"> Requiere o usa conexión a internet</label>

      <label>Tipos de datos recogidos (solo si aplica)</label>
      <div class="checks">
        <?php foreach ($dataTypes as $k => $lbl): ?>
          <label class="chk"><input type="checkbox" name="data_types[]" value="<?= htmlspecialchars($k, ENT_QUOTES, 'UTF-8') ?>"> <?= htmlspecialchars($lbl, ENT_QUOTES, 'UTF-8') ?></label>
        <?php endforeach; ?>
      </div>
    </section>

    <section>
      <h2>4. Notas para el revisor</h2>
      <label class="chk"><input type="checkbox" name="requires_account" value="1"> Requiere cuenta de usuario para probarla</label>
      <label for="demo_notes">Instrucciones o cuenta demo de prueba</label>
      <textarea id="demo_notes" name="demo_notes" maxlength="1000"></textarea>
      <label for="permissions_rationale">Justificación de permisos o accesos necesarios</label>
      <textarea id="permissions_rationale" name="permissions_rationale" maxlength="1000"></textarea>
    </section>

    <button type="submit">Enviar solicitud de revisión</button>
  </form>
</main>
</body>
</html>
