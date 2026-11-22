<?php
declare(strict_types=1);

function respond(int $code, string $title, string $message): never {
    http_response_code($code);
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!DOCTYPE html><html lang="es"><meta charset="UTF-8"><title>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</title>'
       . '<body style="font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px">'
       . '<h1>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h1>'
       . '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
       . '<p><a href="index.php">Volver al formulario</a></p></body></html>';
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(405, 'Método no permitido', 'Utiliza el formulario para enviar tu solicitud.');
}

if (!empty($_FILES)) {
    respond(400, 'Subida no permitida', 'Este formulario no acepta archivos adjuntos.');
}

$configPath = __DIR__ . '/config.php';
if (!file_exists($configPath)) {
    respond(500, 'Servicio no configurado', 'Falta config.php en el servidor.');
}
$config = require $configPath;

$maxBytes = (int) ($config['max_post_bytes'] ?? 32768);
$contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($contentLength <= 0 || $contentLength > $maxBytes) {
    respond(413, 'Solicitud fuera de tamaño', 'El envío excede el tamaño máximo permitido.');
}

// Honeypot anti-bots
if (trim((string) ($_POST['website_hp'] ?? '')) !== '') {
    respond(400, 'Solicitud rechazada', 'Validación anti-spam fallida.');
}

// Verificación de token HMAC sin estado y tiempo mínimo de rellenado
$tsRaw = (string) ($_POST['form_ts'] ?? '');
$token = (string) ($_POST['form_token'] ?? '');
if (!ctype_digit($tsRaw) || $token === '') {
    respond(400, 'Token inválido', 'Recarga el formulario e inténtalo de nuevo.');
}
$expected = hash_hmac('sha256', $tsRaw, (string) ($config['hmac_secret'] ?? ''));
if (!hash_equals($expected, $token)) {
    respond(403, 'Token inválido', 'La firma del formulario no es válida. Recarga la página.');
}
$age = time() - (int) $tsRaw;
$minFill = (int) ($config['min_fill_seconds'] ?? 4);
$maxAge = (int) ($config['max_form_age_seconds'] ?? 3600);
if ($age < $minFill || $age > $maxAge) {
    respond(429, 'Tiempo fuera de rango', 'Recarga el formulario, revísalo con calma y vuelve a enviarlo.');
}

// Rate limit por hash SHA-256 de IP (nunca almacena IPs en claro)
$rlDir = (string) ($config['rate_limit_dir'] ?? '/var/tmp/bookos-submit-rl');
if (!is_dir($rlDir)) {
    @mkdir($rlDir, 0700, true);
}
$ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$ipHash = hash('sha256', $ip . '|' . (string) ($config['hmac_secret'] ?? ''));
$rlFile = rtrim($rlDir, '/') . '/' . $ipHash . '.json';
$now = time();
$limit = (int) ($config['max_per_hour'] ?? 3);

$fh = @fopen($rlFile, 'c+');
if ($fh !== false) {
    flock($fh, LOCK_EX);
    $rawRl = stream_get_contents($fh);
    $stamps = json_decode($rawRl ?: '[]', true);
    if (!is_array($stamps)) {
        $stamps = [];
    }
    $stamps = array_values(array_filter($stamps, static fn($t) => is_int($t) && ($now - $t) < 3600));
    if (count($stamps) >= $limit) {
        flock($fh, LOCK_UN);
        fclose($fh);
        respond(429, 'Límite alcanzado', 'Has alcanzado el límite de envíos por hora. Inténtalo más tarde.');
    }
    $stamps[] = $now;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($stamps));
    flock($fh, LOCK_UN);
    fclose($fh);
}

function clean_text(string $key, int $min, int $max, bool $multiline = false): ?string {
    $val = trim((string) ($_POST[$key] ?? ''));
    $val = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $val) ?? '';
    if (!$multiline) {
        $val = str_replace(["\r", "\n"], ' ', $val);
    } else {
        $val = str_replace("\r\n", "\n", $val);
    }
    $len = mb_strlen($val, 'UTF-8');
    if ($len < $min || $len > $max) {
        return null;
    }
    return $val;
}

function valid_https(string $url, int $maxLen = 256): bool {
    if (!str_starts_with($url, 'https://') || strlen($url) > $maxLen) {
        return false;
    }
    if (preg_match('/[\s\x00-\x1F"\'<>`\\\\]/', $url)) {
        return false;
    }
    $parts = parse_url($url);
    if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user'])) {
        return false;
    }
    $host = $parts['host'];
    return str_contains($host, '.') && !str_starts_with($host, '.') && !str_ends_with($host, '.') && !str_contains($host, '..');
}

function valid_rel_or_https(string $val): bool {
    if (valid_https($val)) {
        return true;
    }
    if ($val === '' || strlen($val) > 256 || str_starts_with($val, '/') || str_contains($val, '\\')) {
        return false;
    }
    foreach (explode('/', $val) as $seg) {
        if ($seg === '' || $seg === '.' || $seg === '..') {
            return false;
        }
    }
    return true;
}

$reserved = [
    'apt','apt-get','archlinux-keyring','base','base-devel','bash','binutils','bwrap','bubblewrap',
    'ca-certificates','chromium','coreutils','curl','dash','dbus','dnf','docker','dpkg','efibootmgr',
    'filesystem','firefox','flatpak','gcc','glibc','gnupg','google-chrome','gpg','grub','gtk3',
    'kernel','libc6','linux','linux-firmware','linux-lts','mesa','networkmanager','openssh','openssl',
    'pacman','pam','pipewire','podman','polkit','pulseaudio','python','python3','rpm','rust','cargo',
    'sh','shadow','snapd','sudo','systemd','tar','thunderbird','udev','util-linux','wayland','wget',
    'xdg-desktop-portal','xorg-server','yum','zsh'
];
$categories = ['Productividad', 'Utilidades', 'Internet', 'Multimedia', 'Oficina', 'Gráficos', 'Desarrollo', 'Educación', 'Juegos', 'Ciencia', 'Sistema'];
$buildSystems = ['tauri', 'cargo', 'meson', 'cmake', 'make', 'python', 'node', 'custom'];
$allowedDataTypes = ['contact_info', 'location', 'identifiers', 'usage_data', 'diagnostics', 'user_content', 'financial', 'other'];

$errors = [];

$pkg = clean_text('pkg', 2, 63) ?? '';
if (!preg_match('/^[a-z0-9][a-z0-9+._-]{1,62}$/', $pkg)) {
    $errors[] = 'pkg inválido.';
} elseif (str_starts_with($pkg, 'bookos-') || in_array($pkg, $reserved, true)) {
    $errors[] = 'Nombre de paquete reservado.';
}

$version = clean_text('version', 1, 32) ?? '';
if (!preg_match('/^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z.]+)?$/', $version)) {
    $errors[] = 'Versión inválida.';
}

$label = clean_text('label', 2, 40);
$labelEn = clean_text('label_en', 0, 40);
$subtitle = clean_text('subtitle', 4, 60);
$description = clean_text('description', 15, 2000, true);
$descriptionEn = clean_text('description_en', 0, 2000, true);
$category = clean_text('category', 2, 32) ?? '';
$license = clean_text('license', 2, 64);
$author = clean_text('author', 2, 80);
$email = clean_text('contact_email', 5, 160) ?? '';
$notes = clean_text('notes', 3, 2000, true);

if ($label === null || $subtitle === null || $description === null || $license === null || $author === null || $notes === null) {
    $errors[] = 'Algún campo de texto obligatorio está vacío o fuera de longitud.';
}
if (!in_array($category, $categories, true)) {
    $errors[] = 'Categoría no válida.';
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email)) {
    $errors[] = 'Email de contacto inválido.';
}

$gitUrl = clean_text('git_url', 10, 256) ?? '';
$commit = clean_text('commit', 40, 40) ?? '';
$buildSystem = clean_text('build_system', 2, 16) ?? '';
if (!valid_https($gitUrl)) {
    $errors[] = 'git_url debe ser https://.';
}
if (!preg_match('/^[0-9a-f]{40}$/', $commit)) {
    $errors[] = 'commit debe ser un hash SHA-1 de 40 caracteres hexadecimales minúsculos.';
}
if (!in_array($buildSystem, $buildSystems, true)) {
    $errors[] = 'Sistema de compilación inválido.';
}

$iconPath = clean_text('icon_path', 1, 256) ?? '';
if (!valid_rel_or_https($iconPath)) {
    $errors[] = 'icon_path inválido.';
}
$shotsRaw = clean_text('screenshots', 1, 1500, true) ?? '';
$shots = array_values(array_filter(array_map('trim', explode("\n", $shotsRaw)), static fn($s) => $s !== ''));
if (count($shots) < 1 || count($shots) > 5) {
    $errors[] = 'Debes indicar entre 1 y 5 capturas.';
} else {
    foreach ($shots as $s) {
        if (!valid_rel_or_https($s)) {
            $errors[] = 'Captura con ruta o URL inválida.';
            break;
        }
    }
}

$homepage = clean_text('homepage', 10, 256) ?? '';
$support = clean_text('support', 10, 256) ?? '';
$privacyUrl = clean_text('privacy_url', 10, 256) ?? '';
if (!valid_https($homepage) || !valid_https($support) || !valid_https($privacyUrl)) {
    $errors[] = 'Las URLs de proyecto, soporte y privacidad deben empezar por https://.';
}

$collectsData = isset($_POST['collects_data']);
$tracking = isset($_POST['tracking']);
$network = isset($_POST['network']);
$postedTypes = is_array($_POST['data_types'] ?? null) ? $_POST['data_types'] : [];
$dataTypes = array_values(array_intersect($allowedDataTypes, array_map('strval', $postedTypes)));
if (!$collectsData && count($dataTypes) > 0) {
    $dataTypes = [];
}

$requiresAccount = isset($_POST['requires_account']);
$demoNotes = clean_text('demo_notes', 0, 1000, true) ?? '';
$permRationale = clean_text('permissions_rationale', 0, 1000, true) ?? '';

if (!empty($errors)) {
    respond(400, 'Revisa los datos del formulario', implode(' ', $errors));
}

$submission = [
    'schema_version' => 1,
    'pkg' => $pkg,
    'label' => $label,
    'subtitle' => $subtitle,
    'description' => $description,
    'category' => $category,
    'author' => $author,
    'contact_email' => $email,
    'license' => $license,
    'version' => $version,
    'notes' => $notes,
    'source' => [
        'git_url' => $gitUrl,
        'commit' => $commit,
        'build_system' => $buildSystem,
    ],
    'urls' => [
        'homepage' => $homepage,
        'support' => $support,
        'privacy' => $privacyUrl,
    ],
    'media' => [
        'icon_path' => $iconPath,
        'screenshots' => $shots,
    ],
    'privacy' => [
        'collects_data' => $collectsData,
        'tracking' => $tracking,
        'network' => $network,
        'data_types' => $dataTypes,
    ],
    'review' => [
        'requires_account' => $requiresAccount,
        'demo_notes' => $demoNotes,
        'permissions_rationale' => $permRationale,
    ],
];
if ($labelEn !== null && $labelEn !== '') {
    $submission['label_en'] = $labelEn;
}
if ($descriptionEn !== null && $descriptionEn !== '') {
    $submission['description_en'] = $descriptionEn;
}

$jsonBody = json_encode($submission, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if ($jsonBody === false) {
    respond(500, 'Error interno', 'No se pudo serializar la solicitud.');
}

$to = str_replace(["\r", "\n"], '', (string) ($config['recipient_email'] ?? 'info@bookos.es'));
$from = str_replace(["\r", "\n"], '', (string) ($config['from_email'] ?? 'info@bookos.es'));
$subject = "[BookOS Store] Nueva solicitud: {$pkg} ({$version})";
$encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
$mailHeaders = "From: {$from}\r\nContent-Type: text/plain; charset=UTF-8\r\n";

$sent = @mail($to, $encodedSubject, $jsonBody . "\n", $mailHeaders);
if (!$sent) {
    respond(500, 'No se pudo enviar', 'El servidor de correo no aceptó el mensaje. Contacta con el equipo de BookOS.');
}

respond(200, 'Solicitud recibida', "Tu app '{$pkg}' ({$version}) se ha enviado al equipo de revisión de BookOS Store.");
