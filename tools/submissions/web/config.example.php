<?php
// Copia este archivo a config.php en el servidor (developer.bookos.es/submit/config.php)
// y asegúrate de que config.php NO tenga permisos de lectura pública.
return [
    // Buzón privado donde llegan las solicitudes en JSON para revisarlas offline.
    'recipient_email' => 'info@bookos.es',
    'from_email'      => 'info@bookos.es',

    // Cambia este secreto por una cadena aleatoria larga (p. ej. 64 hex) antes de desplegar.
    'hmac_secret'     => 'REEMPLAZAR_POR_SECRETO_ALEATORIO_64_HEX_GENERADO_EN_SERVIDOR',

    // Directorio temporal fuera del DocumentRoot para el rate limit por hash de IP.
    'rate_limit_dir'  => '/var/tmp/bookos-submit-rl',
    'max_per_hour'    => 3,
    'min_fill_seconds' => 4,
    'max_form_age_seconds' => 3600,
    'max_post_bytes'  => 32768,
];
