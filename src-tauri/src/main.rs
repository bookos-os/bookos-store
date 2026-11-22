#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Command, Stdio};
use std::io::Write;
use std::sync::Mutex;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use base64::{Engine as _, engine::general_purpose};

#[derive(Clone, Default)]
struct OpState {
    pid: Option<u32>,
    pct: f64,
    downloaded: u64,
    total: u64,
}

/// Active operations: op_id → {pid, progress}. Read by `progress` cmd, set by
/// downloader thread, written by track/untrack.
static OPS: Lazy<Mutex<HashMap<String, OpState>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn track(op_id: &str, pid: u32) {
    if let Ok(mut g) = OPS.lock() {
        g.entry(op_id.to_string()).or_default().pid = Some(pid);
    }
}
fn untrack(op_id: &str) {
    if let Ok(mut g) = OPS.lock() { g.remove(op_id); }
}
fn set_progress(op_id: &str, pct: f64, downloaded: u64, total: u64) {
    if let Ok(mut g) = OPS.lock() {
        let e = g.entry(op_id.to_string()).or_default();
        e.pct = pct; e.downloaded = downloaded; e.total = total;
    }
}

#[tauri::command]
fn progress(op_id: String) -> serde_json::Value {
    if let Ok(g) = OPS.lock() {
        if let Some(s) = g.get(&op_id) {
            return serde_json::json!({
                "pct": s.pct, "downloaded": s.downloaded, "total": s.total, "active": true
            });
        }
    }
    serde_json::json!({ "pct": 100.0, "active": false })
}

/// Clave pública Ed25519 embebida para verificar la firma de `store.json`.
const EMBEDDED_CATALOG_PUBKEY: &str = include_str!("../keys/catalog-pub.pem");

fn non_comment_pem(raw: &str) -> Option<String> {
    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if lines.is_empty() {
        None
    } else {
        Some(format!("{}\n", lines.join("\n")))
    }
}

fn active_catalog_pubkey_with(env_path: Option<&str>, embedded: &str) -> Result<Option<String>, String> {
    if let Some(p) = env_path.map(str::trim).filter(|s| !s.is_empty()) {
        let raw = std::fs::read_to_string(p)
            .map_err(|e| format!("No se pudo leer BOOKOS_CATALOG_PUBKEY ({}): {}", p, e))?;
        return non_comment_pem(&raw)
            .map(Some)
            .ok_or_else(|| format!("BOOKOS_CATALOG_PUBKEY ({}) está vacío o no contiene clave PEM.", p));
    }
    Ok(non_comment_pem(embedded))
}

fn active_catalog_pubkey() -> Result<Option<String>, String> {
    let env_path = std::env::var("BOOKOS_CATALOG_PUBKEY").ok();
    active_catalog_pubkey_with(env_path.as_deref(), EMBEDDED_CATALOG_PUBKEY)
}

fn parse_origin(url: &str) -> Option<(String, String)> {
    if url.is_empty() || url.len() > 2048 {
        return None;
    }
    if url.chars().any(|c| c.is_ascii_control() || c.is_whitespace()) {
        return None;
    }
    let (scheme_raw, rest) = url.split_once("://")?;
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let tail = &rest[auth_end..];
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return None;
    }
    let path_only = tail.split(['?', '#']).next().unwrap_or("");
    if tail.contains('\\')
        || path_only.split('/').any(|seg| seg == "..")
        || path_only.to_ascii_lowercase().contains("%2e%2e")
    {
        return None;
    }
    Some((scheme, authority.to_ascii_lowercase()))
}

fn is_local_http_origin(scheme: &str, authority: &str) -> bool {
    if scheme != "http" {
        return false;
    }
    let (host, port_ok) = match authority.split_once(':') {
        Some((h, p)) => (h, !p.is_empty() && p.parse::<u16>().is_ok()),
        None => (authority, true),
    };
    port_ok && matches!(host, "localhost" | "127.0.0.1")
}

fn trusted_store_file_url_with(
    url: &str,
    catalog_override: Option<&str>,
    allow_local_http: bool,
) -> Result<(), String> {
    let Some((scheme, authority)) = parse_origin(url) else {
        return Err(format!("URL no válida o insegura: {}", url));
    };
    if scheme == "https" && authority == "bookos.es" {
        return Ok(());
    }
    if let Some(cat_url) = catalog_override.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((cat_scheme, cat_auth)) = parse_origin(cat_url) {
            if scheme == cat_scheme
                && authority == cat_auth
                && (cat_scheme == "https"
                    || (allow_local_http && is_local_http_origin(&cat_scheme, &cat_auth)))
            {
                return Ok(());
            }
        }
    }
    Err(format!("Origen no permitido para descarga de BookOS Store: {}", url))
}

fn trusted_store_file_url(url: &str) -> Result<(), String> {
    let override_url = std::env::var("BOOKOS_CATALOG_URL").ok();
    let allow_local = std::env::var("BOOKOS_ALLOW_LOCAL_HTTP").ok().as_deref() == Some("1");
    trusted_store_file_url_with(url, override_url.as_deref(), allow_local)
}

fn trusted_catalog_url(url: &str) -> Result<(), String> {
    trusted_store_file_url(url)
}

fn is_local_http_allowed(url: &str) -> bool {
    let allow_local = std::env::var("BOOKOS_ALLOW_LOCAL_HTTP").ok().as_deref() == Some("1");
    if !allow_local {
        return false;
    }
    parse_origin(url)
        .map(|(s, a)| is_local_http_origin(&s, &a))
        .unwrap_or(false)
}

fn valid_external_https_url(url: &str) -> bool {
    if !url.starts_with("https://") || url.len() > 512 {
        return false;
    }
    if url.chars().any(|c| c.is_ascii_control() || c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`' | '\\')) {
        return false;
    }
    let rest = &url["https://".len()..];
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    if auth.is_empty() || auth.contains('@') {
        return false;
    }
    let (host, port_ok) = match auth.split_once(':') {
        Some((h, p)) => (h, !p.is_empty() && p.parse::<u16>().is_ok()),
        None => (auth, true),
    };
    port_ok
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
}

static SIG_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct TempDirGuard(std::path::PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn decode_sig_bytes(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() == 64 {
        return Ok(raw.to_vec());
    }
    let s = std::str::from_utf8(raw)
        .map_err(|_| "Firma del catálogo con formato inválido.".to_string())?;
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let decoded = general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| "Firma del catálogo no es base64 válido.".to_string())?;
    if decoded.len() != 64 {
        return Err("La firma Ed25519 del catálogo tiene longitud inválida.".into());
    }
    Ok(decoded)
}

fn verify_ed25519_signature(payload: &[u8], sig_raw: &[u8], pubkey_pem: &str) -> Result<(), String> {
    let sig_bytes = decode_sig_bytes(sig_raw)?;
    let seq = SIG_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("bookos-sig-{}-{}-{}", std::process::id(), nanos, seq));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir)
        .map_err(|e| format!("No se pudo crear directorio temporal para verificar firma: {}", e))?;
    let _guard = TempDirGuard(dir.clone());

    let pub_path = dir.join("pub.pem");
    let payload_path = dir.join("payload.bin");
    let sig_path = dir.join("sig.bin");
    std::fs::write(&pub_path, pubkey_pem.as_bytes())
        .map_err(|e| format!("Error escribiendo clave pública temporal: {}", e))?;
    std::fs::write(&payload_path, payload)
        .map_err(|e| format!("Error escribiendo catálogo temporal: {}", e))?;
    std::fs::write(&sig_path, &sig_bytes)
        .map_err(|e| format!("Error escribiendo firma temporal: {}", e))?;

    let out = Command::new("openssl")
        .arg("pkeyutl")
        .arg("-verify")
        .arg("-pubin")
        .arg("-inkey").arg(&pub_path)
        .arg("-rawin")
        .arg("-in").arg(&payload_path)
        .arg("-sigfile").arg(&sig_path)
        .output()
        .map_err(|e| format!("No se pudo ejecutar openssl para verificar la firma: {}", e))?;
    if !out.status.success() {
        return Err("La firma criptográfica del catálogo no es válida.".into());
    }
    Ok(())
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn parse_iso8601_utc_epoch(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.len() < 19 {
        return None;
    }
    let b = s.as_bytes();
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-')
        || !matches!(b.get(10), Some(b'T') | Some(b't') | Some(b' '))
        || b.get(13) != Some(&b':') || b.get(16) != Some(&b':')
    {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let m: i64 = s[5..7].parse().ok()?;
    let d: i64 = s[8..10].parse().ok()?;
    let hh: i64 = s[11..13].parse().ok()?;
    let mm: i64 = s[14..16].parse().ok()?;
    let ss: i64 = s[17..19].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d)
        || !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=59).contains(&ss)
    {
        return None;
    }

    let mut rest = &s[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits = after_dot.bytes().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        rest = &after_dot[digits..];
    }

    let offset_secs: i64 = if rest.is_empty() || rest.eq_ignore_ascii_case("z") {
        0
    } else if let Some(sign) = rest.chars().next().filter(|c| *c == '+' || *c == '-') {
        let tz = &rest[1..];
        let (oh, om) = if let Some((h, m_part)) = tz.split_once(':') {
            (h.parse::<i64>().ok()?, m_part.parse::<i64>().ok()?)
        } else if tz.len() == 4 {
            (tz[0..2].parse::<i64>().ok()?, tz[2..4].parse::<i64>().ok()?)
        } else if tz.len() == 2 {
            (tz.parse::<i64>().ok()?, 0)
        } else {
            return None;
        };
        if !(0..=23).contains(&oh) || !(0..=59).contains(&om) {
            return None;
        }
        let mag = oh * 3600 + om * 60;
        if sign == '+' { mag } else { -mag }
    } else {
        return None;
    };

    let local_epoch = days_from_civil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss;
    u64::try_from(local_epoch - offset_secs).ok()
}

fn generated_at_epoch(v: &serde_json::Value) -> Option<u64> {
    let g = v.get("generated_at")?;
    if let Some(n) = g.as_u64() {
        return Some(n);
    }
    if let Some(s) = g.as_str() {
        let t = s.trim();
        if let Ok(n) = t.parse::<u64>() {
            return Some(n);
        }
        return parse_iso8601_utc_epoch(t);
    }
    None
}

fn check_anti_rollback(incoming: &serde_json::Value, cached: Option<&serde_json::Value>) -> Result<(), String> {
    let Some(old) = cached else { return Ok(()); };
    if let (Some(inc_ts), Some(old_ts)) = (generated_at_epoch(incoming), generated_at_epoch(old)) {
        if inc_ts < old_ts {
            return Err(format!(
                "Catálogo rechazado por protección anti-rollback (recibido {}, local {}).",
                inc_ts, old_ts
            ));
        }
    }
    Ok(())
}

fn sig_url_for(candidate: &str) -> String {
    if let Some(base) = candidate.strip_suffix(".json.php") {
        format!("{}.json.sig", base)
    } else {
        format!("{}.sig", candidate)
    }
}

fn read_verified_cache(
    cache_path: &std::path::Path,
    sig_cache_path: &std::path::Path,
    pubkey: Option<&str>,
) -> Option<serde_json::Value> {
    let payload = std::fs::read(cache_path).ok()?;
    if let Some(pk) = pubkey {
        let sig_bytes = std::fs::read(sig_cache_path).ok()?;
        if verify_ed25519_signature(&payload, &sig_bytes, pk).is_err() {
            return None;
        }
    }
    serde_json::from_slice::<serde_json::Value>(&payload).ok()
}

/// Remote catalog endpoint. Single source of truth for available apps + their
/// latest versions + asset URLs. Served by the BookOS website (PHP backend),
/// not GitHub, so publishing a new app does not need a client recompile.
/// Override at runtime with env BOOKOS_CATALOG_URL.
fn catalog_url() -> String {
    std::env::var("BOOKOS_CATALOG_URL")
        .unwrap_or_else(|_| "https://bookos.es/api/store.json".to_string())
}

/// Fetch catalog from server with on-disk cache (TTL 10 min). On network
/// failure returns stale cache verified cryptographically if available.
/// Sin caché válida y sin red es un error, no una lista vacía: la interfaz
/// tiene que poder distinguir «no hay apps publicadas» de «no se pudo preguntar».
fn fetch_catalog_cached() -> Result<Vec<serde_json::Value>, String> {
    let apps_de = |v: &serde_json::Value| v.get("apps").and_then(|a| a.as_array()).cloned().unwrap_or_default();
    let pubkey = active_catalog_pubkey()?;
    if pubkey.is_none() {
        eprintln!("[bookos-store] aviso: sin clave pública embebida en catalog-pub.pem (modo transición)");
    }

    let mut cache_dir = dirs::cache_dir().ok_or("sin directorio de caché")?;
    cache_dir.push("bookos-store");
    let _ = std::fs::create_dir_all(&cache_dir);
    let cache_path = cache_dir.join("catalog.json");
    let sig_cache_path = cache_dir.join("catalog.json.sig");

    let fresh = std::fs::metadata(&cache_path).ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs() < 600)
        .unwrap_or(false);

    let cached_verified = read_verified_cache(&cache_path, &sig_cache_path, pubkey.as_deref());
    if cache_path.exists() && cached_verified.is_none() {
        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_file(&sig_cache_path);
    }

    if fresh {
        if let Some(ref v) = cached_verified {
            return Ok(apps_de(v));
        }
    }

    let url = catalog_url();
    // Try primary URL; if it fails (e.g. server rewrite not configured), retry
    // with `.php` suffix directly — keeps client working even with a misconfigured Apache.
    let fallback_url = if url.ends_with(".json") {
        Some(format!("{}.php", url))
    } else { None };

    // Nunca se degrada TLS por cuenta propia: el catálogo decide qué URL y qué
    // sha256 llegan al instalador privilegiado, así que un reintento con `-k`
    // ante un certificado inválido entregaba ambos a quien estuviera en medio.
    // `-k` solo con opt-in explícito (BOOKOS_INSECURE_TLS=1), como download_pkg.
    let insecure = std::env::var("BOOKOS_INSECURE_TLS").ok().as_deref() == Some("1");
    let mut motivo = String::from("curl no está disponible");
    for candidate in std::iter::once(url.as_str()).chain(fallback_url.as_deref()) {
        if let Err(e) = trusted_catalog_url(candidate) {
            motivo = e;
            continue;
        }
        let local_http = is_local_http_allowed(candidate);
        let mut cmd = Command::new("curl");
        cmd.args(["-fsSL", "--max-time", "15", "--max-redirs", "3",
                  "-H", "Accept: application/json",
                  "-H", "User-Agent: bookos-store"]);
        if !local_http {
            cmd.args(["--proto", "=https", "--proto-redir", "=https"]);
        }
        if insecure { cmd.arg("-k"); }
        cmd.arg(candidate);
        let out = cmd.output();
        if let Ok(o) = out {
            if o.status.success() {
                let mut sig_to_cache: Option<Vec<u8>> = None;
                if let Some(ref pk) = pubkey {
                    let sig_url = sig_url_for(candidate);
                    let mut sig_cmd = Command::new("curl");
                    sig_cmd.args(["-fsSL", "--max-time", "15", "--max-redirs", "3",
                                  "-H", "User-Agent: bookos-store"]);
                    if !local_http {
                        sig_cmd.args(["--proto", "=https", "--proto-redir", "=https"]);
                    }
                    if insecure { sig_cmd.arg("-k"); }
                    sig_cmd.arg(&sig_url);
                    match sig_cmd.output() {
                        Ok(so) if so.status.success() => {
                            if let Err(e) = verify_ed25519_signature(&o.stdout, &so.stdout, pk) {
                                motivo = e;
                                eprintln!("[bookos-store] firma inválida desde {}: {}", sig_url, motivo);
                                continue;
                            }
                            sig_to_cache = Some(so.stdout);
                        }
                        Ok(so) => {
                            motivo = format!("no se pudo descargar la firma del catálogo ({})", sig_url);
                            eprintln!("[bookos-store] curl {} exit={:?}", sig_url, so.status.code());
                            continue;
                        }
                        Err(e) => {
                            motivo = format!("error al descargar firma del catálogo: {}", e);
                            continue;
                        }
                    }
                }

                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&o.stdout) {
                    if let Err(e) = check_anti_rollback(&v, cached_verified.as_ref()) {
                        motivo = e;
                        eprintln!("[bookos-store] {}", motivo);
                        continue;
                    }
                    let _ = std::fs::write(&cache_path, &o.stdout);
                    if let Some(sb) = sig_to_cache {
                        let _ = std::fs::write(&sig_cache_path, sb);
                    }
                    eprintln!("[bookos-store] catalog ok from {} (signed={}, insecure={})",
                        candidate, pubkey.is_some(), insecure);
                    return Ok(apps_de(&v));
                }
                motivo = format!("respuesta no válida de {}", candidate);
            } else {
                motivo = String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("").to_string();
                eprintln!("[bookos-store] curl {} exit={:?} stderr={}",
                    candidate, o.status.code(), motivo);
            }
        }
    }

    // Stale fallback (ya verificado si había clave pública).
    if let Some(v) = cached_verified {
        return Ok(apps_de(&v));
    }
    Err(motivo)
}

/// Package manager backend detected at runtime.
#[derive(Clone, Copy, PartialEq)]
enum Pm { Pacman, Dnf, Apt }

fn detect_pm() -> Pm {
    // Manual override via env (debug / testing).
    if let Ok(v) = std::env::var("BOOKOS_PM") {
        match v.to_lowercase().as_str() {
            "pacman" => return Pm::Pacman,
            "dnf"    => return Pm::Dnf,
            "apt"    => return Pm::Apt,
            _ => {}
        }
    }
    // Prefer /etc/os-release ID over scanning binaries: tools like dpkg/rpm can
    // be co-installed on Arch (e.g. for build-deps) and would mis-detect.
    if let Ok(s) = std::fs::read_to_string("/etc/os-release") {
        let id = s.lines().find_map(|l| l.strip_prefix("ID=")).unwrap_or("").trim_matches('"').to_lowercase();
        let id_like = s.lines().find_map(|l| l.strip_prefix("ID_LIKE=")).unwrap_or("").trim_matches('"').to_lowercase();
        let combined = format!("{} {}", id, id_like);
        if combined.split_whitespace().any(|w| matches!(w, "arch" | "cachyos" | "manjaro" | "endeavouros" | "garuda" | "artix")) {
            return Pm::Pacman;
        }
        if combined.split_whitespace().any(|w| matches!(w, "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "opensuse" | "suse")) {
            return Pm::Dnf;
        }
        if combined.split_whitespace().any(|w| matches!(w, "debian" | "ubuntu" | "linuxmint" | "pop" | "kali" | "raspbian")) {
            return Pm::Apt;
        }
    }
    // Fallback: scan binaries, but prefer pacman over dpkg.
    let exists = |p: &str| std::path::Path::new(p).exists();
    let has = |bin: &str| exists(&format!("/usr/bin/{}", bin)) || exists(&format!("/bin/{}", bin));
    if has("pacman") { Pm::Pacman }
    else if has("dnf") || has("rpm") { Pm::Dnf }
    else if has("dpkg") || has("apt") { Pm::Apt }
    else { Pm::Pacman }
}

/// Force-clear the local catalog cache so next list_apps does a fresh HTTP fetch.
/// Called by the Refresh button when admin publishes new versions.
#[tauri::command]
fn clear_catalog_cache() -> bool {
    if let Some(mut dir) = dirs::cache_dir() {
        dir.push("bookos-store");
        let _ = std::fs::remove_file(dir.join("catalog.json"));
        let _ = std::fs::remove_file(dir.join("catalog.json.sig"));
        return true;
    }
    false
}

#[tauri::command]
fn list_apps() -> Result<serde_json::Value, String> {
    let pm = detect_pm();
    let apps = fetch_catalog_cached()?;
    // Una sola consulta al gestor de paquetes para todo el catálogo. Antes se
    // lanzaba un proceso por app, en serie, y la rejilla no se pintaba hasta
    // que terminaban los ~30 fork+exec.
    let installed_map = installed_versions(pm);
    let registro = leer_registro();
    let rpm_tiempos = if pm == Pm::Dnf { rpm_install_times() } else { HashMap::new() };
    let sufijo = match pm { Pm::Pacman => ".pkg.tar.zst", Pm::Dnf => ".rpm", Pm::Apt => ".deb" };
    let asset_de = |a: &serde_json::Value| a["assets"].as_array()
        .and_then(|v| v.iter().find(|x| x["name"].as_str().is_some_and(|n| n.ends_with(sufijo))))
        .cloned();
    let anotado_de = |pkg: &str, instalada: Option<&str>| registro.get(pkg)
        .filter(|r| r["version"].as_str() == instalada).cloned();

    // Sin registro de la tienda (instalado por dnf a mano) no hay hash con el
    // que comparar; queda la fecha: si el archivo del servidor es posterior a
    // la instalación, es otra compilación aunque la versión sea la misma.
    // Un HEAD por app, en paralelo: en serie eran ~0,3 s por app.
    let modificados: HashMap<String, u64> = std::thread::scope(|sc| {
        let hilos: Vec<_> = apps.iter().filter_map(|a| {
            let pkg = a["pkg"].as_str()?;
            let inst = lookup_installed(&installed_map, pkg).filter(|v| v != MANUAL_VER)?;
            if anotado_de(pkg, Some(&inst)).is_some() || !rpm_tiempos.contains_key(pkg) { return None; }
            let url = asset_de(a)?["browser_download_url"].as_str()?.to_string();
            Some((pkg.to_string(), url))
        }).map(|(pkg, url)| sc.spawn(move || last_modified(&url).map(|t| (pkg, t)))).collect();
        hilos.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    });

    let enriched: Vec<serde_json::Value> = apps.into_iter().map(|mut a| {
        let pkg = a["pkg"].as_str().unwrap_or("").to_string();
        let installed = lookup_installed(&installed_map, &pkg);
        // Mismo número de versión pero otro paquete en el servidor. El registro
        // solo vale si su versión es la instalada ahora: si se actualizó por
        // fuera de la tienda, el hash anotado ya no describe nada.
        let publicado = asset_de(&a)
            .map(|x| (x["sha256"].as_str().map(str::to_lowercase), x["size"].as_u64()));
        let anotado = anotado_de(&pkg, installed.as_deref());
        // El tamaño se compara también porque un hash ausente o malformado en
        // el catálogo no debe dejar pasar un paquete de otro tamaño.
        let instalada_en = anotado.as_ref().and_then(|r| r["installed_at"].as_u64())
            .or_else(|| rpm_tiempos.get(&pkg).copied());
        a["changed"] = serde_json::json!(match (&anotado, publicado) {
            (Some(r), Some((hash, size))) =>
                hash.is_some_and(|h| r["sha256"].as_str() != Some(h.as_str()))
                    || size.is_some_and(|t| r["size"].as_u64() != Some(t)),
            _ => matches!((modificados.get(&pkg), instalada_en), (Some(m), Some(i)) if *m > i),
        });
        a["installed_at"] = serde_json::json!(instalada_en);
        a["installed"] = serde_json::json!(installed);
        a
    }).collect();
    Ok(serde_json::json!(enriched))
}

/// Volcado completo de paquetes instalados → `{nombre: versión}`, en **una**
/// invocación del gestor. Listar todo y filtrar en memoria sale más barato que
/// preguntar paquete a paquete, y evita las rarezas de código de salida que
/// tiene `pacman -Q` cuando alguno de los nombres no está instalado.
fn installed_versions(pm: Pm) -> HashMap<String, String> {
    let out = match pm {
        Pm::Pacman => Command::new("pacman").arg("-Q").output(),
        Pm::Dnf    => Command::new("rpm").args(["-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"]).output(),
        Pm::Apt    => Command::new("dpkg-query").args(["-W", "-f=${Package} ${Version}\n"]).output(),
    };
    let mut map = HashMap::new();
    if let Ok(o) = out {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let mut it = line.split_whitespace();
                if let (Some(name), Some(ver)) = (it.next(), it.next()) {
                    map.insert(name.to_string(), ver.to_string());
                }
            }
        }
    }
    map
}

/// Hora de instalación (epoch) que guarda rpm, en una sola invocación. Es el
/// respaldo para lo instalado fuera de la tienda; dpkg no guarda esa fecha.
fn rpm_install_times() -> HashMap<String, u64> {
    let out = Command::new("rpm").args(["-qa", "--qf", "%{NAME} %{INSTALLTIME}\n"]).output();
    out.ok().filter(|o| o.status.success()).map(|o| {
        String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| {
            let (n, t) = l.split_once(' ')?;
            Some((n.to_string(), t.trim().parse().ok()?))
        }).collect()
    }).unwrap_or_default()
}

/// Versión instalada de `pkg` según el volcado, con el mismo respaldo que antes:
/// si el gestor no lo conoce pero el binario está en disco, se marca `manual`.
fn lookup_installed(map: &HashMap<String, String>, pkg: &str) -> Option<String> {
    if let Some(v) = map.get(pkg) { return Some(v.clone()); }
    let bin_exists = ["/usr/bin", "/usr/local/bin", "/bin"]
        .iter()
        .any(|d| std::path::Path::new(&format!("{}/{}", d, pkg)).exists());
    if bin_exists { Some(MANUAL_VER.to_string()) } else { None }
}

/// Sentinel returned when the app binary exists on disk but the package manager
/// has no record of it (installed via AppImage, manual copy, or a different
/// package name). Treated as "installed, unknown version" by the frontend so it
/// always offers a clean reinstall to register it properly.
const MANUAL_VER: &str = "manual";

fn pkg_version(pm: Pm, pkg: &str) -> Option<String> {
    let from_pm = match pm {
        Pm::Pacman => {
            Command::new("pacman").args(["-Q", pkg]).output().ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    s.split_whitespace().nth(1).map(|v| v.to_string())
                })
        }
        Pm::Dnf => {
            // Exit code is the source of truth: 0 = installed, nonzero = not.
            // A real version starts with a digit — guards against localized
            // error text ("no está instalado") leaking into stdout.
            Command::new("rpm")
                .args(["-q", "--qf", "%{VERSION}-%{RELEASE}", pkg])
                .output().ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if s.is_empty() || !s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        None
                    } else { Some(s) }
                })
        }
        Pm::Apt => {
            Command::new("dpkg-query").args(["-W", "-f=${Version}", pkg]).output().ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if s.is_empty() { None } else { Some(s) }
                })
        }
    };
    if from_pm.is_some() { return from_pm; }

    // Fallback: binary present but not tracked by the package manager.
    let bin_exists = ["/usr/bin", "/usr/local/bin", "/bin"]
        .iter()
        .any(|d| std::path::Path::new(&format!("{}/{}", d, pkg)).exists());
    if bin_exists { Some(MANUAL_VER.to_string()) } else { None }
}

#[tauri::command]
fn is_installed(pkg: String) -> bool {
    pkg_version(detect_pm(), &pkg).is_some()
}

/// Expose detected package manager + supported asset extensions to frontend.
#[tauri::command]
fn pm_info() -> serde_json::Value {
    match detect_pm() {
        Pm::Pacman => serde_json::json!({ "pm": "pacman", "exts": [".pkg.tar.zst"] }),
        Pm::Dnf => serde_json::json!({ "pm": "dnf", "exts": [".rpm"] }),
        Pm::Apt => serde_json::json!({ "pm": "apt", "exts": [".deb"] }),
    }
}

/// Nombre de paquete plausible: alfanumérico + separadores habituales, sin
/// empezar por '-' (inyectaría flags en pacman/dnf/apt, que corren como root)
/// y sin '/' (launch_app no debe ejecutar rutas arbitrarias).
fn valid_pkg_name(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 128
        && !p.starts_with('-')
        && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '@' | ':'))
}

#[tauri::command]
fn launch_app(pkg: String) -> Result<(), String> {
    if !valid_pkg_name(&pkg) {
        return Err(format!("Nombre de paquete inválido: {}", pkg));
    }
    // Tauri-built apps install their binary at /usr/bin/<pkgname>
    Command::new(&pkg).spawn().map(|_| ())
        .map_err(|e| format!("No se pudo lanzar {}: {}", pkg, e))
}

/// Abre la página de apps de BookOS cuando no hay paquete para esta distro.
/// No se usa `html_url` del catálogo: apunta a `/store-files/<pkg>/`, un
/// directorio sin índice que Apache responde con 403 (comprobado con curl).
/// Tampoco existe una página por app (`/apps/<pkg>` da 404).
#[tauri::command]
fn open_release_page() -> Result<(), String> {
    Command::new("xdg-open").arg("https://bookos.es/apps").spawn().map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    if !valid_external_https_url(&url) {
        return Err(format!("URL externa no permitida: {}", url));
    }
    Command::new("xdg-open").arg(&url).spawn().map(|_| ())
        .map_err(|e| e.to_string())
}

/// Run privileged command. If `password` provided, uses `sudo -S` and feeds it
/// via stdin. If empty, falls back to pkexec. If `op_id` set, registers PID for
/// cancellation.
fn run_priv(args: &[&str], password: &str, op_id: Option<&str>) -> Result<String, String> {
    // Build a clean PATH so spawned sudo/pkexec can find dnf/pacman/apt even
    // when Tauri launches us with a stripped env (e.g. via .desktop entry).
    let safe_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    if password.is_empty() {
        let bin = if Command::new("which").arg("pkexec").output()
            .map(|o| o.status.success()).unwrap_or(false) { "pkexec" } else { "sudo" };
        eprintln!("[bookos-store] run_priv (no password) via {}: {:?}", bin, args);
        let child = Command::new(bin)
            .env("PATH", safe_path)
            .args(args)
            .stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().map_err(|e| format!("Fallo al lanzar {}: {}", bin, e))?;
        if let Some(id) = op_id { track(id, child.id()); }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if let Some(id) = op_id { untrack(id); }
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let combined = if stderr.trim().is_empty() { stdout } else { stderr };
            eprintln!("[bookos-store] run_priv (no-pw) failed exit={:?}: {}", out.status.code(), combined);
            return Err(if combined.trim().is_empty() { format!("fallo sin output (exit {:?})", out.status.code()) } else { combined.trim().to_string() });
        }
        return Ok(String::from_utf8_lossy(&out.stdout).to_string());
    }
    eprintln!("[bookos-store] run_priv (with sudo password): {:?}", args);
    let mut child = Command::new("sudo")
        .env("PATH", safe_path)
        .arg("-S").arg("-p").arg("")
        .args(args)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("Fallo al lanzar sudo: {}", e))?;
    if let Some(id) = op_id { track(id, child.id()); }
    if let Some(mut s) = child.stdin.take() {
        let _ = s.write_all(format!("{}\n", password).as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if let Some(id) = op_id { untrack(id); }
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        if stderr.contains("incorrect password") || stderr.contains("Sorry, try again") {
            return Err("Contraseña incorrecta".into());
        }
        if stderr.contains("Terminated") || stderr.contains("signal: 15") {
            return Err("__cancelled__".into());
        }
        // Return full stderr+stdout so frontend dialog shows useful debug.
        let combined = if stderr.trim().is_empty() { stdout.clone() } else { stderr.clone() };
        eprintln!("[bookos-store] run_priv failed: exit={:?}\nstderr:\n{}\nstdout:\n{}",
            out.status.code(), stderr, stdout);
        return Err(if combined.trim().is_empty() {
            "Falló sin output".into()
        } else {
            combined.trim().to_string()
        });
    }
    Ok(stdout)
}

/// Cancel an in-flight op by sending SIGTERM to its tracked PID.
#[tauri::command]
fn cancel_op(op_id: String) -> bool {
    let pid = match OPS.lock().ok().and_then(|g| g.get(&op_id).and_then(|s| s.pid)) {
        Some(p) => p, None => return false,
    };
    Command::new("kill").arg("-TERM").arg(pid.to_string()).status()
        .map(|s| s.success()).unwrap_or(false)
}

/// Install a local package file. Backend picks pacman -U or dnf install based
/// on detected distro. If `password` is provided, uses sudo -S (custom dialog);
/// otherwise pkexec (system dialog).
#[tauri::command]
async fn install_pkg_file(path: String, pkg: Option<String>, password: Option<String>, op_id: Option<String>) -> Result<String, String> {
    let canon = std::fs::canonicalize(&path)
        .map_err(|e| format!("Archivo no existe: {} ({})", path, e))?;
    let canon_str = canon.to_string_lossy().to_string();
    eprintln!("[bookos-store] install_pkg_file path={}", canon_str);
    let pm = detect_pm();
    eprintln!("[bookos-store] detected pm = {:?}", match pm { Pm::Pacman=>"pacman", Pm::Dnf=>"dnf", Pm::Apt=>"apt" });
    let args: Vec<&str> = match pm {
        Pm::Pacman => vec!["pacman", "-U", "--noconfirm", &canon_str],
        Pm::Dnf => vec!["dnf", "install", "-y", "--allowerasing", &canon_str],
        Pm::Apt => vec!["apt", "install", "-y", "--allow-downgrades", &canon_str],
    };
    eprintln!("[bookos-store] running: {:?}", args);
    // Hash de lo que se entrega al instalador, no de lo que diga el catálogo
    // después: es lo que de verdad acaba en el sistema.
    let hash = sha256_de(&canon)?;
    let salida = run_priv(&args, password.as_deref().unwrap_or(""), op_id.as_deref())?;
    if let Some(pkg) = pkg.filter(|p| valid_pkg_name(p)) {
        if let Some(version) = pkg_version(pm, &pkg) {
            let tam = std::fs::metadata(&canon).map(|m| m.len()).unwrap_or(0);
            anotar_instalado(&pkg, &version, &hash, tam);
        }
    }
    Ok(salida)
}

/// Registro de lo que esta tienda instaló: `{pkg: {version, sha256, size, installed_at}}`. Los
/// gestores no guardan el hash del paquete que instalaron, así que sin esto la
/// única forma de comparar con el servidor es la versión, y un paquete
/// reconstruido con la misma versión pasaba por actualizado.
fn registro_path() -> Option<std::path::PathBuf> {
    dirs::data_dir().map(|d| d.join("bookos-store").join("installed.json"))
}

fn leer_registro() -> serde_json::Map<String, serde_json::Value> {
    registro_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn anotar_instalado(pkg: &str, version: &str, sha256: &str, size: u64) {
    let Some(path) = registro_path() else { return };
    let mut reg = leer_registro();
    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    reg.insert(pkg.to_string(), serde_json::json!({
        "version": version, "sha256": sha256, "size": size, "installed_at": ahora,
    }));
    if let Some(dir) = path.parent() { let _ = std::fs::create_dir_all(dir); }
    if let Err(e) = std::fs::write(&path, serde_json::Value::Object(reg).to_string()) {
        eprintln!("[bookos-store] no se pudo escribir {}: {}", path.display(), e);
    }
}

/// Install a package by NAME from configured repos (no file download).
/// Use when the BookOS dnf repo is configured at /etc/yum.repos.d/bookos.repo.
/// Falls back gracefully on Apt/Pacman.
#[tauri::command]
async fn install_pkg_by_name(pkg: String, password: Option<String>, op_id: Option<String>) -> Result<String, String> {
    if !valid_pkg_name(&pkg) {
        return Err(format!("Nombre de paquete inválido: {}", pkg));
    }
    let args: Vec<&str> = match detect_pm() {
        Pm::Pacman => vec!["pacman", "-Sy", "--noconfirm", &pkg],
        Pm::Dnf => vec!["dnf", "install", "-y", "--refresh", &pkg],
        Pm::Apt => vec!["apt", "install", "-y", &pkg],
    };
    run_priv(&args, password.as_deref().unwrap_or(""), op_id.as_deref())
}

/// Upgrade all BookOS packages via system repos.
#[tauri::command]
async fn upgrade_all(password: Option<String>, op_id: Option<String>) -> Result<String, String> {
    let args: Vec<&str> = match detect_pm() {
        Pm::Pacman => vec!["pacman", "-Syu", "--noconfirm"],
        Pm::Dnf => vec!["dnf", "upgrade", "-y", "--refresh"],
        Pm::Apt => vec!["sh", "-c", "apt update && apt upgrade -y"],
    };
    run_priv(&args, password.as_deref().unwrap_or(""), op_id.as_deref())
}

/// Uninstall a package via pacman -Rs or dnf remove.
#[tauri::command]
async fn uninstall_pkg(pkg: String, password: Option<String>, op_id: Option<String>) -> Result<String, String> {
    if !valid_pkg_name(&pkg) {
        return Err(format!("Nombre de paquete inválido: {}", pkg));
    }
    let args: Vec<&str> = match detect_pm() {
        Pm::Pacman => vec!["pacman", "-Rs", "--noconfirm", &pkg],
        Pm::Dnf => vec!["dnf", "remove", "-y", &pkg],
        Pm::Apt => vec!["apt", "remove", "-y", &pkg],
    };
    run_priv(&args, password.as_deref().unwrap_or(""), op_id.as_deref())?;
    Ok(String::from("ok"))
}

/// Verify a sudo password without doing anything destructive.
#[tauri::command]
async fn verify_password(password: String) -> bool {
    if password.is_empty() { return false; }
    let mut child = match Command::new("sudo")
        .arg("-S").arg("-k").arg("-p").arg("").arg("true")
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn() { Ok(c) => c, Err(_) => return false };
    if let Some(mut s) = child.stdin.take() {
        let _ = s.write_all(format!("{}\n", password).as_bytes());
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Read app icon from hicolor theme and return as base64 PNG. Tries multiple
/// sizes and falls back to scalable SVG. Returns empty string if not found.
#[tauri::command]
fn get_icon(name: String) -> String {
    if !valid_pkg_name(&name) || name.contains("..") {
        return String::new();
    }
    let sizes = ["256x256", "512x512", "128x128", "96x96", "64x64", "48x48"];
    for sz in sizes {
        let p = format!("/usr/share/icons/hicolor/{}/apps/{}.png", sz, name);
        if let Ok(bytes) = std::fs::read(&p) {
            return format!("data:image/png;base64,{}", general_purpose::STANDARD.encode(&bytes));
        }
    }
    let svg = format!("/usr/share/icons/hicolor/scalable/apps/{}.svg", name);
    if let Ok(bytes) = std::fs::read(&svg) {
        return format!("data:image/svg+xml;base64,{}", general_purpose::STANDARD.encode(&bytes));
    }
    String::new()
}

fn sha256_de(path: &std::path::Path) -> Result<String, String> {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|e| format!("No se pudo calcular el hash del paquete: {}", e))?;
    if !out.status.success() {
        return Err("No se pudo calcular el hash del paquete.".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase())
}

/// Comprueba el sha256 del archivo descargado contra el que publica el catálogo.
/// Falla cerrado: si no coincide, el llamante borra el archivo y no se instala.
///
/// Esto detecta corrupción y manipulación en tránsito, pero no protege contra un
/// servidor comprometido (el hash viaja por el mismo canal que el paquete). La
/// defensa real es firmar el catálogo y/o los paquetes con clave criptográfica.
fn verify_sha256(path: &std::path::Path, expected: &str) -> Result<(), String> {
    let expected = expected.trim().to_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("El catálogo no trae un sha256 válido para este paquete.".into());
    }
    let got = sha256_de(path)?;
    if got != expected {
        return Err(format!(
            "El paquete descargado no coincide con el catálogo (sha256 esperado {}…, obtenido {}…). \
             Se ha descartado la descarga.",
            &expected[..12],
            if got.len() >= 12 { &got[..12] } else { "desconocido" }
        ));
    }
    Ok(())
}

/// Download asset to ~/.cache/bookos-store/. Writes progress to OPS map for
/// frontend to poll via `progress(op_id)`. Cancellable via cancel_op(op_id).
/// El paquete se verifica contra el origen permitido y el sha256 del catálogo
/// antes de devolverlo.
#[tauri::command]
async fn download_pkg(url: String, filename: String, sha256: Option<String>, op_id: Option<String>) -> Result<String, String> {
    trusted_store_file_url(&url)?;

    let mut dest = dirs::cache_dir().ok_or_else(|| "no cache dir".to_string())?;
    dest.push("bookos-store");
    std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;

    // `filename` viene del catálogo remoto (asset.name), no es de confianza.
    // Aceptar solo un basename limpio para que la escritura no pueda salir de
    // ~/.cache/bookos-store/ (evita path traversal / escritura arbitraria).
    let safe_name = std::path::Path::new(&filename)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| *n == filename && !n.is_empty() && *n != "." && *n != "..")
        .ok_or_else(|| format!("nombre de archivo inválido: {}", filename))?;
    dest.push(safe_name);

    let total = head_size(&url).unwrap_or(0);
    let dest_clone = dest.clone();
    let op = op_id.clone().unwrap_or_default();

    // No degradar TLS automáticamente: solo aceptar certificados inválidos con
    // opt-in explícito por variable de entorno (nunca de forma silenciosa/memoizada).
    let insecure = std::env::var("BOOKOS_INSECURE_TLS").ok().as_deref() == Some("1");
    let local_http = is_local_http_allowed(&url);
    let mut cmd = Command::new("curl");
    cmd.args(["-fSL", "--silent", "--max-redirs", "3", "-w", "%{url_effective}"]);
    if !local_http {
        cmd.args(["--proto", "=https", "--proto-redir", "=https"]);
    }
    if insecure { cmd.arg("-k"); eprintln!("[bookos-store] download_pkg using -k for {}", url); }
    cmd.arg("-o").arg(&dest).arg(&url);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn().map_err(|e| format!("curl falló: {}", e))?;

    let pid = child.id();
    if let Some(id) = op_id.as_deref() { track(id, pid); }

    let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    let op_for_thread = op.clone();
    let poller = std::thread::spawn(move || {
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let cur = std::fs::metadata(&dest_clone).map(|m| m.len()).unwrap_or(0);
            let pct = if total > 0 { ((cur as f64 / total as f64) * 100.0).min(99.0) } else { 0.0 };
            if !op_for_thread.is_empty() {
                set_progress(&op_for_thread, pct, cur, total);
            }
        }
    });

    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = poller.join();

    if !output.status.success() {
        if let Some(id) = op_id.as_deref() { untrack(id); }
        let _ = std::fs::remove_file(&dest);
        if output.status.code().is_none() { return Err("__cancelled__".into()); }
        return Err(format!("Descarga falló (exit {})", output.status.code().unwrap_or(-1)));
    }
    let effective_url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if effective_url.is_empty() || trusted_store_file_url(&effective_url).is_err() {
        let _ = std::fs::remove_file(&dest);
        if let Some(id) = op_id.as_deref() { untrack(id); }
        return Err(format!("Redirección bloqueada a origen no permitido: {}", effective_url));
    }

    // Integridad antes de entregar la ruta: si el paquete no es el que el
    // catálogo dice, se borra y no llega nunca al instalador privilegiado.
    // Sin sha256 no hay nada que comparar, y el paquete iría igual a root:
    // se rechaza en vez de instalarlo a ciegas.
    let verified = match sha256.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(exp) => verify_sha256(&dest, exp),
        None => Err(format!("El catálogo no trae sha256 para {}; no se instala sin verificar", safe_name)),
    };
    if let Err(e) = verified {
        let _ = std::fs::remove_file(&dest);
        if let Some(id) = op_id.as_deref() { untrack(id); }
        eprintln!("[bookos-store] verificación sha256 fallida para {}: {}", safe_name, e);
        return Err(e);
    }

    let final_size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    if !op.is_empty() { set_progress(&op, 100.0, final_size, if total>0 { total } else { final_size }); }
    if let Some(id) = op_id.as_deref() { untrack(id); }
    Ok(dest.to_string_lossy().to_string())
}

/// Fetch latest release info for a single app from the BookOS catalog.
/// Frontend keeps calling `fetch_release({ repo })` — for back-compat the
/// `repo` argument is now treated as the package id (or, if it contains "/",
/// the last segment is used). Returns a GitHub-release-compatible shape so
/// the existing UI code keeps working unchanged.
#[tauri::command]
async fn fetch_release(repo: String) -> Result<serde_json::Value, String> {
    let pkg = repo.rsplit('/').next().unwrap_or(&repo).to_string();

    // Pull from already-cached catalog first (cheap, no extra HTTP).
    let apps = fetch_catalog_cached()?;
    let app = apps.into_iter().find(|a| a["pkg"].as_str() == Some(&pkg));
    let app = match app {
        Some(a) => a,
        None => return Err(format!("App '{}' no está en el catálogo.", pkg)),
    };

    // Map catalog shape → GitHub-release shape that main.js already consumes.
    let tag = app.get("available").cloned().unwrap_or(serde_json::Value::Null);
    let assets = app.get("assets").cloned().unwrap_or(serde_json::Value::Array(vec![]));
    let html_url = app.get("html_url").cloned().unwrap_or(serde_json::Value::String(String::new()));
    Ok(serde_json::json!({
        "tag_name": tag,
        "assets":   assets,
        "html_url": html_url,
        "body":     app.get("notes").cloned().unwrap_or(serde_json::Value::String(String::new())),
    }))
}

/// `Last-Modified` del archivo remoto, en epoch. None si no lo manda o falla.
fn last_modified(url: &str) -> Option<u64> {
    if trusted_store_file_url(url).is_err() { return None; }
    let local_http = is_local_http_allowed(url);
    let mut cmd = Command::new("curl");
    cmd.args(["-sIL", "--max-time", "8", "--max-redirs", "3", "-o", "/dev/null", "-w", "%{header_json}"]);
    if !local_http {
        cmd.args(["--proto", "=https", "--proto-redir", "=https"]);
    }
    cmd.arg(url);
    let out = cmd.output().ok().filter(|o| o.status.success())?;
    let v = serde_json::from_slice::<serde_json::Value>(&out.stdout).ok()?;
    let fecha = v.get("last-modified")?.as_array()?.last()?.as_str()?.to_string();
    // `date` entiende el formato HTTP; evita escribir un parser de fechas.
    let d = Command::new("date").args(["-u", "-d", &fecha, "+%s"]).output().ok()?;
    String::from_utf8_lossy(&d.stdout).trim().parse().ok()
}

/// HEAD request via curl to discover Content-Length. Returns None on failure.
fn head_size(url: &str) -> Option<u64> {
    if trusted_store_file_url(url).is_err() { return None; }
    let insecure = std::env::var("BOOKOS_INSECURE_TLS").ok().as_deref() == Some("1");
    let local_http = is_local_http_allowed(url);
    let mut cmd = Command::new("curl");
    cmd.args(["-sIL", "--max-redirs", "3", "-o", "/dev/null", "-w", "%{size_download}\n%{header_json}"]);
    if !local_http {
        cmd.args(["--proto", "=https", "--proto-redir", "=https"]);
    }
    if insecure { cmd.arg("-k"); }
    cmd.arg(url);
    let out = cmd.output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().nth(1)?;
    let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
    v.get("content-length")
        .and_then(|h| h.as_array())
        .and_then(|a| a.last())
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<u64>().ok())
}


/// El tema del escritorio, preguntado al portal XDG.
///
/// Va **antes** que `kreadconfig6`: esa orden solo sabe de Plasma y lee el
/// `kdeglobals` del usuario, que en una sesión BookOS no lo escribe nadie —el
/// tema se elige en la tarjeta de Apariencia y vive en `panel.conf`—, así que
/// la app se quedaba con el tema con el que se instaló el sistema. El portal
/// lo sirve la sesión que esté corriendo: BookOS desde el propio compositor,
/// y Plasma y GNOME también, de modo que esto funciona en las tres.
///
/// `color-scheme`: 1 oscuro, 2 claro, 0 sin preferencia. `gdbus` viene con
/// GLib, que ya es dependencia de cualquier app Tauri: no añade nada.
fn portal_color_scheme() -> Option<String> {
    let salida = std::process::Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.portal.Desktop",
            "--object-path",
            "/org/freedesktop/portal/desktop",
            "--method",
            "org.freedesktop.portal.Settings.ReadOne",
            "org.freedesktop.appearance",
            "color-scheme",
        ])
        .output()
        .ok()?;
    // Contesta «(<uint32 1>,)»; el 0 es «sin preferencia» y no es respuesta.
    let texto = String::from_utf8_lossy(&salida.stdout);
    let n = texto.split("uint32").nth(1)?.trim_start().chars().next()?;
    match n {
        '1' => Some("dark".to_string()),
        '2' => Some("light".to_string()),
        _ => None,
    }
}

#[tauri::command]
fn detect_system_theme() -> String {
    if let Some(tema) = portal_color_scheme() {
        return tema;
    }
    let kde = [
        ("kreadconfig6", &["--group", "General", "--key", "ColorScheme"][..]),
        ("kreadconfig5", &["--group", "General", "--key", "ColorScheme"][..]),
    ];
    for (bin, args) in kde {
        if let Ok(out) = Command::new(bin).args(args).output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if s.contains("dark") { return "dark".into(); }
            if s.contains("light") { return "light".into(); }
        }
    }
    if let Ok(out) = Command::new("gsettings")
        .args(["get", "org.gnome.desktop.interface", "color-scheme"]).output()
    {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        if s.contains("dark") { return "dark".into(); }
        if s.contains("light") { return "light".into(); }
    }
    "auto".into()
}

/// Quita el zoom de página que WebKitGTK hace con el pellizco del touchpad.
///
/// No hay ajuste para eso ni en WebKit ni en Tauri, y la página no se entera:
/// el pellizco lo consume un `GtkGestureZoom` de la propia vista y llega como
/// `setMagnification`, no como `wheel` ni `touch*`, así que ningún
/// `preventDefault` lo frena. Se apaga ese gesto y ningún otro: con fase `None`
/// GTK deja de pasarle eventos (gtkeventcontroller.c, 3.24). Va en
/// `on_page_load` para cubrir también las ventanas que se abran después.
fn desactivar_zoom_por_pellizco<R: tauri::Runtime>(
    webview: &tauri::Webview<R>,
    _: &tauri::webview::PageLoadPayload<'_>,
) {
    #[cfg(target_os = "linux")]
    let _ = webview.with_webview(|webview| {
        use gtk::glib::translate::from_glib_none;
        use gtk::prelude::*;

        // WebKitGTK guarda ahí el gesto (WebKitWebViewBase.cpp, 2.52.5). No es
        // API pública: si la clave cambia, no se encuentra y el zoom vuelve.
        // Lo guardado es un puntero C a un GObject, no un tipo de Rust.
        let Some(gesto) = (unsafe { webview.inner().data::<gtk::ffi::GtkGesture>("wk-view-zoom-gesture") }) else {
            return;
        };
        let gesto: gtk::Gesture = unsafe { from_glib_none(gesto.as_ptr()) };
        gesto.set_propagation_phase(gtk::PropagationPhase::None);
    });
}

#[tauri::command]
fn bookos_language() -> String {
    let locale = std::env::var("LANG").unwrap_or_else(|_| "en".into());
    let Some(home) = std::env::var_os("HOME") else {
        return if locale.to_lowercase().starts_with("es") { "es" } else { "en" }.into();
    };
    let path = std::path::PathBuf::from(home).join(".config/bookos/settings.json");
    let language = std::fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
        .and_then(|settings| settings.get("AppLanguage").and_then(|value| value.as_str()).map(str::to_owned));
    match language.as_deref() {
        Some("es") => "es".into(),
        Some("en") => "en".into(),
        _ if locale.to_lowercase().starts_with("es") => "es".into(),
        _ => "en".into(),
    }
}

fn main() {
    // El JavaScript de la tienda pinta listas: con el intérprete sobra. Sin JIT,
    // 121 MB → 117 MB en reposo (PSS de los tres procesos, WebKitGTK 2.54.1).
    // `WEBKIT_DISABLE_DMABUF_RENDERER` no se pone: aquí sube a 126 MB, porque a
    // 960×680 y escala 2 los búferes compartidos pesan más que lo que ahorra.
    if std::env::var_os("JSC_useJIT").is_none() {
        std::env::set_var("JSC_useJIT", "0");
    }
    tauri::Builder::default()
        .on_page_load(desactivar_zoom_por_pellizco)
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            bookos_palette_css,
            list_apps,
            clear_catalog_cache,
            is_installed,
            pm_info,
            get_icon,
            verify_password,
            launch_app,
            open_release_page,
            open_external_url,
            install_pkg_file,
            install_pkg_by_name,
            upgrade_all,
            uninstall_pkg,
            download_pkg,
            cancel_op,
            progress,
            fetch_release,
            bookos_language,
            detect_system_theme,
        ])
        .setup(|app| {
            use tauri::{WebviewWindowBuilder, WebviewUrl};
            let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Bookos Store")
                .inner_size(1180.0, 760.0)
                .min_inner_size(900.0, 560.0)
                .decorations(false)
                .transparent(true)
                .resizable(true)
                .visible(false)
                .initialization_script(include_str!("../tauri-bridge.js"))
                .build()?;
            let _ = win.show();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running app");
}

// ── Color dinámico ───────────────────────────────────────────────────────
// La paleta la genera BookOS Settings desde el fondo de pantalla y la deja en
// ~/.config/bookos/palette.css. Aquí solo se lee: quien tiñe es la hoja, que
// el cliente bookos-palette.js inyecta al final de <head>.
#[tauri::command]
fn bookos_palette_css() -> String {
    std::env::var("HOME").ok()
        .map(|h| std::path::Path::new(&h).join(".config/bookos/palette.css"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_pkg_name() {
        assert!(valid_pkg_name("bookos-store"));
        assert!(valid_pkg_name("cuaderno-ligero_1.2+git"));
        assert!(!valid_pkg_name(""));
        assert!(!valid_pkg_name("-rf"));
        assert!(!valid_pkg_name("../etc/passwd"));
        assert!(!valid_pkg_name("foo/bar"));
        assert!(!valid_pkg_name(&"a".repeat(129)));
    }

    #[test]
    fn test_trusted_store_file_url() {
        assert!(trusted_store_file_url_with("https://bookos.es/store-files/a.deb", None, false).is_ok());
        assert!(trusted_store_file_url_with("http://bookos.es/store-files/a.deb", None, false).is_err());
        assert!(trusted_store_file_url_with("https://evil.com/a.deb", None, false).is_err());
        assert!(trusted_store_file_url_with("https://bookos.es@evil.com/a.deb", None, false).is_err());
        assert!(trusted_store_file_url_with("https://bookos.es/store-files/../etc/passwd", None, false).is_err());
        assert!(trusted_store_file_url_with("https://bookos.es/store-files/%2e%2e/x", None, false).is_err());
        assert!(trusted_store_file_url_with(
            "http://127.0.0.1:8080/a.rpm",
            Some("http://127.0.0.1:8080/store.json"),
            false
        ).is_err());
        assert!(trusted_store_file_url_with(
            "http://127.0.0.1:8080/a.rpm",
            Some("http://127.0.0.1:8080/store.json"),
            true
        ).is_ok());
        assert!(trusted_store_file_url_with(
            "http://evil.com/a.rpm",
            Some("http://evil.com/store.json"),
            true
        ).is_err());
    }

    #[test]
    fn test_valid_external_https_url() {
        assert!(valid_external_https_url("https://example.org/privacy"));
        assert!(valid_external_https_url("https://codeberg.org/user/repo#readme"));
        assert!(!valid_external_https_url("http://example.org/privacy"));
        assert!(!valid_external_https_url("file:///etc/passwd"));
        assert!(!valid_external_https_url("javascript:alert(1)"));
        assert!(!valid_external_https_url("https://user@evil.com/"));
        assert!(!valid_external_https_url("https://localhost/foo"));
        assert!(!valid_external_https_url("https://example.org/a\"b"));
    }

    #[test]
    fn test_ed25519_verify_and_anti_rollback() {
        let dir = std::env::temp_dir().join(format!("bookos-test-ed25519-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _guard = TempDirGuard(dir.clone());

        let priv1 = dir.join("priv1.pem");
        let pub1 = dir.join("pub1.pem");
        let priv2 = dir.join("priv2.pem");
        let pub2 = dir.join("pub2.pem");
        let msg = dir.join("store.json");
        let sig_raw = dir.join("store.sig");

        assert!(Command::new("openssl").args(["genpkey", "-algorithm", "Ed25519", "-out"]).arg(&priv1).status().unwrap().success());
        assert!(Command::new("openssl").args(["pkey", "-in"]).arg(&priv1).args(["-pubout", "-out"]).arg(&pub1).status().unwrap().success());
        assert!(Command::new("openssl").args(["genpkey", "-algorithm", "Ed25519", "-out"]).arg(&priv2).status().unwrap().success());
        assert!(Command::new("openssl").args(["pkey", "-in"]).arg(&priv2).args(["-pubout", "-out"]).arg(&pub2).status().unwrap().success());

        let payload = br#"{"generated_at":1700000100,"apps":[]}"#;
        std::fs::write(&msg, payload).unwrap();
        assert!(Command::new("openssl")
            .args(["pkeyutl", "-sign", "-inkey"]).arg(&priv1)
            .args(["-rawin", "-in"]).arg(&msg)
            .args(["-out"]).arg(&sig_raw)
            .status().unwrap().success());

        let raw_bytes = std::fs::read(&sig_raw).unwrap();
        assert_eq!(raw_bytes.len(), 64);
        let b64_bytes = format!("{}\n", general_purpose::STANDARD.encode(&raw_bytes)).into_bytes();
        let pub1_pem = std::fs::read_to_string(&pub1).unwrap();
        let pub2_pem = std::fs::read_to_string(&pub2).unwrap();

        assert!(verify_ed25519_signature(payload, &raw_bytes, &pub1_pem).is_ok());
        assert!(verify_ed25519_signature(payload, &b64_bytes, &pub1_pem).is_ok());

        let mut tampered = payload.to_vec();
        tampered[18] = b'2';
        assert!(verify_ed25519_signature(&tampered, &b64_bytes, &pub1_pem).is_err());
        assert!(verify_ed25519_signature(payload, &b64_bytes, &pub2_pem).is_err());

        let old_v = serde_json::json!({"generated_at": 1700000100u64});
        let same_v = serde_json::json!({"generated_at": 1700000100u64});
        let new_v = serde_json::json!({"generated_at": 1700000200u64});
        let stale_v = serde_json::json!({"generated_at": 1700000050u64});
        assert!(check_anti_rollback(&same_v, Some(&old_v)).is_ok());
        assert!(check_anti_rollback(&new_v, Some(&old_v)).is_ok());
        assert!(check_anti_rollback(&stale_v, Some(&old_v)).is_err());

        let iso_old = serde_json::json!({"generated_at": "2026-11-20T21:22:11+00:00"});
        let iso_same_tz = serde_json::json!({"generated_at": "2026-11-20T22:22:11+01:00"});
        let iso_new = serde_json::json!({"generated_at": "2026-11-20T21:22:12Z"});
        let iso_stale = serde_json::json!({"generated_at": "2026-11-20T21:22:10+00:00"});
        assert!(check_anti_rollback(&iso_same_tz, Some(&iso_old)).is_ok());
        assert!(check_anti_rollback(&iso_new, Some(&iso_old)).is_ok());
        assert!(check_anti_rollback(&iso_stale, Some(&iso_old)).is_err());
    }

    #[test]
    fn test_embedded_pubkey_and_submit_url() {
        let pk = active_catalog_pubkey_with(None, EMBEDDED_CATALOG_PUBKEY)
            .expect("error leyendo clave embebida")
            .expect("se esperaba clave pública Ed25519 embebida activa");
        assert!(pk.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pk.contains("-----END PUBLIC KEY-----"));
        assert!(valid_external_https_url("https://developer.bookos.es/submit/"));
    }
}

