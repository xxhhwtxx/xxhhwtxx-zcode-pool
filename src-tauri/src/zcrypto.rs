use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const PREFIX: &str = "enc:v1:";
pub const PREFIX_V2: &str = "enc:v2:";

pub fn node_platform_for<'a>(os: &'a str) -> &'a str {
    match os {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    }
}

fn node_os() -> &'static str {
    node_platform_for(std::env::consts::OS)
}

fn pick_username(username: Option<&str>, user: Option<&str>, logname: Option<&str>) -> String {
    username
        .or(user)
        .or(logname)
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(not(windows))]
fn passwd_username() -> Option<String> {
    let out = std::process::Command::new("id")
        .arg("-un")
        .output()
        .ok()?;
    let n = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!n.is_empty()).then_some(n)
}

fn compose_fallback_secret(platform: &str, home: &str, username: &str) -> String {
    format!("zcode-credential-fallback:{}:{}:{}", platform, home, username)
}

pub fn default_secret(home: &Path) -> String {
    if let Ok(s) = std::env::var("ZCODE_CREDENTIAL_SECRET") {
        return s;
    }
    #[cfg(windows)]
    let primary = std::env::var("USERNAME").ok();
    #[cfg(not(windows))]
    let primary = passwd_username().or_else(|| std::env::var("USER").ok());
    let username = pick_username(
        primary.as_deref(),
        std::env::var("USER").ok().as_deref(),
        std::env::var("LOGNAME").ok().as_deref(),
    );
    compose_fallback_secret(node_os(), &home.display().to_string(), &username)
}

fn derive_key(secret: &str) -> [u8; 32] {
    let d = Sha256::digest(secret.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[allow(dead_code)]
pub fn is_encrypted(v: &str) -> bool {
    v.starts_with(PREFIX) || v.starts_with(PREFIX_V2)
}

pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let d = Sha256::digest(key);
    d[..12].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_os_keyring_blob(raw: &[u8]) -> Result<[u8; 32], String> {
    let utf16_candidate = if raw.len() % 2 == 0 {
        let words: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&words).ok().and_then(|s| {
            let trimmed = s.trim_matches('\0').trim();
            (!trimmed.is_empty() && trimmed.is_ascii()).then(|| trimmed.to_string())
        })
    } else {
        None
    };
    let encoded = match utf16_candidate {
        Some(s) => s,
        None => String::from_utf8(raw.to_vec())
            .map_err(|_| "OS 凭据密钥不是有效编码".to_string())?
            .trim_matches('\0')
            .trim()
            .to_string(),
    };
    let clean = encoded.trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD
        .decode(clean)
        .or_else(|_| URL_SAFE.decode(&encoded))
        .map_err(|e| format!("OS 凭据密钥 base64 解码失败：{e}"))?;
    if bytes.len() != 32 {
        return Err(format!("OS 凭据密钥长度异常：{}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decrypt_aes_gcm(nonce_b64: &str, tag_b64: &str, ct_b64: &str, key: &[u8; 32]) -> Result<String, String> {
    let nonce_b = URL_SAFE_NO_PAD
        .decode(nonce_b64.trim_end_matches('='))
        .map_err(|e| format!("nonce 解码失败：{e}"))?;
    let tag_b = URL_SAFE_NO_PAD
        .decode(tag_b64.trim_end_matches('='))
        .map_err(|e| format!("tag 解码失败：{e}"))?;
    let ct_b = URL_SAFE_NO_PAD
        .decode(ct_b64.trim_end_matches('='))
        .map_err(|e| format!("密文解码失败：{e}"))?;
    if nonce_b.len() != 12 {
        return Err("nonce 长度异常".into());
    }
    if tag_b.len() != 16 {
        return Err("tag 长度异常".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败：{e}"))?;
    let mut buf = ct_b;
    buf.extend_from_slice(&tag_b);
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce_b), buf.as_slice())
        .map_err(|_| "解密失败（密钥不匹配或数据损坏）".to_string())?;
    Ok(String::from_utf8_lossy(&pt).to_string())
}

pub fn decrypt_with_secret(value: &str, secret: &str) -> Result<String, String> {
    let body = value.strip_prefix(PREFIX).ok_or("不是 enc:v1 格式")?;
    let parts: Vec<&str> = body.split('.').collect();
    if parts.len() != 3 {
        return Err("enc:v1 格式不正确".into());
    }
    let key = derive_key(secret);
    decrypt_aes_gcm(parts[0], parts[1], parts[2], &key)
}

pub fn parse_v2_header(value: &str) -> Result<(&str, &str, &str), String> {
    let body = value.strip_prefix(PREFIX_V2).ok_or("不是 enc:v2 格式")?;
    let mut it = body.splitn(3, ':');
    let source = it.next().filter(|s| !s.is_empty()).ok_or("enc:v2 缺来源")?;
    let fp = it.next().filter(|s| s.len() == 24).ok_or("enc:v2 指纹异常")?;
    let payload = it.next().filter(|s| !s.is_empty()).ok_or("enc:v2 缺密文")?;
    Ok((source, fp, payload))
}

pub fn decrypt_v2_with_key(value: &str, key: &[u8; 32]) -> Result<String, String> {
    let (_source, fp, payload) = parse_v2_header(value)?;
    let actual_fp = key_fingerprint(key);
    if !fp.eq_ignore_ascii_case(&actual_fp) {
        return Err(format!("enc:v2 密钥指纹不匹配：期望 {fp} 实际 {actual_fp}"));
    }
    let parts: Vec<&str> = payload.split('.').collect();
    if parts.len() != 3 {
        return Err("enc:v2 密文格式不正确".into());
    }
    decrypt_aes_gcm(parts[0], parts[1], parts[2], key)
}

pub fn encrypt_v2_os_with_nonce(plain: &str, key: &[u8; 32], nonce: &[u8; 12]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败：{e}"))?;
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(nonce), plain.as_bytes())
        .map_err(|e| format!("加密失败：{e}"))?;
    if sealed.len() < 16 {
        return Err("加密输出长度异常".into());
    }
    let tag = sealed.split_off(sealed.len() - 16);
    let fp = key_fingerprint(key);
    Ok(format!(
        "{PREFIX_V2}os:{fp}:{}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(&tag),
        URL_SAFE_NO_PAD.encode(&sealed),
    ))
}

fn keyring_target_name(cred_file: &Path) -> String {
    let s = cred_file.to_string_lossy();
    let norm = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let digest = Sha256::digest(norm.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}.ZCode Credential Encryption")
}

#[cfg(windows)]
fn cred_read_raw(target: &str) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };
    let mut wide: Vec<u16> = target.encode_utf16().collect();
    wide.push(0);
    let mut ptr: *mut CREDENTIALW = std::ptr::null_mut();
    let ok = unsafe { CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut ptr) };
    if ok == 0 || ptr.is_null() {
        return Err("Windows 凭据管理器中未找到对应密钥".into());
    }
    let out = unsafe {
        let cred = &*ptr;
        if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize).to_vec()
        }
    };
    unsafe { CredFree(ptr as *const std::ffi::c_void) };
    if out.is_empty() {
        return Err("Windows 凭据密钥为空".into());
    }
    Ok(out)
}

#[cfg(windows)]
fn random_nonce_12() -> Result<[u8; 12], String> {
    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    let mut nonce = [0u8; 12];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            nonce.as_mut_ptr(),
            nonce.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(format!("BCryptGenRandom 失败：0x{status:08x}"));
    }
    Ok(nonce)
}

fn os_key_cache() -> &'static Mutex<HashMap<PathBuf, [u8; 32]>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, [u8; 32]>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn read_os_keyring_key(cred_file: &Path) -> Result<[u8; 32], String> {
    if std::env::var("ZCODE_POOL_HOME").is_ok() {
        return Err("沙盒测试模式禁用宿主 OS 凭据管理器".into());
    }
    #[cfg(windows)]
    {
        if let Some(k) = os_key_cache().lock().unwrap().get(cred_file).copied() {
            return Ok(k);
        }
        let target = keyring_target_name(cred_file);
        let raw = cred_read_raw(&target)?;
        let key = decode_os_keyring_blob(&raw)?;
        os_key_cache().lock().unwrap().insert(cred_file.to_path_buf(), key);
        Ok(key)
    }
    #[cfg(not(windows))]
    {
        let _ = cred_file;
        Err("当前平台暂未实现 enc:v2:os 凭据读取".into())
    }
}

fn read_os_keyring_key_fresh(cred_file: &Path) -> Result<[u8; 32], String> {
    os_key_cache().lock().unwrap().remove(cred_file);
    read_os_keyring_key(cred_file)
}

pub fn encrypt_v2_os_for_file(plain: &str, cred_file: &Path) -> Result<String, String> {
    #[cfg(windows)]
    {
        let key = read_os_keyring_key(cred_file)?;
        let nonce = random_nonce_12()?;
        encrypt_v2_os_with_nonce(plain, &key, &nonce)
    }
    #[cfg(not(windows))]
    {
        let _ = (plain, cred_file);
        Err("当前平台暂未实现 enc:v2:os 凭据加密".into())
    }
}

pub fn decrypt_v2_with_files(value: &str, cred_files: &[&Path]) -> Result<String, String> {
    let (source, fp, _payload) = parse_v2_header(value)?;
    if source == "env" {
        if let Ok(sec) = std::env::var("ZCODE_CREDENTIAL_SECRET") {
            let d = Sha256::digest(sec.as_bytes());
            let mut key = [0u8; 32];
            key.copy_from_slice(&d);
            return decrypt_v2_with_key(value, &key);
        }
        return Err("缺 ZCODE_CREDENTIAL_SECRET，无法解 enc:v2:env".into());
    }
    if source != "os" {
        return Err(format!("不支持的 enc:v2 来源：{source}"));
    }
    let mut last_err = String::new();
    for path in cred_files {
        match read_os_keyring_key(path) {
            Ok(key) if key_fingerprint(&key).eq_ignore_ascii_case(fp) => {
                return decrypt_v2_with_key(value, &key);
            }
            Ok(_) => {
                if let Ok(fresh) = read_os_keyring_key_fresh(path) {
                    if key_fingerprint(&fresh).eq_ignore_ascii_case(fp) {
                        return decrypt_v2_with_key(value, &fresh);
                    }
                }
                last_err = format!("{} 密钥指纹不匹配", path.display());
            }
            Err(e) => last_err = e,
        }
    }
    if cred_files.is_empty() {
        return Err("缺少凭据文件路径，无法定位 OS 密钥".into());
    }
    Err(if last_err.is_empty() { "无法读取 OS 凭据密钥".into() } else { last_err })
}

pub fn default_cred_files(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let paths = crate::store::Paths { home: home.to_path_buf() };
    let live = paths.live_file();
    let legacy = home.join(".zcode").join("v2").join("credentials.json");
    out.push(live);
    if !out.contains(&legacy) {
        out.push(legacy);
    }
    out
}

pub fn decrypt_value_for_home(value: &str, secret: &str, home: &Path) -> Result<String, String> {
    if value.starts_with(PREFIX) {
        decrypt_with_secret(value, secret)
    } else if value.starts_with(PREFIX_V2) {
        let owned = default_cred_files(home);
        let refs: Vec<&Path> = owned.iter().map(|p| p.as_path()).collect();
        decrypt_v2_with_files(value, &refs)
    } else {
        Ok(value.to_string())
    }
}

pub fn decrypt_value_with_secret_or_v2(value: &str, secret: &str) -> Result<String, String> {
    if value.starts_with(PREFIX) {
        decrypt_with_secret(value, secret)
    } else if value.starts_with(PREFIX_V2) {
        let home = crate::store::Paths::detect().home;
        let owned = default_cred_files(&home);
        let refs: Vec<&Path> = owned.iter().map(|p| p.as_path()).collect();
        decrypt_v2_with_files(value, &refs)
    } else {
        Ok(value.to_string())
    }
}

pub fn unprotect_v2_in_place(creds: &mut Value, cred_files: &[&Path]) {
    let Some(map) = creds.as_object_mut() else { return; };
    for v in map.values_mut() {
        if let Some(s) = v.as_str() {
            if s.starts_with(PREFIX_V2) {
                if let Ok(plain) = decrypt_v2_with_files(s, cred_files) {
                    *v = Value::String(plain);
                }
            }
        }
    }
}

pub fn decrypt_json_opt(value: Option<&str>, secret: &str) -> Option<Value> {
    let v = value?;
    let plain = decrypt_value_with_secret_or_v2(v, secret).ok()?;
    serde_json::from_str(&plain).ok()
}

pub fn decode_jwt(jwt: &str) -> Option<Value> {
    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    if payload.is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Identity {
    pub provider: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub user_id: Option<String>,
}

impl Identity {
    pub fn label(&self) -> Option<String> {
        self.display_name
            .clone()
            .or_else(|| self.username.clone())
            .or_else(|| self.email.clone())
    }
}

pub fn identity_with_secret(creds: &Value, secret: &str) -> Identity {
    let mut id = Identity { provider: "bigmodel".into(), ..Default::default() };
    let map = match creds.as_object() {
        Some(m) => m,
        None => return id,
    };
    if let Some(ap) = map.get("oauth:active_provider").and_then(|v| v.as_str()) {
        let plain = decrypt_value_with_secret_or_v2(ap, secret).ok();
        if let Some(p) = plain.filter(|p| !p.is_empty()) {
            id.provider = p;
        }
    }
    let ui_key = format!("oauth:{}:user_info", id.provider);
    let ui = map
        .get(ui_key.as_str())
        .and_then(|v| v.as_str())
        .and_then(|v| decrypt_json_opt(Some(v), secret));
    if let Some(ui) = ui {
        let non_empty = |v: &Value| v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
        id.username = ui.get("username").and_then(non_empty);
        id.display_name = ui
            .get("displayName")
            .and_then(non_empty)
            .or_else(|| ui.get("name").and_then(non_empty));
        id.email = ui
            .get("email")
            .and_then(non_empty)
            .or_else(|| ui.get("rawProfile").and_then(|r| r.get("email")).and_then(non_empty));
        if let Some(uid) = ui
            .get("id")
            .or_else(|| ui.get("user_id"))
            .or_else(|| ui.get("sub"))
            .filter(|v| !v.is_null())
        {
            id.user_id = non_empty(uid).or_else(|| serde_json::to_string(uid).ok());
        }
    }
    if id.user_id.is_none() {
        if let Some(zjwt) = map.get("zcodejwttoken").and_then(|v| v.as_str()) {
            let plain = decrypt_value_with_secret_or_v2(zjwt, secret).ok();
            if let Some(jwt) = plain.as_deref().and_then(decode_jwt) {
                id.user_id = jwt
                    .get("user_id")
                    .or_else(|| jwt.get("sub"))
                    .and_then(|v| v.as_str().map(String::from).or_else(|| v.as_i64().map(|n| n.to_string())));
            }
        }
    }
    if id.user_id.is_none() || id.username.is_none() {
        let at_key = format!("oauth:{}:access_token", id.provider);
        if let Some(at) = map.get(at_key.as_str()).and_then(|v| v.as_str()) {
            let plain = decrypt_value_with_secret_or_v2(at, secret).ok();
            if let Some(jwt) = plain.as_deref().and_then(decode_jwt) {
                if id.username.is_none() {
                    id.username = jwt
                        .get("username")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from);
                }
                if id.user_id.is_none() {
                    id.user_id = jwt
                        .get("user_id")
                        .or_else(|| jwt.get("sub"))
                        .and_then(|v| v.as_str().map(String::from).or_else(|| v.as_i64().map(|n| n.to_string())));
                }
            }
        }
    }
    id
}

pub fn account_identity(creds: &Value, home: &Path) -> Identity {
    identity_with_secret(creds, &default_secret(home))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_v2_roundtrip_and_utf16_blob() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let enc = encrypt_v2_os_with_nonce("secret-jwt-value", &key, &nonce).unwrap();
        assert!(is_encrypted(&enc));
        assert!(enc.starts_with(&format!("enc:v2:os:{}:", key_fingerprint(&key))));
        assert_eq!(decrypt_v2_with_key(&enc, &key).unwrap(), "secret-jwt-value");

        let b64 = URL_SAFE_NO_PAD.encode(key);
        let mut utf16_bytes = Vec::with_capacity(b64.len() * 2);
        for u in b64.encode_utf16() {
            utf16_bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_os_keyring_blob(&utf16_bytes).unwrap(), key);
        assert_eq!(decode_os_keyring_blob(b64.as_bytes()).unwrap(), key);
    }

    #[test]
    fn identity_parses_v4_userinfo_and_zcodejwt() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"user_id":"6bdb7510-6193-4197-b0c8-4db4f5152bca","sub":"6bdb7510-6193-4197-b0c8-4db4f5152bca"}"#);
        let zjwt = format!("eyJhbGciOiJIUzI1NiJ9.{payload}.sig");
        let creds = serde_json::json!({
            "oauth:active_provider": "zai",
            "oauth:zai:user_info": serde_json::json!({
                "email": "u@example.com",
                "name": "nick"
            }).to_string(),
            "zcodejwttoken": zjwt
        });
        let id = identity_with_secret(&creds, "unused");
        assert_eq!(id.provider, "zai");
        assert_eq!(id.display_name.as_deref(), Some("nick"));
        assert_eq!(id.email.as_deref(), Some("u@example.com"));
        assert_eq!(id.user_id.as_deref(), Some("6bdb7510-6193-4197-b0c8-4db4f5152bca"));
    }
}
