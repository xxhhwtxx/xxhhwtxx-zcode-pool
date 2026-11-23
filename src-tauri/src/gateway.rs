use crate::store::{self, Paths};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const UPSTREAM: &str = "https://zcode.z.ai/api/v1/zcode-plan/anthropic";
pub const DEFAULT_PORT: u16 = 8899;
const SWITCH_STATUS: [u16; 5] = [401, 402, 403, 405, 429];
const MAX_TRIES: usize = 6;
const QUOTA_TTL_MS: u64 = 5 * 60 * 1000;

const NO_QUOTA_TTL_MS: u64 = 30 * 60 * 1000;

const RATE_TTL_MS: u64 = 5 * 60 * 1000;
const SHORT_RATE_TTL_MS: u64 = 60 * 1000;
const MAX_TOKENS_LIMIT: u64 = 131_072;

pub const POLICY_EXPIRE: &str = "expire_first";
pub const POLICY_MOST_LEFT: &str = "most_left";
pub const POLICY_PINNED: &str = "pinned";

pub const MODEL_AUTO: &str = "auto";
pub const MODEL_PINNED: &str = "pinned";

pub const EXTERNAL_MODELS: [&str; 3] = ["GLM-5.4", "GLM-5.3-Flash", "GLM-5.3"];

const MINT_PAGE: &str = include_str!("../assets/mint.html");

const CHAT_PAGE: &str = include_str!("../assets/chat.html");

const PROXY_PAGE: &str = include_str!("../assets/proxy.html");

const CLIENT_HEADERS: [(&str, &str); 18] = [
    ("anthropic-version", "2023-06-01"),
    ("content-type", "application/json"),
    ("http-referer", "https://zcode.z.ai"),
    ("user-agent", "@UA@"),
    ("x-client-language", "zh-CN"),
    ("x-client-timezone", "Asia/Shanghai"),
    ("x-os-category", "@OSCAT@"),
    ("x-os-version", "@OSVER@"),
    ("x-platform", "@PLAT@"),
    ("x-release-channel", "production"),
    ("x-title", "Z Code@electron"),
    ("x-zcode-agent", "glm"),
    ("x-zcode-app-version", "@VER@"),
    ("x-zcode-session-type", "main"),
    ("x-zcode-query-source", "main_turn"),
    ("accept", "*/*"),
    ("accept-language", "*"),
    ("sec-fetch-mode", "cors"),
];

const CAPTCHA_REGION: &str = "cn";
const CAPTCHA_HEADER: &str = "X-Aliyun-Captcha-Verify-Param";
const CAPTCHA_REGION_HEADER: &str = "X-Aliyun-Captcha-Verify-Region";

/// Messages 通道请求头：版本号严格锁在 `prompt::PROMPT_ALIGNED_VERSION`（3.17.2），
/// 与 `zcode_system.json` 正文逐字节同源（参考 dengyie/zcode2api 正文锁设计，防止头新于正文触发 405/3012）。
fn client_headers() -> Vec<(&'static str, String)> {
    let ver = crate::prompt::PROMPT_ALIGNED_VERSION.to_string();
    let plat = crate::quota::client_platform();
    let oscat = std::env::consts::OS.to_string();
    let osver = crate::quota::os_version().unwrap_or_else(|| "10.0.26200".into());
    CLIENT_HEADERS
        .iter()
        .map(|(k, v)| {
            let v = match *v {
                "@UA@" => format!("ZCode/{ver} ai-sdk/anthropic/3.0.81"),
                "@VER@" => ver.clone(),
                "@PLAT@" => plat.clone(),
                "@OSCAT@" => oscat.clone(),
                "@OSVER@" => osver.clone(),
                other => other.to_string(),
            };
            (*k, v)
        })
        .collect()
}

const METER_WINDOW_MS: u64 = 15_000;

const PROBE_EVERY_MS: u64 = 90_000;

const PROBE_HISTORY: usize = 24;
const PARAM_PRE: usize = 1;
const PARAM_MAX_POOL: usize = 4;
const PARAM_MAX_AGE_MS: u64 = 90_000;
const PARAM_WAIT_MS: u64 = 25_000;
const ACTIVE_WINDOW_MS: u64 = 180_000;
const INFLIGHT_TTL_MS: u64 = 30_000;

fn quota_cache_file(paths: &Paths) -> std::path::PathBuf {
    paths.store_dir().join("quota-cache.json")
}

const QUOTA_DISK_TTL_MS: u64 = 10 * 60 * 1000;

type QuotaSnap = (Vec<(String, (u64, crate::quota::QuotaOverview))>, Option<String>, usize);

fn quota_snapshot(g: &Inner) -> QuotaSnap {
    let now = now_ms();
    (
        g.quota
            .iter()
            .filter(|(_, (at, _))| now.saturating_sub(*at) <= QUOTA_DISK_TTL_MS)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        g.last_refresh.clone(),
        g.quota_total,
    )
}

fn write_quota_cache(paths: &Paths, snap: QuotaSnap) {
    let (items, last_refresh, total) = snap;
    if items.is_empty() {
        return;
    }
    let mut entries = serde_json::Map::new();
    for (id, (at, ov)) in items {
        let Ok(v) = serde_json::to_value(&ov) else { continue };
        entries.insert(id, json!({ "at": at, "ov": v }));
    }
    let v = json!({ "entries": entries, "lastRefresh": last_refresh, "total": total });
    let p = quota_cache_file(paths);
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = p.with_extension("json.tmp");
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        if std::fs::rename(&tmp, &p).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

fn read_quota_cache(paths: &Paths) -> QuotaSnap {
    let Ok(s) = std::fs::read_to_string(quota_cache_file(paths)) else {
        return (Vec::new(), None, 0);
    };
    let Ok(v) = serde_json::from_str::<Value>(&s) else {
        return (Vec::new(), None, 0);
    };
    let now = now_ms();
    let mut out = Vec::new();
    if let Some(entries) = v.get("entries").and_then(|x| x.as_object()) {
        for (id, e) in entries {
            let at = e.get("at").and_then(|x| x.as_u64()).unwrap_or(0);
            if now.saturating_sub(at) > QUOTA_DISK_TTL_MS {
                continue;
            }
            let Some(ov) = e.get("ov") else { continue };
            let Ok(ov) = serde_json::from_value::<crate::quota::QuotaOverview>(ov.clone()) else {
                continue;
            };
            out.push((id.clone(), (at, ov)));
        }
    }
    let lr = v.get("lastRefresh").and_then(|x| x.as_str()).map(str::to_string);
    let total = v.get("total").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    (out, lr, total)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

struct Route {
    account: String,
    model: String,
    tries: usize,
}

#[derive(Default)]
struct Inner {
    running: bool,
    port: u16,
    served: u64,
    switched: u64,
    client_account: Option<String>,
    last_route: Option<Route>,
    stop: Option<Arc<AtomicBool>>,

    server: Option<Arc<tiny_http::Server>>,

    serving: Option<Arc<AtomicBool>>,
    quota: HashMap<String, (u64, crate::quota::QuotaOverview)>,
    sticky: Option<String>,
    refreshing: bool,
    last_refresh: Option<String>,
    last_billing: Option<String>,
    policy: String,
    pinned: Option<String>,
    model_mode: String,

    model_pinned: Option<String>,

    /// 反代出站的代理（空 = 直连）。见 `Settings::relay_proxy`
    relay_proxy: Option<String>,
    quota_total: usize,
    last_failed: Vec<String>,

    external: bool,

    params: Vec<(String, String, u64)>,

    waiters: usize,

    inflight: Vec<u64>,

    last_use: u64,
    mints: u64,
    mint_times: Vec<u64>,

    bytes_out: u64,

    tokens_sum: u64,

    last_gen_tps: Option<f64>,

    meter: Vec<(u64, u64, u64)>,

    health: HashMap<String, Health>,

    last_ttfb_ms: Option<u64>,
    last_total_ms: Option<u64>,

    bind: String,

    keys: Vec<String>,

    model_map: std::collections::BTreeMap<String, String>,

    no_quota: HashMap<(String, String), u64>,

    blocked: HashMap<String, u64>,
}

#[derive(Clone, Default)]
pub struct Gateway {
    inner: Arc<Mutex<Inner>>,

    app: Arc<std::sync::OnceLock<tauri::AppHandle>>,
}

struct Candidate {
    id: String,
    name: String,
    token: String,
    mid: String,
    expire: Option<String>,
    left: f64,
}

impl Gateway {
    pub fn new() -> Self {
        let g = Self::default();
        {
            let mut i = g.inner.lock().unwrap();
            i.bind = "127.0.0.1".to_string();
            i.policy = POLICY_EXPIRE.to_string();
            i.model_mode = MODEL_AUTO.to_string();
        }
        g
    }

    pub fn set_app(&self, app: tauri::AppHandle) {
        let _ = self.app.set(app);
    }

    fn app(&self) -> Option<tauri::AppHandle> {
        self.app.get().cloned()
    }

    fn sync_exe(&self) {
        if let Some(app) = self.app() {
            crate::rebuild_tray(&app);
            crate::emit_state_changed(&app);
        }
    }

    pub fn console_status(&self, paths: &Paths) -> Value {
        let accs = store::list_accounts(paths).unwrap_or_default();
        let accounts: Vec<String> = accs.iter().map(|a| a.name.clone()).collect();
        let mut g = self.inner.lock().unwrap();
        let now = now_ms();
        g.meter.retain(|s| now.saturating_sub(s.0) < METER_WINDOW_MS);
        let (dt, dbytes, dtok) = meter_delta(&g);

        let (tps, tps_est) = if dt <= 0.0 {
            (0.0, false)
        } else if dtok > 0 {
            (dtok as f64 / dt, false)
        } else {
            (dbytes as f64 / 4.0 / dt, true)
        };
        let bps = if dt <= 0.0 { 0.0 } else { dbytes as f64 / dt };

        let frozen: serde_json::Map<String, Value> = {
            let mut m = serde_json::Map::new();
            for (id, t) in g.blocked.iter() {
                if *t > now {
                    m.insert(id.clone(), json!("限流"));
                }
            }
            for ((id, _), t) in g.no_quota.iter() {
                if now.saturating_sub(*t) < NO_QUOTA_TTL_MS {
                    m.insert(id.clone(), json!("用尽"));
                }
            }
            m
        };
        let generating = g
            .meter
            .last()
            .map(|s| now.saturating_sub(s.0) < 2500)
            .unwrap_or(false);
        let routing = g
            .last_route
            .as_ref()
            .map(|r| r.account.clone())
            .unwrap_or_else(|| "-".into());
        let routed = g
            .last_route
            .as_ref()
            .map(|r| json!({ "account": r.account, "model": r.model, "tries": r.tries }));
        json!({
            "running": g.running,
            "port": g.port,
            "external": g.external,
            "served": g.served,
            "switched": g.switched,
            "models": EXTERNAL_MODELS,
            "mint": mint_stats(&g),
            "routed": routed,
            "routing": routing,
            "accounts": accounts,

            "channels": accs.iter().map(|a| json!({
                "id": a.id,
                "name": a.name,
                "health": g.health.get(&a.id).map(|h| h.json()),
                "frozen": frozen.get(&a.id),
            })).collect::<Vec<_>>(),
            "bytes": g.bytes_out,
            "tokens": g.tokens_sum,
            "lastTps": g.last_gen_tps,
            "tps": (tps * 10.0).round() / 10.0,
            "tpsEstimated": tps_est,
            "bps": (bps * 10.0).round() / 10.0,
            "generating": generating,
            "ttfbMs": g.last_ttfb_ms,
            "totalMs": g.last_total_ms,
            // 反代对外冒充的 ZCode 客户端版本（从安装的 exe 里读，读不到才用兜底常量）
            "zcodeVersion": crate::quota::zcode_app_version(),
            "relayProxy": g.relay_proxy,
            "bind": g.bind,
            "keys": g.keys,
            "modelMap": g.model_map,
            "lanHost": lan_host(),
            "policy": g.policy,
            "pinned": g.pinned,
            "modelMode": g.model_mode,
            "modelPinned": g.model_pinned,
            "health": g.health.iter().map(|(k, v)| (k.clone(), v.json())).collect::<serde_json::Map<String, Value>>(),
            "frozen": frozen,

            "quotaAccounts": g.quota.len(),
            "quotaTotal": g.quota_total,
            "quotaFailed": g.last_failed.clone(),
            "lastRefresh": g.last_refresh.clone(),
        })
    }

    pub fn status(&self, paths: &Paths) -> Value {
        let next_up = if self.inner.lock().unwrap().last_route.is_none() {
            self.next_up(paths)
        } else {
            None
        };
        let live_id = if self.inner.lock().unwrap().client_account.is_none() {
            live_account_id(paths)
        } else {
            None
        };
        let g = self.inner.lock().unwrap();
        let client_id = g.client_account.clone().or(live_id);
        let route_id = g
            .last_route
            .as_ref()
            .map(|r| r.account.clone())
            .or_else(|| next_up.clone());
        json!({
            "running": g.running,
            "port": g.port,
            "defaultPort": DEFAULT_PORT,
            "served": g.served,
            "switched": g.switched,
            "upstream": UPSTREAM,
            "clientAccount": client_id.clone(),
            "routedAccount": g.last_route.as_ref().map(|r| r.account.clone()),
            "routedModel": g.last_route.as_ref().map(|r| r.model.clone()),
            "routedTries": g.last_route.as_ref().map(|r| r.tries),
            "nextAccount": next_up,
            "quotaAccounts": g.quota.len(),
            "quotaTotal": g.quota_total,
            "quotaFailed": g.last_failed.clone(),
            "lastRefresh": g.last_refresh,
            "lastBilling": g.last_billing,
            "routedQuota": quota_rows_for(&g, route_id.as_deref()),
            "clientQuota": quota_rows_for(&g, client_id.as_deref()),
            "blocked": g.blocked.values().filter(|t| **t > now_ms()).count(),
            "policy": g.policy,
            "pinned": g.pinned,
            "sticky": g.sticky,
            "modelMode": g.model_mode,
            "modelPinned": g.model_pinned,
            "models": models_seen(&g.quota),
            "external": g.external,
            "externalModels": EXTERNAL_MODELS,
            "mint": mint_stats(&g),
        })
    }

    fn next_up(&self, paths: &Paths) -> Option<String> {
        let ms = {
            let g = self.inner.lock().unwrap();
            models_seen(&g.quota)
        };
        for m in ms {
            if let Some(c) = self.sticky_order(self.candidates(paths, &m)).into_iter().next() {
                return Some(c.id);
            }
        }
        None
    }

    pub fn warm_quota(
        &self,
        paths: &Paths,
        max_passes: usize,
        progress: impl Fn(Value),
    ) -> Value {
        let ids: Vec<String> = store::list_accounts(paths)
            .map(|v| v.into_iter().map(|a| a.id).collect())
            .unwrap_or_default();
        let total = ids.len();
        let mut pass = 0usize;
        let mut have = 0usize;
        for p in 1..=max_passes.max(1) {
            pass = p;
            let _ = self.refresh_quota(paths, false);
            have = {
                let g = self.inner.lock().unwrap();
                ids.iter().filter(|i| g.quota.contains_key(*i)).count()
            };
            progress(json!({ "pass": p, "have": have, "total": total }));
            if have >= total {
                break;
            }
            if p < max_passes {
                std::thread::sleep(Duration::from_millis(900));
            }
        }
        let failed = self.inner.lock().unwrap().last_failed.clone();
        json!({ "have": have, "total": total, "passes": pass,
                "complete": have >= total, "failed": failed })
    }

    pub fn set_policy(&self, policy: String, pinned: Option<String>) -> Result<(), String> {
        if !matches!(policy.as_str(), POLICY_EXPIRE | POLICY_MOST_LEFT | POLICY_PINNED) {
            return Err(crate::i18n::tr("err.gw.bad_policy"));
        }
        let mut g = self.inner.lock().unwrap();
        g.policy = policy;
        g.pinned = pinned.filter(|p| !p.trim().is_empty());
        g.sticky = None;
        Ok(())
    }

    pub fn set_model_mode(&self, paths: &Paths, mode: String, pinned: Option<String>) -> Result<(), String> {
        if !matches!(mode.as_str(), MODEL_AUTO | MODEL_PINNED) {
            return Err("模型策略只有「自动回退」和「指定模型」两种".into());
        }
        let pin = pinned.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if mode == MODEL_PINNED && pin.is_none() {
            return Err("选了「指定模型」就得挑一个模型".into());
        }
        {
            let mut g = self.inner.lock().unwrap();
            g.model_mode = mode.clone();
            g.model_pinned = pin.clone();
        }
        if let Err(e) = store::set_relay_model_policy(paths, &mode, pin.as_deref()) {
            crate::flowlog::log("relay", "model-mode-persist-fail", &e);
        }
        crate::flowlog::log("relay", "model-mode", &format!(
            "{mode}{}", pin.map(|p| format!(" 指定={p}")).unwrap_or_default()));
        Ok(())
    }

    fn mark_blocked(&self, id: &str, ms: u64) {
        let mut g = self.inner.lock().unwrap();
        let now = now_ms();
        g.blocked.retain(|_, t| *t > now);
        let cur = g.blocked.get(id).copied().unwrap_or(0);
        g.blocked.insert(id.to_string(), cur.max(now + ms));
    }

    fn mark_no_quota(&self, id: &str, model: &str) {
        let mut g = self.inner.lock().unwrap();
        let now = now_ms();
        g.no_quota.retain(|_, t| now.saturating_sub(*t) < NO_QUOTA_TTL_MS);
        g.no_quota.insert((id.to_string(), model_key(model)), now);
        if g.sticky.as_deref() == Some(id) {
            g.sticky = None;
        }
        if let Some((_, ov)) = g.quota.get_mut(id) {
            for p in &mut ov.plans {
                for it in &mut p.items {
                    if model_same(&it.name, model) {
                        it.remaining = Some(0.0);
                        it.percent_used = Some(100.0);
                    }
                }
            }
            for it in &mut ov.items {
                if model_same(&it.name, model) {
                    it.remaining = Some(0.0);
                    it.percent_used = Some(100.0);
                }
            }
        }
    }

    fn has_mint_pool_or_waiter_consumer(&self) -> bool {
        let g = self.inner.lock().unwrap();
        let now = now_ms();
        !g.params.is_empty() || now.saturating_sub(g.last_use) < ACTIVE_WINDOW_MS || self.app().is_some()
    }

    fn probe_one(&self, paths: &Paths, id: &str) -> Result<u64, String> {
        let secret = crate::zcrypto::default_secret(&paths.home);
        let acc = store::load_account(paths, id)?;
        let tokens = crate::quota::candidate_tokens(&acc.credentials, acc.config.as_ref(), &secret);
        if tokens.is_empty() {
            return Err("没有可用凭证".into());
        }
        let mid = store::account_mid(paths, id).ok();
        let t0 = now_ms();
        let r = crate::quota::query_quota_mid(&tokens, mid.as_deref());
        let ms = now_ms().saturating_sub(t0);
        let out = r.map(|_| ms).map_err(|e| e.chars().take(120).collect::<String>());
        let now = now_ms();
        let mut g = self.inner.lock().unwrap();
        let h = g.health.entry(id.to_string()).or_default();
        h.last_at = Some(now);
        h.last_ms = out.as_ref().ok().copied();
        match &out {
            Ok(_) => {
                h.ok += 1;
                h.streak = 0;
                h.last_err.clear();
            }
            Err(e) => {
                h.fail += 1;
                h.streak = h.streak.saturating_add(1);
                h.last_err = e.clone();
            }
        }
        h.history.push((now, out.as_ref().ok().copied()));
        while h.history.len() > PROBE_HISTORY {
            h.history.remove(0);
        }
        out
    }

    fn probe_tick(&self, paths: &Paths) {
        let accounts = store::list_accounts(paths).unwrap_or_default();
        if accounts.is_empty() {
            return;
        }
        let pick = {
            let g = self.inner.lock().unwrap();
            accounts
                .iter()
                .map(|a| (g.health.get(&a.id).and_then(|h| h.last_at).unwrap_or(0), a.id.clone()))
                .min()
                .map(|(_, id)| id)
        };
        let Some(id) = pick else { return };

        let jitter = (now_ms() % (PROBE_EVERY_MS * 8 / 10)) / 2;
        std::thread::sleep(Duration::from_millis(jitter));
        match self.probe_one(paths, &id) {
            Ok(ms) => crate::flowlog::log("relay", "probe-ok", &format!("{id} {ms}ms")),
            Err(e) => crate::flowlog::log("relay", "probe-fail", &format!("{id} {e}")),
        }
    }

    pub fn set_external_and_run(&self, paths: &Paths, on: bool) -> Result<Value, String> {
        if on {
            let running = self.inner.lock().unwrap().running;
            if !running {
                let port = self.port_or_default();
                self.start(Paths { home: paths.home.clone() }, port)?;
            }
        }
        self.set_external(on);

        if let Err(e) = store::set_relay_external(paths, on) {
            crate::flowlog::log("relay", "external-persist-fail", &e);
        }
        if !on {
            self.stop();
        }
        Ok(self.console_status(paths))
    }

    fn port_or_default(&self) -> u16 {
        match self.inner.lock().unwrap().port {
            0 => DEFAULT_PORT,
            p => p,
        }
    }

    pub fn restore_persisted(&self, paths: &Paths) {
        let st = store::load_settings(paths);

        let cached = read_quota_cache(paths);
        let mut g = self.inner.lock().unwrap();
        if let Some(b) = st.relay_bind {
            g.bind = b;
        }
        if let Some(k) = st.relay_keys {
            g.keys = k;
        }
        if let Some(m) = st.model_map {
            g.model_map = m;
        }
        if let Some(m) = st.relay_model_mode {
            if m == MODEL_AUTO || m == MODEL_PINNED {
                g.model_mode = m;
            }
        }
        if let Some(p) = st.relay_model_pinned {
            g.model_pinned = Some(p).filter(|x| !x.trim().is_empty());
        }
        g.relay_proxy = st.relay_proxy.filter(|x| !x.trim().is_empty());
        if !cached.0.is_empty() {
            for (id, (at, ov)) in cached.0 {
                g.quota.insert(id, (at, ov));
            }
            g.quota_total = cached.2.max(g.quota.len());
            g.last_refresh = cached.1;
            crate::flowlog::log("relay", "quota-cache-load", &format!("从盘上恢复了 {} 个号的额度", g.quota.len()));
        }
    }

    pub fn set_model_map(&self, paths: &Paths, from: &str, to: &str) -> Result<Value, String> {
        let from = from.trim();
        if from.is_empty() {
            return Err("请求的模型名不能空".into());
        }
        let mut g = self.inner.lock().unwrap();
        if to.trim().is_empty() {
            g.model_map.remove(from);
        } else {
            let to = to.trim();
            if to == from {
                return Err("映射到自己是多余的".into());
            }
            g.model_map.insert(from.to_string(), to.to_string());
        }
        let m = g.model_map.clone();
        drop(g);
        store::set_model_map(paths, &m)?;
        Ok(self.console_status(paths))
    }

    pub fn set_bind(&self, paths: &Paths, bind: &str) -> Result<Value, String> {
        let bind = bind.trim().to_string();
        let loopback = matches!(bind.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !loopback {
            let n = self.inner.lock().unwrap().keys.len();
            if n == 0 {
                return Err("绑到非本机地址之前，先创建一个 API Key —— 否则同网段的人都能用你的号池".into());
            }
        }
        if let Err(e) = store::set_relay_bind(paths, &bind) {
            crate::flowlog::log("relay", "bind-persist-fail", &e);
        }
        {
            let mut g = self.inner.lock().unwrap();
            g.bind = bind.clone();
        }

        crate::flowlog::log(
            "relay",
            "bind-set",
            if loopback { "监听策略 -> 仅本机" } else { "监听策略 -> 局域网可访问（要带 key）" },
        );
        Ok(self.console_status(paths))
    }

    pub fn key_add(&self, paths: &Paths, want: &str) -> Result<String, String> {
        let want = want.trim();
        let k = if want.is_empty() {

            let mut h = Sha256::new();
            h.update(uuid::Uuid::new_v4().as_bytes());
            h.update(uuid::Uuid::new_v4().as_bytes());
            h.update(now_ms().to_le_bytes());
            format!("zp-{}", hex(&h.finalize())[..32].to_string())
        } else {

            if !want.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err("只能用字母、数字、- 和 _".into());
            }
            want.to_string()
        };
        let mut g = self.inner.lock().unwrap();
        if g.keys.iter().any(|x| x == &k) {
            return Err("这个 key 已经存在了".into());
        }
        g.keys.push(k.clone());
        let keys = g.keys.clone();
        drop(g);
        store::set_relay_keys(paths, &keys)?;
        Ok(k)
    }

    pub fn key_del(&self, paths: &Paths, key: &str) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        g.keys.retain(|k| k != key);
        let keys = g.keys.clone();
        drop(g);
        store::set_relay_keys(paths, &keys)
    }

    pub fn set_port(&self, paths: &Paths, port: u16) -> Result<Value, String> {
        if port < 1024 {
            return Err("端口要 >= 1024".into());
        }
        let old = self.port_or_default();
        if port == old {
            return Ok(self.console_status(paths));
        }

        if let Err(e) = store::set_relay_port(paths, port) {
            crate::flowlog::log("relay", "port-persist-fail", &e);
        }
        let was_on = self.inner.lock().unwrap().external;
        self.stop();

        for _ in 0..12 {
            if !port_answers(old) {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        if port_answers(old) {
            self.set_external(was_on);
            crate::flowlog::log("relay", "port-stuck", &format!("旧端口 {old} 停不掉，没敢切"));
            return Err(format!(
                "旧端口 {old} 停不掉（服务其实还在，能正常用）—— 换端口需要**重启一次工具**，重启后直接就是新端口"
            ));
        }
        if let Err(e) = self.start(Paths { home: paths.home.clone() }, port) {
            let _ = self.start(Paths { home: paths.home.clone() }, old);
            self.set_external(was_on);
            return Err(format!("新端口起不来（{e}），已退回 {old}"));
        }
        self.set_external(was_on);
        Ok(self.console_status(paths))
    }

    pub fn unfreeze(&self, id: &str) -> usize {
        let mut g = self.inner.lock().unwrap();
        let before = g.no_quota.len() + g.blocked.len();
        g.no_quota.retain(|(a, _), _| a != id);
        g.blocked.remove(id);
        let n = before - (g.no_quota.len() + g.blocked.len());
        if let Some(h) = g.health.get_mut(id) {
            h.streak = 0;
        }
        n
    }

    pub fn set_external(&self, on: bool) {
        self.inner.lock().unwrap().external = on;
    }

    /// 从取码池里取一个一次性验证码。
    ///
    /// ⚠ 2026-09-30 起**没有调用点**了：实测上游不再要求模型请求带验证码（见 `handle_external`
    /// 里那段说明）。保留在这里是为了万一上游改回去时能一键恢复，不是漏删。
    #[allow(dead_code)]
    fn take_param(&self) -> Result<(String, String), String> {
        let t0 = now_ms();
        {
            let mut g = self.inner.lock().unwrap();
            g.waiters += 1;

            g.last_use = t0;
        }
        let deadline = t0 + PARAM_WAIT_MS;
        loop {
            {
                let mut g = self.inner.lock().unwrap();
                let now = now_ms();
                let cut = now.saturating_sub(PARAM_MAX_AGE_MS);
                g.params.retain(|p| p.2 >= cut);
                if !g.params.is_empty() {
                    let (param, region, _) = g.params.remove(0);
                    g.last_use = now;
                    g.waiters = g.waiters.saturating_sub(1);
                    return Ok((param, region));
                }
            }
            if now_ms() >= deadline {
                let mut g = self.inner.lock().unwrap();
                g.waiters = g.waiters.saturating_sub(1);
                return Err(crate::i18n::tr("err.gw.no_param"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn put_param(&self, param: String, region: String) -> usize {
        let mut g = self.inner.lock().unwrap();
        let now = now_ms();
        g.params.push((param, region, now));
        g.mints += 1;
        g.mint_times.push(now);
        let cut = now.saturating_sub(10 * 60 * 1000);
        g.mint_times.retain(|t| *t >= cut);
        if !g.inflight.is_empty() {
            g.inflight.pop(); 
        }
        g.params.len()
    }

    fn want_mint(&self, wait: bool) -> Value {
        let deadline = now_ms() + if wait { PARAM_WAIT_MS } else { 0 };
        loop {
            {
                let mut g = self.inner.lock().unwrap();
                let now = now_ms();
                let cut = now.saturating_sub(PARAM_MAX_AGE_MS);
                g.params.retain(|p| p.2 >= cut);
                g.inflight.retain(|t| now.saturating_sub(*t) < INFLIGHT_TTL_MS);
                let n = g.params.len();
                let active = now.saturating_sub(g.last_use) < ACTIVE_WINDOW_MS;
                let want = g.waiters + if active { PARAM_PRE } else { 0 };

                let mut short = want as i64 - n as i64 - g.inflight.len() as i64;
                if n >= PARAM_MAX_POOL {
                    short = 0; 
                }
                if short > 0 {
                    g.inflight.push(now);
                    return json!({ "want": true, "pool": n, "target": n + short as usize });
                }
                if now_ms() >= deadline {
                    return json!({ "want": false, "pool": n, "target": n });
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn start(&self, paths: Paths, port: u16) -> Result<(), String> {
        {
            let g = self.inner.lock().unwrap();
            if g.running {
                return Err(crate::i18n::tr("err.gw.already_running"));
            }
        }

        let server = tiny_http::Server::http(("0.0.0.0", port))
            .map_err(|e| crate::i18n::trf("err.gw.bind", &[("e", &e.to_string())]))?;
        let stop = Arc::new(AtomicBool::new(false));
        let serving = Arc::new(AtomicBool::new(true));
        let server = Arc::new(server);
        {
            let mut g = self.inner.lock().unwrap();
            g.running = true;
            g.port = port;
            g.stop = Some(stop.clone());
            g.server = Some(server.clone());
            g.serving = Some(serving.clone());
        }
        let gw = self.clone();
        let server2 = server.clone();
        let stop2 = stop.clone();
        let serving2 = serving.clone();
        std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match server2.recv_timeout(Duration::from_millis(300)) {
                    Ok(Some(req)) => {
                        let gw = gw.clone();
                        std::thread::spawn(move || {
                            if let Err(e) = handle(req, &gw) {
                                crate::flowlog::log("relay", "req-fail", &e);
                            }
                        });
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }

            serving2.store(false, Ordering::Relaxed);
        });
        let gw2 = self.clone();
        let p2 = paths;
        std::thread::spawn(move || loop {
            let _ = gw2.warm_quota(&p2, 2, |_| {});
            if !gw2.inner.lock().unwrap().running {
                break;
            }
            std::thread::sleep(Duration::from_millis(QUOTA_TTL_MS));
        });
        crate::flowlog::log("relay", "start", &format!("port={port} upstream={UPSTREAM}"));

        let me = self.clone();
        let stop = self.inner.lock().unwrap().stop.clone();
        let halted = move || stop.as_ref().map_or(false, |s| s.load(Ordering::Relaxed));
        std::thread::spawn(move || loop {
            for _ in 0..(PROBE_EVERY_MS / 500) {
                if halted() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            if halted() {
                return;
            }

            me.probe_tick(&Paths::detect());
        });
        Ok(())
    }

    pub fn stop(&self) {
        let (stop, server, serving, port) = {
            let mut g = self.inner.lock().unwrap();
            let s = g.stop.take();
            let srv = g.server.take();
            let sv = g.serving.take();
            g.running = false;
            (s, srv, sv, g.port)
        };
        let Some(s) = stop else { return };
        s.store(true, Ordering::Relaxed);

        if let Some(srv) = server {
            srv.unblock();
        }
        if let Some(sv) = serving {
            for _ in 0..40 {
                if !sv.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        crate::flowlog::log("relay", "stop", &format!("port={port}"));
    }

    pub fn refresh_quota(&self, paths: &Paths, force: bool) -> Result<usize, String> {
        let mut waited = 0u64;
        loop {
            {
                let mut g = self.inner.lock().unwrap();
                if !g.refreshing {
                    g.refreshing = true;
                    break;
                }
            }
            if waited >= 120_000 {
                return Err(crate::i18n::tr("err.gw.busy_refresh"));
            }
            std::thread::sleep(Duration::from_millis(300));
            waited += 300;
        }

        let accounts: Vec<(String, String)> = store::list_accounts(paths)
            .map(|v| v.into_iter().map(|a| (a.id, a.name)).collect())
            .unwrap_or_default();
        let live_ids: std::collections::HashSet<&str> =
            accounts.iter().map(|(id, _)| id.as_str()).collect();
        {
            let mut g = self.inner.lock().unwrap();
            g.quota.retain(|id, _| live_ids.contains(id.as_str()));
        }
        let total = accounts.len();
        let mut n = 0usize;
        let mut failed: Vec<String> = Vec::new();

        for (i, (id, name)) in accounts.iter().enumerate() {
            if !force {
                let g = self.inner.lock().unwrap();
                if let Some((at, _)) = g.quota.get(id) {
                    if now_ms().saturating_sub(*at) < QUOTA_TTL_MS {
                        continue;
                    }
                }
            }
            let mut got = None;
            let mut last = String::new();
            for attempt in 0..4u64 {
                match store::account_quota(paths, id) {
                    Ok(ov) => {
                        got = Some(ov);
                        break;
                    }
                    Err(e) => {
                        last = e;
                        std::thread::sleep(Duration::from_millis(600 + attempt * 700));
                    }
                }
            }
            match got {
                Some(ov) => {
                    self.inner.lock().unwrap().quota.insert(id.clone(), (now_ms(), ov));
                    n += 1;
                }
                None => {
                    let short: String = last.chars().take(140).collect();
                    crate::flowlog::log("relay", "quota-fail", &format!("{name}: {short}"));
                    failed.push(name.clone());
                }
            }
            if i + 1 < total {
                std::thread::sleep(Duration::from_millis(150));
            }
        }

        let snap = {
            let mut g = self.inner.lock().unwrap();
            g.refreshing = false;
            g.last_refresh = Some(store::now_ts());
            g.quota_total = total;
            g.last_failed = failed;
            quota_snapshot(&g)
        };

        write_quota_cache(paths, snap);
        Ok(n)
    }

    fn candidates(&self, paths: &Paths, model: &str) -> Vec<Candidate> {
        let accounts = store::list_accounts(paths).unwrap_or_default();
        let need_warm = !accounts.is_empty() && self.inner.lock().unwrap().quota.is_empty();
        if need_warm {
            let _ = self.refresh_quota(paths, false);
        }
        let secret = crate::zcrypto::default_secret(&paths.home);
        let (policy, pinned) = {
            let g = self.inner.lock().unwrap();
            (g.policy.clone(), g.pinned.clone())
        };
        let mut list: Vec<Candidate> = vec![];
        let model_k = model_key(model);
        for acc in &accounts {
            if policy == POLICY_PINNED && pinned.as_deref() != Some(acc.id.as_str()) {
                continue;
            }

            {
                let g = self.inner.lock().unwrap();
                if let Some(t) = g.no_quota.get(&(acc.id.clone(), model_k.clone())) {
                    if now_ms().saturating_sub(*t) < NO_QUOTA_TTL_MS {
                        continue;
                    }
                }
            }

            {
                let g = self.inner.lock().unwrap();
                if let Some(t) = g.blocked.get(&acc.id) {
                    if *t > now_ms() {
                        continue;
                    }
                }
            }
            let (expire, left) = {
                let g = self.inner.lock().unwrap();
                let Some((_, ov)) = g.quota.get(&acc.id) else { continue };
                let mut best: Option<(Option<String>, f64)> = None;
                let check_items = |items: &[crate::quota::QuotaItem], exp: &Option<String>, best: &mut Option<(Option<String>, f64)>| {
                    let mut here = 0.0f64;
                    let mut hit = false;
                    for it in items {
                        if model_same(&it.name, model) {
                            let r = it.remaining.unwrap_or(0.0);
                            if r > 0.0 {
                                hit = true;
                                here += r;
                            }
                        }
                    }
                    if !hit {
                        return;
                    }
                    *best = match best.take() {
                        None => Some((exp.clone(), here)),
                        Some((be, bl)) => {
                            let sooner = matches!((exp, &be), (Some(x), Some(b)) if x < b)
                                || (exp.is_some() && be.is_none());
                            if sooner {
                                Some((exp.clone(), here))
                            } else {
                                Some((be, bl + here))
                            }
                        }
                    };
                };
                if !ov.plans.is_empty() {
                    for p in &ov.plans {
                        check_items(&p.items, &p.expire, &mut best);
                    }
                } else {
                    check_items(&ov.items, &ov.plan_expire, &mut best);
                }
                match best {
                    Some(b) => b,
                    None => continue,
                }
            };
            let Ok(full) = store::load_account(paths, &acc.id) else { continue };
            let Some(jwt) = crate::quota::candidate_tokens(&full.credentials, full.config.as_ref(), &secret)
                .into_iter()
                .next()
            else {
                continue;
            };
            list.push(Candidate {
                id: acc.id.clone(),
                name: acc.name.clone(),
                token: jwt,
                mid: full.virtual_device_mid.unwrap_or_default(),
                expire,
                left,
            });
        }
        match policy.as_str() {
            POLICY_MOST_LEFT => list.sort_by(|a, b| {
                b.left.partial_cmp(&a.left).unwrap_or(std::cmp::Ordering::Equal).then(a.name.cmp(&b.name))
            }),
            _ => list.sort_by(|a, b| a.expire.cmp(&b.expire).then(a.name.cmp(&b.name))),
        }
        list
    }

    fn sticky_order(&self, mut list: Vec<Candidate>) -> Vec<Candidate> {
        if list.is_empty() {
            return list;
        }
        let mut g = self.inner.lock().unwrap();
        if g.policy == POLICY_PINNED {
            return list;
        }
        let cur = g.sticky.clone();
        if let Some(id) = cur {
            if let Some(i) = list.iter().position(|c| c.id == id) {
                list.rotate_left(i);
                return list;
            }
        }
        g.sticky = list.first().map(|c| c.id.clone());
        list
    }

    fn set_sticky(&self, id: &str) {
        let mut g = self.inner.lock().unwrap();
        if g.policy != POLICY_PINNED {
            g.sticky = Some(id.to_string());
        }
    }

}

fn live_account_id(paths: &Paths) -> Option<String> {
    let st = store::get_state(paths).ok()?;
    if !st.live_logged_in {
        return None;
    }
    st.active_account_id
}

fn quota_rows_for(g: &Inner, id: Option<&str>) -> Value {
    let Some(id) = id else { return Value::Null };
    let Some((_, ov)) = g.quota.get(id) else { return Value::Null };
    let mut rows: Vec<Value> = vec![];
    for p in &ov.plans {
        for it in &p.items {
            if it.total.is_none() && it.remaining.is_none() {
                continue;
            }
            rows.push(json!({
                "name": it.name,
                "left": it.remaining,
                "total": it.total,
                "reset": it.reset.clone().or_else(|| it.period_end.clone()),
                "expire": p.expire,
                "plan": p.name,
            }));
        }
    }
    json!({ "account": id, "rows": rows })
}

fn models_seen(quota: &HashMap<String, (u64, crate::quota::QuotaOverview)>) -> Vec<String> {
    let mut set: Vec<String> = vec![];
    for (_, ov) in quota.values() {
        for p in &ov.plans {
            for it in &p.items {
                let n = it.name.trim().to_string();
                if !n.is_empty() && !set.iter().any(|x| model_eq(x, &n)) {
                    set.push(n);
                }
            }
        }
    }
    set.sort();
    set
}

fn peek_model(head: &[u8]) -> Option<String> {
    let head = String::from_utf8_lossy(head);
    let mut from = 0usize;
    while let Some(rel) = head[from..].find("\"model\"") {
        let i = from + rel + "\"model\"".len();
        let rest = &head[i..];
        let mut it = rest.chars().skip_while(|c| c.is_whitespace());
        if it.next() != Some(':') {
            from = i;
            continue;
        }
        let rest: String = it.collect();
        let rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix('"') {
            if let Some(end) = r.find('"') {
                let m = r[..end].trim().to_string();
                if !m.is_empty() {
                    return Some(m);
                }
            }
        }
        from = i;
    }
    None
}

fn peek_code(head: &[u8]) -> String {
    let s = String::from_utf8_lossy(head);
    let mut from = 0usize;
    while let Some(rel) = s[from..].find("\"code\"") {
        let i = from + rel + "\"code\"".len();
        let rest = &s[i..];
        let mut it = rest.chars().skip_while(|c| c.is_whitespace());
        if it.next() != Some(':') {
            from = i;
            continue;
        }
        let rest: String = it.collect();
        let rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix('"') {
            if let Some(end) = r.find('"') {
                let c = r[..end].trim().to_string();
                if !c.is_empty() {
                    return c;
                }
            }
        } else {
            let c: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !c.is_empty() {
                return c;
            }
        }
        from = i;
    }
    String::new()
}

fn model_key(s: &str) -> String {
    let flat: String = s
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | ' '))
        .collect();
    match flat.strip_prefix("glm") {
        Some(rest) => rest.to_string(),
        None => flat,
    }
}

fn model_same(a: &str, b: &str) -> bool {
    let (x, y) = (model_key(a), model_key(b));
    !x.is_empty() && x == y
}

/// 剥离 `zai/` / `bigmodel/` 命名空间前缀，并对齐官方大小写与退役模型名（参考 dengyie/zcode2api）。
fn normalize_request_model(raw: &str) -> String {
    let mut m = raw.trim();
    if let Some((pref, rest)) = m.split_once('/') {
        if matches!(pref.trim().to_ascii_lowercase().as_str(), "zai" | "bigmodel") && !rest.trim().is_empty() {
            m = rest.trim();
        }
    }
    match m.to_ascii_lowercase().as_str() {
        "glm-5.4" => "GLM-5.4".to_string(),
        "glm-5.3-flash" | "glm-4.7-flash" | "glm-4.7-flashx" => "GLM-5.3-Flash".to_string(),
        "glm-5.3" => "GLM-5.3".to_string(),
        "glm-5.2" | "glm-5-turbo" | "glm-turbo" | "glm-5.1" | "glm-4.7" | "glm-5" => "GLM-5.4".to_string(),
        _ => m.to_string(),
    }
}

fn fallback_models_for(requested: &str) -> Vec<&'static str> {
    let low = requested.trim().to_ascii_lowercase();
    if low == "glm-5.3-flash" || low.contains("haiku") || low.contains("flash") || low.contains("mini") {
        vec!["GLM-5.3-Flash", "GLM-5.4", "GLM-5.3"]
    } else if low == "glm-5.3" {
        vec!["GLM-5.3", "GLM-5.4", "GLM-5.3-Flash"]
    } else {
        vec!["GLM-5.4", "GLM-5.3", "GLM-5.3-Flash"]
    }
}

fn is_date_turn_text(s: &str) -> bool {
    s.contains("<system-reminder>") && s.contains("Today's date is")
}

fn extract_first_user_text(messages: &[Value]) -> String {
    for msg in messages {
        if msg.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        if let Some(s) = msg.get("content").and_then(Value::as_str) {
            if !is_date_turn_text(s) && !s.trim().is_empty() {
                return s.trim().to_string();
            }
        } else if let Some(arr) = msg.get("content").and_then(Value::as_array) {
            for block in arr {
                if block.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(t) = block.get("text").and_then(Value::as_str) {
                        if !is_date_turn_text(t) && !t.trim().is_empty() {
                            return t.trim().to_string();
                        }
                    }
                }
            }
        }
    }
    String::new()
}

fn message_reads_as_query(msg: &Value) -> bool {
    let Some(content) = msg.get("content") else { return false };
    if let Some(s) = content.as_str() {
        return !s.trim().is_empty() && !is_date_turn_text(s);
    }
    let Some(arr) = content.as_array() else { return false };
    for block in arr {
        let Some(obj) = block.as_object() else { continue };
        let btype = obj.get("type").and_then(Value::as_str).unwrap_or("");
        if btype == "tool_result" {
            continue;
        }
        if btype == "text" {
            if let Some(t) = obj.get("text").and_then(Value::as_str) {
                if !t.trim().is_empty() && !is_date_turn_text(t) {
                    return true;
                }
            }
            continue;
        }
        return true;
    }
    false
}

fn conversation_session_id(messages: &[Value], account_id: &str) -> String {
    let first = extract_first_user_text(messages);
    if first.is_empty() {
        return account_session(account_id, &day_seed());
    }
    let digest: String = Sha256::digest(first.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .chars()
        .take(32)
        .collect();
    let name = format!("zcode-hub:{account_id}:{digest}");
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, name.as_bytes()).to_string()
}

fn conversation_query_id(messages: &[Value], session_id: &str) -> Option<String> {
    let turns = messages
        .iter()
        .filter(|m| m.get("role").and_then(Value::as_str) == Some("user") && message_reads_as_query(m))
        .count();
    if turns == 0 {
        return None;
    }
    let seed = format!("zcode-query\0{session_id}\0{turns}");
    Some(uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, seed.as_bytes()).to_string())
}

fn apply_tool_search_alias(obj: &mut serde_json::Map<String, Value>) -> bool {
    const TOOL_SEARCH: &str = "ToolSearch";
    const TOOL_SEARCH_ALIAS: &str = "ToolSearchTool";
    const TOOL_PLACEHOLDER: &str = "DeferredToolPlaceholder";

    let mut aliased = false;
    if let Some(tools) = obj.get_mut("tools").and_then(Value::as_array_mut) {
        let alias_taken = tools
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some(TOOL_SEARCH_ALIAS));
        let old_tools = std::mem::take(tools);
        for mut tool in old_tools {
            if let Some(tobj) = tool.as_object_mut() {
                if tobj.get("name").and_then(Value::as_str) == Some(TOOL_PLACEHOLDER) {
                    continue;
                }
                tobj.remove("defer_loading");
                if !alias_taken && tobj.get("name").and_then(Value::as_str) == Some(TOOL_SEARCH) {
                    tobj.insert("name".into(), Value::String(TOOL_SEARCH_ALIAS.to_string()));
                    aliased = true;
                }
            }
            tools.push(tool);
        }
    }
    if let Some(messages) = obj.get_mut("messages").and_then(Value::as_array_mut) {
        for msg in messages.iter_mut() {
            if msg.get("role").and_then(Value::as_str) != Some("assistant") {
                continue;
            }
            if let Some(arr) = msg.get_mut("content").and_then(Value::as_array_mut) {
                for block in arr.iter_mut() {
                    if let Some(bobj) = block.as_object_mut() {
                        if bobj.get("type").and_then(Value::as_str) == Some("tool_use")
                            && bobj.get("name").and_then(Value::as_str) == Some(TOOL_SEARCH)
                        {
                            bobj.insert("name".into(), Value::String(TOOL_SEARCH_ALIAS.to_string()));
                            aliased = true;
                        }
                    }
                }
            }
        }
    }
    aliased
}

fn apply_cache_control_and_normalize_messages(obj: &mut serde_json::Map<String, Value>) {
    if let Some(tools) = obj.get_mut("tools").and_then(Value::as_array_mut) {
        for t in tools.iter_mut() {
            if let Some(tobj) = t.as_object_mut() {
                tobj.remove("cache_control");
            }
        }
    }
    let Some(messages) = obj.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    let mut last_idx: Option<usize> = None;
    for (idx, msg) in messages.iter_mut().enumerate() {
        let Some(mobj) = msg.as_object_mut() else { continue };
        if mobj.get("role").and_then(Value::as_str) == Some("system") {
            continue;
        }
        last_idx = Some(idx);
        if let Some(s) = mobj.get("content").and_then(Value::as_str).map(str::to_string) {
            if !s.is_empty() {
                mobj.insert("content".into(), json!([{ "type": "text", "text": s }]));
            }
        }
        if let Some(arr) = mobj.get_mut("content").and_then(Value::as_array_mut) {
            for b in arr.iter_mut() {
                if let Some(bobj) = b.as_object_mut() {
                    bobj.remove("cache_control");
                }
            }
        }
    }
    if let Some(i) = last_idx {
        if let Some(arr) = messages[i].get_mut("content").and_then(Value::as_array_mut) {
            if let Some(last_block) = arr.last_mut().and_then(Value::as_object_mut) {
                last_block.insert("cache_control".into(), json!({ "type": "ephemeral" }));
            }
        }
    }
}

fn apply_current_date_turn(obj: &mut serde_json::Map<String, Value>) {
    let Some(messages) = obj.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    if messages.is_empty() {
        return;
    }
    let already = messages.first().is_some_and(|first| {
        first.get("role").and_then(Value::as_str) == Some("user")
            && first
                .get("content")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|b| b.get("text"))
                .and_then(Value::as_str)
                .is_some_and(is_date_turn_text)
    });
    if already {
        return;
    }
    messages.insert(
        0,
        json!({
            "role": "user",
            "content": [{ "type": "text", "text": crate::prompt::current_date_reminder_text() }]
        }),
    );
}

fn parse_business_code(text: &str) -> Option<i64> {
    let v: Value = serde_json::from_str(text).ok()?;
    let code_v = v.get("code")?;
    if let Some(n) = code_v.as_i64() {
        return (n != 0 && n != 200).then_some(n);
    }
    if let Some(s) = code_v.as_str() {
        if let Ok(n) = s.trim().parse::<i64>() {
            return (n != 0 && n != 200).then_some(n);
        }
    }
    None
}

fn is_captcha_challenge(has_header: bool, status: u16, biz_code: Option<i64>, text: &str) -> bool {
    if has_header || biz_code == Some(3007) {
        return true;
    }
    if status == 400 || status == 403 {
        let low = text.to_ascii_lowercase();
        return low.contains("captcha") || low.contains("verify token") || low.contains("verify failed");
    }
    false
}

fn is_edge_block(status: u16, biz_code: Option<i64>, text: &str) -> bool {
    if status != 405 || biz_code == Some(3012) {
        return false;
    }
    let low = text.to_ascii_lowercase();
    if low.contains("unusual activity") || low.contains("\"code\":3012") || low.contains("\"code\": 3012") {
        return false;
    }
    low.contains("address was blocked")
        || low.contains("network's address")
        || low.contains("blocked by the edge")
        || low.contains("<html")
        || low.contains("errors.aliyun.com")
}

fn is_risk_control(status: u16, biz_code: Option<i64>, text: &str) -> bool {
    if status == 405 || biz_code == Some(3012) {
        return true;
    }
    let low = text.to_ascii_lowercase();
    low.contains("unusual activity") || low.contains("\"code\":3012") || low.contains("\"code\": 3012")
}

fn is_exhausted(status: u16, biz_code: Option<i64>, text: &str) -> bool {
    if status == 429 || status >= 500 {
        return false;
    }
    if status == 402 || matches!(biz_code, Some(1005 | 1113 | 1310)) {
        return true;
    }
    let low = text.to_ascii_lowercase();
    [
        "exceed quota",
        "quota limit",
        "quota exceeded",
        "quota exhausted",
        "insufficient balance",
        "insufficient quota",
        "no balance",
        "额度已用完",
        "额度用完",
        "额度不足",
        "余额不足",
        "余额已用完",
        "无余额",
        "使用上限",
    ]
    .iter()
    .any(|k| low.contains(k))
}

fn is_concurrency_429(biz_code: Option<i64>, text: &str) -> bool {
    matches!(biz_code, Some(3008 | 3009 | 3010)) || text.to_ascii_lowercase().contains("concurrency limit")
}

fn replace_bytes(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0usize;
    while i < hay.len() {
        if i + from.len() <= hay.len() && &hay[i..i + from.len()] == from {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

fn trailing_partial_len(buf: &[u8], pat: &[u8]) -> usize {
    let max_k = pat.len().saturating_sub(1).min(buf.len());
    for k in (1..=max_k).rev() {
        if buf.ends_with(&pat[..k]) {
            return k;
        }
    }
    0
}

struct AliasReverseReader {
    inner: Box<dyn std::io::Read + Send>,
    pending: Vec<u8>,
    ready: Vec<u8>,
    ready_off: usize,
    eof: bool,
}

impl AliasReverseReader {
    fn new(inner: Box<dyn std::io::Read + Send>) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            ready: Vec::new(),
            ready_off: 0,
            eof: false,
        }
    }
}

impl std::io::Read for AliasReverseReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        const FROM: &[u8] = b"ToolSearchTool";
        const TO: &[u8] = b"ToolSearch";
        if out.is_empty() {
            return Ok(0);
        }
        while self.ready_off >= self.ready.len() {
            self.ready.clear();
            self.ready_off = 0;
            if self.pending.is_empty() && self.eof {
                return Ok(0);
            }
            if !self.eof {
                let mut tmp = [0u8; 4096];
                match self.inner.read(&mut tmp)? {
                    0 => self.eof = true,
                    n => self.pending.extend_from_slice(&tmp[..n]),
                }
            }
            let replaced = replace_bytes(&self.pending, FROM, TO);
            let hold = if self.eof { 0 } else { trailing_partial_len(&replaced, FROM) };
            let emit_len = replaced.len().saturating_sub(hold);
            if emit_len > 0 {
                self.ready.extend_from_slice(&replaced[..emit_len]);
                self.pending = replaced[emit_len..].to_vec();
            } else {
                self.pending = replaced;
                if self.eof {
                    return Ok(0);
                }
            }
        }
        let n = (self.ready.len() - self.ready_off).min(out.len());
        out[..n].copy_from_slice(&self.ready[self.ready_off..self.ready_off + n]);
        self.ready_off += n;
        Ok(n)
    }
}

fn account_session(id: &str, seed: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"zpool-sid|");
    h.update(id.as_bytes());
    h.update(b"|");
    h.update(seed.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b).to_string()
}

fn day_seed() -> String {
    (now_ms() / 86_400_000).to_string()
}

fn model_eq(a: &str, b: &str) -> bool {
    let n = |s: &str| s.trim().to_ascii_lowercase().replace(['-', '_', ' '], "");
    let (x, y) = (n(a), n(b));
    !x.is_empty() && !y.is_empty() && (x == y || x.contains(&y) || y.contains(&x))
}

fn body_model(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("model").and_then(|m| m.as_str()).map(|s| s.to_string())
}

struct Meter<R> {
    inner: std::sync::Arc<Mutex<Inner>>,
    src: R,
    tail: Vec<u8>,

    head: Vec<u8>,
    tokens: u64,
    tokens_in: u64,

    cache: u64,

    bytes: u64,

    started: u64,

    first_at: Option<u64>,

    rec: Option<crate::usage::UsageRecord>,
    path: std::path::PathBuf,
}

impl<R: Read> Read for Meter<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.src.read(out)?;
        let now = now_ms();
        if n == 0 {

            if let Some(t) = scan_u64_key(&self.tail, b"input_tokens") {
                self.tokens_in = self.tokens_in.max(t);
            }
            if let Some(t) = scan_u64_after(&self.tail, b"output_tokens") {
                self.tokens = self.tokens.max(t);
            }
            if let Some(t) = scan_u64_key(&self.tail, b"cache_read_input_tokens") {
                self.cache = self.cache.max(t);
            }
            let ms = now.saturating_sub(self.started);
            let ttfb = self.first_at.map(|f| f.saturating_sub(self.started));
            let mut code = peek_code(&self.head);
            if code.is_empty() {
                code = peek_code(&self.tail);
            }
            if let Some(mut rec) = self.rec.take() {
                rec.tokens_in = self.tokens_in;
                rec.tokens_out = self.tokens;
                rec.cache = self.cache;
                rec.ttfb = ttfb;
                rec.ms = ms;
                rec.bytes = self.bytes;
                rec.code = code;
                crate::usage::append(&self.path, &rec);
            }
            let mut g = self.inner.lock().unwrap();
            g.last_total_ms = Some(ms);

            g.tokens_sum = g.tokens_sum.saturating_add(self.tokens);
            let gen_ms = ms.saturating_sub(ttfb.unwrap_or(0));
            if self.tokens > 0 && gen_ms > 0 {
                g.last_gen_tps = Some(self.tokens as f64 * 1000.0 / gen_ms as f64);
            }
            return Ok(0);
        }

        if self.first_at.is_none() {
            self.first_at = Some(now);
            let mut g = self.inner.lock().unwrap();
            g.last_ttfb_ms = Some(now.saturating_sub(self.started));
            g.last_total_ms = None;
        }
        self.bytes += n as u64;
        if self.head.len() < 2048 {
            let room = 2048 - self.head.len();
            self.head.extend_from_slice(&out[..n.min(room)]);
        }

        self.tail.extend_from_slice(&out[..n]);
        if self.tail.len() > 8192 {
            let cut = self.tail.len() - 8192;
            self.tail.drain(..cut);
        }
        if let Some(t) = scan_u64_after(&self.tail, b"output_tokens") {
            self.tokens = self.tokens.max(t);
        }
        if let Some(t) = scan_u64_key(&self.tail, b"input_tokens") {
            self.tokens_in = self.tokens_in.max(t);
        }
        if let Some(t) = scan_u64_key(&self.tail, b"cache_read_input_tokens") {
            self.cache = self.cache.max(t);
        }
        let now = now_ms();
        let mut g = self.inner.lock().unwrap();
        g.bytes_out += n as u64;

        let (bytes, tokens) = (g.bytes_out, g.tokens_sum);
        g.meter.push((now, bytes, tokens));
        Ok(n)
    }
}

fn port_answers(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

fn lan_host() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "<本机IP>".into())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn scan_u64_after(hay: &[u8], needle: &[u8]) -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut i = 0usize;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            while j < hay.len() && !hay[j].is_ascii_digit() && j < i + needle.len() + 16 {
                j += 1;
            }
            let mut v: u64 = 0;
            let mut any = false;
            while j < hay.len() && hay[j].is_ascii_digit() {
                v = v.saturating_mul(10).saturating_add((hay[j] - b'0') as u64);
                any = true;
                j += 1;
            }
            if any {
                best = Some(best.map_or(v, |b: u64| b.max(v)));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    best
}

fn scan_u64_key(hay: &[u8], needle: &[u8]) -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut i = 0usize;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            let bounded = i == 0 || !(hay[i - 1].is_ascii_alphanumeric() || hay[i - 1] == b'_');
            if bounded {
                let mut j = i + needle.len();
                let lim = (i + needle.len() + 16).min(hay.len());
                while j < lim && !hay[j].is_ascii_digit() {
                    j += 1;
                }
                let mut v: u64 = 0;
                let mut any = false;
                while j < hay.len() && hay[j].is_ascii_digit() {
                    v = v.saturating_mul(10).saturating_add((hay[j] - b'0') as u64);
                    any = true;
                    j += 1;
                }
                if any {
                    best = Some(best.map_or(v, |b: u64| b.max(v)));
                }
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    best
}

fn meter_delta(g: &Inner) -> (f64, u64, u64) {
    let (Some(first), Some(last)) = (g.meter.first(), g.meter.last()) else {
        return (0.0, 0, 0);
    };
    if last.0 <= first.0 {
        return (0.0, 0, 0);
    }
    (
        (last.0 - first.0) as f64 / 1000.0,
        last.1.saturating_sub(first.1),
        last.2.saturating_sub(first.2),
    )
}

#[derive(Clone, Default)]
struct Health {
    ok: u64,
    fail: u64,

    streak: u32,
    last_ms: Option<u64>,
    last_at: Option<u64>,
    last_err: String,

    history: Vec<(u64, Option<u64>)>,
}

impl Health {
    fn json(&self) -> Value {
        let ok_recent = self.history.iter().filter(|(_, m)| m.is_some()).count();
        json!({
            "ok": self.ok,
            "fail": self.fail,
            "streak": self.streak,
            "lastMs": self.last_ms,
            "lastAt": self.last_at,
            "lastErr": self.last_err,
            "rate": if self.history.is_empty() { Value::Null }
                    else { json!((ok_recent as f64 / self.history.len() as f64 * 100.0).round()) },
            "history": self.history.iter().map(|(t, m)| json!({ "at": t, "ms": m })).collect::<Vec<_>>(),
        })
    }
}

fn auth_token(req: &tiny_http::Request) -> String {
    for h in req.headers() {
        match h.field.as_str().as_str().to_ascii_lowercase().as_str() {
            "x-api-key" => return h.value.as_str().to_string(),
            "authorization" => {
                let v = h.value.as_str();
                return v.strip_prefix("Bearer ").unwrap_or(v).trim().to_string();
            }
            _ => {}
        }
    }
    String::new()
}

fn mint_stats(g: &Inner) -> Value {
    let now = now_ms();
    let recent = g.mint_times.iter().filter(|t| now.saturating_sub(**t) < 600_000).count();
    json!({
        "pool": g.params.len(),
        "waiters": g.waiters,
        "active": now.saturating_sub(g.last_use) < ACTIVE_WINDOW_MS,
        "mints": g.mints,
        "mints10min": recent,
    })
}

fn norm_path(url: &str) -> String {
    let p = url.split('?').next().unwrap_or(url);
    let mut s = p.to_string();
    while let Some(rest) = s.strip_prefix("/v1/v1") {
        s = rest.to_string();
    }
    if s.starts_with("/messages") || s.starts_with("/count_tokens") {
        s = format!("/v1{s}");
    }
    s
}

fn web_dirs() -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(d) = std::env::var("ZPOOL_WEB_DIR") {
        if !d.trim().is_empty() {
            v.push(std::path::PathBuf::from(d));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("web"));
        }
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    if src.is_dir() {
        v.push(src);
    }
    v
}

fn page(name: &str, embedded: &str) -> String {
    for dir in web_dirs() {
        let p = dir.join(name);
        if let Ok(s) = std::fs::read_to_string(&p) {
            crate::flowlog::log("relay", "page-disk", &p.display().to_string());
            return s;
        }
    }
    embedded.to_string()
}

fn reply_html(req: tiny_http::Request, body: String) -> Result<(), String> {
    let mk = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
    let _ = req.respond(tiny_http::Response::new(
        tiny_http::StatusCode(200),
        vec![
            mk("Content-Type", "text/html; charset=utf-8"),
            mk("Cache-Control", "no-store, must-revalidate"),
        ],
        std::io::Cursor::new(body.into_bytes()),
        None,
        None,
    ));
    Ok(())
}

fn reply_json(req: tiny_http::Request, code: u16, v: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    let h = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let _ = req.respond(tiny_http::Response::new(
        tiny_http::StatusCode(code),
        vec![h],
        std::io::Cursor::new(body),
        None,
        None,
    ));
    Ok(())
}

fn reply_text(req: tiny_http::Request, body: String, filename: &str) -> Result<(), String> {
    let mk = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
    let _ = req.respond(tiny_http::Response::new(
        tiny_http::StatusCode(200),
        vec![
            mk("Content-Type", "text/plain; charset=utf-8"),
            mk("Content-Disposition", &format!("attachment; filename=\"{filename}\"")),
            mk("Cache-Control", "no-store"),
        ],
        std::io::Cursor::new(body.into_bytes()),
        None,
        None,
    ));
    Ok(())
}

const SECRET_KEYS: [&str; 12] = [
    "password",
    "refresh_token",
    "refreshtoken",
    "access_token",
    "accesstoken",
    "id_token",
    "jwt",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "token",
];

fn is_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|m| k == *m || k.ends_with(&format!("_{m}")))
}

fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n == 0 {
        return String::new();
    }
    if n <= 4 {
        return "***".to_string();
    }
    let head: String = s.chars().take(4).collect();
    format!("{head}***")
}

fn mask_json(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if is_secret_key(k) {
                    if let Some(s) = val.as_str() {
                        *val = json!(mask_secret(s));
                    }
                } else {
                    mask_json(val);
                }
            }
        }
        Value::Array(arr) => {
            for x in arr.iter_mut() {
                mask_json(x);
            }
        }
        _ => {}
    }
}

fn reply_json_masked(req: tiny_http::Request, code: u16, v: &Value, from_loopback: bool) -> Result<(), String> {
    if from_loopback {
        return reply_json(req, code, v);
    }
    let mut c = v.clone();
    mask_json(&mut c);
    reply_json(req, code, &c)
}

fn system_blocks(paths: &Paths) -> Result<Vec<Value>, String> {
    static B: std::sync::OnceLock<Vec<Value>> = std::sync::OnceLock::new();
    if let Some(v) = B.get() {
        return Ok(v.clone());
    }
    let v = crate::prompt::system_blocks(paths)?;
    let _ = B.set(v.clone());
    Ok(v)
}

struct PreparedBody {
    bytes: Vec<u8>,
    session_id: String,
    query_id: Option<String>,
    effective_mid: String,
    aliased: bool,
}

fn external_body(
    raw: &[u8],
    account_id: &str,
    mid: &str,
    model: &str,
    paths: &Paths,
) -> Result<PreparedBody, (u16, String)> {
    let mut v: Value = serde_json::from_slice(raw)
        .map_err(|e| (400, format!("请求体必须是 UTF-8 编码的 JSON：{e}")))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| (400, "请求体必须是 JSON 对象".to_string()))?;
    obj.insert("model".into(), json!(model));

    let clamped_max = match obj.get("max_tokens").and_then(|x| x.as_u64()) {
        Some(n) => n.clamp(1, MAX_TOKENS_LIMIT),
        None => 8192,
    };
    obj.insert("max_tokens".into(), json!(clamped_max));

    let orig_msgs = obj
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let session_id = conversation_session_id(&orig_msgs, account_id);
    let query_id = conversation_query_id(&orig_msgs, &session_id);

    let has_skill = obj
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(|t| t.get("name").and_then(Value::as_str) == Some("Skill")));

    let caller = obj.get("system").cloned();
    let platform = crate::quota::client_platform();
    let osver = crate::quota::os_version().unwrap_or_else(|| "10.0.26200".into());
    let blocks = match crate::prompt::build_start_plan_system(
        caller.as_ref(),
        Some(model),
        has_skill,
        &platform,
        &osver,
    ) {
        Ok(b) => b,
        Err(_) => system_blocks(paths).map_err(|e| (503, e))?,
    };
    obj.insert("system".into(), Value::Array(blocks));

    let aliased = apply_tool_search_alias(obj);
    apply_cache_control_and_normalize_messages(obj);
    apply_current_date_turn(obj);

    let effective_mid = if mid.trim().is_empty() {
        account_session(account_id, "device-mid")
    } else {
        mid.trim().to_string()
    };
    let uid = json!({
        "device_id": effective_mid,
        "account_uuid": "",
        "session_id": session_id,
    })
    .to_string();
    let mut meta = obj
        .get("metadata")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    meta.insert("user_id".into(), Value::String(uid));
    obj.insert("metadata".into(), Value::Object(meta));

    let bytes = serde_json::to_vec(&v).map_err(|e| (500, e.to_string()))?;
    Ok(PreparedBody {
        bytes,
        session_id,
        query_id,
        effective_mid,
        aliased,
    })
}

fn handle_external(
    req: tiny_http::Request,
    gw: &Gateway,
    paths: &Paths,
    path: &str,
    body: &[u8],
    key_tag: &str,
) -> Result<(), String> {
    let mut slot = Some(req);
    if !gw.inner.lock().unwrap().external {
        return reply_json(
            slot.take().unwrap(),
            403,
            &json!({ "type": "error",
                     "error": { "type": "permission_error",
                                "message": "对外接口没开 —— 到工具的「反代」页打开它" } }),
        );
    }
    let raw_model = body_model(body).unwrap_or_else(|| EXTERNAL_MODELS[0].to_string());
    let client_model = raw_model.clone();
    let mut model = normalize_request_model(&raw_model);

    let (mmode, mpin) = {
        let g = gw.inner.lock().unwrap();
        (g.model_mode.clone(), g.model_pinned.clone())
    };

    if mmode == MODEL_PINNED {
        if let Some(p) = mpin.clone().filter(|x| !x.trim().is_empty()) {
            let norm_p = normalize_request_model(&p);
            if norm_p != model {
                crate::flowlog::log("relay", "model-pinned", &format!("请求={model} 指定={norm_p}"));
            }
            model = norm_p;
        }
    }

    let mapped = {
        let g = gw.inner.lock().unwrap();
        g.model_map
            .get(&model)
            .or_else(|| g.model_map.get(&raw_model))
            .cloned()
    }
    .map(|s| normalize_request_model(&s));
    if let Some(to) = mapped.clone() {
        crate::flowlog::log("relay", "model-map", &format!("请求={model} 上游={to}"));
        model = to;
    }

    let usage_path = crate::usage::path_for(&paths.store_dir());

    let mk = |acct: &str, status: u16, code: &str, tries: usize, stream: bool, t: u64| {
        crate::usage::UsageRecord {
            t,
            acct: acct.to_string(),
            model: client_model.clone(),
            up: None,
            tokens_in: 0,
            tokens_out: 0,
            cache: 0,
            ttfb: None,
            ms: 0,
            bytes: 0,
            status,
            code: code.to_string(),
            tries,
            stream,
            mapped: mapped.clone(),
            key: key_tag.to_string(),
        }
    };
    let target = format!("{UPSTREAM}{path}");
    let proxy_url = gw.inner.lock().unwrap().relay_proxy.clone();
    let mut ab = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(600));
    if let Some(u) = proxy_url.as_deref() {
        match ureq::Proxy::new(u) {
            Ok(px) => ab = ab.proxy(px),
            Err(e) => crate::flowlog::log("relay", "proxy-bad", &format!("{u}：{e} —— 这一发按直连走")),
        }
    }
    let agent = ab.build();

    let mut cands = gw.sticky_order(gw.candidates(paths, &model));

    if cands.is_empty() && mmode == MODEL_AUTO {
        for alt in fallback_models_for(&model).into_iter().filter(|m| !m.eq_ignore_ascii_case(&model)) {
            let c2 = gw.sticky_order(gw.candidates(paths, alt));
            if !c2.is_empty() {
                crate::flowlog::log("relay", "model-fallback", &format!("{model} 无直接额度 → 使用 {alt}"));
                model = alt.to_string();
                cands = c2;
                break;
            }
        }
    }
    if cands.is_empty() {
        let at = now_ms();
        crate::usage::append(&usage_path, &mk("", 502, "no-account", 0, false, at));
        return reply_json(
            slot.take().unwrap(),
            502,
            &json!({ "type": "error",
                     "error": { "type": "overloaded_error",
                                "message": format!("号池里没有可用于 {model} 的号（请先刷新额度或检查可用账号）") } }),
        );
    }

    let mut tried = 0usize;
    let mut last_abnormal: Option<(u16, Option<String>, Vec<u8>, Box<dyn std::io::Read + Send>)> = None;
    let mut last_acct = String::new();
    let mut last_at = now_ms();
    let mut last_err_detail = String::new();
    let mut captcha_param: Option<(String, String)> = None;

    'cand_loop: for c in cands.iter().take(MAX_TRIES) {
        tried += 1;
        let prep = match external_body(body, &c.id, &c.mid, &model, paths) {
            Ok(b) => b,
            Err((code, e)) => {
                let ty = if code >= 500 { "api_error" } else { "invalid_request_error" };
                crate::usage::append(&usage_path, &mk(&c.name, code, "bad-body", tried, false, now_ms()));
                return reply_json(
                    slot.take().unwrap(),
                    code,
                    &json!({ "type": "error", "error": { "type": ty, "message": e } }),
                );
            }
        };

        let mut inner_retries = 0usize;
        let mut captcha_retried = false;
        loop {
            let mut call = agent.request("POST", &target);
            for (k, v) in client_headers() {
                call = call.set(k, &v);
            }
            call = call
                .set("authorization", &format!("Bearer {}", c.token))
                .set("X-Device-Mid", &prep.effective_mid)
                .set("x-request-id", &uuid::Uuid::new_v4().to_string())
                .set("x-session-id", &prep.session_id)
                .set("x-zcode-trace-id", &uuid::Uuid::new_v4().to_string());
            if let Some(ref qid) = prep.query_id {
                call = call.set("x-query-id", qid);
            }
            if let Some((ref param, ref region)) = captcha_param {
                call = call
                    .set(CAPTCHA_HEADER, param)
                    .set(CAPTCHA_REGION_HEADER, region);
            }

            let tried_at = now_ms();
            last_acct = c.name.clone();
            last_at = tried_at;
            let (status, has_captcha_hdr, reader, ctype) = match call.send_bytes(&prep.bytes) {
                Ok(r) => {
                    let ct = r.header("Content-Type").map(|s| s.to_string());
                    let ch = r.header(CAPTCHA_HEADER).is_some_and(|v| !v.trim().is_empty());
                    (r.status(), ch, r.into_reader(), ct)
                }
                Err(ureq::Error::Status(code, r)) => {
                    let ct = r.header("Content-Type").map(|s| s.to_string());
                    let ch = r.header(CAPTCHA_HEADER).is_some_and(|v| !v.trim().is_empty());
                    (code, ch, r.into_reader(), ct)
                }
                Err(e) => {
                    last_err_detail = format!("{}: 网络失败 {e}", c.name);
                    crate::flowlog::log("relay", "external-fail", &last_err_detail);
                    gw.mark_blocked(&c.id, SHORT_RATE_TTL_MS);
                    continue 'cand_loop;
                }
            };

            let ct_lower = ctype.as_deref().unwrap_or("").to_ascii_lowercase();
            let mut reader: Box<dyn std::io::Read + Send> = Box::new(reader);

            let check_json_or_err = status >= 400 || (status == 200 && !ct_lower.contains("event-stream"));
            if check_json_or_err {
                let mut err_buf = Vec::new();
                let _ = reader.by_ref().take(65_536).read_to_end(&mut err_buf);
                let err_txt = String::from_utf8_lossy(&err_buf).to_string();
                let biz_code = parse_business_code(&err_txt);
                let short_snip: String = err_txt.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(180).collect();

                if status == 200 && biz_code.is_none() && peek_model(&err_buf).is_some() {
                    reader = Box::new(std::io::Cursor::new(err_buf).chain(reader));
                } else if status >= 400 || biz_code.is_some() {
                    if is_captcha_challenge(has_captcha_hdr, status, biz_code, &err_txt) && !captcha_retried {
                        captcha_retried = true;
                        captcha_param = None;
                        if gw.has_mint_pool_or_waiter_consumer() {
                            if let Ok((p, reg)) = gw.take_param() {
                                crate::flowlog::log("relay", "captcha-retry", &format!("{} 触发人机校验，已取码重试", c.name));
                                captcha_param = Some((p, reg));
                                continue;
                            }
                        }
                        last_err_detail = format!("{} 需要人机校验（HTTP {status}）：{short_snip}", c.name);
                        crate::flowlog::log("relay", "captcha-skip", &last_err_detail);
                        continue 'cand_loop;
                    }

                    if is_edge_block(status, biz_code, &err_txt) {
                        crate::flowlog::log("relay", "edge-block", &format!("{} HTTP 405 边缘 IP 封禁：{short_snip}", c.name));
                        crate::usage::append(&usage_path, &mk(&c.name, 503, "edge-405", tried, false, tried_at));
                        return reply_json(
                            slot.take().unwrap(),
                            503,
                            &json!({ "type": "error",
                                     "error": { "type": "api_error",
                                                "message": "上游返回边缘 IP 封禁页（HTTP 405），请在控制台「出站代理」更换出口代理后重试" } }),
                        );
                    }

                    if is_exhausted(status, biz_code, &err_txt) {
                        last_err_detail = format!("{} 额度耗尽（HTTP {status}）：{short_snip}", c.name);
                        crate::flowlog::log("relay", "exhausted", &last_err_detail);
                        gw.mark_no_quota(&c.id, &model);
                        continue 'cand_loop;
                    }

                    if status == 429 && is_concurrency_429(biz_code, &err_txt) && inner_retries < 2 {
                        inner_retries += 1;
                        let wait = 1200 + (inner_retries as u64) * 1000;
                        crate::flowlog::log("relay", "concurrency-retry", &format!("{} HTTP 429 并发争用（{inner_retries}/2），退避 {wait}ms", c.name));
                        std::thread::sleep(Duration::from_millis(wait));
                        continue;
                    }

                    if status == 429 {
                        last_err_detail = format!("{} HTTP 429：{short_snip}", c.name);
                        let cool = if is_concurrency_429(biz_code, &err_txt) { 15_000 } else { SHORT_RATE_TTL_MS };
                        gw.mark_blocked(&c.id, cool);
                        crate::flowlog::log("relay", "switch", &last_err_detail);
                        continue 'cand_loop;
                    }

                    if is_risk_control(status, biz_code, &err_txt) {
                        last_err_detail = format!("{} 风控 HTTP {status} code={}：{short_snip}", c.name, biz_code.map_or("-".into(), |x| x.to_string()));
                        gw.mark_blocked(&c.id, RATE_TTL_MS);
                        crate::flowlog::log("relay", "risk-3012", &last_err_detail);
                        continue 'cand_loop;
                    }

                    if status >= 500 && inner_retries == 0 {
                        inner_retries += 1;
                        std::thread::sleep(Duration::from_millis(1200));
                        continue;
                    }

                    if SWITCH_STATUS.contains(&status) || status >= 500 {
                        last_err_detail = format!("{} HTTP {status}：{short_snip}", c.name);
                        gw.mark_blocked(&c.id, SHORT_RATE_TTL_MS);
                        crate::flowlog::log("relay", "switch", &last_err_detail);
                        continue 'cand_loop;
                    }

                    // 4xx request error (e.g. 400 invalid params) -> return directly to client
                    crate::flowlog::log("relay", "client-4xx", &format!("{} HTTP {status}: {short_snip}", c.name));
                    crate::usage::append(&usage_path, &mk(&c.name, status, &biz_code.map(|x| x.to_string()).unwrap_or_default(), tried, false, tried_at));
                    let mut hs = vec![];
                    if let Some(ct) = ctype {
                        if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()) {
                            hs.push(h);
                        }
                    }
                    let rd = std::io::Cursor::new(err_buf);
                    let _ = slot.take().unwrap().respond(tiny_http::Response::new(
                        tiny_http::StatusCode(status), hs, rd, None, None,
                    ));
                    return Ok(());
                } else {
                    last_err_detail = format!("{} 异常响应 HTTP {status}：{short_snip}", c.name);
                    last_abnormal = Some((status, ctype.clone(), err_buf, reader));
                    continue 'cand_loop;
                }
            }

            let stream = ct_lower.contains("event-stream");
            let mut up: Option<String> = None;
            if status == 200 {
                let mut head: Vec<u8> = Vec::new();
                let mut buf = vec![0u8; 2048];
                let mut ended = false;
                for _ in 0..6 {
                    match reader.read(&mut buf) {
                        Ok(0) => { ended = true; break; }
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                        Err(_) => { ended = true; break; }
                    }
                    if peek_model(&head).is_some() || head.len() >= 4096 { break; }
                }
                up = peek_model(&head);
                let txt = String::from_utf8_lossy(&head).to_lowercase();
                if up.is_none() && (ended || !stream || txt.contains("\"error\"") || txt.contains("\"code\"")) {
                    let short: String = String::from_utf8_lossy(&head).chars().take(200).collect();
                    last_err_detail = format!("{} 响应非模型流：{short}", c.name);
                    crate::flowlog::log("relay", "abnormal", &last_err_detail);
                    last_abnormal = Some((status, ctype.clone(), head, reader));
                    continue 'cand_loop;
                }
                reader = Box::new(std::io::Cursor::new(head).chain(reader));
            }
            if prep.aliased {
                reader = Box::new(AliasReverseReader::new(reader));
            }

            gw.set_sticky(&c.id);
            {
                let mut g = gw.inner.lock().unwrap();
                g.served += 1;
                if tried > 1 {
                    g.switched += 1;
                }
                g.last_route = Some(Route {
                    account: c.id.clone(),
                    model: model.clone(),
                    tries: tried,
                });
            }
            crate::flowlog::log(
                "relay",
                "external-ok",
                &format!("{} HTTP {status} model={model} tries={tried} len={}", c.name, prep.bytes.len()),
            );

            let mut hs: Vec<tiny_http::Header> = vec![];
            if let Some(ct) = ctype {
                if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()) {
                    hs.push(h);
                }
            }
            for (k, v) in [
                ("x-relay-account", c.name.clone()),
                ("x-relay-tries", tried.to_string()),
            ] {
                if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                    hs.push(h);
                }
            }
            let reader: Box<dyn std::io::Read + Send> = Box::new(Meter {
                inner: gw.inner.clone(),
                src: reader,
                tail: Vec::new(),
                head: Vec::new(),
                tokens: 0,
                tokens_in: 0,
                cache: 0,
                bytes: 0,
                started: tried_at,
                first_at: None,
                rec: Some(crate::usage::UsageRecord {
                    t: tried_at,
                    acct: c.name.clone(),
                    model: client_model.clone(),
                    up,
                    tokens_in: 0,
                    tokens_out: 0,
                    cache: 0,
                    ttfb: None,
                    ms: 0,
                    bytes: 0,
                    status,
                    code: String::new(),
                    tries: tried,
                    stream,
                    mapped: mapped.clone(),
                    key: key_tag.to_string(),
                }),
                path: usage_path.clone(),
            });
            let resp = tiny_http::Response::new(tiny_http::StatusCode(status), hs, reader, None, None);
            let _ = slot.take().unwrap().respond(resp);
            return Ok(());
        }
    }

    if let Some((status, ctype, head, reader)) = last_abnormal {
        let mut hs: Vec<tiny_http::Header> = vec![];
        if let Some(ct) = ctype {
            if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()) {
                hs.push(h);
            }
        }
        let mut rec = mk(
            &last_acct,
            status,
            "abnormal",
            tried,
            hs.iter().any(|h| h.value.as_str().to_ascii_lowercase().contains("event-stream")),
            last_at,
        );
        rec.up = peek_model(&head);
        rec.bytes = head.len() as u64;
        rec.ms = now_ms().saturating_sub(last_at);
        crate::usage::append(&usage_path, &rec);
        let rd: Box<dyn std::io::Read + Send> = Box::new(std::io::Cursor::new(head).chain(reader));
        let resp = tiny_http::Response::new(tiny_http::StatusCode(status), hs, rd, None, None);
        let _ = slot.take().unwrap().respond(resp);
        crate::flowlog::log("relay", "abnormal-all", &format!("外部 tried={tried} path={path}"));
        return Ok(());
    }
    crate::usage::append(&usage_path, &mk(&last_acct, 502, "rejected", tried, false, last_at));
    let msg = if last_err_detail.is_empty() {
        format!("试了 {tried} 个号都被拒")
    } else {
        format!("试了 {tried} 个号都被拒（最后错误：{last_err_detail}）")
    };
    reply_json(
        slot.take().unwrap(),
        502,
        &json!({ "type": "error",
                 "error": { "type": "overloaded_error", "message": msg } }),
    )
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split('?').nth(1)?;
    for kv in q.split('&') {
        let (k, v) = match kv.split_once('=') {
            Some((k, v)) => (k, v),
            None => (kv, ""),
        };
        if k == key {
            return Some(decode_pct(v));
        }
    }
    None
}

fn decode_pct(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn handle(mut req: tiny_http::Request, gw: &Gateway) -> Result<(), String> {
    let paths = Paths::detect();
    let url = req.url().to_string();
    let mut body = Vec::new();
    if req.as_reader().read_to_end(&mut body).is_err() {
        let _ = req.respond(tiny_http::Response::from_string("bad body").with_status_code(400));
        return Ok(());
    }

    let path = norm_path(&url);

    let from_loopback = req
        .remote_addr()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(true);

    if !from_loopback && gw.inner.lock().unwrap().bind.starts_with("127.") {
        crate::flowlog::log("relay", "bind-deny", &format!("{path} 来自非本机，但当前是「仅本机」模式"));
        let _ = req.respond(
            tiny_http::Response::from_string("not found
").with_status_code(404),
        );
        return Ok(());
    }
    if !from_loopback {
        let keys = gw.inner.lock().unwrap().keys.clone();
        if keys.is_empty() {

            let _ = req.respond(
                tiny_http::Response::from_string("外部访问未启用：没有配置 API Key\n")
                    .with_status_code(401),
            );
            return Ok(());
        }
        let got = auth_token(&req);
        if !keys.iter().any(|k| *k == got) {
            crate::flowlog::log("relay", "auth-deny", &format!("{path} 凭据不对"));
            let _ = req.respond(
                tiny_http::Response::from_string("unauthorized：请在 x-api-key 或 Authorization 里带上 API Key\n")
                    .with_status_code(401),
            );
            return Ok(());
        }
    }

    let key_tag: String = {
        let t = auth_token(&req);
        if t.is_empty() { "本机".to_string() } else { t.chars().take(8).collect() }
    };

    match path.as_str() {
        "/" | "/chat" => return reply_html(req, page("chat.html", CHAT_PAGE)),
        "/proxy" | "/proxy/admin" => return reply_html(req, page("proxy.html", PROXY_PAGE)),
        "/proxy/status" => return reply_json(req, 200, &gw.console_status(&paths)),

        "/proxy/usage" => {
            let limit = query_param(&url, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(200)
                .min(1000);
            let acct = query_param(&url, "acct").unwrap_or_default().to_lowercase();
            let model = query_param(&url, "model").unwrap_or_default().to_lowercase();
            let key = query_param(&url, "key").unwrap_or_default().to_lowercase();
            let ok = query_param(&url, "ok").unwrap_or_default();
            let rows = crate::usage::read_all(&crate::usage::path_for(&paths.store_dir()));
            let total = rows.len();
            let out: Vec<Value> = rows
                .iter()
                .rev()
                .filter(|r| acct.is_empty() || r.acct.to_lowercase() == acct)
                .filter(|r| {
                    model.is_empty()
                        || r.model.to_lowercase() == model
                        || r.up.as_deref().map(|u| u.to_lowercase() == model).unwrap_or(false)
                })
                .filter(|r| key.is_empty() || r.key.to_lowercase() == key)
                .filter(|r| match ok.as_str() {
                    "1" | "true" | "ok" => !crate::usage::is_fail(r),
                    "0" | "false" | "fail" => crate::usage::is_fail(r),
                    _ => true,
                })
                .take(limit)
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            let count = out.len();
            return reply_json(req, 200, &json!({ "rows": out, "count": count, "total": total }));
        }
        "/proxy/usage/stats" => {
            return reply_json(req, 200, &crate::usage::stats(&crate::usage::path_for(&paths.store_dir())));
        }

        "/proxy/logs" => {
            let offset = query_param(&url, "offset").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
            let limit = query_param(&url, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(50).clamp(1, 500);
            let (lines, total) = crate::flowlog::tail_page(offset, limit);
            return reply_json(req, 200, &json!({ "lines": lines, "total": total, "offset": offset, "limit": limit }));
        }

        "/proxy/probe" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let one = v.get("id").and_then(|x| x.as_str()).map(str::to_string);
            let ids: Vec<String> = match one {
                Some(id) => vec![id],
                None => store::list_accounts(&paths).unwrap_or_default().into_iter().map(|a| a.id).collect(),
            };
            let mut res = vec![];
            for id in ids.iter().take(30) {
                let r = gw.probe_one(&paths, id);
                res.push(json!({ "id": id, "ok": r.is_ok(), "ms": r.as_ref().ok(), "err": r.err() }));
            }
            return reply_json(req, 200, &json!({ "results": res, "status": gw.console_status(&paths) }));
        }
        "/proxy/bind" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let bind = v.get("bind").and_then(|x| x.as_str()).unwrap_or("");
            return match gw.set_bind(&paths, bind) {
                Ok(st) => reply_json(req, 200, &st),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/key-add" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let want = v.get("key").and_then(|x| x.as_str()).unwrap_or("");
            return match gw.key_add(&paths, want) {
                Ok(k) => {
                    crate::flowlog::log("relay", "key-add", &format!("新建 API Key {}", k.chars().take(8).collect::<String>()));
                    reply_json(req, 200, &json!({ "key": k, "status": gw.console_status(&paths) }))
                }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/key-del" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let k = v.get("key").and_then(|x| x.as_str()).unwrap_or("");
            let in_use = !gw.inner.lock().unwrap().bind.starts_with("127.");
            if in_use && gw.inner.lock().unwrap().keys.len() <= 1 {
                return reply_json(req, 400, &json!({ "error": "现在是局域网模式，删掉最后一个 key 会让人进不来（先把监听地址改回 127.0.0.1）" }));
            }
            return match gw.key_del(&paths, k) {
                Ok(_) => reply_json(req, 200, &gw.console_status(&paths)),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/model-map" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("");
            let to = v.get("to").and_then(|x| x.as_str()).unwrap_or("");
            return match gw.set_model_map(&paths, from, to) {
                Ok(st) => {
                    crate::flowlog::log("relay", "model-map-set", &format!("{from} -> {}", if to.is_empty() { "(删)" } else { to }));
                    reply_json(req, 200, &st)
                }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/external" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let on = v.get("on").and_then(|x| x.as_bool()).unwrap_or(false);
            match gw.set_external_and_run(&paths, on) {
                Ok(st) => {
                    crate::flowlog::log("relay", "external-set", &format!("网页把反代设为 {on}"));
                    return reply_json(req, 200, &st);
                }
                Err(e) => return reply_json(req, 400, &json!({ "error": e })),
            }
        }
        "/proxy/port" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            return match gw.set_port(&paths, port) {
                Ok(st) => {
                    crate::flowlog::log("relay", "port-set", &format!("网页把端口改成 {port}"));
                    reply_json(req, 200, &st)
                }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/refresh-quota" => {
            if let Err(e) = gw.refresh_quota(&paths, true) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }

        "/proxy/unfreeze" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                let n = gw.unfreeze(id);
                crate::flowlog::log("relay", "unfreeze", &format!("{id} 清了 {n} 条标记"));
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }

        "/proxy/policy" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let policy = v.get("policy").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let pinned = v.get("pinned").and_then(|x| x.as_str()).map(str::to_string);
            if policy.is_empty() {
                return reply_json(req, 400, &json!({ "error": "policy 不能为空" }));
            }
            if let Err(e) = gw.set_policy(policy, pinned) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }
        // 反代出站的代理（空字符串 = 改回直连）
        "/proxy/proxy-url" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if !url.is_empty() {
                if let Err(e) = crate::oauth::parse_proxy_url(&url) {
                    return reply_json(req, 400, &json!({ "error": e }));
                }
            }
            if let Err(e) = store::set_relay_proxy(&paths, &url) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            {
                let mut g = gw.inner.lock().unwrap();
                g.relay_proxy = if url.is_empty() { None } else { Some(url.clone()) };
            }
            crate::flowlog::log("relay", "proxy-set", &if url.is_empty() { "直连".into() } else { url });
            return reply_json(req, 200, &gw.console_status(&paths));
        }
        "/proxy/model-mode" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let mode = v.get("mode").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let pinned = v.get("pinned").and_then(|x| x.as_str()).map(|s| s.to_string());
            if let Err(e) = gw.set_model_mode(&paths, mode, pinned) {
                return reply_json(req, 400, &json!({ "error": e }));
            }
            return reply_json(req, 200, &gw.console_status(&paths));
        }

        "/client-log" => {
            if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("?");
                let detail = v.get("detail").and_then(|x| x.as_str()).unwrap_or("");
                crate::flowlog::log("chat", kind, &detail.chars().take(300).collect::<String>());
            }
            return reply_json(req, 200, &json!({ "ok": true }));
        }
        "/mint" => return reply_html(req, page("mint.html", MINT_PAGE)),
        "/want-mint" => {
            let v = gw.want_mint(url.contains("wait"));
            return reply_json(req, 200, &v);
        }
        "/mint-result" => {
            if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                let param = v.get("param").and_then(|p| p.as_str()).unwrap_or("").trim().to_string();
                let region = v
                    .get("region")
                    .and_then(|p| p.as_str())
                    .unwrap_or(CAPTCHA_REGION)
                    .to_string();
                if !param.is_empty() {
                    let cid = v.get("certifyId").and_then(|p| p.as_str()).unwrap_or("?").to_string();
                    let n = gw.put_param(param, region);
                    crate::flowlog::log("relay", "mint", &format!("+1 池={n} certifyId={cid}"));
                }
            }
            return reply_json(req, 200, &json!({ "ok": true }));
        }

        p if p == "/v1/models" || p == "/models" || p.starts_with("/v1/models/") || p.starts_with("/models/") => {
            let one = p.rsplit('/').next().unwrap_or("");
            let want = if p.starts_with("/v1/models/") || p.starts_with("/models/") {
                let norm = normalize_request_model(one);
                EXTERNAL_MODELS.iter().find(|m| m.eq_ignore_ascii_case(&norm) || m.eq_ignore_ascii_case(one)).copied()
            } else {
                None
            };
            if !one.is_empty() && !p.ends_with("/models") && want.is_none() {
                return reply_json(
                    req,
                    404,
                    &json!({ "type": "error",
                             "error": { "type": "not_found_error",
                                        "message": format!("没有这个模型：{one}（可用：{}）", EXTERNAL_MODELS.join(", ")) } }),
                );
            }
            let list: Vec<&str> = match want {
                Some(m) => vec![m],
                None => EXTERNAL_MODELS.to_vec(),
            };
            let data: Vec<Value> = list
                .iter()
                .map(|m| json!({ "id": m, "type": "model", "object": "model", "display_name": m, "created_at": 0 }))
                .collect();
            return reply_json(
                req,
                200,
                &json!({
                    "object": "list",
                    "type": "list",
                    "data": data,
                    "has_more": false,
                    "first_id": list.first().copied(),
                    "last_id": list.last().copied(),
                }),
            );
        }

        "/proxy/accounts" => {
            return match store::get_state(&paths) {
                Ok(st) => reply_json(req, 200, &json!(st)),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/quota" => {
            let id = query_param(&url, "id").unwrap_or_default();
            return match store::account_quota(&paths, &id) {
                Ok(q) => reply_json(req, 200, &json!(q)),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/capture" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let name = v.get("name").and_then(|x| x.as_str()).map(str::to_string).filter(|s| !s.trim().is_empty());
            let r = { let _g = crate::store_guard(); store::capture_current(&paths, name) };
            return match r {
                Ok(a) => { gw.sync_exe(); reply_json_masked(req, 200, &json!(a), from_loopback) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/rename" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let r = { let _g = crate::store_guard(); store::rename_account(&paths, &id, &name) };
            return match r {
                Ok(a) => { gw.sync_exe(); reply_json_masked(req, 200, &json!(a), from_loopback) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/delete" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let r = { let _g = crate::store_guard(); store::delete_account(&paths, &id) };
            return match r {
                Ok(()) => { gw.sync_exe(); reply_json(req, 200, &json!({ "ok": true, "status": gw.console_status(&paths) })) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/update-live" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let r = { let _g = crate::store_guard(); store::update_account_from_live(&paths, &id) };
            return match r {
                Ok(a) => { gw.sync_exe(); reply_json_masked(req, 200, &json!(a), from_loopback) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/switch" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let force = v.get("force").and_then(|x| x.as_bool()).unwrap_or(false);
            let restart = v.get("restart").and_then(|x| x.as_bool()).unwrap_or(true);
            let r = { let _g = crate::store_guard(); store::switch_to(&paths, &id, force, restart) };
            return match r {
                Ok(s) => { gw.sync_exe(); reply_json(req, 200, &json!({ "result": s, "status": gw.console_status(&paths) })) }
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/claim-preview" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mid = match store::account_mid(&paths, &id) { Ok(m) => m, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            let acc = match store::load_account(&paths, &id) { Ok(a) => a, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            return match crate::claim::preview_plans(&paths.home, &acc.credentials, acc.config.as_ref(), Some(mid)) {
                Ok(plans) => reply_json(req, 200, &json!({ "plans": plans })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/account/claim-refresh" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mid = match store::account_mid(&paths, &id) { Ok(m) => m, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            let acc = match store::load_account(&paths, &id) { Ok(a) => a, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            let (activated, activation_error) = match crate::claim::telemetry_user_id(&paths.home, &acc.credentials) {
                Some(uid) => match crate::claim::report_activation_events(&uid, &mid) {
                    Ok(()) => (true, None),
                    Err(e) => (false, Some(e)),
                },
                None => (false, None),
            };
            return match crate::claim::preview_plans(&paths.home, &acc.credentials, acc.config.as_ref(), Some(mid)) {
                Ok(plans) => reply_json(req, 200, &json!({ "plans": plans, "activated": activated, "activationError": activation_error })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/claim-start" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let plan_id = v.get("plan_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let auto = v.get("auto").and_then(|x| x.as_bool()).unwrap_or(true);
            let Some(app) = gw.app() else {
                return reply_json(req, 400, &json!({ "error": "反代还没拿到 AppHandle（窗口环境未就绪），这一步暂时只能在 exe 面板做" }));
            };
            return match crate::proxy_claim_start(&app, id, plan_id, auto) {
                Ok(v) => reply_json(req, 200, &v),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }

        "/proxy/account/claim-result" => {
            return reply_json(req, 200, &crate::claim_last_result());
        }

        "/proxy/zcode/launch" => {
            let (p, ok) = store::effective_zcode_path(&paths);
            if !ok {
                return reply_json(req, 400, &json!({ "error": format!("ZCode 路径无效：{p}") }));
            }
            return match store::launch_zcode(&p) {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true, "status": gw.console_status(&paths) })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/zcode/kill" => {
            return match store::kill_zcode() {
                Ok(_) => reply_json(req, 200, &json!({ "ok": true, "status": gw.console_status(&paths) })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/zcode/path" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let _g = crate::store_guard();
            let mut s = store::load_settings(&paths);
            s.zcode_path = store::normalize_zcode_path(&path);
            let r = store::save_settings(&paths, &s);
            drop(_g);
            return match r {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/accounts/export" => {
            let accounts = match store::list_accounts(&paths) { Ok(a) => a, Err(e) => return reply_json(req, 400, &json!({ "error": e })) };
            if accounts.is_empty() {
                return reply_json(req, 400, &json!({ "error": "账号库是空的" }));
            }
            let mut payload = store::export_bundle_value(&accounts);
            if !from_loopback { mask_json(&mut payload); }
            let body = serde_json::to_string_pretty(&payload).unwrap_or_default() + "\n";
            return reply_text(req, body, "zcode-accounts.json");
        }

        "/proxy/mail" => {
            let root = paths.store_dir();
            let items: Vec<_> = crate::pool::load(&root).iter().map(|a| a.to_summary()).collect();
            return reply_json(req, 200, &json!({ "accounts": items }));
        }
        "/proxy/mail/get" => {
            let email = query_param(&url, "email").unwrap_or_default();
            let root = paths.store_dir();
            let accounts = crate::pool::load(&root);
            return match crate::pool::find(&accounts, &email) {
                Some(a) => reply_json_masked(req, 200, &json!({ "email": a.email, "password": a.password }), from_loopback),
                None => reply_json(req, 404, &json!({ "error": "邮箱不在库里" })),
            };
        }

        "/proxy/mail/import" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let raw = v.get("text").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let rep = crate::pool::import(&mut accounts, &raw, store::now_ts());
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(rep), Err(e) => Err(e) }
            };
            return match r {
                Ok(rep) => reply_json(req, 200, &json!({ "added": rep.added, "skipped": rep.skipped, "parsed": rep.total_parsed })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/remove" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let email = v.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let before = accounts.len();
                accounts.retain(|a| !a.email.eq_ignore_ascii_case(email.trim()));
                let removed = before - accounts.len();
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(removed), Err(e) => Err(e) }
            };
            return match r {
                Ok(n) => reply_json(req, 200, &json!({ "removed": n })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/remove-many" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let emails: Vec<String> = v.get("emails").and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_ascii_lowercase()).collect())
                .unwrap_or_default();
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let before = accounts.len();
                accounts.retain(|a| !emails.contains(&a.email.trim().to_ascii_lowercase()));
                let removed = before - accounts.len();
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(removed), Err(e) => Err(e) }
            };
            return match r {
                Ok(n) => reply_json(req, 200, &json!({ "removed": n })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/mark-verified" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let email = v.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(true);
            let note = v.get("note").and_then(|x| x.as_str()).map(str::to_string);
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                if let Some(a) = crate::pool::find_mut(&mut accounts, &email) {
                    if ok {
                        a.status = crate::pool::STATUS_VERIFIED.to_string();
                        a.verified_at = Some(store::now_ts());
                        a.note = None;
                    } else {
                        a.status = crate::pool::STATUS_FAILED.to_string();
                        a.note = note;
                    }
                    crate::pool::save(&root, &accounts)
                } else {
                    Ok(())
                }
            };
            return match r {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/reset" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let email = v.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let root = paths.store_dir();
            let r = { let _g = crate::store_guard(); crate::pool::set_status(&root, &email, crate::pool::STATUS_NEW, None) };
            return match r {
                Ok(()) => reply_json(req, 200, &json!({ "ok": true })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/upsert" => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            let line = v.get("line").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let Some((email, password, client_id, refresh_token)) = crate::pool::parse_lines(&line).into_iter().next() else {
                return reply_json(req, 400, &json!({ "error": "行格式不对，应为 email----password----client_id----refresh_token" }));
            };
            let root = paths.store_dir();
            let r = {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                let updated = if let Some(a) = crate::pool::find_mut(&mut accounts, &email) {
                    a.password = password;
                    a.client_id = client_id;
                    a.refresh_token = refresh_token;
                    a.status = crate::pool::STATUS_NEW.to_string();
                    a.note = None;
                    true
                } else {
                    accounts.push(crate::pool::MailAccount {
                        email: email.clone(),
                        password,
                        client_id,
                        refresh_token,
                        status: crate::pool::STATUS_NEW.to_string(),
                        verified_at: None,
                        note: None,
                        created_at: store::now_ts(),
                    });
                    false
                };
                match crate::pool::save(&root, &accounts) { Ok(()) => Ok(updated), Err(e) => Err(e) }
            };
            return match r {
                Ok(updated) => reply_json(req, 200, &json!({ "email": email, "updated": updated })),
                Err(e) => reply_json(req, 400, &json!({ "error": e })),
            };
        }
        "/proxy/mail/export" => {
            let root = paths.store_dir();
            let accounts = crate::pool::load(&root);
            if accounts.is_empty() {
                return reply_json(req, 400, &json!({ "error": "邮箱库是空的" }));
            }
            let body: String = if from_loopback {
                accounts.iter()
                    .map(|a| format!("{}----{}----{}----{}\n", a.email, a.password, a.client_id, a.refresh_token))
                    .collect()
            } else {

                accounts.iter()
                    .map(|a| format!("{}----{}----{}----{}\n", a.email, mask_secret(&a.password), a.client_id, mask_secret(&a.refresh_token)))
                    .collect()
            };
            return reply_text(req, body, "mailboxes.txt");
        }

        "/proxy/mail/messages" => {
            let email = query_param(&url, "email").unwrap_or_default();
            let top = query_param(&url, "top").and_then(|v| v.parse::<usize>().ok()).unwrap_or(15);
            let root = paths.store_dir();
            let accounts = crate::pool::load(&root);
            let acc = match crate::pool::find(&accounts, &email) {
                Some(a) => a.clone(),
                None => return reply_json(req, 404, &json!({ "error": "邮箱不在库里" })),
            };
            let (msgs, new_rt) = match crate::graph::fetch_messages(&acc.client_id, &acc.refresh_token, top) {
                Ok(v) => v,
                Err(e) => {
                    if crate::graph::is_credential_error(&e) {
                        let _ = crate::pool::set_status(&root, &email, crate::pool::STATUS_INVALID, Some("需要重新授权".to_string()));
                    }
                    return reply_json(req, 400, &json!({ "error": e }));
                }
            };
            if let Some(rt) = new_rt {
                let _g = crate::store_guard();
                let mut accounts = crate::pool::load(&root);
                if let Some(a) = crate::pool::find_mut(&mut accounts, &email) {
                    a.refresh_token = rt;
                    let _ = crate::pool::save(&root, &accounts);
                }
            }

            let out: Vec<Value> = msgs.iter().map(|m| json!({
                "id": m.id, "subject": m.subject, "from": m.from,
                "receivedAt": m.received_at, "preview": m.preview,
                "html": m.html, "text": m.text, "body": m.text,
                "links": m.links,
            })).collect();
            return reply_json(req, 200, &json!({ "messages": out, "count": out.len() }));
        }
        _ => {}
    }

    if path.starts_with("/v1") {
        return handle_external(req, gw, &paths, &path, &body, &key_tag);
    }

    let _ = req.respond(
        tiny_http::Response::from_string("404 — / 是对话页，/proxy 是控制台\n")
            .with_status_code(404),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_normalization_handles_namespaces_aliases_and_case() {
        assert_eq!(normalize_request_model("zai/glm-5.4"), "GLM-5.4");
        assert_eq!(normalize_request_model("bigmodel/glm-5.3-flash"), "GLM-5.3-Flash");
        assert_eq!(normalize_request_model("GLM-5.2"), "GLM-5.4");
        assert_eq!(normalize_request_model("glm-5-turbo"), "GLM-5.4");
        assert_eq!(fallback_models_for("claude-haiku-4-5")[0], "GLM-5.3-Flash");
        assert_eq!(fallback_models_for("claude-sonnet-4-5")[0], "GLM-5.4");
    }

    #[test]
    fn attribution_session_and_query_ids_ignore_date_turn_and_tool_results() {
        let msgs = vec![
            json!({ "role": "user", "content": "fix bug" }),
            json!({ "role": "assistant", "content": [{ "type": "tool_use", "id": "t1", "name": "Read", "input": {} }] }),
            json!({ "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "t1", "content": "ok" }] }),
        ];
        let mut with_date = vec![json!({
            "role": "user",
            "content": [{ "type": "text", "text": "<system-reminder>Today's date is 2026-11-24.</system-reminder>" }]
        })];
        with_date.extend(msgs.clone());

        let s1 = conversation_session_id(&msgs, "acc1");
        let s2 = conversation_session_id(&with_date, "acc1");
        assert_eq!(s1, s2);
        assert_ne!(s1, conversation_session_id(&msgs, "acc2"));
        assert_eq!(
            conversation_query_id(&msgs, &s1),
            conversation_query_id(&with_date, &s1)
        );
    }

    #[test]
    fn external_body_shapes_three_blocks_date_turn_cache_and_tool_search_alias() {
        let raw = json!({
            "model": "GLM-5.4",
            "max_tokens": 999_999,
            "system": "Custom prompt",
            "tools": [
                { "name": "ToolSearch", "description": "s", "defer_loading": true, "cache_control": { "type": "ephemeral" } },
                { "name": "DeferredToolPlaceholder", "description": "p" },
                { "name": "Skill", "description": "sk" }
            ],
            "messages": [
                { "role": "user", "content": "hello" }
            ]
        });
        let paths = Paths { home: std::env::temp_dir().join("zpool-gw-test") };
        let prep = external_body(&serde_json::to_vec(&raw).unwrap(), "a1", "mid1", "GLM-5.4", &paths).unwrap();
        assert!(prep.aliased);
        let v: Value = serde_json::from_slice(&prep.bytes).unwrap();
        assert_eq!(v["max_tokens"].as_u64(), Some(MAX_TOKENS_LIMIT));
        let sys = v["system"].as_array().unwrap();
        assert_eq!(sys.len(), 3);
        assert!(sys[2]["text"].as_str().unwrap().contains("Custom prompt"));
        let tools = v["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"].as_str(), Some("ToolSearchTool"));
        assert!(tools[0].get("defer_loading").is_none());
        assert!(tools[0].get("cache_control").is_none());
        let msgs = v["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0]["content"][0]["text"].as_str().unwrap().contains("Today's date is"));
        assert_eq!(msgs[1]["content"][0]["cache_control"]["type"].as_str(), Some("ephemeral"));
        let uid: Value = serde_json::from_str(v["metadata"]["user_id"].as_str().unwrap()).unwrap();
        assert_eq!(uid["session_id"].as_str(), Some(prep.session_id.as_str()));
        assert_eq!(uid["device_id"].as_str(), Some("mid1"));
    }

    #[test]
    fn business_error_and_edge_block_classification_matches_zcode2api() {
        assert_eq!(parse_business_code(r#"{"code":3012,"msg":"unusual"}"#), Some(3012));
        assert_eq!(parse_business_code(r#"{"code":0,"msg":"ok"}"#), None);
        assert!(is_edge_block(405, None, "<html>errors.aliyun.com</html>"));
        assert!(!is_edge_block(405, Some(3012), r#"{"code":3012,"msg":"unusual activity"}"#));
        assert!(is_risk_control(405, Some(3012), r#"{"code":3012,"msg":"unusual activity"}"#));
        assert!(is_exhausted(200, Some(1005), r#"{"code":1005,"msg":"exceed quota limit"}"#));
        assert!(!is_exhausted(429, Some(3009), r#"{"code":3009,"msg":"model concurrency limit"}"#));
        assert!(is_concurrency_429(Some(3009), r#"{"logid":"30099999"}"#));
        assert!(is_captcha_challenge(false, 400, Some(3007), r#"{"code":3007}"#));
    }

    #[test]
    fn alias_reverse_reader_replaces_split_chunks_cleanly() {
        struct ChunkReader(Vec<&'static [u8]>, usize);
        impl std::io::Read for ChunkReader {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.1 >= self.0.len() {
                    return Ok(0);
                }
                let src = self.0[self.1];
                self.1 += 1;
                let n = src.len().min(out.len());
                out[..n].copy_from_slice(&src[..n]);
                Ok(n)
            }
        }
        let cr = ChunkReader(vec![b"{\"name\":\"Tool", b"SearchTool\",\"ok\":true}"], 0);
        let mut r = AliasReverseReader::new(Box::new(cr));
        let mut out = String::new();
        r.read_to_string(&mut out).unwrap();
        assert_eq!(out, r#"{"name":"ToolSearch","ok":true}"#);
    }
}
