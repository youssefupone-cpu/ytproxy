//! الإعدادات: تُقرأ من متغيرات البيئة مع قيم افتراضية آمنة.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// عنوان الربط (افتراضي: كل الواجهات)
    pub bind: String,
    /// منفذ الخادم (افتراضي: 8080)
    pub port: u16,
    /// User-Agent يظهر كمتصفح حقيقي لتجنب الحظر
    pub user_agent: String,
    /// خروج اختياري عبر SOCKS5 (VPN) لتجاوز الحجب الجغرافي — مثال: socks5h://127.0.0.1:1080
    pub socks5: Option<String>,
    /// أقصى حجم لصفحة HTML/CSS يُعاد كتابتها (أكبر من ذلك يُبث كما هو)
    pub text_max_bytes: usize,
    /// عدد خطوات إعادة التوجيه القصوى
    pub redirect_limit: usize,
    /// مهلة الاتصال الخارجي
    pub connect_timeout: Duration,
    /// مهلة بين قراءتين متتاليتين (آمنة للبث الطويل — لا تقطع الفيديو)
    pub read_timeout: Duration,
    /// مهلة الطلب الكلية (تُطبق قبل بدء البث فقط)
    pub request_timeout: Duration,
    /// عدد اتصالات الخمول القصوى لكل مضيف (pool)
    pub pool_max_idle: usize,
    /// مسار شهادة TLS (اختياري) — إن وُجد يُشغَّل HTTPS مع HTTP/2
    pub tls_cert: Option<PathBuf>,
    /// مسار مفتاح TLS الخاص (اختياري)
    pub tls_key: Option<PathBuf>,
    /// السماح بالوصول إلى الشبكات الخاصة (127.x/10.x/192.168.x/...)
    /// — تُحجب افتراضياً لأن البروكسي قد يكون عاماً (SSRF). شغّلها فقط إذا كان
    /// البروكسي خلف جدار حماية موثوق وأنت تعرف سبب الحاجة.
    pub allow_private: bool,
    /// أقصى طلب لكل عنوان IP في الدقيقة (0 = بلا حد) — يمنع استخدام البروكسي
    /// كأداة مفتوحة (open proxy) عبر النفق العام.
    pub rate_limit_per_min: u32,
    /// كلمة سر اختيارية تحمي البروكسي كاملاً (PROXY_PASSWORD) — إن تُركت فارغة
    /// لا تُفعّل المصادقة (وضع الشبكة الموثوقة). طرق الدخول:
    /// - كوكي `ytproxy_auth` يُوضع عبر صفحة /login أو ?password=...
    /// - رأس `Authorization: Bearer <كلمة السر>` (سكربتات/curl)
    pub proxy_password: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let port = env_u16("PORT", 8080);
        let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0".into());
        let user_agent = std::env::var("USER_AGENT").unwrap_or_else(|_| {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                .into()
        });
        let socks5 = std::env::var("PROXY_SOCKS5").ok().filter(|s| !s.is_empty());

        Config {
            bind,
            port,
            user_agent,
            socks5,
            text_max_bytes: env_usize("TEXT_MAX_BYTES", 32 * 1024 * 1024),
            redirect_limit: env_usize("REDIRECT_LIMIT", 10),
            connect_timeout: Duration::from_secs(env_u64("CONNECT_TIMEOUT_SECS", 10)),
            read_timeout: Duration::from_secs(env_u64("READ_TIMEOUT_SECS", 120)),
            request_timeout: Duration::from_secs(env_u64("REQUEST_TIMEOUT_SECS", 60)),
            pool_max_idle: env_usize("POOL_MAX_IDLE", 32),
            tls_cert: env_path("TLS_CERT"),
            tls_key: env_path("TLS_KEY"),
            allow_private: env_bool("ALLOW_PRIVATE"),
            rate_limit_per_min: env_u32("RATE_LIMIT_PER_MIN", 600),
            proxy_password: std::env::var("PROXY_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var(key).ok().filter(|s| !s.is_empty()).map(PathBuf::from)
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_bool(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
