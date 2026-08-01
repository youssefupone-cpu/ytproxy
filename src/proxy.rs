//! معالج `/proxy`: يوجّه الطلبات خارجياً مع:
//! - بث الوسائط مباشرة (ذاكرة ثابتة مهما كان حجم الفيديو)
//! - إعادة كتابة HTML/CSS فقط عند الحاجة
//! - تمرير Range (تخطي الفيديو) والكوكيز، ومتابعة إعادة التوجيه مع مخزن كوكيز
//! - إزالة رؤوس الأمان التي تعطّل البروكسي (CSP/HSTS/COOP)

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use log::{debug, info, warn};
use percent_encoding::percent_decode_str;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use url::Url;

use crate::config::Config;
use crate::rewrite::{rewrite_css, rewrite_html};

/// جسم رد موحّد: بث منسوخ في صندوق، خطأه io::Error.
type RespBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

/// جسم ثابت (صغير) من بايتات.
fn bytes_body(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// ترويسات CORS كاملة تُضاف لكل رد — بدونها يفشل متصفح يوتيوب ديناميكياً
/// (net::ERR_FAILED ~253/300) لأن طلباته تُرسل عبر أصل النفق (cross-origin).
fn cors_headers(builder: http::response::Builder) -> http::response::Builder {
    builder
        .header("access-control-allow-origin", "*")
        .header(
            "access-control-allow-methods",
            "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        )
        .header("access-control-allow-headers", "*")
}

/// جسم بثّي من مجرى (Stream) بايتات — يُحول كل عنصر إلى Frame بيانات.
fn stream_body<S>(s: S) -> RespBody
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let frames = s.map(|item| item.map(hyper::body::Frame::data));
    http_body_util::BodyExt::boxed_unsync(StreamBody::new(frames))
}

/// ترميز قيم `u` في /ytstream-hls: يرمّز الفواصل والرموز الخطرة فقط، ويُبقي
/// '/' ':' خام ليظل رابط المقاطع مضغوطاً تحت حدّي Cloudflare (8KB).
const HLS_U_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'&')
    .add(b'=')
    .add(b'?')
    .add(b'#')
    .add(b'%');

/// الحالة المشتركة للبروكسي (تُبنى مرة واحدة وتُستنسخ رخيصاً لكل طلب).
#[derive(Clone)]
pub struct Proxy {
    pub client: reqwest::Client,
    pub config: Config,
    /// عميل مخصص للـ sidecar (127.0.0.1:8090) — يُبنى مرة واحدة بدل بناء
    /// عميل جديد في كل طلب Waa (كان ذلك يهدر اتصالات وذاكرة).
    pub sidecar_client: reqwest::Client,
    /// كوكيز جلسة يوتيوب (VISITOR_INFO1_LIVE, CONSENT, ...) تُجلب في الخلفية
    /// لتقليل الرفض 403 من واجهات يوتيوب.
    pub yt_cookies: Arc<tokio::sync::Mutex<Option<String>>>,
    /// عدّاد طلبات لكل عنوان IP (نافذة 60 ثانية) — يمنع استخدام البروكسي
    /// كأداة مفتوحة (open proxy) عبر النفق العام.
    rate: Arc<std::sync::Mutex<RateState>>,
}

#[derive(Default)]
struct RateState {
    /// عنوان IP ← طوابع زمنية (ثوانٍ) للطلبات الأخيرة
    hits: HashMap<IpAddr, VecDeque<u64>>,
}

/// رؤوس نمررها من المتصفح إلى الموقع الهدف.
const FORWARD_HEADERS: [&str; 11] = [
    "cookie",
    "range",
    "accept",
    "accept-language",
    "authorization",
    "user-agent",
    "content-type",
    "content-encoding",
    "x-goog-api-key",
    "po-token",
    "x-goog-vary-id",
];

/// وكيل مستعرض افتراضي للطلبات التي تصل بلا UA (curl/سكربتات) — خوادم جوجل
/// (googlevideo/youtubei) ترفض 403 الطلبات بلا UA متصفح.
const DEFAULT_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/// مفاتيح innerTube: عند رفض WEB نعيد المحاولة بمفتاح مشغّل مضمّن.
const YT_KEY_WEB: &str = "AIzaSyA8eiZmM1FaDVjRy-df2KTyQ_vz_yYM39w";
const YT_KEY_EMBEDDED: &str = "AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8";

/// اسم كوكي المصادقة (لا يُمرَّر أبداً إلى الموقع الهدف).
const AUTH_COOKIE: &str = "ytproxy_auth";

/// رمز جلسة مشتق من كلمة السر — حتمي ومستقر عبر عمليات إعادة التشغيل
/// (djb2 → hex). لا يخزن كلمة السر نفسها في الكوكي.
fn auth_token(pwd: &str) -> String {
    let mut h: u64 = 5381;
    for b in pwd.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    format!("{h:016x}")
}

/// مقارنة ثابتة الزمن (تمنع قياس التوقيت عبر الشبكة).
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// هل المتصفح ينتظر HTML (نوجّهه لصفحة الدخول)؟
fn wants_html(req: &Request<Incoming>) -> bool {
    req.headers()
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false)
}

/// إزالة زوج كوكي المصادقة من رأس Cookie قبل تمريره للموقع الهدف.
fn strip_auth_cookie(cookie_header: &str) -> String {
    cookie_header
        .split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            let name = pair.split_once('=').map(|(k, _)| k.trim()).unwrap_or(pair);
            if name == AUTH_COOKIE {
                None
            } else {
                Some(pair.to_string())
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// إزالة معامل `password` من query string (بعد نجاح المصادقة).
fn strip_query_param(query: &str, key: &str) -> String {
    query
        .split('&')
        .filter(|pair| {
            let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
            k != key
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// هل المسار وجهة إعادة توجيه آمنة (يمنع open redirect)؟
fn safe_next_path(next: &str) -> bool {
    next.starts_with('/') && !next.starts_with("//") && !next.contains('\r') && !next.contains('\n')
}

/// هل المضيف يتبع يوتيوب (يستفيد من كوكيز الجلسة)؟
fn is_yt_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "youtube.com"
        || h.ends_with(".youtube.com")
        || h == "ytimg.com"
        || h.ends_with(".ytimg.com")
        || h.ends_with(".googlevideo.com")
        || h == "youtubei.googleapis.com"
        || h.ends_with(".youtube-nocookie.com")
}

/// هل الهدف هو نطاق البروكسي نفسه (طلب نسبي ارتد إلينا)؟
fn is_self_origin(target: &Url, proxy_origin: &str) -> bool {
    let Some(phost) = Url::parse(proxy_origin)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
    else {
        return false;
    };
    target
        .host_str()
        .map(|h| h.eq_ignore_ascii_case(&phost))
        .unwrap_or(false)
}

/// حلّ الطلب الذاتي: من Referer نستخرج رابط الصفحة الأصلي (المعروف عبر /proxy?url=)
/// ثم نركّب هدفاً حقيقياً = مضيف الأصل + المسار/الاستعلام الذي أراده المتصفح.
fn resolve_self_target(req: &Request<Incoming>, target: &Url) -> Option<Url> {
    let referer = req.headers().get("referer")?.to_str().ok()?;
    let ref_url = Url::parse(referer).ok()?;
    let orig = ref_url
        .query_pairs()
        .filter(|(k, _)| k == "url")
        .next()?
        .1
        .to_string();
    let orig_url = Url::parse(&orig).ok()?;
    let mut real = orig_url.clone();
    real.set_scheme(orig_url.scheme()).ok()?;
    real.set_host(orig_url.host_str()).ok()?;
    real.set_port(orig_url.port()).ok()?;
    real.set_path(target.path());
    real.set_query(target.query());
    Some(real)
}

/// هل عنوان IPv4 خاص/محجوز (لا يجوز للبروكسي الوصول إليه)؟
fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 (metadata AWS 169.254.169.254),
    // 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 (CGNAT),
    // نطاقات التوثيق (TEST-NET) 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
    // وكل ما فوق 224.0.0.0 (بث متعدد/محجوز)
    o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224
}

/// هل المضيف خاص/محجوب (SSRF)؟ يشمل عناوين IP الفعلية وأنماط الأسماء الداخلية.
fn is_private_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::Ipv4Addr>() {
        return is_private_ipv4(ip);
    }
    if let Ok(ip) = h.parse::<std::net::Ipv6Addr>() {
        if let Some(v4) = ip.to_ipv4_mapped() {
            return is_private_ipv4(v4); // ::ffff:127.0.0.1 وغيرها
        }
        let seg = ip.segments();
        return ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 (unique local)
            || (seg[0] & 0xffc0) == 0xfe80; // fe80::/10 (link-local)
    }
    // أسماء داخلية شائعة لا تُحل عبر DNS عام
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.ends_with(".lan")
        || h.ends_with(".home")
        || h.ends_with(".home.arpa")
        || h.ends_with(".in-addr.arpa")
        || h.ends_with(".ip6.arpa")
}

impl Proxy {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.read_timeout)
            .hickory_dns(true) // حَلّ DNS عبر Google DNS (8.8.8.8) — بعض نطاقات googlevideo لا تُحل من المحلي
            .redirect(reqwest::redirect::Policy::limited(config.redirect_limit))
            .cookie_store(true) // يمرر شاشة الموافقة (consent) ويحتفظ بالجلسة
            .pool_max_idle_per_host(config.pool_max_idle)
            .pool_idle_timeout(std::time::Duration::from_secs(300))
            .tcp_nodelay(true)
            // googlevideo/Waa يرفضان بصمة client HTTP/2 غير المتصفح (403/404)
            // بينما ينجح HTTP/1.1 (كما في python/urllib) — نجبر h1 على كل الطلبات
            .http1_only();

        if let Some(socks) = &config.socks5 {
            let proxy = reqwest::Proxy::all(socks)?;
            builder = builder.proxy(proxy);
            warn!("🛡️ خروج عبر SOCKS5: {socks}");
        }

        let client = builder.build()?;

        // عميل الـ sidecar: مهلة قصيرة ثابتة (الطلب عبره محصور في واجهات po_token)
        let sidecar_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(150))
            .build()?;

        Ok(Self {
            client,
            sidecar_client,
            config,
            yt_cookies: Arc::new(tokio::sync::Mutex::new(None)),
            rate: Arc::new(std::sync::Mutex::new(RateState::default())),
        })
    }

    /// حدّ الطلبات لكل عنوان IP (نافذة 60 ثانية).
    /// تعيد `true` عندما يجب رفض الطلب (429).
    fn rate_limited(&self, ip: IpAddr) -> bool {
        let limit = self.config.rate_limit_per_min;
        if limit == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let Ok(mut guard) = self.rate.try_lock() else {
            return false; // ازدحام على القفل: نسمح (الأفضلية للتوافر)
        };
        // تنظيف دوري لعموم العناوين المهجورة (يمنع نمو الذاكرة بلا حدود)
        if guard.hits.len() > 4096 {
            guard.hits.retain(|_, q| {
                q.back().map_or(false, |&t| now.saturating_sub(t) < 3600)
            });
        }
        let q = guard.hits.entry(ip).or_default();
        while q.front().map_or(false, |&t| now.saturating_sub(t) >= 60) {
            q.pop_front();
        }
        if q.len() >= limit as usize {
            true
        } else {
            q.push_back(now);
            false
        }
    }

    /// جلب كوكيز جلسة يوتيوب في الخلفية (تُدعى عند البدء وكل ساعة).
    pub async fn refresh_yt_cookies(&self) {
        let res = self
            .client
            .get("https://www.youtube.com/")
            .header("accept-language", "en-US,en;q=0.9")
            .send()
            .await;
        let Ok(res) = res else {
            log::warn!("تعذّر جلب كوكيز يوتيوب (الطلبات ستظل تعمل بلا جلسة)");
            return;
        };
        // نجمع أزواج name=value من رؤوس Set-Cookie (نتجاهل خصائص المسار/الانتهاء)
        let mut pairs: Vec<String> = Vec::new();
        for value in res.headers().get_all("set-cookie") {
            let Ok(v) = value.to_str() else { continue };
            if let Some((name_val, _attrs)) = v.split_once(';') {
                let nv = name_val.trim();
                if !nv.is_empty() {
                    pairs.push(nv.to_string());
                }
            }
        }
        drop(res); // نغلق الجسم
        if pairs.is_empty() {
            log::warn!("لم نستلم أي كوكيز من يوتيوب");
            return;
        }
        let cookies = pairs.join("; ");
        let mut guard = self.yt_cookies.lock().await;
        *guard = Some(cookies);
        log::info!("🍪 كوكيز جلسة يوتيوب محدّثة ({} بايت)", pairs.len() as usize * 16);
    }

    /// هل الطلب موثّق؟ (كوكي صالح أو Bearer صحيح) — بلا كلمة سر: دائماً نعم.
    fn is_authenticated(&self, req: &Request<Incoming>) -> bool {
        let Some(pwd) = self.config.proxy_password.as_deref() else {
            return true;
        };
        // 1) كوكي الجلسة
        if let Some(cookie) = req.headers().get("cookie").and_then(|v| v.to_str().ok()) {
            for pair in cookie.split(';') {
                let pair = pair.trim();
                if let Some((k, v)) = pair.split_once('=') {
                    if k.trim() == AUTH_COOKIE && ct_eq(v.trim(), &auth_token(pwd)) {
                        return true;
                    }
                }
            }
        }
        // 2) رأس Authorization: Bearer <كلمة السر>
        if let Some(auth) = req.headers().get("authorization").and_then(|v| v.to_str().ok()) {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                if ct_eq(token.trim(), pwd) {
                    return true;
                }
            }
        }
        false
    }

    /// إضافة كوكي الجلسة إلى رد (يدوم 7 أيام).
    fn with_auth_cookie(&self, mut builder: http::response::Builder) -> http::response::Builder {
        if let Some(pwd) = self.config.proxy_password.as_deref() {
            let value = format!(
                "{AUTH_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
                auth_token(pwd)
            );
            builder = builder.header("set-cookie", value);
        }
        builder
    }

    /// رد "مطلوبة مصادقة": صفحة دخول للمتصفح، 401 لباقي العملاء.
    fn auth_required(&self, req: &Request<Incoming>, query: &str, path: &str) -> Response<RespBody> {
        if wants_html(req) {
            let next = if query.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{query}")
            };
            let encoded = crate::rewrite::proxy_encode(&next);
            Response::builder()
                .status(StatusCode::FOUND)
                .header("location", format!("/login?next={encoded}"))
                .header("x-content-type-options", "nosniff")
                .body(bytes_body(Bytes::new()))
                .unwrap_or_else(|_| internal_error())
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "text/plain; charset=utf-8")
                .header("x-content-type-options", "nosniff")
                .body(bytes_body("Authentication required — أرسل Authorization: Bearer <كلمة السر>"))
                .unwrap_or_else(|_| internal_error())
        }
    }

    /// صفحة الدخول (GET /login).
    fn serve_login(&self, next: &str) -> Response<RespBody> {
        let next = if safe_next_path(next) {
            html_escape(next)
        } else {
            "/".to_string()
        };
        let page = LOGIN_HTML.replace("__NEXT__", &next);
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .body(bytes_body(page))
            .unwrap_or_else(|_| internal_error())
    }

    /// نقطة الدخول لكل طلب HTTP.
    pub async fn handle(&self, req: Request<Incoming>, peer_ip: IpAddr) -> Response<RespBody> {
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|q| q.to_string()).unwrap_or_default();

        let t_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        log::info!("REQ {} {} {} ?{}", t_ms, req.method(), path, &query[..query.len().min(150)]);

        // ─── المصادقة (اختيارية): كل المسارات ما عدا /login و/health وOPTIONS ───
        if req.method() != Method::OPTIONS
            && path != "/login"
            && path != "/health"
            && !self.is_authenticated(&req)
        {
            // دخول فوري عبر ?password=... — نضع الكوكي ونعيد التوجيه لنفس
            // المسار بلا المعامل (لا يُفضَّح في التاريخ ولا يُمرَّر للهدف).
            if let Some(pw) = extract_query_param(&query, "password") {
                if let Some(pwd) = self.config.proxy_password.as_deref() {
                    if ct_eq(&pw, pwd) {
                        let clean = strip_query_param(&query, "password");
                        let location = if clean.is_empty() {
                            path.clone()
                        } else {
                            format!("{path}?{clean}")
                        };
                        return self
                            .with_auth_cookie(Response::builder().status(StatusCode::FOUND))
                            .header("location", location)
                            .header("x-content-type-options", "nosniff")
                            .body(bytes_body(Bytes::new()))
                            .unwrap_or_else(|_| internal_error());
                    }
                }
            }
            return self.auth_required(&req, &query, &path);
        }

        match path.as_str() {
            // `/p` هو مسار يوتيوب الحديث الداخلي (كل طلباته تصبح /p?url=...)
            // — يُعامل تماماً كـ /proxy (إعادة كتابة + استثناء googlevideo + 302 مباشر).
            "/proxy" | "/p" => {
                // OPTIONS = طلب ما قبل CORS (preflight) من المتصفح لرؤوس/طرق غير بسيطة
                if req.method() == Method::OPTIONS {
                    let t_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
                    log::info!("RESP {} {} {:?} ?{}", t_ms, StatusCode::NO_CONTENT, Some("preflight"), &query[..query.len().min(100)]);
                    return Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .header("access-control-allow-origin", "*")
                        .header("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
                        .header("access-control-allow-headers", "*")
                        .header("access-control-max-age", "86400")
                        .header("x-content-type-options", "nosniff")
                        .body(bytes_body(Bytes::new()))
                        .unwrap_or_else(|_| internal_error());
                }
                if self.rate_limited(peer_ip) {
                    return self.too_many_requests();
                }
                let res = self.proxy_request(req, &query).await;
                let t_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
                log::info!(
                    "RESP {} {} {:?} ?{}",
                    t_ms,
                    res.status(),
                    res.headers().get("content-type").map(|v| v.to_str().unwrap_or("?")),
                    &query[..query.len().min(100)]
                );
                res
            }
            "/ytstream" => self.handle_ytstream(&req, &query).await,
            "/ytstream-hls" => self.handle_ytstream_hls(&req, &query).await,
            "/" | "/index.html" => self.serve_index(),
            "/login" => self.handle_login(req).await,
            "/health" => Response::builder()
                .status(StatusCode::OK)
                .header("x-content-type-options", "nosniff")
                .body(bytes_body("OK"))
                .unwrap_or_else(|_| internal_error()),
            _ => self.cookie_redirect(&req, &query, &path),
        }
    }

    /// بث يوتيوب عبر الخادم: GET /ytstream?video=<videoId>
    ///
    /// المتصفح يرى googlevideo من خلال الخادم فقط (نفس الأصل عبر النفق — لا CORS،
    /// لا po_token، لا روابط مسمومة): yt-dlp (web_safari) يستخرج رابطاً صالحاً
    /// يَفك توقيعات nsig بنفسه، ثم الخادم يبثه chunked للعميل.
    async fn handle_ytstream(&self, req: &Request<Incoming>, query: &str) -> Response<RespBody> {
        let video = match extract_query_param(query, "video") {
            Some(v)
                if !v.is_empty()
                    && v.len() <= 64
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') =>
            {
                v
            }
            _ => return err_response(StatusCode::BAD_REQUEST, "missing or invalid video id"),
        };

        // 1) استخراج رابط بث صالح عبر yt-dlp (مكوّن جاهز)
        let url = match yt_dlp_get_url(&video, "18/best[height<=360]/best").await {
            Ok(u) => u,
            Err(e) => {
                log::warn!("ytstream: extraction failed for {video}: {e}");
                return err_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("extraction failed: {e}"),
                );
            }
        };

        // 2) بث chunked من googlevideo إلى العميل (ذاكرة ثابتة)
        let client = self.client.clone();
        let mut rb = client.get(&url);
        if let Some(range) = req.headers().get("range") {
            if let Ok(r) = range.to_str() {
                rb = rb.header("range", r);
            }
        }
        match rb.send().await {
            Ok(up) => {
                let mut builder = Response::builder().status(up.status());
                for h in [
                    "content-type",
                    "content-length",
                    "content-range",
                    "accept-ranges",
                    "content-disposition",
                ] {
                    if let Some(v) = up.headers().get(h) {
                        builder = builder.header(h, v);
                    }
                }
                let stream = up.bytes_stream().map(|chunk| {
                    chunk.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                });
                builder
                    .header("access-control-allow-origin", "*")
                    .header(
                        "access-control-expose-headers",
                        "accept-ranges, content-range, content-length",
                    )
                    .header("x-content-type-options", "nosniff")
                    .body(stream_body(stream))
                    .unwrap_or_else(|_| internal_error())
            }
            Err(e) => {
                log::warn!("ytstream: upstream request failed for {video}: {e}");
                err_response(StatusCode::BAD_GATEWAY, "upstream stream failed")
            }
        }
    }

    /// بث HLS متعدد الجودات عبر الخادم:
    ///   GET /ytstream-hls?video=<id>[&quality=hls-240|hls-360|hls-480|hls-720|hls-1080|hls/best]
    ///     → yt-dlp يعيد media playlist (m3u8) ويُعاد كتابة كل روابط المقاطع
    ///       إلى /ytstream-hls?u=<مشفَّر> حتى تمر كلها عبر الخادم (لا po_token،
    ///       لا CORS، IP الخروج ثابت).
    ///   GET /ytstream-hls?u=<googlevideo URL مشفَّر> → بث chunked للمورد.
    async fn handle_ytstream_hls(&self, req: &Request<Incoming>, query: &str) -> Response<RespBody> {
        // مورد مُعاد كتابته (مقطع/playlist فرعية)
        if let Some(u) = extract_query_param(query, "u") {
            return self.stream_hls_resource(&u, req).await;
        }

        let video = match extract_query_param(query, "video") {
            Some(v)
                if !v.is_empty()
                    && v.len() <= 64
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') =>
            {
                v
            }
            _ => return err_response(StatusCode::BAD_REQUEST, "missing or invalid video id"),
        };

        // جودة من قائمة مغلقة (يمنع حقن أوامر عبر format). التنسيقات أرقام itag
        // في web_safari (91=144p، 92=240p، 93=360p، 94=480p، 95=720p، 96=1080p)
        // — سلاسل fallback تضمن وصولاً بأعلى جودة متاحة.
        let wanted = extract_query_param(query, "quality").unwrap_or_else(|| "hls-720".into());
        let fmt = match wanted.as_str() {
            "hls-144" => "91/hls/best",
            "hls-240" => "92/91/hls/best",
            "hls-360" => "93/92/91/hls/best",
            "hls-480" => "94/93/92/91/hls/best",
            "hls-1080" => "96/95/94/93/92/91/hls/best",
            "hls/best" => "hls/best",
            _ => "95/94/93/92/91/hls/best",
        };

        let master = match yt_dlp_get_url(&video, fmt).await {
            Ok(u) => u,
            Err(e) => {
                log::warn!("ytstream-hls: extraction failed for {video}: {e}");
                return err_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("extraction failed: {e}"),
                );
            }
        };

        let rewritten = match self.fetch_rewrite_m3u8(&master).await {
            Some(t) => t,
            None => return err_response(StatusCode::BAD_GATEWAY, "upstream playlist failed"),
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/vnd.apple.mpegurl; charset=utf-8")
            .header("access-control-allow-origin", "*")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .body(bytes_body(rewritten))
            .unwrap_or_else(|_| internal_error())
    }

    /// بث مورد HLS مُعاد كتابته (مقطع/playlist) من googlevideo عبر الخادم.
    async fn stream_hls_resource(&self, u: &str, req: &Request<Incoming>) -> Response<RespBody> {
        // نمرر القيمة كما هي (percent-encoded): reqwest يطبّع URL تلقائياً
        // بفك طبقة واحدة — أي فك مسبق هنا يترك sparams مفسودة (403).
        let url = u.trim().to_string();
        if !url.starts_with("https://") || !url.contains("googlevideo.com") {
            return err_response(StatusCode::BAD_REQUEST, "u must be a googlevideo url");
        }

        let client = self.client.clone();
        log::debug!("hls-resource url: {}", &url);
        let mut rb = client.get(&url);
        if let Some(range) = req.headers().get("range") {
            if let Ok(r) = range.to_str() {
                rb = rb.header("range", r);
            }
        }
        match rb.send().await {
            Ok(up) => {
                let status = up.status();
                if status.is_redirection() {
                    let loc = up
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .chars()
                        .take(160)
                        .collect::<String>();
                    log::warn!("hls-resource redirect {status} → {loc}");
                }
                if status == reqwest::StatusCode::FORBIDDEN {
                    log::warn!("hls-resource 403 (url may be expired or poisoned)");
                    return err_response(StatusCode::BAD_GATEWAY, "upstream refused (403)");
                }
                let mut builder = Response::builder().status(status);
                for h in [
                    "content-type",
                    "content-length",
                    "content-range",
                    "accept-ranges",
                    "content-disposition",
                ] {
                    if let Some(v) = up.headers().get(h) {
                        builder = builder.header(h, v);
                    }
                }
                let stream = up.bytes_stream().map(|chunk| {
                    chunk.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                });
                builder
                    .header("access-control-allow-origin", "*")
                    .header(
                        "access-control-expose-headers",
                        "accept-ranges, content-range, content-length",
                    )
                    .header("x-content-type-options", "nosniff")
                    .body(stream_body(stream))
                    .unwrap_or_else(|_| internal_error())
            }
            Err(e) => {
                log::warn!("ytstream-hls: resource fetch failed: {e}");
                err_response(StatusCode::BAD_GATEWAY, "upstream resource failed")
            }
        }
    }

    /// يجلب m3u8 ويستبدل كل روابط المقاطع المطلقة بمسارنا (يمر البث عبر الخادم).
    async fn fetch_rewrite_m3u8(&self, master: &str) -> Option<String> {
        let resp = self.client.get(master).send().await.ok()?;
        let bytes = read_limited(resp, 4 * 1024 * 1024).await?;
        let text = String::from_utf8_lossy(&bytes);
        let mut out = String::with_capacity(text.len() * 3);
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("http://") || t.starts_with("https://") {
                out.push_str("/ytstream-hls?u=");
                out.push_str(&percent_encoding::utf8_percent_encode(t, HLS_U_ENCODE).to_string());
                out.push('\n');
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        Some(out)
    }

    /// معالجة صفحة/نموذج الدخول: GET يعرض النموذج، POST يتحقق من كلمة السر.
    async fn handle_login(&self, req: Request<Incoming>) -> Response<RespBody> {
        let next = req
            .uri()
            .query()
            .and_then(|q| extract_query_param(q, "next"))
            .unwrap_or_else(|| "/".into());

        if req.method() == Method::POST {
            // نموذج form-urlencoded: password=...&next=...
            let body =
                match read_limited_bytes(req.into_body().into_data_stream(), 16 * 1024).await {
                    Some(b) => b,
                    None => return internal_error(),
                };
            let form = String::from_utf8_lossy(&body);
            let mut password: Option<String> = None;
            let mut next_field: Option<String> = None;
            for pair in form.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                let decoded = percent_decode_str(v).decode_utf8().ok().map(|s| s.into_owned());
                match k {
                    "password" => password = decoded,
                    "next" => next_field = decoded,
                    _ => {}
                }
            }
            let next = next_field.unwrap_or(next);
            let next = if safe_next_path(&next) { next } else { "/".into() };

            let ok = match (self.config.proxy_password.as_deref(), password.as_deref()) {
                (Some(pwd), Some(supplied)) => ct_eq(supplied, pwd),
                _ => false,
            };
            if ok {
                return self
                    .with_auth_cookie(
                        Response::builder()
                            .status(StatusCode::SEE_OTHER)
                            .header("location", next),
                    )
                    .header("x-content-type-options", "nosniff")
                    .body(bytes_body(Bytes::new()))
                    .unwrap_or_else(|_| internal_error());
            }
            // كلمة سر خاطئة: نعيد الصفحة مع رسالة خطأ
            let page = LOGIN_HTML
                .replace("__NEXT__", &html_escape(&next))
                .replace("__ERROR__", ERROR_BANNER);
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "text/html; charset=utf-8")
                .header("x-content-type-options", "nosniff")
                .body(bytes_body(page))
                .unwrap_or_else(|_| internal_error());
        }

        self.serve_login(&next)
    }

    /// 429 مع رأس إعادة المحاولة.
    fn too_many_requests(&self) -> Response<RespBody> {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("retry-after", "60")
            .header("x-content-type-options", "nosniff")
            .body(bytes_body("Too many requests — حاول بعد قليل"))
            .unwrap_or_else(|_| internal_error())
    }

    /// الواجهة مدمجة في الثنائي (صفر قراءة قرص عند كل طلب).
    fn serve_index(&self) -> Response<RespBody> {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .body(bytes_body(INDEX_HTML))
            .unwrap_or_else(|_| internal_error())
    }

    /// إعادة توجيه عامة: أي مسار آخر يُوجَّه عبر البروكسي مستخدماً كوكي origin،
    /// أو عبر Referer للطلبات النسبية (JS يبنيها بـ location.host فيرتد إلينا).
    fn cookie_redirect(&self, req: &Request<Incoming>, query: &str, path: &str) -> Response<RespBody> {
        let cookie = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let origin = cookie.as_deref().and_then(extract_origin_cookie);

        // كوكي origin: نمط التصفح الكلاسيكي (المستخدم يفتح /any/path بعد تصفح موقع)
        if let Some(origin) = origin {
            let target = if query.is_empty() {
                format!("{origin}{path}")
            } else {
                format!("{origin}{path}?{query}")
            };
            let encoded = crate::rewrite::proxy_encode(&target);
            return Response::builder()
                .status(StatusCode::FOUND)
                .header("location", format!("/proxy?url={encoded}"))
                .body(bytes_body(Bytes::new()))
                .unwrap_or_else(|_| internal_error());
        }

        // لصق رابط يوتيوب مباشر (بلا كوكي origin): مسارات يوتيوب المعروفة
        // تُوجَّه إلى youtube.com بدل بناء رابط ذاتي (يمنع حلقة 204 الذاتية).
        if is_known_yt_path(path) {
            let target = if query.is_empty() {
                format!("https://www.youtube.com{path}")
            } else {
                format!("https://www.youtube.com{path}?{query}")
            };
            let encoded = crate::rewrite::proxy_encode(&target);
            return Response::builder()
                .status(StatusCode::FOUND)
                .header("location", format!("/proxy?url={encoded}"))
                .body(bytes_body(Bytes::new()))
                .unwrap_or_else(|_| internal_error());
        }

        // طلب نسبي من JS: نبني رابطاً ذاتياً (نطاقنا + المسار) ونجعل /proxy يحلّه
        // عبر Referer، بحيث يذهب فعلاً إلى مضيف الصفحة الأصلية.
        let forwarded_proto = if req.headers().contains_key("x-ytproxy-tls") {
            "https"
        } else {
            req.headers()
                .get("x-forwarded-proto")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("http")
        };
        let host = req
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok().map(|s| s.to_string()))
            })
            .unwrap_or_else(|| "localhost".into());
        let self_target = if query.is_empty() {
            format!("{forwarded_proto}://{host}{path}")
        } else {
            format!("{forwarded_proto}://{host}{path}?{query}")
        };
        let encoded = crate::rewrite::proxy_encode(&self_target);
        Response::builder()
            .status(StatusCode::FOUND)
            .header("location", format!("/proxy?url={encoded}"))
            .body(bytes_body(Bytes::new()))
            .unwrap_or_else(|_| internal_error())
    }

    /// معالجة الطلبات عبر sidecar (python/urllib — بصمة مقبولة لدى جوجل).
    /// البروتوكول: POST http://127.0.0.1:8090/f
    ///   {"method","url","headers":{...},"body_b64":"..."}
    ///   ← {"status", "headers":{...}, "body_b64":"..."}
    async fn sidecar(&self, req: Request<Incoming>, target: &str) -> Response<RespBody> {
        let method = req.method().as_str().to_string();

        let mut headers = serde_json::Map::new();
        let auth_enabled = self.config.proxy_password.is_some();
        for name in FORWARD_HEADERS {
            if auth_enabled && name == "authorization" {
                continue; // Bearer المصادقة المحلية لا يخرج للهدف
            }
            if let Some(v) = req.headers().get(name) {
                if let Ok(s) = v.to_str() {
                    let value = if name == "cookie" {
                        strip_auth_cookie(s)
                    } else {
                        s.to_string()
                    };
                    headers.insert(name.to_string(), serde_json::Value::String(value));
                }
            }
        }
        headers.insert("origin".into(), serde_json::Value::String("https://www.youtube.com".into()));
        headers.insert("referer".into(), serde_json::Value::String("https://www.youtube.com/".into()));
        headers.insert("user-agent".into(), serde_json::Value::String(DEFAULT_UA.into()));

        // قراءة جسم الطلب كاملاً (Waa صغير: بضع كيلوبايت)
        let body = match read_limited_bytes(req.into_body().into_data_stream(), 8 * 1024 * 1024).await
        {
            Some(b) => b,
            None => return internal_error(),
        };

        let body_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &body);

        let payload = serde_json::json!({
            "method": method,
            "url": target,
            "headers": headers,
            "body_b64": body_b64,
        });

        let resp = match self
            .sidecar_client
            .post("http://127.0.0.1:8090/f")
            .json(&payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                log::error!("sidecar unreachable: {e}");
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(bytes_body(format!("sidecar error: {e}")))
                    .unwrap_or_else(|_| internal_error());
            }
        };

        let out: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return internal_error(),
        };

        let status = out["status"].as_u64().unwrap_or(500) as u16;
        let out_headers = out["headers"].as_object().cloned().unwrap_or_default();
        let body_raw = out["body_b64"]
            .as_str()
            .and_then(|s| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).ok())
            .unwrap_or_default();

        let mut builder = Response::builder().status(status);
        for (k, v) in out_headers {
            if let (Ok(kh), Ok(vh)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v.as_str().unwrap_or("")),
            ) {
                builder = builder.header(kh, vh);
            }
        }
        cors_headers(builder)
            .header("x-ytproxy-via", "sidecar")
            .body(bytes_body(Bytes::from(body_raw)))
            .unwrap_or_else(|_| internal_error())
    }
    /// المعالجة الأساسية للبروكسي.
    async fn proxy_request(&self, req: Request<Incoming>, query: &str) -> Response<RespBody> {        // 1) قراءة رابط الهدف
        let target_str = match extract_query_param(query, "url") {
            Some(u) => u,
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(bytes_body("Missing ?url="))
                    .unwrap_or_else(|_| internal_error());
            }
        };

        let target = match Url::parse(&target_str) {
            Ok(u) => u,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(bytes_body("رابط غير صالح"))
                    .unwrap_or_else(|_| internal_error());
            }
        };

        // 2) السماح بـ http/https فقط (حماية SSRF بسيطة)
        if !matches!(target.scheme(), "http" | "https") {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(bytes_body("المخطط غير مدعوم"))
                .unwrap_or_else(|_| internal_error());
        }

        // 2أ) حماية SSRF: حجب الشبكات الخاصة (localhost/10.x/192.168.x/169.254.169.254...)
        //     — البروكسي قد يكون عاماً عبر نفق، فلا يجوز لأي شخص إجباره على
        //     مهاجمة الخادم نفسه أو شبكته الداخلية. يُعطّل بـ ALLOW_PRIVATE=1.
        if !self.config.allow_private && is_private_host(target.host_str().unwrap_or("")) {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("x-content-type-options", "nosniff")
                .body(bytes_body("الهدف ممنوع (عنوان خاص)"))
                .unwrap_or_else(|_| internal_error());
        }

        // 2ب) بث googlevideo: يرفض 403 كل عملاء غير المتصفح (بصمة TLS/ترويسات) —
        //     أي طلب /proxy?url=<googlevideo> يُردّ 302 إلى الرابط الأصلي ليفتحه
        //     المتصفح مباشرة (القرار موثق في مشاكل-حلول/ytproxy-googlevideo-403.md).
        let is_gv_host = target
            .host_str()
            .map(|h| h.ends_with(".googlevideo.com") || h == "googlevideo.com")
            .unwrap_or(false);
        if is_gv_host {
            log::info!("GV-REQS {} -> 302 direct", target.as_str());
            return Response::builder()
                .status(StatusCode::FOUND)
                .header("location", target.as_str())
                .header("x-content-type-options", "nosniff")
                .body(bytes_body(Bytes::new()))
                .unwrap_or_else(|_| internal_error());
        }

        // 2أ) Waa/GenerateIT (po_token): بصمة reqwest مرفوضة 404 من جوجل بينما
        //     urllib/openssl (python) مقبولة — نمرر عبر sidecar (127.0.0.1:8090).
        if target
            .host_str()
            .map(|h| {
                h.ends_with("jnn-pa.googleapis.com") || h.ends_with("waa-pa.googleapis.com")
            })
            .unwrap_or(false)
        {
            return self.sidecar(req, target.as_str()).await;
        }

        // x-ytproxy-tls: وضعناه الخادم نفسه عند الخدمة عبر TLS مباشرة (لا نثق به من الخارج)
        let forwarded_proto = if req.headers().contains_key("x-ytproxy-tls") {
            "https"
        } else {
            req.headers()
                .get("x-forwarded-proto")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("http")
        };
        // HTTP/2 يضع host في :authority وليس في رأس "host"
        let host = req
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok().map(|s| s.to_string()))
            })
            .unwrap_or_else(|| "localhost".into());
        let proxy_origin = format!("{}://{}", forwarded_proto, host);

        // وضع الحجب الشامل أُزيل: كل الروابط تمر الآن عبر البروكسي (إعادة
        // الكتابة في rewrite.rs تحوّل كل شيء إلى /proxy?url=...) بعد نجاح
        // native-tls — لم يعد هناك "خوادم مباشرة" مستثناة.
        // raw=1: بث المحتوى كما هو (لا إعادة كتابة HTML/CSS ولا حقن سكربت).
        // يُستخدم مع إضافات المتصفح (Redirector) التي تعيد توجيه كل طلب بنفسها.
        let raw = extract_query_param(query, "raw").is_some();

        // 3) الطلب الذاتي: JS المواقع يبني روابط نسبية بـ location.host (نطاقنا)
        //    فترتد إلينا. نستخرج الأصل الحقيقي من Referer ونعيد توجيه الطلب.
        let mut target = target;
        if is_self_origin(&target, &proxy_origin) {
            let refdbg = req
                .headers()
                .get("referer")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("NONE");
            let ogdbg = req.headers().get("origin").and_then(|v| v.to_str().ok()).unwrap_or("NONE");
            info!("SELF {} REF={} ORIGIN={} PATH={}", target.as_str(), refdbg, ogdbg, target.path());            match resolve_self_target(&req, &target) {
                Some(real) => target = real,
                None => {
                    // نبضة حياة أو طلب عديم المرجع: 204 صامت يمنع ضجيج 404
                    return Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(bytes_body(Bytes::new()))
                        .unwrap_or_else(|_| internal_error());
                }
            }
        }

        // 4) بناء الطلب الخارجي
        let method = req.method().clone();
        let is_yt = is_yt_host(target.host_str().unwrap_or(""));
        // فيسبوك يرد 400 على "UA يدّعي متصفحاً + بصمة اتصال غير متصفحة" (قاعدة
        // SLB فورية). نرسل له UA صادقاً بدل تمرير UA المتصفح — موثق في docs/حلول.md#5.
        let is_fb = target
            .host_str()
            .map(|h| h.ends_with("facebook.com") || h.ends_with("fbcdn.net"))
            .unwrap_or(false);
        let is_player_api = target.path().contains("youtubei/v1/player")
            || target.path().contains("youtubei/v1/next");

        // ترويسات الطلب الخارجي تُجمع هنا وتُطبَّق في send_with (كل استدعاء).
        let mut base_headers: Vec<(&'static str, String)> = vec![
            ("accept-language", "en-US,en;q=0.9,ar;q=0.8".to_string()),
        ];

        // واجهات player: يوتيوب يرفض الطلبات بلا Origin/Referer صحيحين (UNPLAYABLE)
        if is_player_api {
            base_headers.push(("origin", "https://www.youtube.com".to_string()));
            base_headers.push(("referer", "https://www.youtube.com/".to_string()));
            base_headers.push(("x-youtube-client-name", "1".to_string()));
            base_headers.push(("x-youtube-client-version", "2.20250801.00.00".to_string()));
        }

        // Waa/GenerateIT (po_token): بدون Origin/Referer صحيحين و UA متصفح
        // يرد 404 — نفس الطلب من المتصفح مباشرة ينجح 200 بلا تعديل.
        let is_waa = target
            .host_str()
            .map(|h| h.ends_with("jnn-pa.googleapis.com") || h.ends_with("waa-pa.googleapis.com"))
            .unwrap_or(false);
        if is_waa {
            base_headers.push(("origin", "https://www.youtube.com".to_string()));
            base_headers.push(("referer", "https://www.youtube.com/".to_string()));
            if req.headers().get("user-agent").is_none() {
                base_headers.push(("user-agent", DEFAULT_UA.to_string()));
            }
        }

        // بث googlevideo: يرفض طلبات بلا Accept-Language صحيحة أو التي تطلب
        // ضغطاً (br/zstd) من عملاء غير المتصفح — أضف Accept-Language واترك
        // Accept-Encoding identity (الميزات أُزيلت من Cargo.toml).
        let is_gv = target
            .host_str()
            .map(|h| h.ends_with("googlevideo.com"))
            .unwrap_or(false);
        if is_gv {
            base_headers.push(("origin", "https://www.youtube.com".to_string()));
            base_headers.push(("referer", "https://www.youtube.com/".to_string()));
            base_headers.push(("accept-language", "en-US,en;q=0.5".to_string()));
            base_headers.push(("accept-encoding", "identity".to_string()));
        }

        // ترويسات المستخدم نحو الهدف: نمرّرها مع استثناءين للمصادقة المحلية:
        // - كوكي ytproxy_auth لا يخرج أبداً للموقع الهدف
        // - رأس Authorization حين يكون مصادقتنا (Bearer كلمة السر) لا يُمرَّر
        let auth_enabled = self.config.proxy_password.is_some();
        for name in FORWARD_HEADERS {
            if auth_enabled && name == "authorization" {
                continue;
            }
            if let Some(value) = req.headers().get(name) {
                if let Ok(s) = value.to_str() {
                    if is_fb && name == "user-agent" {
                        continue;
                    }
                    if name == "cookie" {
                        let cleaned = strip_auth_cookie(s);
                        if !cleaned.is_empty() {
                            base_headers.push((name, cleaned));
                        }
                        continue;
                    }
                    base_headers.push((name, s.to_string()));
                }
            }
        }

        // UA افتراضي: curl/سكربتات بلا UA → UA متصفح (يمنع 403 من جوجل).
        // فيسبوك بالعكس: نرسل دائماً UA صادقاً (المتصفح ممرَّر أُسقط أعلاه)
        // لأن بصمة خروجنا ليست بصمة متصفح → 400 مع UA متصفح (مثبت تجريبياً).
        if is_fb {
            base_headers.push(("user-agent", "curl/8.5.0".to_string()));
        } else if req.headers().get("user-agent").is_none() {
            base_headers.push(("user-agent", DEFAULT_UA.to_string()));
        }

        // كوكيز جلسة يوتيوب: تُدمج (كوكيز المستخدم تأتي أولاً إن وُجدت).
        // ملاحظة: خوادم البث googlevideo لا تُرسل إليها كوكيز الجرة — المتصفح المباشر
        // يعمل بها فقط لأنها كوكيز صفحته؛ روابط البث العامة تُقبل بلا كوكيز، وتمرير
        // جرة قديمة يُسبب 403.
        // بلا كوكيز لـ googlevideo وواجهات player: الجرة (جلسة خادم بلا بصمة متصفح)
        // تجعل يوتيوب يُصدر روابط بث مقيدة بـ po_token (تُفشل)، بينما الطلب العام
        // بلا كوكيز يُصدر روابط صالحة مباشرة (كما يفعل المتصفح الخالي من الكوكيز).
        if is_yt && !is_gv && !is_player_api {
            if let Some(yt) = self.yt_cookies.lock().await.clone() {
                let user_cookie = req
                    .headers()
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .map(strip_auth_cookie)
                    .unwrap_or_default();
                let merged = if user_cookie.is_empty() {
                    yt
                } else {
                    format!("{user_cookie}; {yt}")
                };
                base_headers.push(("cookie", merged));
            }
        }

        // جسم الطلب الخارجي: مجمّع (للواجهات — يسمح بإعادة المحاولة) أو بث مباشر (كل الباقي)
        enum ReqBody {
            Empty,
            Cached(Bytes),
            Stream(Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send + Unpin>),
        }
        let mut body = if is_player_api
            && matches!(method, Method::POST | Method::PUT | Method::PATCH)
        {
            match read_limited_bytes(req.into_body().into_data_stream(), 16 * 1024 * 1024).await {
                Some(b) => ReqBody::Cached(b),
                None => ReqBody::Empty, // كبير بشكل غير متوقع: بلا جسم (نادر)
            }
        } else if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            ReqBody::Stream(Box::new(req.into_body().into_data_stream().map(|c| {
                c.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            })))
        } else {
            ReqBody::Empty
        };

        // نسخة للـ retry (Bytes = Arc، النسخ رخيص)
        let cached_retry = match &body {
            ReqBody::Cached(b) => Some(b.clone()),
            _ => None,
        };

        let client = self.client.clone();

        // 4) تنفيذ الطلب مع إعادة محاولة عند رفض يوتيوب
        // `use_timeout`: مهلة الطلب الكلية تُطبَّق فقط على الطلبات غير المُبثَّة
        // (واجهات API صغيرة) — البث المباشر الطويل (فيديو) لا يُقيَّد بها وإلا
        // انقطع الفيديو أثناء التخزين المؤقت.
        let send_with = |client: &reqwest::Client,
                         target_url: &str,
                         body: Option<&Bytes>,
                         headers_extra: Vec<(&str, String)>,
                         use_timeout: bool| {
            let mut r = client.request(method.clone(), target_url);
            for (k, v) in &base_headers {
                r = r.header(*k, v);
            }
            for (k, v) in headers_extra {
                r = r.header(k, v);
            }
            if use_timeout {
                r = r.timeout(self.config.request_timeout);
            }
            if let Some(b) = body {
                r = r.body(b.clone());
            }
            r
        };

        let mut upstream = match &body {
            ReqBody::Cached(b) => send_with(&client, target.as_str(), Some(b), vec![], true)
                .send()
                .await,
            ReqBody::Stream(_) => {
                let ReqBody::Stream(s) = std::mem::replace(&mut body, ReqBody::Empty) else {
                    unreachable!()
                };
                send_with(&client, target.as_str(), None, vec![], false)
                    .body(reqwest::Body::wrap_stream(s))
                    .send()
                    .await
            }
            ReqBody::Empty => send_with(&client, target.as_str(), None, vec![], true)
                .send()
                .await,
        };

        // إعادة محاولة واحدة بمفتاح WEB_EMBEDDED_PLAYER عند 403/401 من واجهات يوتيوب
        if is_player_api {
            if let Some(body) = cached_retry.as_ref() {
                if let Ok(resp) = &upstream {
                    if matches!(
                        resp.status(),
                        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
                    ) {
                        log::warn!(
                            "يوتيوب رفض الطلب ({}) — إعادة محاولة بمفتاح بديل",
                            resp.status()
                        );
                        let alt_url = target.as_str().replace(YT_KEY_WEB, YT_KEY_EMBEDDED);
                        upstream = send_with(&client, &alt_url, Some(body), vec![], true)
                            .send()
                            .await;
                    }
                }
            }
        }

        let upstream = match upstream {
            Ok(resp) => resp,
            Err(e) => {
                warn!("طلب خارجي فشل: {e}");
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(bytes_body(format!("فشل الاتصال بالموقع: {e}")))
                    .unwrap_or_else(|_| internal_error());
            }
        };

        let status = upstream.status();
        let content_type = upstream
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let is_html = content_type.contains("text/html");
        let is_css = content_type.contains("text/css");

        // 5) بناء الرد: نسخ رؤوس الهدف مع استثناءات
        let mut builder = Response::builder().status(status);
        let mut set_cookies: Vec<HeaderValue> = Vec::new();

        for (name, value) in upstream.headers() {
            match name.as_str().to_ascii_lowercase().as_str() {
                // hop-by-hop + رؤوس تخص الطبقة النقلية: لا نمررها أبداً
                "content-length" | "transfer-encoding" | "connection" | "keep-alive"
                | "content-encoding" => {}
                // رؤوس أمان تعطّل البروكسي → تُحذف عمداً
                "content-security-policy" | "content-security-policy-report-only"
                | "strict-transport-security" | "cross-origin-opener-policy"
                | "content-security-policy-ro" => {
                    debug!("إزالة رأس أمان: {}", name);
                }
                "set-cookie" => set_cookies.push(value.clone()),
                _ => {
                    builder = builder.header(name, value);
                }
            }
        }

        // إعادة كتابة Location إن وُجدت (redirect مرتجع بعد استنفاد الحد)
        if let Some(loc) = builder.headers_ref().and_then(|h| h.get("location").cloned()) {
            if let Ok(loc_str) = loc.to_str() {
                if let Ok(absolute) = target.join(loc_str) {
                    if !loc_str.starts_with("/proxy?url=") {
                        let encoded = crate::rewrite::proxy_encode(absolute.as_str());
                        if let Ok(v) = HeaderValue::from_str(&format!("/proxy?url={encoded}")) {
                            builder = builder.header("location", v);
                        }
                    }
                }
            }
        }

        // 6) الجسم
        if raw {
            // وضع امتداد المتصفح: لا نعدّل أي شيء — الامتداد يعترض كل الطلبات.
            let bytes = match read_limited(upstream, self.config.text_max_bytes * 4).await {
                Some(b) => b,
                None => {
                    return cors_headers(builder)
                        .body(bytes_body(Bytes::new()))
                        .unwrap_or_else(|_| internal_error());
                }
            };
            let builder = append_set_cookies(builder, &set_cookies);
            return cors_headers(builder)
                .body(bytes_body(bytes))
                .unwrap_or_else(|_| internal_error());
        } else if is_html || is_css {
            // نقرأ بحد أقصى؛ إن تجاوز → نبث كما هو دون إعادة كتابة
            let bytes = match read_limited(upstream, self.config.text_max_bytes).await {
                Some(b) => b,
                None => {
                    return cors_headers(builder)
                        .body(bytes_body(Bytes::new()))
                        .unwrap_or_else(|_| internal_error());
                }
            };

            if is_html {
                match rewrite_html(&bytes, &target, &proxy_origin, self.config.text_max_bytes) {
                    Some(rewritten) => {
                        let builder = append_set_cookies(builder, &set_cookies);
                        return cors_headers(builder)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(bytes_body(rewritten))
                            .unwrap_or_else(|_| internal_error());
                    }
                    None => {
                        let builder = append_set_cookies(builder, &set_cookies);
                        return cors_headers(builder)
                            .body(bytes_body(bytes))
                            .unwrap_or_else(|_| internal_error());
                    }
                }
            } else {
                let rewritten = rewrite_css(&bytes, &target, &proxy_origin);
                let builder = append_set_cookies(builder, &set_cookies);
                return cors_headers(builder)
                    .header("content-type", "text/css; charset=utf-8")
                    .body(bytes_body(rewritten))
                    .unwrap_or_else(|_| internal_error());
            }
        }

        // 7) بث مباشر (فيديو، صور، JSON، ...) — ذاكرة ثابتة
        let content_length = upstream.content_length();
        let stream = upstream.bytes_stream().map(|chunk| {
            chunk.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        });
        let mut builder = append_set_cookies(builder, &set_cookies);
        builder = cors_headers(builder)
            .header(
                "access-control-expose-headers",
                "accept-ranges, content-range, content-length",
            )
            // يسمح بتضمين الموارد عبر الأصل — يزيل حجب ORB/CORP
            .header("cross-origin-resource-policy", "cross-origin");

        // نمرر طول المحتوى ونطاقه في البث المباشر (غير المُعاد كتابته) حتى
        // يعرف المتصفح الحجم ويتيح التخطي (seek) وعرض شريط التقدم
        if let Some(cl) = content_length {
            builder = builder.header("content-length", cl.to_string());
        }

        // نوع محتوى افتراضي إن غاب (يمنع حجب المتصفح للموارد عديمة النوع)
        let has_ct = builder
            .headers_ref()
            .and_then(|h| h.get("content-type"))
            .is_some();
        if !has_ct {
            if let Some(guess) = guess_content_type(target.path()) {
                builder = builder.header("content-type", guess);
            }
        }

        builder
            .body(stream_body(stream))
            .unwrap_or_else(|_| internal_error())
    }
}

/// تخمين نوع المحتوى من المسار عند غياب الترويسة.
fn guess_content_type(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    Some(match ext {
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "m4a" | "mp3" | "aac" => "audio/mpeg",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "wasm" => "application/wasm",
        "xml" => "text/xml",
        _ => return None,
    })
}

/// قراءة جسم بحد أقصى من مجرى بيانات؛ `None` إذا تجاوز الحد أو فشل.
async fn read_limited_bytes<S, E>(mut stream: S, max: usize) -> Option<Bytes>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    let mut buf = Vec::with_capacity((max.min(1 << 20)) as usize);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if buf.len() + chunk.len() > max {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(Bytes::from(buf))
}

fn append_set_cookies(mut builder: http::response::Builder, set_cookies: &[HeaderValue]) -> http::response::Builder {
    for c in set_cookies {
        builder = builder.header(SET_COOKIE, c);
    }
    builder
}

/// قراءة جسم استجابة بحد أقصى؛ `None` إذا تجاوز الحد.
async fn read_limited(resp: reqwest::Response, max: usize) -> Option<Bytes> {
    let mut buf = Vec::with_capacity((max.min(1 << 20)) as usize);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if buf.len() + chunk.len() > max {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(Bytes::from(buf))
}

/// استخراج معامل من query string مع فك ترميزه.
fn extract_query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k != key {
            return None;
        }
        percent_decode_str(v).decode_utf8().ok().map(|s| s.into_owned())
    })
}

/// هل المسار من مسارات يوتيوب الشائعة عند لصق رابط مباشر؟
fn is_known_yt_path(path: &str) -> bool {
    path == "/watch"
        || path == "/results"
        || path == "/playlist"
        || path == "/live"
        || path == "/shorts"
        || path.starts_with("/@")
        || path.starts_with("/shorts/")
        || path.starts_with("/c/")
        || path.starts_with("/channel/")
        || path.starts_with("/user/")
        || path.starts_with("/embed/")
        || path.starts_with("/playlist?")
}

/// استخراج كوكي proxy_origin من رأس Cookie.
fn extract_origin_cookie(cookie_header: &str) -> Option<String> {
    cookie_header.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (k, v) = pair.split_once('=')?;
        if k == "proxy_origin" {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// هروب قيم سمات HTML (للحقول المخفية) — المتصفح يرمّز النموذج مرة واحدة
/// عند الإرسال، فلا نرمّز نحن هنا.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// استخراج رابط بث صالح عبر yt-dlp (عميل web_safari: يَفك توقيعات nsig ولا
/// يتطلب po_token للـ HLS/GVS حالياً). يُحوَّل عبر Argument (لا shell) بعد
/// تحقق المتصل من video id والتنسيق من قائمة مغلقة.
async fn yt_dlp_get_url(video: &str, format: &str) -> Result<String, String> {
    let watch = format!("https://www.youtube.com/watch?v={video}");
    let args = [
        "--extractor-args",
        "youtube:player_client=web_safari",
        "-g",
        "-f",
        format,
        "--no-download",
        "--no-warnings",
        "--no-playlist",
        "--playlist-items",
        "1",
        &watch,
    ];
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::process::Command::new("/usr/local/bin/yt-dlp")
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await
    .map_err(|_| "yt-dlp timeout".to_string())?
    .map_err(|e| format!("yt-dlp spawn: {e}"))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!(
            "yt-dlp exit {:?}: {}",
            out.status.code(),
            err.chars().take(300).collect::<String>()
        ));
    }
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if line.is_empty() {
        return Err("yt-dlp returned no url".to_string());
    }
    Ok(line)
}

/// استجابة خطأ نصية بسيطة.
fn err_response(status: StatusCode, msg: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(bytes_body(msg.to_string()))
        .unwrap_or_else(|_| internal_error())
}

fn internal_error() -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(bytes_body("خطأ داخلي"))
        .unwrap()
}

/// الواجهة مدمجة في الثنائي (عدّل public/index.html ثم rebuild).
pub const INDEX_HTML: &str = include_str!("../public/index.html");

/// شريط خطأ يُستبدل في صفحة الدخول عند كلمة سر خاطئة.
const ERROR_BANNER: &str = r#"<div style="background:#3b1216;border:1px solid #7f1d1d;color:#fca5a5;padding:12px 16px;border-radius:10px;margin-bottom:18px;font-size:14px;text-align:center">كلمة السر غير صحيحة — حاول مجدداً</div>"#;

/// صفحة الدخول (مدمجة — بلا ملفات خارجية). __NEXT__ يُستبدل بالوجهة المراد
/// العودة إليها و__ERROR__ بشريط الخطأ (فارغ عند أول عرض).
const LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>دخول — ytproxy</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Tahoma, sans-serif;
    background: radial-gradient(1200px 600px at 50% -10%, #1a2332 0%, #0d1117 55%, #0a0e14 100%);
    min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
  }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 16px;
    padding: 36px 32px; width: 100%; max-width: 380px; box-shadow: 0 20px 60px rgba(0,0,0,.5);
  }
  .logo { font-size: 34px; text-align: center; margin-bottom: 8px; }
  h1 { color: #e6edf3; font-size: 22px; text-align: center; margin-bottom: 6px; }
  p.sub { color: #8b949e; font-size: 14px; text-align: center; margin-bottom: 24px; }
  input[type=password] {
    width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #30363d;
    background: #0d1117; color: #e6edf3; font-size: 15px; outline: none; margin-bottom: 16px;
  }
  input[type=password]:focus { border-color: #2f81f7; box-shadow: 0 0 0 3px rgba(47,129,247,.15); }
  button {
    width: 100%; padding: 12px; border: 0; border-radius: 10px; background: #238636; color: #fff;
    font-size: 15px; font-weight: 600; cursor: pointer; transition: background .15s;
  }
  button:hover { background: #2ea043; }
  .hint { margin-top: 18px; color: #6e7681; font-size: 12px; text-align: center; }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">🛡️</div>
    <h1>دخول محمي</h1>
    <p class="sub">هذا البروكسي خاص — أدخل كلمة السر للمتابعة</p>
    __ERROR__
    <form method="POST" action="/login">
      <input type="hidden" name="next" value="__NEXT__">
      <input type="password" name="password" placeholder="كلمة السر" autofocus required>
      <button type="submit">دخول</button>
    </form>
    <div class="hint">ytproxy — بروكسي خفيف وسريع</div>
  </div>
</body>
</html>"#;

use http::header::{HeaderValue, SET_COOKIE};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_url_param() {
        let q = "url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dabc&x=1";
        assert_eq!(
            extract_query_param(q, "url"),
            Some("https://www.youtube.com/watch?v=abc".into())
        );
    }

    #[test]
    fn decodes_plain_url() {
        assert_eq!(
            extract_query_param("url=https://example.com/a?b=1", "url"),
            Some("https://example.com/a?b=1".into())
        );
    }

    #[test]
    fn missing_param_returns_none() {
        assert_eq!(extract_query_param("x=1", "url"), None);
    }

    #[test]
    fn private_hosts_are_blocked() {
        for h in [
            "127.0.0.1",
            "127.0.0.2",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "::ffff:10.0.0.1",
            "fc00::1",
            "fe80::1",
            "localhost",
            "router.local",
            "nas.home",
            "foo.internal",
        ] {
            assert!(is_private_host(h), "يجب حجب {h}");
        }
    }

    #[test]
    fn public_hosts_are_allowed() {
        for h in [
            "www.youtube.com",
            "i.ytimg.com",
            "rr1---sn-googlevideo.com",
            "8.8.8.8",
            "1.1.1.1",
            "example.com.",
            "2606:4700::1111",
        ] {
            assert!(!is_private_host(h), "يجب السماح بـ {h}");
        }
    }

    #[test]
    fn ipv4_private_ranges() {
        assert!(is_private_ipv4("192.168.0.1".parse().unwrap()));
        assert!(is_private_ipv4("224.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4("203.0.113.9".parse().unwrap()));
        assert!(!is_private_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ipv4("104.20.0.1".parse().unwrap()));
    }

    #[test]
    fn auth_token_is_stable_and_distinct() {
        assert_eq!(auth_token("secret"), auth_token("secret"));
        assert_ne!(auth_token("secret"), auth_token("secret2"));
        assert_eq!(auth_token("secret").len(), 16); // hex 64-bit
    }

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "a"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn strip_auth_cookie_removes_only_ours() {
        let header = "ytproxy_auth=abc123; proxy_origin=https://youtube.com; VISITOR_INFO1_LIVE=xyz";
        let cleaned = strip_auth_cookie(header);
        assert!(!cleaned.contains("ytproxy_auth"));
        assert!(cleaned.contains("proxy_origin=https://youtube.com"));
        assert!(cleaned.contains("VISITOR_INFO1_LIVE=xyz"));
    }

    #[test]
    fn strip_query_param_removes_password_keeps_rest() {
        let q = "url=https%3A%2F%2Fyoutube.com&password=secret&raw=1";
        let cleaned = strip_query_param(q, "password");
        assert_eq!(cleaned, "url=https%3A%2F%2Fyoutube.com&raw=1");
        assert_eq!(strip_query_param("password=only", "password"), "");
    }

    #[test]
    fn safe_next_rejects_open_redirects() {
        assert!(safe_next_path("/proxy?url=x"));
        assert!(safe_next_path("/"));
        assert!(!safe_next_path("//evil.com"));
        assert!(!safe_next_path("https://evil.com"));
        assert!(!safe_next_path("/x\r\nSet-Cookie: x"));
    }
}
