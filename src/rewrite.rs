//! إعادة كتابة HTML/CSS:
//! - تحويل كل الروابط إلى روابط بروكسي مطلقة (لا تعتمد على `<base>` الذي قد تحجبه CSP)
//! - حقن سكربت يعترض fetch/XHR ويعالج `<base>` ويوقف Service Workers
//! - إعادة كتابة `url(...)` داخل CSS
//!
//! يُستخدم `lol_html` (محرك Cloudflare) لأنه بثّي: لا يبني DOM كاملاً،
//! فيستهلك ذاكرة ثابتة تقريباً حتى لصفحات YouTube الضخمة (~2MB).

use lol_html::{element, html_content::ContentType, HtmlRewriter, Settings};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use url::Url;

/// ترميز مضغوط لرابط الهدف داخل معامل `url=`:
/// يُبقي النقاط والشرطات والروابط قراءة، ويُرمّز فقط ما يكسر query string.
pub(crate) const PROXY_URL_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'=')
    .add(b'+')
    .add(b'?')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// ترميز رابط هدف بصيغة البروكسي الموحدة.
pub(crate) fn proxy_encode(url: &str) -> String {
    utf8_percent_encode(url, PROXY_URL_ENCODE).to_string()
}

/// السكربت المحقون في `<head>` قبل أي سكربت آخر في الصفحة.
/// وظائفه:
/// 1. إنشاء `<base href="origin الهدف">` إن لم يوجد (حتى تُحل الروابط النسبية نحو الموقع الأصلي).
/// 2. اعتراض fetch / XMLHttpRequest وإعادة كتابة عناوينها عبر البروكسي.
/// 3. إلغاء تسجيل Service Workers (تعطّل البروكسي).
fn injected_script(target_origin: &str) -> String {
    // target_origin يُدرج داخل نص سكربت: ننظفه من أي `</script>` أو `\` ضار.
    let safe = target_origin.replace('\\', "\\\\").replace("'", "\\'");
    format!(
        r#"<script>
(function() {{
    var TARGET = '{safe}';
    if (TARGET && !document.querySelector('base')) {{
        var b = document.createElement('base');
        b.href = TARGET;
        document.head.appendChild(b);
    }}
    var proxyPrefix = location.origin + '/proxy?url=';
    function rewriteUrl(url) {{
        if (!url || url.indexOf('data:') === 0 || url.indexOf('blob:') === 0 ||
            url.indexOf('#') === 0 || url.indexOf('mailto:') === 0 ||
            url.indexOf('/proxy?url=') !== -1) return url;
        try {{
            var absolute = new URL(url, document.baseURI).href;
            // بث googlevideo: يرفض 403 كل ما ليس متصفحاً — يبقى الرابط كما هو
            // ليتصل المتصفح مباشرة (القرار موثق في ytproxy-googlevideo-403.md).
            if (absolute.indexOf('googlevideo.com') !== -1) return absolute;
            // JS الموقع يبني روابط مطلقة بـ location.origin (نطاقنا) — أعد توجيهها للهدف الحقيقي
            var selfPrefix = location.origin + '/';
            if (absolute.indexOf(selfPrefix) === 0) {{
                absolute = TARGET + absolute.slice(selfPrefix.length - 1);
            }}
            return proxyPrefix + encodeURIComponent(absolute);
        }} catch (e) {{ return url; }}
    }}
    var originalFetch = window.fetch;
    window.fetch = function(input, init) {{
        if (typeof input === 'string') {{ input = rewriteUrl(input); }}
        else if (input && input.url) {{ input = new Request(rewriteUrl(input.url), input); }}
        return originalFetch.call(this, input, init);
    }};
    var originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {{
        url = rewriteUrl(url);
        return originalOpen.call(this, method, url, async !== false, user, password);
    }};
    if (navigator.serviceWorker) {{
        navigator.serviceWorker.getRegistrations().then(function(regs) {{
            regs.forEach(function(r) {{ r.unregister(); }});
        }});
    }}
}})();
</script>"#
    )
}

/// هل القيمة تستحق إعادة الكتابة؟
fn should_rewrite(val: &str) -> bool {
    if val.is_empty() {
        return false;
    }
    for prefix in ["data:", "javascript:", "blob:", "mailto:", "tel:", "#", "/proxy?url="] {
        if val.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// بناء رابط بروكسي مطلق من قيمة سمة + أصل الهدف + أصل البروكسي.
/// كل الروابط تمر عبر البروكسي (الخادم يصلح الترويسات) — ضروري لأن المتصفح
/// من نطاقنا لا يستطيع جلب الموارد مباشرة بسبب CORS.
fn proxy_url(proxy_origin: &str, target: &Url, val: &str) -> Option<String> {
    let absolute = target.join(val).ok()?;
    // بث googlevideo يرفض 403 كل عملاء غير المتصفح (بصمة TLS/ترويسات) — لا نعيد
    // كتابة روابطه، يفتحها المتصفح مباشرة (القرار موثق في مشاكل-حلول/ytproxy-googlevideo-403.md).
    // full=true: استثناء لمن يريد إجبار كل شيء عبر البروكسي.
    let gv = absolute
        .host_str()
        .map(|h| h.ends_with(".googlevideo.com") || h == "googlevideo.com")
        .unwrap_or(false);
    if gv && val.find("full=true").is_none() {
        return None;
    }
    Some(format!("{proxy_origin}/proxy?url={}", proxy_encode(absolute.as_str())))
}

/// إعادة كتابة HTML بثّياً عبر lol_html.
/// تعيد `None` إذا تجاوزت الصفحة `max_bytes` (يُبث حينها كما هي).
pub fn rewrite_html(
    html: &[u8],
    target: &Url,
    proxy_origin: &str,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    if html.len() > max_bytes {
        return None;
    }

    let script = injected_script(target.origin().ascii_serialization().as_str());
    let mut output = Vec::with_capacity(html.len() + 4096);

    let mut settings = Settings::default();
    settings.memory_settings.max_allowed_memory_usage = max_bytes;

    // الروابط في السمات الشائعة (action للنماذج له معالجة مخصصة أدناه)
    settings.element_content_handlers.push(element!(
        "[href], [src], [poster]",
        |el| {
            for attr in ["href", "src", "poster"] {
                if let Some(val) = el.get_attribute(attr) {
                    if should_rewrite(&val) {
                        if let Some(p) = proxy_url(proxy_origin, target, &val) {
                            let _ = el.set_attribute(attr, &p);
                        }
                    }
                }
            }
            Ok(())
        }
    ));

    // النماذج: المتصفح يستبدل query الـ action بحقول النموذج عند الإرسال، لذا
    // ?url= في action تُمسح (خطأ "Missing ?url=" في بحث قوقل). ننقل الهدف إلى
    // حقل مخفي name=url ونترك action = /proxy — تُدمج حقول النموذج في الهدف
    // لاحقاً في proxy_request (دمج query الطلب).
    settings.element_content_handlers.push(element!("form", |el| {
        let val = el.get_attribute("action").unwrap_or_default();
        let rewritten = if val.trim().is_empty() || val.trim() == "#" {
            // إرسال لنفس الصفحة: الهدف هو الصفحة الحالية
            Some(format!("{proxy_origin}/proxy?url={}", proxy_encode(target.as_str())))
        } else {
            proxy_url(proxy_origin, target, &val)
        };
        if let Some(p) = rewritten {
            if let Some((base, enc)) = p.split_once("url=") {
                let base = base.trim_end_matches('?');
                let _ = el.set_attribute("action", base);
                let hidden = format!(r#"<input type="hidden" name="url" value="{enc}">"#);
                let _ = el.prepend(&hidden, ContentType::Html);
            }
        }
        Ok(())
    }));

    // srcset (صور متجاوبة)
    settings.element_content_handlers.push(element!("[srcset]", |el| {
        if let Some(srcset) = el.get_attribute("srcset") {
            let mut out = String::with_capacity(srcset.len() + 128);
            for part in srcset.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let mut pieces = part.splitn(2, char::is_whitespace);
                let url = pieces.next().unwrap_or("");
                let rest = pieces.next().unwrap_or("");
                if should_rewrite(url) {
                    if let Some(p) = proxy_url(proxy_origin, target, url) {
                        if !out.is_empty() {
                            out.push(',');
                        }
                        out.push_str(&p);
                        if !rest.is_empty() {
                            out.push(' ');
                            out.push_str(rest);
                        }
                        continue;
                    }
                }
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(part);
            }
            let _ = el.set_attribute("srcset", &out);
        }
        Ok(())
    }));

    // إزالة `integrity` (بعد إعادة الكتابة لم يعد SRI صحيحاً — كسره يكسر الصفحة)
    settings.element_content_handlers.push(element!("[integrity]", |el| {
        let _ = el.remove_attribute("integrity");
        Ok(())
    }));

    // حقن السكربت في بداية <head>
    settings.element_content_handlers.push(element!("head", |el| {
        el.prepend(&script, ContentType::Html);
        Ok(())
    }));

    let mut rewriter = HtmlRewriter::new(settings, |c: &[u8]| output.extend_from_slice(c));
    if rewriter.write(html).is_err() {
        return None;
    }
    if rewriter.end().is_err() {
        return None;
    }
    Some(output)
}

/// إعادة كتابة CSS: تحويل `url(...)` إلى روابط بروكسي مطلقة (عبر regex بسيط وسريع).
pub fn rewrite_css(css: &[u8], target: &Url, proxy_origin: &str) -> Vec<u8> {
    let css_str = match std::str::from_utf8(css) {
        Ok(s) => s,
        Err(_) => return css.to_vec(),
    };

    // لا يدعم regex في Rust المراجع الخلفية — نلتقط القيمة بثلاث صيغ (اقتباس مفرد/مزدوج/بدون).
    let re = match regex::Regex::new(r#"url\(\s*(?:'([^']*)'|"([^"]*)"|([^'")]*))\s*\)"#) {
        Ok(r) => r,
        Err(_) => return css.to_vec(),
    };

    re.replace_all(css_str, |caps: &regex::Captures| {
        let value = caps
            .iter()
            .skip(1)
            .find_map(|g| g)
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if should_rewrite(value) {
            if let Some(p) = proxy_url(proxy_origin, target, value) {
                return format!("url(\"{p}\")");
            }
        }
        caps.get(0).map(|m| m.as_str().to_string()).unwrap_or_default()
    })
    .into_owned()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Url {
        Url::parse("https://www.youtube.com/").unwrap()
    }

    #[test]
    fn html_rewrites_links_and_srcset() {
        let html = br#"<html><head><link rel="stylesheet" href="/s/desktop.css"></head>
        <body><img src="https://i.ytimg.com/x.jpg" srcset="/a.jpg 1x, https://b.com/b.jpg 2x">
        <a href="/watch?v=1">v</a><script src="data:foo"></script></body></html>"#;
        let out = rewrite_html(html, &target(), "http://p.local:8080", 1 << 20).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("http://p.local:8080/proxy?url=https://www.youtube.com/s/desktop.css"), "link rewrite");
        assert!(s.contains("https://i.ytimg.com/x.jpg"), "img rewrite");
        assert!(s.contains("www.youtube.com/watch%3Fv%3D1"), "href rewrite");
        assert!(s.contains("data:foo"), "data: untouched");
        assert!(s.contains("<script>"), "interceptor injected");
    }

    #[test]
    fn html_skips_already_proxied() {
        let html = br##"<img src="/proxy?url=x"><a href="#anchor">a</a>"##;
        let out = rewrite_html(html, &target(), "http://p.local:8080", 1 << 20).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("/proxy?url=x"), "already proxied kept");
        assert!(s.contains("#anchor"), "anchor kept");
    }

    #[test]
    fn css_rewrites_urls() {
        let css = b"body { background: url(https://i.ytimg.com/bg.png); }";
        let out = rewrite_css(css, &target(), "http://p.local:8080");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("http://p.local:8080/proxy?url=https://i.ytimg.com/bg.png"));
    }

    #[test]
    fn css_skips_data_urls() {
        let css = b".a { background: url(data:image/png;base64,AAA); }";
        let out = rewrite_css(css, &target(), "http://p.local:8080");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("data:image/png"));
    }
}
