# ytproxy

وكيل ويب سريع ومنخفض الذاكرة مكتوب بـ Rust — جاهز لموقع يوتيوب، ويوفر تشغيل فيديو يوتيوب عبر الخادم (sidecar yt-dlp) بتقنية HLS متعددة الجودات.

> ملاحظة: المشروع بُني كتجربة عملية لحل مشكلة حجب/تسميم روابط الفيديو عبر النفق — راجع مجلد
> [`docs`](docs/) لتوثيق المشاكل والحلول.

## الميزات

- **وكيل تصفح عام**: يتصفح المواقع عبر الخادم مع إعادة كتابة الروابط والنماذج، ويدعم الـ cookies و `Range` للبث.
- **`/ytstream?video=<id>`**: بث مباشر MP4 (itag 18) عبر الخادم — لا يحتاج PoToken ولا CORS، IP الخروج ثابت.
- **`/ytstream-hls?video=<id>&quality=hls-1080`**: بث HLS متعدد الجودات (144p → 1080p) عبر الخادم، مع إعادة كتابة كل روابط المقاطع لتُجلب من الخادم نفسه.
- **حماية**: كلمة مرور (cookie + query)، فحص أمان للروابط المطلوبة (`googlevideo.com` فقط)، قوائم closed للتنسيقات تمنع حقن أوامر في yt-dlp، تحجيم للطلبات، إلخ.

## المتطلبات

- Rust (edition 2021)
- [`yt-dlp`](https://github.com/yt-dlp/yt-dlp) في `/usr/local/bin/yt-dlp` (يُستخدم كمنتج روابط — يدير فك تشفير `nsig` بنفسه عبر `player_client=web_safari`)

## التشغيل

```bash
export PROXY_PASSWORD="كلمة-سر-قوية"
RUST_LOG=info PORT=8081 cargo run --release
```

للاختبار المحلي:

```bash
# بث مباشر MP4
curl -r 0-1000000 "http://127.0.0.1:8081/ytstream?video=dQw4w9WgXcQ"

# HLS: قائمة التشغيل معاد كتابتها (كل المقاطع عبر /ytstream-hls?u=...)
curl "http://127.0.0.1:8081/ytstream-hls?video=dQw4w9WgXcQ&quality=hls-720"
```

الصفحة الرئيسية توفر مشغلاً جاهزاً (أدخل معرف الفيديو أو الرابط واختر الجودة).

## متغيرات البيئة

| المتغير | الافتراضي | الوصف |
|---|---|---|
| `PROXY_PASSWORD` | — (مطلوب) | كلمة مرور الوصول |
| `PORT` / `BIND` | `8080` / `0.0.0.0` | منفذ الاستماع والعنوان |
| `USER_AGENT` | Chrome UA | وكيل المستخدم للطلبات |
| `PROXY_SOCKS5` | فارغ | خروج عبر SOCKS5 إن حُدّد |
| `REDIRECT_LIMIT` | `10` | حد إعادة التوجيه |
| `CONNECT_TIMEOUT_SECS` / `READ_TIMEOUT_SECS` / `REQUEST_TIMEOUT_SECS` | `10` / `120` / `60` | مهلات الشبكة |
| `TEXT_MAX_BYTES` | `32MiB` | حد النصوص المعاد كتابتها |
| `TLS_CERT` / `TLS_KEY` | فارغ | HTTPS مباشر عبر rustls |
| `TRUST_FORWARDED_FOR` | فارغ | الثقة بترويسة X-Forwarded-For |

## نقاط النهاية

| المسار | الوصف |
|---|---|
| `GET /` | الصفحة الرئيسية (المشغل + الاختصارات) |
| `GET /health` | فحص الصحة |
| `GET /login` / `POST /login` | الدخول |
| `GET /proxy?url=<encoded>` | تصفح موقع عبر الخادم |
| `GET /ytstream?video=<id>` | بث MP4 مباشر (itag 18) |
| `GET /ytstream-hls?video=<id>&quality=<q>` | بث HLS (القائمة المعاد كتابتها) |
| `GET /ytstream-hls?u=<googlevideo-مشفر>` | جلب مقطع/playlist عبر الخادم |

## الإصدارات

- **v1.1.0** — إضافة `/ytstream` (بث MP4) و `/ytstream-hls` (بث متعدد الجودات عبر sidecar yt-dlp) + مشغل في الصفحة الرئيسية.
- **v1.0.0** — الوكيل العام (تصفح، cookies، Range، حماية، HTTPS).

## الترخيص

MIT — انظر [LICENSE](LICENSE).
