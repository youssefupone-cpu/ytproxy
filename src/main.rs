//! ytproxy — خادم بروكسي سريع ومنخفض الذاكرة (Rust)
//!
//! الاستخدام:
//!   http://localhost:8080/proxy?url=https://www.youtube.com/...
//!   https://localhost:8443/proxy?url=... (عند ضبط TLS_CERT + TLS_KEY، مع HTTP/2)
//!
//! خيارات env: PORT, BIND, USER_AGENT, PROXY_SOCKS5, TEXT_MAX_BYTES,
//! REDIRECT_LIMIT, CONNECT_TIMEOUT_SECS, READ_TIMEOUT_SECS, REQUEST_TIMEOUT_SECS,
//! POOL_MAX_IDLE, TLS_CERT, TLS_KEY, ALLOW_PRIVATE, RATE_LIMIT_PER_MIN,
//! PROXY_PASSWORD (كلمة سر اختيارية تحمي البروكسي — صفحة دخول /login)

mod config;
mod proxy;
mod rewrite;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::Request;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = config::Config::from_env();
    let proxy = proxy::Proxy::new(config)?;
    let addr: SocketAddr = format!("{}:{}", proxy.config.bind, proxy.config.port).parse()?;

    let tls_acceptor = match (&proxy.config.tls_cert, &proxy.config.tls_key) {
        (Some(cert), Some(key)) => {
            let acceptor = build_tls_acceptor(cert, key)?;
            log::info!(
                "🟢 ytproxy يعمل على https://{addr} (TLS + HTTP/2) — الشهادة: {}",
                cert.display()
            );
            Some(acceptor)
        }
        _ => {
            log::info!("🟢 ytproxy يعمل على http://{addr} (HTTP/1.1)");
            None
        }
    };
    log::info!("   جرب: https://{addr}/proxy?url=https://www.youtube.com/watch?v=dQw4w9WgXcQ");

    // إشارة إيقاف نظيفة
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // نبدأ الاستماع فوراً — الخادم جاهز للطلبات حتى لو تأخر جلب كوكيز يوتيوب
    let listener = TcpListener::bind(addr).await?;

    // جلب كوكيز جلسة يوتيوب في الخلفية (فوراً ثم كل ساعة) — يقلل 403 بشكل كبير
    {
        let proxy = proxy.clone();
        tokio::spawn(async move {
            proxy.refresh_yt_cookies().await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.tick().await; // أول tick فوري — نتخطاه (جُلب أعلاه)
            loop {
                interval.tick().await;
                proxy.refresh_yt_cookies().await;
            }
        });
    }

    let builder = hyper_util::server::conn::auto::Builder::new(
        hyper_util::rt::TokioExecutor::new(),
    );
    let builder = Arc::new(builder);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        log::warn!("فشل قبول اتصال: {e}");
                        continue;
                    }
                };
                let peer_ip = peer.ip();

                let proxy = proxy.clone();
                let tls_enabled = tls_acceptor.is_some();
                let tls_acceptor = tls_acceptor.clone();
                let builder = builder.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let proxy = proxy.clone();
                        async move {
                            let mut req = req;
                            // عندما نخدم عبر TLS مباشرة، أخبر المعالج بالمخطط الحقيقي
                            if tls_enabled {
                                req.headers_mut().insert(
                                    http::header::HeaderName::from_static("x-ytproxy-tls"),
                                    http::header::HeaderValue::from_static("1"),
                                );
                            }
                            Ok::<_, Infallible>(proxy.handle(req, peer_ip).await)
                        }
                    });

                    let io = if let Some(acceptor) = &tls_acceptor {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => TokioIo::new(Stream::Tls(tls_stream)),
                            Err(e) => {
                                log::debug!("مصافحة TLS فشلت: {e}");
                                return;
                            }
                        }
                    } else {
                        TokioIo::new(Stream::Plain(stream))
                    };

                    if let Err(e) = builder.serve_connection(io, service).await {
                        log::debug!("اتصال انتهى بخطأ: {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("⏹️ إيقاف...");
                break;
            }
            _ = sigterm.recv() => {
                log::info!("⏹️ إيقاف (SIGTERM)...");
                break;
            }
        }
    }

    Ok(())
}

/// تيار اتصال: عادي أو TLS (بعد المصافحة).
enum Stream {
    Plain(tokio::net::TcpStream),
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

fn build_tls_acceptor(    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<tokio_rustls::TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    use rustls_pemfile::{certs, private_key};

    let mut cert_reader = std::io::BufReader::new(std::fs::File::open(cert_path)?);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut cert_reader).collect::<Result<_, _>>()?;
    if cert_chain.is_empty() {
        return Err("لا توجد شهادات في الملف".into());
    }

    let mut key_reader = std::io::BufReader::new(std::fs::File::open(key_path)?);
    let key = private_key(&mut key_reader)?.ok_or("لا يوجد مفتاح خاص في الملف")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    // تفاوض ALPN: يفضّل HTTP/2 ثم HTTP/1.1
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
}
