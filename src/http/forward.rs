//! Plain HTTP forward proxy (RFC 9110), streaming with zero caching.
//!
//! For each absolute-form request (`GET http://host[:port]/path HTTP/1.1`):
//! 1. hop-by-hop headers are stripped (see [`strip_hop_by_hop`]),
//! 2. the URI is rewritten to origin-form and `Host` set from the absolute URI,
//! 3. a **fresh** upstream TCP connection is dialed (no pooling, no DNS cache),
//! 4. request and response bodies are streamed frame by frame (never buffered in full),
//! 5. one access record (`proto=http`, `mitm=false`) is emitted when the response body ends.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;

use super::{dial_error_status, error_response, CountingBody, ProxyBody, RequestCtx};

/// Fixed hop-by-hop headers removed in both directions (RFC 9110 §7.6.1 plus the legacy
/// `Proxy-Connection`, `Keep-Alive`, and `Upgrade`, which plain forwarding does not support).
const HOP_BY_HOP: [&str; 10] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Remove hop-by-hop headers: every header named in `Connection` / `Proxy-Connection`,
/// then the fixed [`HOP_BY_HOP`] set.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = [
        header::CONNECTION,
        HeaderName::from_static("proxy-connection"),
    ]
    .iter()
    .flat_map(|h| headers.get_all(h))
    .filter_map(|v| v.to_str().ok())
    .flat_map(|v| v.split(','))
    .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
    .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Upstream target derived from an absolute-form request URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardTarget {
    pub host: String,
    pub port: u16,
    /// Value for the upstream `Host` header (authority without userinfo).
    pub host_header: String,
    /// Origin-form URI (`/path?query`).
    pub origin: Uri,
}

/// Validate an absolute-form `http://` URI and derive the upstream target.
pub fn parse_target(uri: &Uri) -> Result<ForwardTarget, &'static str> {
    match uri.scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("http") => {}
        Some(_) => return Err("only http:// URIs can be forwarded (use CONNECT for https)"),
        None => return Err("proxy requests must use an absolute-form http:// URI"),
    }
    let authority = uri.authority().ok_or("missing host in request URI")?;
    let host = authority.host();
    if host.is_empty() {
        return Err("missing host in request URI");
    }
    let port = authority.port_u16().unwrap_or(80);
    if port == 0 {
        return Err("invalid port in request URI");
    }
    let host_header = authority
        .as_str()
        .rsplit_once('@')
        .map_or(authority.as_str(), |(_, h)| h)
        .to_string();
    let origin = uri
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .parse::<Uri>()
        .map_err(|_| "invalid request path")?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    Ok(ForwardTarget {
        host,
        port,
        host_header,
        origin,
    })
}

/// Forward one plain HTTP request upstream and stream the response back.
pub(crate) async fn handle(ctx: &RequestCtx, req: Request<Incoming>) -> Response<ProxyBody> {
    let mut guard = ctx.access_guard("http", false, req.method().as_str(), req.uri().to_string());
    let logger = &ctx.proxy.logger;

    let target = match parse_target(req.uri()) {
        Ok(t) => t,
        Err(msg) => {
            guard.set_status(StatusCode::BAD_REQUEST);
            logger.debug(format!("rejected request from {}: {msg}", ctx.peer));
            return error_response(StatusCode::BAD_REQUEST, msg);
        }
    };

    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts.uri = target.origin.clone();
    parts.version = Version::HTTP_11;
    match HeaderValue::from_str(&target.host_header) {
        Ok(v) => {
            parts.headers.insert(header::HOST, v);
        }
        Err(_) => {
            guard.set_status(StatusCode::BAD_REQUEST);
            return error_response(StatusCode::BAD_REQUEST, "invalid host");
        }
    }
    let upstream_req = Request::from_parts(parts, CountingBody::new(body, guard.bytes_in(), None));

    let dial = ctx
        .proxy
        .dialer
        .connect(&target.host, target.port, ctx.proxy.connect_timeout);
    let stream = match dial.await {
        Ok(s) => s,
        Err(e) => {
            let status = dial_error_status(&e);
            guard.set_status(status);
            logger.error(format!(
                "upstream connect to {}:{} failed: {e}",
                target.host, target.port
            ));
            return error_response(status, "upstream connection failed");
        }
    };
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    {
        Ok(pair) => pair,
        Err(e) => {
            guard.set_status(StatusCode::BAD_GATEWAY);
            logger.error(format!(
                "upstream handshake with {} failed: {e}",
                target.host_header
            ));
            return error_response(StatusCode::BAD_GATEWAY, "upstream handshake failed");
        }
    };
    let shutdown = ctx.shutdown.clone();
    let conn_logger = logger.clone();
    ctx.tasks.spawn(async move {
        tokio::select! {
            res = conn => {
                if let Err(e) = res {
                    conn_logger.debug(format!("upstream connection error: {e}"));
                }
            }
            () = shutdown.cancelled() => {}
        }
    });

    let resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            guard.set_status(StatusCode::BAD_GATEWAY);
            logger.error(format!(
                "upstream request to {} failed: {e}",
                target.host_header
            ));
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };
    // One request per upstream connection: dropping the sender lets the driver finish.
    drop(sender);

    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    guard.set_status(parts.status);
    let bytes_out = guard.bytes_out();
    let body = CountingBody::new(body, Arc::clone(&bytes_out), Some(guard)).boxed();
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::test_support::{capture_access, quiet_logger, spawn_proxy};
    use crate::http::HttpProxy;

    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use tokio::net::{TcpListener, TcpStream};

    /// Mock origin: replies with a per-request hit counter, the method, the received path,
    /// the received header names, and the echoed request body. Sends hop-by-hop headers
    /// that the proxy must strip.
    async fn spawn_origin() -> (SocketAddr, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicU64::new(0));
        let hits_srv = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let hits = Arc::clone(&hits_srv);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let hits = Arc::clone(&hits);
                        async move {
                            let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                            let method = req.method().to_string();
                            let uri = req.uri().to_string();
                            let host = req
                                .headers()
                                .get(header::HOST)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let mut names: Vec<String> =
                                req.headers().keys().map(|k| k.to_string()).collect();
                            names.sort();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let head = format!(
                                "hit={n}\nmethod={method}\nuri={uri}\nhost={host}\nheaders={}\nbody=",
                                names.join(",")
                            );
                            let mut out = head.into_bytes();
                            out.extend_from_slice(&body);
                            let resp = Response::builder()
                                .status(StatusCode::CREATED)
                                .header("x-origin", "yes")
                                .header("x-hop-secret", "1")
                                .header("connection", "x-hop-secret")
                                .header("proxy-authenticate", "Basic")
                                .header("cache-control", "no-store")
                                .body(Full::new(Bytes::from(out)))
                                .unwrap();
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (addr, hits)
    }

    async fn send(proxy: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, HeaderMap, String) {
        let stream = TcpStream::connect(proxy).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn field<'a>(body: &'a str, key: &str) -> &'a str {
        body.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key} in {body}"))
    }

    #[test]
    fn parse_target_rewrites_to_origin_form() {
        let t = parse_target(&"http://user:pw@example.com:8080/a/b?q=1".parse().unwrap()).unwrap();
        assert_eq!(
            (
                t.host.as_str(),
                t.port,
                t.host_header.as_str(),
                t.origin.to_string().as_str()
            ),
            ("example.com", 8080, "example.com:8080", "/a/b?q=1")
        );
        let t = parse_target(&"http://example.com".parse().unwrap()).unwrap();
        assert_eq!((t.port, t.origin.to_string().as_str()), (80, "/"));
        let t = parse_target(&"http://[::1]:81/x".parse().unwrap()).unwrap();
        assert_eq!(
            (t.host.as_str(), t.host_header.as_str()),
            ("::1", "[::1]:81")
        );
        assert!(parse_target(&"/relative".parse().unwrap()).is_err());
        assert!(parse_target(&"https://example.com/".parse().unwrap()).is_err());
    }

    #[test]
    fn strips_connection_listed_and_fixed_hop_by_hop_headers() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "keep-alive, X-Custom-Hop"),
            ("proxy-connection", "x-legacy"),
            ("x-custom-hop", "1"),
            ("x-legacy", "1"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic abc"),
            ("proxy-authenticate", "Basic"),
            ("te", "trailers"),
            ("trailer", "x-t"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("x-keep", "1"),
            ("content-length", "3"),
        ] {
            h.append(k, HeaderValue::from_static(v));
        }
        strip_hop_by_hop(&mut h);
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["content-length", "x-keep"]);
    }

    #[tokio::test]
    async fn forwards_get_and_post_streaming_without_caching() {
        let (origin, hits) = spawn_origin().await;
        let (access, log) = capture_access().await;
        let proxy = spawn_proxy(HttpProxy::new(
            access.clone(),
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;
        let url = format!("http://{origin}/dyn?x=1");

        // Two identical GETs must both reach the origin (no response caching).
        let mut bodies = Vec::new();
        for _ in 0..2 {
            let req = Request::get(&url)
                .header("connection", "keep-alive, x-secret")
                .header("x-secret", "s3cr3t")
                .header("keep-alive", "timeout=5")
                .header("proxy-authorization", "Basic Zm9vOmJhcg==")
                .header("proxy-connection", "keep-alive")
                .header("te", "trailers")
                .header("x-end-to-end", "kept")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let (status, headers, body) = send(proxy, req).await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(headers.get("x-origin").unwrap(), "yes");
            assert_eq!(headers.get("cache-control").unwrap(), "no-store");
            for hop in ["x-hop-secret", "proxy-authenticate", "connection"] {
                assert!(
                    !headers.contains_key(hop),
                    "response kept {hop}: {headers:?}"
                );
            }
            assert_eq!(field(&body, "method"), "GET");
            assert_eq!(field(&body, "uri"), "/dyn?x=1");
            assert_eq!(field(&body, "host"), origin.to_string());
            let names = field(&body, "headers");
            assert!(names.contains("x-end-to-end"), "{names}");
            for hop in [
                "x-secret",
                "keep-alive",
                "proxy-authorization",
                "proxy-connection",
                "te",
            ] {
                assert!(
                    !names.split(',').any(|n| n == hop),
                    "forwarded {hop}: {names}"
                );
            }
            bodies.push(field(&body, "hit").to_string());
        }
        assert_eq!(bodies, ["1", "2"]);
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // POST with a large body is streamed through and echoed back.
        let payload = vec![b'p'; 200_000];
        let req = Request::post(&url)
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::from(payload.clone())))
            .unwrap();
        let (status, _, body) = send(proxy, req).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(field(&body, "method"), "POST");
        assert!(body.ends_with(&"p".repeat(200_000)));
        assert_eq!(hits.load(Ordering::SeqCst), 3);

        let lines = log.wait_lines(3).await;
        assert_eq!(lines.len(), 3, "{lines:?}");
        let gets: Vec<&String> = lines.iter().filter(|l| l.contains("method=GET")).collect();
        assert_eq!(gets.len(), 2, "{lines:?}");
        for line in gets {
            assert!(line.contains("kind=http"), "{line}");
            assert!(line.contains("proto=http mitm=false method=GET"), "{line}");
            assert!(
                line.contains(&format!("target=\"http://{origin}/dyn?x=1\"")),
                "{line}"
            );
            assert!(line.contains("status=201 bytes_in=0"), "{line}");
        }
        let post = lines.iter().find(|l| l.contains("method=POST")).unwrap();
        assert!(post.contains("bytes_in=200000"), "{post}");
        let out: u64 = post
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix("bytes_out="))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(out, body.len() as u64);
    }

    #[tokio::test]
    async fn rejects_origin_form_and_reports_bad_gateway() {
        let (access, log) = capture_access().await;
        let proxy = spawn_proxy(HttpProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;

        let req = Request::get("/not-a-proxy-request")
            .header("host", "example.com")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _, _) = send(proxy, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let req = Request::get(format!("http://{closed}/"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _, _) = send(proxy, req).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);

        let lines = log.wait_lines(2).await;
        assert!(lines[0].contains("status=400"), "{lines:?}");
        assert!(lines[1].contains("status=502"), "{lines:?}");
    }
}
