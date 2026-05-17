//! Scanner integration tests. We spin up a fake HTTP server on
//! localhost and point the scanner at it. The egress proxy is not
//! exercised here (its CONNECT-only Phase 0 path doesn't support
//! plain HTTP); proxy-routed tests land in M0.5b once plain-HTTP
//! forwarding is added to the proxy.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use camino::Utf8PathBuf;
use mantis_core::{EngagementId, Signer};
use mantis_event_store::{EventKind, EventStore};
use mantis_scanner_http::{HttpProbeScanner, ProbeConfig, ProbeTarget};
use mantis_workspace::Keypair;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use ulid::Ulid;

const RESPONSE: &str = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.0\r\nContent-Type: text/html\r\nContent-Length: 11\r\n\r\nhello world";

async fn spawn_fake_http_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(RESPONSE.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn temp_event_store() -> (TempDir, Arc<EventStore>) {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = Utf8PathBuf::from_path_buf(tmp.path().join("events.rocksdb")).unwrap();
    let store = Arc::new(EventStore::open(&db_path).unwrap());
    (tmp, store)
}

#[tokio::test]
async fn probe_records_surface_with_status_and_server() {
    let addr = spawn_fake_http_server().await;
    let (_tmp, store) = temp_event_store();
    let kp: Arc<dyn Signer> = Arc::new(Keypair::generate());
    let eng = EngagementId(Ulid::new());
    let scanner = HttpProbeScanner::new(
        store.clone(),
        eng,
        kp,
        ProbeConfig {
            timeout: std::time::Duration::from_secs(2),
            ..Default::default()
        },
    )
    .unwrap();
    let target = ProbeTarget::parse(&format!("http://127.0.0.1:{}/", addr.port())).unwrap();
    let surface = scanner.probe(&target).await.unwrap();

    assert_eq!(surface.status, 200);
    assert_eq!(surface.server.as_deref(), Some("nginx/1.25.0"));
    assert!(surface.tech_hints.iter().any(|h| h == "server:nginx"));
    assert!(surface.tech_hints.iter().any(|h| h == "content:html"));

    // Confirm the event landed in the log.
    let events = store.replay(eng).unwrap();
    let surface_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::SurfaceDiscovered { .. }))
        .collect();
    assert_eq!(surface_events.len(), 1);
}

#[tokio::test]
async fn probe_all_continues_past_failures() {
    let addr = spawn_fake_http_server().await;
    let (_tmp, store) = temp_event_store();
    let kp: Arc<dyn Signer> = Arc::new(Keypair::generate());
    let eng = EngagementId(Ulid::new());
    let scanner = HttpProbeScanner::new(
        store.clone(),
        eng,
        kp,
        ProbeConfig {
            timeout: std::time::Duration::from_millis(500),
            ..Default::default()
        },
    )
    .unwrap();

    let targets = vec![
        ProbeTarget::parse(&format!("http://127.0.0.1:{}/", addr.port())).unwrap(),
        // Unbound port — connection refused, scanner skips it.
        ProbeTarget::parse("http://127.0.0.1:1/").unwrap(),
        ProbeTarget::parse(&format!("http://127.0.0.1:{}/another", addr.port())).unwrap(),
    ];
    let surfaces = scanner.probe_all(&targets).await;
    assert_eq!(surfaces.len(), 2);
}

#[test]
fn probe_target_parsing() {
    let t = ProbeTarget::parse("https://api.example.com/v1/users").unwrap();
    assert_eq!(t.scheme, "https");
    assert_eq!(t.host, "api.example.com");
    assert_eq!(t.port, 443);
    assert_eq!(t.path, "/v1/users");

    let t = ProbeTarget::parse("http://127.0.0.1:8080").unwrap();
    assert_eq!(t.scheme, "http");
    assert_eq!(t.port, 8080);
    assert_eq!(t.path, "/");
}

#[test]
fn probe_target_rejects_malformed() {
    let r = ProbeTarget::parse("not a url");
    assert!(r.is_err());
}

/// Capture the first request received and return its bytes via the
/// channel. The fake server responds with the same hello-world body
/// as `spawn_fake_http_server` so the scanner is happy.
async fn spawn_capturing_server() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        let _ = tx.send(buf);
        let _ = sock.write_all(RESPONSE.as_bytes()).await;
        let _ = sock.shutdown().await;
    });
    (addr, rx)
}

#[tokio::test]
async fn auth_profile_injects_cookies_headers_and_query() {
    use mantis_auth::{AuthCookie, AuthHeader, AuthProfile};

    let (addr, captured) = spawn_capturing_server().await;
    let (_tmp, store) = temp_event_store();
    let kp: Arc<dyn Signer> = Arc::new(Keypair::generate());
    let eng = EngagementId(Ulid::new());

    let profile = AuthProfile {
        name: "attacker".into(),
        headers: vec![AuthHeader {
            name: "X-Test-Token".into(),
            value: "secret-bearer-1234".into(),
        }],
        cookies: vec![
            AuthCookie {
                name: "session".into(),
                value: "abc123".into(),
                domain: None,
                path: None,
                secure: false,
                http_only: false,
            },
            AuthCookie {
                name: "csrf".into(),
                value: "tok456".into(),
                domain: None,
                path: None,
                secure: false,
                http_only: false,
            },
        ],
        query: vec![("api_key".into(), "qkey789".into())],
        expires_at_unix: None,
        created_at_unix: 0,
        origin: "test".into(),
    };

    let scanner = HttpProbeScanner::new(
        store,
        eng,
        kp,
        ProbeConfig {
            timeout: std::time::Duration::from_secs(2),
            auth_profile: Some(profile),
            ..Default::default()
        },
    )
    .unwrap();
    let target =
        ProbeTarget::parse(&format!("http://127.0.0.1:{}/v1/users", addr.port())).unwrap();
    let _ = scanner.probe(&target).await.unwrap();

    let bytes = captured.await.unwrap();
    let request = String::from_utf8_lossy(&bytes);
    let request_lower = request.to_ascii_lowercase();
    assert!(
        request_lower.contains("cookie: session=abc123; csrf=tok456"),
        "cookies not injected:\n{request}"
    );
    assert!(
        request_lower.contains("x-test-token: secret-bearer-1234"),
        "custom header not injected:\n{request}"
    );
    assert!(
        request.contains("GET /v1/users?api_key=qkey789"),
        "query param not appended:\n{request}"
    );
}

#[tokio::test]
async fn no_auth_profile_means_no_cookie_header() {
    let (addr, captured) = spawn_capturing_server().await;
    let (_tmp, store) = temp_event_store();
    let kp: Arc<dyn Signer> = Arc::new(Keypair::generate());
    let eng = EngagementId(Ulid::new());
    let scanner = HttpProbeScanner::new(
        store,
        eng,
        kp,
        ProbeConfig {
            timeout: std::time::Duration::from_secs(2),
            ..Default::default()
        },
    )
    .unwrap();
    let target = ProbeTarget::parse(&format!("http://127.0.0.1:{}/", addr.port())).unwrap();
    let _ = scanner.probe(&target).await.unwrap();

    let bytes = captured.await.unwrap();
    let request = String::from_utf8_lossy(&bytes);
    assert!(!request.to_ascii_lowercase().contains("cookie:"));
    assert!(!request.contains("api_key="));
}
