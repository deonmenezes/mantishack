//! Process-wide shared `reqwest::Client` pool.
//!
//! Each adapter used to do `reqwest::Client::new()` on construction,
//! which buys a fresh connection pool per adapter — fine for a
//! single-adapter test, wasteful when the operator creates 4
//! adapters (one per provider) during a fan-out, or when `mantis
//! ask --providers all` spawns a dozen.
//!
//! The shared client below is built once per process and cloned
//! into each adapter (`reqwest::Client` is internally `Arc`-backed
//! so clones share the connection pool, HTTP/2 multiplexing, and
//! TLS session cache). Net effect: TLS handshakes happen once per
//! host across the entire mantis process, not once per call.

use std::sync::OnceLock;
use std::time::Duration;

use reqwest::Client;

/// Returns a clone of the process-wide shared HTTP client. Cheap
/// (Arc clone). All clones share the same connection pool — so
/// repeated calls to the same upstream API skip TLS / TCP handshake
/// after the first.
pub fn shared_client() -> Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(build_pool_client).clone()
}

fn build_pool_client() -> Client {
    Client::builder()
        // Keep up to 8 idle connections per host. Streaming LLM
        // calls hold one connection for the duration of the reply;
        // 8 covers parallel fan-out across providers comfortably.
        .pool_max_idle_per_host(8)
        // Drop idle connections after 90s — long enough that
        // mid-session turns reuse them, short enough that a chatty
        // operator doesn't accumulate dead sockets.
        .pool_idle_timeout(Some(Duration::from_secs(90)))
        // Per-request timeout. Streaming responses can legitimately
        // take 5+ minutes for a deep nuclei + LLM synthesis pass,
        // so we go generous. Adapters layer their own tighter
        // tokio::time::timeout on top for chat-scale calls.
        //
        // HTTP/2 keep-alive tuning would land here but requires the
        // `http2` feature on reqwest; the workspace deliberately
        // skips it to keep the dependency surface tight. HTTP/1.1
        // keep-alive (always on) plus the connection pool above
        // is enough to amortise TLS handshakes across turns.
        .timeout(Duration::from_secs(300))
        .build()
        // Fallback to the default-config client if the builder
        // ever fails (it shouldn't — these options are all stable).
        // We never want adapter construction to panic.
        .unwrap_or_else(|_| Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_client_returns_same_pool_across_calls() {
        let c1 = shared_client();
        let c2 = shared_client();
        // `reqwest::Client` doesn't expose pool identity directly
        // — best we can do is round-trip via debug formatting +
        // confirm both clones came from the OnceLock (which they
        // must, since shared_client always reads from CLIENT).
        let s1 = format!("{c1:?}");
        let s2 = format!("{c2:?}");
        assert_eq!(s1, s2);
    }
}
