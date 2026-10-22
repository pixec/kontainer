//! The client's address, for sign-in rate limits and the session list.
//!
//! It is the TCP peer (`ConnectInfo`), unless the peer is one of `server.trusted_proxies`: then
//! `X-Forwarded-For` is read from the right, skipping trusted hops, and the first untrusted hop
//! is the client. A client can't spoof its address by sending the header itself, since only
//! hops appended by trusted proxies are believed.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use kontainer_core::config::IpNet;

/// The client's address, as worked out by [`middleware`]. `None` when it is unknown: the
/// server was started without connection info (e.g. a router driven directly in tests).
#[derive(Debug, Clone, Default)]
pub struct ClientIp(pub Option<String>);

impl ClientIp {
    pub fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(parts.extensions.get::<ClientIp>().cloned().unwrap_or_default())
    }
}

/// Middleware: resolve the client address once and store it as a [`ClientIp`] extension.
pub async fn middleware(trusted: Arc<Vec<IpNet>>, mut req: Request, next: Next) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let ip = resolve(peer, req.headers(), &trusted);
    req.extensions_mut().insert(ClientIp(ip.map(|ip| ip.to_string())));
    next.run(req).await
}

/// The client behind `peer`, believing `X-Forwarded-For` only as far as `trusted` proxies vouch.
pub fn resolve(peer: Option<IpAddr>, headers: &HeaderMap, trusted: &[IpNet]) -> Option<IpAddr> {
    let peer = peer.map(canonical)?;
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&peer) {
        return Some(peer);
    }
    let hops = headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).map(str::trim).collect::<Vec<_>>();
    let mut client = peer;
    for hop in hops.iter().rev() {
        // A hop a trusted proxy wrote that isn't an address: stop at the last one we trust.
        let Ok(ip) = hop.parse::<IpAddr>().map(canonical) else { break };
        client = ip;
        if !is_trusted(&ip) {
            break;
        }
    }
    Some(client)
}

/// `::ffff:10.0.0.1` (an IPv4 client on a dual-stack socket) as `10.0.0.1`, so IPv4 ranges match.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }

    #[test]
    fn forwarded_for_only_from_trusted_proxies() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        // Untrusted peer: its own header is ignored.
        assert_eq!(resolve(Some(ip("203.0.113.9")), &xff("1.2.3.4"), &trusted), Some(ip("203.0.113.9")));
        // Through a trusted proxy: the hop it appended.
        assert_eq!(resolve(Some(ip("10.0.0.2")), &xff("1.2.3.4"), &trusted), Some(ip("1.2.3.4")));
        // A client prepending a fake entry gets its real address (the proxy's last append).
        assert_eq!(resolve(Some(ip("10.0.0.2")), &xff("6.6.6.6, 198.51.100.7"), &trusted), Some(ip("198.51.100.7")));
        // Chained trusted proxies are skipped.
        assert_eq!(resolve(Some(ip("10.0.0.2")), &xff("198.51.100.7, 10.0.0.3"), &trusted), Some(ip("198.51.100.7")));
        // No header, or garbage: the proxy itself.
        assert_eq!(resolve(Some(ip("10.0.0.2")), &HeaderMap::new(), &trusted), Some(ip("10.0.0.2")));
        assert_eq!(resolve(Some(ip("10.0.0.2")), &xff("nonsense"), &trusted), Some(ip("10.0.0.2")));
        // Nothing trusted (the default): never the header.
        assert_eq!(resolve(Some(ip("10.0.0.2")), &xff("1.2.3.4"), &[]), Some(ip("10.0.0.2")));
        // IPv4-mapped peers match IPv4 ranges.
        assert_eq!(resolve(Some(ip("::ffff:10.0.0.2")), &xff("1.2.3.4"), &trusted), Some(ip("1.2.3.4")));
        // No connection info.
        assert_eq!(resolve(None, &xff("1.2.3.4"), &trusted), None);
    }
}
