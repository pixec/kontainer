//! Keeping outgoing requests whose target someone else chose (namespace webhooks, Git pollers,
//! token realms named by an upstream) away from this machine, private networks and cloud
//! metadata endpoints.

use std::net::{IpAddr, SocketAddr};

use anyhow::{bail, Context, Result};

/// A DNS resolver that refuses names resolving to internal addresses. Checking the target and
/// then letting the HTTP client resolve it again would let a DNS answer change in between
/// (rebinding); resolving here makes the checked addresses the ones connected to. (IP literals
/// skip resolvers; [`check_target`] covers those.) `hint` names the setting that allows them.
pub struct PublicOnly {
    pub hint: &'static str,
}

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let hint = self.hint;
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if let Some(a) = addrs.iter().find(|a| is_internal(a.ip())) {
                return Err(format!("{host} resolves to {}, an internal address ({hint})", a.ip()).into());
            }
            if addrs.is_empty() {
                return Err(format!("{host} does not resolve").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Refuse URLs that are not http(s) or whose host is (or resolves to) an internal address.
/// Pair it with a client using [`PublicOnly`]: this check covers IP literals, the resolver
/// covers what the client actually connects to.
pub async fn check_target(raw: &str, hint: &str) -> Result<()> {
    let url = url::Url::parse(raw).context("invalid URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("only http:// and https:// URLs");
    }
    let host = url.host_str().context("the URL has no host")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host.trim_matches(['[', ']']), port)).await.with_context(|| format!("resolving {host}"))?.map(|a| a.ip()).collect();
    if addrs.is_empty() {
        bail!("{host} does not resolve");
    }
    if let Some(ip) = addrs.iter().find(|ip| is_internal(**ip)) {
        bail!("{host} resolves to {ip}, an internal address ({hint})");
    }
    Ok(())
}

/// Whether `url`'s host is an IP literal on an internal network (no DNS lookup).
pub fn is_internal_literal(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(v4)) => is_internal(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => is_internal(IpAddr::V6(v6)),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost") || d.to_ascii_lowercase().ends_with(".localhost"),
        None => true,
    }
}

/// Loopback, private, link-local (cloud metadata), carrier-grade NAT, unspecified, broadcast,
/// multicast and documentation addresses.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() || v4.is_documentation()
                // 100.64.0.0/10 (carrier-grade NAT) and 0.0.0.0/8.
                || (o[0] == 100 && (o[1] & 0xc0) == 64) || o[0] == 0
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()
                // fc00::/7 (unique local) and fe80::/10 (link-local).
                || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_addresses() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(is_internal(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
            assert!(!is_internal(ip.parse().unwrap()), "{ip}");
        }
        let u = |s: &str| url::Url::parse(s).unwrap();
        assert!(is_internal_literal(&u("https://169.254.169.254/latest")));
        assert!(is_internal_literal(&u("https://[::1]/")));
        assert!(is_internal_literal(&u("http://localhost:5000/")));
        assert!(!is_internal_literal(&u("https://auth.docker.io/token")));
    }
}
