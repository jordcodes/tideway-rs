//! Secure client IP resolution for applications behind reverse proxies.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::{fmt, net::IpAddr, sync::Arc};

/// Error returned when a trusted proxy network cannot be parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedProxyParseError {
    value: String,
}

impl TrustedProxyParseError {
    fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// The invalid IP address or CIDR value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for TrustedProxyParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid or unsafe trusted proxy '{}'; expected a non-catch-all IP address or CIDR network",
            self.value
        )
    }
}

impl std::error::Error for TrustedProxyParseError {}

/// Resolves the originating client IP without trusting attacker-controlled headers.
///
/// Forwarded headers are considered only when the direct socket peer belongs to a
/// configured trusted proxy network. `X-Forwarded-For` is evaluated from right to
/// left, removing trusted proxy hops until the first untrusted address is found.
#[derive(Clone, Debug, Default)]
pub struct ClientIpResolver {
    trusted_proxies: Arc<[IpNet]>,
}

impl ClientIpResolver {
    /// Create a resolver from trusted IP addresses or CIDR networks.
    pub fn new<I, S>(trusted_proxies: I) -> Result<Self, TrustedProxyParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let trusted_proxies = trusted_proxies
            .into_iter()
            .map(|value| parse_network(value.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            trusted_proxies: trusted_proxies.into(),
        })
    }

    /// Create a resolver from a comma-separated list of IP addresses or CIDRs.
    pub fn from_csv(value: &str) -> Result<Self, TrustedProxyParseError> {
        Self::new(
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        )
    }

    /// Create a resolver from an environment variable containing a comma-separated list.
    ///
    /// A missing variable produces a direct-connection-only resolver. Invalid values
    /// return an error so applications can fail startup instead of silently weakening
    /// their proxy trust boundary.
    pub fn from_env(name: &str) -> Result<Self, TrustedProxyParseError> {
        match std::env::var(name) {
            Ok(value) => Self::from_csv(&value),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => Err(TrustedProxyParseError::new(format!(
                "{name}=<non-Unicode value>"
            ))),
        }
    }

    /// Whether any trusted proxy networks are configured.
    pub fn is_empty(&self) -> bool {
        self.trusted_proxies.is_empty()
    }

    /// Resolve the originating client IP for a request.
    ///
    /// If the peer is not trusted, or a present forwarding header is malformed,
    /// this fails closed and returns the direct peer address.
    pub fn resolve(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.is_trusted(peer) {
            return peer;
        }

        match forwarded_chain(headers) {
            ForwardedChain::Valid(chain) => chain
                .into_iter()
                .rev()
                .find(|address| !self.is_trusted(*address))
                .unwrap_or(peer),
            ForwardedChain::Invalid => peer,
            ForwardedChain::Absent => headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(peer),
        }
    }

    fn is_trusted(&self, address: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|network| network.contains(&address))
    }
}

fn parse_network(value: &str) -> Result<IpNet, TrustedProxyParseError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(TrustedProxyParseError::new(value));
    }

    if let Ok(network) = value.parse::<IpNet>() {
        if network.prefix_len() == 0 {
            return Err(TrustedProxyParseError::new(value));
        }
        return Ok(network);
    }

    value
        .parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| TrustedProxyParseError::new(value))
}

enum ForwardedChain {
    Absent,
    Invalid,
    Valid(Vec<IpAddr>),
}

fn forwarded_chain(headers: &HeaderMap) -> ForwardedChain {
    let values = headers.get_all("x-forwarded-for");
    if values.iter().next().is_none() {
        return ForwardedChain::Absent;
    }

    let mut chain = Vec::new();
    for value in values {
        let Ok(value) = value.to_str() else {
            return ForwardedChain::Invalid;
        };

        for address in value.split(',') {
            let Ok(address) = address.trim().parse() else {
                return ForwardedChain::Invalid;
            };
            chain.push(address);
        }
    }

    if chain.is_empty() {
        ForwardedChain::Invalid
    } else {
        ForwardedChain::Valid(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header::HeaderName};

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid test IP")
    }

    fn resolver(values: &[&str]) -> ClientIpResolver {
        ClientIpResolver::new(values).expect("valid trusted proxies")
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.8".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.9".parse().unwrap());

        assert_eq!(
            resolver(&["10.0.0.0/8"]).resolve(ip("203.0.113.5"), &headers),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn strips_trusted_hops_from_right_to_left() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.8, 10.1.0.4".parse().unwrap());

        assert_eq!(
            resolver(&["10.0.0.0/8"]).resolve(ip("10.2.0.5"), &headers),
            ip("198.51.100.8")
        );
    }

    #[test]
    fn ignores_attacker_supplied_leftmost_address_when_proxy_appends() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.0.2.99, 198.51.100.8".parse().unwrap(),
        );

        assert_eq!(
            resolver(&["10.0.0.0/8"]).resolve(ip("10.2.0.5"), &headers),
            ip("198.51.100.8")
        );
    }

    #[test]
    fn supports_multiple_forwarded_header_lines() {
        let mut headers = HeaderMap::new();
        let name = HeaderName::from_static("x-forwarded-for");
        headers.append(name.clone(), HeaderValue::from_static("198.51.100.8"));
        headers.append(name, HeaderValue::from_static("10.1.0.4"));

        assert_eq!(
            resolver(&["10.0.0.0/8"]).resolve(ip("10.2.0.5"), &headers),
            ip("198.51.100.8")
        );
    }

    #[test]
    fn malformed_forwarded_chain_fails_closed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.8, not-an-ip".parse().unwrap(),
        );
        headers.insert("x-real-ip", "198.51.100.9".parse().unwrap());

        assert_eq!(
            resolver(&["10.0.0.0/8"]).resolve(ip("10.2.0.5"), &headers),
            ip("10.2.0.5")
        );
    }

    #[test]
    fn uses_real_ip_only_when_forwarded_for_is_absent() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "2001:db8::42".parse().unwrap());

        assert_eq!(
            resolver(&["2001:db8:1::/48"]).resolve(ip("2001:db8:1::5"), &headers),
            ip("2001:db8::42")
        );
    }

    #[test]
    fn invalid_network_is_rejected() {
        let error = ClientIpResolver::new(["10.0.0.0/8", "invalid"])
            .expect_err("invalid network should fail");
        assert_eq!(error.value(), "invalid");
    }

    #[test]
    fn catch_all_networks_are_rejected() {
        for value in ["0.0.0.0/0", "::/0"] {
            let error = ClientIpResolver::new([value])
                .expect_err("catch-all networks would trust arbitrary peers");
            assert_eq!(error.value(), value);
        }
    }
}
