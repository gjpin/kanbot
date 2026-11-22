//! The client's IP address, for per-client rate limiting.
//!
//! Behind a reverse proxy every connection comes from the proxy, and the
//! client's address is in `X-Forwarded-For`. That header is only as
//! trustworthy as whoever wrote it: a client can send its own. So it is read
//! only when the connection comes from a configured trusted proxy, and only
//! the entries appended by trusted proxies are skipped: the first address
//! (from the right) that is not a trusted proxy is the client.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderValue;

/// Proxies whose `X-Forwarded-For` entries are trusted (`TRUSTED_PROXIES`):
/// IP addresses and CIDR networks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Network>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Network {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0:?} is not an IP address or CIDR network such as 10.0.0.0/8")]
pub struct InvalidNetwork(pub String);

impl TrustedProxies {
    /// Parses a comma-separated list such as `10.0.0.0/8, 192.168.1.1, ::1`.
    /// Empty entries are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNetwork`] for the first entry that is neither an IP
    /// address nor a network with a valid prefix length.
    pub fn parse_list(raw: &str) -> Result<Self, InvalidNetwork> {
        raw.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| Network::parse(entry).ok_or_else(|| InvalidNetwork(entry.to_owned())))
            .collect::<Result<_, _>>()
            .map(Self)
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|network| network.contains(ip))
    }
}

impl Network {
    fn parse(raw: &str) -> Option<Self> {
        let (addr, prefix) = match raw.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (raw, None),
        };
        let addr = addr.parse::<IpAddr>().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix: u8 = match prefix {
            // Digits only: `u8::from_str` would also accept `+8`.
            Some(prefix) if prefix.bytes().all(|b| b.is_ascii_digit()) => prefix.parse().ok()?,
            Some(_) => return None,
            None => max,
        };
        if prefix > max {
            return None;
        }
        // An IPv4-mapped network (`::ffff:10.0.0.0/104`) is the IPv4 network
        // it maps, as addresses are compared in canonical form.
        Some(match addr {
            IpAddr::V6(v6) => match (v6.to_ipv4_mapped(), prefix.checked_sub(96)) {
                (Some(v4), Some(v4_prefix)) => Self {
                    addr: IpAddr::V4(v4),
                    prefix: v4_prefix,
                },
                _ => Self { addr, prefix },
            },
            IpAddr::V4(_) => Self { addr, prefix },
        })
    }

    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = 32_u32
                    .checked_sub(u32::from(self.prefix))
                    .and_then(|shift| u32::MAX.checked_shl(shift))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = 128_u32
                    .checked_sub(u32::from(self.prefix))
                    .and_then(|shift| u128::MAX.checked_shl(shift))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// The client's address, in the extensions of an authenticated request
/// (put there by the authentication middleware).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// The client address of a connection from `peer` that carried the
/// `X-Forwarded-For` headers `forwarded_for` (in order).
///
/// Walks the forwarded addresses from the right, skipping trusted proxies.
/// An entry is an IP address, or an address and port (`198.51.100.1:443`,
/// `[2001:db8::1]:443`), as some proxies write it. Anything else stops the
/// walk at the last trusted hop: the request is then limited as coming
/// from that proxy, never from an address a client could choose.
pub fn client_ip<'a>(
    peer: IpAddr,
    forwarded_for: impl IntoIterator<Item = &'a HeaderValue>,
    trusted: &TrustedProxies,
) -> IpAddr {
    let mut client = peer.to_canonical();
    if !trusted.contains(client) {
        return client;
    }
    // A value that is not ASCII stops the walk like any other bad hop: a
    // proxy may have appended the real client to a client-sent line, and
    // skipping that line would trust what the client wrote before it.
    let hops: Vec<&str> = forwarded_for
        .into_iter()
        .map(|value| value.to_str().unwrap_or(""))
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect();
    for hop in hops.into_iter().rev() {
        let Some(ip) = hop
            .parse::<IpAddr>()
            .ok()
            .or_else(|| hop.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        else {
            return client;
        };
        client = ip.to_canonical();
        if !trusted.contains(client) {
            return client;
        }
    }
    client
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    fn proxies(raw: &str) -> TrustedProxies {
        TrustedProxies::parse_list(raw).unwrap()
    }

    fn xff(values: &[&'static str]) -> Vec<HeaderValue> {
        values.iter().map(|v| HeaderValue::from_static(v)).collect()
    }

    #[test]
    fn parses_addresses_and_networks() {
        let trusted = proxies(" 10.0.0.0/8 , 192.168.1.1,, ::1, 2001:db8::/32 ");
        for inside in ["10.1.2.3", "192.168.1.1", "::1", "2001:db8::42"] {
            assert!(trusted.contains(ip(inside)), "{inside}");
        }
        for outside in ["11.0.0.1", "192.168.1.2", "::2", "2001:db9::1"] {
            assert!(!trusted.contains(ip(outside)), "{outside}");
        }
    }

    #[test]
    fn empty_list_trusts_nothing() {
        let trusted = proxies("");
        assert_eq!(trusted, TrustedProxies::default());
        assert!(!trusted.contains(ip("127.0.0.1")));
    }

    #[test]
    fn rejects_invalid_entries() {
        for bad in [
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/-1",
            "10.0.0",
            "localhost",
            "10.0.0.0/8/8",
        ] {
            assert_eq!(
                TrustedProxies::parse_list(bad),
                Err(InvalidNetwork(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn prefix_lengths_are_exact() {
        let trusted = proxies("10.0.0.0/31");
        assert!(trusted.contains(ip("10.0.0.0")));
        assert!(trusted.contains(ip("10.0.0.1")));
        assert!(!trusted.contains(ip("10.0.0.2")));
        assert!(proxies("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(!proxies("0.0.0.0/0").contains(ip("::1")));
        assert!(proxies("::/0").contains(ip("2001:db8::1")));
        let v6 = proxies("2001:db8::/127");
        assert!(v6.contains(ip("2001:db8::1")));
        assert!(!v6.contains(ip("2001:db8::2")));
    }

    #[test]
    fn ipv4_mapped_addresses_match_ipv4_networks() {
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 1, 2, 3).to_ipv6_mapped());
        assert!(proxies("10.0.0.0/8").contains(mapped));
        assert!(proxies("::ffff:10.0.0.0/104").contains(ip("10.1.2.3")));
    }

    #[test]
    fn untrusted_peer_is_the_client_whatever_it_forwards() {
        let trusted = proxies("10.0.0.1");
        assert_eq!(
            client_ip(ip("203.0.113.9"), &xff(&["198.51.100.1"]), &trusted),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn forwarded_addresses_may_carry_a_port() {
        let trusted = proxies("10.0.0.0/8");
        for (forwarded, client) in [
            ("198.51.100.1:51234", "198.51.100.1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("198.51.100.1:51234, 10.0.0.2:80", "198.51.100.1"),
        ] {
            let forwarded = HeaderValue::from_str(forwarded).unwrap();
            assert_eq!(
                client_ip(ip("10.0.0.1"), [&forwarded], &trusted),
                ip(client),
                "{forwarded:?}"
            );
        }
        // Not an address: the walk stops at the proxy.
        for bad in ["198.51.100.1:", "[2001:db8::1]", "198.51.100.1:99999"] {
            let bad = HeaderValue::from_str(bad).unwrap();
            assert_eq!(
                client_ip(ip("10.0.0.1"), [&bad], &trusted),
                ip("10.0.0.1"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn trusted_peer_forwards_the_client() {
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff(&["198.51.100.1"]), &trusted),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn spoofed_entries_left_of_the_client_are_ignored() {
        // The client sent "1.1.1.1" itself; the proxy appended the real one.
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff(&["1.1.1.1, 198.51.100.1"]), &trusted),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn a_value_that_is_not_ascii_stops_the_walk() {
        // The client sent "1.1.1.1" and a non-ASCII line; the proxy appended
        // the real client to the latter. The walk stops there, at the proxy,
        // and never trusts what the client wrote.
        let trusted = proxies("10.0.0.0/8");
        let values = vec![
            HeaderValue::from_static("1.1.1.1"),
            HeaderValue::from_bytes(b"\xe9, 198.51.100.1").unwrap(),
        ];
        assert_eq!(client_ip(ip("10.0.0.1"), &values, &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn chained_trusted_proxies_are_skipped() {
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(
            client_ip(
                ip("10.0.0.1"),
                &xff(&["198.51.100.1, 10.0.0.2", "10.0.0.3"]),
                &trusted
            ),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn all_trusted_hops_give_the_leftmost() {
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff(&["10.0.0.9, 10.0.0.2"]), &trusted),
            ip("10.0.0.9")
        );
    }

    #[test]
    fn missing_or_malformed_header_stops_at_the_last_trusted_hop() {
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff(&[]), &trusted),
            ip("10.0.0.1")
        );
        assert_eq!(
            client_ip(ip("10.0.0.1"), &xff(&["198.51.100.1, garbage"]), &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn mapped_peer_is_canonical() {
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped());
        assert_eq!(
            client_ip(mapped, &xff(&[]), &TrustedProxies::default()),
            ip("203.0.113.9")
        );
        assert_eq!(
            client_ip(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                &xff(&[]),
                &TrustedProxies::default()
            ),
            ip("::1")
        );
    }

    proptest! {
        #[test]
        fn never_panics(raw in "\\PC*") {
            let _ = TrustedProxies::parse_list(&raw);
        }

        #[test]
        fn a_network_contains_its_own_address(a: u32, prefix in 0_u8..=32) {
            let addr = Ipv4Addr::from(a);
            let trusted = TrustedProxies::parse_list(&format!("{addr}/{prefix}")).unwrap();
            prop_assert!(trusted.contains(IpAddr::V4(addr)));
        }

        #[test]
        fn untrusted_peers_are_never_overridden(peer: u32, forwarded: u32) {
            let forwarded = HeaderValue::from_str(&Ipv4Addr::from(forwarded).to_string()).unwrap();
            let peer = IpAddr::V4(Ipv4Addr::from(peer));
            prop_assert_eq!(client_ip(peer, [&forwarded], &TrustedProxies::default()), peer);
        }
    }
}
