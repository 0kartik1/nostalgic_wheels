//! Which clients are allowed to ask us to resolve names.
//!
//! This matters more than it looks. netwatch binds `0.0.0.0:53` so devices
//! across the LAN can reach it, and a recursive resolver that answers *anyone*
//! is an open resolver — the classic ingredient in DNS amplification
//! reflection attacks, where a spoofed 60-byte query provokes a multi-kilobyte
//! answer aimed at a victim. That only needs one forwarded port or one stint on
//! a public network to become someone else's problem.
//!
//! So the default is loopback plus the private ranges, and anything else has to
//! be opted into explicitly. dnsmasq and Pi-hole take the same stance.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// This machine only.
    Loopback,
    /// RFC1918, CGNAT, link-local, and their IPv6 equivalents.
    Private,
    /// Everything. Only ever set deliberately.
    Any,
    V4 {
        network: Ipv4Addr,
        prefix: u8,
    },
    V6 {
        network: Ipv6Addr,
        prefix: u8,
    },
}

#[derive(Debug, Clone)]
pub struct Acl {
    rules: Vec<Rule>,
}

impl Acl {
    /// Parse config entries: the keywords `loopback`, `private`, `any`, or any
    /// IPv4/IPv6 CIDR such as `192.168.1.0/24` or `fd00::/8`.
    pub fn parse(entries: &[String]) -> Result<Self> {
        let mut rules = Vec::with_capacity(entries.len());
        for raw in entries {
            let e = raw.trim().to_ascii_lowercase();
            let rule = match e.as_str() {
                "loopback" | "localhost" => Rule::Loopback,
                "private" | "lan" => Rule::Private,
                "any" | "all" | "0.0.0.0/0" => Rule::Any,
                cidr => parse_cidr(cidr)
                    .with_context(|| format!("dns.allow_from entry {raw:?} is not a keyword (loopback/private/any) or a CIDR"))?,
            };
            rules.push(rule);
        }
        Ok(Self { rules })
    }

    /// An empty rule set would silently deny the whole network, which is a
    /// worse failure than being permissive, so treat it as "private".
    pub fn allows(&self, addr: IpAddr) -> bool {
        if self.rules.is_empty() {
            return is_private(addr) || addr.is_loopback();
        }
        self.rules.iter().any(|r| match r {
            Rule::Any => true,
            Rule::Loopback => addr.is_loopback(),
            Rule::Private => is_private(addr) || addr.is_loopback(),
            Rule::V4 { network, prefix } => match addr {
                IpAddr::V4(v4) => v4_in(v4, *network, *prefix),
                IpAddr::V6(_) => false,
            },
            Rule::V6 { network, prefix } => match addr {
                IpAddr::V6(v6) => v6_in(v6, *network, *prefix),
                IpAddr::V4(_) => false,
            },
        })
    }

    /// Also trust the LAN netwatch actually found in the routing table.
    ///
    /// Not every home network uses RFC1918: some ISPs still hand out public
    /// addresses directly to LAN devices. For those households a purely
    /// private-ranges default would silently break DNS for everything —
    /// the worst possible failure for a box the whole house depends on. The
    /// subnet on our own interface is trustworthy by construction, so add it.
    ///
    /// Only applies to the `private` stance. An operator who wrote an explicit
    /// list (`loopback`, or specific CIDRs) has said exactly who they want
    /// served, and silently widening that would be its own security bug.
    /// `private` is a statement of intent — "my local network" — so honouring
    /// it on a network that happens to use public addressing is faithful.
    ///
    /// Returns true if this widened the ACL, so startup can log it.
    pub fn trust_subnet(&mut self, network: Ipv4Addr, prefix: u8) -> bool {
        // An empty rule set behaves as `private`, so it opts in too.
        let private_stance = self.rules.is_empty() || self.rules.contains(&Rule::Private);
        if !private_stance {
            return false;
        }
        // Nothing to add if it is already covered.
        if self.allows(IpAddr::V4(network)) {
            return false;
        }
        self.rules.push(Rule::V4 { network, prefix });
        true
    }

    /// True when the operator has deliberately opened this up to the internet,
    /// so startup can say so out loud.
    pub fn is_open_to_world(&self) -> bool {
        self.rules.contains(&Rule::Any)
    }
}

fn parse_cidr(s: &str) -> Result<Rule> {
    let (addr, len) = s
        .split_once('/')
        .with_context(|| format!("{s:?} has no / prefix length"))?;
    let prefix: u8 = len.trim().parse().context("bad prefix length")?;

    // A bare address without a prefix is ambiguous, so require the /len form
    // and validate it against the family.
    match addr.trim().parse::<IpAddr>().context("bad address")? {
        IpAddr::V4(network) => {
            anyhow::ensure!(prefix <= 32, "IPv4 prefix /{prefix} out of range");
            Ok(Rule::V4 { network, prefix })
        }
        IpAddr::V6(network) => {
            anyhow::ensure!(prefix <= 128, "IPv6 prefix /{prefix} out of range");
            Ok(Rule::V6 { network, prefix })
        }
    }
}

fn v4_in(addr: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(addr) & mask) == (u32::from(network) & mask)
}

fn v6_in(addr: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix);
    (u128::from(addr) & mask) == (u128::from(network) & mask)
}

/// Addresses that can only have come from a local network.
fn is_private(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            // 10/8, 172.16/12, 192.168/16
            v4.is_private()
                // 169.254/16 — a device that failed DHCP still deserves DNS
                || v4.is_link_local()
                // 100.64/10 carrier-grade NAT, which some ISP routers hand out
                // on the LAN side. `Ipv4Addr::is_shared` is still unstable.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // fc00::/7 unique local
            (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (seg[0] & 0xffc0) == 0xfe80
                // A v4-mapped address is judged on its v4 value.
                || v6.to_ipv4_mapped().is_some_and(|v4| is_private(IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(entries: &[&str]) -> Acl {
        Acl::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_stance_allows_lan_and_refuses_the_internet() {
        let a = acl(&["loopback", "private"]);

        // Every shape of home network.
        assert!(a.allows(ip("192.168.1.42")));
        assert!(a.allows(ip("10.0.0.7")));
        assert!(a.allows(ip("172.16.5.1")));
        assert!(a.allows(ip("172.31.255.254")));
        assert!(a.allows(ip("127.0.0.1")));
        assert!(a.allows(ip("::1")));
        assert!(
            a.allows(ip("169.254.10.1")),
            "DHCP-failed device still gets DNS"
        );
        assert!(a.allows(ip("100.64.0.1")), "CGNAT range");
        assert!(a.allows(ip("fd12:3456::1")), "IPv6 unique local");
        assert!(a.allows(ip("fe80::1")), "IPv6 link-local");

        // The whole point: strangers get nothing.
        assert!(!a.allows(ip("8.8.8.8")));
        assert!(!a.allows(ip("1.1.1.1")));
        assert!(!a.allows(ip("203.0.113.9")));
        assert!(!a.allows(ip("2606:4700::1111")));
        // 172.32 is outside 172.16/12 — a classic off-by-one.
        assert!(!a.allows(ip("172.32.0.1")));
        // 100.128 is outside 100.64/10.
        assert!(!a.allows(ip("100.128.0.1")));
    }

    #[test]
    fn explicit_cidrs_are_honoured_per_family() {
        let a = acl(&["192.168.50.0/24", "2001:db8::/32"]);
        assert!(a.allows(ip("192.168.50.1")));
        assert!(a.allows(ip("192.168.50.255")));
        assert!(!a.allows(ip("192.168.51.1")));
        assert!(a.allows(ip("2001:db8::dead")));
        assert!(!a.allows(ip("2001:db9::1")));
        // A v4 address must not be matched by a v6 rule or vice versa.
        assert!(!a.allows(ip("10.0.0.1")));
    }

    #[test]
    fn any_opens_it_up_and_says_so() {
        let a = acl(&["any"]);
        assert!(a.allows(ip("8.8.8.8")));
        assert!(a.is_open_to_world());
        assert!(!acl(&["private"]).is_open_to_world());
    }

    #[test]
    fn empty_rules_fall_back_to_private_rather_than_denying_everything() {
        let a = Acl::parse(&[]).unwrap();
        assert!(a.allows(ip("192.168.1.5")));
        assert!(a.allows(ip("127.0.0.1")));
        assert!(!a.allows(ip("8.8.8.8")));
    }

    #[test]
    fn loopback_alone_excludes_the_lan() {
        let a = acl(&["loopback"]);
        assert!(a.allows(ip("127.0.0.1")));
        assert!(!a.allows(ip("192.168.1.5")));
    }

    #[test]
    fn v4_mapped_v6_is_judged_on_its_v4_value() {
        let a = acl(&["private"]);
        assert!(a.allows(ip("::ffff:192.168.1.5")));
        assert!(!a.allows(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn prefix_zero_matches_everything_in_its_family() {
        let a = acl(&["0.0.0.0/0"]);
        assert!(a.allows(ip("8.8.8.8")));
        assert!(
            a.is_open_to_world(),
            "0.0.0.0/0 is the same promise as `any`"
        );
    }

    #[test]
    fn a_public_addressed_lan_is_trusted_under_the_private_stance() {
        // Some ISPs hand out public addresses straight to LAN devices. Without
        // this, the default would break DNS for the entire house.
        let mut a = acl(&["loopback", "private"]);
        assert!(
            !a.allows(ip("203.0.113.50")),
            "not trusted before detection"
        );

        assert!(a.trust_subnet("203.0.113.0".parse().unwrap(), 24));
        assert!(a.allows(ip("203.0.113.50")), "our own LAN is now served");
        // Widening to our LAN must not open up the rest of the internet.
        assert!(!a.allows(ip("8.8.8.8")));
        assert!(
            !a.allows(ip("203.0.114.1")),
            "neighbouring subnet stays out"
        );
    }

    #[test]
    fn trust_subnet_will_not_widen_an_explicit_narrow_choice() {
        // "loopback" alone is a deliberate statement; do not second-guess it.
        let mut a = acl(&["loopback"]);
        assert!(!a.trust_subnet("192.0.2.0".parse().unwrap(), 24));
        assert!(!a.allows(ip("192.0.2.2")));

        // An explicit CIDR list is equally deliberate.
        let mut b = acl(&["10.1.0.0/16"]);
        assert!(!b.trust_subnet("192.0.2.0".parse().unwrap(), 24));
        assert!(!b.allows(ip("192.0.2.2")));
        assert!(b.allows(ip("10.1.2.3")));
    }

    #[test]
    fn trust_subnet_is_a_no_op_when_already_covered() {
        let mut a = acl(&["private"]);
        // 192.168/16 is already private, so nothing needs adding.
        assert!(!a.trust_subnet("192.168.1.0".parse().unwrap(), 24));
        assert!(a.allows(ip("192.168.1.10")));
    }

    #[test]
    fn empty_rules_opt_into_lan_trust() {
        let mut a = Acl::parse(&[]).unwrap();
        assert!(a.trust_subnet("203.0.113.0".parse().unwrap(), 24));
        assert!(a.allows(ip("203.0.113.7")));
    }

    #[test]
    fn bad_entries_are_rejected_with_a_useful_message() {
        for bad in [
            "nonsense",
            "192.168.1.0",
            "192.168.1.0/33",
            "not/an/ip",
            "/24",
        ] {
            let err = Acl::parse(&[bad.to_string()]).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("allow_from"),
                "error for {bad:?} should name the setting, got: {msg}"
            );
        }
    }
}
