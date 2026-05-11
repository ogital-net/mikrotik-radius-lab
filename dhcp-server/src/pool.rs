//! IP pool & lease state.
//!
//! A pool is just a contiguous range of IPv4 addresses plus a map of who
//! currently holds each lease. The interesting bits are the *rules* a real
//! DHCP server follows:
//!
//!   1. **Sticky.** If a client's MAC already has a non-expired lease, hand
//!      back the same IP. This is what makes a laptop wake up on the same
//!      address it had yesterday.
//!
//!   2. **Pin from policy.** If RADIUS returned a Framed-IP-Address, that
//!      IP wins regardless of pool — even if it's outside the range. (In
//!      production this is how an ISP gives a business customer a static
//!      address while everyone else floats in a pool.)
//!
//!   3. **OFFER vs LEASED.** When we send an OFFER we mark the IP as
//!      "tentatively reserved." Only on REQUEST/ACK do we flip it to
//!      "leased." This prevents two parallel Discovers from colliding.
//!
//! Lease expiry is swept lazily — every allocate call drops anything
//! that's past its `expires_at`. Good enough for a lab; a real server runs
//! a background sweep so dead leases free up even when nobody's asking.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub type Mac = [u8; 6];

#[derive(Debug, Clone)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mac: Mac,
    pub state: LeaseState,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Offered,
    Leased,
}

pub struct Pool {
    start: u32,
    end: u32,
    by_mac: HashMap<Mac, Lease>,
    by_ip: HashMap<u32, Mac>,
}

impl Pool {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            start: u32::from(start),
            end: u32::from(end),
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
        }
    }

    /// Reserve an IP for a Discover. Returns the IP we'll put in the OFFER.
    /// Callers may pass `pinned_ip` (typically from RADIUS Framed-IP-Address)
    /// to bypass pool selection entirely.
    pub fn offer(&mut self, mac: Mac, pinned_ip: Option<Ipv4Addr>, ttl: Duration) -> Option<Ipv4Addr> {
        self.sweep();

        if let Some(ip) = pinned_ip {
            return Some(self.record(mac, ip, LeaseState::Offered, ttl));
        }

        if let Some(existing) = self.by_mac.get(&mac).cloned() {
            // Sticky: same MAC always gets the same IP unless something else
            // forced a change. We renew the timer.
            return Some(self.record(mac, existing.ip, LeaseState::Offered, ttl));
        }

        let ip = self.first_free()?;
        Some(self.record(mac, ip, LeaseState::Offered, ttl))
    }

    /// Confirm a lease on REQUEST/ACK. Returns true if the requested IP
    /// matches what we offered (or if we can satisfy the request).
    pub fn commit(&mut self, mac: Mac, requested: Ipv4Addr, ttl: Duration) -> bool {
        self.sweep();
        let req_u32 = u32::from(requested);
        if let Some(&owner) = self.by_ip.get(&req_u32) {
            if owner != mac {
                // Someone else holds this IP — refuse.
                return false;
            }
        }
        self.record(mac, requested, LeaseState::Leased, ttl);
        true
    }

    pub fn release(&mut self, mac: Mac) {
        if let Some(l) = self.by_mac.remove(&mac) {
            self.by_ip.remove(&u32::from(l.ip));
        }
    }

    fn record(&mut self, mac: Mac, ip: Ipv4Addr, state: LeaseState, ttl: Duration) -> Ipv4Addr {
        // If this MAC previously held a different IP, free the old one.
        if let Some(old) = self.by_mac.get(&mac).cloned() {
            if old.ip != ip {
                self.by_ip.remove(&u32::from(old.ip));
            }
        }
        let lease = Lease {
            ip,
            mac,
            state,
            expires_at: Instant::now() + ttl,
        };
        self.by_ip.insert(u32::from(ip), mac);
        self.by_mac.insert(mac, lease);
        ip
    }

    fn first_free(&self) -> Option<Ipv4Addr> {
        for n in self.start..=self.end {
            if !self.by_ip.contains_key(&n) {
                return Some(Ipv4Addr::from(n));
            }
        }
        None
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        let dead: Vec<Mac> = self
            .by_mac
            .iter()
            .filter(|(_, l)| l.expires_at <= now)
            .map(|(m, _)| *m)
            .collect();
        for m in dead {
            if let Some(l) = self.by_mac.remove(&m) {
                self.by_ip.remove(&u32::from(l.ip));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(last: u8) -> Mac {
        [0x52, 0x54, 0x00, 0x00, 0x00, last]
    }

    #[test]
    fn offers_first_free() {
        let mut p = Pool::new(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        let ip = p.offer(mac(1), None, Duration::from_secs(60)).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 100));
    }

    #[test]
    fn sticky_for_same_mac() {
        let mut p = Pool::new(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        let ip1 = p.offer(mac(1), None, Duration::from_secs(60)).unwrap();
        let ip2 = p.offer(mac(2), None, Duration::from_secs(60)).unwrap();
        let ip1_again = p.offer(mac(1), None, Duration::from_secs(60)).unwrap();
        assert_eq!(ip1, ip1_again);
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn pinned_ip_overrides_pool() {
        let mut p = Pool::new(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        // Outside the pool — RADIUS-issued static IP.
        let pinned = Ipv4Addr::new(10, 0, 0, 5);
        let ip = p.offer(mac(1), Some(pinned), Duration::from_secs(60)).unwrap();
        assert_eq!(ip, pinned);
    }

    #[test]
    fn commit_rejects_someone_elses_ip() {
        let mut p = Pool::new(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        let ip = p.offer(mac(1), None, Duration::from_secs(60)).unwrap();
        // mac(2) tries to claim mac(1)'s IP.
        assert!(!p.commit(mac(2), ip, Duration::from_secs(60)));
    }
}
