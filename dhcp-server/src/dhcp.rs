//! DHCPv4 server — the DORA state machine.
//!
//! `D`iscover → we learn the client wants an address.
//! `O`ffer    → we propose one (and bookkeep it as tentatively held).
//! `R`equest  → the client confirms which OFFER it picked (servers fight for
//!              clients in a multi-server LAN; the client only accepts one).
//! `A`ck      → we lock the lease in.
//!
//! In a relayed setup (which is the only setup we serve), every message
//! arrives with `giaddr` set to the relay's client-facing IP. We always send
//! replies back at L4 to whoever sent the packet (see `wire.rs`); the relay
//! handles broadcasting to the actual client based on giaddr.

use std::net::Ipv4Addr;
use std::time::Duration;

use dhcproto::v4::{
    relay::{RelayCode, RelayInfo},
    DhcpOption, Message, MessageType, Opcode, OptionCode,
};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};

use crate::pool::Pool;
use crate::radius_upstream::{Client as RadiusClient, Decision};
use crate::wire::Mac;

/// What we know about the subscriber line, extracted from Option 82.
/// Either or both can be missing depending on relay configuration; the
/// upstream RADIUS lookup tries Circuit-Id first, then falls back to
/// Remote-Id, mirroring the existing radius-server's resolver.
pub struct LineIdentity {
    pub circuit_id: Option<String>,
    pub remote_id: Option<String>,
}

pub struct Handler<'a> {
    pub server_ip: Ipv4Addr,
    pub server_mac: Mac,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub lease_seconds: u32,
    pub pool: &'a mut Pool,
    pub radius: Option<&'a RadiusClient>,
}

impl<'a> Handler<'a> {
    /// Process one DHCP payload (the bytes after the UDP header). Returns
    /// the encoded reply to send back, or None to stay silent (for messages
    /// we don't answer, like RELEASE).
    pub fn handle(&mut self, payload: &[u8], from: Ipv4Addr) -> Option<Vec<u8>> {
        let msg = match Message::decode(&mut Decoder::new(payload)) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("dhcp decode error from {from}: {e}");
                return None;
            }
        };
        log::info!("dhcp opts: {:?}", msg.opts());
        let mt = msg.opts().msg_type()?;
        let chaddr = chaddr_to_mac(msg.chaddr())?;
        let circuit_id = circuit_id_from(&msg);
        let remote_id = remote_id_from(&msg);

        log::info!(
            "dhcp <-{from} {mt:?} chaddr={} xid=0x{:08x} giaddr={} circuit_id={:?} remote_id={:?}",
            mac_str(&chaddr),
            msg.xid(),
            msg.giaddr(),
            circuit_id.as_deref().unwrap_or("<none>"),
            remote_id.as_deref().unwrap_or("<none>"),
        );

        let identity = LineIdentity { circuit_id, remote_id };
        match mt {
            MessageType::Discover => self.on_discover(&msg, chaddr, &identity),
            MessageType::Request => self.on_request(&msg, chaddr, &identity),
            MessageType::Release | MessageType::Decline => {
                self.pool.release(chaddr);
                None
            }
            other => {
                log::debug!("ignoring DHCP {other:?}");
                None
            }
        }
    }

    fn on_discover(
        &mut self,
        req: &Message,
        chaddr: Mac,
        identity: &LineIdentity,
    ) -> Option<Vec<u8>> {
        let decision = self.consult_radius(chaddr, identity);
        if matches!(decision, Decision::Reject) {
            log::info!("dhcp REJECT chaddr={} (RADIUS denied)", mac_str(&chaddr));
            return None; // silently drop — DHCP has no NAK for Discover
        }
        let pinned = decision.pinned_ip();
        let ttl = Duration::from_secs(self.lease_seconds as u64);
        let offered = self.pool.offer(chaddr, pinned, ttl)?;
        log::info!("dhcp -> OFFER {offered} to {}", mac_str(&chaddr));
        Some(self.build_reply(req, MessageType::Offer, offered))
    }

    fn on_request(
        &mut self,
        req: &Message,
        chaddr: Mac,
        identity: &LineIdentity,
    ) -> Option<Vec<u8>> {
        // The IP the client wants is in option 50 (RequestedIpAddress) when
        // the client is in the "selecting" phase, or in `ciaddr` when it's
        // renewing. We try both.
        let requested = match req.opts().get(OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(ip)) => *ip,
            _ => req.ciaddr(),
        };
        if requested.is_unspecified() {
            log::warn!(
                "dhcp REQUEST from {} with no requested IP",
                mac_str(&chaddr)
            );
            return Some(self.build_nak(req));
        }
        let decision = self.consult_radius(chaddr, identity);
        if matches!(decision, Decision::Reject) {
            return Some(self.build_nak(req));
        }
        // If RADIUS pinned a specific IP and the client wants something
        // else (e.g. a stale lease from before policy was wired in), force
        // a re-discover by NAK'ing. The client will broadcast Discover
        // again and this time we'll Offer the policy IP.
        if let Some(pinned) = decision.pinned_ip() {
            if pinned != requested {
                log::warn!(
                    "dhcp REQUEST {requested} from {} != RADIUS pinned {pinned} — NAK",
                    mac_str(&chaddr)
                );
                return Some(self.build_nak(req));
            }
        }
        let ttl = Duration::from_secs(self.lease_seconds as u64);
        if !self.pool.commit(chaddr, requested, ttl) {
            log::warn!(
                "dhcp REQUEST {requested} from {} doesn't match lease — NAK",
                mac_str(&chaddr)
            );
            return Some(self.build_nak(req));
        }
        log::info!("dhcp -> ACK {requested} to {}", mac_str(&chaddr));
        Some(self.build_reply(req, MessageType::Ack, requested))
    }

    fn consult_radius(&self, chaddr: Mac, identity: &LineIdentity) -> Decision {
        let Some(client) = self.radius else {
            // No upstream configured → permissive, allocate from local pool.
            return Decision::PoolDefault;
        };
        if identity.circuit_id.is_none() && identity.remote_id.is_none() {
            // RADIUS is on but the relay didn't include Option 82 at all.
            // RFC says the message is still valid; we allow but log.
            log::warn!("dhcp request without any line identity; allowing from default pool");
            return Decision::PoolDefault;
        }
        client.authorize(chaddr, identity)
    }

    fn build_reply(&self, req: &Message, mt: MessageType, yiaddr: Ipv4Addr) -> Vec<u8> {
        let mut reply = Message::default();
        reply
            .set_opcode(Opcode::BootReply)
            .set_xid(req.xid())
            .set_flags(req.flags())
            .set_ciaddr(req.ciaddr())
            .set_yiaddr(yiaddr)
            .set_siaddr(self.server_ip)
            .set_giaddr(req.giaddr())
            .set_chaddr(req.chaddr());

        // The relay's giaddr is the client's gateway, by definition: it's
        // the IP on the relay's interface facing the client. In a per-port-
        // relay topology each line has its own giaddr → its own gateway,
        // and the static `--client-gateway` arg only acts as a fallback for
        // requests that arrive without giaddr (which shouldn't happen here).
        let client_gateway = if req.giaddr().is_unspecified() {
            self.gateway
        } else {
            req.giaddr()
        };

        let opts = reply.opts_mut();
        opts.insert(DhcpOption::MessageType(mt));
        opts.insert(DhcpOption::ServerIdentifier(self.server_ip));
        opts.insert(DhcpOption::AddressLeaseTime(self.lease_seconds));
        opts.insert(DhcpOption::SubnetMask(self.netmask));
        opts.insert(DhcpOption::Router(vec![client_gateway]));
        opts.insert(DhcpOption::DomainNameServer(vec![self.dns]));
        // RFC 2131: server SHOULD echo back the relay agent info from the
        // request so the relay can correlate the reply with its own state.
        if let Some(opt @ DhcpOption::RelayAgentInformation(_)) =
            req.opts().get(OptionCode::RelayAgentInformation)
        {
            opts.insert(opt.clone());
        }

        encode(&reply)
    }

    fn build_nak(&self, req: &Message) -> Vec<u8> {
        let mut nak = Message::default();
        nak.set_opcode(Opcode::BootReply)
            .set_xid(req.xid())
            .set_flags(req.flags())
            .set_giaddr(req.giaddr())
            .set_chaddr(req.chaddr());
        let opts = nak.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::Nak));
        opts.insert(DhcpOption::ServerIdentifier(self.server_ip));
        encode(&nak)
    }
}

fn encode(msg: &Message) -> Vec<u8> {
    let mut buf = Vec::with_capacity(300);
    let mut e = Encoder::new(&mut buf);
    msg.encode(&mut e).expect("dhcp encode");
    buf
}

fn chaddr_to_mac(chaddr: &[u8]) -> Option<Mac> {
    if chaddr.len() < 6 {
        return None;
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&chaddr[..6]);
    Some(out)
}

fn mac_str(mac: &Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Pull the Circuit-Id sub-option out of Option 82 (RFC 3046). The relay
/// (CHR-ACCESS or CHR-CORE depending on which lab mode you're in) puts a
/// per-port identifier here — that identifier is the subscriber's identity.
///
/// Different relays encode it differently:
///   - explicit string ("acc01:eth2", "ether2") when the relay was told
///     to use a specific Circuit-Id
///   - raw 6-byte MAC of the relay's interface (RouterOS default with
///     `add-relay-info=yes` and no override)
///   - opaque binary blob from vendor-specific gear (DSLAMs / OLTs)
///
/// We try UTF-8 first; if that fails we fall back to a MAC-style hex
/// rendering. The radius-server's subscriber lookup just key-compares the
/// resulting string, so as long as we render consistently the lookup works.
fn circuit_id_from(msg: &Message) -> Option<String> {
    let DhcpOption::RelayAgentInformation(info) =
        msg.opts().get(OptionCode::RelayAgentInformation)?
    else {
        return None;
    };
    let RelayInfo::AgentCircuitId(bytes) = info.get(RelayCode::AgentCircuitId)? else {
        return None;
    };
    Some(stringify_circuit_id(bytes))
}

/// Pull the Remote-Id sub-option out of Option 82. RouterOS exposes this
/// as `relay-info-remote-id` — settable to any string per relay, so we
/// use it to carry friendly per-line identifiers like "ether2" / "ether3"
/// when Circuit-Id falls back to a less-identifying default (interface MAC).
fn remote_id_from(msg: &Message) -> Option<String> {
    let DhcpOption::RelayAgentInformation(info) =
        msg.opts().get(OptionCode::RelayAgentInformation)?
    else {
        return None;
    };
    let RelayInfo::AgentRemoteId(bytes) = info.get(RelayCode::AgentRemoteId)? else {
        return None;
    };
    Some(stringify_circuit_id(bytes))
}

fn stringify_circuit_id(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if !s.is_empty() && !s.bytes().any(|b| b.is_ascii_control()) {
            return s.to_string();
        }
    }
    if bytes.len() == 6 {
        return format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        );
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::stringify_circuit_id;

    #[test]
    fn utf8_circuit_id_passes_through() {
        assert_eq!(stringify_circuit_id(b"ether2"), "ether2");
        assert_eq!(stringify_circuit_id(b"acc01:eth3"), "acc01:eth3");
    }

    #[test]
    fn binary_mac_renders_as_colon_hex() {
        let mac = [0x52, 0x54, 0x00, 0x00, 0xc0, 0x01];
        assert_eq!(stringify_circuit_id(&mac), "52:54:00:00:c0:01");
    }

    #[test]
    fn opaque_binary_renders_as_hex() {
        assert_eq!(stringify_circuit_id(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn rejects_strings_with_control_bytes() {
        // 6-byte payload that happens to be ASCII printable except for a NUL
        // — falls through to MAC formatter rather than producing "ab\0cd1"
        let payload = [b'a', b'b', 0, b'c', b'd', b'1'];
        assert_eq!(stringify_circuit_id(&payload), "61:62:00:63:64:31");
    }
}
