//! Ethernet / ARP / IPv4 / UDP dispatch.
//!
//! We do not run a real OS network stack — we are speaking raw frames to
//! QEMU's virtual switch. Two protocols matter:
//!
//!   * **ARP** — CHR-CORE will broadcast `who-has 192.168.99.2 tell 192.168.99.1`
//!     before it can send us anything. We reply with our MAC, and from then
//!     on it sends DHCP packets unicast to us.
//!
//!   * **IPv4/UDP/67** — DHCP messages, relayed to us by CHR-CORE. Each one
//!     arrives as an Ethernet frame: relay's MAC → our MAC, relay's IP →
//!     our IP, src/dst port 67. We hand the DHCP payload to `dhcp::Handler`,
//!     and if it produces a reply we wrap it back in UDP/IPv4/Ethernet
//!     pointed at whoever sent the request.
//!
//! Anything else (IPv6 RAs, broadcast garbage, etc.) is ignored.

use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

use crate::dhcp;

pub type Mac = [u8; 6];

const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;
const IPPROTO_UDP: u8 = 17;
const DHCP_PORT: u16 = 67;

pub fn parse_mac(s: &str) -> Result<Mac> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!("MAC must be 6 colon-separated bytes: {s}"));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|_| anyhow!("bad MAC byte: {p}"))?;
    }
    Ok(out)
}

pub fn dispatch(frame: &[u8], our_ip: Ipv4Addr, our_mac: Mac, h: &mut dhcp::Handler) -> Option<Vec<u8>> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac: Mac = frame[0..6].try_into().ok()?;
    let src_mac: Mac = frame[6..12].try_into().ok()?;
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    // Frames go to either our unicast MAC or broadcast. Anything else is a
    // QEMU-switch artifact (e.g. another guest's traffic) and we drop it.
    let bcast = [0xff; 6];
    if dst_mac != our_mac && dst_mac != bcast {
        return None;
    }

    let payload = &frame[14..];
    match ethertype {
        ETH_TYPE_ARP => handle_arp(payload, src_mac, our_ip, our_mac),
        ETH_TYPE_IPV4 => handle_ipv4(payload, src_mac, our_ip, our_mac, h),
        _ => None,
    }
}

fn handle_arp(arp: &[u8], src_mac: Mac, our_ip: Ipv4Addr, our_mac: Mac) -> Option<Vec<u8>> {
    // ARP packet (IPv4 over Ethernet): 28 bytes, fields per RFC 826.
    //   htype=1 ptype=0x0800 hlen=6 plen=4 op=1(req)/2(reply)
    //   sha[6] spa[4] tha[6] tpa[4]
    if arp.len() < 28 {
        return None;
    }
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    if op != 1 {
        return None; // not a request — replies are someone else's problem
    }
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
    if target_ip != our_ip {
        return None; // not asking for us
    }
    let sender_mac: Mac = arp[8..14].try_into().ok()?;
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    log::debug!("arp who-has {our_ip} tell {sender_ip} → reply with {our_mac:02x?}");

    let mut reply = Vec::with_capacity(14 + 28);
    reply.extend_from_slice(&src_mac);
    reply.extend_from_slice(&our_mac);
    reply.extend_from_slice(&ETH_TYPE_ARP.to_be_bytes());
    reply.extend_from_slice(&[0x00, 0x01]);                // htype: Ethernet
    reply.extend_from_slice(&[0x08, 0x00]);                // ptype: IPv4
    reply.extend_from_slice(&[6, 4]);                      // hlen, plen
    reply.extend_from_slice(&2u16.to_be_bytes());          // op: reply
    reply.extend_from_slice(&our_mac);                     // sha
    reply.extend_from_slice(&our_ip.octets());             // spa
    reply.extend_from_slice(&sender_mac);                  // tha
    reply.extend_from_slice(&sender_ip.octets());          // tpa
    Some(reply)
}

fn handle_ipv4(
    ipv4: &[u8],
    src_mac: Mac,
    our_ip: Ipv4Addr,
    our_mac: Mac,
    h: &mut dhcp::Handler,
) -> Option<Vec<u8>> {
    use etherparse::{Ipv4HeaderSlice, UdpHeaderSlice};

    let ip_hdr = Ipv4HeaderSlice::from_slice(ipv4).ok()?;
    if ip_hdr.protocol().0 != IPPROTO_UDP {
        return None;
    }
    if ip_hdr.destination_addr() != our_ip {
        return None;
    }
    let ip_total = ip_hdr.total_len() as usize;
    let ip_payload_off = ip_hdr.slice().len();
    if ip_total > ipv4.len() {
        return None;
    }
    let udp_and_data = &ipv4[ip_payload_off..ip_total];
    let udp_hdr = UdpHeaderSlice::from_slice(udp_and_data).ok()?;
    if udp_hdr.destination_port() != DHCP_PORT {
        return None;
    }
    let dhcp_payload = &udp_and_data[8..];
    let src_ip = ip_hdr.source_addr();
    let src_port = udp_hdr.source_port();

    let reply_dhcp = h.handle(dhcp_payload, src_ip)?;

    // Per RFC 2131 §4.1, a server MUST send replies to a relayed request
    // back to the relay's giaddr on UDP/67. In our lab the relay's giaddr
    // (192.168.50.1, the client-facing side) is NOT on our subnet, so we
    // can't reach it directly — we send back to whatever IP/MAC actually
    // delivered the request (i.e. the relay's server-side address). The
    // relay's L3 stack still accepts it because the dst_ip equals one of
    // its own interfaces, and rebroadcasts the OFFER/ACK to the client
    // based on giaddr inside the DHCP payload.
    Some(build_ipv4_udp(
        our_mac, src_mac, our_ip, src_ip, DHCP_PORT, src_port, &reply_dhcp,
    ))
}

fn build_ipv4_udp(
    src_mac: Mac,
    dst_mac: Mac,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use etherparse::PacketBuilder;

    let mut out = Vec::with_capacity(14 + 20 + 8 + payload.len());
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip.octets(), dst_ip.octets(), 64)
        .udp(src_port, dst_port);
    // PacketBuilder writes Ethernet → IPv4 → UDP and computes both
    // checksums for us. The IPv4 ID field defaults to 0, which is fine
    // since DHCP packets are short and never fragmented.
    builder.write(&mut out, payload).expect("packet build");
    out
}
