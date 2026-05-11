//! RADIUS client (RFC 2865 / RFC 3579) used to consult the existing
//! `radius-server` before making lease decisions.
//!
//! One round trip per Discover/Request:
//!
//!   dhcp-server  →  Access-Request
//!     User-Name = client MAC ("aa:bb:cc:dd:ee:ff" — radius-server's
//!                              `classify` heuristic routes any MAC-shaped
//!                              User-Name to the DHCP code path)
//!     User-Password = encrypted MAC (kept for parity with RouterOS, not
//!                                    actually validated on the DHCP path)
//!     NAS-Identifier = "dhcp-ext"
//!     VSA vendor=3561 sub-type=1 = Circuit-Id (DSL-Forum / TR-101 layout
//!                                              — the same shape RouterOS
//!                                              forwards Option 82 in)
//!     VSA vendor=3561 sub-type=2 = Remote-Id  (the client MAC bytes)
//!     Message-Authenticator      = HMAC-MD5 of the whole packet
//!
//!   radius-server  →  Access-Accept (with optional Framed-IP-Address)
//!                  or Access-Reject
//!
//! We hand-roll the wire format because we only need a sliver of RFC 2865
//! and pulling in a full client crate is overkill. The existing
//! `radius-server` validates Message-Authenticator strictly, so we compute
//! it correctly: the field is set to 16 zero bytes during HMAC computation,
//! then the result patches it in place before sending.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use hmac::{Hmac, Mac as _};
use md5::{Digest, Md5};
use rand::Rng;

use crate::dhcp::LineIdentity;
use crate::wire::Mac;

const ACCESS_REQUEST: u8 = 1;
const ACCESS_ACCEPT: u8 = 2;
const ACCESS_REJECT: u8 = 3;

const ATTR_USER_NAME: u8 = 1;
const ATTR_USER_PASSWORD: u8 = 2;
const ATTR_FRAMED_IP_ADDRESS: u8 = 8;
const ATTR_VENDOR_SPECIFIC: u8 = 26;
const ATTR_NAS_IDENTIFIER: u8 = 32;
const ATTR_FRAMED_POOL: u8 = 88;
const ATTR_MESSAGE_AUTHENTICATOR: u8 = 80;

const VENDOR_DSL_FORUM: u32 = 3561;
const DSL_AGENT_CIRCUIT_ID: u8 = 1;
const DSL_AGENT_REMOTE_ID: u8 = 2;

const RADIUS_HEADER_LEN: usize = 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy)]
pub enum Decision {
    /// RADIUS approved — allocate from default pool.
    PoolDefault,
    /// RADIUS approved with a static IP (Framed-IP-Address). Honor exactly.
    Pinned(Ipv4Addr),
    /// RADIUS rejected — silently drop Discover, NAK Request.
    Reject,
}

impl Decision {
    pub fn pinned_ip(self) -> Option<Ipv4Addr> {
        match self {
            Decision::Pinned(ip) => Some(ip),
            _ => None,
        }
    }
}

pub struct Client {
    pub addr: SocketAddr,
    pub secret: String,
}

impl Client {
    pub fn new(addr: SocketAddr, secret: String) -> Self {
        Self { addr, secret }
    }

    pub fn authorize(&self, chaddr: Mac, identity: &LineIdentity) -> Decision {
        match self.try_authorize(chaddr, identity) {
            Ok(d) => d,
            Err(e) => {
                // Fail-open: if RADIUS is unreachable or replied with junk,
                // we still hand out a pool address rather than blocking the
                // client. A real ISP would fail-closed; for the lab,
                // fail-open keeps debugging tractable.
                log::warn!("radius authorize failed: {e}; falling back to pool");
                Decision::PoolDefault
            }
        }
    }

    fn try_authorize(&self, chaddr: Mac, identity: &LineIdentity) -> Result<Decision, String> {
        let mac_str = mac_str(&chaddr);
        let secret = self.secret.as_bytes();

        let mut req_auth = [0u8; 16];
        rand::thread_rng().fill(&mut req_auth);
        let id: u8 = rand::thread_rng().gen();

        // Build attributes. Order doesn't matter on the wire, but
        // Message-Authenticator must go last so we know its offset for the
        // patch-after-HMAC step below.
        //
        // The DSL-Forum convention (RFC 4679) puts the *line* identifier in
        // sub-type 1 (Circuit-Id) and the *device* identifier in sub-type 2
        // (Remote-Id). Real DSLAMs/OLTs follow this. RouterOS dhcp-relay
        // breaks the convention: it hardcodes Circuit-Id to the relay
        // interface's MAC (just hardware, no line info) and lets us
        // configure Remote-Id with `relay-info-remote-id="..."`. So in
        // RouterOS the *line* identifier arrives in the Remote-Id slot.
        //
        // We re-shuffle here on the way out: the most meaningful per-line
        // string (Remote-Id if present, else Circuit-Id) goes into RADIUS
        // sub-type 1, where the radius-server's resolver looks first. The
        // relay's interface MAC and the client MAC ride along in sub-type
        // 2 for accounting purposes.
        let primary_line_id = identity
            .remote_id
            .as_deref()
            .or(identity.circuit_id.as_deref());

        let mut attrs = Vec::with_capacity(128);
        push_attr(&mut attrs, ATTR_USER_NAME, mac_str.as_bytes());
        push_attr(&mut attrs, ATTR_NAS_IDENTIFIER, b"dhcp-ext");
        if let Some(line) = primary_line_id {
            push_dsl_vsa(&mut attrs, DSL_AGENT_CIRCUIT_ID, line.as_bytes());
        }
        // Remote-Id: client MAC (the device on the line). If we want to
        // keep the relay's own Circuit-Id around for forensics we could
        // append a vendor-specific extra here, but for now sub-type 2 just
        // identifies which device used the line.
        push_dsl_vsa(&mut attrs, DSL_AGENT_REMOTE_ID, &chaddr);
        let pw = encrypt_password(mac_str.as_bytes(), secret, &req_auth);
        push_attr(&mut attrs, ATTR_USER_PASSWORD, &pw);

        let ma_value_offset_in_attrs = attrs.len() + 2;
        push_attr(&mut attrs, ATTR_MESSAGE_AUTHENTICATOR, &[0u8; 16]);

        let total_len = RADIUS_HEADER_LEN + attrs.len();
        if total_len > 4096 {
            return Err(format!("packet too large: {total_len} bytes"));
        }
        let mut pkt = Vec::with_capacity(total_len);
        pkt.push(ACCESS_REQUEST);
        pkt.push(id);
        pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
        pkt.extend_from_slice(&req_auth);
        pkt.extend_from_slice(&attrs);

        // Patch in Message-Authenticator: HMAC-MD5 over the whole packet,
        // with the MA field still zeros at this point.
        let ma = hmac_md5(secret, &pkt);
        let ma_offset = RADIUS_HEADER_LEN + ma_value_offset_in_attrs;
        pkt[ma_offset..ma_offset + 16].copy_from_slice(&ma);

        // One-shot UDP exchange. Bind ephemeral, send, recv with timeout.
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
        socket
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|e| format!("timeout: {e}"))?;
        socket
            .send_to(&pkt, self.addr)
            .map_err(|e| format!("send: {e}"))?;

        let mut buf = vec![0u8; 4096];
        let n = socket.recv(&mut buf).map_err(|e| format!("recv: {e}"))?;
        let resp = &buf[..n];
        if resp.len() < RADIUS_HEADER_LEN {
            return Err(format!("response too short: {n} bytes"));
        }
        if resp[1] != id {
            return Err(format!("response id mismatch: sent {id} got {}", resp[1]));
        }

        // Validate Response Authenticator: MD5(Code | ID | Length |
        // RequestAuthenticator | ResponseAttributes | Secret). RFC 2865 §3.
        let mut hasher = Md5::new();
        hasher.update(&resp[0..4]);
        hasher.update(&req_auth);
        hasher.update(&resp[20..n]);
        hasher.update(secret);
        let expected = hasher.finalize();
        if resp[4..20] != expected[..] {
            return Err("response authenticator mismatch".into());
        }

        match resp[0] {
            ACCESS_ACCEPT => Ok(decision_from_accept(&resp[20..n])),
            ACCESS_REJECT => Ok(Decision::Reject),
            other => Err(format!("unexpected response code {other}")),
        }
    }
}

fn decision_from_accept(attrs: &[u8]) -> Decision {
    if let Some(ip_bytes) = find_attr(attrs, ATTR_FRAMED_IP_ADDRESS) {
        if ip_bytes.len() == 4 {
            let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            log::info!("radius accept: Framed-IP-Address={ip}");
            return Decision::Pinned(ip);
        }
    }
    if let Some(pool) = find_attr(attrs, ATTR_FRAMED_POOL) {
        // Framed-Pool support would require the dhcp-server to know about
        // multiple named pools. For now we honor it as "use the default
        // pool" and just log; wiring named pools is a follow-up.
        log::info!(
            "radius accept: Framed-Pool={} (using default pool)",
            String::from_utf8_lossy(pool)
        );
    }
    Decision::PoolDefault
}

fn push_attr(attrs: &mut Vec<u8>, typ: u8, value: &[u8]) {
    debug_assert!(value.len() <= 253, "RADIUS attribute too long");
    attrs.push(typ);
    attrs.push((value.len() + 2) as u8);
    attrs.extend_from_slice(value);
}

fn push_dsl_vsa(attrs: &mut Vec<u8>, sub_type: u8, value: &[u8]) {
    let mut payload = Vec::with_capacity(6 + value.len());
    payload.extend_from_slice(&VENDOR_DSL_FORUM.to_be_bytes());
    payload.push(sub_type);
    payload.push((value.len() + 2) as u8);
    payload.extend_from_slice(value);
    push_attr(attrs, ATTR_VENDOR_SPECIFIC, &payload);
}

fn find_attr(attrs: &[u8], target: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= attrs.len() {
        let typ = attrs[i];
        let len = attrs[i + 1] as usize;
        if len < 2 || i + len > attrs.len() {
            return None;
        }
        if typ == target {
            return Some(&attrs[i + 2..i + len]);
        }
        i += len;
    }
    None
}

/// RFC 2865 §5.2 User-Password encryption: password is padded to a multiple
/// of 16 bytes, then each 16-byte block is XORed with MD5(secret | prev),
/// where `prev` is the Request Authenticator for the first block and the
/// previous ciphertext block thereafter.
fn encrypt_password(password: &[u8], secret: &[u8], req_auth: &[u8; 16]) -> Vec<u8> {
    let mut padded = password.to_vec();
    let pad = (16 - padded.len() % 16) % 16;
    padded.resize(padded.len() + pad, 0);
    if padded.is_empty() {
        padded.resize(16, 0);
    }

    let mut out = Vec::with_capacity(padded.len());
    let mut prev = req_auth.to_vec();
    for chunk in padded.chunks(16) {
        let mut hasher = Md5::new();
        hasher.update(secret);
        hasher.update(&prev);
        let block = hasher.finalize();
        let xor: Vec<u8> = chunk.iter().zip(block.iter()).map(|(a, b)| a ^ b).collect();
        out.extend_from_slice(&xor);
        prev = xor;
    }
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    type HmacMd5 = Hmac<Md5>;
    let mut mac = HmacMd5::new_from_slice(key).expect("any key length is valid for HMAC");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn mac_str(mac: &Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsa_packs_dsl_circuit_id() {
        let mut attrs = Vec::new();
        push_dsl_vsa(&mut attrs, DSL_AGENT_CIRCUIT_ID, b"ether3");
        assert_eq!(attrs[0], ATTR_VENDOR_SPECIFIC);
        assert_eq!(attrs[1] as usize, attrs.len());
        // vendor-id big-endian
        assert_eq!(&attrs[2..6], &VENDOR_DSL_FORUM.to_be_bytes());
        assert_eq!(attrs[6], DSL_AGENT_CIRCUIT_ID);
        assert_eq!(attrs[7] as usize, 2 + b"ether3".len());
        assert_eq!(&attrs[8..], b"ether3");
    }

    #[test]
    fn password_encryption_roundtrip() {
        // Verify symmetry: encrypt then "decrypt" with the same algorithm
        // yields the original plaintext (DHCP servers don't decrypt, but
        // this catches obvious off-by-ones in the chunk loop).
        let secret = b"secret";
        let req_auth = [0xab; 16];
        let plain = b"52:54:00:00:0a:01";
        let cipher = encrypt_password(plain, secret, &req_auth);
        assert_eq!(cipher.len() % 16, 0);
        // Decrypt = same op (XOR is symmetric per block).
        let mut prev = req_auth.to_vec();
        let mut decrypted = Vec::new();
        for chunk in cipher.chunks(16) {
            let mut h = Md5::new();
            h.update(secret);
            h.update(&prev);
            let block = h.finalize();
            for (i, b) in chunk.iter().enumerate() {
                decrypted.push(b ^ block[i]);
            }
            prev = chunk.to_vec();
        }
        // Trim trailing zeros from padding.
        let trimmed: &[u8] = match decrypted.iter().rposition(|&b| b != 0) {
            Some(p) => &decrypted[..=p],
            None => &[],
        };
        assert_eq!(trimmed, plain);
    }
}
