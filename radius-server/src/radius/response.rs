use super::SECRET;
use hmac::{Hmac, Mac};
use md5::Md5;
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::dict::rfc2869;

pub fn finalize(mut resp: Packet, req_authenticator: &[u8]) -> Vec<u8> {
    rfc2869::add_message_authenticator(&mut resp, &[0u8; 16]);

    let mut tmp = resp.encode().unwrap();
    tmp[4..20].copy_from_slice(req_authenticator);
    let mut mac = Hmac::<Md5>::new_from_slice(SECRET).unwrap();
    mac.update(&tmp);
    let hmac_result = mac.finalize().into_bytes();

    rfc2869::delete_message_authenticator(&mut resp);
    rfc2869::add_message_authenticator(&mut resp, &hmac_result);
    resp.encode().unwrap()
}

pub fn make(req_packet: &Packet, code: Code) -> Packet {
    req_packet.make_response_packet(code)
}

pub fn encode(req_packet: &Packet, code: Code) -> Vec<u8> {
    finalize(make(req_packet, code), req_packet.authenticator())
}
