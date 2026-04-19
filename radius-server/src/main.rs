#[macro_use]
extern crate log;

use std::net::SocketAddr;
use std::{io, process};

use hmac::{Hmac, Mac};
use md5::Md5;
use tokio::net::UdpSocket;
use tokio::signal;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::dict::{mikrotik, rfc2865, rfc2869};
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

const SECRET: &[u8] = b"secret";

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut server = Server::listen("0.0.0.0", 1812, MyRequestHandler {}, MySecretProvider {})
        .await
        .unwrap();
    server.set_buffer_size(1500);
    server.set_skip_authenticity_validation(false);

    info!("server is now ready: {}", server.listen_address().unwrap());

    let result = server.run(signal::ctrl_c()).await;
    info!("{:?}", result);
    if result.is_err() {
        process::exit(1);
    }
}

/// Build a RADIUS response with a correct Message-Authenticator (HMAC-MD5).
///
/// Uses the radius-rs library helpers to build the packet, then manually
/// computes the Message-Authenticator HMAC (which the library doesn't handle).
fn build_response(req_packet: &radius::core::packet::Packet, code: Code) -> Vec<u8> {
    let req_auth = req_packet.authenticator();

    let mut resp = req_packet.make_response_packet(code);

    if code == Code::AccessAccept {
        mikrotik::add_mikrotik_rate_limit(&mut resp, "10M/10M");
    }

    // Add zeroed Message-Authenticator placeholder for HMAC computation
    rfc2869::add_message_authenticator(&mut resp, &[0u8; 16]);

    // First encode: serialize with zeroed MA to compute HMAC-MD5
    let mut tmp = resp.encode().unwrap();
    tmp[4..20].copy_from_slice(req_auth); // HMAC uses Request Authenticator
    let mut mac = Hmac::<Md5>::new_from_slice(SECRET).unwrap();
    mac.update(&tmp);
    let hmac_result = mac.finalize().into_bytes();

    // Replace zeroed MA with computed HMAC, then re-encode for correct Response Authenticator
    rfc2869::delete_message_authenticator(&mut resp);
    rfc2869::add_message_authenticator(&mut resp, &hmac_result);
    resp.encode().unwrap()
}

struct MyRequestHandler {}

impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();
        println!("received request from {}: {:?}", req.remote_addr(), req_packet);
        let maybe_user_name_attr = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password_attr = rfc2865::lookup_user_password(req_packet);

        let user_name = maybe_user_name_attr.unwrap().unwrap();
        let user_password = String::from_utf8(maybe_user_password_attr.unwrap().unwrap()).unwrap();
        let code = if user_name == "admin" && user_password == "p@ssw0rd" {
            Code::AccessAccept
        } else {
            Code::AccessReject
        };
        info!("response => {:?} for user '{}' to {}", code, user_name, req.remote_addr());

        let response_bytes = build_response(req_packet, code);
        conn.send_to(&response_bytes, req.remote_addr()).await?;
        Ok(())
    }
}

struct MySecretProvider {}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(SECRET.to_vec())
    }
}
