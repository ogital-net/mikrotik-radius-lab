use anyhow::Result;
use clap::Parser;
use log::info;
use std::net::Ipv4Addr;

mod dhcp;
mod pool;
mod qemu;
mod radius_upstream;
mod wire;

/// dhcp-server: a tiny lab DHCPv4 server that joins the QEMU lab via a
/// socket-netdev TCP link, plays the role real ISPs assign to a separate
/// box (Kea / ISC dhcpd / Windows DHCP), and consults the existing
/// `radius-server` for per-line policy decisions.
///
/// The whole binary is a single thread:
///   1. read a length-prefixed Ethernet frame from the QEMU socket-netdev,
///   2. dispatch ARP / DHCP-over-UDP to the right handler,
///   3. build and write back the Ethernet response.
///
/// There is no kernel networking involved — the binary speaks raw frames
/// directly to QEMU's virtual switch. That's why it doesn't need root.
#[derive(Parser)]
struct Args {
    /// QEMU socket-netdev endpoint we connect to. CHR-CORE listens on its
    /// "server segment" interface using `-netdev socket,...,listen=:22229`.
    #[arg(long, default_value = "127.0.0.1:22229")]
    qemu: String,

    /// IPv4 address this server presents on the server segment. Must live
    /// in the same /24 as CHR-CORE's server-side interface (192.168.99.1).
    #[arg(long, default_value = "192.168.99.2")]
    ip: Ipv4Addr,

    /// MAC for our virtual NIC. CHR-CORE will ARP for `ip` and learn this.
    #[arg(long, default_value = "52:54:00:00:dd:01")]
    mac: String,

    /// Default DHCP pool range. Used when RADIUS doesn't override with
    /// Framed-IP-Address / Framed-Pool.
    #[arg(long, default_value = "192.168.50.100")]
    pool_start: Ipv4Addr,
    #[arg(long, default_value = "192.168.50.200")]
    pool_end: Ipv4Addr,

    /// Network parameters returned to clients in OFFER / ACK.
    #[arg(long, default_value = "192.168.50.1")]
    client_gateway: Ipv4Addr,
    #[arg(long, default_value = "255.255.255.0")]
    client_netmask: Ipv4Addr,
    #[arg(long, default_value = "8.8.8.8")]
    client_dns: Ipv4Addr,

    /// Lease lifetime in seconds (10 minutes by default — short so the lab
    /// exercises renew/rebind quickly).
    #[arg(long, default_value_t = 600)]
    lease_seconds: u32,

    /// Upstream RADIUS server. Same one the HotSpot/DHCP labs already use.
    #[arg(long, default_value = "127.0.0.1:1812")]
    radius: std::net::SocketAddr,

    /// RADIUS shared secret (matches `radius-server::radius::SECRET`).
    #[arg(long, default_value = "secret")]
    radius_secret: String,

    /// If true, allocate from the local pool only and never call RADIUS.
    /// Useful for bring-up before the upstream is wired in.
    #[arg(long, default_value_t = false)]
    no_radius: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let mac = wire::parse_mac(&args.mac)?;
    info!(
        "dhcp-server starting: ip={} mac={} qemu={} pool={}..{} radius={}{}",
        args.ip,
        args.mac,
        args.qemu,
        args.pool_start,
        args.pool_end,
        args.radius,
        if args.no_radius { " (DISABLED)" } else { "" },
    );

    let mut link = qemu::Link::connect(&args.qemu)?;
    let mut pool = pool::Pool::new(args.pool_start, args.pool_end);
    let radius = if args.no_radius {
        None
    } else {
        Some(radius_upstream::Client::new(
            args.radius,
            args.radius_secret.clone(),
        ))
    };

    info!("event loop running — waiting for frames from CHR-CORE");
    loop {
        let frame = match link.read_frame() {
            Ok(f) => f,
            Err(e) => {
                log::error!("link read error: {e:?}; exiting");
                return Err(e);
            }
        };

        let mut handler = dhcp::Handler {
            server_ip: args.ip,
            server_mac: mac,
            gateway: args.client_gateway,
            netmask: args.client_netmask,
            dns: args.client_dns,
            lease_seconds: args.lease_seconds,
            pool: &mut pool,
            radius: radius.as_ref(),
        };

        if let Some(reply) = wire::dispatch(&frame, args.ip, mac, &mut handler) {
            if let Err(e) = link.write_frame(&reply) {
                log::error!("link write error: {e:?}");
            }
        }
    }
}
