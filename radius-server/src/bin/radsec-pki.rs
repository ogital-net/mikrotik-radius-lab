//! Issue a private RadSec PKI: one CA, one server leaf, one client leaf.
//!
//! Run with:
//!   cargo run --bin radsec-pki -- [--out-dir DIR] [--ca-cn NAME]
//!                                 [--server-name DNS] [--client-name DNS]
//!
//! Re-running with an existing CA at `--out-dir` reuses it and only
//! re-issues the leaves.

use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Args {
    out_dir: PathBuf,
    ca_cn: String,
    server_name: String,
    server_ips: Vec<IpAddr>,
    client_name: String,
}

impl Args {
    fn parse() -> Result<Self, anyhow::Error> {
        let mut out_dir = PathBuf::from("radsec-certs");
        let mut ca_cn = "captive-portal RadSec CA".to_string();
        let mut server_name = "radsec.captive-portal.local".to_string();
        let mut server_ips: Vec<IpAddr> = Vec::new();
        let mut client_name = "mikrotik".to_string();

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let next = |it: &mut std::iter::Skip<std::env::Args>| {
                it.next()
                    .ok_or_else(|| anyhow::anyhow!("flag {flag} expects a value"))
            };
            match flag.as_str() {
                "--out-dir" => out_dir = PathBuf::from(next(&mut it)?),
                "--ca-cn" => ca_cn = next(&mut it)?,
                "--server-name" => server_name = next(&mut it)?,
                "--server-ip" => server_ips.push(next(&mut it)?.parse()?),
                "--client-name" => client_name = next(&mut it)?,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown flag: {other}"),
            }
        }

        Ok(Self {
            out_dir,
            ca_cn,
            server_name,
            server_ips,
            client_name,
        })
    }
}

fn print_help() {
    println!(
        "radsec-pki — generate a private RadSec PKI

USAGE:
    radsec-pki [OPTIONS]

OPTIONS:
    --out-dir DIR        output directory (default: ./radsec-certs)
    --ca-cn NAME         CA common name
    --server-name DNS    server SAN dNSName (the server's identity)
    --server-ip IP       add an IP SAN to the server cert. Repeatable.
                         Required when peers (e.g. MikroTik) connect by IP
                         literal rather than by name — most RadSec clients
                         refuse the handshake if the IP they dialled isn't
                         in the server cert's SAN list.
    --client-name DNS    client SAN dNSName (RADSEC_CLIENT_NAME for the server,
                         and the cert MikroTik will present)
"
    );
}

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse()?;
    fs::create_dir_all(&args.out_dir)?;

    let ca_cert_path = args.out_dir.join("ca.crt");
    let ca_key_path = args.out_dir.join("ca.key");

    let ca = if ca_cert_path.exists() && ca_key_path.exists() {
        println!("reusing existing CA at {}", ca_cert_path.display());
        let cert_pem = fs::read(&ca_cert_path)?;
        let key_pem = fs::read(&ca_key_path)?;
        CertificateAuthority::from_pem(&cert_pem, &key_pem)?
    } else {
        println!("issuing new CA: {}", args.ca_cn);
        let ca = CertificateAuthority::new(&args.ca_cn)?;
        write_pem(&ca_cert_path, &ca.cert_pem()?, false)?;
        write_pem(&ca_key_path, &ca.key_pem()?, true)?;
        ca
    };

    let mut server_sans = vec![SubjectAltName::Dns(args.server_name.clone())];
    for ip in &args.server_ips {
        server_sans.push(SubjectAltName::Ip(*ip));
    }
    println!(
        "issuing server leaf: {} (SANs: DNS:{}{})",
        args.server_name,
        args.server_name,
        args.server_ips
            .iter()
            .map(|ip| format!(", IP:{ip}"))
            .collect::<String>()
    );
    let server = ca.issue_server(&args.server_name, &server_sans)?;
    let server_crt = args.out_dir.join("server.crt");
    let server_key = args.out_dir.join("server.key");
    write_pem(&server_crt, &server.chain_pem, false)?;
    write_pem(&server_key, &server.key_pem, true)?;

    println!("issuing client leaf: {}", args.client_name);
    let client = ca.issue_client(
        &args.client_name,
        &[SubjectAltName::Dns(args.client_name.clone())],
    )?;
    let client_crt = args.out_dir.join("client.crt");
    let client_key = args.out_dir.join("client.key");
    write_pem(&client_crt, client.cert_pem(), false)?;
    write_pem(&client_key, &client.key_pem, true)?;

    let abs = fs::canonicalize(&args.out_dir)?;
    println!();
    println!("wrote {} files to {}", 6, abs.display());
    println!("  ca.crt       trust anchor (give to clients)");
    println!("  ca.key       CA private key (KEEP SECRET; never ship)");
    println!("  server.crt   chain for radius-server (leaf + CA)");
    println!("  server.key   private key for radius-server");
    println!("  client.crt   leaf cert for the NAS (e.g. MikroTik)");
    println!("  client.key   private key for the NAS");
    println!();
    println!("─── radius-server env ────────────────────────────────────");
    println!("export RADSEC_SERVER_CERT={}/server.crt", abs.display());
    println!("export RADSEC_SERVER_KEY={}/server.key", abs.display());
    println!("export RADSEC_CLIENT_CA={}/ca.crt", abs.display());
    println!("export RADSEC_CLIENT_NAME={}", args.client_name);
    println!("export RADSEC_PORT=2083   # optional, default 2083");
    println!();
    println!("─── MikroTik RouterOS setup ──────────────────────────────");
    println!("# 1. Upload ca.crt, client.crt, client.key to the router:");
    println!(
        "#    scp {0}/ca.crt {0}/client.crt {0}/client.key admin@<router>:",
        abs.display()
    );
    println!("#");
    println!("# 2. On the router, import the three files. Each `import` reads");
    println!("#    one PEM blob from /file and creates (or attaches to) a /certificate entry.");
    println!("/certificate import file-name=ca.crt     passphrase=\"\"");
    println!("/certificate import file-name=client.crt passphrase=\"\"");
    println!("/certificate import file-name=client.key passphrase=\"\"");
    println!("#");
    println!(
        "# 3. Find the imported client cert (look for the one with `KT` flags = has private key):"
    );
    println!("/certificate print");
    println!("#");
    println!("# 4. Rename it for clarity (replace <auto-name> with the printed name, e.g. `client.crt_0`):");
    println!("/certificate set <auto-name> name=radsec-client");
    println!("#");
    println!("# 5. Point the RADIUS client at the server over RadSec.");
    println!("#    Replace <server-ip> with the IP your radius-server listens on.");
    println!("/radius add service=hotspot,login \\");
    println!("            address=<server-ip> \\");
    println!("            protocol=radsec \\");
    println!("            certificate=radsec-client \\");
    println!("            secret=radsec");
    println!("#");
    println!("# 6. Verify the RADIUS entry and test from /tool fetch or a hotspot login.");
    println!("/radius print");

    Ok(())
}

fn write_pem(path: &Path, bytes: &[u8], secret: bool) -> std::io::Result<()> {
    fs::write(path, bytes)?;
    if secret {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
