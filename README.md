# Captive Portal Lab

Local lab that simulates a real-world captive portal scenario using Mikrotik CHR, a Rust RADIUS server, and a client VM with a browser.

```
                                    Host (macOS)
                                    ┌──────────────────────────┐
                                    │  RADIUS Server (Rust)    │
                                    │  0.0.0.0:1812            │
┌──────────────┐   QEMU socket    ┌─┴────────────────┐        │
│ Lubuntu VM   │◄────────────────►│ Mikrotik CHR VM  │        │
│ (client)     │   192.168.88.0/24│ (arm64 or x64)   │        │
│              │                  │                  │        │
│ Firefox      │                  │ ether1: WAN/NAT  ├──NAT───┤──► Internet
│ DHCP client  │                  │ ether2: HotSpot  │ 10.0.2.x    │
└──────────────┘                  └──────────────────┘        │
                                    └──────────────────────────┘
```

## Prerequisites

```bash
brew install qemu socat
# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Quick Start

```bash
./run.sh            # auto-detects architecture, downloads images, builds RADIUS, starts everything
```

On Apple Silicon it defaults to ARM64 CHR; on x86_64 hosts it uses native x86_64 CHR. You can override with `./run.sh arm64` or `./run.sh x64`.

First run downloads Mikrotik CHR (~134MB) and Lubuntu ISO (~3.2GB). Subsequent runs skip downloads.

1. Wait for the Lubuntu QEMU window to load (~3-5 min under emulation)
2. Select **"Try Lubuntu"** for a live session
3. Open Firefox, navigate to any HTTP site (e.g. `http://example.com`)
4. Captive portal appears -- login with `admin` / `p@ssw0rd`
5. Internet is released

## Commands

```bash
./run.sh              # start the lab (auto-detects architecture)
./run.sh arm64        # force ARM64 CHR
./run.sh x64          # force x86_64 CHR
./run.sh stop         # stop everything
./run.sh --help       # show help
```

### Mikrotik access

```bash
nc localhost 4444                    # serial console
ssh -p 2222 admin@localhost          # SSH
```

### Mikrotik diagnostics (inside serial/SSH)

```routeros
/ip address print                    # check interface IPs
/ip dhcp-server print                # check DHCP server status
/ip hotspot active print             # list authenticated clients
/ip hotspot active remove [find]     # clear stuck sessions
/log print where topics~"radius"     # radius-specific log
/tool sniffer quick port=1812        # capture RADIUS traffic
```

## Credentials

| Component | Username | Password |
|---|---|---|
| Captive Portal | `admin` | `p@ssw0rd` |
| Mikrotik SSH/Serial | `admin` | *(empty, press Enter)* |

## Networking

- Mikrotik ether1 (WAN): QEMU user-mode NAT, gets internet via host
- Mikrotik ether2 (LAN): QEMU socket network, serves DHCP + HotSpot to client
- Client VM: single NIC on the socket network, gets IP from Mikrotik DHCP
- RADIUS: host listens on port 1812, Mikrotik reaches it via NAT gateway (10.0.2.2)

## HotSpot Configuration

The configuration is in `configs/mikrotik-hotspot.rsc` and applied automatically via serial on first boot. The disk image is writable, so **the config persists across restarts**.

If auto-config fails (client VM has no network):

1. Connect to Mikrotik serial: `nc localhost 4444`
2. Login: `admin` (press Enter for password)
3. Check: `/ip address print` -- should show `192.168.88.1` on ether2
4. If missing, paste commands from `configs/mikrotik-hotspot.rsc`
5. In Lubuntu, reconnect network or run `sudo dhcpcd`

## Troubleshooting

### RADIUS Access-Accept sent but login doesn't work

Mikrotik requires the **Message-Authenticator** attribute (HMAC-MD5, RFC 2869) in RADIUS responses. Without it, the response is silently discarded. This is already handled in the Rust RADIUS server.

The computation order:
1. Build response with Message-Authenticator set to 16 zero bytes
2. Place the Request Authenticator in the authenticator field
3. Compute HMAC-MD5 of the entire packet using the shared secret
4. Replace the zero bytes with the computed HMAC
5. Compute Response Authenticator: `MD5(Code + ID + Length + RequestAuth + Attributes + Secret)`
6. Replace the authenticator field with the computed Response Authenticator

The `radius-rs` library handles step 5-6 but NOT steps 3-4 -- we build the response packet manually.

### "Already authorizing, retry later"

Clear stuck sessions: `/ip hotspot active remove [find]`

### Client VM has no network

See [HotSpot Configuration](#hotspot-configuration) above.

## Project Structure

```
├── run.sh                       # main script -- starts everything
├── configs/
│   └── mikrotik-hotspot.rsc     # RouterOS HotSpot + RADIUS config
├── radius-server/
│   ├── Cargo.toml
│   └── src/main.rs              # RADIUS server (radius-rs + manual HMAC)
├── test-radius.py               # diagnostic Python RADIUS server
└── images/                      # downloaded VM images (gitignored)
```
