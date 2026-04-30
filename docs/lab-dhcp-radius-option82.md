# Lab: DHCP-driven RADIUS subscriber identification with Option 82

This document is the build spec for a second lab living alongside the existing HotSpot lab. The HotSpot lab validates **web-based per-user authentication**. This lab validates **line-based per-subscriber authorization** — the model real ISPs use to hand out IPs and enforce plans without ever asking a human to type a password.

The two labs share infrastructure (`radius-rs`, `mikrotik-ingester`, ClickHouse) but exercise different RouterOS subsystems and a different RADIUS code path. Eventually `radius-rs` should serve both flows from the same binary.

> **Prerequisites — read before following §5 verbatim:**
> - **RouterOS 7.21+ is required.** The DHCP-server property `support-broadband-tr101=yes` (which makes RouterOS forward Option 82 sub-options to RADIUS as RFC 4679 DSL-Forum VSAs) does not exist on 7.20.x or earlier. `run.sh` pins `CHR_VERSION="7.21.4"`. On older versions, Option 82 has no path to RADIUS via `use-radius=yes` and the lab cannot work as designed. See §12.2 / §12.7.
> - Several spec details (Circuit-Id strings, dispatch heuristic, attribute table in §5.4, REQUEST-phase behavior) were corrected by wire captures during the build. **Always read §12 alongside the section you're implementing.**

---

## 1. What we're building and why

The existing HotSpot setup authenticates a user by username/password through a captive web page. That model fits coffee-shop Wi-Fi but doesn't scale to an ISP, where:

- A subscriber signs a contract before any device exists.
- Devices come and go (laptop, phone, IoT, kid's switch hidden in the wall) without the ISP knowing about each one.
- Plan, IP allocation, and rate-limit are decided per **subscriber line**, not per device.
- "Logging in" doesn't happen — the device just plugs in and DHCPs.

The mechanism that makes this work is **DHCP Option 82** combined with **RADIUS as the DHCP authorization backend**. The access-layer device stamps every DHCP request with a string identifying the physical/logical line it came in on (`Agent-Circuit-Id`). The DHCP server, instead of allocating from a local pool, asks RADIUS *"what should I do with a lease on this circuit?"* RADIUS looks up the circuit in its subscriber database and replies with the IP, the rate-limit, the lease lifetime, and any other policy.

In short: **the wire is the subscriber identity**, and RADIUS is the policy brain. This lab proves the entire round trip end-to-end with two simulated subscribers on two different plans.

### Goals

1. Two Lubuntu VMs come up on different access-layer ports and receive two **different** policies — different IPs, different (eventual) rate-limits, different lease behavior — keyed entirely on the port they plugged into.
2. One subscriber demonstrates **pool-based** IP assignment (`Framed-Pool`).
3. The other subscriber demonstrates **fixed-IP** assignment (`Framed-IP-Address`).
4. `radius-rs` correctly distinguishes a DHCP-style Access-Request from a HotSpot-style one and runs the right authorization path for each.
5. RADIUS Accounting fires on lease bind / renew / expire, and those events flow into ClickHouse alongside the existing audit stream.

### Non-goals (explicitly out of scope for this lab)

- Q-in-Q / 802.1ad. Production scale uses double-tagging; this lab uses untagged Ethernet on separate ports because it tests the same RADIUS pipeline with less moving config. Section 9 documents the production evolution path.
- Multiple access nodes. Only one CHR-ACCESS, so Circuit-Id doesn't yet need a node-prefix.
- Real-world rate-limit enforcement on the data plane. We'll *return* the `Mikrotik-Rate-Limit` VSA from RADIUS and confirm CHR-CORE accepts it; we won't iperf to validate enforcement.
- IPv6. The current `mikrotik-ingester` and `radius-server` schemas are IPv6-capable but the policies here are IPv4-only.
- A subscriber admin UI. Provisioning is done by inserting rows directly into `latigo.db` (or whatever sqlite/sql store `radius-rs` ends up using for subscribers).

---

## 2. How this differs from the existing HotSpot lab

| Aspect | HotSpot lab (existing) | Option 82 lab (this doc) |
|---|---|---|
| **Auth model** | User types username/password into a web page | Device plugs in, DHCP request gets stamped with circuit-id, RADIUS replies with policy |
| **Identity key** | `User-Name` + `User-Password` | `Agent-Circuit-Id` (Option 82) |
| **RADIUS service** | `service=hotspot` on `/radius` | `service=dhcp` on `/radius` |
| **DHCP server role** | Allocates IPs locally; doesn't talk to RADIUS | Calls RADIUS for every lease (`use-radius=yes`) |
| **Number of CHRs** | One CHR (does everything) | Two CHRs: CHR-ACCESS (L2 + Option 82 insertion) and CHR-CORE (DHCP server + RADIUS client) |
| **Number of VMs** | One Lubuntu | Two Lubuntu VMs, on different access ports |
| **What RADIUS returns** | Accept/reject + session params | Accept + `Framed-IP-Address` *or* `Framed-Pool` + rate-limit + session-timeout |
| **Captive web portal** | Yes — auth happens through it | No — there's no portal in this flow at all |
| **Walled garden** | Yes — pre-auth restriction | No — once the lease is up, the device has policy-shaped network access |

The two labs co-exist by running different `service=` definitions on the same RADIUS server. RouterOS sends DHCP-flavored Access-Requests with `service=dhcp` and HotSpot-flavored ones with `service=hotspot`; `radius-rs` dispatches on what's present in the packet (Option 82 → DHCP path; User-Password → HotSpot path).

---

## 3. Topology

```
                                Host (macOS)
                                ┌──────────────────────────────────────────────┐
                                │  RADIUS Server (radius-rs)   0.0.0.0:1812    │
                                │  Ingester (Rust)             0.0.0.0:5140    │
                                │  ClickHouse                  0.0.0.0:8123    │
                                │  SubscriberDB (sqlite)       latigo.db       │
                                └──────────────────────────────────────────────┘
                                                      ▲
                                                      │ RADIUS / Accounting
                                                      │ (10.0.2.2:1812)
                                                      │
  ┌──────────────┐  socket :22221   ┌─────────────────────────────────────┐
  │ Lubuntu VM-A │◄────────────────►│ CHR-ACCESS (Mikrotik CHR)           │
  │ "house-A"    │   ether2 (line)  │   ether1 = uplink (trunk to CORE)   │
  │ DHCP client  │                  │   ether2 = client port (line A)     │
  └──────────────┘                  │   ether3 = client port (line B)     │
                                    │   bridge: snooping + Option 82      │
  ┌──────────────┐  socket :22223   │                                     │
  │ Lubuntu VM-B │◄────────────────►│                                     │
  │ "house-B"    │   ether3 (line)  │                                     │
  │ DHCP client  │                  └────────────────┬────────────────────┘
  └──────────────┘                                   │ ether1 ↔ ether1
                                                     │ socket :22228
                                                     ▼
                                    ┌─────────────────────────────────────┐
                                    │ CHR-CORE (Mikrotik CHR)             │
                                    │   ether1 = downlink to ACCESS       │
                                    │   ether2 = WAN (QEMU NAT to host)   │
                                    │   /ip dhcp-server use-radius=yes    │
                                    │   /radius service=dhcp address=10.0.2.2 │
                                    └────────────────┬────────────────────┘
                                                     │ NAT
                                                     ▼
                                                  Internet
```

QEMU socket networks ("crossover cables in software") connect the four VMs:

| Socket port | Endpoints | Purpose |
|---|---|---|
| `:22221` | VM-A ↔ CHR-ACCESS ether2 | Line A subscriber link |
| `:22223` | VM-B ↔ CHR-ACCESS ether3 | Line B subscriber link |
| `:22228` | CHR-ACCESS ether1 ↔ CHR-CORE ether1 | Access ↔ Core uplink |
| QEMU `user`/NAT | CHR-CORE ether2 → host | Internet via host (also reaches host:1812 for RADIUS via `10.0.2.2`) |

There's no socket between the VMs and CHR-CORE directly — every subscriber packet must traverse CHR-ACCESS so Option 82 gets stamped. That's the whole point.

---

## 4. Identity model

### 4.1 What identifies a subscriber

The Circuit-Id stamped by CHR-ACCESS. Format we'll use in this lab:

```
acc01:eth2     ← line A
acc01:eth3     ← line B
```

(`acc01` = name of CHR-ACCESS; `eth2`/`eth3` = the bridge port the request came in on. In production this prefix would be globally unique; in the lab it's locally unique because there's only one access node.)

The Remote-Id (also Option 82) carries the client MAC. We don't use Remote-Id for identity — it's stored in accounting so we know *which device* used the line at a given time, but the policy lookup is on Circuit-Id alone.

### 4.2 Subscriber data model

A new sqlite table (or extension of `latigo.db`) holds one row per provisioned line:

```sql
CREATE TABLE subscribers (
    circuit_id        TEXT PRIMARY KEY,           -- 'acc01:eth2'
    plan              TEXT NOT NULL,              -- '100mbps' | '50mbps' | 'suspended'
    fixed_ip          TEXT,                       -- '192.168.50.10' or NULL
    pool_name         TEXT,                       -- 'lab-pool-100' or NULL
    rate_limit        TEXT,                       -- '100M/100M' or NULL — Mikrotik-Rate-Limit VSA
    session_timeout   INTEGER NOT NULL DEFAULT 3600,
    status            TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'suspended'
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes             TEXT
);
```

Constraint: exactly one of `fixed_ip` or `pool_name` must be set. We enforce that in the `radius-rs` lookup logic rather than via a SQL CHECK constraint, because the failure mode we want is a clean log line, not a write-time error.

For the lab, two seed rows:

```sql
INSERT INTO subscribers (circuit_id, plan, fixed_ip, rate_limit, session_timeout, status)
VALUES ('acc01:eth2', '100mbps-static', '192.168.50.10', '100M/100M', 3600, 'active');

INSERT INTO subscribers (circuit_id, plan, pool_name, rate_limit, session_timeout, status)
VALUES ('acc01:eth3', '50mbps-pool', 'lab-pool-50', '50M/50M', 3600, 'active');
```

VM-A on line A → fixed `192.168.50.10`, 100/100 Mbit/s.
VM-B on line B → some IP from `lab-pool-50` (defined on CHR-CORE), 50/50 Mbit/s.

### 4.3 Why Circuit-Id over MAC

Already discussed in the design conversation, but pinning the rationale here so it survives:

- **No pre-registration burden.** Whatever device the subscriber plugs in inherits the line's policy. Replace a router, swap a laptop — nothing changes operationally.
- **MAC is for accounting, not authorization.** We log which MACs took leases on which line so we can answer "what device was active on subscriber 1234 at 19:42," but the lease decision is line-based.
- **Aligns with how access topology is provisioned.** Ops already thinks about "port 3 on access node 1," so the data model just records what's already physically true.

---

## 5. Configuration plan

### 5.1 Lubuntu VMs

Two independent VMs. Each one is a copy of the existing client image with one change: each gets its own QEMU socket-network socket port number so they don't collide on the bus.

```
VM-A: -netdev socket,id=net0,connect=127.0.0.1:22221 -device virtio-net-pci,netdev=net0,mac=52:54:00:00:0a:01
VM-B: -netdev socket,id=net0,connect=127.0.0.1:22223 -device virtio-net-pci,netdev=net0,mac=52:54:00:00:0b:01
```

Inside each VM, NetworkManager handles the DHCP request. For debugging it's useful to bypass NM and run `sudo dhclient -v eth0` so the wire-level exchange prints to the terminal. We won't pre-bake any DHCP config — the whole point is that an unmodified client takes the lease that RADIUS dictates.

### 5.2 CHR-ACCESS (`configs/mikrotik-access.rsc`, new file)

CHR-ACCESS is L2 only. It does not have IPs on the subscriber-facing ports, doesn't run a DHCP server, doesn't NAT. It exists to bridge subscriber traffic and stamp Option 82.

```routeros
/system identity set name=acc01

# Bridge with DHCP snooping + Option 82 insertion enabled at the bridge level.
# This is the L2-snooping path (no DHCP relay involved). The bridge inspects
# DHCP packets in flight and adds Option 82 before forwarding.
/interface bridge add name=bridge1 vlan-filtering=no \
    dhcp-snooping=yes add-dhcp-option82=yes

# Subscriber-facing ports. These are UNTRUSTED — DHCP server messages
# (OFFER/ACK) arriving on these ports get dropped by the snooper.
/interface bridge port add bridge=bridge1 interface=ether2 trusted=no
/interface bridge port add bridge=bridge1 interface=ether3 trusted=no

# Uplink to CHR-CORE. TRUSTED — legitimate DHCPOFFER/ACK comes back this way.
/interface bridge port add bridge=bridge1 interface=ether1 trusted=yes

# Per-port Option 82 strings. Without these, RouterOS defaults to interface
# MACs which are not human-readable. We override with the documented scheme.
# (See RouterOS docs: relay-info-remote-id / circuit-id properties on bridge ports.)
/interface bridge port set [find interface=ether2] add-dhcp-option82=yes \
    dhcp-snooping-circuit-id="acc01:eth2"
/interface bridge port set [find interface=ether3] add-dhcp-option82=yes \
    dhcp-snooping-circuit-id="acc01:eth3"

# Management IP on the bridge (so we can reach this CHR for diagnostics).
/ip address add address=10.10.10.2/24 interface=bridge1
```

Note: the precise property name for per-port Circuit-Id varies slightly between RouterOS versions and between bridge-snooping vs DHCP-relay paths. We need to **verify the exact attribute name on the version we're running** before committing this config — if `dhcp-snooping-circuit-id` isn't the correct property, the alternative is to use `/ip dhcp-relay` instead of bridge snooping (Option B in section 5.3 below).

### 5.3 CHR-CORE (`configs/mikrotik-core.rsc`, new file)

CHR-CORE is the BNG-lite. It runs the DHCP server, talks to RADIUS, and NATs out to the internet.

```routeros
/system identity set name=core01

# WAN (internet via QEMU NAT)
/ip dhcp-client add interface=ether2 disabled=no add-default-route=yes

# Downlink to ACCESS (L3 — this is the subnet subscribers will live in)
/ip address add address=192.168.50.1/24 interface=ether1

# Pool used by the pool-mode subscriber (line B). The fixed-IP subscriber's
# address (192.168.50.10) intentionally sits OUTSIDE this range so we never
# get a duplicate-lease scenario.
/ip pool add name=lab-pool-50 ranges=192.168.50.100-192.168.50.200

# DHCP server. Note: NO address-pool here — pool/IP comes from RADIUS.
# use-radius=yes makes every lease an Access-Request to the RADIUS server.
/ip dhcp-server add name=dhcp-core interface=ether1 \
    use-radius=yes radius-default=yes \
    lease-time=10m disabled=no

# Network parameters returned to the client (gateway/DNS) — these are
# common to all subscribers, the per-subscriber bits come from RADIUS.
/ip dhcp-server network add address=192.168.50.0/24 \
    gateway=192.168.50.1 dns-server=8.8.8.8,8.8.4.4

# RADIUS server entry. service=dhcp distinguishes this from the hotspot
# entry (which uses service=hotspot). Same physical RADIUS server, different
# code path on the server side.
/radius add service=dhcp address=10.0.2.2 secret=secret \
    authentication-port=1812 accounting-port=1813 timeout=3s

# RADIUS-driven session timeout: when RADIUS returns Session-Timeout, honor it.
/ip dhcp-server set [find name=dhcp-core] use-radius=yes radius-default=yes

# NAT out to the internet
/ip firewall nat add chain=srcnat out-interface=ether2 action=masquerade
```

**Decision point: bridge snooping vs DHCP relay.** The lab plans for the bridge-snooping path because it's L2-only on CHR-ACCESS (which mirrors a real DSLAM/OLT-style access node). If RouterOS quirks force us to switch to the DHCP-relay path, the change is:
- CHR-ACCESS: drop the bridge-snooping flags; instead give the subscriber-facing ports IPs (one /30 per subscriber, or a shared /24) and configure `/ip dhcp-relay` with `add-relay-info=yes` and per-relay `relay-info-remote-id`.
- CHR-CORE: no change — still receives DHCP packets with Option 82 inside, just sourced from a relay instead of a snooping bridge.

We'll start with snooping and fall back to relay only if we can't get per-port Circuit-Id strings out of the bridge.

### 5.4 `radius-rs` DHCP code path (`radius-server/`)

This is the substantive code change. Today `radius-server/src/main.rs` handles HotSpot-style Access-Requests (User-Name + User-Password). We need a second path for DHCP-style requests.

**Dispatch rule** at the top of the request handler:

```
if packet contains Agent-Circuit-Id (Option 82, RFC 3046 / RADIUS attr 87)
   OR User-Name looks like a MAC (12 hex chars or aa:bb:...)
   AND no User-Password is present:
       → run dhcp_authorize(packet)
else:
       → run hotspot_authenticate(packet)  [existing path]
```

(Heuristic, not a hard protocol distinction. Cleanest single signal is the presence of Agent-Circuit-Id; the `service=dhcp` definition on RouterOS is what causes that attribute to be included.)

**`dhcp_authorize` flow:**

1. Pull `Agent-Circuit-Id` out of the Access-Request. If absent, log and reject — we don't authorize anonymous DHCP.
2. `SELECT * FROM subscribers WHERE circuit_id = ? AND status = 'active'`. If no row, return Access-Reject. If `status='suspended'`, return Access-Accept but with `Framed-Pool='walled-garden'` so the subscriber lands in a captive-style restricted network (parking lot for the lab).
3. Build Access-Accept with:
   - `Framed-IP-Address` if `fixed_ip` is set, **OR** `Framed-Pool` if `pool_name` is set. Never both. If both columns are NULL, log and reject (data error).
   - `Mikrotik-Rate-Limit` VSA from `rate_limit` if set. (Vendor dictionary: `radius::dict::mikrotik`.)
   - `Session-Timeout` from `session_timeout`.
   - `Acct-Interim-Interval` = some small value (5 minutes) so accounting heartbeats are visible during the lab.
4. Sign the response (existing Message-Authenticator handling carries over).
5. On Accounting-Request, write a row into `radius_session_events` exactly as the HotSpot path does today — same schema. The `username` column gets `circuit_id` for DHCP sessions (we may want to add a `subscriber_id` column eventually, but for the POC reusing `username` keeps the audit join intact).

**Concrete attribute references** (using the dictionaries `radius-rs` already exposes):

| Attribute | Source | Module |
|---|---|---|
| `User-Name` | request | `rfc2865` |
| `Agent-Circuit-Id` | request (inside Option 82 / attr 87) | `rfc2868` / RFC 3046 wrapper — **verify which dict module covers this in `radius-rs`** |
| `Calling-Station-Id` (client MAC) | request | `rfc2865` |
| `NAS-Port-Id` | request — RouterOS includes this for DHCP | `rfc2865` |
| `Framed-IP-Address` | response | `rfc2865` |
| `Framed-Pool` | response | `rfc2869` |
| `Session-Timeout` | response | `rfc2865` |
| `Acct-Interim-Interval` | response | `rfc2869` |
| `Mikrotik-Rate-Limit` | response | `mikrotik` (VSA) |

The Option 82 attribute mapping is the one variable we genuinely have to confirm on the wire. Plan: capture the first lease's Access-Request with `tcpdump` on the host and decode it with `radclient -x` or just pretty-print the packet bytes from the `radius-rs` server. Whatever attribute carries `acc01:eth2`, that's our source — don't assume from the RFC.

### 5.5 Subscriber DB

`latigo.db` already exists at the repo root. We extend it (or, if it's currently used for something else, namespace the new tables with `subscriber_*`). Migration path:

```
radius-server/migrations/  ←  new directory
  V001__subscribers.sql    ←  CREATE TABLE subscribers (…)
  V002__seed_lab.sql       ←  the two INSERT rows from §4.2
```

We need a tiny migration runner like the one in `mikrotik-ingester/src/migrate.rs` — same pattern. (Or just port that file over; it's ~50 lines.)

---

## 6. End-to-end packet flow

Following a single VM-B boot from cold:

1. **VM-B boots, NetworkManager runs `dhclient` on `eth0`.**
   `eth0` has MAC `52:54:00:00:0b:01`.

2. **VM-B sends DHCPDISCOVER as Ethernet broadcast** to `ff:ff:ff:ff:ff:ff`, src MAC `52:54:00:00:0b:01`, src IP `0.0.0.0`, dst IP `255.255.255.255`. Reaches CHR-ACCESS ether3.

3. **CHR-ACCESS bridge-snooping intercepts the DISCOVER.**
   Recognizes a DHCP packet, looks at the ingress port (ether3), looks up its `dhcp-snooping-circuit-id` setting (`"acc01:eth3"`), and inserts Option 82:
   - sub-option 1 (Agent-Circuit-Id) = `"acc01:eth3"`
   - sub-option 2 (Agent-Remote-Id) = `52:54:00:00:0b:01` (or bridge MAC, depending on default — we'll measure)

4. **Bridge floods the modified DISCOVER** out the trusted uplink ether1, into CHR-CORE ether1.

5. **CHR-CORE DHCP server receives DISCOVER.**
   `use-radius=yes` triggers a RADIUS Access-Request to `10.0.2.2:1812`. The packet contains:
   - `User-Name` = client MAC (RouterOS convention for DHCP)
   - `Calling-Station-Id` = client MAC
   - `NAS-IP-Address` = CHR-CORE's own address
   - `NAS-Identifier` = `core01`
   - `NAS-Port-Id` = formatted string including the relay info, OR a separate Agent-Circuit-Id attribute — *to be confirmed on the wire*
   - The Option 82 sub-options carrying `"acc01:eth3"` and the client MAC

6. **`radius-rs` receives the Access-Request.**
   Dispatch logic sees Option 82 / no User-Password → DHCP path.

7. **`radius-rs` looks up `acc01:eth3` in `subscribers`.**
   Finds: plan `50mbps-pool`, pool `lab-pool-50`, rate-limit `50M/50M`, session-timeout 3600, status active.

8. **`radius-rs` builds Access-Accept** with:
   - `Framed-Pool` = `"lab-pool-50"`
   - `Mikrotik-Rate-Limit` = `"50M/50M"`
   - `Session-Timeout` = `3600`
   - `Acct-Interim-Interval` = `300`
   - Message-Authenticator (HMAC-MD5 of the whole packet)
   - Response-Authenticator

9. **CHR-CORE receives Access-Accept.**
   Picks an IP from `lab-pool-50` (e.g. `192.168.50.137`), records the rate-limit on the lease (downstream queue tree applies it), formats DHCPOFFER with that IP, gateway `192.168.50.1`, DNS `8.8.8.8`, lease-time honoring `Session-Timeout`.

10. **DHCPOFFER flows back through CHR-ACCESS** (uplink port is trusted, so the snooper lets it through unmodified), reaches VM-B.

11. **VM-B sends DHCPREQUEST** for `192.168.50.137`. Round trip 3-4-5-6-7-8-9-10 repeats; `radius-rs` returns the same answer. CHR-CORE confirms the lease and sends DHCPACK.

12. **VM-B installs the lease.** It now has `192.168.50.137`, gateway `192.168.50.1`, DNS `8.8.8.8`. Traffic flows: VM-B → CHR-ACCESS bridge (no L3) → CHR-CORE (NAT) → host → internet.

13. **CHR-CORE sends RADIUS Accounting-Request (Start)** to `10.0.2.2:1813`.
    `radius-rs` writes a `radius_session_events` row to ClickHouse (event=`'start'`, mac=normalized client MAC, framed_ip=`192.168.50.137`, username=`acc01:eth3`).

14. **Every 5 minutes**, CHR-CORE sends Accounting-Request (Interim-Update) with byte counters. Another `radius_session_events` row lands.

15. **On lease expiry** (or `dhclient release`, or VM-B shutdown), Accounting-Request (Stop) fires with terminate-cause + final byte counters. Final row.

VM-A's flow is identical except step 8 returns `Framed-IP-Address=192.168.50.10` instead of a pool name, and CHR-CORE hands out exactly that IP every time.

---

## 7. Validation plan

Numbered tests, each independently verifiable. These belong in a `tests/` subdirectory eventually but for the lab spec they're the acceptance criteria.

### T1 — VM-A always gets the same fixed IP

```bash
# On VM-A, in a loop:
for i in 1 2 3; do
  sudo dhclient -r eth0 && sudo dhclient -v eth0
  ip -4 addr show eth0 | grep inet
  sleep 5
done
# Expected: every iteration prints "inet 192.168.50.10/24"
```

### T2 — VM-B gets an IP from the pool, and a different one is plausible across releases

```bash
# Same loop on VM-B
# Expected: every iteration prints an IP in 192.168.50.100-200,
# and across multiple cold boots the IPs aren't always identical
# (RouterOS may persist by MAC even with RADIUS, that's fine —
# what we're confirming is that the IP is in-pool, not out-of-pool)
```

### T3 — Wrong-port test: swap the Lubuntu VMs

Boot VM-A on socket port 22223 (line B) and VM-B on 22221 (line A). VM-A should now get a pool IP (line B's policy); VM-B should now get `192.168.50.10` (line A's policy). Proves identity is bound to the line, not the device/MAC/VM.

### T4 — Unknown circuit rejection

Add a third `ether4` to CHR-ACCESS without provisioning it in the subscribers table. Plug a VM in. Expected: `radius-rs` logs an unauthorized Access-Request, returns Access-Reject, the VM never gets a lease. Validates fail-closed behavior.

### T5 — Suspended subscriber

`UPDATE subscribers SET status='suspended' WHERE circuit_id='acc01:eth2'`. Bounce VM-A's DHCP. Expected: lease succeeds (we want the device on the network for the captive page) but `Framed-Pool='walled-garden'` is returned, so the device gets an IP from a pool that has no internet route. *(Walled-garden pool config to be added to CHR-CORE — it's a small follow-on.)*

### T6 — Wire-level capture

```bash
# On the host:
sudo tcpdump -i lo0 -s0 -w /tmp/dhcp-radius.pcap port 1812 or port 1813
# Trigger a fresh lease on VM-B
# Open in Wireshark, confirm:
#   Access-Request contains Agent-Circuit-Id = "acc01:eth3"
#   Access-Accept contains Framed-Pool = "lab-pool-50"
#   Accounting-Request follows within seconds
```

This is the single most important test — everything else is downstream of "is the right Circuit-Id actually on the wire."

### T7 — Audit trail in ClickHouse

```sql
SELECT event, username, mac, IPv6NumToString(framed_ip), session_time, ts
FROM mikrotik.radius_session_events
WHERE username IN ('acc01:eth2', 'acc01:eth3')
ORDER BY ts DESC
LIMIT 20;
```

Expected: a Start row per lease, periodic Interim rows, a Stop row when the lease ends. The audit join in `mikrotik-ingester/README.md` should now be answerable for DHCP-mode subscribers, not just HotSpot ones.

---

## 8. What we need to figure out before / during the build

Honest list of unknowns. Each one is a small spike, not a blocker.

1. **Exact RouterOS property name for per-port Circuit-Id under bridge snooping.** Likely `dhcp-snooping-circuit-id` on `/interface bridge port` but not 100% confirmed for the version we'll run. *Spike: configure a single port, capture a DHCP request on the uplink with `/tool sniffer`, decode Option 82 contents.*
2. **Exact RADIUS attribute layout for Option 82 sub-options when CHR-CORE sends Access-Request.** RouterOS may put the sub-options into standard RADIUS attribute 82 (Agent-Circuit-Id is RFC 3046 sub-option 1, exposed as RADIUS attr 87 in some implementations), into Mikrotik VSAs, or into `NAS-Port-Id` as a formatted string — it varies. *Spike: tcpdump the first Access-Request, look at every attribute.*
3. **Whether `radius-rs`' generated dictionary modules already cover Agent-Circuit-Id.** The radius-rs dict list in `radius-rs/README.md` includes RFC 2868 (Tunnel attributes) but doesn't explicitly list RFC 3046. May need to add a small dictionary file or read the bytes by attribute number directly via `Packet::lookup_vsa`. *Spike: read the packet bytes once, decide.*
4. **Whether a single `radius-rs` binary can serve both HotSpot and DHCP requests on the same port.** Almost certainly yes (RouterOS `service=` is a hint to the server, not a strict separation), but worth confirming the dispatch heuristic doesn't accidentally route a HotSpot request to the DHCP path or vice versa.
5. **Walled-garden network for the suspended-subscriber case.** Could be as simple as an extra `/ip pool` on CHR-CORE that hands out IPs from a subnet with a default route to a "you have been suspended" page. Defer until T5 is being validated.

---

## 9. Production evolution path (for context only)

Not building this in the lab, but the design has to hold up if/when we go this way:

1. **Q-in-Q on CHR-ACCESS uplink.** Subscriber-facing ports stay as access ports on a per-subscriber C-VLAN. Uplink becomes 802.1ad trunk with S-VLAN identifying the access node. Circuit-Id naturally encodes `(node, port, c-vlan)`.
2. **Multiple access nodes.** Circuit-Id grows the node prefix to globally unique form: `acc-saopaulo-01:eth15:vlan100`. Subscriber DB is unaffected — same primary key.
3. **CHR-CORE → BNG cluster.** Replace the single CHR-CORE with a pair (active/standby or anycast) using the same RADIUS server. Still no change to the DB or the RADIUS code path.
4. **Real subscriber admin UI.** A small web app on top of the `subscribers` table, plus a CLI script that pushes port/VLAN config to the access nodes via SSH/REST when a row is added. Out of scope here; this is what `radius-rs` fronts in production.
5. **Plan changes.** When ops bumps a subscriber from 50/50 to 100/100, RADIUS sends Disconnect-Message (CoA) to CHR-CORE for that session, which forces a re-auth, which pulls the new rate-limit. Already supported in `radius-rs` via RFC 5176 dictionary; just needs wiring.

---

## 10. Project layout after this lab lands

```
captive-portal/
├── README.md                           # add a section linking to docs/
├── docs/
│   └── lab-dhcp-radius-option82.md    # this file
├── configs/
│   ├── mikrotik-hotspot.rsc           # existing (HotSpot lab)
│   ├── mikrotik-logging.rsc           # existing (compliance logging)
│   ├── mikrotik-access.rsc            # NEW — CHR-ACCESS L2 + Option 82
│   └── mikrotik-core.rsc              # NEW — CHR-CORE DHCP+RADIUS
├── radius-server/
│   ├── src/
│   │   ├── main.rs                    # extend dispatch
│   │   ├── dhcp_authz.rs              # NEW — DHCP authorization path
│   │   └── subscribers.rs             # NEW — sqlite-backed subscriber lookup
│   └── migrations/
│       ├── V001__subscribers.sql      # NEW
│       └── V002__seed_lab.sql         # NEW
├── run.sh                              # add --lab=hotspot|dhcp flag
└── …
```

`run.sh` grows a `--lab` flag selecting which scenario to bring up. The two labs aren't mutually exclusive in principle — you could run both side by side with separate VMs — but for development, picking one keeps the QEMU command line tractable.

---

## 11. Decisions captured (in case anyone re-opens this)

- **Two CHRs, not one.** Yes it's more VMs to babysit; the alternative (one CHR with a bridge that also does DHCP server) muddles the access-vs-core boundary that's the whole point of the production architecture being modeled. Worth the extra VM.
- **Bridge snooping over DHCP relay** as the default path on CHR-ACCESS. Closer to how a real DSLAM/OLT behaves and keeps CHR-ACCESS L2-only. Will fall back to relay only if the snooping path can't produce per-port Circuit-Id strings.
- **`Framed-IP-Address` and `Framed-Pool` both in scope** in the same lab run, one per subscriber. Validates the production hybrid model in one shot rather than splitting it across two iterations.
- **Identity is Circuit-Id only.** MAC goes into accounting, never into authorization. This is what makes the model work for IoT and unmanaged devices — and it's the point of the whole exercise.
- **Out of scope: Q-in-Q, IPv6, multiple access nodes, admin UI, rate-limit data-plane verification.** Documented in §1 and §9; revisit when there's a reason to.

---

## 12. Wire-level amendments (2026-04-30 spike)

The §1–§11 design above is the original intent. The build that follows it
ran into RouterOS 7.21.4 reality and several spec assumptions did not hold.
The amendments below are the truth-on-the-wire; sections retain their
original text so the design rationale and amendments stay separately
auditable.

### 12.1 Circuit-Id strings (§4.1, §4.2, §5.2, §6, §7)

The bridge does NOT expose a `dhcp-snooping-circuit-id` property on
RouterOS 7.21.4. The `:do { ... } on-error={ :put "WARN..." }` wrapper
in `configs/mikrotik-access.rsc` silently absorbs the failure (no WARN
appears because the property name parses but the `set` no-ops). The
bridge falls back to its default Circuit-Id format, which on this
version is the **bare ingress port name**:

| Spec said | Wire delivers |
|---|---|
| `acc01:eth2` | `ether2` |
| `acc01:eth3` | `ether3` |

Consequences:
- `subscriber_lines.circuit_id` seeds in `radius-server/src/db.rs` use
  `ether2` / `ether3`, not the spec's `acc01:eth2` / `acc01:eth3`.
- T7 audit-trail SQL: filter by the actual circuit_id string, not the
  spec's. Note that the `username` column in `radius_session_events`
  actually carries the client MAC (RouterOS sends `User-Name=<MAC>` in
  DHCP accounting), not the circuit_id — §6 step 13 was wrong about that.
- For production multi-access-node use, the `acc01:` prefix scheme would
  need to come from outside the bridge — likely DHCP relay with
  `relay-info-circuit-id` (if/when RouterOS exposes it) or the
  per-line-DHCP-server design in §12.5 below.

### 12.2 RouterOS DHCP-server → RADIUS attribute set is fixed

Per Mikrotik's current docs, `/ip dhcp-server` with `use-radius=yes`
sends a documented attribute list. **Option 82 sub-options are NOT in
that list by default.** The spike capture confirmed: zero VSAs, zero
attribute 82, zero Agent-Circuit-Id-shaped attribute anywhere.

The escape hatch is `support-broadband-tr101=yes` (RFC 4679 / TR-101).
With it enabled, RouterOS forwards Option 82 sub-options as **DSL-Forum
VSAs (vendor 3561)**:

| RFC 4679 attribute | Vendor | Sub-type |
|---|---|---|
| Agent-Circuit-Id | 3561 | 1 (string) |
| Agent-Remote-Id | 3561 | 2 (string) |
| Actual-Data-Rate-Upstream | 3561 | 129 (0x81) |
| Actual-Data-Rate-Downstream | 3561 | 130 (0x82) |

The docs misleadingly phrase this as "additional sub-options (e.g. 0x81,
0x82)" — but it actually covers sub-options 1 and 2 too. Without TR-101
enabled, there is no other path to get Circuit-Id to RADIUS via the
DHCP-server-with-use-radius mechanism on this RouterOS.

`support-broadband-tr101` does NOT exist on RouterOS 7.20.x. We bumped
`CHR_VERSION` from 7.20.8 → 7.21.4 (latest long-term as of 2026-04-21)
to access it. Even on 7.21.4 it is not accepted on `add`, so the config
splits to a separate `set` line wrapped in `:do/on-error`.

`radius-default=yes` (§5.3 line in the original config block) also does
not exist on 7.20.x or 7.21.x and was removed.

### 12.3 Remote-Id is the bridge MAC, not the client MAC (§4.1, §6)

§4.1 says "Remote-Id (also Option 82) carries the client MAC". The wire
shows the bridge instead inserts its **own** MAC as Remote-Id, identical
across every line. So Remote-Id cannot be used either as a per-device
identifier or as a per-line one. Useful only as "which access node",
which we already have from `NAS-Identifier`. Don't use Remote-Id for
anything in our schema.

### 12.4 Dispatch heuristic (§5.4)

Spec said "if packet contains Agent-Circuit-Id … AND no User-Password
is present → DHCP path". The wire shows RouterOS's DHCP-mode RADIUS
client **always** includes a `User-Password` (the encrypted client MAC,
RouterOS convention), so the no-User-Password test never fires. The
implemented classifier in `radius-server/src/radius/mod.rs::classify`
is: **if `User-Name` matches a MAC pattern → DHCP path**, else HotSpot.

§5.4's table has another error: "Agent-Circuit-Id … RADIUS attr 87" —
attr 87 is `NAS-Port-Id`, not Agent-Circuit-Id. Agent-Circuit-Id has no
fixed RADIUS attribute number; on this RouterOS it arrives as a
DSL-Forum VSA (see §12.2).

### 12.5 DHCP REQUEST phase carries no Option 82 — transaction cache needed

Bridge snooping stamps Option 82 on broadcast DHCP messages (DISCOVER).
The DHCP REQUEST phase (where the client confirms the OFFERed IP) is
typically unicast to the server and does NOT get re-stamped. CHR-CORE
sends a second Access-Request to RADIUS for the REQUEST phase, but that
packet has no DSL-Forum VSAs and no Option 82.

We added a 60-second MAC-keyed transaction cache in
`radius-server/src/radius/dhcp.rs`. On every ACCEPT, we remember
`(User-Name, circuit_id)`. On a follow-up Access-Request that lacks
Option 82, we recall the circuit_id from the cache by User-Name. This
is **not MAC-based authorization** — the original LINE-based decision
already happened on the DISCOVER. The cache only carries the
authorization across the two RADIUS round-trips of one DHCP exchange.

If the spec's principle "identity is the line, never the device" is to
be defended strictly, the alternative is to redesign so REQUEST-phase
packets carry their circuit_id too. The two paths to do that:
- DHCP relay on CHR-ACCESS (one relay per port), which adds Option 82
  to all relayed messages including REQUEST. Trades L2 simplicity for
  L3 routing on ACCESS.
- Per-line DHCP servers on CHR-CORE keyed on `Called-Station-Id` (the
  DHCP server name), which IS in the documented attribute list and IS
  present on every Access-Request. Trades one server for N.

We chose the cache because it preserves the §11 "bridge snooping over
DHCP relay" decision and keeps the topology simple. Revisit if this
ever becomes a security concern (e.g. an attacker spoofing a MAC during
the few-second cache window — but they'd need to be on the same line
the legitimate client just authorized on, so the attack is bounded by
physical access to the same port).

### 12.6 QEMU device-order matters for CHR interface naming

CHR enumerates `ether1` as the first `-device virtio-net-pci` on the
QEMU command line. The first iteration of `start_chr_access` in `run.sh`
put the management WAN (QEMU NAT) first, which made the bridge include
the QEMU NAT in the subscriber broadcast domain. Symptom: VM-A's DHCP
DISCOVER reached QEMU's SLIRP DHCP server (`10.0.2.2`) instead of
CHR-CORE, and CHR-CORE's `ether1` somehow leased a `10.0.2.x` address.
Fix: socket netdevs first (uplink `:22228` → ether1, lineA `:22221` →
ether2, lineB `:22223` → ether3), management WAN last (ether4).

### 12.7 RouterOS version requirement

This lab requires **RouterOS 7.21+** because of `support-broadband-tr101`.
The original spec had no version requirement. `run.sh` pins
`CHR_VERSION="7.21.4"`. On 7.20.x, the spike confirmed Option 82 cannot
reach RADIUS at all through the documented `use-radius=yes` path.

### 12.8 Project layout — what actually got built

| Spec §10 said | Built as |
|---|---|
| `radius-server/src/dhcp_authz.rs` | `radius-server/src/radius/dhcp.rs` |
| `radius-server/src/subscribers.rs` | (same) |
| `radius-server/migrations/` | dropped — single `db::init` with seed-on-empty in `db.rs` |
| `subscribers` table | `subscriber_lines` (namespaced; `latigo.db` already had `users`/`sessions` from the HotSpot lab) |
| (not in spec) | `radius-server/src/radius/{mod,response,spike,hotspot,accounting}.rs` — split out the previously monolithic `main.rs` so the DHCP path has a clean home |
| (not in spec) | `radius-server/src/web.rs` — captive portal handlers, also split out |

The `--lab=hotspot|dhcp` flag in `run.sh` was implemented as planned; the
HotSpot path (default) is unchanged behaviorally.

### 12.9 §8 unknowns — final status

| § | Unknown | Resolution |
|---|---|---|
| 8.1 | RouterOS property for per-port Circuit-Id under bridge snooping | **No such property on 7.21.4.** Bridge defaults to ingress port name. |
| 8.2 | RADIUS attribute layout for Option 82 sub-options | **DSL-Forum VSA, vendor 3561, sub-type 1 / 2** when `support-broadband-tr101=yes`. Nothing forwarded otherwise. |
| 8.3 | Whether radius-rs covers Agent-Circuit-Id | No. We did not add a dictionary file (kept upstream lib unmodified per project preference); instead `dhcp.rs::extract_circuit_id` walks raw AVP bytes via `Packet::encode()` and matches vendor=3561 sub-type=1. The constants in `dhcp.rs` are the ad-hoc dictionary. |
| 8.4 | Single binary serving both labs | Confirmed working; classifier on User-Name MAC pattern. |
| 8.5 | Walled-garden network for suspended subscribers | Code path exists in `subscribers::Authorization::WalledGarden` but the corresponding `walled-garden` pool on CHR-CORE is not yet defined. Defer until T5. |

