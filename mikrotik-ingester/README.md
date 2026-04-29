# mikrotik-ingester

A Rust service that captures every new connection on a Mikrotik RouterOS firewall, parses the BSD-syslog stream Mikrotik emits over UDP, and writes a structured row into ClickHouse for the regulatory audit trail.

Built as a POC for an ISP scenario where the captive portal is just one piece — many subscribers behind a Mikrotik need a per-flow log retained long enough to satisfy law-enforcement requests when subscribers do something illegal on the network.

```
                       Lubuntu / subscribers
                       192.168.88.0/24
                                │
                                ▼
                       ┌────────────────┐
                       │ Mikrotik CHR   │  /ip firewall filter
                       │ ether2 → ether1│   chain=forward
                       │                │   connection-state=new
                       │                │   action=log
                       └────────┬───────┘   log-prefix="conn-new"
                                │
                       BSD syslog over UDP/5140
                       (RouterOS forces UDP for syslog)
                                │
                                ▼
                       ┌────────────────┐         ┌──────────────────┐
                       │ mikrotik-      │  HTTP   │   ClickHouse     │
                       │ ingester       ├────────►│   :8123          │
                       │ (Rust, tokio)  │         │   /play UI       │
                       └────────────────┘         └──────────────────┘
                       │ UDP listener  │            firewall_connections
                       │ regex parser  │            raw_log
                       │ Inserter      │            radius_session_events  ◄── radius-server
                       │ (5s/100k/50MB)│            _schema_migrations
```

---

## What's in here

| File | What it does |
|---|---|
| `src/main.rs` | Wires everything: config, ClickHouse client, migrations, listener, pipeline, signal handling. |
| `src/config.rs` | Reads `INGESTER_LISTEN`, `INGESTER_METRICS`, `CLICKHOUSE_URL/USER/PASSWORD/DB` from env, with sane defaults for the lab. |
| `src/migrate.rs` | Tiny migration runner. Embeds each `migrations/Vxxx__*.sql` via `include_str!`, tracks applied versions in `_schema_migrations`, runs each missing migration once. |
| `src/listener.rs` | UDP `recv_from` loop. One datagram = one syslog line; each line gets parsed and shipped down a bounded mpsc channel. Listens to a `CancellationToken` for graceful shutdown. |
| `src/mikrotik.rs` | Single regex against the BSD-syslog body for `<log-prefix> <chain>: in:<if> out:<if>, … src-mac <mac>, proto <P>, <sip>:<sport>-><dip>:<dport>, len <n>`. Derives `severity` from the `<priority>` byte. Uses `syslog_loose` to extract `mikrotik_ts` and the hostname (`router`); both fall back to `received_at` / peer IP if the header doesn't parse. ICMP and any other shape that doesn't match the regex falls through to `raw_log`. |
| `src/model.rs` | `RawLogRow` and `FirewallEvent` structs with `clickhouse::Row` derives, plus the `Message` enum the listener and pipeline pass between them. |
| `src/pipeline.rs` | Owns two `clickhouse::Inserter`s — one for `firewall_connections`, one for `raw_log`. Routes each `Message` to the right inserter, commits on a 5s/100k row/50MB period, and calls `end()` on shutdown to flush the in-flight batch. |
| `migrations/V001__init.sql` | All tables in one shot: `firewall_connections`, `raw_log`, `radius_session_events` (the audit stream radius-server writes — one row per Accounting Start/Interim/Stop/On/Off, ordered by `(mac, ts)` so the firewall ↔ session ASOF join is a fast merge). TTLs: 12 months for parsed events, 30 days for raw fallback. |
| `docker-compose.yml` | Single-node ClickHouse 25.3 with named volumes for data and logs. |

---

## Design decisions and the reasoning behind them

### Compliance reframes the problem

This isn't an ops log stream — it's evidence for regulators. That changes the priorities away from "fast and lossy" and toward "preserve everything, even when our parser is wrong."

Concrete consequences:
- **Always retain the raw line.** `firewall_connections.raw` keeps the original syslog text alongside the structured fields, so a forensic analyst can re-parse it if our extractor has a bug.
- **Never silently drop on parse failure.** If the body regex doesn't match (e.g. ICMP, IPv6 with brackets, an unfamiliar message shape), the line lands in `raw_log` with a `parse_error` column. Two-tier table: structured for analytics, raw for completeness.
- **Retention is a regulatory input.** TTLs are set at 12 months / 30 days as a placeholder; they belong in the migration so they're versioned with the schema.
- **Partition by month + TTL.** Partitioning by `toYYYYMM(ts)` lets ClickHouse drop expired data by detaching whole partitions, which is cheap.
- **UDP loss is accepted, parser loss is not.** What the kernel hands us, we keep. What we receive but can't classify, we route to `raw_log` rather than synthesizing a row in `firewall_connections`.

### BSD syslog over UDP — what RouterOS gives us

Mikrotik can emit logs in three remote formats:

| Format | Wire | Notes |
|---|---|---|
| Default ("proprietary") | UDP only | Free-text body, no syslog framing |
| BSD syslog (RFC 3164 / RFC 5424-ish) | UDP only | Standard `<priority>` + timestamp + hostname header, then the proprietary body |
| CEF | UDP, TCP, or TLS | Pipe-delimited header + `key=value` extension |

The RouterOS docs are explicit: **"TCP and TLS only works with CEF; for syslog it will always use UDP, even if TCP/TLS is set."** So once we choose syslog, the wire is UDP and we lose the kernel-level backpressure that TCP would give us. That's the trade-off we accept here — the format is much simpler to parse and operationally cheaper to deploy than CEF.

What "best-effort" means in practice:
- The Linux/macOS kernel will drop UDP datagrams when its receive buffer fills (`SO_RCVBUF`); we can raise that ceiling but not eliminate it.
- If the ClickHouse insert side stalls and our internal mpsc channel fills, `tx.send().await` blocks the listener, the kernel buffer fills next, then datagrams hit the floor.
- Mikrotik never knows it's losing — UDP has no acknowledgment.

For the regulatory query "who was on this IP at this time," the loss profile is the same as every other syslog-based ISP setup. We make up for it with two cheap things: keep the raw line in the structured table for re-parsing, and route shape-mismatch parses to `raw_log` instead of inventing a row.

RouterOS 7.18+ is required; we tested with 7.20.8.

### `clickhouse-rs` over alternatives

We considered:
- **`refinery` for migrations** — refinery does not support ClickHouse. Adding it would have required switching to the `klickhouse` driver, sacrificing the more mature `clickhouse-rs` (with its built-in `Inserter` batching primitive). For ClickHouse the migration story is mostly additive (`ALTER TABLE ADD COLUMN`), so we wrote a ~50-line migration runner that's good enough.
- **`async_insert=1` on the server** — server-side buffering is great for many small inserts but client-side `Inserter` batching gives us better visibility (we see committed row counts in logs) and works for small POC volumes where async-insert's flush interval would dominate.

### Schema choices

```sql
-- from V001__init.sql
CREATE TABLE firewall_connections (
    ts          DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    received_at DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    mikrotik_ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    router      LowCardinality(String),
    chain       LowCardinality(String),
    log_prefix  LowCardinality(String),
    severity    LowCardinality(String),
    in_iface    LowCardinality(String),
    out_iface   LowCardinality(String),
    src_mac     String,
    proto       LowCardinality(String),
    src_ip      IPv6,
    src_port    UInt16,
    dst_ip      IPv6,
    dst_port    UInt16,
    len         UInt32,
    raw         String CODEC(ZSTD(3))
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (src_ip, ts)
TTL toDateTime(ts) + INTERVAL 12 MONTH;
```

The three timestamp columns each answer a different question:
- **`ts`** — the canonical event time used for partitioning, indexing, TTL. Today this equals `received_at`. We could prefer `mikrotik_ts` (the parsed router clock) but `received_at` keeps the canonical clock on infrastructure we control.
- **`received_at`** — when the ingester saw the line. Authoritative for the audit trail (this clock is on infrastructure you control).
- **`mikrotik_ts`** — the router's own wall clock at the moment it generated the log line. Useful for spotting clock skew between routers and the ingester. Falls back to `received_at` when the syslog timestamp can't be parsed (notably, RouterOS's `iso8601` mode emits a non-standard fractional-seconds shape — see Empirical findings below).

- **`IPv6` for both source and destination** — IPv4 addresses are stored in their v4-mapped form (`::ffff:192.168.88.10`) so we don't need two columns or a tagged union. ClickHouse's `IPv6NumToString` shows the mapped form when reading.
- **`ORDER BY (src_ip, ts)`** — the primary compliance query is *"who was on this IP at this time"*. Indexing by `src_ip` first makes that lookup almost free.
- **`LowCardinality` on chain/iface/proto** — these have ~5 distinct values across millions of rows; LC encodes as a dictionary lookup with much smaller storage.
- **`Delta + ZSTD` on timestamps** — Delta exploits the near-monotonic insertion order, ZSTD then compresses the deltas. Saves ~80% over raw timestamps for a busy stream.
- **`raw` with `ZSTD(3)`** — the raw column is large per row (~500 bytes) but highly compressible (lots of repeated structure). ZSTD level 3 hits a good size/CPU balance.

### Bounded mpsc + Inserter batching

The listener pushes into `mpsc::channel(10_000)`. The pipeline task consumes from it and feeds a `clickhouse::Inserter` configured for `(5s | 100k rows | 50MB)` periods. Rationale:

- **Internal backpressure only** — when the pipeline can't keep up, the channel fills, the listener's `tx.send().await` blocks, and the kernel UDP recv buffer starts filling. Once the kernel buffer is full, *the kernel drops*. There is no propagation back to Mikrotik (UDP has no acknowledgment). This is why we keep the channel large (10k) and the inserter periods short — the goal is to avoid tipping into kernel-side drops.
- **Periodic flush even at low rate** — without a period, the inserter would only commit when the row/byte limit hit, which is fine at high QPS but stale at low QPS. 5 seconds is a reasonable observability/durability tradeoff for a POC.
- **`commit()` after every write** — `commit()` is a no-op when no threshold is reached. It's checked after every write so we get a tight upper bound on staleness.

### Two inserters, one channel

Both `firewall_connections` and `raw_log` are written from the same goroutine via two separate `Inserter` instances. Routing happens via the `Message` enum:

```rust
enum Message {
    Firewall(FirewallEvent),  // matched the body regex
    Raw(RawLogRow),           // anything that didn't (ICMP, garbage, IPv6)
}
```

This keeps the pipeline single-threaded (cheap mutex-free state) while letting the two tables have independent batches.

### Graceful shutdown

The first version used `tokio::select!` over the listener, pipeline, and ctrl-c arms — fine for the happy path but on shutdown the pipeline future got dropped *mid-batch*, losing whatever was buffered in the inserter's current INSERT chunk.

The current version:

1. Listener and pipeline are spawned as separate tasks.
2. A `CancellationToken` is cloned to the listener.
3. On `SIGINT`/Ctrl-C, the token is cancelled. The listener's `select!` returns from `recv_from`, the loop breaks, `tx` drops.
4. The pipeline's `mpsc::Receiver` returns `None`, the loop breaks, `inserter.end()` is called for both tables, the final commit lands.
5. Main waits up to 15s for the drain before exiting.

Test: send `kill -INT` while traffic is flowing; rows in flight at shutdown end up in ClickHouse rather than being lost.

---

## Empirical findings about Mikrotik's BSD syslog output

The Mikrotik docs describe the property names but not the wire format. We captured it from RouterOS 7.20.8 with `remote-log-format=syslog`, in both timestamp modes:

```
<134>Apr 29 19:13:35 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac 52:54:00:00:02:01, proto TCP (SYN), 192.168.88.254:48954->34.107.221.82:80, len 60
<134>2026-04-29T19:13:57.0000+0000 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac 52:54:00:00:02:01, proto UDP, 192.168.88.254:57036->34.107.243.93:443, len 1280
<134>2026-04-29T19:16:14.0000+0000 MikroTik conn-new forward: in:ether2 out:ether1, connection-state:new src-mac 52:54:00:00:02:01, proto ICMP (type 8, code 0), 192.168.88.254->1.1.1.1, len 84
```

A few things worth knowing:

1. **`<134>` priority byte is `local0.info`.** `134 = 16*8 + 6` — facility 16 (local0, set via `syslog-facility=local0`) and severity 6 (info). We derive the textual `severity` column directly from the priority byte.
2. **Body is the proprietary RouterOS log message, unmodified.** It's exactly what used to live inside CEF's `msg=` extension. The shape is `<log-prefix> <chain>: in:<if> out:<if>, connection-state:<state> src-mac <mac>, proto <PROTO>(?: \([^)]*\))?, <sip>:<sport>-><dip>:<dport>, len <n>`. A single regex covers TCP and UDP cleanly.
3. **Proto carries side-info in parens.** `TCP (SYN)`, `UDP`, `ICMP (type 8, code 0)`. The flag/type/code is stripped before storage so the `proto` column stays low-cardinality.
4. **ICMP has no port pair.** The address pair becomes `<sip>-><dip>` with no `:port`. Our regex requires ports, so ICMP lines route to `raw_log` rather than `firewall_connections` (the line is preserved; just not promoted). For "who was on this IP at this time," ICMP isn't load-bearing.
5. **`syslog-time-format=iso8601` is non-standard.** RouterOS emits `2026-04-29T19:13:57.0000+0000` — *4-digit* fractional seconds (not 3 or 6) and `+0000` without a colon. Looking at consecutive packets, the `.0001`, `.0002` increments aren't actual sub-second precision; they're a per-second event counter. `syslog_loose` handles or fails this on a best-effort basis; `mikrotik_ts` falls back to `received_at` when parsing breaks, and the canonical `ts` is unaffected because it's already `received_at`.
6. **Hostname comes from `/system identity`.** We pull it from the syslog header (`MikroTik` in this capture) and use it as the `router` column. Falls back to peer IP, which on QEMU NAT is just `127.0.0.1` — useless for distinguishing routers, so for a real fleet you'd want a peer-IP → router-name map.

---

## Mikrotik-side configuration

Lives in [`../configs/mikrotik-logging.rsc`](../configs/mikrotik-logging.rsc) and is applied by `run.sh` on first boot via the same expect-over-serial path as the hotspot config:

```routeros
/system logging remove [find action=syslogremote]
/system logging action remove [find name=syslogremote]
/system logging action add name=syslogremote target=remote remote=10.0.2.2 remote-port=5140 \
    remote-log-format=syslog syslog-time-format=iso8601 syslog-facility=local0
/system logging add topics=firewall action=syslogremote

/ip firewall filter remove [find log-prefix="conn-new"]
/ip firewall filter add chain=forward connection-state=new action=log log-prefix="conn-new" place-before=0
```

A couple of RouterOS quirks worth flagging:

- **`remote-protocol` does nothing for syslog.** Per the RouterOS docs: "TCP and TLS only works with CEF; for syslog it will always use UDP, even if TCP/TLS is set." So we don't bother setting it.
- **Action names must be alphanumeric.** No hyphens, no underscores. We use `syslogremote` (not `syslog-remote`).
- **No connection state to bounce.** Unlike CEF/TCP, a syslog/UDP action has no socket that can go stale across an ingester restart — Mikrotik just sends datagrams into the void until the listener returns.

---

## Running it

### Standalone (without the lab)

```bash
cd mikrotik-ingester
docker compose up -d                     # ClickHouse on :8123 + :9000
cargo run --release                      # listens on :5140
```

Then send a test syslog line over UDP:

```bash
printf '<134>2026-04-29T19:13:57.0000+0000 router1 conn-new forward: in:ether2 out:ether1, connection-state:new src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 192.168.88.10:54321->1.2.3.4:443, len 60' \
  | nc -u -w1 localhost 5140
```

After ~5s the row appears in `firewall_connections`.

### As part of the lab

`./run.sh` from the repo root brings up ClickHouse, builds and starts the ingester, applies both Mikrotik configs (hotspot + logging), and starts the VMs.

### Inspecting

ClickHouse Play UI: <http://localhost:8123/play> (user `ingester`, password `ingester`).

```sql
SELECT
  ts, mikrotik_ts, router, chain, log_prefix, severity,
  IPv6NumToString(src_ip) AS src, src_port,
  IPv6NumToString(dst_ip) AS dst, dst_port,
  proto, src_mac
FROM mikrotik.firewall_connections
ORDER BY ts DESC
LIMIT 100
```

Clock-skew between router and ingester:

```sql
SELECT
  router,
  avg(received_at - mikrotik_ts) AS avg_skew,
  max(abs(received_at - mikrotik_ts)) AS worst_skew
FROM mikrotik.firewall_connections
WHERE received_at > now() - INTERVAL 1 HOUR
GROUP BY router
```

Compliance lookup ("who was on IP X at time T"):

```sql
SELECT *
FROM mikrotik.firewall_connections
WHERE src_ip = toIPv6('::ffff:192.168.88.254')
  AND ts BETWEEN '2026-04-28 17:00:00' AND '2026-04-28 18:00:00'
ORDER BY ts
```

Anything that failed parsing:

```sql
SELECT received_at, parse_error, raw
FROM mikrotik.raw_log
WHERE parse_error != ''
ORDER BY received_at DESC
LIMIT 50
```

---

## Joining firewall events with RADIUS sessions

The compliance question "who was on this IP at this time" needs the *user* behind the IP. The RADIUS server (`../radius-server`) streams an event per Accounting packet into ClickHouse, alongside the firewall events written here:

```sql
CREATE TABLE radius_session_events (
    ts              DateTime64(3, 'UTC'),
    event           LowCardinality(String),  -- 'start' | 'interim' | 'stop' | 'on' | 'off'
    acct_session_id String,
    nas_ip          IPv6,
    username        String,
    mac             String,                  -- normalized lowercase, colons
    framed_ip       IPv6,
    session_time    UInt32,
    bytes_in        UInt64,
    bytes_out       UInt64,
    terminate_cause LowCardinality(String)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (mac, ts)
TTL toDateTime(ts) + INTERVAL 12 MONTH;
```

The join key is **MAC**, not IP — IPs get reused across hotspot sessions, MACs are tied to the device for the lifetime of the session. Both writers normalize to `aa:bb:cc:dd:ee:ff` (lowercase, colons) so the equality holds. Use `ASOF JOIN` so each firewall event picks up the latest preceding session event for that MAC:

```sql
SELECT
  fc.ts,
  IPv6NumToString(fc.src_ip) AS src,
  IPv6NumToString(fc.dst_ip) AS dst,
  fc.dst_port,
  fc.proto,
  s.username,
  s.acct_session_id
FROM mikrotik.firewall_connections fc
ASOF LEFT JOIN mikrotik.radius_session_events s
  ON fc.src_mac = s.mac AND fc.ts >= s.ts
WHERE fc.ts BETWEEN '2026-04-28 17:00:00' AND '2026-04-28 18:00:00'
ORDER BY fc.ts
```

The `ASOF` semantics: for each `(src_mac, ts)` on the left, ClickHouse finds the row in `radius_session_events` with the same `mac` and the largest `s.ts <= fc.ts`. With both tables ordered by `(mac, ts)` it's a streaming merge — no nested loop.

`ASOF LEFT JOIN` keeps firewall rows even when no session was active for that MAC (useful for spotting gaps); plain `ASOF JOIN` drops them.

### Common audit queries

**"Who was on this IP at this time"** — the LE-style lookup:

```sql
SELECT fc.ts, s.username, fc.src_mac,
       IPv6NumToString(fc.dst_ip) AS dst, fc.dst_port
FROM mikrotik.firewall_connections fc
ASOF LEFT JOIN mikrotik.radius_session_events s
  ON fc.src_mac = s.mac AND fc.ts >= s.ts
WHERE fc.src_ip = toIPv6('::ffff:192.168.88.10')
  AND fc.ts BETWEEN '2026-04-28 17:00:00' AND '2026-04-28 18:00:00'
ORDER BY fc.ts
```

**"What did user X do"** — pre-filter sessions to one user, then ASOF join their MACs:

```sql
WITH user_events AS (
  SELECT mac, ts AS sess_ts, username
  FROM mikrotik.radius_session_events
  WHERE username = 'admin'
)
SELECT fc.ts, fc.src_mac, IPv6NumToString(fc.dst_ip) AS dst, fc.dst_port
FROM mikrotik.firewall_connections fc
ASOF JOIN user_events u
  ON fc.src_mac = u.mac AND fc.ts >= u.sess_ts
WHERE fc.ts > now() - INTERVAL 1 DAY
ORDER BY fc.ts DESC
```

**Sanity-check the audit stream is flowing:**

```sql
SELECT event, count(), max(ts) FROM mikrotik.radius_session_events GROUP BY event
```

Two practical notes:
- **Empty until both sides have data.** A row appears in `radius_session_events` only when MikroTik sends an Accounting packet (Start at login, Stop at logout, Interim every 5–10 min). If you've only just authenticated, you may need to trigger a logout or wait for an interim before the join hits.
- **MAC normalization matters.** Both writers emit `aa:bb:cc:dd:ee:ff` lowercase. If you see `NULL`s in `s.username` for rows that should have matched, double-check the MAC casing on both sides — a single `AA:BB:...` row will silently fall out of the equi-join.

### Operational note

The radius-server bootstrap is async and non-blocking: if ClickHouse is unreachable at startup, the audit task logs and exits without taking down RADIUS auth. Events generated during a ClickHouse outage are absorbed by the in-memory mpsc channel until it fills, then dropped (`audit channel send dropped` in the log) — RADIUS itself keeps working.

---

## Configuration

All knobs are environment variables with sensible defaults for the lab:

| Variable | Default | Meaning |
|---|---|---|
| `INGESTER_LISTEN` | `0.0.0.0:5140` | TCP listen address for incoming CEF |
| `INGESTER_METRICS` | `0.0.0.0:9100` | Reserved (Prometheus endpoint deferred) |
| `CLICKHOUSE_URL` | `http://localhost:8123` | HTTP endpoint |
| `CLICKHOUSE_USER` | `ingester` | |
| `CLICKHOUSE_PASSWORD` | `ingester` | |
| `CLICKHOUSE_DB` | `mikrotik` | |
| `RUST_LOG` | `mikrotik_ingester=info,clickhouse=warn` | Tracing filter |

---

## What was deferred

These were considered during the build and explicitly punted:

- **Prometheus `/metrics` endpoint.** For a POC the tracing logs (`committed table=… rows=N`) plus ad-hoc SQL counts cover the same observability. Worth adding when running for real — especially a kernel-drop counter (`/proc/net/udp`) so we can tell when we're losing.
- **Multi-router routing-table.** Today we use the syslog hostname as the `router` column, falling back to the peer IP when missing. For a real fleet we'd want a config map of `peer_ip → router_name` so the column is stable even if Mikrotik's identity changes.
- **`SO_RCVBUF` tuning.** The default kernel UDP receive buffer is small (~200 KB). Bumping it on the listener socket would reduce drops during transient bursts. Worth measuring before adding the knob.
- **ICMP / IPv6 promotion to `firewall_connections`.** Both currently land in `raw_log` because the body regex is anchored on `<sip>:<sport>->` (IPv4 with ports). If forensic queries ever need ICMP type/code or bracketed IPv6, the regex grows a couple of alternatives.
- **RFC 5424 structured-data parsing.** Mikrotik doesn't emit it for firewall events; if a future RouterOS adds it we'd want to extract it before the body regex runs.

---

## Build journey notes

Things that bit us on the way to a working POC, in case they bite again:

- **`#[serde(with = "clickhouse::serde::ipv6")]` does not exist.** `Ipv6Addr` works natively with no annotation in `clickhouse-rs` 0.13. Only `Ipv4Addr` needs the `clickhouse::serde::ipv4` adapter. The crate's CHANGELOG explicitly notes "IPv6 requires no annotations."
- **`Inserter::time_left()` takes `&mut self`.** Helper functions that read it must take `&mut Inserter<T>`, not `&Inserter<T>`.
- **RouterOS log filter syntax.** `last=N` is invalid for `/log print`; use `count-only=N` or just `/log print where ...` and visually scan. The print's `where` clause supports regex via `~`, e.g., `where topics~"firewall"`.
- **Action names alphanumeric only.** RouterOS rejects `syslog-remote` with `failure: action name can contain only letters and numbers`. Use `syslogremote` instead.
- **`remote-protocol` is a no-op for syslog.** Setting `remote-protocol=tcp` while `remote-log-format=syslog` *silently* downgrades to UDP. The docs say so explicitly; surprising on first read.
- **RouterOS ISO 8601 isn't quite ISO 8601.** `syslog-time-format=iso8601` produces `2026-04-29T19:13:57.0000+0000` — 4-digit fractional seconds, no colon in the offset, and the fractional digits act as a per-second event counter rather than real sub-second precision. Most strict parsers reject it; we let `syslog_loose` try and fall back to `received_at`.
- **Multi-statement SQL through ClickHouse HTTP doesn't work.** A `;`-separated batch only runs the first statement. Send statements one by one or use a tool that splits them.
