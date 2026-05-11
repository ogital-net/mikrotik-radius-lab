CREATE TABLE IF NOT EXISTS firewall_connections (
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

CREATE TABLE IF NOT EXISTS raw_log (
    received_at DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    router      LowCardinality(String),
    raw         String CODEC(ZSTD(3)),
    parse_error String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY received_at
TTL toDateTime(received_at) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS radius_session_events (
    ts              DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    event           LowCardinality(String),
    acct_session_id String,
    nas_ip          IPv6,
    username        String,
    mac             String,
    framed_ip       IPv6,
    session_time    UInt32,
    bytes_in        UInt64,
    bytes_out       UInt64,
    terminate_cause LowCardinality(String)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (mac, ts)
TTL toDateTime(ts) + INTERVAL 12 MONTH;

CREATE TABLE IF NOT EXISTS flows (
    ts                  DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    received_at         DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    flow_start          DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    flow_end            DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    router              LowCardinality(String),
    observation_domain  UInt32,
    sampling_interval   UInt32,
    src_ip              IPv6,
    dst_ip              IPv6,
    src_port            UInt16,
    dst_port            UInt16,
    proto               UInt8,
    tcp_flags           UInt16,
    octets              UInt64,
    packets             UInt64,
    ingress_if          UInt32,
    egress_if           UInt32,
    src_mac             String,
    dst_mac             String,
    next_hop            IPv6
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (src_ip, ts)
TTL toDateTime(ts) + INTERVAL 6 MONTH;
