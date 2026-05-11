use crate::model::FlowEvent;
use ipfix_parser::ie::id;
use ipfix_parser::store::{InsertOutcome, SessionTemplateStore};
use ipfix_parser::{
    DataRecordIter, FieldSpecifier, MessageHeader, SetIter, SetKind, TemplateSetIter,
    TemplateSetKind, TemplateStore,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use time::OffsetDateTime;
use tracing::{debug, warn};

pub struct IpfixParser {
    store: SessionTemplateStore<IpAddr>,
    fbuf: [FieldSpecifier; 128],
    default_sampling_interval: u32,
}

impl IpfixParser {
    pub fn new(default_sampling_interval: u32) -> Self {
        Self {
            store: SessionTemplateStore::new(),
            fbuf: [FieldSpecifier::EMPTY; 128],
            default_sampling_interval: default_sampling_interval.max(1),
        }
    }

    pub fn parse_datagram(
        &mut self,
        buf: &[u8],
        peer: IpAddr,
        received_at: OffsetDateTime,
    ) -> Vec<FlowEvent> {
        let mut out = Vec::new();

        let (header, sets_buf) = match MessageHeader::decode(buf) {
            Ok(ok) => ok,
            Err(e) => {
                debug!(%peer, ?e, "ipfix header decode error");
                return out;
            }
        };
        let odid = header.observation_domain_id;
        let router = peer.to_string();

        for set in SetIter::new(sets_buf) {
            let set = match set {
                Ok(s) => s,
                Err(e) => {
                    debug!(%peer, ?e, "ipfix set decode error");
                    break;
                }
            };
            match set.kind {
                SetKind::Template => {
                    let mut iter = TemplateSetIter::new(
                        set.records,
                        &mut self.fbuf,
                        TemplateSetKind::Template,
                    );
                    while let Some(rec) = iter.next() {
                        match rec {
                            Ok(rec) => {
                                if let InsertOutcome::Collision =
                                    self.store.insert(&peer, odid, &rec)
                                {
                                    warn!(%peer, tid = rec.id, "ipfix template id collision");
                                }
                            }
                            Err(e) => debug!(%peer, ?e, "ipfix template error"),
                        }
                    }
                }
                SetKind::OptionsTemplate => {
                    let mut iter = TemplateSetIter::new(
                        set.records,
                        &mut self.fbuf,
                        TemplateSetKind::OptionsTemplate,
                    );
                    while let Some(rec) = iter.next() {
                        match rec {
                            Ok(rec) => {
                                if let InsertOutcome::Collision =
                                    self.store.insert(&peer, odid, &rec)
                                {
                                    warn!(%peer, tid = rec.id, "ipfix options template collision");
                                }
                            }
                            Err(e) => debug!(%peer, ?e, "ipfix options template error"),
                        }
                    }
                }
                SetKind::Data(tid) => {
                    let view = self.store.view(peer);
                    let Some(template) = view.get(odid, tid) else {
                        debug!(%peer, odid, tid, "ipfix data set for unknown template");
                        continue;
                    };
                    for record in DataRecordIter::new(set.records, template) {
                        let record = match record {
                            Ok(r) => r,
                            Err(e) => {
                                debug!(%peer, ?e, "ipfix record decode error");
                                break;
                            }
                        };
                        out.push(build_flow_event(
                            &record,
                            &router,
                            odid,
                            self.default_sampling_interval,
                            received_at,
                        ));
                    }
                }
                _ => {}
            }
        }

        out
    }
}

fn build_flow_event(
    record: &ipfix_parser::DataRecord<'_>,
    router: &str,
    odid: u32,
    default_sampling: u32,
    received_at: OffsetDateTime,
) -> FlowEvent {
    let mut ev = FlowEvent {
        ts: received_at,
        received_at,
        flow_start: received_at,
        flow_end: received_at,
        router: router.to_string(),
        observation_domain: odid,
        sampling_interval: default_sampling,
        src_ip: Ipv6Addr::UNSPECIFIED,
        dst_ip: Ipv6Addr::UNSPECIFIED,
        src_port: 0,
        dst_port: 0,
        proto: 0,
        tcp_flags: 0,
        octets: 0,
        packets: 0,
        ingress_if: 0,
        egress_if: 0,
        src_mac: String::new(),
        dst_mac: String::new(),
        next_hop: Ipv6Addr::UNSPECIFIED,
    };

    for field in record.fields() {
        let Ok(f) = field else { continue };
        match f.information_element_id {
            id::SOURCE_IPV4_ADDRESS => {
                if let Some(v4) = ipv4(f.data) {
                    ev.src_ip = v4.to_ipv6_mapped();
                }
            }
            id::DESTINATION_IPV4_ADDRESS => {
                if let Some(v4) = ipv4(f.data) {
                    ev.dst_ip = v4.to_ipv6_mapped();
                }
            }
            id::IP_NEXT_HOP_IPV4_ADDRESS => {
                if let Some(v4) = ipv4(f.data) {
                    ev.next_hop = v4.to_ipv6_mapped();
                }
            }
            id::SOURCE_IPV6_ADDRESS => {
                if let Some(v6) = ipv6(f.data) {
                    ev.src_ip = v6;
                }
            }
            id::DESTINATION_IPV6_ADDRESS => {
                if let Some(v6) = ipv6(f.data) {
                    ev.dst_ip = v6;
                }
            }
            id::IP_NEXT_HOP_IPV6_ADDRESS => {
                if let Some(v6) = ipv6(f.data) {
                    ev.next_hop = v6;
                }
            }
            id::SOURCE_TRANSPORT_PORT => {
                if let Some(v) = f.as_u16() {
                    ev.src_port = v;
                }
            }
            id::DESTINATION_TRANSPORT_PORT => {
                if let Some(v) = f.as_u16() {
                    ev.dst_port = v;
                }
            }
            id::PROTOCOL_IDENTIFIER => {
                if let Some(v) = f.as_u8() {
                    ev.proto = v;
                }
            }
            id::TCP_CONTROL_BITS => {
                // RFC 7012 specifies u16; RFC 5102 had u8. Accept either.
                ev.tcp_flags = f.as_u16().or_else(|| f.as_u8().map(u16::from)).unwrap_or(0);
            }
            id::OCTET_DELTA_COUNT => {
                if let Some(v) = f.as_u64() {
                    ev.octets = v;
                }
            }
            id::PACKET_DELTA_COUNT => {
                if let Some(v) = f.as_u64() {
                    ev.packets = v;
                }
            }
            id::INGRESS_INTERFACE => {
                if let Some(v) = f.as_u32() {
                    ev.ingress_if = v;
                }
            }
            id::EGRESS_INTERFACE => {
                if let Some(v) = f.as_u32() {
                    ev.egress_if = v;
                }
            }
            id::SOURCE_MAC_ADDRESS => {
                if let Some(s) = fmt_mac(f.data) {
                    ev.src_mac = s;
                }
            }
            id::DESTINATION_MAC_ADDRESS => {
                if let Some(s) = fmt_mac(f.data) {
                    ev.dst_mac = s;
                }
            }
            id::FLOW_START_MILLISECONDS => {
                if let Some(v) = f.as_u64() {
                    ev.flow_start = ms_to_dt(v).unwrap_or(received_at);
                }
            }
            id::FLOW_END_MILLISECONDS => {
                if let Some(v) = f.as_u64() {
                    ev.flow_end = ms_to_dt(v).unwrap_or(received_at);
                }
            }
            _ => {}
        }
    }
    ev
}

fn ipv4(b: &[u8]) -> Option<Ipv4Addr> {
    <&[u8; 4]>::try_from(b).ok().map(|a| Ipv4Addr::from(*a))
}

fn ipv6(b: &[u8]) -> Option<Ipv6Addr> {
    <&[u8; 16]>::try_from(b).ok().map(|a| Ipv6Addr::from(*a))
}

fn fmt_mac(b: &[u8]) -> Option<String> {
    if b.len() != 6 {
        return None;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    ))
}

fn ms_to_dt(ms: u64) -> Option<OffsetDateTime> {
    let nanos = i128::from(ms).checked_mul(1_000_000)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()
}
