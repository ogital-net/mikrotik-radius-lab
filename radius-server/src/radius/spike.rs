use log::info;
use radius_tokio::server::Request;

const VENDOR_SPECIFIC: u8 = 26;
const ATTR_DHCP_AGENT_CIRCUIT_ID: u8 = 82;

pub fn dump(label: &str, request: &Request<'_>) {
    info!(
        "[{}] code={:?} id={} from={}",
        label,
        request.code(),
        request.identifier(),
        request.src()
    );

    let mut any = false;
    for slot in request.attributes_iter() {
        any = true;
        match slot {
            Ok(raw) => log_avp(raw.attribute_type(), raw.value()),
            Err(e) => {
                info!("  malformed AVP: {}", e);
                break;
            }
        }
    }
    if !any {
        info!("[{}] no AVPs", label);
    }
}

fn log_avp(typ: u8, value: &[u8]) {
    let hex = hexdump(value);
    let ascii = printable(value);
    info!(
        "  type={:>3} len={:>3} hex={} ascii=\"{}\"",
        typ,
        value.len(),
        hex,
        ascii
    );

    match typ {
        VENDOR_SPECIFIC => log_vsa(value),
        ATTR_DHCP_AGENT_CIRCUIT_ID => log_option82(value),
        _ => {}
    }
}

fn log_vsa(value: &[u8]) {
    if value.len() < 6 {
        return;
    }
    let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    let vendor_name = match vendor_id {
        14988 => "Mikrotik",
        3561 => "DSL-Forum",
        _ => "vendor",
    };
    let mut j = 4;
    while j + 2 <= value.len() {
        let sub_typ = value[j];
        let sub_len = value[j + 1] as usize;
        if sub_len < 2 || j + sub_len > value.len() {
            break;
        }
        let sub_value = &value[j + 2..j + sub_len];
        let label = match (vendor_id, sub_typ) {
            (3561, 1) => " (Agent-Circuit-Id)",
            (3561, 2) => " (Agent-Remote-Id)",
            (3561, 129) => " (Actual-Data-Rate-Upstream)",
            (3561, 130) => " (Actual-Data-Rate-Downstream)",
            _ => "",
        };
        info!(
            "    vsa {}={} sub_type={}{} len={} hex={} ascii=\"{}\"",
            vendor_name,
            vendor_id,
            sub_typ,
            label,
            sub_value.len(),
            hexdump(sub_value),
            printable(sub_value),
        );
        j += sub_len;
    }
}

fn log_option82(value: &[u8]) {
    let mut j = 0;
    while j + 2 <= value.len() {
        let sub_typ = value[j];
        let sub_len = value[j + 1] as usize;
        if sub_len < 2 || j + sub_len > value.len() {
            break;
        }
        let sub_value = &value[j + 2..j + sub_len];
        let label = match sub_typ {
            1 => "Agent-Circuit-Id",
            2 => "Agent-Remote-Id",
            _ => "sub",
        };
        info!(
            "    opt82 {}={} hex={} ascii=\"{}\"",
            label,
            sub_typ,
            hexdump(sub_value),
            printable(sub_value),
        );
        j += sub_len;
    }
}

fn hexdump(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}
