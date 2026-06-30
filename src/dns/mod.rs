//! Minimal RFC 1035 DNS wire protocol: message parsing + response building.
//!
//! Hand-rolled rather than pulling a full resolver crate — the same dependency-minimal posture as
//! the rest of the estate (sanctum hand-rolls its HTTP client, the healthcheck hand-rolls its
//! probe). We support exactly what an authoritative server for a handful of zones needs:
//! A / AAAA / MX / TXT / NS / CNAME / SOA, the standard `QUERY` opcode, class `IN`, wildcard owners,
//! the AA bit, and correct NXDOMAIN vs NODATA. Names are encoded WITHOUT compression (compression is
//! optional in the protocol), which keeps the encoder trivial and is accepted by every resolver.
//!
//! [`resolver`] turns a query name+type into a [`Lookup`] from the in-memory zone snapshot;
//! [`server`] runs the UDP + TCP listeners that call into here.

pub mod resolver;
pub mod server;

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::{SOA_EXPIRE, SOA_MINIMUM, SOA_REFRESH, SOA_RETRY};

// Record / query type codes.
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_ANY: u16 = 255;

pub const CLASS_IN: u16 = 1;

// Response codes (RFC 1035 §4.1.1).
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// Map a textual record type (`A`, `mx`, …) to its wire code. Case-insensitive; `None` for unknown.
pub fn type_from_str(s: &str) -> Option<u16> {
    match s.trim().to_ascii_uppercase().as_str() {
        "A" => Some(TYPE_A),
        "NS" => Some(TYPE_NS),
        "CNAME" => Some(TYPE_CNAME),
        "SOA" => Some(TYPE_SOA),
        "MX" => Some(TYPE_MX),
        "TXT" => Some(TYPE_TXT),
        "AAAA" => Some(TYPE_AAAA),
        "ANY" | "*" => Some(TYPE_ANY),
        _ => None,
    }
}

/// Render a wire type code back to its conventional text label.
pub fn type_to_str(t: u16) -> String {
    match t {
        TYPE_A => "A",
        TYPE_NS => "NS",
        TYPE_CNAME => "CNAME",
        TYPE_SOA => "SOA",
        TYPE_MX => "MX",
        TYPE_TXT => "TXT",
        TYPE_AAAA => "AAAA",
        TYPE_ANY => "ANY",
        _ => return format!("TYPE{t}"),
    }
    .to_string()
}

/// The RDATA of a single answer, in a typed form that knows how to encode itself.
#[derive(Clone, Debug)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// NS / CNAME target (a domain name).
    Name(u16, String),
    Mx { pref: u16, host: String },
    Txt(String),
    Soa(Soa),
}

/// The synthesized start-of-authority record for a zone apex.
#[derive(Clone, Debug)]
pub struct Soa {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl Soa {
    /// Build the SOA for a zone from its primary NS, hostmaster, and serial (timers are estate
    /// defaults).
    pub fn new(mname: &str, rname: &str, serial: u32) -> Self {
        Soa {
            mname: mname.to_string(),
            rname: rname.to_string(),
            serial,
            refresh: SOA_REFRESH,
            retry: SOA_RETRY,
            expire: SOA_EXPIRE,
            minimum: SOA_MINIMUM,
        }
    }
}

impl RData {
    /// The wire type code this RDATA carries.
    pub fn type_code(&self) -> u16 {
        match self {
            RData::A(_) => TYPE_A,
            RData::Aaaa(_) => TYPE_AAAA,
            RData::Name(t, _) => *t,
            RData::Mx { .. } => TYPE_MX,
            RData::Txt(_) => TYPE_TXT,
            RData::Soa(_) => TYPE_SOA,
        }
    }

    /// A presentation-form string for the dashboard "test query" box.
    pub fn to_text(&self) -> String {
        match self {
            RData::A(ip) => ip.to_string(),
            RData::Aaaa(ip) => ip.to_string(),
            RData::Name(_, n) => format!("{n}."),
            RData::Mx { pref, host } => format!("{pref} {host}."),
            RData::Txt(s) => format!("\"{s}\""),
            RData::Soa(s) => format!(
                "{}. {}. {} {} {} {} {}",
                s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum
            ),
        }
    }

    /// Append this RDATA's bytes (NOT including the 2-byte RDLENGTH prefix) to `out`.
    fn encode_rdata(&self, out: &mut Vec<u8>) {
        match self {
            RData::A(ip) => out.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
            RData::Name(_, n) => encode_name(n, out),
            RData::Mx { pref, host } => {
                out.extend_from_slice(&pref.to_be_bytes());
                encode_name(host, out);
            }
            RData::Txt(s) => encode_txt(s, out),
            RData::Soa(s) => {
                encode_name(&s.mname, out);
                encode_name(&s.rname, out);
                out.extend_from_slice(&s.serial.to_be_bytes());
                out.extend_from_slice(&s.refresh.to_be_bytes());
                out.extend_from_slice(&s.retry.to_be_bytes());
                out.extend_from_slice(&s.expire.to_be_bytes());
                out.extend_from_slice(&s.minimum.to_be_bytes());
            }
        }
    }
}

/// One resource record in an answer/authority section.
#[derive(Clone, Debug)]
pub struct Rr {
    /// Owner name (no trailing dot; encoded canonically).
    pub name: String,
    pub ttl: u32,
    pub data: RData,
}

/// The result of resolving one question: an rcode, the AA flag, and the answer/authority RRs.
#[derive(Clone, Debug, Default)]
pub struct Lookup {
    pub rcode: u8,
    pub aa: bool,
    pub answers: Vec<Rr>,
    pub authority: Vec<Rr>,
}

/// A parsed query (we only ever read a single question).
#[derive(Clone, Debug)]
pub struct Query {
    pub id: u16,
    /// Recursion-desired bit, echoed back into the response header.
    pub rd: bool,
    pub opcode: u8,
    /// Question owner name, normalized (lowercase, no trailing dot).
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Parse a DNS request message into its single question. Returns `None` on a malformed/short buffer
/// (the caller answers FORMERR using the best-effort id, or drops it).
pub fn parse_query(buf: &[u8]) -> Option<Query> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rd = (flags & 0x0100) != 0;
    if qdcount < 1 {
        return Some(Query {
            id,
            rd,
            opcode,
            qname: String::new(),
            qtype: 0,
            qclass: 0,
        });
    }
    let (qname, pos) = decode_name(buf, 12)?;
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    Some(Query {
        id,
        rd,
        opcode,
        qname: crate::config::normalize_name(&qname),
        qtype,
        qclass,
    })
}

/// Build the wire response for `query` given its resolved `lookup`.
pub fn build_response(query: &Query, lookup: &Lookup) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    // Header.
    out.extend_from_slice(&query.id.to_be_bytes());
    let mut flags: u16 = 0x8000; // QR = 1 (response)
    flags |= (query.opcode as u16 & 0x0F) << 11;
    if lookup.aa {
        flags |= 0x0400; // AA
    }
    if query.rd {
        flags |= 0x0100; // echo RD
    }
    flags |= lookup.rcode as u16 & 0x000F;
    out.extend_from_slice(&flags.to_be_bytes());

    let qd: u16 = if query.qname.is_empty() && query.qtype == 0 {
        0
    } else {
        1
    };
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&(lookup.answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(lookup.authority.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question (echoed).
    if qd == 1 {
        encode_name(&query.qname, &mut out);
        out.extend_from_slice(&query.qtype.to_be_bytes());
        out.extend_from_slice(&query.qclass.to_be_bytes());
    }

    for rr in &lookup.answers {
        encode_rr(rr, &mut out);
    }
    for rr in &lookup.authority {
        encode_rr(rr, &mut out);
    }
    out
}

/// A bare header-only response carrying just an rcode (used for FORMERR/NOTIMP before we have a
/// parsed question). Echoes the id and opcode/RD when available.
pub fn header_only_response(id: u16, opcode: u8, rd: bool, rcode: u8) -> Vec<u8> {
    let q = Query {
        id,
        rd,
        opcode,
        qname: String::new(),
        qtype: 0,
        qclass: 0,
    };
    build_response(
        &q,
        &Lookup {
            rcode,
            aa: false,
            answers: Vec::new(),
            authority: Vec::new(),
        },
    )
}

fn encode_rr(rr: &Rr, out: &mut Vec<u8>) {
    encode_name(&rr.name, out);
    out.extend_from_slice(&rr.data.type_code().to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&rr.ttl.to_be_bytes());
    // RDLENGTH is back-patched after the RDATA is encoded.
    let len_pos = out.len();
    out.extend_from_slice(&0u16.to_be_bytes());
    let start = out.len();
    rr.data.encode_rdata(out);
    let rdlen = (out.len() - start) as u16;
    out[len_pos..len_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
}

/// Encode a domain name (no trailing dot expected) as length-prefixed labels + a zero terminator.
/// The root (empty string) encodes as a single `0` byte. Over-long labels are truncated to 63.
pub fn encode_name(name: &str, out: &mut Vec<u8>) {
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            let bytes = label.as_bytes();
            let len = bytes.len().min(63);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out.push(0);
}

/// Encode a TXT value as one or more 255-byte-max character-strings.
fn encode_txt(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        out.push(0);
        return;
    }
    for chunk in bytes.chunks(255) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
}

/// Decode a domain name starting at `start`, following compression pointers. Returns the dotted name
/// (lowercased on the resolver side later) and the offset just past the name in the ORIGINAL stream
/// (pointer jumps do not advance the returned offset past the first pointer). `None` on malformed
/// input or a pointer loop.
fn decode_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut next_after = start;
    let mut guard = 0;

    loop {
        guard += 1;
        if guard > 128 || pos >= buf.len() {
            return None;
        }
        let len = buf[pos];
        if len & 0xC0 == 0xC0 {
            // Compression pointer (two bytes).
            if pos + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
            if !jumped {
                next_after = pos + 2;
            }
            jumped = true;
            pos = ptr;
            continue;
        }
        if len == 0 {
            if !jumped {
                next_after = pos + 1;
            }
            break;
        }
        let len = len as usize;
        let from = pos + 1;
        let to = from + len;
        if to > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[from..to]).ok()?;
        labels.push(label.to_string());
        pos = to;
    }
    Some((labels.join("."), next_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        encode_name(name, &mut out);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    #[test]
    fn roundtrip_question() {
        let buf = encode_query(0x1234, "Foo.W33d.XYZ", TYPE_A);
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.id, 0x1234);
        assert!(q.rd);
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
        // Normalized: lowercased, no trailing dot.
        assert_eq!(q.qname, "foo.w33d.xyz");
    }

    #[test]
    fn response_header_bits() {
        let q = parse_query(&encode_query(7, "w33d.xyz", TYPE_A)).unwrap();
        let lk = Lookup {
            rcode: RCODE_NOERROR,
            aa: true,
            answers: vec![Rr {
                name: "w33d.xyz".to_string(),
                ttl: 300,
                data: RData::A(Ipv4Addr::new(159, 195, 136, 226)),
            }],
            authority: Vec::new(),
        };
        let resp = build_response(&q, &lk);
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 7);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR set");
        assert_eq!(flags & 0x0400, 0x0400, "AA set");
        assert_eq!(flags & 0x000F, 0, "NOERROR");
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1, "QDCOUNT");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT");
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 0, "NSCOUNT");
    }

    #[test]
    fn txt_splits_long_strings() {
        let mut out = Vec::new();
        encode_txt(&"a".repeat(300), &mut out);
        // 255-byte chunk (1 + 255) then 45-byte chunk (1 + 45).
        assert_eq!(out.len(), 256 + 46);
        assert_eq!(out[0], 255);
        assert_eq!(out[256], 45);
    }
}
