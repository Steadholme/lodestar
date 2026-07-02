//! BIND-style zone file import/export plus record-level validation.
//!
//! This module stays presentation-format only: it normalizes names and RDATA into the same `records`
//! table shape the dashboard already uses, while the resolver remains the single path that turns rows
//! into DNS wire answers.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::config::{normalize_name, SOA_EXPIRE, SOA_MINIMUM, SOA_REFRESH, SOA_RETRY};
use crate::store::{Record, Zone};

/// Parsed record ready to be turned into a stored [`Record`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRecord {
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: i64,
}

#[derive(Clone, Debug)]
struct LogicalLine {
    text: String,
    leading_space: bool,
    line_no: usize,
}

/// Compute the canonical owner name from operator or zone-file input and a current origin.
pub fn owner_name(input: &str, origin: &str) -> String {
    let n = normalize_name(input);
    if n.is_empty() || n == "@" {
        return origin.to_string();
    }
    if n.ends_with('.') {
        return normalize_name(&n);
    }
    if n == origin || n.ends_with(&format!(".{origin}")) {
        return n;
    }
    format!("{n}.{origin}")
}

/// Parse a TTL, clamping to a sane non-negative range with a 300s default for blank/garbage input.
pub fn parse_ttl(s: &str) -> i64 {
    s.trim()
        .parse::<i64>()
        .ok()
        .filter(|t| *t >= 0)
        .map(|t| t.min(2_147_483_647))
        .unwrap_or(300)
}

/// Normalize and validate one RDATA value for storage.
pub fn normalize_record_value(rtype: &str, value: &str, origin: &str) -> Result<String, String> {
    let bad = |m: &str| m.to_string();
    let rtype = rtype.trim().to_ascii_uppercase();
    let value = value.trim();
    if value.is_empty() {
        return Err(bad("value is required"));
    }

    match rtype.as_str() {
        "A" => Ipv4Addr::from_str(value)
            .map(|ip| ip.to_string())
            .map_err(|_| bad("invalid IPv4 address for A record")),
        "AAAA" => Ipv6Addr::from_str(value)
            .map(|ip| ip.to_string())
            .map_err(|_| bad("invalid IPv6 address for AAAA record")),
        "NS" | "CNAME" => {
            let name = name_rdata(value, origin);
            if name.is_empty() {
                Err(bad("target name is required"))
            } else {
                Ok(name)
            }
        }
        "MX" => {
            let parts = words(value);
            if parts.len() < 2 {
                return Err(bad("MX needs: <preference> <host>"));
            }
            let pref = parse_u16(&parts[0], "MX preference must be 0-65535")?;
            let host = name_rdata(&parts[1..].join(" "), origin);
            if host.is_empty() {
                return Err(bad("MX needs a mail host after the preference"));
            }
            Ok(format!("{pref} {host}"))
        }
        "TXT" => Ok(strip_quotes(value).to_string()),
        "SRV" => {
            let parts = words(value);
            if parts.len() != 4 {
                return Err(bad("SRV needs: <priority> <weight> <port> <target>"));
            }
            let priority = parse_u16(&parts[0], "SRV priority must be 0-65535")?;
            let weight = parse_u16(&parts[1], "SRV weight must be 0-65535")?;
            let port = parse_u16(&parts[2], "SRV port must be 0-65535")?;
            let target = name_rdata(&parts[3], origin);
            if target.is_empty() {
                return Err(bad("SRV target is required"));
            }
            Ok(format!("{priority} {weight} {port} {target}"))
        }
        "CAA" => {
            let parts = words(value);
            if parts.len() < 3 {
                return Err(bad("CAA needs: <flags> <tag> <value>"));
            }
            let flags = parts[0]
                .parse::<u8>()
                .map_err(|_| bad("CAA flags must be 0-255"))?;
            let tag = parts[1].trim().to_ascii_lowercase();
            if tag.is_empty()
                || !tag
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(bad(
                    "CAA tag must contain only letters, numbers, '-' or '_'",
                ));
            }
            let caa_value = strip_quotes(&parts[2..].join(" ")).to_string();
            if caa_value.is_empty() {
                return Err(bad("CAA value is required"));
            }
            Ok(format!("{flags} {tag} {caa_value}"))
        }
        _ => Err(format!("unsupported record type: {rtype}")),
    }
}

/// Validate CNAME exclusivity and exact duplicate records inside one zone.
pub fn validate_record_set(records: &[Record]) -> Result<(), String> {
    for (idx, a) in records.iter().enumerate() {
        let a_type = a.rtype.to_ascii_uppercase();
        for b in records.iter().skip(idx + 1) {
            if a.name != b.name {
                continue;
            }
            let b_type = b.rtype.to_ascii_uppercase();
            if a_type == b_type && a.value.trim() == b.value.trim() {
                return Err(format!(
                    "duplicate {} record for {}",
                    a_type,
                    display_name(&a.name)
                ));
            }
            if a_type == "CNAME" || b_type == "CNAME" {
                return Err(format!(
                    "CNAME record for {} cannot coexist with other records at the same name",
                    display_name(&a.name)
                ));
            }
        }
    }
    Ok(())
}

/// Validate a candidate record against an existing zone snapshot.
pub fn validate_new_record(existing: &[Record], candidate: &Record) -> Result<(), String> {
    let mut records = existing.to_vec();
    records.push(candidate.clone());
    validate_record_set(&records)
}

/// Parse a common BIND zone file into normalized records for `zone`.
pub fn parse_zone_file(zone: &Zone, input: &str) -> Result<Vec<ParsedRecord>, String> {
    let mut origin = zone.name.clone();
    let mut default_ttl = 300i64;
    let mut previous_owner = "@".to_string();
    let mut records = Vec::new();

    for line in logical_lines(input)? {
        let tokens = tokenize(&line.text).map_err(|e| format!("line {}: {e}", line.line_no))?;
        if tokens.is_empty() {
            continue;
        }
        let first = tokens[0].to_ascii_uppercase();
        if first == "$ORIGIN" {
            if tokens.len() != 2 {
                return Err(format!("line {}: $ORIGIN needs one value", line.line_no));
            }
            origin = normalize_name(&tokens[1]);
            ensure_in_zone(&origin, zone, line.line_no)?;
            continue;
        }
        if first == "$TTL" {
            if tokens.len() != 2 {
                return Err(format!("line {}: $TTL needs one value", line.line_no));
            }
            default_ttl = parse_ttl(&tokens[1]);
            continue;
        }
        if first.starts_with('$') {
            return Err(format!(
                "line {}: unsupported directive {first}",
                line.line_no
            ));
        }

        let mut idx = 0usize;
        let owner = if line.leading_space || is_ttl(&tokens[0]) || is_class(&tokens[0]) {
            previous_owner.clone()
        } else if is_rr_type(&tokens[0]) {
            previous_owner.clone()
        } else {
            idx = 1;
            tokens[0].clone()
        };
        let owner = owner_name(&owner, &origin);
        ensure_in_zone(&owner, zone, line.line_no)?;
        previous_owner = owner.clone();

        let mut ttl = default_ttl;
        while idx < tokens.len() {
            if is_ttl(&tokens[idx]) {
                ttl = parse_ttl(&tokens[idx]);
                idx += 1;
            } else if is_class(&tokens[idx]) {
                idx += 1;
            } else {
                break;
            }
        }
        if idx >= tokens.len() {
            return Err(format!("line {}: missing record type", line.line_no));
        }

        let rtype = tokens[idx].to_ascii_uppercase();
        idx += 1;
        if rtype == "SOA" {
            continue;
        }
        if !is_editable_type(&rtype) {
            return Err(format!(
                "line {}: unsupported record type {rtype}",
                line.line_no
            ));
        }
        if idx >= tokens.len() {
            return Err(format!("line {}: missing value for {rtype}", line.line_no));
        }
        let raw_value = tokens[idx..].join(" ");
        let value = normalize_record_value(&rtype, &raw_value, &origin)
            .map_err(|e| format!("line {}: {e}", line.line_no))?;
        records.push(ParsedRecord {
            name: owner,
            rtype,
            value,
            ttl,
        });
    }

    Ok(records)
}

/// Render a BIND-compatible zone file from stored records.
pub fn render_zone_file(
    zone: &Zone,
    records: &[Record],
    primary_ns: &str,
    hostmaster: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("$ORIGIN {}.\n", zone.name));
    out.push_str("$TTL 300\n");
    out.push_str(&format!(
        "@ 300 IN SOA {}. {}. {} {} {} {} {}\n",
        normalize_name(primary_ns),
        normalize_name(hostmaster),
        zone.serial.max(0),
        SOA_REFRESH,
        SOA_RETRY,
        SOA_EXPIRE,
        SOA_MINIMUM
    ));

    let mut rows = records.to_vec();
    rows.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.rtype.cmp(&b.rtype))
            .then_with(|| a.value.cmp(&b.value))
    });
    for r in rows {
        out.push_str(&format!(
            "{} {} IN {} {}\n",
            relative_owner(&r.name, &zone.name),
            r.ttl,
            r.rtype.to_ascii_uppercase(),
            render_rdata(&r.rtype, &r.value),
        ));
    }
    out
}

fn logical_lines(input: &str) -> Result<Vec<LogicalLine>, String> {
    let mut lines = Vec::new();
    let mut buf = String::new();
    let mut start_line = 0usize;
    let mut leading_space = false;
    let mut depth = 0i32;

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = strip_comment(raw);
        if stripped.trim().is_empty() {
            continue;
        }
        if buf.is_empty() {
            start_line = line_no;
            leading_space = stripped
                .chars()
                .next()
                .map(|c| c.is_whitespace())
                .unwrap_or(false);
        } else {
            buf.push(' ');
        }

        let cleaned = stripped.replace(['(', ')'], " ");
        depth += paren_delta(&stripped);
        buf.push_str(cleaned.trim());
        if depth < 0 {
            return Err(format!("line {line_no}: unmatched ')'"));
        }
        if depth == 0 {
            lines.push(LogicalLine {
                text: buf.trim().to_string(),
                leading_space,
                line_no: start_line,
            });
            buf.clear();
        }
    }

    if !buf.is_empty() {
        return Err(format!(
            "line {start_line}: unterminated parenthesized record"
        ));
    }
    Ok(lines)
}

fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            out.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            out.push(ch);
            continue;
        }
        if ch == ';' && !quoted {
            break;
        }
        out.push(ch);
    }
    out
}

fn paren_delta(line: &str) -> i32 {
    let mut quoted = false;
    let mut escaped = false;
    let mut delta = 0i32;
    for ch in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            continue;
        }
        match ch {
            '(' => delta += 1,
            ')' => delta -= 1,
            _ => {}
        }
    }
    delta
}

fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if ch.is_whitespace() && !quoted {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if quoted {
        return Err("unterminated quote".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn words(value: &str) -> Vec<String> {
    tokenize(value).unwrap_or_else(|_| value.split_whitespace().map(|s| s.to_string()).collect())
}

fn parse_u16(s: &str, err: &str) -> Result<u16, String> {
    s.parse::<u16>().map_err(|_| err.to_string())
}

fn name_rdata(value: &str, origin: &str) -> String {
    let value = value.trim();
    if value == "." {
        String::new()
    } else if value.ends_with('.') {
        normalize_name(value)
    } else {
        owner_name(value, origin)
    }
}

fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    t.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(t)
}

fn is_ttl(s: &str) -> bool {
    s.parse::<i64>().map(|n| n >= 0).unwrap_or(false)
}

fn is_class(s: &str) -> bool {
    s.eq_ignore_ascii_case("IN")
}

fn is_rr_type(s: &str) -> bool {
    let t = s.to_ascii_uppercase();
    t == "SOA" || is_editable_type(&t)
}

fn is_editable_type(s: &str) -> bool {
    matches!(
        s,
        "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT" | "SRV" | "CAA"
    )
}

fn ensure_in_zone(name: &str, zone: &Zone, line_no: usize) -> Result<(), String> {
    if name == zone.name || name.ends_with(&format!(".{}", zone.name)) {
        Ok(())
    } else {
        Err(format!(
            "line {line_no}: {name} is outside selected zone {}",
            zone.name
        ))
    }
}

fn display_name(name: &str) -> String {
    format!("{name}.")
}

fn relative_owner(name: &str, zone: &str) -> String {
    if name == zone {
        "@".to_string()
    } else {
        name.strip_suffix(&format!(".{zone}"))
            .unwrap_or(name)
            .to_string()
    }
}

fn render_rdata(rtype: &str, value: &str) -> String {
    match rtype.to_ascii_uppercase().as_str() {
        "NS" | "CNAME" => dotted(value),
        "MX" => {
            let mut parts = value.split_whitespace();
            let pref = parts.next().unwrap_or("10");
            let host = parts.next().unwrap_or("");
            format!("{pref} {}", dotted(host))
        }
        "TXT" => quote_text(value),
        "SRV" => {
            let mut parts = value.split_whitespace();
            let priority = parts.next().unwrap_or("0");
            let weight = parts.next().unwrap_or("0");
            let port = parts.next().unwrap_or("0");
            let target = parts.next().unwrap_or("");
            format!("{priority} {weight} {port} {}", dotted(target))
        }
        "CAA" => {
            let mut parts = value.splitn(3, ' ');
            let flags = parts.next().unwrap_or("0");
            let tag = parts.next().unwrap_or("issue");
            let caa_value = parts.next().unwrap_or("");
            format!("{flags} {tag} {}", quote_text(caa_value))
        }
        _ => value.to_string(),
    }
}

fn dotted(name: &str) -> String {
    if name.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", normalize_name(name))
    }
}

fn quote_text(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Zone {
        Zone {
            id: "z1".to_string(),
            name: "example.com".to_string(),
            serial: 42,
            created_at: 0,
        }
    }

    #[test]
    fn parses_bind_zone_records() {
        let parsed = parse_zone_file(
            &zone(),
            r#"
$ORIGIN example.com.
$TTL 600
@ IN SOA ns1.example.com. hostmaster.example.com. ( 42 7200 3600 1209600 300 )
@ IN A 192.0.2.10
www 120 IN CNAME @
_sip._tcp IN SRV 10 20 5060 sip
@ IN CAA 0 issue "letsencrypt.org"
"spf value" TXT "v=spf1 mx -all"
"#,
        )
        .unwrap();

        assert_eq!(parsed.len(), 5);
        assert!(parsed.iter().any(|r| {
            r.name == "_sip._tcp.example.com"
                && r.rtype == "SRV"
                && r.value == "10 20 5060 sip.example.com"
        }));
        assert!(parsed
            .iter()
            .any(|r| r.rtype == "CAA" && r.value == "0 issue letsencrypt.org"));
    }

    #[test]
    fn rejects_cname_conflicts_and_duplicates() {
        let records = vec![
            Record {
                id: "r1".to_string(),
                zone_id: "z".to_string(),
                name: "www.example.com".to_string(),
                rtype: "A".to_string(),
                value: "192.0.2.1".to_string(),
                ttl: 300,
                created_at: 0,
            },
            Record {
                id: "r2".to_string(),
                zone_id: "z".to_string(),
                name: "www.example.com".to_string(),
                rtype: "CNAME".to_string(),
                value: "example.com".to_string(),
                ttl: 300,
                created_at: 0,
            },
        ];
        assert!(validate_record_set(&records).is_err());
    }
}
