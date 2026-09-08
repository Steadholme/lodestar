//! Authority-free HTML rendering for the Lodestar zone console.
//!
//! The controller owns authentication, CSRF, storage, resolver queries, mutations, audit, and
//! responses. This module receives only already-loaded data and returns escaped HTML strings.

use crate::dns::{type_to_str, Lookup};
use crate::handlers::{esc, fmt_date};
use crate::store::{Record, Zone, ZoneHistory};

pub(super) enum TestOutcome {
    Empty,
    Resolved {
        qname: String,
        qtype: u16,
        lookup: Lookup,
    },
    UnknownType,
}

/// Render one zone card: header + records table + add/import forms + recent history.
pub(super) fn render_zone(
    zone: &Zone,
    records: &[Record],
    history: &[ZoneHistory],
    csrf: &str,
    editable_types: &[&str],
) -> String {
    let mut rows = String::new();
    if records.is_empty() {
        rows.push_str(r#"<tr><td colspan="5" class="muted">No records.</td></tr>"#);
    }
    for r in records {
        rows.push_str(&format!(
            r#"<tr>
  <td class="mono">{name}</td>
  <td><span class="rtype" data-type="{rtype}">{rtype}</span></td>
  <td class="mono">{ttl}</td>
  <td class="mono value">{value}</td>
  <td class="row-action">
    <form class="inline-form" method="post" action="/api/records/delete" onsubmit="return confirm('Delete this record?');">
      <input type="hidden" name="id" value="{id}">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button class="btn btn-danger btn-sm" type="submit">Delete</button>
    </form>
  </td>
</tr>"#,
            name = esc(&r.name),
            rtype = esc(&r.rtype),
            ttl = r.ttl,
            value = esc(&r.value),
            id = esc(&r.id),
            csrf = esc(csrf),
        ));
    }

    let type_options = editable_types
        .iter()
        .map(|t| format!(r#"<option value="{t}">{t}</option>"#))
        .collect::<String>();

    let history_block = render_history(history);

    format!(
        r#"<section class="card zone">
  <div class="card__body">
    <div class="zone__head">
      <h2 class="zone__name mono">{name}</h2>
      <div class="zone-tools">
        <span class="zone__serial">serial {serial}</span>
        <a class="btn btn-secondary btn-sm" href="/api/zones/export?zone_id={zone_id}">Export</a>
      </div>
    </div>
    <div class="rec-wrap">
      <table class="rec-table">
        <thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Value</th><th></th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    <form class="add-form" method="post" action="/api/records">
      <input type="hidden" name="zone_id" value="{zone_id}">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input class="mono" type="text" name="name" placeholder="name (@ for apex, * for wildcard)" maxlength="255">
      <select name="rtype">{type_options}</select>
      <input class="mono" type="text" name="value" placeholder="value (e.g. 159.195.136.226)" maxlength="2048" required>
      <input class="mono ttl" type="text" name="ttl" placeholder="TTL" value="300">
      <button class="btn btn-primary" type="submit">Add record</button>
    </form>
    <form class="import-form" method="post" action="/api/zones/import">
      <input type="hidden" name="zone_id" value="{zone_id}">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <textarea class="mono" name="zone_file" rows="8" placeholder="$ORIGIN {name}.&#10;@ 300 IN A 203.0.113.10&#10;www 300 IN CNAME @"></textarea>
      <button class="btn btn-secondary" type="submit">Import zone file</button>
    </form>
    {history_block}
  </div>
</section>"#,
        name = esc(&zone.name),
        serial = zone.serial,
        rows = rows,
        zone_id = esc(&zone.id),
        csrf = esc(csrf),
        type_options = type_options,
        history_block = history_block,
    )
}

pub(super) fn render_history(history: &[ZoneHistory]) -> String {
    let mut rows = String::new();
    if history.is_empty() {
        rows.push_str(r#"<tr><td colspan="4" class="muted">No local changes yet.</td></tr>"#);
    }
    for h in history {
        rows.push_str(&format!(
            r#"<tr>
  <td>{when}</td>
  <td class="mono">{actor}</td>
  <td>{action}</td>
  <td>{detail}</td>
</tr>"#,
            when = esc(&fmt_date(h.created_at)),
            actor = esc(&h.actor),
            action = esc(&h.action),
            detail = esc(&h.detail),
        ));
    }
    format!(
        r#"<div class="history">
  <h3>Change history</h3>
  <div class="rec-wrap">
    <table class="rec-table history-table">
      <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"#,
        rows = rows,
    )
}

pub(super) fn render_test_card(name: &str, qtype_str: &str, outcome: &TestOutcome) -> String {
    let type_options = [
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "SOA", "ANY",
    ]
    .iter()
    .map(|t| {
        let sel = if *t == qtype_str { " selected" } else { "" };
        format!(r#"<option value="{t}"{sel}>{t}</option>"#)
    })
    .collect::<String>();

    let result = match outcome {
        TestOutcome::Empty => String::new(),
        TestOutcome::Resolved {
            qname,
            qtype,
            lookup,
        } => render_lookup(qname, *qtype, lookup),
        TestOutcome::UnknownType => format!(
            r#"<div class="answer answer--err">Unknown query type: {}</div>"#,
            esc(qtype_str)
        ),
    };

    format!(
        r#"<section class="card test">
  <div class="card__body">
    <h2 class="test__title">Test query</h2>
    <p class="sub">Resolve a name against the in-process authoritative resolver (the same answers served on the wire).</p>
    <form class="test-form" method="get" action="/">
      <input class="mono" type="text" name="q" placeholder="name (e.g. id.w33d.xyz)" value="{name}" maxlength="255">
      <select name="qtype">{type_options}</select>
      <button class="btn btn-secondary" type="submit">Resolve</button>
    </form>
    {result}
  </div>
</section>"#,
        name = esc(name),
        type_options = type_options,
        result = result,
    )
}

/// Format a [`Lookup`] as a dig-style answer block.
pub(super) fn render_lookup(qname: &str, qtype: u16, lk: &Lookup) -> String {
    let mut lines = String::new();
    for rr in &lk.answers {
        lines.push_str(&format!(
            "{:<28} {:>6}  {:<6} {}\n",
            format!("{}.", rr.name),
            rr.ttl,
            type_to_str(rr.data.type_code()),
            rr.data.to_text(),
        ));
    }
    let answer_section = if lk.answers.is_empty() {
        "; (no answer records)\n".to_string()
    } else {
        lines
    };
    let mut authority = String::new();
    for rr in &lk.authority {
        authority.push_str(&format!(
            "; AUTHORITY  {:<24} {:>6}  {:<6} {}\n",
            format!("{}.", rr.name),
            rr.ttl,
            type_to_str(rr.data.type_code()),
            rr.data.to_text(),
        ));
    }
    let aa = if lk.aa { " aa" } else { "" };
    format!(
        r#"<pre class="answer">; QUESTION  {qname}. {qtype}
; status: {rcode}{aa}, {ancount} answer(s)
{answers}{authority}</pre>"#,
        qname = esc(qname),
        qtype = esc(&type_to_str(qtype)),
        rcode = rcode_str(lk.rcode),
        aa = aa,
        ancount = lk.answers.len(),
        answers = esc(&answer_section),
        authority = esc(&authority),
    )
}

pub(super) fn rcode_str(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::dns::{RData, Rr, TYPE_A};
    use crate::handlers::zones::EDITABLE_TYPES;

    fn fingerprint(value: &str) -> u64 {
        value
            .as_bytes()
            .iter()
            .fold(0xcbf29ce484222325, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
            })
    }

    fn assert_golden(value: &str, expected_len: usize, expected_hash: u64) {
        assert_eq!(value.len(), expected_len, "whole-output length changed");
        assert_eq!(
            fingerprint(value),
            expected_hash,
            "whole-output fingerprint changed"
        );
    }

    fn zone() -> Zone {
        Zone {
            id: "zone-1".to_string(),
            name: "example.test".to_string(),
            serial: 42,
            created_at: 0,
        }
    }

    fn records() -> Vec<Record> {
        vec![
            Record {
                id: "rec-a".to_string(),
                zone_id: "zone-1".to_string(),
                name: "example.test".to_string(),
                rtype: "A".to_string(),
                value: "203.0.113.10".to_string(),
                ttl: 300,
                created_at: 0,
            },
            Record {
                id: "rec-mx".to_string(),
                zone_id: "zone-1".to_string(),
                name: "example.test".to_string(),
                rtype: "MX".to_string(),
                value: "10 mail.example.test".to_string(),
                ttl: 600,
                created_at: 0,
            },
        ]
    }

    fn history() -> Vec<ZoneHistory> {
        vec![ZoneHistory {
            id: "hist-1".to_string(),
            zone_id: "zone-1".to_string(),
            actor: "alice@example.test".to_string(),
            action: "add".to_string(),
            detail: "add A example.test -> 203.0.113.10".to_string(),
            created_at: 0,
        }]
    }

    fn answer_lookup() -> Lookup {
        Lookup {
            rcode: 0,
            aa: true,
            answers: vec![Rr {
                name: "example.test".to_string(),
                ttl: 300,
                data: RData::A(Ipv4Addr::new(203, 0, 113, 10)),
            }],
            authority: Vec::new(),
        }
    }

    #[test]
    fn render_zone_representative_golden() {
        let output = render_zone(&zone(), &records(), &history(), "csrf-1", EDITABLE_TYPES);
        assert_golden(&output, 3315, 0x718ce706884edef5);
        assert_eq!(output.matches("<tr>").count(), 5);
        assert!(output.contains("serial 42"));
    }

    #[test]
    fn render_zone_empty_records_golden() {
        let output = render_zone(&zone(), &[], &[], "csrf-empty", EDITABLE_TYPES);
        assert_golden(&output, 2263, 0x12f7c83d9c1d4ded);
        assert!(output.contains(r#"<td colspan="5" class="muted">No records.</td>"#));
    }

    #[test]
    fn render_zone_escaping_golden() {
        let hostile_zone = Zone {
            id: "zone<&\"'".to_string(),
            name: "name<&\"'".to_string(),
            serial: 7,
            created_at: 0,
        };
        let hostile_record = Record {
            id: "rec<&\"'".to_string(),
            zone_id: hostile_zone.id.clone(),
            name: "owner<&\"'".to_string(),
            rtype: "TXT<&\"'".to_string(),
            value: "value<&\"'".to_string(),
            ttl: 30,
            created_at: 0,
        };
        let hostile_history = ZoneHistory {
            id: "hist".to_string(),
            zone_id: hostile_zone.id.clone(),
            actor: "actor<&\"'".to_string(),
            action: "action<&\"'".to_string(),
            detail: "detail<&\"'".to_string(),
            created_at: 0,
        };
        let output = render_zone(
            &hostile_zone,
            &[hostile_record],
            &[hostile_history],
            "csrf<&\"'",
            EDITABLE_TYPES,
        );
        assert_golden(&output, 3020, 0xe6b76af3843e0a82);
        assert!(output.contains("name&lt;&amp;&quot;&#x27;"));
        assert!(!output.contains("owner<&"));
    }

    #[test]
    fn render_zone_editable_types_golden() {
        let output = render_zone(&zone(), &[], &[], "options", EDITABLE_TYPES);
        assert_golden(&output, 2257, 0x78b2515d7ccfa02f);
        let expected = r#"<select name="rtype"><option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option><option value="MX">MX</option><option value="NS">NS</option><option value="TXT">TXT</option><option value="SRV">SRV</option><option value="CAA">CAA</option></select>"#;
        assert!(output.contains(expected));
    }

    #[test]
    fn render_zone_csrf_forms_golden() {
        let records = records();
        let output = render_zone(
            &zone(),
            std::slice::from_ref(&records[0]),
            &[],
            "csrf<&\"'",
            EDITABLE_TYPES,
        );
        assert_golden(&output, 2772, 0x0e2473f782bc374b);
        assert_eq!(output.matches(r#"name="csrf_token""#).count(), 3);
        assert_eq!(output.matches("csrf&lt;&amp;&quot;&#x27;").count(), 3);
        assert!(output.contains("return confirm('Delete this record?');"));
    }

    #[test]
    fn render_history_representative_golden() {
        let output = render_history(&history());
        assert_golden(&output, 395, 0x2c8ad5f7fc941de3);
        assert!(output.contains("Jan 1, 1970"));
    }

    #[test]
    fn render_history_empty_golden() {
        let output = render_history(&[]);
        assert_golden(&output, 320, 0xdea79e02c1e410d8);
        assert!(output.contains("No local changes yet."));
    }

    #[test]
    fn render_history_escaping_golden() {
        let hostile = ZoneHistory {
            id: "hist".to_string(),
            zone_id: "zone".to_string(),
            actor: "actor<&\"'".to_string(),
            action: "action<&\"'".to_string(),
            detail: "detail<&\"'".to_string(),
            created_at: 0,
        };
        let output = render_history(&[hostile]);
        assert_golden(&output, 417, 0x006e4ff347a78fe1);
        assert!(output.contains("actor&lt;&amp;&quot;&#x27;"));
    }

    #[test]
    fn render_lookup_answer_golden() {
        let output = render_lookup("example.test", TYPE_A, &answer_lookup());
        assert_golden(&output, 145, 0x5755270d03fc5853);
        assert!(output.contains("status: NOERROR aa, 1 answer(s)"));
    }

    #[test]
    fn render_lookup_negative_responses_golden() {
        let nodata = Lookup {
            rcode: 0,
            aa: true,
            ..Default::default()
        };
        let nxdomain = Lookup {
            rcode: 3,
            aa: true,
            ..Default::default()
        };
        let output = format!(
            "{}\n---\n{}",
            render_lookup("nodata.example.test", TYPE_A, &nodata),
            render_lookup("missing.example.test", TYPE_A, &nxdomain)
        );
        assert_golden(&output, 241, 0x8faa2a6f6eff8718);
        assert_eq!(rcode_str(0), "NOERROR");
        assert_eq!(rcode_str(3), "NXDOMAIN");
        assert_eq!(rcode_str(5), "REFUSED");
    }

    #[test]
    fn render_test_card_empty_golden() {
        let output = render_test_card("", "A", &TestOutcome::Empty);
        assert_golden(&output, 857, 0x67be56518852ce89);
        assert!(output.contains(r#"<option value="A" selected>A</option>"#));
    }

    #[test]
    fn render_test_card_unknown_type_golden() {
        let output = render_test_card("bad<&\"'", "ZZZ<&\"'", &TestOutcome::UnknownType);
        assert_golden(&output, 954, 0x397177cc13d4ee38);
        assert!(output.contains("Unknown query type: ZZZ&lt;&amp;&quot;&#x27;"));
    }

    #[test]
    fn render_test_card_resolved_golden() {
        let lookup = Lookup {
            rcode: 0,
            aa: true,
            answers: vec![Rr {
                name: "w33d.xyz".to_string(),
                ttl: 300,
                data: RData::A(Ipv4Addr::new(159, 195, 136, 226)),
            }],
            authority: Vec::new(),
        };
        let output = render_test_card(
            "w33d.xyz",
            "A",
            &TestOutcome::Resolved {
                qname: "w33d.xyz".to_string(),
                qtype: TYPE_A,
                lookup,
            },
        );
        assert_golden(&output, 1009, 0xf25d6d9653f9bd04);
        let start = output.find(r#"<pre class="answer">"#).unwrap();
        let end = output[start..].find("</pre>").unwrap() + start + 6;
        assert_golden(&output[start..end], 144, 0xa217768838ef080c);
        assert!(output.contains("159.195.136.226"));
    }
}
