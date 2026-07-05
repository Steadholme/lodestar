//! Zone editor + record add/delete/import/export flow + JSON list + the in-process test-query box.
//!
//! All routes are mounted behind the gateway `auth=sso` route: the operator identity is taken from
//! the injected `X-Auth-Subject` / `X-Auth-Email` (never a client field), and every state-changing
//! POST is double-submit CSRF protected. Every record edit bumps the zone serial, mirrors a
//! `dns.zone.edit` event to Watchtower, and triggers an immediate resolver reload so the change is
//! served at once.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::auth;
use crate::dns::{type_from_str, type_to_str};
use crate::error::AppError;
use crate::handlers::{app_css, esc, fmt_date, topbar};
use crate::store::{Record, Zone, ZoneHistory};
use crate::{new_id, now_secs, reload_now, zonefile, AppState};

const ZONES_HTML: &str = include_str!("../../templates/zones.html");

/// Record types an operator may store. SOA is excluded (it is synthesized per-zone); ANY is a query
/// type only.
const EDITABLE_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA"];

/// Optional test-query params on `GET /` (`?q=name&qtype=A`).
#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub qtype: Option<String>,
}

/// `POST /api/records` body — add a record. Identity is NEVER taken from the form.
#[derive(Debug, Deserialize)]
pub struct AddForm {
    #[serde(default)]
    pub zone_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub rtype: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub ttl: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /api/records/delete` body — delete a record by id.
#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /api/zones/export?zone_id=...` query.
#[derive(Debug, Deserialize)]
pub struct ZoneQuery {
    #[serde(default)]
    pub zone_id: String,
}

/// `POST /api/zones/import` body — replace a zone from a BIND zone file.
#[derive(Debug, Deserialize)]
pub struct ImportForm {
    #[serde(default)]
    pub zone_id: String,
    #[serde(default)]
    pub zone_file: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// One record in the `GET /api/records` JSON list.
#[derive(Debug, Serialize)]
pub struct RecordJson {
    pub id: String,
    pub zone_id: String,
    pub zone: String,
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: i64,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// GET / — the zone editor
// ---------------------------------------------------------------------------

/// `GET /` — list zones + records, the add forms, and the test-query box.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IndexQuery>,
) -> Response {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let zones = state.store.list_zones().await;
    let mut zone_blocks = String::new();
    let mut total_records = 0usize;
    if zones.is_empty() {
        zone_blocks.push_str(
            r#"<div class="empty-state"><h2>No zones yet</h2><p>The default zone is seeded on first run. If you see this, the store is empty.</p></div>"#,
        );
    }
    for z in &zones {
        let records = state.store.list_records(&z.id).await;
        let history = state.store.list_history(&z.id).await;
        total_records += records.len();
        zone_blocks.push_str(&render_zone(z, &records, &history, &csrf));
    }

    let status = format!(
        "{zones} zone(s), {records} record(s) loaded · serving authoritative DNS on {dns}",
        zones = zones.len(),
        records = total_records,
        dns = state.config.dns_addr,
    );

    let test = render_test(&state, &query);

    let body = ZONES_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("Lodestar", &email))
        .replace("{{STATUS}}", &esc(&status))
        .replace("{{TEST}}", &test)
        .replace("{{ZONES}}", &zone_blocks);

    html_with_cookie(body, set_cookie)
}

/// Render one zone card: header + records table + add/import forms + recent history.
fn render_zone(zone: &Zone, records: &[Record], history: &[ZoneHistory], csrf: &str) -> String {
    let mut rows = String::new();
    if records.is_empty() {
        rows.push_str(r#"<tr><td colspan="5" class="muted">No records.</td></tr>"#);
    }
    for r in records {
        rows.push_str(&format!(
            r#"<tr>
  <td class="mono">{name}</td>
  <td><span class="rtype">{rtype}</span></td>
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

    let type_options = EDITABLE_TYPES
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

fn render_history(history: &[ZoneHistory]) -> String {
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

/// Render the test-query card + (when a name was submitted) the resolved answer.
fn render_test(state: &AppState, query: &IndexQuery) -> String {
    let name = query.q.as_deref().unwrap_or("").trim().to_string();
    let qtype_str = query
        .qtype
        .as_deref()
        .unwrap_or("A")
        .trim()
        .to_ascii_uppercase();

    let type_options = [
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "SOA", "ANY",
    ]
    .iter()
    .map(|t| {
        let sel = if *t == qtype_str { " selected" } else { "" };
        format!(r#"<option value="{t}"{sel}>{t}</option>"#)
    })
    .collect::<String>();

    let mut result = String::new();
    if !name.is_empty() {
        let normalized = crate::config::normalize_name(&name);
        match type_from_str(&qtype_str) {
            Some(qtype) => {
                let lk = state.resolver.lookup(&normalized, qtype);
                result = render_lookup(&normalized, qtype, &lk);
            }
            None => {
                result = format!(
                    r#"<div class="answer answer--err">Unknown query type: {}</div>"#,
                    esc(&qtype_str)
                );
            }
        }
    }

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
        name = esc(&name),
        type_options = type_options,
        result = result,
    )
}

/// Format a [`Lookup`] as a dig-style answer block.
fn render_lookup(qname: &str, qtype: u16, lk: &crate::dns::Lookup) -> String {
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

fn rcode_str(rcode: u8) -> &'static str {
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

// ---------------------------------------------------------------------------
// GET /api/records — JSON list
// ---------------------------------------------------------------------------

/// `GET /api/records` — every record across every zone, as JSON.
pub async fn api_records(State(state): State<AppState>) -> Json<Vec<RecordJson>> {
    let zones = state.store.list_zones().await;
    let names: HashMap<String, String> = zones.into_iter().map(|z| (z.id, z.name)).collect();
    let mut out: Vec<RecordJson> = state
        .store
        .all_records()
        .await
        .into_iter()
        .map(|r| RecordJson {
            zone: names.get(&r.zone_id).cloned().unwrap_or_default(),
            id: r.id,
            zone_id: r.zone_id,
            name: r.name,
            rtype: r.rtype,
            value: r.value,
            ttl: r.ttl,
            created_at: r.created_at,
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.rtype.cmp(&b.rtype)));
    Json(out)
}

// ---------------------------------------------------------------------------
// GET /api/zones/export — BIND zone file
// ---------------------------------------------------------------------------

/// `GET /api/zones/export` — export one zone as a BIND-compatible zone file.
pub async fn export_zone(
    State(state): State<AppState>,
    Query(query): Query<ZoneQuery>,
) -> Result<Response, AppError> {
    let zone = state
        .store
        .get_zone(&query.zone_id)
        .await
        .ok_or_else(|| AppError::NotFound("no such zone".to_string()))?;
    let records = state.store.list_records(&zone.id).await;
    let body = zonefile::render_zone_file(
        &zone,
        &records,
        &state.config.primary_ns,
        &state.config.hostmaster,
    );
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    let filename = zone.name.replace('"', "");
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}.zone\"")) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// POST /api/zones/import — replace zone records from BIND text
// ---------------------------------------------------------------------------

/// `POST /api/zones/import` — replace one zone from a BIND zone file, bump serial, reload, audit.
pub async fn import_zone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ImportForm>,
) -> Result<Response, AppError> {
    let (_sub, _email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let zone = state
        .store
        .get_zone(&form.zone_id)
        .await
        .ok_or_else(|| AppError::NotFound("no such zone".to_string()))?;

    let parsed =
        zonefile::parse_zone_file(&zone, &form.zone_file).map_err(AppError::InvalidRequest)?;
    if parsed.is_empty() {
        return Err(AppError::InvalidRequest(
            "zone file contains no supported records".to_string(),
        ));
    }

    let now = now_secs();
    let records: Vec<Record> = parsed
        .into_iter()
        .map(|r| Record {
            id: new_id("rec"),
            zone_id: zone.id.clone(),
            name: r.name,
            rtype: r.rtype,
            value: r.value,
            ttl: r.ttl,
            created_at: now,
        })
        .collect();
    zonefile::validate_record_set(&records).map_err(AppError::Conflict)?;

    state.store.replace_records(&zone.id, &records).await?;
    bump_serial(&state, &zone).await;

    let detail = format!("import BIND zone file ({} records)", records.len());
    record_history(&state, &headers, &zone, "import", &detail).await;
    state.audit.emit(AuditEvent::notice(
        "dns.zone.edit",
        &auth::actor(&headers),
        &zone.name,
        &detail,
    ));
    reload_now(&state).await;
    tracing::info!(zone = %zone.name, records = records.len(), "zone file imported");

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// POST /api/records — add
// ---------------------------------------------------------------------------

/// `POST /api/records` — add a record to a zone, bump the serial, reload the resolver, audit.
pub async fn add_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AddForm>,
) -> Result<Response, AppError> {
    let (_sub, _email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let zone = state
        .store
        .get_zone(&form.zone_id)
        .await
        .ok_or_else(|| AppError::NotFound("no such zone".to_string()))?;

    // Resolve the record type.
    let rtype = form.rtype.trim().to_ascii_uppercase();
    if !EDITABLE_TYPES.contains(&rtype.as_str()) {
        return Err(AppError::InvalidRequest(format!(
            "unsupported record type: {rtype}"
        )));
    }
    let owner = zonefile::owner_name(&form.name, &zone.name);
    let value = zonefile::normalize_record_value(&rtype, &form.value, &zone.name)
        .map_err(AppError::InvalidRequest)?;
    let ttl: i64 = zonefile::parse_ttl(&form.ttl);

    let record = Record {
        id: new_id("rec"),
        zone_id: zone.id.clone(),
        name: owner.clone(),
        rtype: rtype.clone(),
        value: value.clone(),
        ttl,
        created_at: now_secs(),
    };
    let existing = state.store.list_records(&zone.id).await;
    zonefile::validate_new_record(&existing, &record).map_err(AppError::Conflict)?;
    state.store.create_record(&record).await?;
    bump_serial(&state, &zone).await;

    let detail = format!("add {rtype} {owner} -> {value}");
    record_history(&state, &headers, &zone, "add", &detail).await;
    state.audit.emit(AuditEvent::notice(
        "dns.zone.edit",
        &auth::actor(&headers),
        &zone.name,
        &detail,
    ));
    reload_now(&state).await;
    tracing::info!(zone = %zone.name, name = %owner, rtype = %rtype, "record added");

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// POST /api/records/delete — delete
// ---------------------------------------------------------------------------

/// `POST /api/records/delete` — delete a record by id, bump the serial, reload, audit.
pub async fn delete_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let (_sub, _email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let record = state
        .store
        .get_record(&form.id)
        .await
        .ok_or_else(|| AppError::NotFound("no such record".to_string()))?;
    let zone = state.store.get_zone(&record.zone_id).await;

    state.store.delete_record(&record.id).await?;
    if let Some(z) = &zone {
        bump_serial(&state, z).await;
    }

    let zone_name = zone.as_ref().map(|z| z.name.clone()).unwrap_or_default();
    let detail = format!(
        "delete {} {} -> {}",
        record.rtype, record.name, record.value
    );
    if let Some(z) = &zone {
        record_history(&state, &headers, z, "delete", &detail).await;
    }
    state.audit.emit(AuditEvent::warning(
        "dns.zone.edit",
        &auth::actor(&headers),
        &zone_name,
        &detail,
    ));
    reload_now(&state).await;
    tracing::info!(name = %record.name, rtype = %record.rtype, "record deleted");

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Bump the zone serial: strictly increasing, preferring the current epoch so it keeps climbing
/// across restarts. Logged-and-ignored on failure (the record write already succeeded).
async fn bump_serial(state: &AppState, zone: &Zone) {
    let next = (zone.serial + 1).max(now_secs());
    if let Err(e) = state.store.set_serial(&zone.id, next).await {
        tracing::warn!(error = %e, zone = %zone.name, "serial bump failed");
    }
}

/// Append a local history row; failures are logged but never fail the DNS edit already applied.
async fn record_history(
    state: &AppState,
    headers: &HeaderMap,
    zone: &Zone,
    action: &str,
    detail: &str,
) {
    let entry = ZoneHistory {
        id: new_id("hist"),
        zone_id: zone.id.clone(),
        actor: auth::actor(headers),
        action: action.to_string(),
        detail: detail.to_string(),
        created_at: now_secs(),
    };
    if let Err(e) = state.store.create_history(&entry).await {
        tracing::warn!(error = %e, zone = %zone.name, "history write failed");
    }
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).expect("valid location"),
        )],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}
