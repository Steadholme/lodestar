//! End-to-end HTTP flow over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate. Covers:
//! health, the seeded zone editor, the JSON list, the SSO/CSRF guards on add/delete, a real
//! add->resolve->delete cycle, and the test-query box (exact + wildcard).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use lodestar::{app, build_dev_state, reload_now, seed, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

async fn seeded_state() -> AppState {
    let state = build_dev_state();
    seed::seed_if_empty(state.store.as_ref(), &state.config).await;
    reload_now(&state).await;
    state
}

#[tokio::test]
async fn full_zone_flow_in_memory() {
    let state = seeded_state().await;

    // --- health ------------------------------------------------------------
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    // --- the seeded zone shows up ------------------------------------------
    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("w33d.xyz"), "seeded zone listed");
    assert!(body.contains("159.195.136.226"), "seeded apex A shown");

    // --- GET / mints a CSRF cookie -----------------------------------------
    let resp = app(state.clone()).oneshot(get("/")).await.unwrap();
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(set_cookie.contains("__Host-csrf="), "GET / mints CSRF cookie");

    // --- JSON list ---------------------------------------------------------
    let (status, body) = call(&state, get("/api/records")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"v=spf1 mx -all\""), "TXT SPF in JSON list");

    // --- the zone id we will edit ------------------------------------------
    let zone_id = state.store.list_zones().await[0].id.clone();

    // --- POST /api/records without identity -> 401 -------------------------
    let body = form(&[
        ("zone_id", zone_id.as_str()),
        ("name", "www"),
        ("rtype", "A"),
        ("value", "10.1.2.3"),
        ("ttl", "300"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post_csrf("/api/records", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST with bad CSRF -> 401 -----------------------------------------
    let body = form(&[
        ("zone_id", zone_id.as_str()),
        ("name", "www"),
        ("rtype", "A"),
        ("value", "10.1.2.3"),
        ("csrf_token", "WRONG"),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/api/records", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- add a real record (relative name -> www.w33d.xyz) -----------------
    let body = form(&[
        ("zone_id", zone_id.as_str()),
        ("name", "www"),
        ("rtype", "A"),
        ("value", "10.1.2.3"),
        ("ttl", "120"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/api/records", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "add -> redirect");

    // serial bumped past the seed value of 1
    assert!(state.store.list_zones().await[0].serial > 1, "serial bumped");

    // --- the test-query box resolves the new record exactly ----------------
    let (status, body) = call(&state, get("/?q=www.w33d.xyz&qtype=A")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("10.1.2.3"), "exact resolve hits the new record");
    assert!(body.contains("NOERROR"), "status line shown");

    // --- the wildcard answers an unknown subdomain -------------------------
    let (_, body) = call(&state, get("/?q=whatever.w33d.xyz&qtype=A")).await;
    assert!(
        body.contains("159.195.136.226"),
        "wildcard *.w33d.xyz resolves unknown names"
    );

    // --- a bad value is rejected at the form -------------------------------
    let body = form(&[
        ("zone_id", zone_id.as_str()),
        ("name", "broken"),
        ("rtype", "A"),
        ("value", "not-an-ip"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/api/records", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "invalid A value rejected");

    // --- delete the www record ---------------------------------------------
    let rec = state
        .store
        .list_records(&zone_id)
        .await
        .into_iter()
        .find(|r| r.name == "www.w33d.xyz")
        .expect("www record exists");
    let body = form(&[("id", rec.id.as_str()), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf("/api/records/delete", &body, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "delete -> redirect");

    // gone from the resolver: www now falls through to the wildcard (seed IP, not 10.1.2.3)
    let (_, body) = call(&state, get("/?q=www.w33d.xyz&qtype=A")).await;
    assert!(!body.contains("10.1.2.3"), "deleted record no longer resolves");
    assert!(body.contains("159.195.136.226"), "falls through to wildcard");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b.header("x-auth-subject", sub).header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal application/x-www-form-urlencoded value encoder.
fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
