//! Lodestar — authoritative DNS server + zone admin for the Steadholme stack.
//!
//! Two surfaces, one binary:
//! - The ADMIN DASHBOARD (`app`) is an axum service behind a Sluice `auth=sso` route at the
//!   subdomain ROOT (`dns.w33d.xyz`): list zones + records, add/delete a record (double-submit
//!   CSRF), and a "test query" box resolving a name against the in-process resolver. Lodestar is
//!   internal-only and trusts the gateway-injected `X-Auth-*` identity headers.
//! - The DNS SERVER ([`dns::server`]) answers authoritative queries from the DB over UDP + TCP on
//!   the ALT port `:5353` (NEVER `:53` — see [`config`]). It serves a periodically-reloaded
//!   in-memory snapshot, so changes made in the dashboard take effect promptly.
//!
//! Storage is a portable async `Store` (in-memory default + a standard-SQL PgStore). Notable zone
//! edits are mirrored to Watchtower via the non-blocking [`audit`] emitter.
//!
//! Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified):
//! - `GET  /healthz`             — liveness (public; container HEALTHCHECK)
//! - `GET  /`                    — zone editor: zones + records + the test-query box
//! - `GET  /api/records`         — JSON list of all records
//! - `POST /api/records`         — add a record (CSRF) -> 303 `/`
//! - `POST /api/records/delete`  — delete a record by id (CSRF) -> 303 `/`
//! - `GET  /api/zones/export`    — export one zone as a BIND zone file
//! - `POST /api/zones/import`    — replace one zone from a BIND zone file (CSRF) -> 303 `/`

pub mod audit;
pub mod auth;
pub mod config;
pub mod dns;
pub mod error;
pub mod handlers;
pub mod seed;
pub mod store;
pub mod zonefile;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::dns::resolver::Resolver;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink/resolver).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub resolver: Resolver,
    pub audit: AuditSink,
}

/// Build the router wiring the admin-dashboard endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route(handlers::APP_CSS_PATH, get(handlers::app_css_asset))
        .route("/", get(handlers::zones::index))
        .route("/api/zones/export", get(handlers::zones::export_zone))
        .route("/api/zones/import", post(handlers::zones::import_zone))
        .route(
            "/api/records",
            get(handlers::zones::api_records).post(handlers::zones::add_record),
        )
        .route("/api/records/delete", post(handlers::zones::delete_record))
        .with_state(state)
}

/// Construct dev state: dev [`Config`] + an empty [`InMemoryStore`], an empty resolver, and a
/// disabled audit sink. Used by the integration tests (no database, no network).
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        resolver: Resolver::new(),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment, seed the default zone on first run, and load the
/// resolver snapshot. The store is selected by `LODESTAR_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required (seeded in-process).
/// - `postgres`: connect `LODESTAR_DATABASE_URL` (db `lodestar`), run the idempotent migration,
///   wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`. Returns
/// an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("LODESTAR_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("LODESTAR_DATABASE_URL")
                .or_else(|| env_nonempty("DATABASE_URL"))
                .ok_or_else(|| {
                    "LODESTAR_STORE=postgres requires LODESTAR_DATABASE_URL".to_string()
                })?;
            tracing::info!("LODESTAR_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => {
            return Err(format!(
                "unknown LODESTAR_STORE={other} (use memory|postgres)"
            ))
        }
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    // First-run seed (idempotent: only when empty), then load the resolver snapshot.
    seed::seed_if_empty(store.as_ref(), &config).await;
    let resolver = Resolver::new();
    resolver.reload(store.as_ref(), &config).await;

    Ok(AppState {
        config: Arc::new(config),
        store,
        resolver,
        audit,
    })
}

/// Spawn the long-running background tasks: the DNS UDP+TCP listeners and the periodic resolver
/// reload. Binding errors on the DNS listener are returned so `main` can fail loudly; the reload
/// loop runs for the life of the process. Call once after [`build_state_from_env`].
pub async fn start_background(state: &AppState) -> Result<(), String> {
    dns::server::serve(state.resolver.clone(), &state.config.dns_addr)
        .await
        .map_err(|e| format!("bind DNS listener {}: {e}", state.config.dns_addr))?;

    let store = state.store.clone();
    let config = state.config.clone();
    let resolver = state.resolver.clone();
    let secs = state.config.reload_secs;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(secs));
        // The first immediate tick is redundant with the startup reload; skip it.
        tick.tick().await;
        loop {
            tick.tick().await;
            resolver.reload(store.as_ref(), &config).await;
        }
    });
    Ok(())
}

/// Trigger an immediate resolver reload (called after a zone edit so changes apply at once).
pub async fn reload_now(state: &AppState) {
    state
        .resolver
        .reload(state.store.as_ref(), &state.config)
        .await;
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
}

/// Current wall-clock time in epoch seconds (`created_at` granularity + the serial bump source).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// A unique id with a typed prefix: `{prefix}_{16 hex chars}` from the OS CSPRNG.
pub fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    format!("{prefix}_{}", hex::encode(bytes))
}
