//! First-run seed: a `w33d.xyz` zone mirroring the KNOWN live records, so the server answers
//! something real out of the box (apex + wildcard + the common subdomains + MX + SPF + NS).
//!
//! Seeding is idempotent at the zone level: it runs only when the store has NO zones, so a restart
//! against an already-populated database never duplicates or overwrites operator edits.

use crate::config::Config;
use crate::store::{Record, Store, Zone};
use crate::{new_id, now_secs};

/// Seed the default zone + records when the store is empty. No-op otherwise.
pub async fn seed_if_empty(store: &dyn Store, cfg: &Config) {
    if !store.list_zones().await.is_empty() {
        return;
    }
    let zone_name = crate::config::normalize_name(&cfg.zone_name);
    let ip = cfg.seed_ip.clone();
    let now = now_secs();

    let zone = Zone {
        id: new_id("zone"),
        name: zone_name.clone(),
        serial: 1,
        created_at: now,
    };
    if let Err(e) = store.create_zone(&zone).await {
        tracing::warn!(error = %e, "seed: create zone failed");
        return;
    }

    // (owner, rtype, value) triples for the KNOWN live records.
    let ns1 = &cfg.primary_ns;
    let ns2 = format!("ns2.{zone_name}");
    let mail = format!("mail.{zone_name}");
    let records: Vec<(String, &str, String)> = vec![
        // Apex A + wildcard A (the live wildcard resolution).
        (zone_name.clone(), "A", ip.clone()),
        (format!("*.{zone_name}"), "A", ip.clone()),
        // Mail exchanger + the SPF policy.
        (zone_name.clone(), "MX", format!("10 {mail}")),
        (zone_name.clone(), "TXT", "v=spf1 mx -all".to_string()),
        // Apex authority: the two nameservers (and their glue A records).
        (zone_name.clone(), "NS", ns1.clone()),
        (zone_name.clone(), "NS", ns2.clone()),
        (ns1.clone(), "A", ip.clone()),
        (ns2.clone(), "A", ip.clone()),
        // Common subdomains that resolve today.
        (format!("id.{zone_name}"), "A", ip.clone()),
        (format!("status.{zone_name}"), "A", ip.clone()),
        (mail.clone(), "A", ip.clone()),
    ];

    for (name, rtype, value) in records {
        let rec = Record {
            id: new_id("rec"),
            zone_id: zone.id.clone(),
            name: crate::config::normalize_name(&name),
            rtype: rtype.to_string(),
            value,
            ttl: 300,
            created_at: now,
        };
        if let Err(e) = store.create_record(&rec).await {
            tracing::warn!(error = %e, name = %rec.name, "seed: create record failed");
        }
    }
    tracing::info!(zone = %zone_name, "seeded default zone with live records");
}
