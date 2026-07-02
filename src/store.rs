//! Zone + record storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! keystone/inkwell/sanctum seam: handlers and the resolver depend only on the trait, so a
//! FusionDB-backed store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT, PK/UNIQUE/NOT NULL/DEFAULT, parameterized queries, a CREATE INDEX) and runtime
//! queries (no compile-time macros), so the build needs NO database and the same statements later
//! run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers and the resolver-reload task `.await` them directly,
//! and `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge,
//! so a DB round-trip never blocks a worker thread.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::LIST_LIMIT;

/// A DNS zone (maps 1:1 to a `zones` row).
#[derive(Clone, Debug)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub serial: i64,
    pub created_at: i64,
}

/// A resource record (maps 1:1 to a `records` row). `rtype` is the textual type (`A`, `AAAA`, `MX`,
/// `TXT`, `NS`, `CNAME`, `SRV`, `CAA`), `value` its presentation form (e.g. `159.195.136.226`,
/// `10 mail.w33d.xyz`).
#[derive(Clone, Debug)]
pub struct Record {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: i64,
    pub created_at: i64,
}

/// One local change-history entry for a zone edit/import.
#[derive(Clone, Debug)]
pub struct ZoneHistory {
    pub id: String,
    pub zone_id: String,
    pub actor: String,
    pub action: String,
    pub detail: String,
    pub created_at: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A zone with this name already exists (the UNIQUE(name) guard).
    #[error("zone already exists: {0}")]
    Conflict(String),
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable zone/record store.
#[async_trait]
pub trait Store: Send + Sync {
    /// All zones, name-ascending, capped at [`LIST_LIMIT`].
    async fn list_zones(&self) -> Vec<Zone>;
    /// One zone by its id.
    async fn get_zone(&self, id: &str) -> Option<Zone>;
    /// One zone by its (already normalized) name.
    async fn get_zone_by_name(&self, name: &str) -> Option<Zone>;
    /// Insert a new zone. Errors with [`StoreError::Conflict`] if the name is taken.
    async fn create_zone(&self, zone: &Zone) -> Result<(), StoreError>;
    /// Set a zone's serial (bumped on every record change).
    async fn set_serial(&self, zone_id: &str, serial: i64) -> Result<(), StoreError>;

    /// All records in one zone, capped at [`LIST_LIMIT`].
    async fn list_records(&self, zone_id: &str) -> Vec<Record>;
    /// Every record across every zone — the resolver's reload snapshot.
    async fn all_records(&self) -> Vec<Record>;
    /// One record by its id.
    async fn get_record(&self, id: &str) -> Option<Record>;
    /// Insert a new record.
    async fn create_record(&self, record: &Record) -> Result<(), StoreError>;
    /// Replace every record in a zone with a prepared set (zone-file import).
    async fn replace_records(&self, zone_id: &str, records: &[Record]) -> Result<(), StoreError>;
    /// Delete a record by id.
    async fn delete_record(&self, id: &str) -> Result<(), StoreError>;

    /// Recent local change-history entries for one zone.
    async fn list_history(&self, zone_id: &str) -> Vec<ZoneHistory>;
    /// Append one local change-history entry.
    async fn create_history(&self, entry: &ZoneHistory) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    zones: Mutex<Vec<Zone>>,
    records: Mutex<Vec<Record>>,
    history: Mutex<Vec<ZoneHistory>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_zones(&self) -> Vec<Zone> {
        let mut v: Vec<Zone> = self.zones.lock().expect("zones lock poisoned").clone();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v.truncate(LIST_LIMIT);
        v
    }

    async fn get_zone(&self, id: &str) -> Option<Zone> {
        self.zones
            .lock()
            .expect("zones lock poisoned")
            .iter()
            .find(|z| z.id == id)
            .cloned()
    }

    async fn get_zone_by_name(&self, name: &str) -> Option<Zone> {
        self.zones
            .lock()
            .expect("zones lock poisoned")
            .iter()
            .find(|z| z.name == name)
            .cloned()
    }

    async fn create_zone(&self, zone: &Zone) -> Result<(), StoreError> {
        let mut zones = self.zones.lock().expect("zones lock poisoned");
        if zones.iter().any(|z| z.name == zone.name) {
            return Err(StoreError::Conflict(zone.name.clone()));
        }
        zones.push(zone.clone());
        Ok(())
    }

    async fn set_serial(&self, zone_id: &str, serial: i64) -> Result<(), StoreError> {
        let mut zones = self.zones.lock().expect("zones lock poisoned");
        match zones.iter_mut().find(|z| z.id == zone_id) {
            Some(z) => {
                z.serial = serial;
                Ok(())
            }
            None => Err(StoreError::Backend(format!("no zone with id {zone_id}"))),
        }
    }

    async fn list_records(&self, zone_id: &str) -> Vec<Record> {
        let mut v: Vec<Record> = self
            .records
            .lock()
            .expect("records lock poisoned")
            .iter()
            .filter(|r| r.zone_id == zone_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.rtype.cmp(&b.rtype)));
        v.truncate(LIST_LIMIT);
        v
    }

    async fn all_records(&self) -> Vec<Record> {
        self.records.lock().expect("records lock poisoned").clone()
    }

    async fn get_record(&self, id: &str) -> Option<Record> {
        self.records
            .lock()
            .expect("records lock poisoned")
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    async fn create_record(&self, record: &Record) -> Result<(), StoreError> {
        self.records
            .lock()
            .expect("records lock poisoned")
            .push(record.clone());
        Ok(())
    }

    async fn replace_records(&self, zone_id: &str, records: &[Record]) -> Result<(), StoreError> {
        let mut current = self.records.lock().expect("records lock poisoned");
        current.retain(|r| r.zone_id != zone_id);
        current.extend(records.iter().cloned());
        Ok(())
    }

    async fn delete_record(&self, id: &str) -> Result<(), StoreError> {
        self.records
            .lock()
            .expect("records lock poisoned")
            .retain(|r| r.id != id);
        Ok(())
    }

    async fn list_history(&self, zone_id: &str) -> Vec<ZoneHistory> {
        let mut v: Vec<ZoneHistory> = self
            .history
            .lock()
            .expect("history lock poisoned")
            .iter()
            .filter(|h| h.zone_id == zone_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v.truncate(25);
        v
    }

    async fn create_history(&self, entry: &ZoneHistory) -> Result<(), StoreError> {
        self.history
            .lock()
            .expect("history lock poisoned")
            .push(entry.clone());
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `LODESTAR_STORE=postgres`. Each method drives sqlx natively and the
// callers `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The DB
// enforces the zone-name UNIQUE constraint, so no in-process serializer is needed.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS zones (\
                 id TEXT PRIMARY KEY, \
                 name TEXT NOT NULL UNIQUE, \
                 serial BIGINT NOT NULL DEFAULT 1, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS records (\
                 id TEXT PRIMARY KEY, \
                 zone_id TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 rtype TEXT NOT NULL, \
                 value TEXT NOT NULL, \
                 ttl BIGINT NOT NULL DEFAULT 300, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the per-name/type lookups (resolver reload pulls everything, but the index keeps
        // the zone-editor + future per-name scans cheap).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_records_zone_name_rtype \
             ON records (zone_id, name, rtype)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS zone_history (\
                 id TEXT PRIMARY KEY, \
                 zone_id TEXT NOT NULL, \
                 actor TEXT NOT NULL, \
                 action TEXT NOT NULL, \
                 detail TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_zone_history_zone_created \
             ON zone_history (zone_id, created_at)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn zone_from_row(row: &sqlx::postgres::PgRow) -> Result<Zone, sqlx::Error> {
        Ok(Zone {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            serial: row.try_get("serial")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn record_from_row(row: &sqlx::postgres::PgRow) -> Result<Record, sqlx::Error> {
        Ok(Record {
            id: row.try_get("id")?,
            zone_id: row.try_get("zone_id")?,
            name: row.try_get("name")?,
            rtype: row.try_get("rtype")?,
            value: row.try_get("value")?,
            ttl: row.try_get("ttl")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn history_from_row(row: &sqlx::postgres::PgRow) -> Result<ZoneHistory, sqlx::Error> {
        Ok(ZoneHistory {
            id: row.try_get("id")?,
            zone_id: row.try_get("zone_id")?,
            actor: row.try_get("actor")?,
            action: row.try_get("action")?,
            detail: row.try_get("detail")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn list_zones_async(&self) -> Result<Vec<Zone>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, serial, created_at FROM zones ORDER BY name ASC LIMIT $1",
        )
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::zone_from_row).collect()
    }

    async fn get_zone_async(&self, id: &str) -> Result<Option<Zone>, sqlx::Error> {
        let row = sqlx::query("SELECT id, name, serial, created_at FROM zones WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::zone_from_row).transpose()
    }

    async fn get_zone_by_name_async(&self, name: &str) -> Result<Option<Zone>, sqlx::Error> {
        let row = sqlx::query("SELECT id, name, serial, created_at FROM zones WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::zone_from_row).transpose()
    }

    async fn create_zone_async(&self, z: &Zone) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO zones (id, name, serial, created_at) VALUES ($1, $2, $3, $4)")
            .bind(&z.id)
            .bind(&z.name)
            .bind(z.serial)
            .bind(z.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_serial_async(&self, zone_id: &str, serial: i64) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE zones SET serial = $1 WHERE id = $2")
            .bind(serial)
            .bind(zone_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_records_async(&self, zone_id: &str) -> Result<Vec<Record>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, zone_id, name, rtype, value, ttl, created_at FROM records \
             WHERE zone_id = $1 ORDER BY name ASC, rtype ASC LIMIT $2",
        )
        .bind(zone_id)
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::record_from_row).collect()
    }

    async fn all_records_async(&self) -> Result<Vec<Record>, sqlx::Error> {
        let rows =
            sqlx::query("SELECT id, zone_id, name, rtype, value, ttl, created_at FROM records")
                .fetch_all(&self.pool)
                .await?;
        rows.iter().map(Self::record_from_row).collect()
    }

    async fn get_record_async(&self, id: &str) -> Result<Option<Record>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, zone_id, name, rtype, value, ttl, created_at FROM records WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::record_from_row).transpose()
    }

    async fn create_record_async(&self, r: &Record) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO records (id, zone_id, name, rtype, value, ttl, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&r.id)
        .bind(&r.zone_id)
        .bind(&r.name)
        .bind(&r.rtype)
        .bind(&r.value)
        .bind(r.ttl)
        .bind(r.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn replace_records_async(
        &self,
        zone_id: &str,
        records: &[Record],
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM records WHERE zone_id = $1")
            .bind(zone_id)
            .execute(&mut *tx)
            .await?;
        for r in records {
            sqlx::query(
                "INSERT INTO records (id, zone_id, name, rtype, value, ttl, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&r.id)
            .bind(&r.zone_id)
            .bind(&r.name)
            .bind(&r.rtype)
            .bind(&r.value)
            .bind(r.ttl)
            .bind(r.created_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn delete_record_async(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM records WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_history_async(&self, zone_id: &str) -> Result<Vec<ZoneHistory>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, zone_id, actor, action, detail, created_at FROM zone_history \
             WHERE zone_id = $1 ORDER BY created_at DESC LIMIT 25",
        )
        .bind(zone_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::history_from_row).collect()
    }

    async fn create_history_async(&self, h: &ZoneHistory) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO zone_history (id, zone_id, actor, action, detail, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&h.id)
        .bind(&h.zone_id)
        .bind(&h.actor)
        .bind(&h.action)
        .bind(&h.detail)
        .bind(h.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// True when a sqlx error is a UNIQUE/PK violation (Postgres SQLSTATE 23505) — the zone-name clash.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait]
impl Store for PgStore {
    async fn list_zones(&self) -> Vec<Zone> {
        self.list_zones_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_zones failed");
            Vec::new()
        })
    }

    async fn get_zone(&self, id: &str) -> Option<Zone> {
        self.get_zone_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_zone failed");
            None
        })
    }

    async fn get_zone_by_name(&self, name: &str) -> Option<Zone> {
        self.get_zone_by_name_async(name).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_zone_by_name failed");
            None
        })
    }

    async fn create_zone(&self, zone: &Zone) -> Result<(), StoreError> {
        self.create_zone_async(zone).await.map_err(|e| {
            if is_unique_violation(&e) {
                StoreError::Conflict(zone.name.clone())
            } else {
                StoreError::Backend(e.to_string())
            }
        })
    }

    async fn set_serial(&self, zone_id: &str, serial: i64) -> Result<(), StoreError> {
        self.set_serial_async(zone_id, serial)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_records(&self, zone_id: &str) -> Vec<Record> {
        self.list_records_async(zone_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_records failed");
            Vec::new()
        })
    }

    async fn all_records(&self) -> Vec<Record> {
        self.all_records_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg all_records failed");
            Vec::new()
        })
    }

    async fn get_record(&self, id: &str) -> Option<Record> {
        self.get_record_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_record failed");
            None
        })
    }

    async fn create_record(&self, record: &Record) -> Result<(), StoreError> {
        self.create_record_async(record)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn replace_records(&self, zone_id: &str, records: &[Record]) -> Result<(), StoreError> {
        self.replace_records_async(zone_id, records)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_record(&self, id: &str) -> Result<(), StoreError> {
        self.delete_record_async(id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_history(&self, zone_id: &str) -> Vec<ZoneHistory> {
        self.list_history_async(zone_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_history failed");
            Vec::new()
        })
    }

    async fn create_history(&self, entry: &ZoneHistory) -> Result<(), StoreError> {
        self.create_history_async(entry)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}
