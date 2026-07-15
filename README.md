# Lodestar — authoritative DNS server + zone admin

Lodestar stands up **sovereign authoritative DNS** for `w33d.xyz`, served from a database and ready
for a future NS-delegation cutover. It is part of the Steadholme estate and follows the same shape as
inkwell / sanctum: an async `Store` trait (in-memory default + portable-SQL `PgStore`), a
server-rendered enterprise dashboard reusing the estate design tokens, gateway-injected SSO identity,
double-submit CSRF, a non-blocking Watchtower audit emitter, and a dependency-free container
healthcheck.

Two surfaces, one binary:

- **Admin dashboard** (HTTP, internal port **9110**) — behind the Sluice `auth=sso` route at
  `dns.w33d.xyz`. List zones + records, add / delete records (CSRF), import/export BIND zone files,
  show local change history, and provide a **test-query box** that resolves a name against the
  in-process resolver and shows the dig-style answer. Internal-only: Lodestar trusts the
  gateway-injected `X-Auth-Subject` / `X-Auth-Email` headers and has no login UI.
- **DNS server** (UDP + TCP) — answers authoritative queries from the DB: `A` / `AAAA` / `MX` /
  `TXT` / `NS` / `CNAME` / `SRV` / `CAA`, synthesized `SOA` + apex `NS`, wildcard matching, the AA
  bit, and correct NXDOMAIN vs NODATA. It serves a snapshot reloaded from the store every
  `LODESTAR_RELOAD_SECS` and immediately after every dashboard edit.

## ⚠️ Port :5353 — NOT :53 (build-only)

The DNS server binds **`:5353`** (UDP + TCP) by default — the ALT port. This deployment is **not
delegated** and **must not touch the live `:53`** or the live wildcard resolution. It runs
**alongside** the production resolver so it can be validated end-to-end before any cutover.

**Go-live is a deliberate, human step performed at the registrar:** repoint the `w33d.xyz` NS records
to this server (and bind it to `:53`). That cutover is **out of scope** for this service — Lodestar
never performs it automatically.

## SQL schema (portable standard SQL — runs unchanged on FusionDB over pgwire)

```
zones(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, serial BIGINT NOT NULL DEFAULT 1,
      created_at BIGINT NOT NULL)
records(id TEXT PRIMARY KEY, zone_id TEXT NOT NULL, name TEXT NOT NULL, rtype TEXT NOT NULL,
        value TEXT NOT NULL, ttl BIGINT NOT NULL DEFAULT 300, created_at BIGINT NOT NULL)
CREATE INDEX ON records (zone_id, name, rtype)
zone_history(id TEXT PRIMARY KEY, zone_id TEXT NOT NULL, actor TEXT NOT NULL,
             action TEXT NOT NULL, detail TEXT NOT NULL, created_at BIGINT NOT NULL)
CREATE INDEX ON zone_history (zone_id, created_at)
```

No JSONB / arrays / SERIAL / extensions / vendor types. `CREATE TABLE IF NOT EXISTS` runs on startup.

## First-run seed

When the store has no zones, Lodestar seeds a `w33d.xyz` zone mirroring the KNOWN live records so the
server answers something real immediately: apex `A` → `159.195.136.226`, wildcard `*.w33d.xyz` `A`,
`MX 10 mail.w33d.xyz`, the `id` / `status` / `mail` subdomain `A` records, a `TXT` SPF
(`v=spf1 mx -all`), the apex `NS` (`ns1`/`ns2`) + their glue `A` records. Seeding is idempotent
(zone-level): a restart against a populated DB never duplicates or overwrites operator edits.

## Endpoints

| Method | Path                  | Auth     | Description                              |
|--------|-----------------------|----------|------------------------------------------|
| GET    | `/healthz`            | public   | Liveness (`ok`). Container HEALTHCHECK.  |
| GET    | `/`                   | sso      | Zone editor + test-query box.            |
| GET    | `/api/zones/export`   | sso      | Export `?zone_id=...` as BIND text.      |
| POST   | `/api/zones/import`   | sso+CSRF | Replace a zone from BIND text. → 303 `/` |
| GET    | `/api/records`        | sso      | JSON list of all records.                |
| POST   | `/api/records`        | sso+CSRF | Add a record. → 303 `/`                  |
| POST   | `/api/records/delete` | sso+CSRF | Delete a record by id. → 303 `/`         |

Editing a record = delete + re-add (the API exposes add and delete; every change bumps the zone
serial, writes local history, mirrors a `dns.zone.edit` audit event, and reloads the resolver).
Imports replace all records in the selected zone after BIND parsing and CNAME/duplicate conflict
validation; `SOA` rows are accepted but skipped because Lodestar synthesizes SOA from zone metadata.
DNS queries arrive on the `:5353` UDP/TCP listeners — that surface is unauthenticated by design, as
authoritative DNS is, and never reads the `X-Auth-*` headers.

## Configuration (env, with working in-memory defaults)

| Variable                | Default              | Purpose                                            |
|-------------------------|---------------------|----------------------------------------------------|
| `BIND_ADDR`             | `0.0.0.0:9110`      | Admin dashboard listen address.                    |
| `LODESTAR_DNS_ADDR`     | `0.0.0.0:5353`      | DNS listen address (UDP + TCP). **ALT port.**      |
| `LODESTAR_STORE`        | `memory`            | `memory` or `postgres`.                            |
| `LODESTAR_DATABASE_URL` | —                   | Required when `LODESTAR_STORE=postgres` (db `lodestar`). |
| `LODESTAR_ZONE`         | `w33d.xyz`          | Seeded apex zone name.                             |
| `LODESTAR_PRIMARY_NS`   | `ns1.w33d.xyz`      | SOA MNAME + apex NS.                               |
| `LODESTAR_HOSTMASTER`   | `hostmaster.w33d.xyz` | SOA RNAME.                                       |
| `LODESTAR_SEED_IP`      | `159.195.136.226`   | Public A address used by the seed.                 |
| `LODESTAR_RELOAD_SECS`  | `15`                | Resolver reload interval.                          |
| `AUDIT_ENABLED`         | off                 | Enable the Watchtower audit emitter.               |
| `WATCHTOWER_URL`        | `http://watchtower:8500` | Watchtower base URL (plain http).             |
| `AUDIT_INGEST_TOKEN`    | —                   | Bearer token for audit ingest.                     |

## Build / test

```
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test            # unit (wire + resolver) + the in-memory HTTP flow
```

No OpenSSL anywhere: the DNS server is hand-rolled over tokio UDP+TCP and sqlx uses rustls (ring).
