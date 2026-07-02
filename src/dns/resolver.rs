//! In-process authoritative resolver over a periodically-reloaded zone snapshot.
//!
//! The DNS listeners and the dashboard "test query" box both call [`Resolver::lookup`]. The
//! resolver holds an immutable [`Snapshot`] behind an `RwLock<Arc<..>>`: a reader clones the `Arc`
//! (cheap) and answers without holding the lock, while [`Resolver::reload`] rebuilds the snapshot
//! from the store and swaps it in. Reload runs on a timer AND is triggered after every zone edit,
//! so changes take effect promptly without a per-query database round-trip.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use crate::config::{Config, SOA_MINIMUM};
use crate::dns::{
    type_from_str, type_to_str, Lookup, RData, Rr, Soa, RCODE_NOERROR, RCODE_NXDOMAIN,
    RCODE_REFUSED, TYPE_ANY, TYPE_CNAME, TYPE_NS, TYPE_SOA,
};
use crate::store::{Record, Store};

/// One stored record parsed into wire form.
#[derive(Clone, Debug)]
struct RecView {
    /// Normalized owner name (may be a wildcard like `*.w33d.xyz`).
    name: String,
    rtype: u16,
    ttl: u32,
    data: RData,
}

/// One zone, with its records pre-parsed for lookups.
#[derive(Clone, Debug)]
struct ZoneView {
    name: String,
    serial: u32,
    records: Vec<RecView>,
}

/// An immutable point-in-time view of all zones, plus the SOA identity fields.
#[derive(Clone, Debug, Default)]
struct Snapshot {
    zones: Vec<ZoneView>,
    primary_ns: String,
    hostmaster: String,
}

/// The shared authoritative resolver. Cheap to clone (an `Arc` handle to the snapshot cell).
#[derive(Clone)]
pub struct Resolver {
    inner: Arc<RwLock<Arc<Snapshot>>>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver {
    /// A resolver with an empty snapshot (answers REFUSED until the first reload).
    pub fn new() -> Self {
        Resolver {
            inner: Arc::new(RwLock::new(Arc::new(Snapshot::default()))),
        }
    }

    /// Rebuild the snapshot from the store and atomically swap it in. Unparseable records are
    /// skipped with a warning rather than failing the reload, so one bad row never blanks a zone.
    pub async fn reload(&self, store: &dyn Store, cfg: &Config) {
        let zones = store.list_zones().await;
        let records = store.all_records().await;

        let mut views = Vec::with_capacity(zones.len());
        for z in &zones {
            let mut recs = Vec::new();
            for r in records.iter().filter(|r| r.zone_id == z.id) {
                match parse_record(r) {
                    Some(rv) => recs.push(rv),
                    None => tracing::warn!(
                        name = %r.name, rtype = %r.rtype, value = %r.value,
                        "skipping unparseable record"
                    ),
                }
            }
            views.push(ZoneView {
                name: z.name.clone(),
                serial: z.serial.max(0) as u32,
                records: recs,
            });
        }
        // Longest zone name first, so the apex/sub authority match is a simple linear scan.
        views.sort_by(|a, b| b.name.len().cmp(&a.name.len()));

        let snap = Snapshot {
            zones: views,
            primary_ns: cfg.primary_ns.clone(),
            hostmaster: cfg.hostmaster.clone(),
        };
        *self.inner.write().expect("resolver lock poisoned") = Arc::new(snap);
    }

    /// Resolve one question into a [`Lookup`]. `qname` is normalized (lowercase, no trailing dot);
    /// `qtype` is a wire type code.
    pub fn lookup(&self, qname: &str, qtype: u16) -> Lookup {
        let snap = self.inner.read().expect("resolver lock poisoned").clone();
        snap.lookup(qname, qtype)
    }

    /// Number of zones currently loaded (for the dashboard status line).
    pub fn zone_count(&self) -> usize {
        self.inner
            .read()
            .expect("resolver lock poisoned")
            .zones
            .len()
    }
}

impl Snapshot {
    /// The authoritative zone for `qname`: the longest zone name that is `qname` or a suffix of it.
    /// Zones are kept longest-name-first, so the first match is the most specific.
    fn authoritative_zone(&self, qname: &str) -> Option<&ZoneView> {
        self.zones
            .iter()
            .find(|z| qname == z.name || qname.ends_with(&format!(".{}", z.name)))
    }

    /// Synthesize the zone's SOA record (we never store SOA rows; it is derived from the zone).
    fn soa_rr(&self, zone: &ZoneView) -> Rr {
        Rr {
            name: zone.name.clone(),
            ttl: SOA_MINIMUM,
            data: RData::Soa(Soa::new(&self.primary_ns, &self.hostmaster, zone.serial)),
        }
    }

    fn lookup(&self, qname: &str, qtype: u16) -> Lookup {
        let Some(zone) = self.authoritative_zone(qname) else {
            // Not authoritative for this name — an authoritative server REFUSES.
            return Lookup {
                rcode: RCODE_REFUSED,
                aa: false,
                ..Default::default()
            };
        };
        let apex = qname == zone.name;
        let want = |t: u16| qtype == TYPE_ANY || t == qtype;

        // CNAME indirection: a CNAME owner carries no other types. For a non-CNAME/non-ANY query,
        // return the CNAME and (best-effort) chase its in-zone target for the requested type.
        if qtype != TYPE_CNAME && qtype != TYPE_ANY {
            if let Some(cn) = zone
                .records
                .iter()
                .find(|r| r.name == qname && r.rtype == TYPE_CNAME)
            {
                let mut answers = vec![rr_for(qname, cn)];
                if let RData::Name(_, target) = &cn.data {
                    for r in zone
                        .records
                        .iter()
                        .filter(|r| r.name == *target && r.rtype == qtype)
                    {
                        answers.push(rr_for(target, r));
                    }
                }
                return Lookup {
                    rcode: RCODE_NOERROR,
                    aa: true,
                    answers,
                    authority: Vec::new(),
                };
            }
        }

        // Direct (exact-owner) answers.
        let mut answers: Vec<Rr> = Vec::new();
        if apex && (qtype == TYPE_SOA || qtype == TYPE_ANY) {
            answers.push(self.soa_rr(zone));
        }
        for r in zone
            .records
            .iter()
            .filter(|r| r.name == qname && want(r.rtype))
        {
            answers.push(rr_for(qname, r));
        }
        if !answers.is_empty() {
            return Lookup {
                rcode: RCODE_NOERROR,
                aa: true,
                answers,
                authority: Vec::new(),
            };
        }

        // No exact match — try wildcard synthesis (owner stays the queried name).
        if !apex {
            if let Some(wild) = self.wildcard_owner(qname, zone) {
                if qtype != TYPE_CNAME && qtype != TYPE_ANY {
                    if let Some(cn) = zone
                        .records
                        .iter()
                        .find(|r| r.name == wild && r.rtype == TYPE_CNAME)
                    {
                        return Lookup {
                            rcode: RCODE_NOERROR,
                            aa: true,
                            answers: vec![rr_for(qname, cn)],
                            authority: Vec::new(),
                        };
                    }
                }
                let wanswers: Vec<Rr> = zone
                    .records
                    .iter()
                    .filter(|r| r.name == wild && want(r.rtype))
                    .map(|r| rr_for(qname, r))
                    .collect();
                if !wanswers.is_empty() {
                    return Lookup {
                        rcode: RCODE_NOERROR,
                        aa: true,
                        answers: wanswers,
                        authority: Vec::new(),
                    };
                }
                // Wildcard owner exists but not this type -> NODATA (name exists).
                return self.negative(zone, RCODE_NOERROR);
            }
        }

        // Nothing matched. NODATA when the name exists (apex, or an exact owner of another type),
        // otherwise NXDOMAIN.
        let name_exists = apex || zone.records.iter().any(|r| r.name == qname);
        let rcode = if name_exists {
            RCODE_NOERROR
        } else {
            RCODE_NXDOMAIN
        };
        self.negative(zone, rcode)
    }

    /// A negative answer (NODATA or NXDOMAIN): no answers, the SOA in the authority section, AA set.
    fn negative(&self, zone: &ZoneView, rcode: u8) -> Lookup {
        Lookup {
            rcode,
            aa: true,
            answers: Vec::new(),
            authority: vec![self.soa_rr(zone)],
        }
    }

    /// Find the nearest wildcard owner (`*.<ancestor>`) covering `qname`, walking from the immediate
    /// parent up to the zone apex. Returns the wildcard owner name when a record at it exists.
    fn wildcard_owner(&self, qname: &str, zone: &ZoneView) -> Option<String> {
        let mut parent = match qname.split_once('.') {
            Some((_, p)) => p.to_string(),
            None => return None,
        };
        loop {
            let candidate = format!("*.{parent}");
            if zone.records.iter().any(|r| r.name == candidate) {
                return Some(candidate);
            }
            if parent == zone.name {
                return None;
            }
            parent = match parent.split_once('.') {
                Some((_, p)) => p.to_string(),
                None => return None,
            };
        }
    }
}

/// Build an answer [`Rr`] for an owner name from a parsed record.
fn rr_for(owner: &str, rec: &RecView) -> Rr {
    Rr {
        name: owner.to_string(),
        ttl: rec.ttl,
        data: rec.data.clone(),
    }
}

/// Parse a stored [`Record`] into a [`RecView`]. Returns `None` (skip) when the value cannot be
/// parsed for its type. SOA rows are ignored — the SOA is synthesized per-zone.
fn parse_record(r: &Record) -> Option<RecView> {
    let rtype_code = type_from_str(&r.rtype)?;
    let name = crate::config::normalize_name(&r.name);
    let value = r.value.trim();
    let data = match type_to_str(rtype_code).as_str() {
        "A" => RData::A(Ipv4Addr::from_str(value).ok()?),
        "AAAA" => RData::Aaaa(Ipv6Addr::from_str(value).ok()?),
        "NS" => RData::Name(TYPE_NS, crate::config::normalize_name(value)),
        "CNAME" => RData::Name(TYPE_CNAME, crate::config::normalize_name(value)),
        "MX" => {
            let mut it = value.split_whitespace();
            let pref: u16 = it.next()?.parse().ok()?;
            let host = crate::config::normalize_name(&it.collect::<Vec<_>>().join(" "));
            if host.is_empty() {
                return None;
            }
            RData::Mx { pref, host }
        }
        "TXT" => RData::Txt(strip_quotes(&r.value).to_string()),
        "SRV" => {
            let mut it = value.split_whitespace();
            let priority: u16 = it.next()?.parse().ok()?;
            let weight: u16 = it.next()?.parse().ok()?;
            let port: u16 = it.next()?.parse().ok()?;
            let target = crate::config::normalize_name(&it.collect::<Vec<_>>().join(" "));
            if target.is_empty() {
                return None;
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        "CAA" => {
            let mut it = value.split_whitespace();
            let flags: u8 = it.next()?.parse().ok()?;
            let tag = it.next()?.to_ascii_lowercase();
            let value = strip_quotes(&it.collect::<Vec<_>>().join(" ")).to_string();
            if tag.is_empty() || value.is_empty() {
                return None;
            }
            RData::Caa { flags, tag, value }
        }
        // SOA is synthesized, never stored; ignore any stray SOA rows.
        _ => return None,
    };
    let ttl = r.ttl.clamp(0, u32::MAX as i64) as u32;
    Some(RecView {
        name,
        rtype: rtype_code,
        ttl,
        data,
    })
}

/// Strip a single pair of surrounding double quotes from a TXT value, if present.
fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    t.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{
        RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED, TYPE_A, TYPE_CAA, TYPE_MX, TYPE_SRV, TYPE_TXT,
    };

    fn rec(zone_id: &str, name: &str, rtype: &str, value: &str) -> Record {
        Record {
            id: format!("r_{name}_{rtype}"),
            zone_id: zone_id.to_string(),
            name: name.to_string(),
            rtype: rtype.to_string(),
            value: value.to_string(),
            ttl: 300,
            created_at: 0,
        }
    }

    async fn loaded() -> Resolver {
        use crate::store::{InMemoryStore, Zone};
        let store = InMemoryStore::new();
        store
            .create_zone(&Zone {
                id: "z1".into(),
                name: "w33d.xyz".into(),
                serial: 5,
                created_at: 0,
            })
            .await
            .unwrap();
        for r in [
            rec("z1", "w33d.xyz", "A", "159.195.136.226"),
            rec("z1", "*.w33d.xyz", "A", "159.195.136.226"),
            rec("z1", "w33d.xyz", "MX", "10 mail.w33d.xyz"),
            rec("z1", "w33d.xyz", "TXT", "v=spf1 mx -all"),
            rec("z1", "w33d.xyz", "NS", "ns1.w33d.xyz"),
            rec("z1", "_sip._tcp.w33d.xyz", "SRV", "10 20 5060 sip.w33d.xyz"),
            rec("z1", "w33d.xyz", "CAA", "0 issue letsencrypt.org"),
            rec("z1", "mail.w33d.xyz", "A", "159.195.136.226"),
        ] {
            store.create_record(&r).await.unwrap();
        }
        let cfg = Config::dev();
        let resolver = Resolver::new();
        resolver.reload(&store, &cfg).await;
        resolver
    }

    #[tokio::test]
    async fn apex_a_answers() {
        let r = loaded().await;
        let lk = r.lookup("w33d.xyz", TYPE_A);
        assert_eq!(lk.rcode, RCODE_NOERROR);
        assert!(lk.aa);
        assert_eq!(lk.answers.len(), 1);
    }

    #[tokio::test]
    async fn wildcard_matches_unknown_subdomain() {
        let r = loaded().await;
        let lk = r.lookup("anything.w33d.xyz", TYPE_A);
        assert_eq!(lk.rcode, RCODE_NOERROR);
        assert_eq!(lk.answers.len(), 1);
        assert_eq!(lk.answers[0].name, "anything.w33d.xyz");
    }

    #[tokio::test]
    async fn mx_and_txt_resolve() {
        let r = loaded().await;
        assert_eq!(r.lookup("w33d.xyz", TYPE_MX).answers.len(), 1);
        assert_eq!(r.lookup("w33d.xyz", TYPE_TXT).answers.len(), 1);
    }

    #[tokio::test]
    async fn srv_and_caa_resolve() {
        let r = loaded().await;
        let srv = r.lookup("_sip._tcp.w33d.xyz", TYPE_SRV);
        assert_eq!(srv.answers.len(), 1);
        assert_eq!(srv.answers[0].data.to_text(), "10 20 5060 sip.w33d.xyz.");

        let caa = r.lookup("w33d.xyz", TYPE_CAA);
        assert_eq!(caa.answers.len(), 1);
        assert_eq!(caa.answers[0].data.to_text(), "0 issue \"letsencrypt.org\"");
    }

    #[tokio::test]
    async fn nodata_vs_nxdomain() {
        let r = loaded().await;
        // mail.w33d.xyz exists (A) but has no MX -> NODATA (NOERROR, no answers, SOA authority).
        let nodata = r.lookup("mail.w33d.xyz", TYPE_MX);
        assert_eq!(nodata.rcode, RCODE_NOERROR);
        assert!(nodata.answers.is_empty());
        assert_eq!(nodata.authority.len(), 1);
        // A non-authoritative name -> REFUSED.
        assert_eq!(r.lookup("example.com", TYPE_A).rcode, RCODE_REFUSED);
    }

    #[tokio::test]
    async fn unknown_apex_type_is_nodata_not_nxdomain() {
        let r = loaded().await;
        // The apex exists; AAAA is absent -> NODATA, never NXDOMAIN.
        let lk = r.lookup("w33d.xyz", crate::dns::TYPE_AAAA);
        assert_eq!(lk.rcode, RCODE_NOERROR);
        assert!(lk.answers.is_empty());
    }

    #[tokio::test]
    async fn truly_absent_name_is_nxdomain_when_no_wildcard() {
        use crate::store::{InMemoryStore, Zone};
        // A zone with no wildcard: an absent name is NXDOMAIN.
        let store = InMemoryStore::new();
        store
            .create_zone(&Zone {
                id: "z".into(),
                name: "bare.test".into(),
                serial: 1,
                created_at: 0,
            })
            .await
            .unwrap();
        store
            .create_record(&rec("z", "bare.test", "A", "10.0.0.1"))
            .await
            .unwrap();
        let r = Resolver::new();
        r.reload(&store, &Config::dev()).await;
        assert_eq!(r.lookup("ghost.bare.test", TYPE_A).rcode, RCODE_NXDOMAIN);
    }
}
