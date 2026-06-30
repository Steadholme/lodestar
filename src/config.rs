//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! keystone/inkwell/sanctum. Production overrides each via the environment.
//!
//! The DNS listener defaults to the ALT port `:5353` (NOT the privileged `:53`): Lodestar is being
//! stood up alongside the live resolver and must never touch port 53 or the live wildcard. Go-live
//! is a deliberate human step (repoint the registrar NS records), out of scope for this service.

/// Default admin-dashboard listen address (all interfaces, internal-only port 9110).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9110";
/// Default DNS listen address. ALT PORT `:5353` — never the live `:53`.
pub const DEFAULT_DNS_ADDR: &str = "0.0.0.0:5353";
/// Default apex/primary zone name served by the seed.
pub const DEFAULT_ZONE_NAME: &str = "w33d.xyz";
/// Default primary nameserver (SOA MNAME + apex NS).
pub const DEFAULT_PRIMARY_NS: &str = "ns1.w33d.xyz";
/// Default hostmaster mailbox (SOA RNAME; `@` written as `.`).
pub const DEFAULT_HOSTMASTER: &str = "hostmaster.w33d.xyz";
/// Default public A address used by the first-run seed (the KNOWN live record).
pub const DEFAULT_SEED_IP: &str = "159.195.136.226";
/// Default interval, in seconds, at which the resolver reloads zone data from the store.
pub const DEFAULT_RELOAD_SECS: u64 = 15;

/// Hard cap on how many records the dashboard renders / the JSON list returns.
pub const LIST_LIMIT: usize = 2000;
/// SOA timers (seconds): refresh / retry / expire. `minimum` doubles as the negative-cache TTL.
pub const SOA_REFRESH: u32 = 7200;
pub const SOA_RETRY: u32 = 3600;
pub const SOA_EXPIRE: u32 = 1_209_600;
pub const SOA_MINIMUM: u32 = 300;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Admin dashboard listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// DNS server listen address, UDP + TCP (`LODESTAR_DNS_ADDR`). ALT port `:5353`.
    pub dns_addr: String,
    /// Apex zone name the seed creates (`LODESTAR_ZONE`).
    pub zone_name: String,
    /// Primary nameserver, used for the synthesized SOA MNAME (`LODESTAR_PRIMARY_NS`).
    pub primary_ns: String,
    /// Hostmaster mailbox, used for the synthesized SOA RNAME (`LODESTAR_HOSTMASTER`).
    pub hostmaster: String,
    /// Public A address the seed wires to the apex/wildcard/subdomains (`LODESTAR_SEED_IP`).
    pub seed_ip: String,
    /// Resolver reload interval in seconds (`LODESTAR_RELOAD_SECS`).
    pub reload_secs: u64,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            dns_addr: DEFAULT_DNS_ADDR.to_string(),
            zone_name: DEFAULT_ZONE_NAME.to_string(),
            primary_ns: DEFAULT_PRIMARY_NS.to_string(),
            hostmaster: DEFAULT_HOSTMASTER.to_string(),
            seed_ip: DEFAULT_SEED_IP.to_string(),
            reload_secs: DEFAULT_RELOAD_SECS,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("LODESTAR_DNS_ADDR") {
            config.dns_addr = v;
        }
        if let Some(v) = env_nonempty("LODESTAR_ZONE") {
            config.zone_name = normalize_name(&v);
        }
        if let Some(v) = env_nonempty("LODESTAR_PRIMARY_NS") {
            config.primary_ns = normalize_name(&v);
        }
        if let Some(v) = env_nonempty("LODESTAR_HOSTMASTER") {
            config.hostmaster = normalize_name(&v);
        }
        if let Some(v) = env_nonempty("LODESTAR_SEED_IP") {
            config.seed_ip = v;
        }
        if let Some(v) = env_nonempty("LODESTAR_RELOAD_SECS") {
            if let Ok(n) = v.parse::<u64>() {
                config.reload_secs = n.max(1);
            }
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Lowercase a DNS name and strip any trailing dot, so comparisons are canonical.
pub fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
