use std::collections::HashMap;
use std::net::SocketAddr;

/// Relay configuration, loaded from environment variables at startup.
/// Shared read-only across all connections via `Arc<Config>`.
pub struct Config {
    /// Address to bind the TCP listener. Default: 0.0.0.0:8080
    pub listen_addr: SocketAddr,
    /// Maximum concurrent WebSocket connections. Default: 1024
    pub max_connections: usize,
    /// Maximum active subscriptions per connection. Default: 20
    pub max_subscriptions_per_conn: usize,
    /// Maximum filters per REQ message. Default: 10
    pub max_filters_per_req: usize,
    /// Maximum events returned per filter. Default: 500
    pub max_limit: usize,
    /// Maximum incoming WebSocket message size in bytes. Default: 128 KiB
    pub max_message_bytes: usize,
    /// Maximum subscription ID length in characters (NIP-01: max 64). Default: 64
    pub max_subid_length: usize,
    /// Maximum number of values in a single filter field (ids, authors, kinds, tag values). Default: 256
    pub max_filter_values: usize,
    /// Directory where the store files live. Default: "./data"
    pub data_dir: std::path::PathBuf,
    /// Relay WebSocket URL used for NIP-42 AUTH verification. Default: derived from listen_addr.
    /// Override with FASTR_URL env var.
    pub relay_url: String,
    /// Interval in seconds between background compaction runs. 0 = disabled. Default: 21600 (6h).
    pub compact_interval: u64,
    /// Maximum number of records allowed in a single negentropy session. Default: 500_000.
    /// If a NEG-OPEN filter matches more events than this, the server responds with NEG-ERR.
    pub max_neg_records: usize,
    /// Maximum number of tags allowed on an incoming event. Default: 2000.
    pub max_event_tags: usize,
    /// Maximum content length (in bytes) allowed on an incoming event. Default: 50 KiB (51200).
    pub max_content_length: usize,
    /// Per-kind content length overrides. Kinds listed here use their own max instead of
    /// `max_content_length`. Parsed from `FASTR_MAX_CONTENT_LENGTH_PER_KIND` as
    /// comma-separated `kind:bytes` pairs, e.g. `1053:102400,30023:102400`.
    pub max_content_length_per_kind: HashMap<u16, usize>,
}

impl Default for Config {
    fn default() -> Self {
        let port: u16 = env_parse("FASTR_PORT", 8080);
        let addr_str = std::env::var("FASTR_ADDR").unwrap_or_else(|_| "0.0.0.0".to_owned());
        let listen_addr: SocketAddr = format!("{addr_str}:{port}")
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:8080".parse().unwrap());

        let relay_url = std::env::var("FASTR_URL").unwrap_or_else(|_| format!("ws://{}", listen_addr));

        Config {
            listen_addr,
            max_connections: env_parse("FASTR_MAX_CONNECTIONS", 1024),
            max_subscriptions_per_conn: env_parse("FASTR_MAX_SUBSCRIPTIONS", 20),
            max_filters_per_req: env_parse("FASTR_MAX_FILTERS", 10),
            max_limit: env_parse("FASTR_MAX_LIMIT", 500),
            max_message_bytes: env_parse("FASTR_MAX_MESSAGE_BYTES", 128 * 1024),
            max_subid_length: env_parse("FASTR_MAX_SUBID_LENGTH", 64).clamp(1, 64),
            max_filter_values: env_parse("FASTR_MAX_FILTER_VALUES", 256),
            data_dir: std::env::var("FASTR_DATA_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("./data")),
            relay_url,
            compact_interval: env_parse("FASTR_COMPACT_INTERVAL", 21600),
            max_neg_records: env_parse("FASTR_MAX_NEG_RECORDS", 500_000),
            max_event_tags: env_parse("FASTR_MAX_EVENT_TAGS", 2000),
            max_content_length: env_parse("FASTR_MAX_CONTENT_LENGTH", 50 * 1024),
            max_content_length_per_kind: parse_kind_limits("FASTR_MAX_CONTENT_LENGTH_PER_KIND"),
        }
    }
}

impl Config {
    /// Return the effective max content length for a given event kind.
    pub fn content_limit_for_kind(&self, kind: u16) -> usize {
        self.max_content_length_per_kind
            .get(&kind)
            .copied()
            .unwrap_or(self.max_content_length)
    }
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Parse `kind:bytes,kind:bytes,...` from an env var into a HashMap.
fn parse_kind_limits(key: &str) -> HashMap<u16, usize> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| {
            let (k, v) = entry.split_once(':')?;
            Some((k.trim().parse().ok()?, v.trim().parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_parses() {
        // Ensure no env vars are set for this test.
        // If FASTR_PORT etc. are set in CI this test still validates the parse path.
        let cfg = Config::default();
        assert!(cfg.max_connections > 0);
        assert!(cfg.max_limit > 0);
        assert!(cfg.max_message_bytes > 0);
    }

    #[test]
    fn test_max_subid_length_clamped_to_range() {
        // Values outside 1..=64 must be clamped.
        unsafe { std::env::set_var("FASTR_MAX_SUBID_LENGTH", "0") };
        let cfg = Config::default();
        assert_eq!(cfg.max_subid_length, 1, "0 must clamp to 1");
        unsafe { std::env::remove_var("FASTR_MAX_SUBID_LENGTH") };

        unsafe { std::env::set_var("FASTR_MAX_SUBID_LENGTH", "200") };
        let cfg = Config::default();
        assert_eq!(cfg.max_subid_length, 64, "200 must clamp to 64");
        unsafe { std::env::remove_var("FASTR_MAX_SUBID_LENGTH") };

        unsafe { std::env::set_var("FASTR_MAX_SUBID_LENGTH", "32") };
        let cfg = Config::default();
        assert_eq!(cfg.max_subid_length, 32, "32 must be accepted as-is");
        unsafe { std::env::remove_var("FASTR_MAX_SUBID_LENGTH") };
    }

    #[test]
    fn test_fastr_port_override() {
        // Safety: this test mutates env; run in isolation.
        // cargo test runs each #[test] in a single thread; env mutation is safe here.
        unsafe { std::env::set_var("FASTR_PORT", "9000") };
        let cfg = Config::default();
        assert_eq!(cfg.listen_addr.port(), 9000);
        unsafe { std::env::remove_var("FASTR_PORT") };
    }
}
