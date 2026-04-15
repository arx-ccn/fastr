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
    /// Per-kind maximum content length (in bytes). Every kind falls back to the global default
    /// (FASTR_MAX_CONTENT_LENGTH, default 50 KiB). Individual kinds can be overridden via
    /// `FASTR_MAX_CONTENT_LENGTH_PER_KIND` as comma-separated `kind:bytes` pairs,
    /// e.g. `30023:102400`.
    /// NIP-11 `max_content_length` is reported as the limit for kind 1.
    pub max_content_length_per_kind: HashMap<u16, usize>,
    /// Global default content length limit. Kinds not in max_content_length_per_kind use this.
    /// Default: 50 KiB (51200). Override with `FASTR_MAX_CONTENT_LENGTH`.
    pub max_content_length: usize,
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
///
/// Panics at startup if any token is malformed so configuration mistakes surface immediately.
fn parse_kind_limits(key: &str) -> HashMap<u16, usize> {
    let raw = match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => return HashMap::new(),
    };
    let mut map = HashMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (k, v) = entry.split_once(':').unwrap_or_else(|| {
            panic!("{key}: missing ':' separator in entry {entry:?}");
        });
        let kind = k.trim().parse::<u16>().unwrap_or_else(|e| {
            panic!("{key}: bad kind in entry {entry:?}: {e}");
        });
        let limit = v.trim().parse::<usize>().unwrap_or_else(|e| {
            panic!("{key}: bad byte limit in entry {entry:?}: {e}");
        });
        map.insert(kind, limit);
    }
    map
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

    #[test]
    fn test_parse_kind_limits_valid() {
        unsafe { std::env::set_var("FASTR_TEST_KIND_LIMITS", "1053:102400,30023:204800") };
        let map = parse_kind_limits("FASTR_TEST_KIND_LIMITS");
        assert_eq!(map.get(&1053), Some(&102400));
        assert_eq!(map.get(&30023), Some(&204800));
        assert_eq!(map.len(), 2);
        unsafe { std::env::remove_var("FASTR_TEST_KIND_LIMITS") };
    }

    #[test]
    #[should_panic(expected = "bad byte limit")]
    fn test_parse_kind_limits_bad_value_panics() {
        unsafe { std::env::set_var("FASTR_TEST_KIND_LIMITS2", "1053:abc") };
        parse_kind_limits("FASTR_TEST_KIND_LIMITS2");
    }

    #[test]
    #[should_panic(expected = "missing ':'")]
    fn test_parse_kind_limits_missing_separator_panics() {
        unsafe { std::env::set_var("FASTR_TEST_KIND_LIMITS3", "bad") };
        parse_kind_limits("FASTR_TEST_KIND_LIMITS3");
    }

    #[test]
    #[should_panic(expected = "bad kind")]
    fn test_parse_kind_limits_bad_kind_panics() {
        unsafe { std::env::set_var("FASTR_TEST_KIND_LIMITS4", "notanumber:100") };
        parse_kind_limits("FASTR_TEST_KIND_LIMITS4");
    }

    #[test]
    fn test_content_limit_for_kind_override() {
        let cfg = Config {
            max_content_length: 50 * 1024,
            max_content_length_per_kind: HashMap::from([(30023, 200 * 1024)]),
            ..Config::default()
        };
        assert_eq!(cfg.content_limit_for_kind(30023), 200 * 1024);
        assert_eq!(cfg.content_limit_for_kind(1), 50 * 1024);
    }

    #[test]
    fn test_nip11_reports_kind1_limit() {
        let cfg = Config {
            max_content_length_per_kind: HashMap::from([(1, 69420)]),
            ..Config::default()
        };
        // NIP-11 should report the kind-1 specific limit, not the global default
        assert_eq!(cfg.content_limit_for_kind(1), 69420);
    }
}
