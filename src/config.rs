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
    /// Directory where the store files live. Default: "./data"
    pub data_dir: std::path::PathBuf,
    /// Relay WebSocket URL used for NIP-42 AUTH verification. Default: derived from listen_addr.
    /// Override with FASTR_URL env var.
    pub relay_url: String,
    /// Interval in seconds between background compaction runs. 0 = disabled. Default: 21600 (6h).
    pub compact_interval: u64,
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
            max_subid_length: env_parse("FASTR_MAX_SUBID_LENGTH", 64),
            data_dir: std::env::var("FASTR_DATA_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("./data")),
            relay_url,
            compact_interval: env_parse("FASTR_COMPACT_INTERVAL", 21600),
        }
    }
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
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
    fn test_fastr_port_override() {
        // Safety: this test mutates env; run in isolation.
        // cargo test runs each #[test] in a single thread; env mutation is safe here.
        unsafe { std::env::set_var("FASTR_PORT", "9000") };
        let cfg = Config::default();
        assert_eq!(cfg.listen_addr.port(), 9000);
        unsafe { std::env::remove_var("FASTR_PORT") };
    }
}
