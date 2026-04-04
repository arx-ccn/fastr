/// NIP-11 relay information document.
///
/// When an HTTP request arrives on the WebSocket port with
/// `Accept: application/nostr+json`, this module handles it:
/// returns a JSON document describing the relay's capabilities, then closes the connection.
use crate::config::Config;
use crate::nostr::CREATED_AT_WINDOW;

// Relay info structures

pub struct Limitation {
    pub max_message_length: usize,
    pub max_subscriptions: usize,
    pub max_limit: usize,
    pub max_subid_length: usize,
    pub max_event_tags: usize,
    pub max_content_length: usize,
    /// NIP-01 / NIP-17 window: 48 hours in seconds.
    pub created_at_upper_limit: i64,
    pub auth_required: bool,
}

pub struct RelayInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub pubkey: Option<&'static str>,
    pub contact: Option<&'static str>,
    pub supported_nips: Vec<u16>,
    pub software: &'static str,
    pub version: &'static str,
    pub limitation: Limitation,
}

impl RelayInfo {
    /// Create a default `RelayInfo` configured from the given `Config`.
    ///
    /// The returned `RelayInfo` uses fixed identity fields (`name`, `description`,
    /// `software`, `version`, and supported NIPs) and populates capability fields
    /// from `config` (`max_message_length`, `max_subscriptions`, `max_limit`).
    /// Other limitation fields use fixed defaults (e.g., `max_subid_length` from config,
    /// `created_at_upper_limit = CREATED_AT_WINDOW`, `auth_required = false`).
    ///
    /// # Examples
    ///
    /// ```
    /// use fastr::config::Config;
    /// use fastr::http::RelayInfo;
    /// let cfg = Config::default();
    /// let info = RelayInfo::from_config(&cfg);
    /// assert_eq!(info.name, "fastr");
    /// assert!(info.supported_nips.contains(&77));
    /// ```
    pub fn from_config(config: &Config) -> Self {
        RelayInfo {
            name: "fastr",
            description: "A high-performance Nostr relay",
            pubkey: None,
            contact: None,
            supported_nips: vec![1, 9, 11, 17, 40, 42, 45, 62, 70, 77],
            software: "https://github.com/arx-ccn/fastr",
            version: env!("CARGO_PKG_VERSION"),
            limitation: Limitation {
                max_message_length: config.max_message_bytes,
                max_subscriptions: config.max_subscriptions_per_conn,
                max_limit: config.max_limit,
                max_subid_length: config.max_subid_length,
                max_event_tags: 2000,
                max_content_length: 8192,
                created_at_upper_limit: CREATED_AT_WINDOW,
                auth_required: false,
            },
        }
    }
}

// JSON serialization - hand-rolled to avoid serde overhead on a cold path.

pub fn relay_info_json(info: &RelayInfo) -> String {
    let nips: String = info
        .supported_nips
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let name = serde_json::to_string(info.name).unwrap();
    let desc = serde_json::to_string(info.description).unwrap();
    let sw = serde_json::to_string(info.software).unwrap();
    let ver = serde_json::to_string(info.version).unwrap();

    let pubkey_field = info
        .pubkey
        .map(|p| format!(",\"pubkey\":{}", serde_json::to_string(p).unwrap()))
        .unwrap_or_default();

    let contact_field = info
        .contact
        .map(|c| format!(",\"contact\":{}", serde_json::to_string(c).unwrap()))
        .unwrap_or_default();

    let lim = &info.limitation;
    format!(
        r#"{{"name":{name},"description":{desc}{pubkey}{contact},"supported_nips":[{nips}],"software":{sw},"version":{ver},"limitation":{{"max_message_length":{mml},"max_subscriptions":{ms},"max_limit":{ml},"max_subid_length":{msl},"max_event_tags":{met},"max_content_length":{mcl},"created_at_upper_limit":{caul},"auth_required":{ar}}}}}"#,
        name = name,
        desc = desc,
        pubkey = pubkey_field,
        contact = contact_field,
        nips = nips,
        sw = sw,
        ver = ver,
        mml = lim.max_message_length,
        ms = lim.max_subscriptions,
        ml = lim.max_limit,
        msl = lim.max_subid_length,
        met = lim.max_event_tags,
        mcl = lim.max_content_length,
        caul = lim.created_at_upper_limit,
        ar = lim.auth_required,
    )
}

// Request detection

/// Returns true if the HTTP headers contain a WebSocket upgrade request.
pub fn is_websocket_request(headers: &[httparse::Header<'_>]) -> bool {
    headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("upgrade")
            && std::str::from_utf8(h.value)
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    })
}

/// Returns true if the HTTP headers indicate a NIP-11 relay info request:
/// `Accept: application/nostr+json`.
pub fn is_relay_info_request(headers: &[httparse::Header<'_>]) -> bool {
    headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("accept")
            && std::str::from_utf8(h.value)
                .map(|v| v.contains("application/nostr+json"))
                .unwrap_or(false)
    })
}

/// Returns the HTML for the relay's index page shown to plain browser visitors.
pub fn index_page_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fastr</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',Courier,monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center}
.wrap{padding:2rem;max-width:700px}
.logo img{max-width:min(480px,90vw);height:auto;display:block;margin:0 auto}
.brrr{margin-top:1.5rem;font-size:clamp(0.95rem,2.5vw,1.15rem);color:#fff;font-style:italic}
.brrr em{color:#00ff41;font-style:normal}
.pitch{margin-top:1.5rem;font-size:clamp(0.8rem,2vw,0.95rem);color:#aaa;line-height:1.7}
.pitch strong{color:#fff}
.kudos{margin-top:1rem;font-size:0.85rem;color:#555;font-style:italic}
.sub{margin-top:1.5rem;font-size:0.8rem;color:#444}
a{color:#00ff41;text-decoration:none}a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="wrap">
<div class="logo"><img src="https://blossom.primal.net/cf86102c5f0c0ab39b0330727ac1a70ddf8208bc848f1d2bda1c17666e659e06.png" alt="fastr"></div>
<p class="brrr">A Nostr relay that goes <em>*brrrrrrrrrrrrrrrrrrrrrrrrr*</em>.</p>
<p class="pitch">
<strong>fastr</strong> is a Nostr relay that makes you reconsider every life choice that led you to running anything else.<br><br>
Your relay is slow. Your memory usage is embarrassing. Your disk is screaming. You already knew this in your heart. We just made it impossible to ignore.<br><br>
We did it, nostr!
</p>
<p class="sub">connect with a nostr client &mdash; <a href="https://github.com/arx-ccn/fastr">github</a> &mdash; <a href="https://git.arx-ccn.com/fastr/fastr">gitea</a></p>
</div>
</body>
</html>"#
}

/// Build a complete HTTP/1.1 200 response for the index HTML page.
pub fn index_page_response(body: &str) -> String {
    let len = body.len();
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    )
}

/// Build a complete HTTP/1.1 200 response with the NIP-11 JSON body and CORS headers.
pub fn relay_info_response(body: &str) -> String {
    let len = body.len();
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/nostr+json\r\n\
         Content-Length: {len}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Access-Control-Allow-Methods: GET\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    )
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn default_info() -> RelayInfo {
        RelayInfo::from_config(&Config::default())
    }

    #[test]
    fn test_relay_info_json_valid_json() {
        let info = default_info();
        let json = relay_info_json(&info);
        let v: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(v["name"], "fastr");
    }

    #[test]
    fn test_relay_info_supported_nips() {
        let info = default_info();
        let json = relay_info_json(&info);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let nips: Vec<u64> = v["supported_nips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect();
        assert!(nips.contains(&1));
        assert!(nips.contains(&11));
        assert!(nips.contains(&45));
        assert!(nips.contains(&62));
        assert!(nips.contains(&70));
    }

    #[test]
    fn test_relay_info_created_at_upper_limit() {
        let info = default_info();
        let json = relay_info_json(&info);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["limitation"]["created_at_upper_limit"], 172_800);
    }

    #[test]
    fn test_relay_info_auth_required_false() {
        let info = default_info();
        let json = relay_info_json(&info);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["limitation"]["auth_required"], false);
    }

    #[test]
    fn test_is_relay_info_request_accept_header() {
        let value = b"application/nostr+json";
        let headers = [httparse::Header {
            name: "Accept",
            value: value.as_slice(),
        }];
        assert!(is_relay_info_request(&headers));
    }

    #[test]
    fn test_is_relay_info_request_wrong_type() {
        let value = b"text/html";
        let headers = [httparse::Header {
            name: "Accept",
            value: value.as_slice(),
        }];
        assert!(!is_relay_info_request(&headers));
    }

    #[test]
    fn test_is_relay_info_request_no_accept() {
        let headers: [httparse::Header<'_>; 0] = [];
        assert!(!is_relay_info_request(&headers));
    }

    #[test]
    fn test_relay_info_response_cors_headers() {
        let resp = relay_info_response(r#"{"name":"test"}"#);
        assert!(resp.contains("Access-Control-Allow-Origin: *"));
        assert!(resp.contains("Access-Control-Allow-Headers: *"));
        assert!(resp.contains("Access-Control-Allow-Methods: GET"));
    }

    #[test]
    fn test_relay_info_response_content_type() {
        let resp = relay_info_response("{}");
        assert!(resp.contains("Content-Type: application/nostr+json"));
    }
}
