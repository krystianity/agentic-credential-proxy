use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Placeholder replaced with the secret inside `header_value`.
pub const CREDENTIAL_PLACEHOLDER: &str = "{credential}";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    bind: String,

    #[serde(default = "default_keychain_service")]
    keychain_service: String,

    #[serde(default = "default_timeout_s")]
    upstream_timeout_s: u64,

    #[serde(default = "default_max_body_bytes")]
    max_request_body_bytes: u64,

    #[serde(default)]
    providers: Vec<RawProvider>,

    /// Absent means the file share is off; there is no default directory.
    files: Option<RawFiles>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFiles {
    dir: String,

    /// So the directory can stay configured while the feature is off.
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvider {
    name: String,
    base_url: String,
    header: String,

    #[serde(default = "default_header_value")]
    header_value: String,

    /// Defaults to the provider name, mirroring argonath's "account named after
    /// the thing it belongs to" shape.
    keychain_account: Option<String>,

    #[serde(default)]
    extra_headers: BTreeMap<String, String>,

    /// Glob patterns for upstream paths the agent may not reach, e.g.
    /// "v1/user*". Matched against a normalised path; see `deny_paths` on
    /// `Provider`.
    #[serde(default)]
    deny_paths: Vec<String>,

    /// Glob patterns for the only upstream paths the agent may reach. Empty
    /// means "no allowlist", which is the fluent default; a non-empty list
    /// turns this provider into deny-by-default.
    #[serde(default)]
    allow_paths: Vec<String>,

    /// The only methods the agent may use on this provider. Empty means all of
    /// them (except the ones the proxy refuses outright).
    #[serde(default)]
    allow_methods: Vec<String>,

    /// Both optional and non-secret; surfaced on the discovery endpoint so an
    /// agent can work out what a route is for without a copy of this file.
    description: Option<String>,
    docs: Option<String>,
}

/// Routes the proxy serves itself. A provider with one of these names would be
/// shadowed by it and never reachable, so refuse the config instead. `files` is
/// reserved whether or not the file share is enabled, so turning it on later
/// cannot silently take a route away from a provider.
const RESERVED_NAMES: &[&str] = &["healthz", "providers", "files"];

fn default_keychain_service() -> String {
    "agentic-credential-proxy".to_string()
}

fn default_enabled() -> bool {
    true
}

fn default_header_value() -> String {
    format!("Bearer {CREDENTIAL_PLACEHOLDER}")
}

fn default_timeout_s() -> u64 {
    300
}

fn default_max_body_bytes() -> u64 {
    // Generous enough for image/audio uploads, bounded enough that a runaway
    // agent cannot stream the host out of memory.
    256 * 1024 * 1024
}

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub keychain_service: String,
    pub upstream_timeout_s: u64,
    pub max_request_body_bytes: u64,
    pub providers: BTreeMap<String, Provider>,

    /// `None` when the file share is absent from the config or switched off, so
    /// nothing downstream has to carry an "is it on" flag around.
    pub files: Option<FileShare>,
}

#[derive(Debug)]
pub struct FileShare {
    /// Absolute, with a leading `~/` expanded, but not yet resolved against the
    /// filesystem -- that happens at startup in `files::FileStore::open`.
    pub dir: PathBuf,
}

/// Methods the proxy refuses for every provider, whatever the config says.
///
/// TRACE is the dangerous one: an upstream that honours it echoes the request
/// back, injected credential header and all, and that echo would go straight to
/// the agent. CONNECT asks the proxy to open a tunnel, which is not a thing this
/// proxy does.
pub const REFUSED_METHODS: &[&str] = &["TRACE", "CONNECT"];

#[derive(Debug)]
pub struct Provider {
    pub name: String,
    pub base_url: String,

    /// `base_url` parsed once, so a built URL can be checked against the origin
    /// and path prefix it is supposed to stay inside.
    pub base: reqwest::Url,

    pub header: http::HeaderName,
    pub header_value: String,
    pub keychain_account: String,
    pub extra_headers: Vec<(http::HeaderName, http::HeaderValue)>,

    /// Normalised deny patterns: lowercased, leading slashes stripped. `*`
    /// matches any run of characters, including `/`.
    ///
    /// A denylist only knows the no-gos you thought of -- anything a provider
    /// adds later is allowed by default. That is the trade for staying fluent.
    pub deny_paths: Vec<String>,

    /// Normalised allow patterns. Empty means every path that is not denied;
    /// non-empty flips this provider to deny-by-default.
    pub allow_paths: Vec<String>,

    /// Uppercased method names. Empty means every method the proxy itself
    /// allows.
    pub allow_methods: Vec<String>,

    pub description: Option<String>,
    pub docs: Option<String>,
}

impl Provider {
    /// Build the outgoing header value for this provider.
    pub fn render_header_value(&self, credential: &str) -> String {
        self.header_value.replace(CREDENTIAL_PLACEHOLDER, credential)
    }

    /// Whether a *normalised* path is blocked. Callers must normalise first --
    /// matching the raw path would let `/v1%2Fuser` walk straight past a rule
    /// written as `v1/user*`.
    pub fn is_denied(&self, normalised_path: &str) -> bool {
        self.deny_paths
            .iter()
            .any(|pattern| glob_match(pattern, normalised_path))
    }

    /// Whether a *normalised* path is on the allowlist. An empty allowlist
    /// permits everything, which keeps the default behaviour fluent: you opt
    /// into deny-by-default per provider, you do not have to enumerate an API
    /// you only wanted to use casually.
    pub fn is_allowed(&self, normalised_path: &str) -> bool {
        self.allow_paths.is_empty()
            || self
                .allow_paths
                .iter()
                .any(|pattern| glob_match(pattern, normalised_path))
    }

    pub fn method_allowed(&self, method: &str) -> bool {
        self.allow_methods.is_empty() || self.allow_methods.iter().any(|m| m == method)
    }
}

/// Lowercase, strip leading slashes, and collapse repeated ones, so that
/// `//V1//User` and `v1/user` compare equal. Applied to both patterns and
/// incoming paths, so the two can never disagree about shape.
pub fn normalise_path(path: &str) -> String {
    let lowered = path.to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut last_was_slash = false;
    for c in lowered.chars() {
        if c == '/' {
            // Leading slashes drop out because `out` is still empty here.
            if !last_was_slash && !out.is_empty() {
                out.push(c);
            }
            last_was_slash = true;
        } else {
            out.push(c);
            last_was_slash = false;
        }
    }
    // A trailing slash is not meaningful for matching: `v1/user/` is `v1/user`.
    while out.ends_with('/') {
        out.pop();
    }
    out
}

/// Glob match where `*` spans any run of characters, `/` included. Deliberately
/// greedy: for a denylist, over-matching fails safe and under-matching does not.
fn glob_match(pattern: &str, value: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !value.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // The tail must land at the end and not overlap what we consumed.
            if value.len() < pos + part.len() || !value[pos..].ends_with(part) {
                return false;
            }
        } else {
            match value[pos..].find(part) {
                // find() returns a byte offset of a real match, so pos stays on
                // a char boundary even for multi-byte paths.
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

impl Config {
    /// `path` only selects which of the `embedded` configs to run (see
    /// build.rs). Its contents must match one of them byte for byte, so a
    /// config written or edited after the build is refused rather than obeyed.
    pub fn load(path: &Path, embedded: &[&str]) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config at {}", path.display()))?;
        let Some(raw) = embedded.iter().find(|c| **c == raw) else {
            bail!(
                "{} is not one of the configs built into this binary; if you \
                 changed it, run ./start.sh --rebuild (and expect the keychain prompt)",
                path.display()
            );
        };
        Self::parse(raw)
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(raw).context("parsing config")?;

        let bind: SocketAddr = raw
            .bind
            .parse()
            .with_context(|| format!("bind {:?} is not a valid host:port", raw.bind))?;
        if !is_bindable(bind.ip()) {
            bail!(
                "bind {bind} is not a tailnet or loopback address; \
                 binding a LAN or wildcard address would expose your credentials \
                 to the whole network"
            );
        }

        if raw.providers.is_empty() {
            bail!("config declares no providers");
        }

        let mut providers = BTreeMap::new();
        for p in raw.providers {
            if p.name.is_empty()
                || !p
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                bail!("provider name {:?} must be alphanumeric, '-' or '_'", p.name);
            }

            if RESERVED_NAMES.contains(&p.name.as_str()) {
                bail!(
                    "provider name {:?} collides with a built-in route; pick another",
                    p.name
                );
            }

            let base_url = p.base_url.trim_end_matches('/').to_string();
            let base = reqwest::Url::parse(&base_url)
                .with_context(|| format!("provider {:?}: base_url is not a URL", p.name))?;

            // Plaintext would put the credential we inject on the wire in the
            // clear. An upstream on this machine is refused too, whatever the
            // scheme: any local process could stand in for it by taking its
            // port first, and would then be handed the key.
            if base.scheme() != "https" {
                bail!("provider {:?}: base_url must be https", p.name);
            }
            if is_local_host(&base) {
                bail!(
                    "provider {:?}: base_url must not point at this machine \
                     (localhost, loopback or unspecified addresses)",
                    p.name
                );
            }
            if base.query().is_some() || base.fragment().is_some() {
                bail!(
                    "provider {:?}: base_url must not carry a query or fragment",
                    p.name
                );
            }

            if !p.header_value.contains(CREDENTIAL_PLACEHOLDER) {
                bail!(
                    "provider {:?}: header_value must contain the {CREDENTIAL_PLACEHOLDER} placeholder",
                    p.name
                );
            }

            let header = http::HeaderName::try_from(p.header.as_str())
                .with_context(|| format!("provider {:?}: invalid header name", p.name))?;

            let mut extra_headers = Vec::new();
            for (k, v) in &p.extra_headers {
                let name = http::HeaderName::try_from(k.as_str())
                    .with_context(|| format!("provider {:?}: invalid extra header {k:?}", p.name))?;
                let value = http::HeaderValue::try_from(v.as_str()).with_context(|| {
                    format!("provider {:?}: invalid value for extra header {k:?}", p.name)
                })?;
                extra_headers.push((name, value));
            }

            let mut deny_paths = Vec::with_capacity(p.deny_paths.len());
            for pattern in &p.deny_paths {
                let normalised = normalise_path(pattern);
                if normalised.is_empty() {
                    bail!("provider {:?}: empty deny_paths pattern", p.name);
                }
                deny_paths.push(normalised);
            }

            let mut allow_paths = Vec::with_capacity(p.allow_paths.len());
            for pattern in &p.allow_paths {
                let normalised = normalise_path(pattern);
                if normalised.is_empty() {
                    bail!("provider {:?}: empty allow_paths pattern", p.name);
                }
                allow_paths.push(normalised);
            }

            let mut allow_methods = Vec::with_capacity(p.allow_methods.len());
            for m in &p.allow_methods {
                let upper = m.to_ascii_uppercase();
                http::Method::try_from(upper.as_str())
                    .with_context(|| format!("provider {:?}: invalid method {m:?}", p.name))?;
                if REFUSED_METHODS.contains(&upper.as_str()) {
                    bail!(
                        "provider {:?}: {upper} is refused by the proxy for every \
                         provider and cannot be allowed here",
                        p.name
                    );
                }
                allow_methods.push(upper);
            }

            let keychain_account = p.keychain_account.unwrap_or_else(|| p.name.clone());

            if providers
                .insert(
                    p.name.clone(),
                    Provider {
                        name: p.name.clone(),
                        base_url,
                        base,
                        header,
                        header_value: p.header_value,
                        keychain_account,
                        extra_headers,
                        deny_paths,
                        allow_paths,
                        allow_methods,
                        description: p.description,
                        docs: p.docs,
                    },
                )
                .is_some()
            {
                bail!("provider {:?} is declared more than once", p.name);
            }
        }

        let files = match raw.files {
            Some(f) if f.enabled => {
                let dir = expand_tilde(&f.dir);
                // A relative path would resolve against whatever directory the
                // process happened to start in. Refuse it rather than share a
                // directory nobody meant to share.
                if !dir.is_absolute() {
                    bail!("[files] dir {:?} must be an absolute path", f.dir);
                }
                Some(FileShare { dir })
            }
            _ => None,
        };

        Ok(Config {
            bind,
            keychain_service: raw.keychain_service,
            upstream_timeout_s: raw.upstream_timeout_s,
            max_request_body_bytes: raw.max_request_body_bytes,
            providers,
            files,
        })
    }
}

/// `~/drop` is what anyone writes in a config file by hand; expanding it here
/// keeps the alternative from being a baffling "no such directory".
fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

/// Whether an upstream URL names this machine: `localhost` and its subdomains,
/// loopback, or the unspecified address (connecting to `0.0.0.0` reaches this
/// machine too). The URL parser has already normalised IPv4 spellings like
/// `127.1` or `2130706433` to `127.0.0.1`, and lowercased the host.
///
/// A public name that merely resolves to 127.0.0.1 is not caught here, but it
/// does not need to be: upstreams are https, and a local listener cannot show
/// a publicly trusted certificate for someone else's name.
fn is_local_host(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return true;
    };
    let host = host.trim_end_matches('.');
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    // host_str keeps the brackets on an IPv6 literal.
    match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
        Err(_) => false,
    }
}

/// Tailscale CGNAT (100.64.0.0/10), Tailscale ULA (fd7a:115c:a1e0::/48), or
/// loopback. Everything else -- wildcard, LAN, VM bridges -- is refused, so the
/// blast radius cannot be widened by a typo in the config.
fn is_bindable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return true;
            }
            let o = v4.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
bind = "127.0.0.1:8787"
[[providers]]
name = "pixellab"
base_url = "https://api.pixellab.ai/"
header = "Authorization"
"#;

    #[test]
    fn applies_defaults() {
        let cfg = Config::parse(MINIMAL).unwrap();
        assert_eq!(cfg.keychain_service, "agentic-credential-proxy");
        let p = &cfg.providers["pixellab"];
        // keychain_account defaults to the provider name
        assert_eq!(p.keychain_account, "pixellab");
        // trailing slash is trimmed so path joining stays unambiguous
        assert_eq!(p.base_url, "https://api.pixellab.ai");
        assert_eq!(p.render_header_value("sk-123"), "Bearer sk-123");
    }

    #[test]
    fn bare_credential_header_is_supported() {
        let cfg = Config::parse(
            r#"
bind = "127.0.0.1:8787"
[[providers]]
name = "eleven"
base_url = "https://api.elevenlabs.io"
header = "xi-api-key"
header_value = "{credential}"
"#,
        )
        .unwrap();
        assert_eq!(cfg.providers["eleven"].render_header_value("k"), "k");
    }

    #[test]
    fn rejects_non_tailnet_binds() {
        for bind in ["0.0.0.0:8787", "192.168.1.10:8787", "10.0.0.5:8787"] {
            let toml = MINIMAL.replace("127.0.0.1:8787", bind);
            let err = Config::parse(&toml).unwrap_err().to_string();
            assert!(err.contains("not a tailnet"), "{bind} was accepted: {err}");
        }
    }

    #[test]
    fn accepts_tailnet_binds() {
        for bind in ["100.101.102.103:8787", "100.64.63.98:8787"] {
            let toml = MINIMAL.replace("127.0.0.1:8787", bind);
            assert!(Config::parse(&toml).is_ok(), "{bind} was rejected");
        }
    }

    #[test]
    fn rejects_header_value_without_placeholder() {
        let toml = format!("{MINIMAL}header_value = \"Bearer oops\"\n");
        assert!(Config::parse(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let toml = format!("{MINIMAL}upstream = \"https://evil.example\"\n");
        assert!(Config::parse(&toml).is_err());
    }

    #[test]
    fn rejects_names_that_shadow_built_in_routes() {
        for name in ["healthz", "providers"] {
            let toml = MINIMAL.replace("\"pixellab\"", &format!("\"{name}\""));
            let err = Config::parse(&toml).unwrap_err().to_string();
            assert!(err.contains("built-in route"), "{name} was accepted: {err}");
        }
    }

    #[test]
    fn carries_optional_discovery_metadata() {
        let cfg = Config::parse(
            r#"
bind = "127.0.0.1:8787"
[[providers]]
name = "elevenlabs"
base_url = "https://api.elevenlabs.io"
header = "xi-api-key"
header_value = "{credential}"
description = "text to speech"
docs = "https://elevenlabs.io/docs"
"#,
        )
        .unwrap();
        let p = &cfg.providers["elevenlabs"];
        assert_eq!(p.description.as_deref(), Some("text to speech"));
        assert_eq!(p.docs.as_deref(), Some("https://elevenlabs.io/docs"));
        // absent in MINIMAL, and must stay absent rather than becoming ""
        assert!(Config::parse(MINIMAL).unwrap().providers["pixellab"]
            .description
            .is_none());
    }

    fn eleven_with_denies() -> Config {
        Config::parse(
            r#"
bind = "127.0.0.1:8787"
[[providers]]
name = "elevenlabs"
base_url = "https://api.elevenlabs.io"
header = "xi-api-key"
header_value = "{credential}"
deny_paths = ["v1/user*", "v1/history*", "*api-keys*"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn denies_listed_paths_and_allows_the_rest() {
        let p = &eleven_with_denies().providers["elevenlabs"];
        for blocked in [
            "v1/user",
            "v1/user/subscription",
            "v1/history",
            "v1/history/abc/audio",
            "v1/workspace/api-keys",
        ] {
            assert!(p.is_denied(&normalise_path(blocked)), "{blocked} slipped through");
        }
        for allowed in ["v1/text-to-speech/abc", "v1/voices", "v1/models", "v1/dubbing"] {
            assert!(!p.is_denied(&normalise_path(allowed)), "{allowed} was blocked");
        }
    }

    /// `*` is greedy on purpose, so `v1/user*` also catches `v1/users-guide`.
    /// Over-blocking is the safe direction for a denylist; write `v1/user` and
    /// `v1/user/*` instead if you need the segment boundary.
    #[test]
    fn star_over_matches_rather_than_under_matches() {
        let p = &eleven_with_denies().providers["elevenlabs"];
        assert!(p.is_denied(&normalise_path("v1/users-guide")));
    }

    #[test]
    fn normalisation_closes_the_obvious_bypasses() {
        let p = &eleven_with_denies().providers["elevenlabs"];
        // Case, leading slash, doubled slashes, trailing slash.
        for variant in ["V1/User", "/v1/user", "v1//user", "v1/user/", "//V1//USER//"] {
            assert!(
                p.is_denied(&normalise_path(variant)),
                "{variant} bypassed the denylist"
            );
        }
    }

    #[test]
    fn glob_star_spans_slashes() {
        assert!(glob_match("v1/user*", "v1/user/subscription"));
        assert!(glob_match("*api-keys*", "v1/workspace/api-keys/create"));
        assert!(glob_match("*", "anything/at/all"));
        assert!(!glob_match("v1/user*", "v2/user"));
        // No star means exact match.
        assert!(glob_match("v1/user", "v1/user"));
        assert!(!glob_match("v1/user", "v1/user/x"));
    }

    #[test]
    fn normalise_is_idempotent() {
        for raw in ["/V1//User/", "v1/user", "", "///"] {
            let once = normalise_path(raw);
            assert_eq!(normalise_path(&once), once, "not idempotent for {raw:?}");
        }
    }

    #[test]
    fn rejects_empty_deny_pattern() {
        let toml = format!("{MINIMAL}deny_paths = [\"/\"]\n");
        assert!(Config::parse(&toml).is_err());
    }

    #[test]
    fn rejects_empty_providers() {
        assert!(Config::parse("bind = \"127.0.0.1:8787\"").is_err());
    }

    /// A credential injected into a plaintext request is a credential on the
    /// wire, and one sent to this machine goes to whoever holds the port.
    #[test]
    fn upstreams_must_be_https_and_not_on_this_machine() {
        let with_base = |url: &str| {
            Config::parse(&format!(
                "bind = \"127.0.0.1:8787\"\n\
                 [[providers]]\nname = \"p\"\nbase_url = {url:?}\nheader = \"Authorization\"\n"
            ))
        };

        assert!(with_base("https://api.pixellab.ai").is_ok());
        // Not this machine, whatever it looks like.
        assert!(with_base("https://localhost.evil.example").is_ok());

        for refused in [
            "http://api.pixellab.ai",
            "http://100.101.102.103:8080",
            "http://192.168.1.4",
            "http://127.0.0.1:1",
            "https://127.0.0.1:8443",
            "https://127.1",
            "https://2130706433",
            "https://127.9.9.9",
            "https://localhost",
            "https://LOCALHOST.:8443",
            "https://api.localhost",
            "https://[::1]:8443",
            "https://[::ffff:127.0.0.1]",
            "https://0.0.0.0:8443",
            "https://[::]:8443",
        ] {
            assert!(with_base(refused).is_err(), "{refused} must be refused");
        }

        // Not a scheme this proxy speaks at all.
        assert!(with_base("ftp://example.com").is_err());
        // Query and fragment belong to the request, not the base.
        assert!(with_base("https://api.pixellab.ai/?k=v").is_err());
        assert!(with_base("https://api.pixellab.ai/#frag").is_err());
    }

    #[test]
    fn a_globally_refused_method_cannot_be_allowed_back_in() {
        for method in REFUSED_METHODS {
            let toml = format!("{MINIMAL}allow_methods = [\"GET\", \"{method}\"]\n");
            assert!(Config::parse(&toml).is_err(), "{method} must not be allowable");
            // Lower case is the same method.
            let toml = format!("{MINIMAL}allow_methods = [\"{}\"]\n", method.to_lowercase());
            assert!(Config::parse(&toml).is_err(), "{method} must not be allowable");
        }

        // A normal list is kept, upper-cased so the comparison is exact.
        let cfg = Config::parse(&format!("{MINIMAL}allow_methods = [\"get\", \"post\"]\n")).unwrap();
        assert_eq!(cfg.providers["pixellab"].allow_methods, ["GET", "POST"]);
        assert!(cfg.providers["pixellab"].method_allowed("GET"));
        assert!(!cfg.providers["pixellab"].method_allowed("DELETE"));

        // No list means no restriction.
        let cfg = Config::parse(MINIMAL).unwrap();
        assert!(cfg.providers["pixellab"].method_allowed("DELETE"));
        assert!(cfg.providers["pixellab"].is_allowed("anything/at/all"));
    }

    fn with_files(block: &str) -> Result<Config> {
        Config::parse(&format!("{MINIMAL}\n{block}"))
    }

    #[test]
    fn the_file_share_is_off_unless_it_is_configured() {
        // No [files] table at all.
        assert!(Config::parse(MINIMAL).unwrap().files.is_none());

        // Present but switched off collapses to the same None, so no code
        // downstream has to remember to check a flag.
        assert!(with_files("[files]\ndir = \"/tmp/drop\"\nenabled = false")
            .unwrap()
            .files
            .is_none());

        let cfg = with_files("[files]\ndir = \"/tmp/drop\"").unwrap();
        assert_eq!(cfg.files.unwrap().dir, PathBuf::from("/tmp/drop"));
    }

    #[test]
    fn the_file_share_dir_must_be_absolute() {
        for dir in ["drop", "./drop", "../drop"] {
            let err = with_files(&format!("[files]\ndir = {dir:?}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("absolute"), "{dir} was accepted: {err}");
        }
    }

    #[test]
    fn expands_a_leading_tilde() {
        let home = std::env::var("HOME").expect("HOME is set");
        let cfg = with_files("[files]\ndir = \"~/acp-drop\"").unwrap();
        assert_eq!(cfg.files.unwrap().dir, PathBuf::from(home).join("acp-drop"));
    }

    #[test]
    fn rejects_unknown_fields_in_the_files_table() {
        assert!(with_files("[files]\ndir = \"/tmp/drop\"\nwritable = true").is_err());
        // dir is not optional: a [files] table with nothing in it is a mistake.
        assert!(with_files("[files]").is_err());
    }

    #[test]
    fn a_provider_may_not_be_called_files() {
        let toml = MINIMAL.replace("\"pixellab\"", "\"files\"");
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("built-in route"), "{err}");
    }
}
