use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::sync::RwLock;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;

use crate::config::Config;
use crate::control::Control;
use crate::files::{self, FileStore};
use crate::keychain;
use crate::secret::Secret;

/// The caller must name the provider it believes it is calling, and it must
/// agree with the path. Not a security control -- anything reaching the port can
/// set it -- but a model that hallucinates a route now has to hallucinate the
/// same wrong name twice, through two different parts of the request, to get a
/// credential attached to it. Stripped before the request goes upstream.
const PROVIDER_HEADER: &str = "x-acp-provider";

/// Headers that describe a single hop and must never be forwarded across one.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub struct AppState {
    pub config: Config,
    pub client: reqwest::Client,
    /// Provider name -> API key.
    creds: RwLock<HashMap<String, Secret>>,
    /// `None` unless the file share is configured and enabled.
    files: Option<Arc<FileStore>>,
    /// The pause switch and per-target counters, driven from the menu bar over
    /// the local control socket; never from the bind address.
    pub control: Control,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Arc<Self>> {
        // Resolved before anything binds, so a directory that does not exist is
        // a startup error rather than a 500 the first time an agent looks.
        let files = match &config.files {
            Some(share) => {
                let store = FileStore::open(&share.dir)?;
                tracing::info!(dir = %store.root().display(), "sharing files from");
                Some(store)
            }
            None => None,
        };

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            // Per-read inactivity rather than a total deadline, so a long SSE
            // stream or a slow image render is not cut off mid-flight.
            .read_timeout(std::time::Duration::from_secs(config.upstream_timeout_s))
            // Never follow a redirect. reqwest strips `Authorization` when one
            // crosses an origin, but it knows nothing about `xi-api-key` or any
            // other header a provider invents, so a redirect to an attacker's
            // host would hand over the credential. Following even a same-origin
            // one would also step around deny_paths, since the destination is
            // chosen by the upstream and never sees these checks. The 3xx goes
            // back to the agent, which can re-issue it through the proxy and be
            // checked properly.
            .redirect(reqwest::redirect::Policy::none())
            // Ignore HTTP_PROXY / HTTPS_PROXY / ALL_PROXY. reqwest honours them
            // by default, which would hand a plaintext loopback upstream's
            // credential to whatever proxy the launching shell happened to name.
            // Connections go where the config says and nowhere else.
            .no_proxy()
            .build()
            .context("building HTTP client")?;

        let control = Control::new(
            config
                .providers
                .keys()
                .map(String::as_str)
                .chain(files.is_some().then_some("files")),
        );

        let state = Arc::new(AppState {
            config,
            client,
            creds: RwLock::new(HashMap::new()),
            files,
            control,
        });
        state.load_credentials().await?;
        Ok(state)
    }

    /// Reads every credential out of the keychain. Called once at startup so the
    /// ACL prompts land in the launching terminal rather than mid-request, and
    /// again on SIGHUP so a rotated key takes effect without a restart.
    pub async fn load_credentials(&self) -> Result<()> {
        let service = &self.config.keychain_service;
        let mut next = HashMap::new();

        for (name, provider) in &self.config.providers {
            let secret = keychain::read(service, &provider.keychain_account)
                .await
                .with_context(|| format!("reading the credential for provider {name:?}"))?;
            next.insert(name.clone(), secret);
        }

        *self.creds.write().await = next;
        Ok(())
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let limit = state.config.max_request_body_bytes as usize;
    Router::new()
        .route("/", get(discover))
        .route("/healthz", get(healthz))
        .route("/providers", get(discover))
        // Registered whether or not the share is enabled, so a disabled
        // instance can say so plainly instead of answering "unknown provider".
        .route("/files", get(list_files))
        .route("/files/{*name}", get(take_file))
        .fallback(proxy)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            refuse_while_paused,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_bind_host,
        ))
        .layer(RequestBodyLimitLayer::new(limit))
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

/// Every request must be addressed to the bind address itself. Without this,
/// DNS rebinding turns any web page open in a browser that can reach the port
/// into a client: the page points its own hostname at the bind address, and the
/// browser then treats the proxy as same-origin, custom headers and all. What
/// the page cannot do is change the Host header, which still names its own
/// domain, so this is where it stops. Applies to every route, discovery included.
async fn require_bind_host(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if host_allowed(state.config.bind, host) {
        return next.run(req).await;
    }

    let path = req.uri().path();
    let (target, _) = split_path(path);
    let status = StatusCode::FORBIDDEN;
    audit("deny-host", &target, req.method(), path, status, Instant::now());
    state.control.record(&target, "deny-host");
    text(
        status,
        &format!("address this proxy as {}, not by another name", state.config.bind),
    )
}

/// The bind address as an IP, or `localhost` when the bind is loopback, since
/// that name never leaves the machine and so cannot be rebound. The port may
/// only be left out when it is 80, as HTTP clients do.
fn host_allowed(bind: SocketAddr, host: &str) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) if !port.ends_with(']') => (name, port.parse().ok()),
        _ => (host, Some(80)),
    };
    if port != Some(bind.port()) {
        return false;
    }
    let ip = name.trim_start_matches('[').trim_end_matches(']');
    ip.parse::<IpAddr>() == Ok(bind.ip())
        || (bind.ip().is_loopback() && name.eq_ignore_ascii_case("localhost"))
}

/// While paused, nothing is forwarded and nothing leaves the file drop. Only
/// discovery and health still answer, so an agent can tell "paused" from
/// "gone". A guard in front of the router rather than a check in each handler,
/// so a route added later is covered without anyone remembering to.
async fn refuse_while_paused(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if !state.control.is_paused() || matches!(path, "/" | "/healthz" | "/providers") {
        return next.run(req).await;
    }

    let (target, _) = split_path(path);
    let status = StatusCode::SERVICE_UNAVAILABLE;
    audit("deny-paused", &target, req.method(), path, status, Instant::now());
    state.control.record(&target, "deny-paused");
    text(status, "this proxy is paused; nothing is forwarded until it is resumed")
}

async fn healthz() -> &'static str {
    "ok\n"
}

/// Machine-readable list of what this instance can reach, so an agent can find
/// its routes at runtime instead of being told them or carrying a config copy.
///
/// Everything here is non-secret by construction: names, upstreams, and the
/// *name* of the header the credential is injected into, never its value.
async fn discover(State(state): State<Arc<AppState>>) -> Response {
    let providers: Vec<serde_json::Value> = state
        .config
        .providers
        .values()
        .map(|p| {
            let mut entry = serde_json::json!({
                "name": p.name,
                "route": format!("/{}/{{upstream path}}", p.name),
                "upstream": p.base_url,
            });
            let obj = entry.as_object_mut().expect("built as an object");
            if let Some(d) = &p.description {
                obj.insert("description".into(), serde_json::json!(d));
            }
            if let Some(d) = &p.docs {
                obj.insert("docs".into(), serde_json::json!(d));
            }
            // Advertised so an agent knows what is off-limits up front rather
            // than discovering it through a 403.
            if !p.deny_paths.is_empty() {
                obj.insert("denied_paths".into(), serde_json::json!(p.deny_paths));
            }
            // Absent means "no list, everything else is fair game"; present
            // means the list is exhaustive. Saying so beats an agent inferring
            // an allowlist from a single 403 on an unrelated path.
            if !p.allow_paths.is_empty() {
                obj.insert("allowed_paths".into(), serde_json::json!(p.allow_paths));
            }
            if !p.allow_methods.is_empty() {
                obj.insert("allowed_methods".into(), serde_json::json!(p.allow_methods));
            }
            entry
        })
        .collect();

    let mut body = serde_json::json!({
        "service": "agentic-credential-proxy",
        "usage": format!(
            "Call /<name>/<upstream path> and set the {PROVIDER_HEADER} header to \
             the same <name>; a request whose header and path disagree is refused. \
             Method, body, and query pass through unchanged, except that TRACE \
             and CONNECT are never forwarded and redirects are never followed -- \
             a 3xx comes back as-is for you to re-issue through the proxy. Do \
             not send credentials -- they are injected here."
        ),
        "providers": providers,
    });

    // Only advertised when it is on; the directory it serves stays off the wire
    // either way, since the agent addresses files by name and never by path.
    //
    // The `usage` line is the whole protocol, statuses included, because an
    // agent that has to guess at retry semantics guesses wrong in the expensive
    // direction: it either abandons a file that is still sitting there or waits
    // for one that has already been consumed.
    if state.files.is_some() {
        body.as_object_mut().expect("built as an object").insert(
            "files".into(),
            serde_json::json!({
                "list": "/files",
                "get": "/files/{name}",
                "usage": "GET /files returns \
                          {\"files\":[{\"name\",\"bytes\",\"modified_unix\"}],\"skipped\":N}. \
                          GET /files/<name>, URL-encoding the name exactly as listed, \
                          returns the bytes and then deletes the file: 200 means it is \
                          yours and gone from the host, 404 means it never existed or \
                          was already taken, 409 means someone else is fetching it right \
                          now. The delete happens after the last byte, so a transfer \
                          that fails part way leaves the file in place and retrying is \
                          safe. One-way only -- there is no upload, and only plain files \
                          in a single directory are reachable.",
            }),
        );
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        format!("{}\n", serde_json::to_string_pretty(&body).unwrap_or_default()),
    )
        .into_response()
}

fn text(status: StatusCode, body: &str) -> Response {
    (status, format!("{body}\n")).into_response()
}

/// One line per request: who was asked, what was decided, what came back. No
/// header values, so no credential can reach the log.
fn audit(
    decision: &str,
    provider: &str,
    method: &Method,
    path: &str,
    status: StatusCode,
    started: Instant,
) {
    tracing::info!(
        target: "audit",
        decision,
        provider,
        method = %method,
        path,
        status = status.as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "request"
    );
}

/// What is currently in the shared directory. Off means off: a proxy without a
/// file share says so rather than pretending the directory is empty.
async fn list_files(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let started = Instant::now();
    let method = req.method().clone();

    let outcome = match &state.files {
        Some(store) => files::list(store).await,
        None => Err(file_sharing_is_off()),
    };

    match outcome {
        Ok(json) => {
            audit("allow", "files", &method, "/files", StatusCode::OK, started);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                format!("{}\n", serde_json::to_string_pretty(&json).unwrap_or_default()),
            )
                .into_response()
        }
        Err(RejectedWith {
            status,
            decision,
            message,
        }) => {
            audit(decision, "files", &method, "/files", status, started);
            text(status, &message)
        }
    }
}

/// Hand over one file and delete it.
///
/// The name is taken from the raw path and decoded here rather than through an
/// extractor, so it goes through exactly the same single percent-decode as every
/// other path in this proxy -- `%2e%2e%2f` becomes `../` before it is judged, not
/// after.
async fn take_file(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let raw = path.strip_prefix("/files/").unwrap_or_default();

    let outcome = match (&state.files, percent_decode(raw)) {
        (None, _) => Err(file_sharing_is_off()),
        (Some(_), None) => Err(reject(
            StatusCode::BAD_REQUEST,
            "deny-name",
            "the file name is not valid percent-encoded UTF-8",
        )),
        (Some(store), Some(name)) => files::serve(store, &name).await,
    };

    let (status, decision) = match &outcome {
        Ok(resp) => (resp.status(), "allow"),
        Err(RejectedWith { status, decision, .. }) => (*status, *decision),
    };
    audit(decision, "files", &method, &path, status, started);
    state.control.record("files", decision);

    match outcome {
        Ok(resp) => resp,
        Err(RejectedWith { status, message, .. }) => text(status, &message),
    }
}

fn file_sharing_is_off() -> RejectedWith {
    reject(
        StatusCode::NOT_FOUND,
        "deny-file",
        "file sharing is not enabled on this proxy",
    )
}

async fn proxy(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    let (provider_name, rest) = split_path(uri.path());

    let outcome = forward(&state, req, &provider_name, &rest).await;

    let (status, decision) = match &outcome {
        Ok(resp) => (resp.status(), "allow"),
        Err(RejectedWith { status, decision, .. }) => (*status, *decision),
    };

    audit(decision, &provider_name, &method, uri.path(), status, started);
    state.control.record(&provider_name, decision);

    match outcome {
        Ok(resp) => resp,
        Err(RejectedWith { status, message, .. }) => text(status, &message),
    }
}

pub(crate) struct RejectedWith {
    pub(crate) status: StatusCode,
    pub(crate) decision: &'static str,
    pub(crate) message: String,
}

pub(crate) fn reject(
    status: StatusCode,
    decision: &'static str,
    message: impl Into<String>,
) -> RejectedWith {
    RejectedWith {
        status,
        decision,
        message: message.into(),
    }
}

async fn forward(
    state: &Arc<AppState>,
    req: Request<Body>,
    provider_name: &str,
    rest: &str,
) -> Result<Response, RejectedWith> {
    let (parts, body) = req.into_parts();

    // Before anything else, and regardless of provider: an upstream that
    // honours TRACE echoes the request back with the credential header we just
    // injected, straight to the agent.
    if crate::config::REFUSED_METHODS.contains(&parts.method.as_str()) {
        return Err(reject(
            StatusCode::METHOD_NOT_ALLOWED,
            "deny-method",
            format!("{} is never forwarded by this proxy", parts.method),
        ));
    }

    let Some(provider) = state.config.providers.get(provider_name) else {
        // `/files/` with nothing after it matches neither file route and lands
        // here. Calling it an unknown provider would be true and useless.
        if provider_name == "files" {
            return Err(match state.files {
                None => file_sharing_is_off(),
                Some(_) => reject(
                    StatusCode::BAD_REQUEST,
                    "deny-name",
                    "name a file: GET /files/<name>, or GET /files for what is there",
                ),
            });
        }
        return Err(reject(
            StatusCode::NOT_FOUND,
            "deny-provider",
            format!("unknown provider {provider_name:?}; see GET /providers"),
        ));
    };

    let declared = parts
        .headers
        .get(PROVIDER_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if declared != provider_name {
        let detail = if declared.is_empty() {
            format!("missing {PROVIDER_HEADER} header; it must name the provider in the path")
        } else {
            // Debug-escaped and truncated: this is caller-controlled text going
            // back out in a response body.
            let shown: String = declared.chars().take(64).collect();
            format!("{PROVIDER_HEADER} {shown:?} does not match the path provider {provider_name:?}")
        };
        return Err(reject(StatusCode::BAD_REQUEST, "deny-mismatch", detail));
    }

    if !provider.method_allowed(parts.method.as_str()) {
        return Err(reject(
            StatusCode::METHOD_NOT_ALLOWED,
            "deny-method",
            format!(
                "{} is not in allow_methods for provider {provider_name:?}",
                parts.method
            ),
        ));
    }

    // The URL is built *before* anything is judged, because building it is what
    // normalises it: `Url::parse` removes dot segments, so `/v1/./user` and
    // `/v1/%2e/user` both become `/v1/user` here. Judging the path we were sent
    // rather than the one we are about to send is how a denylist gets walked
    // straight past.
    let url = build_url(&provider.base_url, rest, parts.uri.query());
    let url = match reqwest::Url::parse(&url) {
        Ok(u) => u,
        Err(e) => {
            return Err(reject(
                StatusCode::BAD_REQUEST,
                "deny-path",
                format!("could not build upstream URL: {e}"),
            ))
        }
    };

    // Whatever the caller wrote, the request must still be going to the
    // provider we configured -- same origin, and still under its path prefix if
    // it has one. This is what a resolved `..` would have to get past.
    let base_prefix = provider.base.path().trim_end_matches('/');
    if url.origin() != provider.base.origin()
        || !(url.path() == base_prefix || url.path().starts_with(&format!("{base_prefix}/")))
    {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "deny-traversal",
            "that path resolves outside the provider's base URL",
        ));
    }

    // Now the checks, against the path that is actually going on the wire --
    // minus the base's own prefix, since `deny_paths` and `allow_paths` are
    // written as upstream paths, the way they appear after the provider name.
    // The slice is safe because the containment check above just proved the
    // prefix is there.
    let upstream_path = &url.path()[base_prefix.len()..];

    // `%2F` survives `Url::parse` unchanged, so this decode is still what turns
    // `v1%2Fuser` into the `v1/user` a rule is written against.
    let Some(decoded) = percent_decode(upstream_path) else {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "deny-path",
            "path is not valid percent-encoded UTF-8",
        ));
    };

    // Belt and braces: `Url::parse` has already resolved these away, so this can
    // only fire if that ever stops being true.
    if decoded.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "deny-traversal",
            "'.' and '..' are not allowed in the path",
        ));
    }

    let normalised = crate::config::normalise_path(&decoded);

    // Checked before the credential is read, so a blocked request never causes
    // a keychain access at all.
    if provider.is_denied(&normalised) {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "deny-path",
            "this path is blocked by the proxy's deny_paths for this provider",
        ));
    }
    if !provider.is_allowed(&normalised) {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "deny-unlisted",
            "this provider has an allow_paths list and this path is not on it",
        ));
    }

    let credential = {
        let creds = state.creds.read().await;
        match creds.get(provider_name) {
            Some(secret) => secret.clone(),
            None => {
                return Err(reject(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "deny-credential",
                    "credential unavailable",
                ))
            }
        }
    };

    let mut headers = forwardable_headers(&parts.headers, &provider.header);
    let mut injected = match HeaderValue::try_from(provider.render_header_value(credential.expose()))
    {
        Ok(v) => v,
        Err(_) => {
            return Err(reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "deny-credential",
                "credential is not valid in an HTTP header",
            ))
        }
    };
    // Keeps the value out of any Debug rendering of the header map.
    injected.set_sensitive(true);
    headers.insert(provider.header.clone(), injected);

    for (name, value) in &provider.extra_headers {
        headers.insert(name.clone(), value.clone());
    }

    let upstream = state
        .client
        .request(parts.method.clone(), url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await;

    let upstream = match upstream {
        Ok(r) => r,
        Err(e) => {
            // `{e}` on a reqwest error is the URL and the transport failure, not
            // anything we put in a header.
            tracing::warn!(provider = %provider_name, error = %e, "upstream request failed");
            let status = if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            return Err(reject(status, "error", "upstream request failed"));
        }
    };

    let mut response = Response::builder().status(upstream.status());
    if let Some(out) = response.headers_mut() {
        for (name, value) in upstream.headers() {
            if is_hop_by_hop(name) {
                continue;
            }
            out.append(name.clone(), value.clone());
        }
    }

    response
        .body(Body::from_stream(upstream.bytes_stream()))
        .map_err(|e| {
            tracing::warn!(error = %e, "building response failed");
            reject(StatusCode::BAD_GATEWAY, "error", "building response failed")
        })
}

/// Splits "/pixellab/v1/generate" into ("pixellab", "v1/generate").
///
/// Operates on the raw path rather than an axum `Path` extractor so percent
/// encoding survives the trip to the upstream byte for byte.
fn split_path(path: &str) -> (String, String) {
    let trimmed = path.trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((provider, rest)) => (provider.to_string(), rest.to_string()),
        None => (trimmed.to_string(), String::new()),
    }
}

/// Decodes `%XX` once, which is what the upstream's own decoder will do. Returns
/// None on a truncated escape or on bytes that are not valid UTF-8, both of
/// which are refused rather than guessed at.
///
/// Only used for *checking*. Double-encoded input like `%252e` decodes to the
/// literal `%2e`, which is also what the upstream sees after its single decode,
/// so the check and the effect stay in agreement.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn build_url(base: &str, rest: &str, query: Option<&str>) -> String {
    let mut url = String::with_capacity(base.len() + rest.len() + 16);
    url.push_str(base);
    if !rest.is_empty() {
        url.push('/');
        url.push_str(rest);
    }
    if let Some(q) = query {
        url.push('?');
        url.push_str(q);
    }
    url
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

/// Client headers minus anything that describes our hop, identifies our host,
/// or would let the caller overwrite the credential we are about to inject.
///
/// `Authorization` is dropped even when it is not the injected header: the agent
/// has no credentials of its own to send, so anything arriving in that header is
/// a mistake or an attempt to smuggle one past the provider config.
fn forwardable_headers(incoming: &HeaderMap, injected: &HeaderName) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in incoming {
        if is_hop_by_hop(name)
            || name == axum::http::header::HOST
            || name == axum::http::header::AUTHORIZATION
            || name == injected
            // Proxy metadata; the upstream has no business seeing it.
            || name.as_str() == PROVIDER_HEADER
        {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use tower::ServiceExt;

    /// A router wired to a real `AppState` whose credentials are planted
    /// directly, so nothing here touches the keychain -- these tests must never
    /// raise an ACL prompt.
    ///
    /// The upstream is 127.0.0.1:1, where nothing listens. A request that gets
    /// all the way past the checks therefore fails to connect and answers 502,
    /// which is how these tests tell "allowed through" from "rejected" without
    /// sending a byte anywhere real.
    fn test_router() -> Router {
        router_sharing(None)
    }

    /// `files_dir` is a directory to share, or None for an instance with the
    /// file share switched off.
    fn router_sharing(files_dir: Option<&Path>) -> Router {
        let mut toml = r#"
            bind = "127.0.0.1:9999"

            [[providers]]
            name = "elevenlabs"
            base_url = "http://127.0.0.1:1"
            header = "xi-api-key"
            header_value = "{credential}"
            deny_paths = ["v1/user*"]

            [[providers]]
            name = "pixellab"
            base_url = "http://127.0.0.1:1"
            header = "Authorization"
            "#
        .to_string();
        if let Some(dir) = files_dir {
            toml.push_str(&format!("\n[files]\ndir = {:?}\n", dir.display().to_string()));
        }
        router_from(&toml)
    }

    /// The same wiring for a config written by the test itself.
    fn router_from(toml: &str) -> Router {
        router(state_from(toml))
    }

    /// Validation refuses upstreams on this machine, but these tests need one:
    /// a dead port to tell "let through" from "refused", or a local server. So
    /// the config is validated with each `http://127.0.0.1:` swapped for a
    /// public-looking https origin, and the loopback upstream is planted after.
    fn state_from(toml: &str) -> Arc<AppState> {
        const STAND_IN: &str = "https://upstream.test:";
        let mut config = Config::parse(&toml.replace("http://127.0.0.1:", STAND_IN))
            .expect("test config parses");
        for p in config.providers.values_mut() {
            p.base_url = p.base_url.replace(STAND_IN, "http://127.0.0.1:");
            p.base = reqwest::Url::parse(&p.base_url).expect("planted upstream parses");
        }

        let mut creds = HashMap::new();
        for name in config.providers.keys() {
            creds.insert(name.clone(), Secret::new("FAKE".to_string()));
        }

        let files = config
            .files
            .as_ref()
            .map(|share| FileStore::open(&share.dir).expect("the shared directory opens"));

        let control = Control::new(
            config
                .providers
                .keys()
                .map(String::as_str)
                .chain(files.is_some().then_some("files")),
        );

        Arc::new(AppState {
            config,
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(2))
                // Same policy as production, so the redirect test exercises the
                // real behaviour rather than a laxer stand-in.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client builds"),
            creds: RwLock::new(creds),
            files,
            control,
        })
    }

    async fn send(app: &Router, path: &str, provider_header: Option<&str>) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder().uri(path).header("host", "127.0.0.1:9999");
        if let Some(v) = provider_header {
            req = req.header(PROVIDER_HEADER, v);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).expect("request builds"))
            .await
            .expect("router responds");
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("body reads");
        (status, body.to_vec())
    }

    async fn get(path: &str, provider_header: Option<&str>) -> (StatusCode, String) {
        let (status, body) = send(&test_router(), path, provider_header).await;
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// Like `send`, but the caller picks the method and gets the whole response
    /// back, headers included.
    async fn send_method(app: &Router, method: &str, path: &str, header: Option<&str>) -> Response {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:9999");
        if let Some(v) = header {
            req = req.header(PROVIDER_HEADER, v);
        }
        app.clone()
            .oneshot(req.body(Body::empty()).expect("request builds"))
            .await
            .expect("router responds")
    }

    #[tokio::test]
    async fn provider_header_must_agree_with_the_path() {
        // 502 means it got past every check and tried to dial the upstream --
        // the only outcome here that is not a rejection.
        let (status, _) = get("/elevenlabs/v1/voices", Some("elevenlabs")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "a matching header is forwarded");

        let (status, body) = get("/elevenlabs/v1/voices", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "the header is required");
        assert!(body.contains("missing"), "{body}");

        // A hallucinated route now has to be hallucinated identically twice.
        for wrong in ["pixellab", "elevenlab", "ElevenLabs", "", " elevenlabs"] {
            let (status, _) = get("/elevenlabs/v1/voices", Some(wrong)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "header {wrong:?} must be refused");
        }
    }

    #[tokio::test]
    async fn the_header_does_not_rescue_an_unknown_provider_or_a_denied_path() {
        // Naming a provider that does not exist is still a 404, not a 400: the
        // header check cannot be used to probe which providers are configured.
        let (status, _) = get("/nosuch/v1/voices", Some("nosuch")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // And agreeing with the path does not unlock a denied one.
        let (status, body) = get("/elevenlabs/v1/user", Some("elevenlabs")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("deny_paths"), "{body}");
    }

    /// The denylist has to be judged on the path that goes on the wire, not the
    /// one that came in. `Url::parse` strips dot segments and decodes `%2e`, so
    /// every spelling below leaves this proxy as `/v1/user` -- checking the
    /// request path instead would wave all of them through.
    #[tokio::test]
    async fn dot_segments_cannot_walk_around_the_denylist() {
        for path in [
            "/elevenlabs/v1/./user",
            "/elevenlabs/v1/%2e/user",
            "/elevenlabs/v1/a/../user",
            "/elevenlabs/v1/a/%2e%2e/user",
            "/elevenlabs/./v1/./user",
        ] {
            let (status, body) = get(path, Some("elevenlabs")).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path} must not reach the upstream");
            assert!(body.contains("deny"), "{path}: {body}");
        }

        // The same normalisation must not push a request *out* of the provider's
        // own base path, for a base_url that has one to escape.
        let app = router_from(
            r#"
            bind = "127.0.0.1:9999"

            [[providers]]
            name = "sub"
            base_url = "http://127.0.0.1:1/v1/safe"
            header = "x-key"
            header_value = "{credential}"
            "#,
        );
        let (status, _) = send(&app, "/sub/voices", Some("sub")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "under the base is forwarded");

        // And the rules are still written as upstream paths: the base's own
        // prefix is not something a pattern has to spell out.
        let app_denied = router_from(
            r#"
            bind = "127.0.0.1:9999"

            [[providers]]
            name = "sub"
            base_url = "http://127.0.0.1:1/v1/safe"
            header = "x-key"
            header_value = "{credential}"
            deny_paths = ["voices*"]
            "#,
        );
        let (status, _) = send(&app_denied, "/sub/voices", Some("sub")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        for escape in ["/sub/../../admin", "/sub/%2e%2e/%2e%2e/admin", "/sub/../safe2"] {
            let (status, body) = send(&app, escape, Some("sub")).await;
            let body = String::from_utf8_lossy(&body);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{escape}: {body}");
            assert!(body.contains("outside"), "{escape}: {body}");
        }
    }

    #[tokio::test]
    async fn trace_and_connect_are_never_forwarded() {
        let app = test_router();
        for method in ["TRACE", "CONNECT"] {
            // Even on a path with no denylist entry, and for a provider that
            // exists: the refusal is global and comes first.
            let resp = send_method(&app, method, "/pixellab/v1/anything", Some("pixellab")).await;
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} must be refused"
            );
        }

        // A method that is not on the refused list still goes through.
        let resp = send_method(&app, "PUT", "/pixellab/v1/anything", Some("pixellab")).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn allowlists_are_exhaustive_when_present() {
        let app = router_from(
            r#"
            bind = "127.0.0.1:9999"

            [[providers]]
            name = "narrow"
            base_url = "http://127.0.0.1:1"
            header = "x-key"
            header_value = "{credential}"
            allow_paths = ["v1/tts*"]
            allow_methods = ["GET", "POST"]
            "#,
        );

        // On both lists: forwarded, so it dies at the dial.
        let resp = send_method(&app, "POST", "/narrow/v1/tts/stream", Some("narrow")).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        // Off the path list.
        let (status, body) = send(&app, "/narrow/v1/voices", Some("narrow")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&body).contains("allow_paths"), "{body:?}");

        // On the path list, off the method list.
        let resp = send_method(&app, "DELETE", "/narrow/v1/tts/1", Some("narrow")).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // And an allowlist does not let dot segments in through the back door.
        let (status, _) = send(&app, "/narrow/v1/tts/../voices", Some("narrow")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Both lists are advertised so an agent does not have to learn them by 403.
        let (status, body) = send(&app, "/", None).await;
        assert_eq!(status, StatusCode::OK);
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("allowed_paths"), "{body}");
        assert!(body.contains("allowed_methods"), "{body}");
    }

    /// The one test that needs a real socket: a redirect only exists once an
    /// upstream sends one. It goes to loopback, and the response never leaves
    /// the machine.
    #[tokio::test]
    async fn a_redirect_comes_back_instead_of_being_followed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port is free");
        let port = listener.local_addr().expect("addr").port();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("a connection arrives");
            // Enough of the request to know it is complete; we do not care what
            // it says, only that we get to answer it with a 3xx.
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut sock,
                b"HTTP/1.1 302 Found\r\n\
                  Location: https://evil.example/steal\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await;
        });

        let app = router_from(&format!(
            r#"
            bind = "127.0.0.1:9999"

            [[providers]]
            name = "hop"
            base_url = "http://127.0.0.1:{port}"
            header = "xi-api-key"
            header_value = "{{credential}}"
            "#
        ));

        let resp = send_method(&app, "GET", "/hop/v1/voices", Some("hop")).await;

        // The 3xx is handed to the agent verbatim. If the policy were anything
        // but `none`, reqwest would have chased the Location -- carrying
        // `xi-api-key`, which it has no reason to strip -- and this would be
        // whatever evil.example answered, or a 502 from failing to reach it.
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://evil.example/steal"),
        );
    }

    #[tokio::test]
    async fn discovery_names_the_required_header_but_not_the_injected_one() {
        let (status, body) = get("/", None).await;
        assert_eq!(status, StatusCode::OK);

        // Which header carries the credential is the proxy's business, not the
        // caller's -- knowing the name only helps someone trying to pin it.
        assert!(!body.contains("injects_header"), "{body}");
        assert!(!body.contains("xi-api-key"), "{body}");

        // But the one the caller must send has to be discoverable.
        assert!(body.contains(PROVIDER_HEADER), "{body}");
        assert!(body.contains("denied_paths"), "{body}");
    }

    /// A directory of our own under the system temp dir. Named after the test
    /// that asked for it, so two tests running in parallel cannot collide.
    #[test]
    fn only_the_bind_address_is_an_acceptable_host() {
        let v4: SocketAddr = "100.101.102.103:8788".parse().unwrap();
        assert!(host_allowed(v4, "100.101.102.103:8788"));
        for host in [
            "evil.example:8788",      // rebound to the bind address
            "100.101.102.103",           // wrong (default) port
            "100.101.102.103:8789",
            "localhost:8788",         // not loopback, so not a name for this bind
            "100.101.102.103:8788.evil.example",
            "",
        ] {
            assert!(!host_allowed(v4, host), "{host:?}");
        }

        let lo: SocketAddr = "127.0.0.1:8788".parse().unwrap();
        assert!(host_allowed(lo, "127.0.0.1:8788"));
        assert!(host_allowed(lo, "LocalHost:8788"));
        assert!(!host_allowed(lo, "localhost.evil.example:8788"));
        assert!(!host_allowed(lo, "[::1]:8788"));

        let v6: SocketAddr = "[::1]:8788".parse().unwrap();
        assert!(host_allowed(v6, "[::1]:8788"));
        assert!(host_allowed(v6, "[0:0:0:0:0:0:0:1]:8788"));
        assert!(!host_allowed(v6, "[::1]"));

        let port80: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(host_allowed(port80, "127.0.0.1"));
        assert!(host_allowed(port80, "localhost"));
    }

    #[tokio::test]
    async fn a_request_by_any_other_name_is_refused_on_every_route() {
        let app = test_router();
        for path in ["/", "/healthz", "/files", "/pixellab/v1/anything"] {
            for host in [None, Some("rebound.example:9999")] {
                let mut req = Request::builder().uri(path).header(PROVIDER_HEADER, "pixellab");
                if let Some(h) = host {
                    req = req.header("host", h);
                }
                let resp = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
                assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path} with host {host:?}");
            }
        }
    }

    #[tokio::test]
    async fn pausing_stops_forwarding_and_the_file_drop_but_not_discovery() {
        let dir = temp_dir("paused");
        std::fs::write(dir.join("keep.txt"), b"still here").unwrap();
        let state = state_from(&format!(
            "bind = \"127.0.0.1:9999\"\n\
             [[providers]]\nname = \"pixellab\"\nbase_url = \"http://127.0.0.1:1\"\nheader = \"Authorization\"\n\
             [files]\ndir = {:?}\n",
            dir.display().to_string()
        ));
        let app = router(Arc::clone(&state));

        state.control.set_paused(true);
        for path in ["/pixellab/v1/anything", "/files", "/files/keep.txt", "/nonexistent/x"] {
            let (status, _) = send(&app, path, Some("pixellab")).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path} while paused");
        }
        assert!(dir.join("keep.txt").exists(), "a paused fetch must not consume");
        for path in ["/", "/providers", "/healthz"] {
            let (status, _) = send(&app, path, None).await;
            assert_eq!(status, StatusCode::OK, "{path} while paused");
        }

        state.control.set_paused(false);
        // Past every check and on to the dead upstream, so it was let through.
        let (status, _) = send(&app, "/pixellab/v1/anything", Some("pixellab")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("acp-files-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir is created");
        dir
    }

    #[tokio::test]
    async fn lists_plain_files_and_deletes_each_one_as_it_is_fetched() {
        let dir = temp_dir("list");
        std::fs::write(dir.join("castle.png"), b"PNG-BYTES").unwrap();
        std::fs::write(dir.join("notes.txt"), b"hello").unwrap();
        // None of these are shareable, so none of them may be listed: the
        // listing must never advertise something a fetch would then refuse.
        std::fs::create_dir(dir.join("subdir")).unwrap();
        std::fs::write(dir.join(".hidden"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link.txt")).unwrap();

        let app = router_sharing(Some(&dir));

        let (status, body) = send(&app, "/files", None).await;
        assert_eq!(status, StatusCode::OK);
        let listing: serde_json::Value = serde_json::from_slice(&body).expect("listing is JSON");
        let names: Vec<&str> = listing["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["castle.png", "notes.txt"], "sorted, and nothing else");
        assert_eq!(listing["skipped"], 3, "subdir, dotfile and symlink");
        assert_eq!(listing["files"][0]["bytes"], 9);

        // Fetching hands over the bytes...
        let (status, body) = send(&app, "/files/castle.png", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"PNG-BYTES");

        // ...and consumes the file. Same request again finds nothing.
        assert!(!dir.join("castle.png").exists(), "the file was not deleted");
        let (status, _) = send(&app, "/files/castle.png", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The one we did not ask for is untouched.
        assert!(dir.join("notes.txt").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_name_cannot_reach_outside_the_shared_directory() {
        let dir = temp_dir("escape");
        let outside = dir.parent().unwrap().join("acp-files-secret.txt");
        std::fs::write(&outside, b"NOT-FOR-THE-AGENT").unwrap();
        std::fs::create_dir(dir.join("subdir")).unwrap();
        std::fs::write(dir.join("subdir").join("inner.txt"), b"inner").unwrap();
        std::fs::write(dir.join(".hidden"), b"hidden").unwrap();
        // The interesting one: a link that lives inside the directory but
        // points at something that does not.
        std::os::unix::fs::symlink(&outside, dir.join("innocent.txt")).unwrap();

        let app = router_sharing(Some(&dir));

        for attempt in [
            "/files/../acp-files-secret.txt",
            "/files/..%2Facp-files-secret.txt",
            "/files/%2e%2e%2facp-files-secret.txt",
            "/files/....//acp-files-secret.txt",
            "/files//etc/passwd",
            "/files/%2Fetc%2Fpasswd",
            "/files/subdir/inner.txt",
            "/files/subdir%2Finner.txt",
            "/files/.hidden",
            "/files/innocent.txt",
            "/files/.",
            "/files/..",
        ] {
            let (status, _) = send(&app, attempt, None).await;
            assert!(
                status.is_client_error(),
                "{attempt} was answered with {status}"
            );
        }

        // Nothing outside was read, and above all nothing outside was deleted.
        assert_eq!(std::fs::read(&outside).unwrap(), b"NOT-FOR-THE-AGENT");
        assert!(dir.join("subdir").join("inner.txt").exists());
        assert!(dir.join(".hidden").exists());
        assert!(std::fs::symlink_metadata(dir.join("innocent.txt")).is_ok());

        std::fs::remove_file(&outside).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_symlink_is_refused_rather_than_followed() {
        let dir = temp_dir("symlink");
        let outside = dir.parent().unwrap().join("acp-files-target.txt");
        std::fs::write(&outside, b"TARGET").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("shortcut.txt")).unwrap();

        // A link out of the directory: refused because it does not resolve
        // inside the root.
        let app = router_sharing(Some(&dir));
        let (status, body) = send(&app, "/files/shortcut.txt", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&body).contains("does not resolve inside"));

        // A link to a sibling *inside* the directory resolves fine, so the only
        // thing standing in its way is the O_NOFOLLOW open -- which is the
        // check that has no window for the name to change under it.
        std::fs::write(dir.join("real.txt"), b"REAL").unwrap();
        std::os::unix::fs::symlink(dir.join("real.txt"), dir.join("sibling.txt")).unwrap();
        let (status, body) = send(&app, "/files/sibling.txt", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&body).contains("symlink"));

        // Refusing is not the same as deleting: every link and target survives.
        assert_eq!(std::fs::read(&outside).unwrap(), b"TARGET");
        assert_eq!(std::fs::read(dir.join("real.txt")).unwrap(), b"REAL");
        assert!(std::fs::symlink_metadata(dir.join("sibling.txt")).is_ok());

        std::fs::remove_file(&outside).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `/files/` matches neither file route, so it falls through to the proxy
    /// fallback. It must still get an answer about files, not about providers.
    #[tokio::test]
    async fn a_bare_files_path_is_told_what_to_do() {
        let dir = temp_dir("slash");
        let (status, body) = send(&router_sharing(Some(&dir)), "/files/", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&body).contains("name a file"));

        let (status, body) = send(&test_router(), "/files/", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(String::from_utf8_lossy(&body).contains("not enabled"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_share_is_absent_entirely_when_it_is_not_configured() {
        let app = test_router();

        let (status, body) = send(&app, "/files", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(String::from_utf8_lossy(&body).contains("not enabled"));

        let (status, _) = send(&app, "/files/anything.txt", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // And it is not advertised, so an agent never asks in the first place.
        let (_, discovery) = send(&app, "/", None).await;
        assert!(!String::from_utf8_lossy(&discovery).contains("/files"));
    }

    #[tokio::test]
    async fn discovery_advertises_the_share_without_naming_the_directory() {
        let dir = temp_dir("discovery");
        let (status, body) = send(&router_sharing(Some(&dir)), "/", None).await;
        assert_eq!(status, StatusCode::OK);

        let doc: serde_json::Value = serde_json::from_slice(&body).expect("discovery is JSON");
        assert_eq!(doc["files"]["list"], "/files");
        assert_eq!(doc["files"]["get"], "/files/{name}");

        // The protocol has to be in the document, not just in this README: an
        // agent that guesses at these guesses wrong in the expensive direction.
        let usage = doc["files"]["usage"].as_str().expect("a usage line");
        for must_mention in ["modified_unix", "404", "409", "retrying is safe", "no upload"] {
            assert!(usage.contains(must_mention), "usage omits {must_mention:?}: {usage}");
        }
        // The agent addresses files by name; where they live on this Mac is
        // host layout it has no use for.
        assert!(
            !String::from_utf8_lossy(&body).contains(&dir.display().to_string()),
            "the discovery document leaked the shared directory's path"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn splits_provider_from_rest() {
        assert_eq!(
            split_path("/pixellab/v1/generate"),
            ("pixellab".to_string(), "v1/generate".to_string())
        );
        assert_eq!(split_path("/pixellab"), ("pixellab".to_string(), String::new()));
        assert_eq!(split_path("/"), (String::new(), String::new()));
    }

    #[test]
    fn decodes_escapes_that_would_bypass_a_string_match() {
        // The whole point: these decode to something the denylist knows about.
        assert_eq!(percent_decode("v1%2Fuser").unwrap(), "v1/user");
        assert_eq!(percent_decode("v1/%75ser").unwrap(), "v1/user");
        assert_eq!(percent_decode("%2e%2e/admin").unwrap(), "../admin");
        // Untouched input survives unchanged.
        assert_eq!(percent_decode("v1/text-to-speech").unwrap(), "v1/text-to-speech");
        // Double encoding decodes once, matching what the upstream will do.
        assert_eq!(percent_decode("%252e%252e").unwrap(), "%2e%2e");
        // Malformed input is refused, not guessed at.
        assert!(percent_decode("v1/%2").is_none());
        assert!(percent_decode("v1/%zz").is_none());
        assert!(percent_decode("%ff%fe").is_none()); // not valid UTF-8
    }

    #[test]
    fn preserves_percent_encoding() {
        let (_, rest) = split_path("/eleven/v1/text%2Fspeech");
        assert_eq!(rest, "v1/text%2Fspeech");
    }

    #[test]
    fn builds_urls_with_and_without_query() {
        assert_eq!(
            build_url("https://api.pixellab.ai", "v1/gen", Some("size=64")),
            "https://api.pixellab.ai/v1/gen?size=64"
        );
        assert_eq!(
            build_url("https://api.pixellab.ai", "v1/gen", None),
            "https://api.pixellab.ai/v1/gen"
        );
        assert_eq!(
            build_url("https://api.pixellab.ai", "", None),
            "https://api.pixellab.ai"
        );
    }

    #[test]
    fn strips_client_authorization_and_the_injected_header() {
        let mut incoming = HeaderMap::new();
        incoming.insert("authorization", HeaderValue::from_static("Bearer smuggled"));
        incoming.insert("x-api-key", HeaderValue::from_static("attacker-supplied"));
        incoming.insert("content-type", HeaderValue::from_static("application/json"));
        incoming.insert("connection", HeaderValue::from_static("keep-alive"));
        incoming.insert("host", HeaderValue::from_static("100.101.102.103:8787"));

        incoming.insert(PROVIDER_HEADER, HeaderValue::from_static("bare"));

        let injected = HeaderName::from_static("x-api-key");
        let out = forwardable_headers(&incoming, &injected);

        // Proxy metadata must not leak to the upstream.
        assert!(!out.contains_key(PROVIDER_HEADER));

        // A credential the caller invented must not reach the upstream.
        assert!(!out.contains_key("authorization"));
        // The caller must not be able to pin the credential header themselves.
        assert!(!out.contains_key("x-api-key"));
        assert!(!out.contains_key("connection"));
        assert!(!out.contains_key("host"));
        // Everything else rides along untouched.
        assert_eq!(out.get("content-type").unwrap(), "application/json");
    }
}
