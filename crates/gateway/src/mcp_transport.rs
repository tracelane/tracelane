//! Legacy SSE transport. Every message URL is same-origin, DNS-pinned, and redirect-free.
use crate::{
    admission::Admitted,
    mcp_policy,
    mcp_proxy::{self, McpRoute},
    mcp_store::Server,
    server::AppState,
};
use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;
type Result<T> = std::result::Result<T, &'static str>;
type Frame = std::result::Result<Bytes, std::io::Error>;
struct PendingResponse {
    sender: mpsc::Sender<Frame>,
    responded: bool,
}
struct Connection {
    endpoint: String,
    pending: parking_lot::Mutex<HashMap<String, PendingResponse>>,
    events: mpsc::Sender<Frame>,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<Frame>>>,
    listening: std::sync::atomic::AtomicBool,
    cancel: watch::Sender<bool>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.cancel.send_replace(true);
    }
}
impl Connection {
    async fn open(
        server: &Server,
        headers: &HeaderMap,
        secret: Option<&SecretString>,
    ) -> Result<Arc<Self>> {
        let l = &mcp_policy::settings()
            .map_err(|_| "mcp_policy_invalid")?
            .limits;
        let client = mcp_proxy::safe_client(&server.url).await?;
        let mut response = client
            .get(&server.url)
            .headers(mcp_proxy::outbound_headers(server, headers, secret)?)
            .header("accept", "text/event-stream")
            .timeout(Duration::from_secs(l.legacy_session_secs))
            .send()
            .await
            .map_err(|_| "upstream_unavailable")?;
        status(&response)?;
        if !response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.starts_with("text/event-stream"))
        {
            return Err("invalid_mcp_response");
        }
        let mut buffer = Vec::new();
        let endpoint = loop {
            if let Some(frame) = crate::anthropic_messages::split_frame(&mut buffer) {
                if frame.len() > l.max_event_bytes {
                    return Err("result_too_large");
                }
                let event = mcp_proxy::parse_event(&frame)?;
                if event.event == "endpoint" {
                    break endpoint(&server.url, &event.data)?;
                }
                if !event.data.is_empty() {
                    return Err("invalid_mcp_endpoint");
                }
            } else {
                let chunk = response
                    .chunk()
                    .await
                    .map_err(|_| "upstream_unavailable")?
                    .ok_or("upstream_unavailable")?;
                buffer.extend_from_slice(&chunk);
                if buffer.len() > l.max_event_bytes {
                    return Err("result_too_large");
                }
            }
        };
        // The endpoint is checked again at every POST; this check also refuses it at setup.
        mcp_proxy::safe_client(&endpoint).await?;
        let (events, receiver) = mpsc::channel(l.legacy_event_buffer);
        let (cancel, mut stop) = watch::channel(false);
        let connection = Arc::new(Self {
            endpoint,
            pending: Default::default(),
            events,
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
            listening: Default::default(),
            cancel,
        });
        let weak = Arc::downgrade(&connection);
        tokio::spawn(async move {
            let _reader = Reader(weak.clone());
            loop {
                while let Some(frame) = crate::anthropic_messages::split_frame(&mut buffer) {
                    if frame.len() > l.max_event_bytes {
                        return;
                    }
                    let Ok(event) = mcp_proxy::parse_event(&frame) else {
                        return;
                    };
                    if event.data.is_empty() {
                        continue;
                    }
                    let Ok(value) = serde_json::from_str::<Value>(&event.data) else {
                        return;
                    };
                    let Some(connection) = weak.upgrade() else {
                        return;
                    };
                    if value.get("method").is_none() {
                        if let Some(id) = value.get("id")
                            && let Some(pending) =
                                connection.pending.lock().get_mut(&id.to_string())
                            && !pending.responded
                        {
                            pending.responded = true;
                            if pending
                                .sender
                                .try_send(Ok(mcp_proxy::encode_event(&event)))
                                .is_err()
                            {
                                return;
                            }
                        }
                    } else {
                        // Deliver a server request once, to GET or one active request stream.
                        let sender = if connection
                            .listening
                            .load(std::sync::atomic::Ordering::Acquire)
                        {
                            connection.events.clone()
                        } else {
                            connection
                                .pending
                                .lock()
                                .values()
                                .find(|p| !p.responded)
                                .map(|p| p.sender.clone())
                                .unwrap_or_else(|| connection.events.clone())
                        };
                        if sender
                            .try_send(Ok(mcp_proxy::encode_event(&event)))
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                if buffer.len() > l.max_event_bytes {
                    return;
                }
                tokio::select! {
                    _=stop.changed()=>return,
                    chunk=response.chunk()=>match chunk {Ok(Some(c))=>buffer.extend_from_slice(&c),_=>return}
                }
            }
        });
        Ok(connection)
    }
    async fn rpc(
        self: &Arc<Self>,
        server: &Server,
        headers: &HeaderMap,
        secret: Option<&SecretString>,
        body: &Value,
        fresh: impl std::future::Future<Output = Result<()>>,
    ) -> Result<reqwest::Response> {
        let l = &mcp_policy::settings()
            .map_err(|_| "mcp_policy_invalid")?
            .limits;
        if *self.cancel.borrow() {
            return Err("upstream_unavailable");
        }
        let client = mcp_proxy::safe_client(&self.endpoint).await?;
        let outgoing = mcp_proxy::outbound_headers(server, headers, secret)?;
        let mut pending = if body.get("method").is_some() {
            body.get("id")
                .map(|id| {
                    let id = id.to_string();
                    let (sender, receiver) = mpsc::channel(l.legacy_event_buffer);
                    let mut pending = self.pending.lock();
                    if pending.contains_key(&id) {
                        return Err("mcp_duplicate_request_id");
                    }
                    if pending.len() >= l.max_pending_calls_per_session {
                        return Err("mcp_session_capacity");
                    }
                    pending.insert(
                        id.clone(),
                        PendingResponse {
                            sender,
                            responded: false,
                        },
                    );
                    Ok((
                        Pending {
                            connection: Arc::downgrade(self),
                            id,
                        },
                        receiver,
                    ))
                })
                .transpose()?
        } else {
            None
        };
        fresh.await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(l.call_timeout_secs);
        let response = client
            .post(&self.endpoint)
            .headers(outgoing)
            .json(body)
            .timeout(Duration::from_secs(l.call_timeout_secs))
            .send()
            .await
            .map_err(|_| "upstream_unavailable")?;
        status(&response)?;
        let Some((guard, mut receive)) = pending.take() else {
            return reply(
                StatusCode::ACCEPTED,
                reqwest::Body::from(Bytes::new()),
                false,
            );
        };
        let id = body["id"].clone();
        let connection = self.clone();
        let stream = async_stream::stream! {
            let _guard=guard;let _connection=connection;
            loop {
                let frame=tokio::time::timeout_at(deadline,receive.recv()).await;
                match frame {
                    Ok(Some(Ok(bytes)))=>{
                        let done=mcp_proxy::parse_event(&bytes).ok().and_then(|e|serde_json::from_str::<Value>(&e.data).ok()).is_some_and(|v|v.get("method").is_none()&&v.get("id")==Some(&id));
                        yield Ok::<_,std::io::Error>(bytes);if done{break}
                    },
                    _=>{yield Err(std::io::Error::other("upstream unavailable"));break}
                }
            }
        };
        reply(StatusCode::OK, reqwest::Body::wrap_stream(stream), true)
    }
    fn stream(self: &Arc<Self>) -> Result<reqwest::Response> {
        if *self.cancel.borrow() {
            return Err("upstream_unavailable");
        }
        let mut receiver = self
            .receiver
            .clone()
            .try_lock_owned()
            .map_err(|_| "mcp_session_in_use")?;
        self.listening
            .store(true, std::sync::atomic::Ordering::Release);
        let connection = self.clone();
        let mut stop = self.cancel.subscribe();
        let stream = async_stream::stream! {
            let _listener=Listener(connection);
            loop{tokio::select!{_ = stop.changed()=>break,frame=receiver.recv()=>match frame{Some(frame)=>yield frame,None=>break}}}
        };
        reply(StatusCode::OK, reqwest::Body::wrap_stream(stream), true)
    }
}
struct Reader(Weak<Connection>);
impl Drop for Reader {
    fn drop(&mut self) {
        if let Some(c) = self.0.upgrade() {
            c.pending.lock().clear();
            let _ = c.cancel.send_replace(true);
        }
    }
}
struct Listener(Arc<Connection>);
impl Drop for Listener {
    fn drop(&mut self) {
        self.0
            .listening
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
struct Pending {
    connection: Weak<Connection>,
    id: String,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(c) = self.connection.upgrade() {
            c.pending.lock().remove(&self.id);
        }
    }
}
fn status(response: &reqwest::Response) -> Result<()> {
    match response.status().as_u16() {
        401 | 403 | 407 => Err("upstream_unauthorized"),
        300..=399 => Err("upstream_redirect"),
        200..=299 => Ok(()),
        _ => Err("upstream_unavailable"),
    }
}
fn endpoint(base: &str, value: &str) -> Result<String> {
    let base = reqwest::Url::parse(base).map_err(|_| "invalid_mcp_endpoint")?;
    let target = base.join(value).map_err(|_| "invalid_mcp_endpoint")?;
    if target.origin() != base.origin()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Err("invalid_mcp_endpoint");
    }
    Ok(target.to_string())
}
fn reply(status: StatusCode, body: reqwest::Body, sse: bool) -> Result<reqwest::Response> {
    let mut reply = axum::http::Response::builder().status(status);
    if sse {
        reply = reply.header("content-type", "text/event-stream");
    }
    reply
        .body(body)
        .map(reqwest::Response::from)
        .map_err(|_| "upstream_unavailable")
}
struct Session {
    tenant: Uuid,
    caller: String,
    context: String,
    started: Instant,
    connection: Arc<Connection>,
}
fn sessions() -> &'static parking_lot::Mutex<HashMap<Uuid, Arc<Session>>> {
    static S: OnceLock<parking_lot::Mutex<HashMap<Uuid, Arc<Session>>>> = OnceLock::new();
    S.get_or_init(Default::default)
}
fn opening_sessions() -> &'static parking_lot::Mutex<HashMap<Uuid, usize>> {
    static S: OnceLock<parking_lot::Mutex<HashMap<Uuid, usize>>> = OnceLock::new();
    S.get_or_init(Default::default)
}
struct OpeningSession(Uuid);
impl Drop for OpeningSession {
    fn drop(&mut self) {
        let mut opening = opening_sessions().lock();
        if let Some(count) = opening.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                opening.remove(&self.0);
            }
        }
    }
}
fn commit_opening(id: Uuid, session: Arc<Session>, opening: OpeningSession) {
    let mut all = sessions().lock();
    // A capacity check holds this same lock before reading opening_sessions.
    drop(opening);
    all.insert(id, session);
}
pub(crate) fn context(
    tenant: &tracelane_shared::TenantId,
    server: &Server,
    secret: Option<&SecretString>,
) -> Result<String> {
    let key = crate::tool_fingerprint::workspace_key(tenant).ok_or("mcp_policy_invalid")?;
    let mut hash = blake3::Hasher::new_keyed(key.expose_secret());
    hash.update(b"mcp-session-v1");
    let config = serde_json::to_vec(server).map_err(|_| "mcp_policy_invalid")?;
    for part in [
        config.as_slice(),
        secret.map_or("", |s| s.expose_secret()).as_bytes(),
    ] {
        hash.update(&(part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    Ok(hash.finalize().to_hex().to_string())
}
pub(crate) fn close(id: &str) {
    if let Ok(id) = Uuid::parse_str(id) {
        streamable_sessions().lock().remove(&id);
    }
    if let Ok(id) = Uuid::parse_str(id)
        && let Some(s) = sessions().lock().remove(&id)
    {
        let _ = s.connection.cancel.send_replace(true);
    }
}
/// Reject unknown/foreign legacy handles before any credentialed discovery.
pub(crate) fn validate_session(
    claims: &crate::auth::Claims,
    server: &Server,
    secret: Option<&SecretString>,
    headers: &HeaderMap,
    method: &str,
) -> Result<()> {
    let Some(raw) = headers.get("mcp-session-id") else {
        return if method == "initialize" {
            Ok(())
        } else {
            Err("mcp_session_required")
        };
    };
    let id = raw
        .to_str()
        .ok()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("mcp_session_not_found")?;
    let context = context(&claims.tenant_id, server, secret)?;
    let all = sessions().lock();
    let session = all.get(&id).ok_or("mcp_session_not_found")?;
    let ttl = mcp_policy::settings()
        .map_err(|_| "mcp_policy_invalid")?
        .limits
        .legacy_session_secs;
    if session.tenant != *claims.tenant_id.as_uuid()
        || session.caller != claims.sub
        || session.context != context
        || session.started.elapsed() >= Duration::from_secs(ttl)
    {
        return Err("mcp_session_not_found");
    }
    Ok(())
}

/// A committed server change invalidates execution context and releases its capacity.
pub(crate) fn evict_tenant(tenant: Uuid) {
    streamable_sessions()
        .lock()
        .retain(|_, s| s.tenant != tenant);
    sessions().lock().retain(|_, s| {
        if s.tenant == tenant {
            s.connection.cancel.send_replace(true);
            false
        } else {
            true
        }
    });
    downstream().lock().retain(|_, s| {
        if s.tenant == tenant {
            s.cancel.send_replace(true);
            false
        } else {
            true
        }
    });
}
pub async fn request<const INVOKE: bool>(
    state: &AppState,
    headers: &HeaderMap,
    server: &Server,
    secret: Option<&SecretString>,
    a: &Admitted<McpRoute<INVOKE>>,
) -> Result<reqwest::Response> {
    let l = &mcp_policy::settings()
        .map_err(|_| "mcp_policy_invalid")?
        .limits;
    let context = context(&a.claims.tenant_id, server, secret)?;
    let supplied = headers.get("mcp-session-id").and_then(|h| h.to_str().ok());
    let (id, session) = if let Some(raw) = supplied {
        let id = Uuid::parse_str(raw).map_err(|_| "mcp_session_not_found")?;
        let session = sessions()
            .lock()
            .get(&id)
            .cloned()
            .ok_or("mcp_session_not_found")?;
        if session.tenant != *a.claims.tenant_id.as_uuid()
            || session.caller != a.claims.sub
            || session.context != context
            || session.started.elapsed() > Duration::from_secs(l.legacy_session_secs)
        {
            return Err("mcp_session_not_found");
        }
        (id, session)
    } else {
        if a.parsed.method != "initialize" {
            return Err("mcp_session_required");
        }
        let opening = {
            let mut all = sessions().lock();
            all.retain(|_, s| s.started.elapsed() < Duration::from_secs(l.legacy_session_secs));
            let mut opening = opening_sessions().lock();
            if all.len() + opening.values().sum::<usize>() >= l.max_legacy_sessions_total
                || all
                    .values()
                    .filter(|s| s.tenant == *a.claims.tenant_id.as_uuid())
                    .count()
                    + opening
                        .get(a.claims.tenant_id.as_uuid())
                        .copied()
                        .unwrap_or(0)
                    >= l.max_legacy_sessions_per_workspace
            {
                return Err("mcp_session_capacity");
            }
            *opening.entry(*a.claims.tenant_id.as_uuid()).or_default() += 1;
            OpeningSession(*a.claims.tenant_id.as_uuid())
        };
        let connection = tokio::time::timeout(
            Duration::from_secs(l.call_timeout_secs),
            Connection::open(server, headers, secret),
        )
        .await
        .map_err(|_| "upstream_timeout")??;
        let session = Arc::new(Session {
            tenant: *a.claims.tenant_id.as_uuid(),
            caller: a.claims.sub.clone(),
            context,
            started: Instant::now(),
            connection,
        });
        let id = Uuid::new_v4();
        commit_opening(id, session.clone(), opening);
        (id, session)
    };
    let mut response = if a.parsed.http_method == Method::DELETE {
        close(&id.to_string());
        reply(
            StatusCode::NO_CONTENT,
            reqwest::Body::from(Bytes::new()),
            false,
        )?
    } else if a.parsed.http_method == Method::GET {
        session.connection.stream()?
    } else {
        session
            .connection
            .rpc(server, headers, secret, &a.parsed.envelope, async {
                mcp_policy::ensure_fresh(state, headers, &a.claims, a.entitlements.as_ref())
                    .await
                    .map_err(|_| "control_changed")
            })
            .await?
    };
    response.headers_mut().insert(
        "mcp-session-id",
        HeaderValue::from_str(&id.to_string()).map_err(|_| "mcp_session_not_found")?,
    );
    Ok(response)
}
/// Verification is an ephemeral session, never the execution connection.
pub async fn discover(server: &Server, secret: Option<&SecretString>) -> Result<Value> {
    let headers = HeaderMap::new();
    let connection = Connection::open(server, &headers, secret).await?;
    let init = json!({"jsonrpc":"2.0","id":"verify-init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"tracelane","version":env!("CARGO_PKG_VERSION")}}});
    let reply = connection
        .rpc(server, &headers, secret, &init, async { Ok(()) })
        .await?;
    let initialized = mcp_proxy::read_rpc(reply, &init).await?;
    if initialized.get("error").is_some() {
        return Err("mcp_tool_unverifiable");
    }
    connection
        .rpc(
            server,
            &headers,
            secret,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            async { Ok(()) },
        )
        .await?;
    let mut collected = json!({"jsonrpc":"2.0","id":"verify-tools","result":{"tools":[]}});
    let mut cursor = None;
    let max_pages = mcp_policy::settings()
        .map_err(|_| "mcp_policy_invalid")?
        .limits
        .max_tool_list_pages;
    for _ in 0..max_pages {
        let mut body = json!({"jsonrpc":"2.0","id":"verify-tools","method":"tools/list"});
        if let Some(value) = cursor {
            body["params"] = json!({"cursor":value});
        }
        let reply = connection
            .rpc(server, &headers, secret, &body, async { Ok(()) })
            .await?;
        let page = mcp_proxy::read_rpc(reply, &body).await?;
        cursor = mcp_proxy::append_discovered_tools(&mut collected, page)?;
        if cursor.is_none() {
            return Ok(collected);
        }
    }
    Err("mcp_tool_unverifiable")
}

struct Downstream {
    cancel: watch::Sender<bool>,
    reader_started: std::sync::atomic::AtomicBool,
    tenant: Uuid,
    caller: String,
    slug: String,
    context: String,
    started: Instant,
    sender: mpsc::Sender<Bytes>,
    upstream: parking_lot::Mutex<Option<HeaderValue>>,
}
fn downstream() -> &'static parking_lot::Mutex<HashMap<Uuid, Arc<Downstream>>> {
    static S: OnceLock<parking_lot::Mutex<HashMap<Uuid, Arc<Downstream>>>> = OnceLock::new();
    S.get_or_init(Default::default)
}
struct DownstreamGuard(Uuid);
impl Drop for DownstreamGuard {
    fn drop(&mut self) {
        if let Some(session) = downstream().lock().remove(&self.0) {
            session.cancel.send_replace(true);
            if let Some(id) = session
                .upstream
                .lock()
                .as_ref()
                .and_then(|h| h.to_str().ok())
            {
                close(id);
            }
        }
    }
}
pub async fn listen(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    use crate::admission::Route;
    use axum::{body::Body, response::IntoResponse};
    let request = mcp_proxy::McpRequest {
        raw_body: None,
        protected: Default::default(),
        slug: slug.clone(),
        method: "$session".into(),
        envelope: json!({}),
        http_method: Method::GET,
    };
    let a = match crate::admission::admit::<McpRoute<false>>(&state, &headers, request).await {
        Ok(a) => a,
        Err(e) => return McpRoute::<false>::refuse(e),
    };
    let Some(snapshot) = a.entitlements.as_ref().and_then(|e| e.mcp.as_ref()) else {
        return mcp_proxy::error(StatusCode::FORBIDDEN, "mcp_policy_invalid");
    };
    let Some(server) = snapshot.servers.iter().find(|s| s.slug == slug) else {
        return mcp_proxy::error(StatusCode::NOT_FOUND, "mcp_server_not_found");
    };
    let secret = match mcp_proxy::credential(snapshot, server, &a.claims.tenant_id, &headers).await
    {
        Ok(s) => s,
        Err(e) => return mcp_proxy::error(StatusCode::BAD_GATEWAY, e),
    };
    let context = match context(&a.claims.tenant_id, server, secret.as_ref()) {
        Ok(c) => c,
        Err(e) => return mcp_proxy::error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let Ok(settings) = mcp_policy::settings() else {
        return mcp_proxy::error(StatusCode::SERVICE_UNAVAILABLE, "mcp_policy_invalid");
    };
    let limits = &settings.limits;
    let (sender, mut receive) = mpsc::channel(limits.legacy_event_buffer);
    let (cancel, mut cancelled) = watch::channel(false);
    let id = Uuid::new_v4();
    {
        let mut all = downstream().lock();
        all.retain(|_, s| {
            s.started.elapsed() < Duration::from_secs(limits.legacy_session_secs)
                && !s.sender.is_closed()
        });
        if all.len() >= limits.max_legacy_sessions_total
            || all
                .values()
                .filter(|s| s.tenant == *a.claims.tenant_id.as_uuid())
                .count()
                >= limits.max_legacy_sessions_per_workspace
        {
            return mcp_proxy::error(StatusCode::TOO_MANY_REQUESTS, "mcp_session_capacity");
        }
        all.insert(
            id,
            Arc::new(Downstream {
                cancel,
                reader_started: Default::default(),
                tenant: *a.claims.tenant_id.as_uuid(),
                caller: a.claims.sub,
                slug: slug.clone(),
                context,
                started: Instant::now(),
                sender,
                upstream: Default::default(),
            }),
        );
    }
    let guard = DownstreamGuard(id);
    let stream = async_stream::stream! {
        let _guard = guard;
        yield Ok::<_,std::io::Error>(mcp_proxy::encode_event(&mcp_proxy::Event { event:"endpoint".into(), data:format!("/v1/mcp/{slug}/messages?sessionId={id}"), id:None }));
        let expires = tokio::time::sleep(Duration::from_secs(limits.legacy_session_secs));
        tokio::pin!(expires);
        loop { tokio::select! { _ = &mut expires=>break, _ = cancelled.changed()=>break, frame=receive.recv()=>match frame { Some(frame)=>yield Ok(frame), None=>break } } }
    };
    (
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}
#[derive(serde::Deserialize)]
pub struct SessionQuery {
    #[serde(rename = "sessionId")]
    session_id: Uuid,
}
pub async fn message(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    query: std::result::Result<
        axum::extract::Query<SessionQuery>,
        axum::extract::rejection::QueryRejection,
    >,
    mut headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let claims = match crate::auth::validate_authorization(
        headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default(),
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return mcp_proxy::error(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    if !claims.allows_scope(crate::auth::scope::Scope::Mcp) {
        return mcp_proxy::error(StatusCode::FORBIDDEN, "insufficient_scope");
    }
    let query = match query {
        Ok(axum::extract::Query(query)) => query,
        Err(_) => return mcp_proxy::error(StatusCode::BAD_REQUEST, "invalid_mcp_session"),
    };
    let Some(session) = downstream().lock().get(&query.session_id).cloned() else {
        return mcp_proxy::error(StatusCode::NOT_FOUND, "mcp_session_not_found");
    };
    let Ok(settings) = mcp_policy::settings() else {
        return mcp_proxy::error(StatusCode::SERVICE_UNAVAILABLE, "mcp_policy_invalid");
    };
    if session.tenant != *claims.tenant_id.as_uuid()
        || session.caller != claims.sub
        || session.slug != slug
        || session.started.elapsed() >= Duration::from_secs(settings.limits.legacy_session_secs)
    {
        return mcp_proxy::error(StatusCode::NOT_FOUND, "mcp_session_not_found");
    }
    // This preflight only binds the connection. The ordinary handler admits every POST.
    let Some(cache) = state.entitlements.as_ref() else {
        return mcp_proxy::error(StatusCode::SERVICE_UNAVAILABLE, "mcp_policy_invalid");
    };
    let snapshot = cache.resolved(*claims.tenant_id.as_uuid()).await;
    let Some(snapshot) = snapshot.mcp.as_ref() else {
        return mcp_proxy::error(StatusCode::FORBIDDEN, "mcp_policy_invalid");
    };
    let Some(server) = snapshot.servers.iter().find(|s| s.slug == slug) else {
        return mcp_proxy::error(StatusCode::NOT_FOUND, "mcp_server_not_found");
    };
    let secret = match mcp_proxy::credential(snapshot, server, &claims.tenant_id, &headers).await {
        Ok(s) => s,
        Err(e) => return mcp_proxy::error(StatusCode::BAD_GATEWAY, e),
    };
    if context(&claims.tenant_id, server, secret.as_ref())
        .ok()
        .as_ref()
        != Some(&session.context)
    {
        return mcp_proxy::error(StatusCode::NOT_FOUND, "mcp_session_not_found");
    }
    let permit = match session.sender.clone().try_reserve_owned() {
        Ok(p) => p,
        Err(_) => return mcp_proxy::error(StatusCode::TOO_MANY_REQUESTS, "mcp_session_capacity"),
    };
    headers.remove("mcp-session-id");
    if let Some(id) = session.upstream.lock().as_ref() {
        headers.insert("mcp-session-id", id.clone());
    }
    let initialize = serde_json::from_slice::<Value>(&body)
        .ok()
        .is_some_and(|v| v["method"] == "initialize");
    let event_state = state.clone();
    let event_slug = slug.clone();
    let mut event_headers = headers.clone();
    let response = mcp_proxy::handle(
        axum::extract::State(state),
        axum::extract::Path(slug),
        Method::POST,
        headers,
        body,
    )
    .await;
    if !response.status().is_success() {
        return response;
    }
    if let Some(id) = response.headers().get("mcp-session-id") {
        *session.upstream.lock() = Some(id.clone());
        event_headers.insert("mcp-session-id", id.clone());
    }
    if initialize
        && !session
            .reader_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        let session = session.clone();
        tokio::spawn(async move {
            let mut cancelled = session.cancel.subscribe();
            if *cancelled.borrow() {
                return;
            }
            let response = tokio::select! {
                _=cancelled.changed()=>return,
                reply=mcp_proxy::handle(axum::extract::State(event_state),axum::extract::Path(event_slug),Method::GET,event_headers,Bytes::new())=>reply
            };
            if response.status().is_success() {
                forward(response, session, None).await;
            }
        });
    }
    if response.status() == StatusCode::ACCEPTED || response.status() == StatusCode::NO_CONTENT {
        return StatusCode::ACCEPTED.into_response();
    }
    // The proxy already bounded and inspected the body.
    tokio::spawn(forward(response, session, Some(permit)));
    StatusCode::ACCEPTED.into_response()
}
async fn forward(
    response: axum::response::Response,
    session: Arc<Downstream>,
    mut permit: Option<mpsc::OwnedPermit<Bytes>>,
) {
    use futures::StreamExt;
    let sse = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.starts_with("text/event-stream"));
    let mut cancelled = session.cancel.subscribe();
    if *cancelled.borrow() {
        return;
    }
    let mut stream = response.into_body().into_data_stream();
    loop {
        let next = tokio::select! {_=cancelled.changed()=>break,next=stream.next()=>next};
        let bytes = match next {
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => {
                session.cancel.send_replace(true);
                break;
            }
            None => break,
        };
        let bytes = if sse {
            bytes
        } else {
            mcp_proxy::encode_event(&mcp_proxy::Event {
                event: "message".into(),
                data: String::from_utf8_lossy(&bytes).into_owned(),
                id: None,
            })
        };
        if let Some(p) = permit.take() {
            p.send(bytes);
        } else if session.sender.try_send(bytes).is_err() {
            session.cancel.send_replace(true);
            break;
        }
    }
}

struct StreamableSession {
    tenant: Uuid,
    caller: String,
    context: String,
    upstream: HeaderValue,
    started: Instant,
}
fn streamable_sessions() -> &'static parking_lot::Mutex<HashMap<Uuid, StreamableSession>> {
    static S: OnceLock<parking_lot::Mutex<HashMap<Uuid, StreamableSession>>> = OnceLock::new();
    S.get_or_init(Default::default)
}
pub(crate) fn streamable_headers(
    claims: &crate::auth::Claims,
    server: &Server,
    secret: Option<&SecretString>,
    headers: &HeaderMap,
) -> Result<(HeaderMap, Option<Uuid>)> {
    let mut outgoing = mcp_proxy::outbound_headers(server, headers, secret)?;
    let Some(raw) = headers.get("mcp-session-id") else {
        return Ok((outgoing, None));
    };
    let id = raw
        .to_str()
        .ok()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("mcp_session_not_found")?;
    let context = context(&claims.tenant_id, server, secret)?;
    let limits = &mcp_policy::settings()
        .map_err(|_| "mcp_policy_invalid")?
        .limits;
    let all = streamable_sessions().lock();
    let s = all.get(&id).ok_or("mcp_session_not_found")?;
    if s.tenant != *claims.tenant_id.as_uuid()
        || s.caller != claims.sub
        || s.context != context
        || s.started.elapsed() >= Duration::from_secs(limits.legacy_session_secs)
    {
        return Err("mcp_session_not_found");
    }
    outgoing.insert("mcp-session-id", s.upstream.clone());
    Ok((outgoing, Some(id)))
}
pub(crate) fn streamable_response(
    claims: &crate::auth::Claims,
    context: String,
    method: &Method,
    rpc_method: &str,
    current: Option<Uuid>,
    response: &mut reqwest::Response,
) -> Result<()> {
    let limits = &mcp_policy::settings()
        .map_err(|_| "mcp_policy_invalid")?
        .limits;
    let mut all = streamable_sessions().lock();
    if *method == Method::DELETE && response.status().is_success() {
        if let Some(id) = current {
            all.remove(&id);
        }
        response.headers_mut().remove("mcp-session-id");
        return Ok(());
    }
    let Some(upstream) = response.headers().get("mcp-session-id").cloned() else {
        return Ok(());
    };
    if !response.status().is_success() {
        response.headers_mut().remove("mcp-session-id");
        return Ok(());
    }
    if upstream.as_bytes().is_empty()
        || upstream.as_bytes().len() > limits.max_header_bytes
        || !upstream.as_bytes().iter().all(|c| c.is_ascii_graphic())
    {
        return Err("invalid_mcp_session");
    }
    let id = if let Some(id) = current {
        let session = all.get_mut(&id).ok_or("mcp_session_not_found")?;
        session.upstream = upstream;
        id
    } else {
        if rpc_method != "initialize" {
            return Err("invalid_mcp_session");
        }
        all.retain(|_, s| s.started.elapsed() < Duration::from_secs(limits.legacy_session_secs));
        if all.len() >= limits.max_legacy_sessions_total
            || all
                .values()
                .filter(|s| s.tenant == *claims.tenant_id.as_uuid())
                .count()
                >= limits.max_legacy_sessions_per_workspace
        {
            return Err("mcp_session_capacity");
        }
        let id = Uuid::new_v4();
        all.insert(
            id,
            StreamableSession {
                tenant: *claims.tenant_id.as_uuid(),
                caller: claims.sub.clone(),
                context,
                upstream,
                started: Instant::now(),
            },
        );
        id
    };
    response.headers_mut().insert(
        "mcp-session-id",
        HeaderValue::from_str(&id.to_string()).map_err(|_| "invalid_mcp_session")?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (crate::auth::Claims, Server) {
        crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
        let claims = crate::auth::Claims {
            tenant_id: tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4()),
            sub: format!("caller:{}", Uuid::new_v4()),
            ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
        };
        let server=serde_json::from_value(json!({"id":Uuid::new_v4(),"slug":"test","name":"Test","url":"https://example.com/mcp","transport":"streamable_http","auth_mode":"passthrough","credential_kind":"bearer","credential_header":null,"credential_ct":null,"credential_last4":null,"enabled":true})).unwrap();
        (claims, server)
    }
    fn initialize(
        claims: &crate::auth::Claims,
        server: &Server,
        secret: &SecretString,
    ) -> Result<HeaderValue> {
        let mut reply = reply(StatusCode::OK, reqwest::Body::from(Bytes::new()), false)?;
        reply.headers_mut().insert(
            "mcp-session-id",
            HeaderValue::from_static("private-upstream-session"),
        );
        streamable_response(
            claims,
            context(&claims.tenant_id, server, Some(secret))?,
            &Method::POST,
            "initialize",
            None,
            &mut reply,
        )?;
        Ok(reply.headers()["mcp-session-id"].clone())
    }
    #[test]
    fn principal_token_never_forwarded() {
        let (claims, server) = fixture();
        let secret = SecretString::from("synthetic-upstream-key");
        let mut headers = HeaderMap::new();
        headers.insert(
            "tracelane-principal",
            HeaderValue::from_static("synthetic-principal-token"),
        );
        headers.insert(
            "x-human-authorizer",
            HeaderValue::from_static("unverified-assertion"),
        );
        let (outgoing, _) = streamable_headers(&claims, &server, Some(&secret), &headers).unwrap();
        assert!(!outgoing.contains_key("tracelane-principal"));
        assert!(!outgoing.contains_key("x-human-authorizer"));
    }
    #[test]
    fn mcp_streamable_sessions_bind_tenant_caller_configuration_and_credential() {
        let (claims, server) = fixture();
        let secret = SecretString::from("account-a");
        let token = initialize(&claims, &server, &secret).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", token.clone());
        let (outgoing, id) = streamable_headers(&claims, &server, Some(&secret), &headers).unwrap();
        assert_eq!(outgoing["mcp-session-id"], "private-upstream-session");
        let mut changed = claims.clone();
        changed.sub = "other-caller".into();
        assert!(streamable_headers(&changed, &server, Some(&secret), &headers).is_err());
        changed = claims.clone();
        changed.tenant_id = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
        assert!(streamable_headers(&changed, &server, Some(&secret), &headers).is_err());
        let mut changed = server.clone();
        changed.url = "https://other.example.com/mcp".into();
        assert!(streamable_headers(&claims, &changed, Some(&secret), &headers).is_err());
        assert!(
            streamable_headers(
                &claims,
                &server,
                Some(&SecretString::from("account-b")),
                &headers
            )
            .is_err()
        );
        streamable_sessions()
            .lock()
            .get_mut(&id.unwrap())
            .unwrap()
            .started = Instant::now()
            - Duration::from_secs(mcp_policy::settings().unwrap().limits.legacy_session_secs);
        assert!(streamable_headers(&claims, &server, Some(&secret), &headers).is_err());
        close(token.to_str().unwrap());
        assert!(streamable_headers(&claims, &server, Some(&secret), &headers).is_err());
    }
    #[test]
    fn mcp_streamable_sessions_enforce_workspace_capacity_and_delete_cleanup() {
        let (claims, server) = fixture();
        let secret = SecretString::from("account-a");
        let limits = &mcp_policy::settings().unwrap().limits;
        let mut tokens = Vec::new();
        for _ in 0..limits.max_legacy_sessions_per_workspace {
            tokens.push(initialize(&claims, &server, &secret).unwrap());
        }
        assert_eq!(
            initialize(&claims, &server, &secret).unwrap_err(),
            "mcp_session_capacity"
        );
        let first = tokens.pop().unwrap();
        let id = Uuid::parse_str(first.to_str().unwrap()).unwrap();
        let mut response = reply(
            StatusCode::NO_CONTENT,
            reqwest::Body::from(Bytes::new()),
            false,
        )
        .unwrap();
        streamable_response(
            &claims,
            context(&claims.tenant_id, &server, Some(&secret)).unwrap(),
            &Method::DELETE,
            "$session",
            Some(id),
            &mut response,
        )
        .unwrap();
        assert!(!streamable_sessions().lock().contains_key(&id));
        tokens.push(initialize(&claims, &server, &secret).unwrap());
        for token in tokens {
            close(token.to_str().unwrap());
        }
    }
    #[test]
    fn mcp_legacy_endpoint_refuses_other_origin_userinfo_and_fragment() {
        assert_eq!(
            endpoint("https://example.com/sse", "/messages?session=x").unwrap(),
            "https://example.com/messages?session=x"
        );
        for target in [
            "https://other.example.com/messages",
            "http://example.com/messages",
            "https://user@example.com/messages",
            "/messages#fragment",
            "https://example.com:8443/messages",
        ] {
            assert!(
                endpoint("https://example.com/sse", target).is_err(),
                "{target}"
            );
        }
    }
    #[tokio::test]
    async fn mcp_legacy_notification_after_result_waits_for_get_listener() {
        use axum::{
            Json, Router,
            body::Body,
            routing::{get, post},
        };
        let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
        let (sender, receive) = mpsc::channel::<Bytes>(8);
        let receive = Arc::new(tokio::sync::Mutex::new(Some(receive)));
        let app=Router::new().route("/sse",get(move||{let receive=receive.clone();async move{
            let mut receive=receive.lock().await.take().unwrap();let stream=async_stream::stream!{yield Ok::<_,std::io::Error>(Bytes::from_static(b"event: endpoint\ndata: /messages\n\n"));while let Some(frame)=receive.recv().await{yield Ok(frame)}};
            ([("content-type","text/event-stream")],Body::from_stream(stream))
        }})).route("/messages",post(move|Json(v):Json<Value>|{let sender=sender.clone();async move{
            let response=mcp_proxy::encode_event(&mcp_proxy::Event{event:"message".into(),id:None,data:json!({"jsonrpc":"2.0","id":v["id"],"result":{}}).to_string()});
            let notice=mcp_proxy::encode_event(&mcp_proxy::Event{event:"message".into(),id:None,data:json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}).to_string()});
            let mut both=response.to_vec();both.extend_from_slice(&notice);sender.send(Bytes::from(both)).await.unwrap();StatusCode::ACCEPTED
        }}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (_, mut server) = fixture();
        server.url = format!("http://{addr}/sse");
        server.auth_mode = "none".into();
        server.transport = "legacy_sse".into();
        let connection = Connection::open(&server, &HeaderMap::new(), None)
            .await
            .unwrap();
        let body = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}});
        let response = connection
            .rpc(&server, &HeaderMap::new(), None, &body, async { Ok(()) })
            .await
            .unwrap();
        assert_eq!(mcp_proxy::read_rpc(response, &body).await.unwrap()["id"], 0);
        let mut events = connection.stream().unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(2), events.chunk()).await;
        task.abort();
        let frame = frame
            .expect("post-result notification must remain available for GET")
            .unwrap()
            .unwrap();
        assert!(
            mcp_proxy::parse_event(&frame)
                .unwrap()
                .data
                .contains("notifications/tools/list_changed")
        );
    }
}

#[cfg(test)]
#[path = "../tests/support/mcp_transport_quality_fix_tests.rs"]
mod quality_fix_tests;
