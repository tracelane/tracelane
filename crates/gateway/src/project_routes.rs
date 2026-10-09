//! `OG-23` — `/v1/projects`: a tenant's projects (named groups of API keys, with the
//! environments their keys may carry) and, `OG-20`, the policy each project imposes on
//! its keys. Spec: `specs/OG-23-projects-environments.md`, `specs/OG-20-per-key-policy.md`.
//!
//! | Route | Who |
//! |---|---|
//! | `GET /v1/projects`, `GET /v1/projects/{id}` | any recognised role on a session, the self-host operator, or an API key holding `read` |
//! | `POST /v1/projects`, `PATCH /v1/projects/{id}`, `DELETE /v1/projects/{id}` (archive) | a VERIFIED owner, or the self-host operator — a project's policy governs every key in it, and an API key never manages keys (`key_routes::key_editor`) |
//!
//! Tenant isolation: the tenant is `claims.tenant_id` ONLY, never a path or body field;
//! another tenant's project id answers 404 exactly like an absent one. Mounted only with
//! a Postgres control plane (`server.rs`, beside the key routes).

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracelane_shared::TenantId;

use crate::db::projects::{
    ArchiveOutcome, CreateOutcome, NewProject, PatchOutcome, Project, ProjectPatch,
};

/// Storage seam — the routes are unit-tested without Postgres; the SQL is proven by the
/// real-Postgres suite. Off the hot path, so `async_trait` is fine.
#[async_trait::async_trait]
pub trait ProjectStore: Send + Sync {
    async fn list(&self, tenant: &TenantId) -> anyhow::Result<Vec<Project>>;
    async fn get(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
    ) -> anyhow::Result<Option<(Project, Vec<uuid::Uuid>)>>;
    async fn create(
        &self,
        tenant: &TenantId,
        new: &NewProject,
        max: usize,
        actor: &str,
    ) -> anyhow::Result<CreateOutcome>;
    async fn update(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        patch: &ProjectPatch,
        actor: &str,
    ) -> anyhow::Result<PatchOutcome>;
    async fn archive(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
    ) -> anyhow::Result<ArchiveOutcome>;
}

/// The production store.
pub struct PgProjectStore {
    pub pool: deadpool_postgres::Pool,
}

#[async_trait::async_trait]
impl ProjectStore for PgProjectStore {
    async fn list(&self, tenant: &TenantId) -> anyhow::Result<Vec<Project>> {
        crate::db::projects::list(&self.pool, tenant).await
    }
    async fn get(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
    ) -> anyhow::Result<Option<(Project, Vec<uuid::Uuid>)>> {
        crate::db::projects::get(&self.pool, tenant, id).await
    }
    async fn create(
        &self,
        tenant: &TenantId,
        new: &NewProject,
        max: usize,
        actor: &str,
    ) -> anyhow::Result<CreateOutcome> {
        crate::db::projects::create(
            &self.pool,
            tenant,
            new,
            max,
            &crate::key_routes::audit_actor(actor),
        )
        .await
    }
    async fn update(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        patch: &ProjectPatch,
        actor: &str,
    ) -> anyhow::Result<PatchOutcome> {
        crate::db::projects::update(
            &self.pool,
            tenant,
            id,
            patch,
            &crate::key_routes::audit_actor(actor),
        )
        .await
    }
    async fn archive(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        actor: &str,
    ) -> anyhow::Result<ArchiveOutcome> {
        crate::db::projects::archive(
            &self.pool,
            tenant,
            id,
            &crate::key_routes::audit_actor(actor),
        )
        .await
    }
}

#[derive(Clone)]
pub struct ProjectRoutesState {
    pub store: Arc<dyn ProjectStore>,
}

pub fn routes() -> Router<ProjectRoutesState> {
    Router::new()
        .route("/v1/projects", get(list_handler).post(create_handler))
        .route(
            "/v1/projects/{id}",
            get(get_handler)
                .patch(update_handler)
                .delete(archive_handler),
        )
}

// ── Who may ─────────────────────────────────────────────────────────────────

/// READ: any recognised role on a session, the self-host operator, or an API key that
/// holds `read` (the auditor's scope). Never mTLS. Fail-CLOSED.
fn can_read_projects(claims: &crate::auth::Claims) -> bool {
    use crate::auth::AuthMethod;
    match claims.auth_method {
        AuthMethod::SelfHostMasterKey => true,
        AuthMethod::JwtBearer => claims.role.is_some(),
        AuthMethod::ApiKey => claims.allows_scope(crate::auth::scope::Scope::Read),
        AuthMethod::Mtls => false,
    }
}

/// WRITE: a verified owner (session `owner`/`admin`) or the self-host operator. A
/// member, a viewer and ANY API key are refused: a project's policy governs every key
/// in it, so changing it is changing every key's limits.
pub(crate) fn may_manage_governance(claims: &crate::auth::Claims) -> bool {
    claims.is_verified_owner()
        || matches!(
            claims.auth_method,
            crate::auth::AuthMethod::SelfHostMasterKey
        )
}

// ── Validation (shared with `key_routes` for the key's own fields) ──────────

/// One refused field, as `key_routes`' 400 shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invalid {
    pub field: String,
    pub message: String,
}

impl Invalid {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
    pub(crate) fn response(&self) -> Response {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_field",
            &self.message,
            Some(&self.field),
        )
    }
}

/// `^[a-z0-9][a-z0-9_-]{0,31}$` — the migration's `api_keys_environment_slug_chk`.
pub(crate) fn valid_environment(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// OG-20: a submitted policy, validated STRICTLY (unknown fields, malformed entries and
/// the reference-table bounds all refuse) and returned in canonical form — what is
/// stored, so re-submitting the same policy is a no-op.
pub(crate) fn validate_policy(v: &Value) -> Result<Value, Invalid> {
    let limits = crate::providers::translation_policy::key_policy_limits();
    tracelane_shared::key_policy::KeyPolicy::parse(v, Some(&limits.document))
        .map(|p| p.to_value())
        .map_err(|e| {
            let field = if e.field == "policy" {
                "policy".to_owned()
            } else {
                format!("policy.{}", e.field)
            };
            Invalid::new(field, e.message)
        })
}

fn validate_name(raw: &str) -> Result<String, Invalid> {
    let n = raw.trim();
    if n.is_empty() || n.chars().count() > 128 {
        return Err(Invalid::new("name", "name must be 1-128 characters"));
    }
    Ok(n.to_owned())
}

fn validate_environments(raw: Vec<String>) -> Result<Vec<String>, Invalid> {
    let max =
        crate::providers::translation_policy::key_policy_limits().max_environments_per_project;
    if raw.is_empty() || raw.len() > max {
        return Err(Invalid::new(
            "environments",
            format!("environments must name 1-{max} labels"),
        ));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for e in raw {
        let e = e.trim().to_owned();
        if !valid_environment(&e) {
            let shown: String = e.chars().take(40).collect();
            return Err(Invalid::new(
                "environments",
                format!(
                    "`{shown}` is not a valid environment — lower-case letters, digits, `_` and \
                     `-`, starting with a letter or digit, at most 32"
                ),
            ));
        }
        if !out.contains(&e) {
            out.push(e);
        }
    }
    Ok(out)
}

// ── Wire ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectView {
    id: String,
    name: String,
    environments: Vec<String>,
    policy: Option<Value>,
    created_at: String,
    updated_at: String,
}

impl From<Project> for ProjectView {
    fn from(p: Project) -> Self {
        Self {
            id: p.id.to_string(),
            name: p.name,
            environments: p.environments,
            policy: p.policy,
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    name: String,
    #[serde(default)]
    environments: Option<Vec<String>>,
    #[serde(default)]
    policy: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchBody {
    #[serde(default, deserialize_with = "crate::key_routes::present")]
    name: Option<Option<String>>,
    #[serde(default, deserialize_with = "crate::key_routes::present")]
    environments: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "crate::key_routes::present")]
    policy: Option<Option<Value>>,
}

fn json_error(status: StatusCode, code: &str, message: &str, field: Option<&str>) -> Response {
    crate::key_routes::json_error(status, code, message, field)
}

fn not_found() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "project_not_found",
        "project not found",
        None,
    )
}

fn unavailable(what: &str) -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unavailable",
        &format!("failed to {what} — nothing was changed"),
        None,
    )
}

fn no_store(resp: impl IntoResponse) -> Response {
    let mut r = resp.into_response();
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    r
}

/// Authenticate. The tenant comes from these claims and nowhere else.
async fn authenticate(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let Some(raw) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing Authorization header",
            None,
        ));
    };
    crate::auth::validate_authorization(raw).await.map_err(|e| {
        let (status, message) = crate::auth::failure(&e);
        json_error(status, crate::auth::failure_code(&e), message, None)
    })
}

/// A JSON OBJECT body, parsed as `T` (serde would also build a struct from an array).
fn object_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Box<Response>> {
    serde_json::from_slice::<Value>(body)
        .and_then(|v| {
            if v.is_object() {
                serde_json::from_value(v)
            } else {
                Err(serde::de::Error::custom("expected a JSON object"))
            }
        })
        .map_err(|e| {
            Box::new(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                &format!("the body must be a JSON object: {e}"),
                None,
            ))
        })
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// `GET /v1/projects` — the tenant's live projects.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn list_handler(State(state): State<ProjectRoutesState>, headers: HeaderMap) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !can_read_projects(&claims) {
        return crate::key_routes::insufficient_read();
    }
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    match state.store.list(&claims.tenant_id).await {
        Ok(list) => no_store(Json(json!({
            "projects": list.into_iter().map(ProjectView::from).collect::<Vec<_>>()
        }))),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "project list failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to read projects",
                None,
            )
        }
    }
}

/// `GET /v1/projects/{id}` — one live project and the ids of its live keys.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn get_handler(
    State(state): State<ProjectRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !can_read_projects(&claims) {
        return crate::key_routes::insufficient_read();
    }
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return not_found();
    };
    match state.store.get(&claims.tenant_id, id).await {
        Ok(Some((p, keys))) => {
            let mut v = json!(ProjectView::from(p));
            v["keyIds"] = json!(keys.iter().map(ToString::to_string).collect::<Vec<_>>());
            no_store(Json(v))
        }
        Ok(None) => not_found(),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "project read failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unavailable",
                "failed to read the project",
                None,
            )
        }
    }
}

/// `POST /v1/projects` — create. Owner only.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn create_handler(
    State(state): State<ProjectRoutesState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !may_manage_governance(&claims) {
        return crate::key_routes::role_forbidden("owner");
    }
    // OG-36: allowlist + SSO-required; the actor is the OG-35 audit row's.
    let control = match crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::EditProjects,
        &headers,
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let body: CreateBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let new = match validate_create(body) {
        Ok(n) => n,
        Err(e) => return e.response(),
    };
    let max = crate::providers::translation_policy::key_policy_limits().max_projects_per_tenant;
    match crate::db::control_audit::scoped(
        control.audit.clone(),
        state
            .store
            .create(&claims.tenant_id, &new, max, &claims.sub),
    )
    .await
    {
        Ok(CreateOutcome::Created(p)) => {
            no_store((StatusCode::CREATED, Json(ProjectView::from(p))))
        }
        Ok(CreateOutcome::NameTaken) => json_error(
            StatusCode::CONFLICT,
            "project_name_taken",
            "a project with this name already exists in this workspace",
            Some("name"),
        ),
        Ok(CreateOutcome::LimitReached { max }) => json_error(
            StatusCode::CONFLICT,
            "project_limit_reached",
            &format!("this workspace already has {max} projects — archive one first"),
            None,
        ),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "project create failed");
            unavailable("create the project")
        }
    }
}

fn validate_create(body: CreateBody) -> Result<NewProject, Invalid> {
    Ok(NewProject {
        name: validate_name(&body.name)?,
        environments: validate_environments(
            body.environments
                .unwrap_or_else(|| vec!["production".to_owned()]),
        )?,
        policy: match body.policy {
            None | Some(Value::Null) => None,
            Some(v) => Some(validate_policy(&v)?),
        },
    })
}

fn validate_patch(body: PatchBody) -> Result<ProjectPatch, Invalid> {
    let mut patch = ProjectPatch::default();
    match body.name {
        None => {}
        Some(None) => return Err(Invalid::new("name", "name cannot be cleared")),
        Some(Some(n)) => patch.name = Some(validate_name(&n)?),
    }
    match body.environments {
        None => {}
        Some(None) => {
            return Err(Invalid::new(
                "environments",
                "environments cannot be cleared — a project has at least one",
            ));
        }
        Some(Some(e)) => patch.environments = Some(validate_environments(e)?),
    }
    match body.policy {
        None => {}
        Some(None) => patch.policy = Some(None),
        Some(Some(v)) => patch.policy = Some(Some(validate_policy(&v)?)),
    }
    if patch == ProjectPatch::default() {
        return Err(Invalid::new(
            "body",
            "the patch names no field — send at least one of name, environments, policy",
        ));
    }
    Ok(patch)
}

/// `PATCH /v1/projects/{id}` — RFC 7396. Owner only.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn update_handler(
    State(state): State<ProjectRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !may_manage_governance(&claims) {
        return crate::key_routes::role_forbidden("owner");
    }
    // OG-36: allowlist + SSO-required; the actor is the OG-35 audit row's.
    let control = match crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::EditProjects,
        &headers,
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return not_found();
    };
    let body: PatchBody = match object_body(&body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let patch = match validate_patch(body) {
        Ok(p) => p,
        Err(e) => return e.response(),
    };
    match crate::db::control_audit::scoped(
        control.audit.clone(),
        state
            .store
            .update(&claims.tenant_id, id, &patch, &claims.sub),
    )
    .await
    {
        Ok(PatchOutcome::Updated { project, changed }) => {
            let mut v = json!(ProjectView::from(*project));
            v["changed"] = json!(changed);
            no_store(Json(v))
        }
        Ok(PatchOutcome::NotFound) => not_found(),
        Ok(PatchOutcome::NameTaken) => json_error(
            StatusCode::CONFLICT,
            "project_name_taken",
            "a project with this name already exists in this workspace",
            Some("name"),
        ),
        Ok(PatchOutcome::EnvironmentInUse { environment }) => json_error(
            StatusCode::CONFLICT,
            "environment_in_use",
            &format!(
                "a key of this project still carries the environment `{environment}` — move \
                 or relabel it first"
            ),
            Some("environments"),
        ),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "project update failed");
            unavailable("update the project")
        }
    }
}

/// `DELETE /v1/projects/{id}` — ARCHIVE. Owner only; refused while live keys remain.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn archive_handler(
    State(state): State<ProjectRoutesState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !may_manage_governance(&claims) {
        return crate::key_routes::role_forbidden("owner");
    }
    // OG-36: allowlist + SSO-required; the actor is the OG-35 audit row's.
    let control = match crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::EditProjects,
        &headers,
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return not_found();
    };
    match crate::db::control_audit::scoped(
        control.audit.clone(),
        state.store.archive(&claims.tenant_id, id, &claims.sub),
    )
    .await
    {
        Ok(ArchiveOutcome::Archived) => StatusCode::NO_CONTENT.into_response(),
        Ok(ArchiveOutcome::NotFound) => not_found(),
        Ok(ArchiveOutcome::HasKeys { count }) => json_error(
            StatusCode::CONFLICT,
            "project_has_keys",
            &format!(
                "{count} live key(s) still belong to this project — move or revoke them first"
            ),
            None,
        ),
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "project archive failed");
            unavailable("archive the project")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, Claims, Role};

    fn claims(method: AuthMethod, role: Option<Role>, scope: &[&str]) -> Claims {
        let mut c = crate::auth::dev_stub_claims(method);
        c.role = role;
        if method == AuthMethod::ApiKey {
            let v: Vec<String> = scope.iter().map(|s| (*s).to_owned()).collect();
            c.key_scope = crate::auth::scope::KeyScope::from_column(Some(v.as_slice()));
        }
        c
    }

    #[test]
    fn only_a_verified_owner_or_the_operator_manages_projects() {
        assert!(may_manage_governance(&claims(
            AuthMethod::JwtBearer,
            Some(Role::Owner),
            &[]
        )));
        assert!(may_manage_governance(&claims(
            AuthMethod::SelfHostMasterKey,
            None,
            &[]
        )));
        for c in [
            claims(AuthMethod::JwtBearer, Some(Role::Member), &[]),
            claims(AuthMethod::JwtBearer, Some(Role::Viewer), &[]),
            claims(AuthMethod::JwtBearer, None, &[]),
            claims(AuthMethod::ApiKey, None, &["admin", "read", "chat"]),
            claims(AuthMethod::Mtls, None, &[]),
        ] {
            assert!(
                !may_manage_governance(&c),
                "{:?} {:?}",
                c.auth_method,
                c.role
            );
        }
    }

    #[test]
    fn reading_needs_a_role_or_the_read_scope() {
        assert!(can_read_projects(&claims(
            AuthMethod::JwtBearer,
            Some(Role::Viewer),
            &[]
        )));
        assert!(can_read_projects(&claims(
            AuthMethod::ApiKey,
            None,
            &["read"]
        )));
        assert!(!can_read_projects(&claims(
            AuthMethod::ApiKey,
            None,
            &["chat"]
        )));
        assert!(!can_read_projects(&claims(
            AuthMethod::ApiKey,
            None,
            &["ingest"]
        )));
        assert!(!can_read_projects(&claims(
            AuthMethod::JwtBearer,
            None,
            &[]
        )));
        assert!(!can_read_projects(&claims(AuthMethod::Mtls, None, &[])));
    }

    #[test]
    fn create_and_patch_validate_every_field_and_canonicalise_the_policy() {
        let new = validate_create(CreateBody {
            name: "  Checkout  ".into(),
            environments: None,
            policy: Some(json!({"models": {"allow": ["GPT-4o*"]}})),
        })
        .unwrap();
        assert_eq!(new.name, "Checkout");
        assert_eq!(new.environments, vec!["production"]);
        assert_eq!(new.policy, Some(json!({"models": {"allow": ["gpt-4o*"]}})));
        for (body, field) in [
            (
                CreateBody {
                    name: " ".into(),
                    environments: None,
                    policy: None,
                },
                "name",
            ),
            (
                CreateBody {
                    name: "x".into(),
                    environments: Some(vec![]),
                    policy: None,
                },
                "environments",
            ),
            (
                CreateBody {
                    name: "x".into(),
                    environments: Some(vec!["Prod".into()]),
                    policy: None,
                },
                "environments",
            ),
            (
                CreateBody {
                    name: "x".into(),
                    environments: None,
                    policy: Some(json!({"nope": 1})),
                },
                "policy",
            ),
            (
                CreateBody {
                    name: "x".into(),
                    environments: None,
                    policy: Some(json!({"source_ips": ["10.0.0.0/99"]})),
                },
                "policy.source_ips",
            ),
        ] {
            assert_eq!(validate_create(body).unwrap_err().field, field);
        }
        assert_eq!(
            validate_patch(PatchBody {
                name: None,
                environments: None,
                policy: None
            })
            .unwrap_err()
            .field,
            "body"
        );
        assert_eq!(
            validate_patch(PatchBody {
                name: None,
                environments: Some(None),
                policy: None
            })
            .unwrap_err()
            .field,
            "environments"
        );
        let clear = validate_patch(PatchBody {
            name: None,
            environments: None,
            policy: Some(None),
        })
        .unwrap();
        assert_eq!(clear.policy, Some(None));
    }

    #[test]
    fn environment_slugs_match_the_database_check() {
        for ok in ["production", "staging", "dev-1", "eu_west", "0"] {
            assert!(valid_environment(ok), "{ok}");
        }
        for bad in ["", "Prod", "-x", "_x", "a b", &"x".repeat(33)] {
            assert!(!valid_environment(bad), "{bad}");
        }
    }
}
