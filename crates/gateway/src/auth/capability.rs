//! `OG-34` — the ONE role × capability matrix (`specs/OG-34-granular-roles.md`).
//!
//! **Every "may this principal do X?" question in the gateway is answered here.**
//! The legacy predicates on [`Claims`] (`can_admin`, `is_verified_owner`,
//! `can_mint_keys`, `can_write_prompts`) are thin wrappers over a row of
//! [`MATRIX`], so the old call sites and the new [`Claims::can`] cannot disagree.
//! This file is to roles what `Scope::from_slug` (`tracelane_shared::api_scope`) is
//! to API-key scopes: the closed vocabulary and the single authority.
//!
//! ## Principals and columns
//!
//! A row answers for seven principals. Which column applies is decided by HOW the
//! caller authenticated ([`AuthMethod`]), then — for a human session — by the WorkOS
//! role slug ([`Role`]):
//!
//! | column | principal |
//! |---|---|
//! | `admin` | WorkOS JWT, slug `owner` or `admin` ([`Role::Owner`]) |
//! | `developer` | WorkOS JWT, slug `developer` or legacy `member` ([`Role::Member`]) |
//! | `viewer` | WorkOS JWT, slug `viewer` |
//! | `billing` | WorkOS JWT, slug `billing` |
//! | `unrecognised` | WorkOS JWT whose slug is absent or unknown (PL-9) |
//! | `api_key` | a tenant `tlane_` key — its SCOPES still apply at the route |
//! | `master` | the single-tenant self-host master key (ADR-067) |
//!
//! An mTLS identity is never in the matrix: it holds no capability.
//!
//! **The `unrecognised` column is explicit, not a fallthrough** (PL-9, founder ruling
//! OG-00 §2.4: an unknown slug resolves to the least privilege). It grants exactly
//! what such a session could do before OG-34 — read recorded data and spend — and
//! nothing that writes.
//!
//! ## Adding a capability
//!
//! Add the variant, add ONE row at the variant's index (a `const` assertion below
//! refuses a misplaced row at compile time), then regenerate the dashboard mirror
//! (`python3 scripts/ci/build-role-capabilities.py`) — `--check` fails the gate on a
//! stale mirror. A route that changes gateway control state also needs a
//! [`CONTROL_ROUTES`] entry; `scripts/ci/check-route-auth.py` refuses a mutating route
//! that is neither registered nor explained.

use super::{AuthMethod, Claims, Role};

/// What a principal may do. The discriminant indexes [`MATRIX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Capability {
    /// Read recorded traces, spans, sessions and other recorded content.
    ReadTraces,
    /// Read spend, usage and cost aggregates.
    ViewSpend,
    /// Read workspace settings that carry no secret (capture policy, …).
    ViewSettings,
    /// Read API-key metadata (never key material).
    ViewKeys,
    /// Mint a key, and edit a key the caller minted.
    MintKeys,
    /// Edit, rotate or revoke ANY key in the workspace.
    ManageAllKeys,
    /// Grant the `passthrough` scope (OG-08 H1).
    GrantPassthrough,
    /// Read routing / guardrail policy (model aliases, failover, tool pins).
    ViewPolicies,
    /// Change routing / guardrail / capture policy.
    EditPolicies,
    /// Change a spend ceiling or clear a promotion freeze.
    EditBudgets,
    /// Create, change or delete projects and environments (OG-23).
    EditProjects,
    /// Create or delete alert rules and destinations.
    ManageAlerts,
    /// Annotate traces and record outcomes.
    AnnotateTraces,
    /// Change prompts, datasets, experiments and online-eval policy (A8/EVL-18).
    WritePrompts,
    /// Read BYOK provider-key metadata (never key material).
    ViewProviderKeys,
    /// Upload, validate or delete a BYOK provider key.
    ManageProviderKeys,
    /// Open checkout or the billing portal.
    ManageBilling,
    /// Invite, remove or change the role of a workspace member.
    ManageTeam,
    /// Change the admin IP allowlist, SSO-required, or encryption keys (OG-36).
    ManageSecurity,
    /// Read the control-change audit trail (OG-35).
    ReadControlAudit,
    /// OG-21/22/24/25 workspace controls: the workspace policy, pause / resume, block
    /// lists and spend-alert channels.
    ManageControls,
    /// Grant the `admin` scope to an API key (rev5 H1). An `admin`-scoped key holds the
    /// matrix's `api_key` column — `edit_budgets`, `write_prompts` — so granting it is an
    /// admin decision: a key never holds more than its minter's role allows.
    GrantAdminScope,
}

/// One row of the matrix. `const`-constructible so [`MATRIX`] is data, not code.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub cap: Capability,
    /// Stable wire name (403 bodies, the dashboard mirror, the audit trail).
    pub slug: &'static str,
    pub admin: bool,
    pub developer: bool,
    pub viewer: bool,
    pub billing: bool,
    pub unrecognised: bool,
    pub api_key: bool,
    pub master: bool,
}

impl Row {
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    const fn new(
        cap: Capability,
        slug: &'static str,
        admin: bool,
        developer: bool,
        viewer: bool,
        billing: bool,
        unrecognised: bool,
        api_key: bool,
        master: bool,
    ) -> Self {
        Self {
            cap,
            slug,
            admin,
            developer,
            viewer,
            billing,
            unrecognised,
            api_key,
            master,
        }
    }
}

const Y: bool = true;
const N: bool = false;

/// THE matrix. One row per [`Capability`], at the variant's index. The dashboard
/// mirror (`apps/web/lib/role-capabilities.generated.ts`) is generated from these
/// lines, so keep each row on ONE line in exactly this shape.
#[rustfmt::skip]
pub const MATRIX: &[Row] = &[
    //       capability                          slug                    admin developer viewer billing unrecognised api_key master
    Row::new(Capability::ReadTraces,         "read_traces",          Y, Y, Y, N, Y, Y, Y),
    Row::new(Capability::ViewSpend,          "view_spend",           Y, Y, Y, Y, Y, Y, Y),
    Row::new(Capability::ViewSettings,       "view_settings",        Y, Y, Y, Y, N, N, Y),
    Row::new(Capability::ViewKeys,           "view_keys",            Y, Y, Y, Y, N, N, Y),
    Row::new(Capability::MintKeys,           "mint_keys",            Y, Y, N, N, N, N, Y),
    Row::new(Capability::ManageAllKeys,      "manage_all_keys",      Y, N, N, N, N, N, Y),
    Row::new(Capability::GrantPassthrough,   "grant_passthrough",    Y, N, N, N, N, N, Y),
    Row::new(Capability::ViewPolicies,       "view_policies",        Y, N, N, N, N, N, Y),
    Row::new(Capability::EditPolicies,       "edit_policies",        Y, N, N, N, N, N, N),
    Row::new(Capability::EditBudgets,        "edit_budgets",         Y, N, N, Y, N, Y, Y),
    Row::new(Capability::EditProjects,       "edit_projects",        Y, N, N, N, N, N, Y),
    Row::new(Capability::ManageAlerts,       "manage_alerts",        Y, Y, N, N, N, N, Y),
    Row::new(Capability::AnnotateTraces,     "annotate_traces",      Y, Y, N, N, N, Y, Y),
    Row::new(Capability::WritePrompts,       "write_prompts",        Y, N, N, N, N, Y, Y),
    Row::new(Capability::ViewProviderKeys,   "view_provider_keys",   Y, N, N, N, N, N, Y),
    Row::new(Capability::ManageProviderKeys, "manage_provider_keys", Y, N, N, N, N, N, N),
    Row::new(Capability::ManageBilling,      "manage_billing",       Y, N, N, Y, N, N, Y),
    Row::new(Capability::ManageTeam,         "manage_team",          Y, N, N, N, N, N, N),
    Row::new(Capability::ManageSecurity,     "manage_security",      Y, N, N, N, N, N, N),
    Row::new(Capability::ReadControlAudit,   "read_control_audit",   Y, N, N, N, N, N, Y),
    Row::new(Capability::ManageControls,     "manage_controls",      Y, N, N, N, N, N, Y),
    Row::new(Capability::GrantAdminScope,    "grant_admin_scope",    Y, N, N, N, N, N, Y),
];

/// Every row sits at its variant's index — a misplaced or missing row is a
/// COMPILE error, not a silent mis-grant.
const _: () = {
    let mut i = 0;
    while i < MATRIX.len() {
        assert!(MATRIX[i].cap as usize == i, "MATRIX row out of order");
        i += 1;
    }
    assert!(
        MATRIX.len() == Capability::GrantAdminScope as usize + 1,
        "MATRIX must have one row per Capability"
    );
};

impl Capability {
    /// This capability's row.
    #[must_use]
    pub const fn row(self) -> &'static Row {
        &MATRIX[self as usize]
    }

    /// Stable wire name.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        self.row().slug
    }

    /// The least-privileged role that holds this capability, for the
    /// `required_role` field of a 403 (`viewer` < `billing` < `developer` < `admin`).
    #[must_use]
    pub const fn least_role(self) -> &'static str {
        let r = self.row();
        if r.viewer {
            "viewer"
        } else if r.billing {
            "billing"
        } else if r.developer {
            "developer"
        } else {
            "admin"
        }
    }
}

/// rev5 H1 — the capability a principal needs to put `scope` on a key it mints or edits.
///
/// **A key never holds more than its minter's role allows.** `chat`, `read` and `ingest`
/// are within what any key minter (`mint_keys`) may do; `admin` reaches the matrix's
/// `api_key` column (`edit_budgets`, `write_prompts`), which a developer does not hold, so
/// it needs [`Capability::GrantAdminScope`]; `passthrough` bypasses every guardrail, so it
/// needs [`Capability::GrantPassthrough`]. An EXHAUSTIVE match: a new scope cannot be
/// minted until someone decides who may grant it.
#[must_use]
pub const fn scope_grant_capability(scope: tracelane_shared::api_scope::Scope) -> Capability {
    use tracelane_shared::api_scope::Scope as S;
    match scope {
        S::Chat | S::Read | S::Ingest => Capability::MintKeys,
        S::Admin => Capability::GrantAdminScope,
        S::Passthrough => Capability::GrantPassthrough,
    }
}

impl Role {
    /// The product name of the role (`admin` / `developer` / `viewer` / `billing`).
    /// The variant names predate OG-34 and are kept so in-flight branches compile:
    /// `Owner` IS the admin role and `Member` IS the developer role.
    #[must_use]
    pub const fn product_name(self) -> &'static str {
        match self {
            Self::Owner => "admin",
            Self::Member => "developer",
            Self::Viewer => "viewer",
            Self::Billing => "billing",
        }
    }
}

impl Claims {
    /// May this principal exercise `cap`? THE question; every role gate in the
    /// gateway reduces to it. Fail-CLOSED: an mTLS identity holds nothing, and a
    /// WorkOS session with an unknown role gets only the `unrecognised` column.
    #[must_use]
    pub fn can(&self, cap: Capability) -> bool {
        let r = cap.row();
        match self.auth_method {
            AuthMethod::JwtBearer => match self.role {
                Some(Role::Owner) => r.admin,
                Some(Role::Member) => r.developer,
                Some(Role::Viewer) => r.viewer,
                Some(Role::Billing) => r.billing,
                None => r.unrecognised,
            },
            AuthMethod::ApiKey => r.api_key,
            AuthMethod::SelfHostMasterKey => r.master,
            AuthMethod::Mtls => false,
        }
    }

    /// The caller's role for an audit row: the product name, or a principal label
    /// for a credential with no role system.
    #[must_use]
    pub fn role_label(&self) -> &'static str {
        match self.auth_method {
            AuthMethod::JwtBearer => self.role.map_or("unrecognised", Role::product_name),
            AuthMethod::ApiKey => "api_key",
            AuthMethod::SelfHostMasterKey => "self_host_operator",
            AuthMethod::Mtls => "mtls",
        }
    }

    /// The authentication method, as the audit trail names it.
    #[must_use]
    pub fn auth_method_label(&self) -> &'static str {
        match self.auth_method {
            AuthMethod::JwtBearer => "workos_session",
            AuthMethod::ApiKey => "api_key",
            AuthMethod::SelfHostMasterKey => "self_host_master_key",
            AuthMethod::Mtls => "mtls",
        }
    }
}

/// HTTP method of a registered control route. (Registry types: read by the guard
/// and the tests, not the request path — see [`CONTROL_ROUTES`].)
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// One gateway route that changes (or exposes) gateway CONTROL state. Every
/// handler listed here calls `crate::control_plane::require_control` — the
/// capability check, the admin IP allowlist and SSO-required (OG-36) — and every
/// mutating one writes an `admin_audit_log` row in the same transaction as the
/// change (OG-35). `scripts/ci/check-route-auth.py` parses this table: a mutating
/// `/v1` route that is neither here nor in its explained not-control list fails the
/// gate, and so does a listed handler that never reaches `require_control`.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct ControlRoute {
    pub method: Method,
    pub path: &'static str,
    pub cap: Capability,
    /// The `admin_audit_log.action` this route records; `None` for a read, or for a
    /// route that changes no Tracelane state (checkout/portal open a Polar session).
    pub audit: Option<&'static str>,
}

#[cfg_attr(not(test), allow(dead_code))]
const fn cr(
    method: Method,
    path: &'static str,
    cap: Capability,
    audit: Option<&'static str>,
) -> ControlRoute {
    ControlRoute {
        method,
        path,
        cap,
        audit,
    }
}

use Capability as C;
use Method::{Delete, Get, Patch, Post, Put};

/// THE control-route registry. One entry per (method, path); keep each on ONE line
/// (the route-auth guard reads them).
///
/// Its consumers are the guard (`scripts/ci/check-route-auth.py`, which parses this
/// table) and the tests below — not the request path, which calls
/// `require_control` with the capability inline. Hence no runtime reader.
#[cfg_attr(not(test), allow(dead_code))]
#[rustfmt::skip]
pub const CONTROL_ROUTES: &[ControlRoute] = &[
    cr(Get, "/v1/security/kms", C::ViewSettings, None),
    cr(Put, "/v1/security/kms", C::ManageSecurity, Some("security.kms.set")),
    cr(Post, "/v1/security/kms/migrate", C::ManageSecurity, Some("security.kms.migrate")),
    cr(Post, "/v1/security/kms/rewrap", C::ManageSecurity, Some("security.kms.rewrap")),
    cr(Delete, "/v1/security/kms", C::ManageSecurity, Some("security.kms.delete")),
    cr(Put,    "/v1/guardrails/policy",                 C::EditPolicies,       Some("guardrail.policy.set")),
    cr(Put, "/v1/guardrails/hooks/{id}", C::EditPolicies, Some("guardrail.hook.put")),
    cr(Delete, "/v1/guardrails/hooks/{id}", C::EditPolicies, Some("guardrail.hook.delete")),
    cr(Post,   "/v1/keys",                              C::MintKeys,           Some("api_key.create")),
    cr(Post,   "/v1/keys/{id}/rotate",                  C::ManageAllKeys,      Some("api_key.rotate")),
    cr(Patch,  "/v1/keys/{id}",                         C::MintKeys,           Some("api_key.update")),
    cr(Delete, "/v1/keys/{id}",                         C::ManageAllKeys,      Some("api_key.revoke")),
    cr(Post,   "/v1/byok/provider-keys",                C::ManageProviderKeys, Some("provider_key.upsert")),
    cr(Delete, "/v1/byok/provider-keys/{provider_id}",  C::ManageProviderKeys, Some("provider_key.delete")),
    cr(Post,   "/v1/provider-keys/{id}/validate",       C::ManageProviderKeys, Some("provider_key.validate")),
    cr(Post,   "/v1/billing/checkout",                  C::ManageBilling,      None),
    cr(Post,   "/v1/billing/portal",                    C::ManageBilling,      None),
    cr(Put,    "/v1/billing/ceiling",                   C::EditBudgets,        Some("billing.ceiling.set")),
    cr(Delete, "/v1/billing/promotion-freeze",          C::EditBudgets,        Some("billing.promotion_freeze.clear")),
    cr(Post,   "/v1/guardrails/tool-pins",              C::EditPolicies,       Some("guardrail.tool_pin.set")),
    cr(Post,   "/v1/guardrails/tool-pins/approve",      C::EditPolicies,       Some("guardrail.tool_pin.approve")),
    cr(Delete, "/v1/guardrails/tool-pins/{tool_name}",  C::EditPolicies,       Some("guardrail.tool_pin.delete")),
    cr(Put,    "/v1/model-aliases",                     C::EditPolicies,       Some("model_alias.put")),
    cr(Delete, "/v1/model-aliases",                     C::EditPolicies,       Some("model_alias.delete")),
    cr(Put,    "/v1/gateway/failover",                  C::EditPolicies,       Some("gateway.failover.set")),
    cr(Get,    "/v1/routing",                           C::ViewPolicies,       None),
    cr(Put,    "/v1/routing",                           C::EditPolicies,       Some("routing.update")),
    cr(Post,   "/v1/routing/simulate",                  C::ViewPolicies,       None),
    cr(Put,    "/v1/workspace/capture",                 C::EditPolicies,       Some("workspace.capture.set")),
    cr(Put,    "/v1/cache/settings",                    C::EditPolicies,       Some("cache.settings.set")),
    cr(Post,   "/v1/cache/invalidate",                  C::EditPolicies,       Some("cache.invalidate")),
    cr(Post,   "/v1/exports/otel",                      C::EditPolicies,       Some("otel_export.create")),
    cr(Patch,  "/v1/exports/otel/{id}",                 C::EditPolicies,       Some("otel_export.update")),
    cr(Delete, "/v1/exports/otel/{id}",                 C::EditPolicies,       Some("otel_export.delete")),
    cr(Post,   "/v1/exports/otel/{id}/test",            C::EditPolicies,       None),
    cr(Post,   "/v1/alerts/rules",                      C::ManageAlerts,       Some("alert.rule.create")),
    cr(Delete, "/v1/alerts/rules/{id}",                 C::ManageAlerts,       Some("alert.rule.delete")),
    cr(Post,   "/v1/alerts/destinations",               C::ManageAlerts,       Some("alert.destination.create")),
    cr(Delete, "/v1/alerts/destinations/{id}",          C::ManageAlerts,       Some("alert.destination.delete")),
    cr(Post,   "/v1/alerts/test",                       C::ManageAlerts,       None),
    cr(Post,   "/v1/online-evals/policy",               C::WritePrompts,       Some("online_eval.policy.set")),
    cr(Delete, "/v1/online-evals/policy",               C::WritePrompts,       Some("online_eval.policy.disable")),
    cr(Post,   "/v1/projects",                          C::EditProjects,       Some("project.create")),
    cr(Patch,  "/v1/projects/{id}",                     C::EditProjects,       Some("project.update")),
    cr(Delete, "/v1/projects/{id}",                     C::EditProjects,       Some("project.archive")),
    cr(Put,    "/v1/controls/policy",                   C::ManageControls,     Some("workspace.policy.update")),
    cr(Post,   "/v1/controls/pause",                    C::ManageControls,     Some("workspace.pause")),
    cr(Post,   "/v1/controls/resume",                   C::ManageControls,     Some("workspace.resume")),
    cr(Put,    "/v1/controls/blocks",                   C::ManageControls,     Some("workspace.blocks.update")),
    cr(Post,   "/v1/controls/revoke-all-keys",          C::ManageAllKeys,      Some("api_key.revoke_all")),
    cr(Post,   "/v1/controls/alert-channels",           C::ManageControls,     Some("spend_alert_channel.create")),
    cr(Delete, "/v1/controls/alert-channels/{id}",      C::ManageControls,     Some("spend_alert_channel.delete")),
    cr(Post,   "/v1/controls/alert-channels/{id}/test", C::ManageControls,     None),
    cr(Get,    "/v1/security/admin-access",             C::ManageSecurity,     None),
    cr(Put,    "/v1/security/admin-access",             C::ManageSecurity,     Some("security.admin_access.set")),
    cr(Get,    "/v1/audit/control-changes",             C::ReadControlAudit,   None),
    cr(Post,   "/v1/audit/control-changes",             C::ManageTeam,         Some("web.control_change")),
];

/// A control change performed OUTSIDE the gateway (by the dashboard against WorkOS
/// or its own Postgres tables) that the dashboard records through
/// `POST /v1/audit/control-changes` BEFORE performing it. Each action names the
/// capability the caller must hold — the endpoint checks it, the IP allowlist and
/// SSO-required, exactly as a gateway control route does. An action not listed is
/// refused 400: the endpoint cannot be used to write an arbitrary audit row.
/// The `.failed` form records that the downstream call did not complete.
#[rustfmt::skip]
pub const WEB_CONTROL_ACTIONS: &[(&str, Capability)] = &[
    ("member.role_change",          C::ManageTeam),
    ("member.role_change.failed",   C::ManageTeam),
    ("member.remove",               C::ManageTeam),
    ("member.remove.failed",        C::ManageTeam),
    ("member.invite",               C::ManageTeam),
    ("member.invite.failed",        C::ManageTeam),
    ("member.invite_revoke",        C::ManageTeam),
    ("member.invite_revoke.failed", C::ManageTeam),
    ("workspace.rename",            C::ManageTeam),
    ("workspace.rename.failed",     C::ManageTeam),
    ("workspace.delete",            C::ManageTeam),
    ("workspace.delete.failed",     C::ManageTeam),
    ("cmk.register",                C::ManageSecurity),
    ("cmk.register.failed",         C::ManageSecurity),
    ("cmk.revoke",                  C::ManageSecurity),
    ("cmk.revoke.failed",           C::ManageSecurity),
    ("cmk.rotate",                  C::ManageSecurity),
    ("cmk.rotate.failed",           C::ManageSecurity),
];

/// The capability a dashboard-performed action requires, or `None` when the
/// action is not one the endpoint records.
#[must_use]
pub fn web_action_capability(action: &str) -> Option<Capability> {
    WEB_CONTROL_ACTIONS
        .iter()
        .find(|(a, _)| *a == action)
        .map(|(_, c)| *c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scope::KeyScope;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn principal(auth_method: AuthMethod, role: Option<Role>) -> Claims {
        Claims {
            tenant_id: TenantId::from_jwt_claim(Uuid::nil()),
            sub: "user_test".into(),
            auth_method,
            role,
            key_scope: KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        }
    }

    const ALL: [Capability; 22] = [
        C::ReadTraces,
        C::ViewSpend,
        C::ViewSettings,
        C::ViewKeys,
        C::MintKeys,
        C::ManageAllKeys,
        C::GrantPassthrough,
        C::ViewPolicies,
        C::EditPolicies,
        C::EditBudgets,
        C::EditProjects,
        C::ManageAlerts,
        C::AnnotateTraces,
        C::WritePrompts,
        C::ViewProviderKeys,
        C::ManageProviderKeys,
        C::ManageBilling,
        C::ManageTeam,
        C::ManageSecurity,
        C::ReadControlAudit,
        C::ManageControls,
        C::GrantAdminScope,
    ];

    #[test]
    fn every_capability_has_its_own_row_and_a_unique_slug() {
        assert_eq!(ALL.len(), MATRIX.len());
        let mut slugs = std::collections::HashSet::new();
        for c in ALL {
            assert_eq!(c.row().cap, c);
            assert!(slugs.insert(c.slug()), "duplicate slug {}", c.slug());
        }
    }

    #[test]
    fn an_mtls_identity_holds_nothing() {
        let p = principal(AuthMethod::Mtls, None);
        for c in ALL {
            assert!(!p.can(c), "mTLS must not hold {c:?}");
        }
    }

    #[test]
    fn the_billing_role_sees_spend_and_manages_billing_but_reads_no_traces() {
        let b = principal(AuthMethod::JwtBearer, Some(Role::Billing));
        assert!(b.can(C::ViewSpend));
        assert!(b.can(C::ManageBilling));
        assert!(b.can(C::EditBudgets));
        assert!(
            !b.can(C::ReadTraces),
            "billing must not read recorded content"
        );
        assert!(!b.can(C::MintKeys));
        assert!(!b.can(C::EditPolicies));
        assert!(!b.can(C::ManageTeam));
        assert!(!b.can(C::AnnotateTraces));
    }

    #[test]
    fn a_viewer_and_a_developer_cannot_touch_budgets_policy_team_or_security() {
        for role in [Role::Viewer, Role::Member] {
            let p = principal(AuthMethod::JwtBearer, Some(role));
            for c in [
                C::EditBudgets,
                C::EditPolicies,
                C::EditProjects,
                C::ManageTeam,
                C::ManageSecurity,
                C::ManageAllKeys,
                C::GrantPassthrough,
                C::GrantAdminScope,
                C::ManageProviderKeys,
                C::ReadControlAudit,
            ] {
                assert!(!p.can(c), "{role:?} must not hold {c:?}");
            }
        }
        let dev = principal(AuthMethod::JwtBearer, Some(Role::Member));
        assert!(dev.can(C::MintKeys));
        assert!(dev.can(C::ManageAlerts));
        assert!(!principal(AuthMethod::JwtBearer, Some(Role::Viewer)).can(C::MintKeys));
    }

    #[test]
    fn an_unrecognised_slug_reads_and_writes_nothing() {
        let u = principal(AuthMethod::JwtBearer, None);
        let granted: Vec<_> = ALL.into_iter().filter(|c| u.can(*c)).collect();
        assert_eq!(granted, vec![C::ReadTraces, C::ViewSpend]);
    }

    #[test]
    fn the_admin_role_holds_everything() {
        let a = principal(AuthMethod::JwtBearer, Some(Role::Owner));
        for c in ALL {
            assert!(a.can(c), "admin must hold {c:?}");
        }
    }

    #[test]
    fn a_tenant_api_key_never_holds_a_human_control_capability() {
        let k = principal(AuthMethod::ApiKey, None);
        for c in [
            C::MintKeys,
            C::ManageAllKeys,
            C::GrantPassthrough,
            C::GrantAdminScope,
            C::EditPolicies,
            C::EditProjects,
            C::ManageProviderKeys,
            C::ManageBilling,
            C::ManageTeam,
            C::ManageSecurity,
            C::ReadControlAudit,
            C::ViewKeys,
        ] {
            assert!(!k.can(c), "an API key must not hold {c:?}");
        }
    }

    #[test]
    fn every_registered_control_route_is_unique_and_audits_every_mutation_but_checkout() {
        let mut seen = std::collections::HashSet::new();
        for r in CONTROL_ROUTES {
            assert!(
                seen.insert((r.method, r.path)),
                "duplicate {:?} {}",
                r.method,
                r.path
            );
            let mutating = r.method != Method::Get;
            let stateless = matches!(
                r.path,
                "/v1/billing/checkout"
                    | "/v1/billing/portal"
                    | "/v1/alerts/test"
                    | "/v1/controls/alert-channels/{id}/test"
                    | "/v1/exports/otel/{id}/test"
                    // OG-11: a dry run of the dispatch plan — nothing is written.
                    | "/v1/routing/simulate"
            );
            assert_eq!(
                r.audit.is_some(),
                mutating && !stateless,
                "{:?} {}: a mutating control route records an audit row",
                r.method,
                r.path
            );
        }
    }

    /// No registered control route is reachable by a viewer or an unrecognised
    /// slug — the control plane is never the least-privileged column's.
    #[test]
    fn no_control_route_is_open_to_a_viewer_or_an_unrecognised_slug() {
        let viewer = principal(AuthMethod::JwtBearer, Some(Role::Viewer));
        let unknown = principal(AuthMethod::JwtBearer, None);
        for r in CONTROL_ROUTES {
            // OG-37 (`specs/OG-37-external-kms-byok.md` §2): the KMS status READ is
            // `ViewSettings` by design — every writing KMS route is `ManageSecurity`.
            if r.method == Method::Get && r.path == "/v1/security/kms" {
                continue;
            }
            assert!(
                !viewer.can(r.cap),
                "{:?} {} open to viewer",
                r.method,
                r.path
            );
            assert!(
                !unknown.can(r.cap),
                "{:?} {} open to unknown slug",
                r.method,
                r.path
            );
        }
    }

    #[test]
    fn web_actions_resolve_and_unknown_actions_do_not() {
        assert_eq!(
            web_action_capability("member.role_change"),
            Some(C::ManageTeam)
        );
        assert_eq!(web_action_capability("cmk.rotate"), Some(C::ManageSecurity));
        assert_eq!(web_action_capability("api_key.create"), None);
        assert_eq!(web_action_capability(""), None);
    }

    #[test]
    fn least_role_names_the_cheapest_holder() {
        assert_eq!(C::ReadTraces.least_role(), "viewer");
        assert_eq!(C::ViewSpend.least_role(), "viewer");
        assert_eq!(C::ManageBilling.least_role(), "billing");
        assert_eq!(C::MintKeys.least_role(), "developer");
        assert_eq!(C::ManageSecurity.least_role(), "admin");
    }
}
