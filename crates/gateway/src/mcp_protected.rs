//! Protected MCP calls retain shared admission; only committed reservations can send.
use super::*;
use crate::action_control::{self as ac, execution as ex};
use std::sync::atomic::Ordering;

/// The Tools step classifies a call before legacy approval consumption.
/// Errors fail CLOSED. The marker is shared by the parsed request and its clone.
pub(crate) async fn classify(
    state: &AppState,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    mcp: &McpRequest,
    server: &Server,
    tool: &str,
) -> anyhow::Result<bool> {
    #[cfg(test)]
    if EXECUTION_REFUSAL.try_with(|_| ()).is_ok() {
        // Replace only database classification in the real-route HTTP test.
        mcp.protected.store(true, Ordering::Release);
        return Ok(true);
    }
    if !ac::enabled(resolved) {
        return Ok(false);
    }
    let pool = state
        .pg
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("evidence_unavailable"))?;
    let mut db = pool.get().await?;
    let tx = db.transaction().await?;
    let protected = classify_tx(&tx, claims, resolved, mcp, server, tool).await?;
    tx.commit().await?;
    #[cfg(test)]
    if let Ok((classified, resume)) = CLASSIFICATION_PAUSE.try_with(Clone::clone) {
        classified.wait().await;
        resume.wait().await;
    }
    Ok(protected)
}
/// Classification uses a short transaction. Activation takes the exclusive server
/// lock; protected execution reloads in its own reservation transaction.
pub(super) async fn classify_tx(
    tx: &tokio_postgres::Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    mcp: &McpRequest,
    server: &Server,
    tool: &str,
) -> anyhow::Result<bool> {
    ex::deadline_tx(
        tx,
        Duration::from_secs(mcp_policy::settings()?.limits.call_timeout_secs),
    )
    .await?;
    let protected = ac::policy_store::protected_tx(tx, claims, resolved, server.id, tool)
        .await?
        .is_some();
    if protected {
        // Validate preserved bytes before Value normalization can erase duplicates.
        arguments(mcp).map_err(|_| anyhow::anyhow!("invalid_protected_request"))?;
        mcp.protected.store(true, Ordering::Release);
    } else if ac::policy_store::protected_elsewhere_tx(tx, claims, server.id, &server.url, tool)
        .await?
    {
        // Audit H1: the same upstream is protected under another registration.
        anyhow::bail!("mcp_tool_protected_elsewhere");
    }
    Ok(protected)
}

/// Errors fail CLOSED before forwarding. The epoch is the only retained DB state.
pub(super) async fn legacy_preflight(
    state: &AppState,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    mcp: &McpRequest,
    server: &Server,
) -> anyhow::Result<Option<i64>> {
    if !ac::enabled(resolved) {
        return Ok(None);
    }
    let timeout = Duration::from_secs(mcp_policy::settings()?.limits.call_timeout_secs);
    tokio::time::timeout(timeout, async {
        let mut db = state
            .pg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("evidence_unavailable"))?
            .get()
            .await?;
        let tx = db.transaction().await?;
        let tool = mcp.envelope["params"]["name"].as_str().unwrap_or_default();
        classify_tx(&tx, claims, resolved, mcp, server, tool).await?;
        let epoch = ac::policy_store::legacy_epoch_tx(&tx, claims, server.id, tool).await?;
        tx.commit().await?;
        Ok(Some(epoch))
    })
    .await?
}
/// The linearisation point for a legacy call: a short transaction re-reads the
/// activation epoch immediately before the send (after credentials, pin checks
/// and `ensure_fresh`). A protection that commits after this read can still race
/// the send; ADR-082's tool-side attestation verifier is the backstop for that
/// window, and `legacy_after_send` records it. No connection is held across I/O.
/// # Errors
/// Fail-CLOSED: a changed epoch or any read error refuses the send.
pub(super) async fn legacy_recheck(
    state: &AppState,
    claims: &crate::auth::Claims,
    mcp: &McpRequest,
    server: &Server,
    before: i64,
) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(mcp_policy::settings()?.limits.call_timeout_secs);
    tokio::time::timeout(timeout, async {
        let mut db = state
            .pg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("evidence_unavailable"))?
            .get()
            .await?;
        let tx = db.transaction().await?;
        let tool = mcp.envelope["params"]["name"].as_str().unwrap_or_default();
        let now = ac::policy_store::legacy_epoch_tx(&tx, claims, server.id, tool).await?;
        tx.commit().await?;
        anyhow::ensure!(now == before, "protection_activated");
        Ok(())
    })
    .await?
}
/// Errors after a legacy send are ambiguous, never a claim of protected execution.
pub(super) async fn legacy_after_send(
    state: &AppState,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    mcp: &McpRequest,
    server: &Server,
    before: i64,
) -> anyhow::Result<bool> {
    let timeout = Duration::from_secs(mcp_policy::settings()?.limits.call_timeout_secs);
    let rows = tokio::time::timeout(timeout, async {
        let mut db = state
            .pg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("evidence_unavailable"))?
            .get()
            .await?;
        let tx = db.transaction().await?;
        ex::deadline_tx(&tx, timeout).await?;
        let tool = mcp.envelope["params"]["name"].as_str().unwrap_or_default();
        let after = ac::policy_store::legacy_epoch_tx(&tx, claims, server.id, tool).await?;
        if after == before {
            tx.commit().await?;
            return Ok::<_, anyhow::Error>(None);
        }
        let event = ac::ActionEvent {
            event_id: Uuid::new_v4(),
            action_id: Uuid::new_v4(),
            occurred_at: chrono::Utc::now(),
            request_digest: ac::sha(ac::canonical(&mcp.envelope)?.as_bytes()),
            body: ac::ActionPayload::LegacyForwardAttempted {
                server_id: server.id,
                activation_epoch: after,
            },
        };
        let rows = ac::append_actions_tx(&tx, claims, resolved, &[event])
            .await?
            .ok_or_else(|| anyhow::anyhow!("evidence_unavailable"))?;
        tx.commit().await?;
        Ok(Some(rows))
    })
    .await??;
    let raced = rows.is_some();
    ex::after_commit(
        Some(&state.audit_chain),
        claims,
        rows.into_iter().collect(),
        timeout,
    );
    Ok(raced)
}

pub(super) fn arguments(mcp: &McpRequest) -> anyhow::Result<String> {
    let value = if let Some(raw) = &mcp.raw_body {
        serde_json::from_str::<Value>(&ac::canonical_json(std::str::from_utf8(raw)?)?)?
    } else {
        mcp.envelope.clone()
    };
    anyhow::ensure!(
        value["params"]
            .as_object()
            .is_some_and(|p| p.keys().all(|k| matches!(k.as_str(), "name" | "arguments"))),
        "invalid_protected_request"
    );
    let args = value["params"]
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    ac::canonical(&args)
}
fn selector(headers: &HeaderMap, name: &str) -> anyhow::Result<Option<Uuid>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    anyhow::ensure!(values.next().is_none(), "invalid_execution_selector");
    let invalid = || anyhow::anyhow!("invalid_execution_selector");
    Ok(Some(
        Uuid::parse_str(value.to_str().map_err(|_| invalid())?).map_err(|_| invalid())?,
    ))
}
fn refusal(err: anyhow::Error) -> Response {
    if let Some(p) = err.downcast_ref::<ex::ApprovalRequired>() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"approval_required","approval_id":p.id,"expires_at":p.expires_at})),
        )
            .into_response();
    }
    let code = match err.to_string().as_str() {
        "approval_mismatch" => "approval_mismatch",
        "approval_expired" => "approval_expired",
        "approval_denied" => "approval_denied",
        "approval_not_approved" => "approval_not_approved",
        "policy_denied" => "policy_denied",
        "principal_required" => "principal_required",
        "principal_invalid" => "principal_invalid",
        "principal_unverifiable" => "principal_unverifiable",
        "receipt_key_conflict" => "receipt_key_conflict",
        "mcp_tool_definition_changed" => "mcp_tool_definition_changed",
        "idempotency_mismatch" => "idempotency_mismatch",
        "idempotency_key_required" => "idempotency_key_required",
        "invalid_execution_selector" => "invalid_execution_selector",
        "protected_transport_unsupported" => "protected_transport_unsupported",
        "workspace_paused" => "workspace_paused",
        "key_revoked" => "key_revoked",
        _ => "protected_execution_unavailable",
    };
    error(
        if matches!(
            code,
            "idempotency_key_required"
                | "invalid_execution_selector"
                | "protected_transport_unsupported"
        ) {
            StatusCode::BAD_REQUEST
        } else if matches!(
            code,
            "mcp_tool_definition_changed" | "principal_required" | "principal_invalid"
        ) {
            StatusCode::FORBIDDEN
        } else if code == "workspace_paused" {
            StatusCode::LOCKED
        } else if code == "key_revoked" {
            StatusCode::UNAUTHORIZED
        } else if matches!(
            code,
            "protected_execution_unavailable" | "principal_unverifiable" | "receipt_key_conflict"
        ) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::CONFLICT
        },
        code,
    )
}
/// Request-path half of paused-refusal evidence: resolves the server and arguments exactly as
/// dispatch does and offers the call to the background queue. In-process only (no database, no
/// `await`). Skips anything that is not a flag-on `tools/call` on a snapshot server.
/// # Errors
/// None; fail-OPEN. Undigestible arguments are counted, never an error.
pub(crate) fn offer_paused(
    queue: &ac::paused_evidence::PausedEvidence,
    claims: &crate::auth::Claims,
    resolved: Option<&std::sync::Arc<crate::entitlement_cache::ResolvedEntitlements>>,
    mcp: &McpRequest,
    since: chrono::DateTime<chrono::Utc>,
) {
    let Some(resolved) = resolved.filter(|r| ac::enabled(Some(r))) else {
        return;
    };
    if mcp.method != "tools/call" {
        return;
    }
    // Same lookup as dispatch: a slug the snapshot lacks would 404 there, so no evidence.
    let Some(server) = resolved
        .mcp
        .as_ref()
        .and_then(|m| m.servers.iter().find(|s| s.slug == mcp.slug))
    else {
        return;
    };
    let Some(tool) = mcp.envelope["params"]["name"].as_str() else {
        return;
    };
    let Ok(args) = arguments(mcp) else {
        return ex::evidence_deferred();
    };
    let call = ex::PausedCall {
        server: server.id,
        tool,
        args: &args,
    };
    queue.offer(claims, resolved, &call, since);
}
/// Errors fail CLOSED before reservation; any ambiguous result after send is Unknown.
pub(super) async fn dispatch<const INVOKE: bool>(
    state: &AppState,
    headers: &HeaderMap,
    admitted: &admission::Admitted<McpRoute<INVOKE>>,
    snapshot: &Snapshot,
    server: &Server,
) -> Response {
    let result = async {
        anyhow::ensure!(
            server.transport == "streamable_http",
            "protected_transport_unsupported"
        );
        let key = selector(headers, "idempotency-key")?
            .ok_or_else(|| anyhow::anyhow!("idempotency_key_required"))?;
        let approval = selector(headers, "x-tracelane-approval-id")?;
        let signer = state
            .action_signer
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("attestation_signer_unavailable"))?;
        let pool = state
            .pg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("evidence_unavailable"))?;
        let tenant = &admitted.claims.tenant_id;
        let fpkey = crate::tool_fingerprint::workspace_key(tenant)
            .ok_or_else(|| anyhow::anyhow!("fingerprint_unavailable"))?;
        let context =
            mcp_policy::execution_binding(&admitted.parsed, server, headers, fpkey.expose_secret())
                ["execution_context"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("fingerprint_unavailable"))?
                .to_owned();
        let args = arguments(&admitted.parsed)?;
        let tool = admitted.parsed.envelope["params"]["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid_tool_name"))?;
        let secret = credential(snapshot, server, tenant, headers)
            .await
            .map_err(anyhow::Error::msg)?;
        let (mut outgoing, session) = crate::mcp_transport::streamable_headers(
            &admitted.claims,
            server,
            secret.as_ref(),
            headers,
        )
        .map_err(anyhow::Error::msg)?;
        let session_context = crate::mcp_transport::context(tenant, server, secret.as_ref())
            .map_err(anyhow::Error::msg)?;
        // A changed definition is refused inside the reservation so the refusal is signed
        // evidence; every other verification failure still refuses here, before any ledger work.
        let mut definition_changed = false;
        if snapshot
            .approved
            .contains_key(&(server.id, tool.to_owned()))
        {
            match crate::mcp_inspection::verify(snapshot, server, tenant, secret.as_ref(), tool)
                .await
            {
                Err("mcp_tool_definition_changed") => definition_changed = true,
                other => {
                    other.map_err(anyhow::Error::msg)?;
                }
            }
        }
        let client = safe_client(&server.url).await.map_err(anyhow::Error::msg)?;
        mcp_policy::ensure_fresh(
            state,
            headers,
            &admitted.claims,
            admitted.entitlements.as_ref(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control_changed"))?;
        let principal = crate::action_control::principal::verify_headers(
            state
                .pg
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("evidence_unavailable"))?,
            &admitted.claims.tenant_id,
            headers,
        )
        .await;
        let call = ex::Call {
            principal: Some(&principal),
            server: server.id,
            tool,
            args: &args,
            execution_context: &context,
            idempotency_key: key,
            approval_id: approval,
            legacy: mcp_policy::evaluate(
                &snapshot.policy,
                &snapshot.rules,
                server.id,
                admitted
                    .claims
                    .api_key_id()
                    .and_then(|k| Uuid::parse_str(k).ok()),
                tool,
            ),
            mode: snapshot.policy.rules_mode,
            definition_changed,
        };
        let receipt = ex::execute(
            pool,
            &admitted.claims,
            admitted.entitlements.as_deref(),
            &call,
            signer,
            Some(&state.audit_chain),
            |attestation| async move {
                let send = async {
                    mcp_policy::ensure_fresh(
                        state,
                        headers,
                        &admitted.claims,
                        admitted.entitlements.as_ref(),
                    )
                    .await
                    .map_err(|_| "control_changed")?;
                    // outbound_headers is an allowlist; inbound attestations never survive it.
                    outgoing.insert(
                        ex::HEADER,
                        HeaderValue::from_str(&attestation).map_err(|_| "attestation_invalid")?,
                    );
                    let mut response = client
                        .post(&server.url)
                        .headers(outgoing)
                        .json(&admitted.parsed.envelope)
                        .send()
                        .await
                        .map_err(|e| {
                            let _ = e.without_url();
                            "upstream_unavailable"
                        })?;
                    crate::mcp_transport::streamable_response(
                        &admitted.claims,
                        session_context,
                        &Method::POST,
                        "tools/call",
                        session,
                        &mut response,
                    )?;
                    let limit = mcp_policy::settings()
                        .map_err(|_| "mcp_policy_invalid")?
                        .limits
                        .max_response_bytes;
                    let mut bytes = Vec::new();
                    while let Some(chunk) =
                        response.chunk().await.map_err(|_| "upstream_unavailable")?
                    {
                        if bytes.len().saturating_add(chunk.len()) > limit {
                            return Err("result_too_large");
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    // Only a matching minimized tool receipt establishes a completed effect.
                    // Non-JSON/streamed/failed/malformed replies remain ambiguous.
                    parse_receipt(response.status(), &admitted.parsed.envelope["id"], &bytes)
                }
                .await;
                match send {
                    Ok((id, Some(signature))) => ex::Outcome::Countersigned(id, signature),
                    Ok((id, None)) => ex::Outcome::Succeeded(id),
                    Err(_) => ex::Outcome::Unknown,
                }
            },
        )
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(if definition_changed {
                "mcp_tool_definition_changed"
            } else {
                "protected_policy_changed"
            })
        })?;
        Ok::<_, anyhow::Error>(
            json!({"jsonrpc":"2.0","id":admitted.parsed.envelope["id"],"result":{"structuredContent":receipt}}),
        )
    };
    // execute owns its post-send timeout/Unknown handling. Do not wrap the whole
    // operation in a timeout that could expose a retryable error after forwarding.
    #[cfg(test)]
    let result = match EXECUTION_REFUSAL.try_with(|code| *code) {
        Ok(code) => Err(anyhow::anyhow!(code)),
        Err(_) => result.await,
    };
    #[cfg(not(test))]
    let result = result.await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(e) => refusal(e),
    }
}

/// The tool's receipt id and, when it countersigned (ACT-17), its hex signature.
type ToolReceipt = (Uuid, Option<String>);
fn parse_receipt(
    status: StatusCode,
    id: &Value,
    bytes: &[u8],
) -> Result<ToolReceipt, &'static str> {
    // The shared wire parser refuses recursive duplicates without narrowing valid
    // JSON-RPC result data (for example, fractional tool metadata).
    let value = crate::strict_json::from_slice(bytes).map_err(|_| "invalid_mcp_response")?;
    response_receipt(status, id, &value)
}

fn response_receipt(
    status: StatusCode,
    id: &Value,
    value: &Value,
) -> Result<ToolReceipt, &'static str> {
    if !status.is_success()
        || value["jsonrpc"] != "2.0"
        || value.get("id") != Some(id)
        || !(id.is_string() || id.is_number() || id.is_null())
        || !value.get("result").is_some_and(Value::is_object)
        || value.get("error").is_some()
        || value["result"].get("isError").is_some_and(|v| v != false)
    {
        return Err("invalid_mcp_response");
    }
    let receipt = value["result"]["structuredContent"]["tool_receipt"]
        .as_str()
        .ok_or("invalid_mcp_response")?;
    // Optional; whether it is REQUIRED is decided against the registered key in `execute`.
    let signature = match value["result"]["structuredContent"].get("tool_receipt_signature") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("invalid_mcp_response"),
    };
    Ok((
        Uuid::parse_str(receipt).map_err(|_| "invalid_mcp_response")?,
        signature,
    ))
}

#[cfg(test)]
mod fix_tests {
    use super::*;
    #[test]
    fn invalid_uuid_selector_is_client_error() {
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", HeaderValue::from_static("invalid-uuid"));
        assert_eq!(
            refusal(selector(&headers, "idempotency-key").unwrap_err()).status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[test]
    fn non_text_selector_is_client_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-tracelane-approval-id",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert_eq!(
            refusal(selector(&headers, "x-tracelane-approval-id").unwrap_err()).status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[test]
    fn duplicate_money_is_rejected_before_value_normalization() {
        let mcp=McpRequest {raw_body:Some(Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount_minor":1,"amount_minor":1500000}}}"#)),protected:Default::default(),slug:"synthetic".into(),method:"tools/call".into(),http_method:Method::POST,envelope:json!({"params":{"arguments":{"amount_minor":1500000}}})};
        assert!(arguments(&mcp).is_err());
    }
}

#[cfg(test)]
mod response_shape_tests {
    use super::*;
    fn valid() -> Value {
        json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"tool_receipt":Uuid::nil()}}})
    }
    #[test]
    fn response_shape_duplicate_envelope_members_are_unknown() {
        let bytes = br#"{"jsonrpc":"1.0","jsonrpc":"2.0","id":99,"id":1,"result":{"structuredContent":{"tool_receipt":"00000000-0000-0000-0000-000000000000"}}}"#;
        assert!(parse_receipt(StatusCode::OK, &json!(1), bytes).is_err());
    }
    #[test]
    fn response_shape_duplicate_receipt_is_unknown() {
        let bytes = br#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"tool_receipt":"invalid","tool_receipt":"00000000-0000-0000-0000-000000000000"}}}"#;
        assert!(parse_receipt(StatusCode::OK, &json!(1), bytes).is_err());
    }
    #[test]
    fn response_shape_valid_receipt() {
        let mut wire = valid();
        wire["result"]["metadata"] = json!({"score":0.95});
        assert_eq!(
            parse_receipt(StatusCode::OK, &json!(1), wire.to_string().as_bytes()),
            Ok((Uuid::nil(), None))
        );
        assert_eq!(
            response_receipt(StatusCode::OK, &json!(1), &valid()),
            Ok((Uuid::nil(), None))
        );
    }
    #[test]
    fn response_shape_countersignature_is_extracted() {
        let mut v = valid();
        v["result"]["structuredContent"]["tool_receipt_signature"] = json!("ab");
        assert_eq!(
            response_receipt(StatusCode::OK, &json!(1), &v),
            Ok((Uuid::nil(), Some("ab".into())))
        );
    }
    #[test]
    fn response_shape_null_countersignature_is_absent() {
        let mut v = valid();
        v["result"]["structuredContent"]["tool_receipt_signature"] = json!(null);
        assert_eq!(
            response_receipt(StatusCode::OK, &json!(1), &v),
            Ok((Uuid::nil(), None))
        );
    }
    #[test]
    fn response_shape_non_text_countersignature_is_unknown() {
        for bad in [json!(7), json!({"sig":"ab"})] {
            let mut v = valid();
            v["result"]["structuredContent"]["tool_receipt_signature"] = bad;
            assert!(response_receipt(StatusCode::OK, &json!(1), &v).is_err());
        }
    }
    #[test]
    fn response_shape_missing_jsonrpc_is_unknown() {
        let mut v = valid();
        v.as_object_mut().unwrap().remove("jsonrpc");
        assert!(response_receipt(StatusCode::OK, &json!(1), &v).is_err());
    }
    #[test]
    fn response_shape_wrong_jsonrpc_is_unknown() {
        let mut v = valid();
        v["jsonrpc"] = json!("1.0");
        assert!(response_receipt(StatusCode::OK, &json!(1), &v).is_err());
    }
    #[test]
    fn response_shape_result_and_string_error_is_unknown() {
        let mut v = valid();
        v["error"] = json!("timeout");
        assert!(response_receipt(StatusCode::OK, &json!(1), &v).is_err());
    }
    #[test]
    fn response_shape_result_and_null_error_is_unknown() {
        let mut v = valid();
        v["error"] = Value::Null;
        assert!(response_receipt(StatusCode::OK, &json!(1), &v).is_err());
    }
    #[test]
    fn response_shape_negative_envelopes_are_unknown() {
        let mut wrong_id = valid();
        wrong_id["id"] = json!(2);
        let mut invalid_receipt = valid();
        invalid_receipt["result"]["structuredContent"]["tool_receipt"] = json!("bad");
        let mut tool_error = valid();
        tool_error["result"]["isError"] = json!(true);
        let mut object_error = valid();
        object_error["error"] = json!({"code":-32000,"message":"timeout"});
        for v in [
            wrong_id,
            invalid_receipt,
            tool_error,
            object_error,
            json!({"jsonrpc":"2.0","id":1}),
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"timeout"}}),
            json!({"jsonrpc":"2.0","id":1,"tool_receipt":Uuid::nil()}),
            json!({"jsonrpc":"2.0","result":{"structuredContent":{"tool_receipt":Uuid::nil()}}}),
            json!([]),
            Value::Null,
        ] {
            assert!(
                response_receipt(StatusCode::OK, &json!(1), &v).is_err(),
                "{v}"
            );
        }
        assert!(response_receipt(StatusCode::BAD_GATEWAY, &json!(1), &valid()).is_err());
    }
}

#[cfg(test)]
tokio::task_local! {
    pub(crate) static CLASSIFICATION_PAUSE: (std::sync::Arc<tokio::sync::Barrier>, std::sync::Arc<tokio::sync::Barrier>);
}

#[cfg(test)]
mod fix_pass_tests {
    use super::*;
    #[test]
    fn fix_pass_protected_params_reject_unbound_members() {
        for raw in [false, true] {
            for member in ["_meta", "unknown"] {
                let mut envelope = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{}}});
                envelope["params"][member] = json!({"unbound":"value"});
                let mcp = McpRequest {
                    raw_body: raw.then(|| Bytes::from(envelope.to_string())),
                    envelope,
                    protected: Default::default(),
                    slug: "synthetic".into(),
                    method: "tools/call".into(),
                    http_method: Method::POST,
                };
                assert!(
                    arguments(&mcp).is_err(),
                    "unbound {member} accepted (raw={raw})"
                );
            }
        }
    }
}

// Inject only the execution error; exercise the real protected dispatch handler's response.
#[cfg(test)]
tokio::task_local! { static EXECUTION_REFUSAL: &'static str; }
#[cfg(test)]
mod denial_http_tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn denied_grant_http_response_is_409_approval_denied() {
        let (state, claims) = super::super::tests::fixture("https://example.invalid");
        let _auth = crate::auth::test_claims::Guard::set(claims);
        // The real public router runs admission, proxy dispatch and protected dispatch.
        // Only PG classification and the execution result are replaced by task-local seams.
        let app = super::super::router(state);
        let response = EXECUTION_REFUSAL
            .scope(
                "approval_denied",
                app.oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/v1/mcp/fixture")
                        .header("authorization", "Bearer fixture")
                        .body(Body::from(super::super::tests::call().to_string()))
                        .unwrap(),
                ),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "approval_denied");
        assert_eq!(body["message"], "approval denied");
    }
}

#[cfg(test)]
mod paused_refusal_tests {
    async fn check(err: &str, status: u16, code: &str) {
        let r = super::refusal(anyhow::anyhow!("{err}"));
        assert_eq!(r.status().as_u16(), status, "{err}");
        let body = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains(code), "{err}");
    }
    #[tokio::test]
    async fn refusal_maps_workspace_paused_to_423() {
        check("workspace_paused", 423, "workspace_paused").await;
    }
    #[tokio::test]
    async fn refusal_maps_key_revoked_to_401() {
        check("key_revoked", 401, "key_revoked").await;
    }
    #[tokio::test]
    async fn refusal_keeps_other_codes_and_unknown_errors_503() {
        check("policy_denied", 409, "policy_denied").await;
        check("anything_else", 503, "protected_execution_unavailable").await;
    }
}

#[cfg(test)]
mod receipt_key_refusal_tests {
    #[tokio::test]
    async fn b634_http_conflict_code() {
        let response = super::refusal(anyhow::anyhow!("receipt_key_conflict"));
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"], "receipt_key_conflict");
        assert_eq!(value["message"], "receipt key conflict");
    }
}
