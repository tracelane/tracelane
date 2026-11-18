use super::*;
fn contract() -> Contract {
    parse_contract(&json!({"tool_ref":Uuid::nil(),"server_id":Uuid::nil(),"tool_name":"pay","version":1,"protected":true,"fields":{
        "amount":{"path":"/amount","kind":"minor_units","required":true,"evidence":"clear"},
        "memo":{"path":"/memo","kind":"string","required":false,"evidence":"digest_only"}
    }}).to_string()).unwrap()
}
fn policy() -> Policy {
    parse_policy(
        &json!({"policy_id":Uuid::nil(),"version":1,"agents":null,"rules":[
            {"id":"first","when":[],"decision":"allow"},
            {"id":"second","when":[],"decision":"deny"}
        ]})
        .to_string(),
        &contract(),
    )
    .unwrap()
}
fn empty(p: Option<&Policy>, legacy: Action, mode: Mode) -> (Action, String) {
    evaluate(p, Uuid::nil(), &BTreeMap::new(), legacy, mode)
}
#[test]
fn first_match() {
    let p = policy();
    assert_eq!(
        empty(Some(&p), Action::Deny, Mode::Observe),
        (Action::Allow, "first".into())
    );
}
#[test]
fn absent_policy() {
    assert_eq!(
        empty(None, Action::Allow, Mode::Observe).0,
        Action::Deny,
        "absent policy authorized"
    );
    let mut p = policy();
    p.rules.clear();
    assert_eq!(
        empty(Some(&p), Action::Allow, Mode::Enforce).0,
        Action::Deny,
        "empty policy authorized"
    );
    p = policy();
    p.agents = Some(vec![Uuid::new_v4()]);
    assert_eq!(
        empty(Some(&p), Action::Allow, Mode::Enforce).0,
        Action::Deny
    );
}
#[test]
fn legacy_dominance() {
    use Action::{Allow, Deny, RequireApproval};
    for (protected, legacy, expected) in [
        (Allow, Allow, Allow),
        (Allow, RequireApproval, RequireApproval),
        (Allow, Deny, Deny),
        (RequireApproval, Allow, RequireApproval),
        (RequireApproval, RequireApproval, RequireApproval),
        (RequireApproval, Deny, Deny),
        (Deny, Allow, Deny),
        (Deny, RequireApproval, Deny),
        (Deny, Deny, Deny),
    ] {
        let mut p = policy();
        p.rules[0].decision = protected;
        assert_eq!(
            empty(Some(&p), legacy, Mode::Enforce).0,
            expected,
            "protected={protected:?}, legacy={legacy:?}"
        );
        assert_eq!(empty(Some(&p), legacy, Mode::Observe).0, protected);
    }
}
#[test]
fn typed_fields() {
    let c = contract();
    for bad in [
        json!({}),
        json!({"amount":-1}),
        json!({"amount":"1"}),
        json!({"amount":true}),
        json!({"amount":1,"memo":false}),
    ] {
        assert!(
            fields(&c, &bad).is_err(),
            "invalid typed field accepted: {bad}"
        );
    }
    let mut bad = c.clone();
    bad.fields.get_mut("memo").unwrap().evidence = FieldMode::Clear;
    assert!(
        parse_contract(&serde_json::to_string(&bad).unwrap()).is_err(),
        "clear confidential field accepted"
    );
}
#[test]
fn operators() {
    for (op, v, expected) in [
        ("eq", json!(5), true),
        ("ne", json!(5), false),
        ("gt", json!(4), true),
        ("gte", json!(5), true),
        ("lt", json!(5), false),
        ("lte", json!(5), true),
        ("in_list", json!([5, 6]), true),
        ("not_in_list", json!([5]), false),
        ("present", Value::Null, true),
        ("absent", Value::Null, false),
    ] {
        let raw=json!({"policy_id":Uuid::nil(),"version":1,"agents":null,"rules":[{"id":"match","when":[{"field":"amount","op":op,"value":v}],"decision":"allow"}]}).to_string();
        let p = parse_policy(&raw, &contract()).unwrap();
        let f = fields(&contract(), &json!({"amount":5})).unwrap();
        assert_eq!(
            evaluate(Some(&p), Uuid::nil(), &f, Action::Allow, Mode::Observe).0 == Action::Allow,
            expected,
            "{op}"
        );
    }
    let mut p = policy();
    p.rules[0].when = vec![Condition {
        field: "amount".into(),
        op: Op::Gt,
        value: Some(json!("5")),
    }];
    assert!(
        parse_policy(&serde_json::to_string(&p).unwrap(), &contract()).is_err(),
        "type-invalid operator accepted"
    );
}
#[test]
fn digest_vectors() {
    let t = TenantId::from_jwt_claim(Uuid::nil());
    let c = contract();
    assert_eq!(
        intent_digest(&t, Uuid::nil(), &c, 1, r#"{"amount":1,"memo":"x"}"#).unwrap(),
        "826fa81c9bae1d3ca33a79c26b507e22f825b06844a0f9f6c4635faea0a2708c"
    );
    assert_eq!(
        intent_digest(&t, Uuid::nil(), &c, 1, r#"{"amount":1,"memo":"x"}"#).unwrap(),
        intent_digest(&t, Uuid::nil(), &c, 1, r#"{"memo":"x","amount":1}"#).unwrap()
    );
}
#[test]
fn intent_binding() {
    let t = TenantId::from_jwt_claim(Uuid::nil());
    let c = contract();
    let k = Uuid::nil();
    let base = intent_digest(&t, k, &c, 1, r#"{"amount":1}"#).unwrap();
    let foreign_tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    let foreign_contract = Contract {
        server_id: Uuid::new_v4(),
        ..c.clone()
    };
    for (tenant, key, contract, version, args) in [
        (foreign_tenant, k, c.clone(), 1, r#"{"amount":1}"#),
        (t.clone(), Uuid::new_v4(), c.clone(), 1, r#"{"amount":1}"#),
        (t.clone(), k, foreign_contract, 1, r#"{"amount":1}"#),
        (t.clone(), k, c.clone(), 2, r#"{"amount":1}"#),
        (t.clone(), k, c.clone(), 1, r#"{"amount":1,"extra":true}"#),
    ] {
        assert_ne!(
            base,
            intent_digest(&tenant, key, &contract, version, args).unwrap(),
            "intent mutation not bound"
        );
    }
}
#[test]
fn digest_rejections() {
    let t = TenantId::from_jwt_claim(Uuid::nil());
    let c = contract();
    for raw in [
        r#"{"amount":1.0}"#,
        r#"{"amount":1e0}"#,
        r#"{"amount":1,"extra":0.1}"#,
        r#"{"amount":1,"amount":2}"#,
        r#"{"amount":1,"extra":[{"x":1,"x":2}]}"#,
        r#"{"amount":9007199254740992}"#,
    ] {
        assert!(
            intent_digest(&t, Uuid::nil(), &c, 1, raw).is_err(),
            "invalid intent accepted: {raw}"
        );
    }
}
#[test]
fn boundary_and_optional() {
    let c = contract();
    let mut p = policy();
    p.rules[0].when = vec![Condition {
        field: "amount".into(),
        op: Op::Gt,
        value: Some(json!(500000)),
    }];
    p.rules[0].decision = Action::RequireApproval;
    p.rules[1].decision = Action::Allow;
    for (value, expected) in [
        (500000_i64, Action::Allow),
        (500001, Action::RequireApproval),
        (9007199254740991, Action::RequireApproval),
    ] {
        let f = fields(&c, &json!({"amount":value})).unwrap();
        assert_eq!(
            evaluate(Some(&p), Uuid::nil(), &f, Action::Allow, Mode::Observe).0,
            expected
        );
    }
    let f = fields(&c, &json!({"amount":1})).unwrap();
    p.rules[0].when = vec![Condition {
        field: "memo".into(),
        op: Op::Absent,
        value: None,
    }];
    assert_eq!(
        evaluate(Some(&p), Uuid::nil(), &f, Action::Allow, Mode::Observe).0,
        Action::RequireApproval
    );
    p.rules[0].when = vec![Condition {
        field: "memo".into(),
        op: Op::Ne,
        value: Some(json!("x")),
    }];
    assert_eq!(
        evaluate(Some(&p), Uuid::nil(), &f, Action::Allow, Mode::Observe).0,
        Action::Allow,
        "missing must not satisfy ne"
    );
}
#[test]
fn currency_and_boolean() {
    let mut c = contract();
    c.fields.extend(
        serde_json::from_value::<BTreeMap<String, Field>>(json!({
            "currency":{"path":"/currency","kind":"currency","required":true,"evidence":"clear"},
            "ready":{"path":"/ready","kind":"boolean","required":true,"evidence":"clear"}
        }))
        .unwrap(),
    );
    assert!(fields(&c, &json!({"amount":0,"currency":"USD","ready":true})).is_ok());
    for currency in [json!("EUR"), json!("usd"), json!(840), Value::Null] {
        assert!(fields(&c, &json!({"amount":0,"currency":currency,"ready":true})).is_err());
    }
}

#[test]
fn approval_lifetime_is_policy_data() {
    let c = parse_contract(&json!({"tool_ref":Uuid::new_v4(),"server_id":Uuid::new_v4(),"tool_name":"pay","version":1,"protected":true,"fields":{}}).to_string()).unwrap();
    let raw = json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"review","when":[],"decision":"require_approval"}]}).to_string();
    assert!(
        parse_policy(&raw, &c).is_err(),
        "approval policy accepted without expiry data"
    );
}

#[test]
fn approval_lifetime_bounds() {
    let c = contract();
    let mut p = policy();
    p.rules[0].decision = Action::RequireApproval;
    p.approval_ttl_secs = Some(900);
    assert!(parse_policy(&super::canonical(&p).unwrap(), &c).is_ok());
    for ttl in [0, u32::MAX] {
        p.approval_ttl_secs = Some(ttl);
        assert!(parse_policy(&super::canonical(&p).unwrap(), &c).is_err());
    }
}
/// ACT-18: the offline verifier's replay must agree with `evaluate` on every case the
/// evidence can decide, and must flag (never mismatch) the cases it cannot.
#[test]
fn verifier_replay_parity() {
    use tracelane_audit_verifier::action::replay::{Outcome, replay};
    use tracelane_audit_verifier::action::{ClearValue, Decision, EvidenceField, Usd};
    let c = parse_contract(&json!({"tool_ref":Uuid::nil(),"server_id":Uuid::nil(),"tool_name":"pay","version":1,"protected":true,"fields":{
        "amount":{"path":"/amount","kind":"minor_units","required":true,"evidence":"clear"},
        "currency":{"path":"/currency","kind":"currency","required":false,"evidence":"clear"},
        "urgent":{"path":"/urgent","kind":"boolean","required":false,"evidence":"clear"},
        "to":{"path":"/to","kind":"string","required":false,"evidence":"tokenize"},
        "memo":{"path":"/memo","kind":"string","required":false,"evidence":"digest_only"}
    }}).to_string()).unwrap();
    let agent = Uuid::from_u128(7);
    let rule_sets = [
        json!([{"id":"small","when":[{"field":"amount","op":"lt","value":100}],"decision":"allow"},
               {"id":"big","when":[{"field":"amount","op":"gte","value":100}],"decision":"require_approval"}]),
        json!([{"id":"u","when":[{"field":"urgent","op":"eq","value":true},{"field":"amount","op":"gt","value":50}],"decision":"deny"},
               {"id":"usd","when":[{"field":"currency","op":"in_list","value":["USD"]}],"decision":"allow"}]),
        json!([{"id":"cur","when":[{"field":"currency","op":"absent"}],"decision":"require_approval"},
               {"id":"ne","when":[{"field":"amount","op":"ne","value":0},{"field":"urgent","op":"not_in_list","value":[true]}],"decision":"allow"}]),
        json!([{"id":"to","when":[{"field":"to","op":"present"},{"field":"amount","op":"lte","value":10}],"decision":"allow"},
               {"id":"toeq","when":[{"field":"to","op":"eq","value":"acct"}],"decision":"deny"}]),
        json!([{"id":"memo","when":[{"field":"memo","op":"eq","value":"rent"}],"decision":"require_approval"},
               {"id":"rest","when":[{"field":"amount","op":"lt","value":51}],"decision":"allow"}]),
    ];
    let agent_lists = [json!(null), json!([agent]), json!([Uuid::from_u128(8)])];
    let (mut decided, mut opaque) = (0, 0);
    for rules in &rule_sets {
        for agents in &agent_lists {
            let raw = json!({"approval_ttl_secs":600,"policy_id":Uuid::nil(),"version":1,"agents":agents,"rules":rules}).to_string();
            let p = parse_policy(&raw, &c).unwrap();
            let policy_bytes = serde_json::to_vec(&p).unwrap();
            let contract_bytes = serde_json::to_vec(&c).unwrap();
            for amount in [0u64, 10, 11, 50, 51, 99, 100, 101, 9_007_199_254_740_991] {
                for currency in [None, Some("USD")] {
                    for urgent in [None, Some(true), Some(false)] {
                        for to in [None, Some("acct")] {
                            let mut args = json!({"amount": amount, "memo": "rent"});
                            let mut ev = BTreeMap::from([
                                (
                                    "amount".to_string(),
                                    EvidenceField::Clear {
                                        value: ClearValue::MinorUnits(amount),
                                    },
                                ),
                                (
                                    "memo".to_string(),
                                    EvidenceField::DigestOnly {
                                        sha256: "00".into(),
                                    },
                                ),
                            ]);
                            if let Some(cur) = currency {
                                args["currency"] = json!(cur);
                                ev.insert(
                                    "currency".into(),
                                    EvidenceField::Clear {
                                        value: ClearValue::Currency(Usd::Usd),
                                    },
                                );
                            }
                            if let Some(u) = urgent {
                                args["urgent"] = json!(u);
                                ev.insert(
                                    "urgent".into(),
                                    EvidenceField::Clear {
                                        value: ClearValue::Boolean(u),
                                    },
                                );
                            }
                            if let Some(t) = to {
                                args["to"] = json!(t);
                                ev.insert(
                                    "to".into(),
                                    EvidenceField::Tokenize {
                                        hmac: "00".into(),
                                        last4: "acct".into(),
                                    },
                                );
                            }
                            let typed = fields(&c, &args).unwrap();
                            let (action, rule) =
                                evaluate(Some(&p), agent, &typed, Action::Allow, Mode::Observe);
                            let recorded = match action {
                                Action::Allow => Decision::Allow,
                                Action::RequireApproval => Decision::RequireApproval,
                                Action::Deny => Decision::Deny,
                            };
                            let out = replay(
                                &policy_bytes,
                                &contract_bytes,
                                Some(agent),
                                &ev,
                                &recorded,
                                &rule,
                            )
                            .unwrap_or_else(|e| panic!("{e}: {raw} {args}"));
                            match out {
                                Outcome::Match => decided += 1,
                                Outcome::NotReplayable => {
                                    assert!(
                                        to.is_some() || rules.to_string().contains("memo"),
                                        "only an opaque field may block replay: {raw} {args}"
                                    );
                                    opaque += 1;
                                }
                            }
                            // A rule id the policy never produced must never pass.
                            assert!(
                                replay(
                                    &policy_bytes,
                                    &contract_bytes,
                                    Some(agent),
                                    &ev,
                                    &recorded,
                                    "not-a-rule"
                                )
                                .is_err()
                            );
                            // Enforce mode may raise to the legacy verdict; the record is then stricter and must pass.
                            let (raised, raised_rule) =
                                evaluate(Some(&p), agent, &typed, Action::Deny, Mode::Enforce);
                            assert_eq!(raised, Action::Deny);
                            replay(
                                &policy_bytes,
                                &contract_bytes,
                                Some(agent),
                                &ev,
                                &Decision::Deny,
                                &raised_rule,
                            )
                            .unwrap_or_else(|e| panic!("enforce raise {e}: {raw} {args}"));
                            // A weaker recorded decision must never pass the replay.
                            if action != Action::Allow && out == Outcome::Match {
                                assert!(
                                    replay(
                                        &policy_bytes,
                                        &contract_bytes,
                                        Some(agent),
                                        &ev,
                                        &Decision::Allow,
                                        &rule
                                    )
                                    .is_err()
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        decided > 500 && opaque > 0,
        "decided {decided}, opaque {opaque}"
    );
}

#[test]
fn principal_requirement_policy_parses() {
    let raw = json!({"policy_id":Uuid::nil(),"version":1,"require_principal":true,
        "rules":[{"id":"treasury","when":[{"field":"principal.roles",
        "op":"in_list","value":["treasury"]}],"decision":"allow"}]});
    assert!(
        parse_policy(&raw.to_string(), &contract()).is_ok(),
        "principal policy rejected"
    );
}

#[test]
fn principal_role_policy_replay_parity() {
    use tracelane_audit_verifier::action::{
        Decision, Principal,
        replay::{Outcome, replay_with_principal},
    };
    let principal = Principal {
        iss: "https://issuer.example".into(),
        sub_digest: "ab".repeat(32),
        roles: vec!["treasury".into()],
    };
    let c=parse_contract(&json!({"tool_ref":Uuid::nil(),"server_id":Uuid::nil(),"tool_name":"pay","version":1,"protected":true,"fields":{}}).to_string()).unwrap();
    for (op, list, expected) in [
        ("in_list", json!(["treasury"]), Action::Allow),
        ("in_list", json!([]), Action::Deny),
        ("not_in_list", json!(["other"]), Action::Allow),
        ("not_in_list", json!(["treasury"]), Action::Deny),
        ("not_in_list", json!([]), Action::Allow),
    ] {
        let raw=json!({"policy_id":Uuid::nil(),"version":1,"require_principal":true,"rules":[{"id":"role","when":[{"field":"principal.roles","op":op,"value":list}],"decision":"allow"}]}).to_string();
        let p = parse_policy(&raw, &c).unwrap();
        let (decision, id) = evaluate_with_principal(
            Some(&p),
            Uuid::nil(),
            &BTreeMap::from([("principal.roles".into(), json!("spoof"))]),
            Action::Allow,
            Mode::Observe,
            Some(&principal),
        );
        assert_eq!(decision, expected);
        let decision = if decision == Action::Allow {
            Decision::Allow
        } else {
            Decision::Deny
        };
        assert_eq!(
            replay_with_principal(
                raw.as_bytes(),
                canonical(&c).unwrap().as_bytes(),
                Some(Uuid::nil()),
                &BTreeMap::new(),
                Some(&principal),
                &decision,
                &id
            )
            .unwrap(),
            Outcome::Match
        );
        let missing = evaluate_with_principal(
            Some(&p),
            Uuid::nil(),
            &BTreeMap::new(),
            Action::Allow,
            Mode::Observe,
            None,
        );
        assert_eq!(missing, (Action::Deny, "principal_required".into()));
        assert_eq!(
            replay_with_principal(
                raw.as_bytes(),
                canonical(&c).unwrap().as_bytes(),
                Some(Uuid::nil()),
                &BTreeMap::new(),
                None,
                &Decision::Deny,
                "principal_required"
            )
            .unwrap(),
            Outcome::Match
        );
    }
}
#[test]
fn principal_policy_rejects_unsafe_conditions() {
    for (required, op, value) in [
        (false, "in_list", json!(["treasury"])),
        (true, "eq", json!("treasury")),
        (true, "in_list", json!([7])),
        (true, "not_in_list", json!("treasury")),
    ] {
        let raw=json!({"policy_id":Uuid::nil(),"version":1,"require_principal":required,"rules":[{"id":"role","when":[{"field":"principal.roles","op":op,"value":value}],"decision":"allow"}]}).to_string();
        assert!(parse_policy(&raw, &contract()).is_err());
    }
}
#[test]
fn historical_principal_field_loads() {
    let raw=json!({"tool_ref":Uuid::nil(),"server_id":Uuid::nil(),"tool_name":"pay","version":1,"protected":true,"fields":{"principal.roles":{"path":"/label","kind":"string","required":false,"evidence":"digest_only"}}}).to_string();
    let c = parse_contract(&raw).unwrap();
    let p=parse_policy(&json!({"policy_id":Uuid::nil(),"version":1,"rules":[{"id":"old","when":[{"field":"principal.roles","op":"present"}],"decision":"allow"}]}).to_string(),&c).unwrap();
    assert_eq!(
        evaluate(
            Some(&p),
            Uuid::nil(),
            &BTreeMap::from([("principal.roles".into(), json!("old-label"))]),
            Action::Allow,
            Mode::Observe
        )
        .0,
        Action::Allow
    );
}
#[test]
fn principal_digest_binds_intent() {
    let tenant = TenantId::from_jwt_claim(Uuid::nil());
    let c = contract();
    let args = r#"{"amount":5}"#;
    let old = intent_digest(&tenant, Uuid::nil(), &c, 1, args).unwrap();
    assert_eq!(
        old,
        intent_digest_bound(&tenant, Uuid::nil(), &c, Some(1), args, None).unwrap()
    );
    let first = intent_digest_bound(
        &tenant,
        Uuid::nil(),
        &c,
        Some(1),
        args,
        Some(&"ab".repeat(32)),
    )
    .unwrap();
    assert_ne!(old, first);
    assert_ne!(
        first,
        intent_digest_bound(
            &tenant,
            Uuid::nil(),
            &c,
            Some(1),
            args,
            Some(&"cd".repeat(32))
        )
        .unwrap()
    );
}
