//! Startup configuration diagnostics must be observable without disclosing values.

#[test]
fn workos_missing_api_key_warns_at_startup() {
    for (signal, api_key, warning) in [
        (None, None, false),
        (Some("WORKOS_CLIENT_ID"), None, true),
        (Some("WORKOS_JWKS_URL"), None, true),
        (Some("WORKOS_ISSUER"), None, true),
        (Some("WORKOS_AUDIENCE"), None, true),
        (Some("WORKOS_WEBHOOK_SECRET"), None, true),
        (Some("WORKOS_CLIENT_ID"), Some(""), true),
        (Some("WORKOS_CLIENT_ID"), Some("   "), true),
        (
            Some("WORKOS_CLIENT_ID"),
            Some("sk_test_not_a_real_secret"),
            false,
        ),
        (None, Some(""), true),
        (None, Some("sk_test_not_a_real_secret"), false),
    ] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_gateway"));
        for (name, _) in std::env::vars().filter(|(k, _)| k.starts_with("WORKOS_")) {
            cmd.env_remove(name);
        }
        // Exit during config parsing, before any pool, network or listener is opened.
        cmd.env("TRACELANE_PORT", "invalid-test-port")
            .env("RUST_LOG", "warn");
        if let Some(name) = signal {
            cmd.env(name, "config_test_value_must_not_be_logged");
        }
        if let Some(key) = api_key {
            cmd.env("WORKOS_API_KEY", key);
        }
        let output = cmd.output().unwrap();
        assert!(!output.status.success());
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            logs.contains("TRACELANE_PORT"),
            "startup must reach config parsing: {logs}"
        );
        assert_eq!(
            logs.contains("WORKOS_API_KEY"),
            warning,
            "wrong startup diagnostic: {logs}"
        );
        if warning {
            assert!(
                logs.contains("WARN"),
                "missing credential must log at warning level: {logs}"
            );
        }
        assert!(!logs.contains("sk_test_not_a_real_secret"));
        assert!(!logs.contains("config_test_value_must_not_be_logged"));
    }
}
