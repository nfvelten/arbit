mod common;

use common::*;
use serde_json::{Value, json};

// ── Session ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_returns_server_info_and_session() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, body) = h.init("cursor").await;
    assert!(body["result"]["serverInfo"].is_object(), "serverInfo missing");
    assert!(!sid.is_empty(), "session ID not assigned");
}

#[tokio::test]
async fn notifications_initialized_returns_202() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;
    let status = h.status(Some(&sid), notif_body()).await;
    assert_eq!(status, 202);
}

#[tokio::test]
async fn unknown_session_returns_404() {
    let h = harness(DEFAULT_CONFIG).await;
    let status = h.status(Some("invalid-session-id"), list_body()).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn delete_session_invalidates_it() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;

    // DELETE the session
    let del = h
        .client
        .delete(h.url("/mcp"))
        .header("mcp-session-id", &sid)
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204);

    // Further requests to the same session → 404
    let status = h.status(Some(&sid), list_body()).await;
    assert_eq!(status, 404);

    // Duplicate DELETE → 404
    let dup = h
        .client
        .delete(h.url("/mcp"))
        .header("mcp-session-id", &sid)
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status().as_u16(), 404);
}

#[tokio::test]
async fn delete_without_session_header_returns_400() {
    let h = harness(DEFAULT_CONFIG).await;
    let status = h
        .client
        .delete(h.url("/mcp"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 400);
}

// ── Tool filtering ────────────────────────────────────────────────────────────

#[tokio::test]
async fn tools_list_filters_by_allowlist() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;
    let body = h.json(Some(&sid), list_body()).await;
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"echo"), "echo should be visible to cursor");
    assert!(
        !names.contains(&"delete_database"),
        "delete_database should be hidden from cursor"
    );
    assert!(
        !names.contains(&"secret_dump"),
        "secret_dump should be hidden from cursor"
    );
}

#[tokio::test]
async fn tools_list_hides_denied_tools() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("claude-code").await;
    let body = h.json(Some(&sid), list_body()).await;
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        !names.contains(&"delete_database"),
        "delete_database should be hidden from claude-code"
    );
    assert!(names.contains(&"echo"), "echo should be visible to claude-code");
}

// ── Policy enforcement ────────────────────────────────────────────────────────

#[tokio::test]
async fn allowed_tool_call_succeeds() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;
    let body = h
        .json(Some(&sid), call_body("echo", json!({"text": "hello"})))
        .await;
    let text = body["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "echo: hello");
}

#[tokio::test]
async fn tool_not_in_allowlist_is_blocked() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;
    let body = h
        .json(Some(&sid), call_body("delete_database", json!({})))
        .await;
    let msg = body.to_string().to_lowercase();
    assert!(msg.contains("blocked"), "expected blocked, got: {body}");
}

#[tokio::test]
async fn denied_tool_call_is_blocked() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("claude-code").await;
    let body = h
        .json(Some(&sid), call_body("delete_database", json!({})))
        .await;
    let msg = body.to_string().to_lowercase();
    assert!(msg.contains("blocked"), "expected blocked, got: {body}");
}

#[tokio::test]
async fn unknown_agent_is_blocked() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("malicious-agent").await;
    let body = h
        .json(Some(&sid), call_body("echo", json!({"text": "hi"})))
        .await;
    let msg = body.to_string().to_lowercase();
    assert!(msg.contains("unknown"), "expected unknown agent error, got: {body}");
}

// ── Payload filtering ─────────────────────────────────────────────────────────

#[tokio::test]
async fn request_matching_block_pattern_is_blocked() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;
    // "password=" matches the block_pattern in DEFAULT_CONFIG
    let body = h
        .json(
            Some(&sid),
            call_body("echo", json!({"text": "password=hunter2"})),
        )
        .await;
    let msg = body.to_string().to_lowercase();
    assert!(msg.contains("blocked"), "expected blocked, got: {body}");
}

// ── Response filtering ────────────────────────────────────────────────────────

#[tokio::test]
async fn response_containing_blocked_pattern_is_redacted() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("secret-dumper").await;
    let body = h
        .json(Some(&sid), call_body("secret_dump", json!({})))
        .await;
    let text = body.to_string();
    assert!(
        text.contains("REDACTED"),
        "private_key should be redacted, got: {body}"
    );
    assert!(
        !text.contains("AAABBBCCC123"),
        "raw private_key value must not reach client"
    );
}

// ── Authentication ────────────────────────────────────────────────────────────

#[tokio::test]
async fn api_key_required_returns_401_without_key() {
    let h = harness(DEFAULT_CONFIG).await;
    let status = h
        .client
        .post(h.url("/mcp"))
        .json(&init_body("secured-agent"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 401);
}

#[tokio::test]
async fn api_key_wrong_key_returns_401() {
    let h = harness(DEFAULT_CONFIG).await;
    let status = h
        .client
        .post(h.url("/mcp"))
        .header("x-api-key", "wrong-key")
        .json(&init_body("secured-agent"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 401);
}

#[tokio::test]
async fn api_key_correct_key_creates_session() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, body) = h.init_with("secured-agent", &[("x-api-key", "test-key-123")]).await;
    assert!(body["result"]["serverInfo"].is_object());
    assert!(!sid.is_empty());

    // Session works and agent policy is applied (echo is allowed)
    let call = h
        .json(Some(&sid), call_body("echo", json!({"text": "ok"})))
        .await;
    assert_eq!(
        call["result"]["content"][0]["text"].as_str().unwrap(),
        "echo: ok"
    );
}

#[tokio::test]
async fn api_key_overrides_claimed_agent_name() {
    let h = harness(DEFAULT_CONFIG).await;
    // Key belongs to secured-agent; clientInfo.name is "i-am-lying"
    let (sid, body) = h
        .init_with("i-am-lying", &[("x-api-key", "test-key-123")])
        .await;
    assert!(body["result"]["serverInfo"].is_object());
    // Identity is resolved to secured-agent → echo allowed
    let call = h
        .json(Some(&sid), call_body("echo", json!({"text": "trust"})))
        .await;
    assert_eq!(
        call["result"]["content"][0]["text"].as_str().unwrap(),
        "echo: trust"
    );
}

#[tokio::test]
async fn jwt_valid_token_creates_session() {
    let h = harness(DEFAULT_CONFIG).await;
    // HS256 token: {"sub":"jwt-agent","exp":9999999999}, secret "test-jwt-secret"
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiJqd3QtYWdlbnQiLCJleHAiOjk5OTk5OTk5OTl9.\
                 2BhA_cFyVkszZaPrzdXbUlLRs5tNMXhzyFLA03g5tsE";

    let resp = h
        .client
        .post(h.url("/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .json(&init_body("ignored"))
        .send()
        .await
        .unwrap();

    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(!sid.is_empty());

    let body: Value = h
        .json(Some(&sid), call_body("echo", json!({"text": "jwt-works"})))
        .await;
    assert_eq!(
        body["result"]["content"][0]["text"].as_str().unwrap(),
        "echo: jwt-works"
    );
}

#[tokio::test]
async fn jwt_invalid_token_returns_401() {
    let h = harness(DEFAULT_CONFIG).await;
    let status = h
        .client
        .post(h.url("/mcp"))
        .header("authorization", "Bearer invalid.token.here")
        .json(&init_body("x"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 401);
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn global_rate_limit_blocks_after_threshold() {
    let h = harness(DEFAULT_CONFIG).await; // rate-test: 3/min
    let (sid, _) = h.init("rate-test").await;
    let call = call_body("echo", json!({"text": "x"}));

    for _ in 0..3 {
        h.json(Some(&sid), call.clone()).await;
    }
    let body = h.json(Some(&sid), call).await;
    let msg = body.to_string().to_lowercase();
    assert!(msg.contains("rate limit"), "expected rate limit error, got: {body}");
}

#[tokio::test]
async fn per_tool_rate_limit_blocks_after_threshold() {
    let h = harness(DEFAULT_CONFIG).await; // tool-rate-test: echo 2/min
    let (sid, _) = h.init("tool-rate-test").await;
    let call = call_body("echo", json!({"text": "x"}));

    for _ in 0..2 {
        h.json(Some(&sid), call.clone()).await;
    }
    let body = h.json(Some(&sid), call).await;
    let msg = body.to_string().to_lowercase();
    assert!(msg.contains("rate limit"), "expected rate limit error, got: {body}");
}

#[tokio::test]
async fn ip_rate_limit_blocks_after_threshold() {
    let config = r#"agents:
  cursor:
    allowed_tools: [echo]
    rate_limit: 100
rules:
  ip_rate_limit: 3
"#;
    let h = harness(config).await;
    let (sid, _) = h.init("cursor").await;
    let call = call_body("echo", json!({"text": "x"}));

    for _ in 0..3 {
        h.json(Some(&sid), call.clone()).await;
    }
    let body = h.json(Some(&sid), call).await;
    let msg = body.to_string().to_lowercase();
    assert!(msg.contains("rate limit"), "expected IP rate limit, got: {body}");
}

#[tokio::test]
async fn rate_limit_headers_present_on_allowed_call() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;
    let resp = h.post(Some(&sid), call_body("echo", json!({"text": "x"}))).await;
    let headers = resp.headers();
    assert!(
        headers.contains_key("x-ratelimit-limit"),
        "X-RateLimit-Limit missing"
    );
    assert!(
        headers.contains_key("x-ratelimit-remaining"),
        "X-RateLimit-Remaining missing"
    );
    assert!(
        headers.contains_key("x-ratelimit-reset"),
        "X-RateLimit-Reset missing"
    );
}

#[tokio::test]
async fn retry_after_header_present_on_blocked_call() {
    let config = r#"agents:
  cursor:
    allowed_tools: [echo]
    rate_limit: 1
"#;
    let h = harness(config).await;
    let (sid, _) = h.init("cursor").await;
    let call = call_body("echo", json!({"text": "x"}));

    h.json(Some(&sid), call.clone()).await; // consume the 1 allowed call
    let resp = h.post(Some(&sid), call).await; // this one is blocked
    assert!(
        resp.headers().contains_key("retry-after"),
        "Retry-After missing on blocked call"
    );
    let remaining = resp
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("?");
    assert_eq!(remaining, "0");
}

// ── Observability ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_endpoint_tracks_outcomes() {
    let h = harness(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;

    // Generate an allowed call
    h.json(Some(&sid), call_body("echo", json!({"text": "x"}))).await;
    // Generate a blocked call
    h.json(Some(&sid), call_body("delete_database", json!({}))).await;

    let metrics = h
        .client
        .get(h.url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        metrics.contains("mcp_shield_requests_total"),
        "metric name missing"
    );
    assert!(
        metrics.contains(r#"outcome="allowed""#),
        "allowed outcome missing"
    );
    assert!(
        metrics.contains(r#"outcome="blocked""#),
        "blocked outcome missing"
    );
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let h = harness(DEFAULT_CONFIG).await;
    let resp = h
        .client
        .get(h.url("/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "ok");
    assert!(body["version"].is_string());
}

// ── SSE transport ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn sse_endpoint_returns_event_stream() {
    let h = harness(DEFAULT_CONFIG).await;
    let resp = h
        .client
        .get(h.url("/mcp"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/event-stream"), "expected SSE content-type, got: {ct}");
}

// ── Edge cases ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_name_over_128_chars_returns_400() {
    let h = harness(DEFAULT_CONFIG).await;
    let long_name = "a".repeat(130);
    let status = h
        .client
        .post(h.url("/mcp"))
        .json(&init_body(&long_name))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 400);
}

#[tokio::test]
async fn malformed_json_returns_4xx() {
    let h = harness(DEFAULT_CONFIG).await;
    let status = h
        .client
        .post(h.url("/mcp"))
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert!(
        status == 400 || status == 422,
        "expected 400 or 422, got {status}"
    );
}

// ── Config hot-reload ─────────────────────────────────────────────────────────

#[cfg(unix)]
#[tokio::test]
async fn config_hot_reload_via_sigusr1() {
    use std::time::Duration;

    let config_with_block = r#"agents:
  cursor:
    allowed_tools: [echo]
    rate_limit: 100
rules:
  block_patterns:
    - "reload-blocker"
"#;
    let h = harness(config_with_block).await;
    let (sid, _) = h.init("cursor").await;

    // Verify the block pattern is active
    let body = h
        .json(
            Some(&sid),
            call_body("echo", json!({"text": "reload-blocker"})),
        )
        .await;
    assert!(
        body.to_string().to_lowercase().contains("blocked"),
        "block pattern should be active before reload"
    );

    // Overwrite the config without the block pattern
    let config_without_block = format!(
        r#"transport:
  type: http
  addr: "0.0.0.0:{}"
  upstream: "http://127.0.0.1:{}/mcp"
  session_ttl_secs: 3600
audit:
  type: stdout
agents:
  cursor:
    allowed_tools: [echo]
    rate_limit: 100
rules:
  block_patterns: []
"#,
        h.port,
        // We need to know the dummy port — embed it in the config path as a workaround
        // by re-reading the original config
        {
            let cfg = std::fs::read_to_string(&h.config_path).unwrap();
            cfg.lines()
                .find(|l| l.contains("upstream:"))
                .and_then(|l| l.split(':').nth(2))
                .and_then(|s| s.trim().trim_end_matches("/mcp").parse::<u16>().ok())
                .unwrap_or(3000)
        }
    );
    std::fs::write(&h.config_path, &config_without_block).unwrap();

    // Send SIGUSR1 for immediate reload
    std::process::Command::new("kill")
        .args(["-USR1", &h.pid().to_string()])
        .status()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Re-initialize to get a fresh session (reload doesn't invalidate sessions,
    // but we need new one to pick up the new policy)
    let (sid2, _) = h.init("cursor").await;
    let body = h
        .json(
            Some(&sid2),
            call_body("echo", json!({"text": "reload-blocker"})),
        )
        .await;
    assert!(
        body["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("reload-blocker"),
        "block pattern should be gone after reload, got: {body}"
    );
}
