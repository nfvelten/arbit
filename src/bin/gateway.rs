use mcp_gateway::{
    audit::{
        fanout::FanoutAudit, sqlite::SqliteAudit, stdout::StdoutAudit, webhook::WebhookAudit,
        AuditLog,
    },
    config::{AuditConfig, Config, TransportConfig},
    gateway::McpGateway,
    live_config::LiveConfig,
    metrics::GatewayMetrics,
    middleware::{
        auth::AuthMiddleware, payload_filter::PayloadFilterMiddleware,
        rate_limit::RateLimitMiddleware, Pipeline,
    },
    transport::{http::HttpTransport, stdio::StdioTransport, Transport},
    upstream::{http::HttpUpstream, McpUpstream},
};
use regex::Regex;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "gateway.yml".into());
    let config = Config::from_file(&config_path)?;

    // ── Audit log — pluggable, fan-out to all configured backends ──────────────
    let mut audit_backends: Vec<Arc<dyn AuditLog>> = Vec::new();

    // New-style `audits:` list
    for backend_cfg in &config.audits {
        audit_backends.push(build_audit_backend(backend_cfg)?);
    }
    // Legacy `audit:` single backend (backward compat)
    if let Some(backend_cfg) = &config.audit {
        audit_backends.push(build_audit_backend(backend_cfg)?);
    }
    // Default: stdout if nothing configured
    if audit_backends.is_empty() {
        audit_backends.push(Arc::new(StdoutAudit));
    }

    let audit: Arc<dyn AuditLog> = if audit_backends.len() == 1 {
        audit_backends.remove(0)
    } else {
        Arc::new(FanoutAudit::new(audit_backends))
    };

    // ── Live config — shared via watch channel for hot-reload ──────────────────
    let block_patterns: Vec<Regex> = config
        .rules
        .block_patterns
        .iter()
        .map(|p| Regex::new(p).unwrap_or_else(|_| panic!("invalid regex: {p}")))
        .collect();

    let live = Arc::new(LiveConfig {
        agents: config.agents,
        block_patterns,
    });
    let (config_tx, config_rx) = watch::channel(live);

    // ── Hot-reload — polls config file mtime every 5s ─────────────────────────
    {
        let reload_path = config_path.clone();
        let tx = config_tx;
        tokio::spawn(async move {
            let mut last_modified = tokio::fs::metadata(&reload_path)
                .await
                .ok()
                .and_then(|m| m.modified().ok());
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                let modified = tokio::fs::metadata(&reload_path)
                    .await
                    .ok()
                    .and_then(|m| m.modified().ok());
                if modified.is_some() && modified != last_modified {
                    last_modified = modified;
                    match Config::from_file(&reload_path) {
                        Ok(new_cfg) => {
                            let new_patterns: Vec<Regex> = new_cfg
                                .rules
                                .block_patterns
                                .iter()
                                .filter_map(|p| {
                                    Regex::new(p)
                                        .map_err(|e| eprintln!("[RELOAD] invalid regex '{p}': {e}"))
                                        .ok()
                                })
                                .collect();
                            let new_live = Arc::new(LiveConfig {
                                agents: new_cfg.agents,
                                block_patterns: new_patterns,
                            });
                            if tx.send(new_live).is_ok() {
                                eprintln!("[GATEWAY] config reloaded from {reload_path}");
                            }
                        }
                        Err(e) => eprintln!("[GATEWAY] config reload failed: {e}"),
                    }
                }
            }
        });
    }

    // ── Pipeline — each middleware subscribes to live config ───────────────────
    let pipeline = Pipeline::new()
        .add(Arc::new(RateLimitMiddleware::new(config_rx.clone())))
        .add(Arc::new(AuthMiddleware::new(config_rx.clone())))
        .add(Arc::new(PayloadFilterMiddleware::new(config_rx.clone())));

    // ── Named upstreams ────────────────────────────────────────────────────────
    let named_upstreams: HashMap<String, Arc<dyn McpUpstream>> = config
        .upstreams
        .iter()
        .map(|(name, url)| {
            let upstream: Arc<dyn McpUpstream> = Arc::new(HttpUpstream::new(url));
            (name.clone(), upstream)
        })
        .collect();

    let metrics = Arc::new(GatewayMetrics::new()?);

    match config.transport {
        TransportConfig::Http { addr, upstream, session_ttl_secs, tls } => {
            eprintln!("[GATEWAY] HTTP mode | upstream={upstream} | addr={addr}");
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                Arc::new(HttpUpstream::new(&upstream)),
                named_upstreams,
                audit.clone(),
                Arc::clone(&metrics),
                config_rx.clone(),
            ));
            HttpTransport::new(addr, session_ttl_secs, tls, metrics, config_rx)
                .serve(gateway)
                .await?;
        }
        TransportConfig::Stdio { server } => {
            eprintln!("[GATEWAY] stdio mode | server={}", server.join(" "));
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                Arc::new(HttpUpstream::new("")), // not used in stdio mode
                named_upstreams,
                audit.clone(),
                Arc::clone(&metrics),
                config_rx,
            ));
            StdioTransport::new(server).serve(gateway).await?;
        }
    }

    // Flush pending audit writes before the process exits
    audit.flush().await;
    Ok(())
}

fn build_audit_backend(cfg: &AuditConfig) -> anyhow::Result<Arc<dyn AuditLog>> {
    match cfg {
        AuditConfig::Stdout => Ok(Arc::new(StdoutAudit)),
        AuditConfig::Sqlite { path } => {
            eprintln!("[GATEWAY] SQLite audit at {path}");
            Ok(Arc::new(SqliteAudit::new(path)?))
        }
        AuditConfig::Webhook { url, token } => {
            eprintln!("[GATEWAY] Webhook audit to {url}");
            Ok(Arc::new(WebhookAudit::new(url, token.clone())))
        }
    }
}
