use super::{Decision, McpContext, Middleware};
use crate::{
    config::tool_matches,
    hitl::{ApprovalDecision, HitlStore},
    live_config::LiveConfig,
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

pub struct HitlMiddleware {
    store: Arc<HitlStore>,
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl HitlMiddleware {
    pub fn new(store: Arc<HitlStore>, config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { store, config }
    }
}

#[async_trait]
impl Middleware for HitlMiddleware {
    fn name(&self) -> &'static str {
        "hitl"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow { rl: None };
        }

        let tool = match ctx.tool_name.as_deref() {
            Some(t) => t,
            None => return Decision::Allow { rl: None },
        };

        let (needs_approval, timeout_secs) = {
            let cfg = self.config.borrow();
            let policy = cfg
                .agents
                .get(&ctx.agent_id)
                .or(cfg.default_policy.as_ref());
            match policy {
                Some(p) => {
                    let matched = p
                        .approval_required
                        .iter()
                        .any(|pat| tool_matches(pat, tool));
                    (matched, p.hitl_timeout_secs)
                }
                None => (false, 60),
            }
        };

        if !needs_approval {
            return Decision::Allow { rl: None };
        }

        let args = ctx.arguments.clone().unwrap_or(serde_json::Value::Null);
        let (id, rx) = self
            .store
            .insert(ctx.agent_id.clone(), tool.to_string(), args)
            .await;

        tracing::info!(
            approval_id = %id,
            agent = %ctx.agent_id,
            tool = %tool,
            timeout_secs,
            "awaiting human approval"
        );

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(ApprovalDecision::Approved)) => {
                tracing::info!(approval_id = %id, "approved");
                Decision::Allow { rl: None }
            }
            Ok(Ok(ApprovalDecision::Rejected { reason })) => {
                tracing::info!(approval_id = %id, ?reason, "rejected by operator");
                Decision::Block {
                    reason: format!(
                        "tool '{}' rejected by operator{}",
                        tool,
                        reason
                            .as_deref()
                            .map(|r| format!(": {r}"))
                            .unwrap_or_default()
                    ),
                    rl: None,
                }
            }
            // Sender dropped (race with timeout cleanup) or timeout elapsed
            Ok(Err(_)) | Err(_) => {
                // Clean up the entry if the timeout fired before the operator acted
                self.store
                    .resolve(
                        &id,
                        ApprovalDecision::Rejected {
                            reason: Some("timeout".into()),
                        },
                    )
                    .await;
                tracing::warn!(approval_id = %id, "approval timed out, auto-rejecting");
                Decision::Block {
                    reason: format!("tool '{}' approval timed out", tool),
                    rl: None,
                }
            }
        }
    }
}
