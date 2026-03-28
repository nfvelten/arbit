use super::{Decision, McpContext, Middleware};
use crate::live_config::LiveConfig;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

pub struct AuthMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl AuthMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    fn name(&self) -> &'static str {
        "auth"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow;
        }

        let tool = ctx.tool_name.as_deref().unwrap_or("");
        let cfg = self.config.borrow();
        let Some(policy) = cfg.agents.get(&ctx.agent_id) else {
            return Decision::Block {
                reason: format!("unknown agent '{}'", ctx.agent_id),
            };
        };

        if policy.denied_tools.iter().any(|t| t == tool) {
            return Decision::Block {
                reason: format!("tool '{tool}' explicitly denied"),
            };
        }

        if let Some(allowed) = &policy.allowed_tools {
            if !allowed.iter().any(|t| t == tool) {
                return Decision::Block {
                    reason: format!("tool '{tool}' not in allowlist"),
                };
            }
        }

        Decision::Allow
    }
}
