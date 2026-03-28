use super::{Decision, McpContext, Middleware};
use crate::live_config::LiveConfig;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

pub struct PayloadFilterMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl PayloadFilterMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for PayloadFilterMiddleware {
    fn name(&self) -> &'static str {
        "payload_filter"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow;
        }

        let args = match &ctx.arguments {
            Some(v) => v,
            None => return Decision::Allow,
        };

        // Snapshot patterns — Arc clone is O(1); no per-Regex allocation
        let patterns = {
            let cfg = self.config.borrow();
            if cfg.block_patterns.is_empty() {
                return Decision::Allow;
            }
            Arc::clone(&cfg.block_patterns)
        };

        let text = args.to_string();
        for pattern in patterns.as_ref() {
            if pattern.is_match(&text) {
                return Decision::Block {
                    reason: format!("sensitive data detected (pattern: {})", pattern.as_str()),
                };
            }
        }

        Decision::Allow
    }
}
