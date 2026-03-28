use super::{AuditEntry, AuditLog};
use async_trait::async_trait;
use std::sync::Arc;

/// Fans out every audit event to multiple backends simultaneously.
/// All backends receive the same entry; flush waits for all of them.
pub struct FanoutAudit {
    backends: Vec<Arc<dyn AuditLog>>,
}

impl FanoutAudit {
    pub fn new(backends: Vec<Arc<dyn AuditLog>>) -> Self {
        Self { backends }
    }
}

#[async_trait]
impl AuditLog for FanoutAudit {
    fn record(&self, entry: AuditEntry) {
        for backend in &self.backends {
            backend.record(entry.clone());
        }
    }

    async fn flush(&self) {
        for backend in &self.backends {
            backend.flush().await;
        }
    }
}
