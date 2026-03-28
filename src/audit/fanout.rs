use super::{AuditEntry, AuditLog};
use async_trait::async_trait;
use std::sync::Arc;

/// Fans out every audit event to multiple backends simultaneously.
/// Uses `Arc<AuditEntry>` so all backends share the same allocation.
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
    fn record(&self, entry: Arc<AuditEntry>) {
        for backend in &self.backends {
            backend.record(Arc::clone(&entry));
        }
    }

    async fn flush(&self) {
        for backend in &self.backends {
            backend.flush().await;
        }
    }
}
