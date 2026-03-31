//! Human-in-the-Loop approval store.
//!
//! When a tool is marked `approval_required` in the agent policy, the
//! `HitlMiddleware` inserts a pending entry here, waits on a oneshot channel,
//! and only allows the request once an operator approves via `POST /approvals/:id/approve`.

use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;

/// The operator's decision.
#[derive(Debug, Clone)]
pub enum ApprovalDecision {
    Approved,
    Rejected { reason: Option<String> },
}

/// Snapshot of a pending approval — returned by `GET /approvals`.
#[derive(Debug, Clone, Serialize)]
pub struct PendingApproval {
    pub id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    /// Unix timestamp (seconds) of when the approval was created.
    pub created_at: u64,
}

struct Entry {
    approval: PendingApproval,
    tx: oneshot::Sender<ApprovalDecision>,
}

/// Thread-safe store of in-flight approval requests.
#[derive(Default)]
pub struct HitlStore {
    pending: Mutex<HashMap<String, Entry>>,
}

impl HitlStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a new pending approval.
    ///
    /// Returns the approval `id` and the receiver end of the decision channel.
    /// The middleware awaits the receiver; the HTTP handler sends on the transmitter.
    pub async fn insert(
        &self,
        agent_id: String,
        tool_name: String,
        arguments: serde_json::Value,
    ) -> (String, oneshot::Receiver<ApprovalDecision>) {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.pending.lock().await.insert(
            id.clone(),
            Entry {
                approval: PendingApproval {
                    id: id.clone(),
                    agent_id,
                    tool_name,
                    arguments,
                    created_at,
                },
                tx,
            },
        );
        (id, rx)
    }

    /// List all pending approvals (for the operator UI).
    pub async fn list(&self) -> Vec<PendingApproval> {
        self.pending
            .lock()
            .await
            .values()
            .map(|e| e.approval.clone())
            .collect()
    }

    /// Resolve an approval by id. Returns `false` if the id is unknown.
    ///
    /// If the middleware already timed out and dropped the receiver, the send
    /// will fail silently — that is fine.
    pub async fn resolve(&self, id: &str, decision: ApprovalDecision) -> bool {
        if let Some(entry) = self.pending.lock().await.remove(id) {
            let _ = entry.tx.send(decision);
            true
        } else {
            false
        }
    }
}
