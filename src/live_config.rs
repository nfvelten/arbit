use crate::config::AgentPolicy;
use regex::Regex;
use std::collections::HashMap;

/// Hot-reloadable configuration snapshot.
/// Wrapped in `Arc` and broadcast via `tokio::sync::watch`.
/// All consumers (`borrow()`) always see the latest reloaded version.
pub struct LiveConfig {
    pub agents: HashMap<String, AgentPolicy>,
    pub block_patterns: Vec<Regex>,
}
