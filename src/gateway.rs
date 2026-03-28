use crate::{
    audit::{AuditEntry, AuditLog, Outcome},
    config::AgentPolicy,
    metrics::GatewayMetrics,
    middleware::{Decision, McpContext, Pipeline},
    upstream::McpUpstream,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::SystemTime};

pub struct McpGateway {
    pipeline: Pipeline,
    /// Default upstream — used when the agent has no named upstream configured.
    default_upstream: Arc<dyn McpUpstream>,
    /// Named upstreams — keyed by the names defined in `config.upstreams`.
    named_upstreams: HashMap<String, Arc<dyn McpUpstream>>,
    audit: Arc<dyn AuditLog>,
    metrics: Arc<GatewayMetrics>,
    /// Per-agent policies — used to filter tools/list responses.
    policies: Arc<HashMap<String, AgentPolicy>>,
}

impl McpGateway {
    pub fn new(
        pipeline: Pipeline,
        default_upstream: Arc<dyn McpUpstream>,
        named_upstreams: HashMap<String, Arc<dyn McpUpstream>>,
        audit: Arc<dyn AuditLog>,
        metrics: Arc<GatewayMetrics>,
        policies: Arc<HashMap<String, AgentPolicy>>,
    ) -> Self {
        Self { pipeline, default_upstream, named_upstreams, audit, metrics, policies }
    }

    /// Select the upstream for a given agent. Falls back to the default.
    fn upstream_for(&self, agent_id: &str) -> &Arc<dyn McpUpstream> {
        self.policies
            .get(agent_id)
            .and_then(|p| p.upstream.as_ref())
            .and_then(|name| self.named_upstreams.get(name))
            .unwrap_or(&self.default_upstream)
    }

    /// Check policy without forwarding.
    /// `None` = allowed, `Some(error)` = blocked.
    /// Used by StdioTransport, which manages piping directly.
    pub async fn intercept(&self, agent_id: &str, msg: &Value) -> Option<Value> {
        let method = msg["method"].as_str().unwrap_or("");

        if method != "tools/call" {
            self.audit.record(AuditEntry {
                ts: SystemTime::now(),
                agent_id: agent_id.to_string(),
                method: method.to_string(),
                tool: None,
                outcome: Outcome::Forwarded,
            });
            self.metrics.record(agent_id, "forwarded");
            return None;
        }

        let id = msg["id"].clone();
        let tool_name = msg["params"]["name"].as_str().map(String::from);
        let arguments = Some(msg["params"]["arguments"].clone());

        let ctx = McpContext {
            agent_id: agent_id.to_string(),
            method: method.to_string(),
            tool_name: tool_name.clone(),
            arguments,
        };

        match self.pipeline.run(&ctx).await {
            Decision::Allow => {
                self.audit.record(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    outcome: Outcome::Allowed,
                });
                self.metrics.record(agent_id, "allowed");
                None
            }
            Decision::Block { reason } => {
                self.audit.record(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    outcome: Outcome::Blocked(reason.clone()),
                });
                self.metrics.record(agent_id, "blocked");
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": format!("blocked: {reason}") }
                }))
            }
        }
    }

    /// Policy check + upstream forwarding.
    /// Used by HttpTransport.
    pub async fn handle(&self, agent_id: &str, msg: Value) -> Option<Value> {
        let method = msg["method"].as_str().unwrap_or("").to_string();

        match self.intercept(agent_id, &msg).await {
            Some(err) => Some(err),
            None => {
                let response = self.upstream_for(agent_id).forward(&msg).await;
                // Filter tools/list so the agent only sees what it can call
                if method == "tools/list" {
                    response.map(|r| self.filter_tools_response(agent_id, r))
                } else {
                    response
                }
            }
        }
    }

    /// Filters the tools list in a `tools/list` response according to agent policy.
    /// Called by both HttpTransport and StdioTransport.
    pub fn filter_tools_response(&self, agent_id: &str, mut response: Value) -> Value {
        let Some(policy) = self.policies.get(agent_id) else {
            return response;
        };

        if let Some(tools) = response["result"]["tools"].as_array_mut() {
            tools.retain(|tool| {
                let name = tool["name"].as_str().unwrap_or("");
                if policy.denied_tools.iter().any(|t| t == name) {
                    return false;
                }
                if let Some(allowed) = &policy.allowed_tools {
                    return allowed.iter().any(|t| t == name);
                }
                true
            });
        }

        response
    }
}
