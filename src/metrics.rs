use prometheus::{CounterVec, Encoder, Opts, Registry, TextEncoder};

pub struct GatewayMetrics {
    registry: Registry,
    requests: CounterVec,
}

impl GatewayMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let requests = CounterVec::new(
            Opts::new(
                "mcp_shield_requests_total",
                "Total requests processed by mcp-shield",
            ),
            &["agent", "outcome"],
        )?;
        registry.register(Box::new(requests.clone()))?;

        Ok(Self { registry, requests })
    }

    pub fn record(&self, agent: &str, outcome: &str) {
        self.requests.with_label_values(&[agent, outcome]).inc();
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = Vec::new();
        let _ = encoder.encode(&families, &mut buf);
        String::from_utf8(buf).unwrap_or_default()
    }
}
