//! Thin wrapper over the generated tonic client.
//!
//! Each MCP tool method connects on demand: gRPC channels are cheap
//! and the daemon endpoint is local, so we don't bother with a
//! long-lived client. Connecting per-call also means a transient
//! daemon restart between tool calls is recovered transparently.

use anyhow::{Context, Result};

use mantis_proto::v1::engagement_client::EngagementClient;

pub type Client = EngagementClient<tonic::transport::Channel>;

pub async fn connect(endpoint: &str) -> Result<Client> {
    EngagementClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("connecting to mantis-daemon at {endpoint}"))
}
