//! Pluggable tool registry for the chat engine.
//!
//! A [`ChatToolRegistry`] exposes the tools the model can call and
//! handles dispatch when the model emits a [`ToolCall`]. The chat
//! engine treats the registry as opaque — concrete implementations
//! (MCP bridge in mantis-mcp, user-defined HTTP tools loaded from
//! TOML) live in their own modules.

use async_trait::async_trait;

use mantis_synthesizer::{Tool, ToolCall};

pub mod user;

/// Trait implemented by anything that can expose tools to the chat
/// model and execute the tool calls the model emits.
#[async_trait]
pub trait ChatToolRegistry: Send + Sync {
    /// The tools available to the model on the next turn. Called
    /// once per turn — registries with dynamic tool sets are free
    /// to return different lists across calls.
    fn tools(&self) -> Vec<Tool>;

    /// Execute a single tool call and return its textual result.
    /// Errors are surfaced to the model as `[tool error: ...]`
    /// blocks; they should not abort the conversation.
    async fn execute(&self, call: &ToolCall) -> Result<String, anyhow::Error>;
}

/// Default registry used when the operator hasn't wired any tools.
/// Exposes no tools and refuses any call.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoTools;

#[async_trait]
impl ChatToolRegistry for NoTools {
    fn tools(&self) -> Vec<Tool> {
        Vec::new()
    }

    async fn execute(&self, call: &ToolCall) -> Result<String, anyhow::Error> {
        Err(anyhow::anyhow!(
            "no tool registry attached to this conversation; cannot execute `{}`",
            call.name
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn no_tools_returns_empty_list_and_refuses_execution() {
        let r = NoTools;
        assert!(r.tools().is_empty());
        let call = ToolCall {
            id: "c1".into(),
            name: "anything".into(),
            arguments: json!({}),
        };
        let err = r.execute(&call).await.unwrap_err();
        assert!(err.to_string().contains("anything"));
    }
}
