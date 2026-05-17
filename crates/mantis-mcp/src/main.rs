use anyhow::Result;
use clap::Parser;
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::EnvFilter;

use mantis_mcp::server::MantisMcpServer;

const DEFAULT_DAEMON_ENDPOINT: &str = "http://127.0.0.1:50451";

#[derive(Parser, Debug)]
#[command(
    about = "Mantis MCP stdio server — LLM-driven engagement orchestration",
    long_about = "Speaks the Model Context Protocol over stdio. Wraps the local \
                  mantis-daemon's gRPC API so an LLM host (Claude Code, Codex) \
                  can drive an engagement by calling tools instead of running \
                  `mantis pentest` and polling the daemon."
)]
struct Args {
    /// gRPC endpoint of the running mantis-daemon.
    #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
    daemon: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // MCP servers reserve stdout for protocol traffic; logs go to stderr only.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let args = Args::parse();
    tracing::info!(daemon = %args.daemon, "starting mantis-mcp stdio server");

    let server = MantisMcpServer::new(args.daemon);
    let service = server.serve(stdio()).await.inspect_err(|e| {
        tracing::error!(error = %e, "stdio handshake failed");
    })?;
    service.waiting().await?;
    Ok(())
}
