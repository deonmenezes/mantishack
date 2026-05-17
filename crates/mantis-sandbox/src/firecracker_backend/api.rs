//! Firecracker REST API client over a Unix-socket transport
//! (M2.1c orchestration path).
//!
//! Implements the subset of the Firecracker API the daemon needs
//! to boot a microVM:
//!
//! - `PUT /boot-source`       — kernel image + boot args
//! - `PUT /drives/rootfs`     — root filesystem
//! - `PUT /machine-config`    — vCPUs + memory
//! - `PUT /actions`           — `InstanceStart`
//!
//! Each call writes a minimal HTTP/1.1 request to the Unix socket
//! and parses the status line + body. We don't use `reqwest` here
//! because reqwest doesn't support Unix-socket transports
//! out-of-the-box.

use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::SandboxError;

#[derive(Debug, Clone)]
pub struct FirecrackerApi {
    socket_path: PathBuf,
}

impl FirecrackerApi {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn configure(&self, cfg: &VmConfig) -> Result<(), SandboxError> {
        let boot = BootSource {
            kernel_image_path: &cfg.kernel_image_path,
            boot_args: &cfg.boot_args,
        };
        self.put("/boot-source", &boot).await?;

        let drive = Drive {
            drive_id: "rootfs",
            path_on_host: &cfg.rootfs_path,
            is_root_device: true,
            is_read_only: false,
        };
        self.put("/drives/rootfs", &drive).await?;

        let machine = MachineConfig {
            vcpu_count: cfg.vcpu_count,
            mem_size_mib: cfg.mem_size_mib.max(64),
        };
        self.put("/machine-config", &machine).await?;
        Ok(())
    }

    pub async fn start_instance(&self) -> Result<(), SandboxError> {
        let action = Action {
            action_type: "InstanceStart",
        };
        self.put("/actions", &action).await
    }

    pub async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<(), SandboxError> {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| SandboxError::Backend(format!("api serialize: {e}")))?;
        let request = format!(
            "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\n\r\n",
            body_bytes.len()
        );
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| SandboxError::Backend(format!("connect {:?}: {e}", self.socket_path)))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| SandboxError::Backend(format!("api write head: {e}")))?;
        stream
            .write_all(&body_bytes)
            .await
            .map_err(|e| SandboxError::Backend(format!("api write body: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| SandboxError::Backend(format!("api flush: {e}")))?;

        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| SandboxError::Backend(format!("api read: {e}")))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16_384 {
                // Got headers; try a bounded final read to capture
                // body before close.
                continue;
            }
            if buf.len() > 16_384 {
                break;
            }
        }

        let text = String::from_utf8_lossy(&buf);
        let status_line = text.lines().next().unwrap_or("");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(SandboxError::Backend(format!(
                "firecracker API PUT {path} -> {status}: {text}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VmConfig {
    pub kernel_image_path: String,
    pub rootfs_path: String,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub boot_args: String,
}

#[derive(Serialize)]
struct BootSource<'a> {
    kernel_image_path: &'a str,
    boot_args: &'a str,
}

#[derive(Serialize)]
struct Drive<'a> {
    drive_id: &'a str,
    path_on_host: &'a str,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Serialize)]
struct MachineConfig {
    vcpu_count: u32,
    mem_size_mib: u32,
}

#[derive(Serialize)]
struct Action<'a> {
    action_type: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    /// Spawn a Unix-socket "firecracker" that records each request
    /// and replies with the supplied status code.
    async fn spawn_mock_firecracker(
        captured: Arc<Mutex<Vec<(String, String)>>>,
        status: u16,
    ) -> PathBuf {
        // Unique-per-test temp dir: pid + nanos + counter avoids
        // collisions even when multiple tests run in the same
        // tokio runtime tick.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "mantis-fc-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            n
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let sock = dir.join("api.sock");
        let _ = tokio::fs::remove_file(&sock).await;
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let captured = captured.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match s.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let request_line = raw.lines().next().unwrap_or("").to_string();
                    let body = raw
                        .split_once("\r\n\r\n")
                        .map(|(_, b)| b.to_string())
                        .unwrap_or_default();
                    captured.lock().await.push((request_line, body));
                    let resp_body = "{}";
                    let reason = if (200..300).contains(&status) {
                        "OK"
                    } else {
                        "ERR"
                    };
                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                        resp_body.len()
                    );
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(resp_body.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        sock
    }

    #[tokio::test]
    async fn configure_sends_three_put_requests() {
        let captured: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let sock = spawn_mock_firecracker(captured.clone(), 204).await;
        let api = FirecrackerApi::new(sock);
        let cfg = VmConfig {
            kernel_image_path: "/var/lib/mantis/vmlinux".into(),
            rootfs_path: "/var/lib/mantis/rootfs.ext4".into(),
            vcpu_count: 2,
            mem_size_mib: 512,
            boot_args: "console=ttyS0".into(),
        };
        api.configure(&cfg).await.unwrap();

        let calls = captured.lock().await;
        assert_eq!(calls.len(), 3);
        assert!(calls[0].0.contains("PUT /boot-source"));
        assert!(calls[0].1.contains("vmlinux"));
        assert!(calls[1].0.contains("PUT /drives/rootfs"));
        assert!(calls[1].1.contains("rootfs.ext4"));
        assert!(calls[2].0.contains("PUT /machine-config"));
        assert!(calls[2].1.contains("\"vcpu_count\":2"));
        assert!(calls[2].1.contains("\"mem_size_mib\":512"));
    }

    #[tokio::test]
    async fn start_instance_sends_actions_put_with_instancestart() {
        let captured: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let sock = spawn_mock_firecracker(captured.clone(), 204).await;
        let api = FirecrackerApi::new(sock);
        api.start_instance().await.unwrap();
        let calls = captured.lock().await;
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("PUT /actions"));
        assert!(calls[0].1.contains("InstanceStart"));
    }

    #[tokio::test]
    async fn non_2xx_surfaces_as_backend_error() {
        let captured: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let sock = spawn_mock_firecracker(captured, 400).await;
        let api = FirecrackerApi::new(sock);
        let err = api.start_instance().await.unwrap_err();
        assert!(format!("{err}").contains("400"));
    }

    #[tokio::test]
    async fn connect_failure_surfaces_as_backend_error() {
        let api = FirecrackerApi::new("/nonexistent-socket-path");
        let err = api.start_instance().await.unwrap_err();
        assert!(format!("{err}").contains("connect"));
    }

    #[tokio::test]
    async fn enforces_minimum_64mib_memory() {
        let captured: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let sock = spawn_mock_firecracker(captured.clone(), 204).await;
        let api = FirecrackerApi::new(sock);
        let cfg = VmConfig {
            kernel_image_path: "/k".into(),
            rootfs_path: "/r".into(),
            vcpu_count: 1,
            mem_size_mib: 1, // intentionally below 64
            boot_args: "".into(),
        };
        api.configure(&cfg).await.unwrap();
        let calls = captured.lock().await;
        let machine_call = &calls[2];
        assert!(machine_call.1.contains("\"mem_size_mib\":64"));
    }
}
