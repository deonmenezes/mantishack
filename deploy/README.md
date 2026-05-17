# Mantis deployment

Templates for the five deployment modes from PRD §14.

## §14.1 Local workstation

```sh
cargo install --path crates/mantis-cli
cargo install --path crates/mantis-daemon
mantis-daemon &
mantis engagement create demo
```

## §14.2 Self-hosted VPS (systemd)

See `deploy/systemd/mantis-daemon.service`. Install on Debian/Ubuntu:

```sh
sudo useradd --system --create-home --home-dir /var/lib/mantis mantis
cargo build --release --bin mantis-daemon --bin mantis
sudo install -m 755 target/release/mantis-daemon /usr/local/bin/
sudo install -m 755 target/release/mantis /usr/local/bin/
sudo cp deploy/systemd/mantis-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mantis-daemon
journalctl -u mantis-daemon -f
```

## §14.3 Hibernating serverless (Modal)

See `deploy/modal/mantis_modal.py`. Modal cold-starts the daemon
on webhook/cron triggers and hibernates back to zero when idle —
the workspace volume persists engagement state across hibernations.

```sh
pip install modal
modal token new
modal deploy deploy/modal/mantis_modal.py
# Trigger a rescan:
curl -X POST $MODAL_URL -d '{"engagement_id":"01HXX..."}'
```

Other serverless backends with the same pattern:
- **Daytona** — bring-your-own-VM platform; install the daemon as a
  systemd unit inside the workspace VM and let Daytona hibernate the
  VM between sessions.
- **Vercel Sandbox** — Firecracker-backed microVMs invoked from
  Vercel Functions. The `mantis-sandbox::firecracker_backend` crate
  handles the in-VM contract.

## §14.4 Multi-tenant service

`mantis-tenant` (Rust crate) ships the per-tenant workspace
isolation and per-client billing tracker. Multi-tenant deployments
generally combine §14.5 (K8s) with `mantis-tenant`'s tenant header
on the gRPC API.

## §14.5 Kubernetes operator

See `deploy/k8s/mantis-deployment.yaml`. The Deployment runs the
daemon as a non-root pod with the workspace volume mounted from a
PVC. Engagements are Custom Resources (CRDs):

```sh
mantis-k8s --print-crd | kubectl apply -f -
kubectl apply -f deploy/k8s/mantis-deployment.yaml
kubectl get engagements -n mantis
```

## Building images

```sh
docker build -t mantis:latest -f deploy/docker/Dockerfile .
docker run --rm -p 8080:8080 -v $PWD/workspace:/workspace mantis:latest
```
