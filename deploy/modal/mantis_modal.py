"""Modal deployment for Mantis (PRD §14.3 hibernating serverless).

Usage:
    pip install modal
    modal token new       # first-time setup
    modal deploy deploy/modal/mantis_modal.py

The Modal function hibernates between engagement bursts. Wake
triggers:
  - HTTP call to the deployed function URL
  - Scheduled cron via `@stub.function(schedule=modal.Cron(...))`
  - Webhook ingress via `@stub.web_endpoint`

The workspace persists in a Modal Volume so engagement state
survives container exits.
"""

import os

import modal

stub = modal.App("mantis-daemon")

workspace_volume = modal.Volume.from_name("mantis-workspace", create_if_missing=True)

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("ca-certificates", "libssl3", "curl")
    # Operators pre-build the daemon binary into the image via a
    # local file copy. The Dockerfile-built binary is the same one.
    .copy_local_file(
        "target/release/mantis-daemon",
        "/usr/local/bin/mantis-daemon",
    )
)


@stub.function(
    image=image,
    volumes={"/workspace": workspace_volume},
    cpu=2.0,
    memory=2048,
    timeout=3600,
    # Hibernate aggressively: scale to zero whenever idle.
    container_idle_timeout=60,
)
@modal.web_endpoint(method="POST", label="mantis-rescan")
def trigger_rescan(payload: dict) -> dict:
    """Webhook ingress that wakes the daemon for an ad-hoc rescan.

    Modal cold-starts the container if it was hibernated, mounts
    the workspace volume, then invokes the daemon's
    `mantis engagement rescan` command for the engagement named in
    the payload.
    """
    import subprocess

    engagement_id = payload.get("engagement_id")
    if not engagement_id:
        return {"ok": False, "error": "missing engagement_id"}
    result = subprocess.run(
        [
            "/usr/local/bin/mantis-daemon",
            "engagement",
            "rescan",
            "--id",
            engagement_id,
        ],
        env={**os.environ, "MANTIS_WORKSPACE": "/workspace"},
        capture_output=True,
        text=True,
        check=False,
    )
    workspace_volume.commit()
    return {
        "ok": result.returncode == 0,
        "engagement_id": engagement_id,
        "stdout": result.stdout[-2000:],
        "stderr": result.stderr[-2000:],
    }


@stub.function(
    image=image,
    volumes={"/workspace": workspace_volume},
    schedule=modal.Cron("0 */6 * * *"),
    cpu=2.0,
    memory=2048,
    timeout=3600,
)
def scheduled_sweep():
    """Six-hourly cron that runs every active engagement's
    monitoring sweep. Pairs with PRD §5.10 continuous monitoring."""
    import subprocess

    subprocess.run(
        ["/usr/local/bin/mantis-daemon", "schedule", "tick"],
        env={**os.environ, "MANTIS_WORKSPACE": "/workspace"},
        check=False,
    )
    workspace_volume.commit()
