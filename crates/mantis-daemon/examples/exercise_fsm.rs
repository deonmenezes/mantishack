//! Live-daemon FSM exercise. Connects to the running daemon at
//! 127.0.0.1:50451 and walks RECON -> AUTH -> HUNT for the most
//! recent engagement (typically the one created by `mantis pentest`).

use mantis_proto::v1::engagement_client::EngagementClient;
use mantis_proto::v1::{ListRequest, SessionStateRequest, TransitionPhaseRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = EngagementClient::connect("http://127.0.0.1:50451").await?;

    // Find the most recent engagement.
    let resp = client.list(ListRequest {}).await?.into_inner();
    let mut sorted = resp.engagements;
    sorted.sort_by_key(|e| e.created_at_unix);
    let target = sorted.last().ok_or("no engagements")?.clone();
    println!("== exercising engagement: {} ({})", target.id, target.name);

    // Read FSM state.
    let state = client
        .get_session_state(SessionStateRequest {
            engagement_id: target.id.clone(),
        })
        .await?
        .into_inner();
    let json: serde_json::Value = serde_json::from_slice(&state.session_json)?;
    println!("== current phase:    {}", json["phase"]);
    println!("== auth_status:      {}", json["auth_status"]);
    println!(
        "== explored surfaces: {}",
        json["explored"].as_array().map(|a| a.len()).unwrap_or(0)
    );
    if let Some(arr) = json["explored"].as_array() {
        for s in arr {
            println!("    - {}", s);
        }
    }

    // RECON -> AUTH (requires a discovered surface; pentest already ran scan).
    println!("\n== RECON -> AUTH");
    match client
        .transition_phase(TransitionPhaseRequest {
            engagement_id: target.id.clone(),
            to_phase: "AUTH".into(),
            override_reason: None,
            auth_status: None,
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            println!(
                "    ok: {} -> {} (transitioned={}, override_applied={})",
                r.from_phase, r.to_phase, r.transitioned, r.override_applied
            );
        }
        Err(e) => println!("    REFUSED: {}", e.message()),
    }

    // AUTH -> HUNT (must declare auth_status).
    println!("\n== AUTH -> HUNT with auth_status=unauthenticated");
    match client
        .transition_phase(TransitionPhaseRequest {
            engagement_id: target.id.clone(),
            to_phase: "HUNT".into(),
            override_reason: None,
            auth_status: Some("unauthenticated".into()),
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            println!(
                "    ok: {} -> {} (transitioned={})",
                r.from_phase, r.to_phase, r.transitioned
            );
        }
        Err(e) => println!("    REFUSED: {}", e.message()),
    }

    // Try HUNT -> CHAIN without an open_requeue (should pass — no
    // coverage rows or high_priority_surfaces set).
    println!("\n== HUNT -> CHAIN");
    match client
        .transition_phase(TransitionPhaseRequest {
            engagement_id: target.id.clone(),
            to_phase: "CHAIN".into(),
            override_reason: None,
            auth_status: None,
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            println!(
                "    ok: {} -> {} (transitioned={})",
                r.from_phase, r.to_phase, r.transitioned
            );
        }
        Err(e) => println!("    REFUSED: {}", e.message()),
    }

    // Confirm final state.
    let state = client
        .get_session_state(SessionStateRequest {
            engagement_id: target.id,
        })
        .await?
        .into_inner();
    let json: serde_json::Value = serde_json::from_slice(&state.session_json)?;
    println!("\n== final phase:       {}", json["phase"]);
    println!("== final auth_status: {}", json["auth_status"]);

    Ok(())
}
