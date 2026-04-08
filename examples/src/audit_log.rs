//! Audit Log — tamper-evident user access tracking for compliance.
//!
//! Demonstrates logging user access events to Arbor for regulatory compliance
//! (GDPR, SOC 2, HIPAA). The ZK proof proves the audit trail is complete —
//! no events were deleted or altered by a privileged admin.
//!
//! # Prerequisites
//!
//! 1. Start Trillian: `cd examples && docker compose up -d`
//! 2. Start Arbor:    `cargo run -p arbor-service -- --trillian-endpoint http://localhost:8090 --create-tree`
//!
//! # Run
//!
//! ```sh
//! cargo run --example audit-log
//! ```

use serde::Serialize;

#[derive(Serialize)]
struct AccessEvent {
    event_id: &'static str,
    timestamp: &'static str,
    actor: &'static str,
    action: &'static str,
    resource: &'static str,
    ip_address: &'static str,
    result: &'static str,
    data_classification: &'static str,
}

fn make_leaf(event: &AccessEvent) -> Vec<u8> {
    serde_json::to_vec(event).expect("serialization cannot fail")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Audit Log Example ===\n");

    let mut client = arbor_examples::connect(None).await?;

    // -- Phase 1: Log a batch of access events --------------------------------
    println!("Phase 1: Logging access events\n");

    let events = vec![
        AccessEvent {
            event_id: "EVT-20250407-0001",
            timestamp: "2025-04-07T09:15:32Z",
            actor: "user:jane.doe@acme.com",
            action: "read",
            resource: "customers/CUST-4421/pii",
            ip_address: "10.0.42.7",
            result: "allowed",
            data_classification: "PII",
        },
        AccessEvent {
            event_id: "EVT-20250407-0002",
            timestamp: "2025-04-07T09:16:01Z",
            actor: "user:bob@acme.com",
            action: "export",
            resource: "reports/quarterly-revenue",
            ip_address: "10.0.42.12",
            result: "allowed",
            data_classification: "confidential",
        },
        AccessEvent {
            event_id: "EVT-20250407-0003",
            timestamp: "2025-04-07T09:17:45Z",
            actor: "admin:ops@acme.com",
            action: "delete",
            resource: "customers/CUST-1002",
            ip_address: "10.0.1.1",
            result: "denied",
            data_classification: "PII",
        },
        AccessEvent {
            event_id: "EVT-20250407-0004",
            timestamp: "2025-04-07T09:20:00Z",
            actor: "service:billing-worker",
            action: "read",
            resource: "invoices/INV-2025-0042",
            ip_address: "10.0.50.3",
            result: "allowed",
            data_classification: "financial",
        },
    ];

    let leaves: Vec<Vec<u8>> = events.iter().map(make_leaf).collect();
    arbor_examples::queue_leaves(&mut client, leaves, "4 access events").await?;

    // -- Phase 2: New event with proof for the auditor ------------------------
    println!("Phase 2: Logging event with ZK proof for the auditor\n");

    let sensitive_event = AccessEvent {
        event_id: "EVT-20250407-0005",
        timestamp: "2025-04-07T10:00:00Z",
        actor: "user:jane.doe@acme.com",
        action: "update",
        resource: "customers/CUST-4421/address",
        ip_address: "10.0.42.7",
        result: "allowed",
        data_classification: "PII",
    };

    let job_id = arbor_examples::submit_append(
        &mut client,
        vec![make_leaf(&sensitive_event)],
        "PII update event",
    )
    .await?;
    arbor_examples::wait_for_job(&mut client, &job_id).await?;

    // -- Phase 3: Consistency check -------------------------------------------
    println!("Phase 3: Verifying log consistency\n");

    let response = client
        .get_consistency_proof(arbor_server::proto::GetConsistencyProofRequest {
            first_tree_size: 4,
            second_tree_size: 5,
        })
        .await?
        .into_inner();

    println!(
        "  Consistency proof (size 4 -> 5): {} hashes",
        response.hashes.len()
    );
    println!();

    arbor_examples::print_tree_state(&mut client).await?;

    println!("An auditor can verify the ZK append proof to confirm the audit");
    println!("trail is complete — no events were deleted or altered.\n");

    Ok(())
}
