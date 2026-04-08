//! Certificate Transparency — publicly auditable TLS certificate issuance.
//!
//! Demonstrates the classic CT use case: logging TLS certificates to an
//! append-only Merkle tree. Arbor adds a ZK layer on top — a single proof
//! attests that the log grew correctly, verifiable without contacting the
//! log server.
//!
//! # Prerequisites
//!
//! 1. Start Trillian: `cd examples && docker compose up -d`
//! 2. Start Arbor:    `cargo run -p arbor-service -- --trillian-endpoint http://localhost:8090 --create-tree`
//!
//! # Run
//!
//! ```sh
//! cargo run --example certificate-transparency
//! ```

use serde::Serialize;

#[derive(Serialize)]
struct CertificateEntry {
    log_entry_type: &'static str,
    timestamp: &'static str,
    issuer: &'static str,
    subject: &'static str,
    serial: &'static str,
    not_before: &'static str,
    not_after: &'static str,
    san: Vec<&'static str>,
    fingerprint_sha256: &'static str,
}

fn make_leaf(cert: &CertificateEntry) -> Vec<u8> {
    serde_json::to_vec(cert).expect("serialization cannot fail")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Certificate Transparency Example ===\n");

    let mut client = arbor_examples::connect(None).await?;

    // -- Phase 1: Log certificate issuances -----------------------------------
    println!("Phase 1: Logging certificate issuances\n");

    let certs = vec![
        CertificateEntry {
            log_entry_type: "x509_entry",
            timestamp: "2025-04-07T08:00:00Z",
            issuer: "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
            subject: "CN=example.com",
            serial: "03:a1:b2:c3:d4:e5:f6:00:11:22:33:44:55:66:77:88",
            not_before: "2025-04-07T00:00:00Z",
            not_after: "2025-07-06T00:00:00Z",
            san: vec!["example.com", "www.example.com"],
            fingerprint_sha256: "b5:4a:c1:d2:e3:f4:05:16:27:38:49:5a:6b:7c:8d:9e",
        },
        CertificateEntry {
            log_entry_type: "x509_entry",
            timestamp: "2025-04-07T08:01:00Z",
            issuer: "CN=DigiCert SHA2 Extended Validation Server CA",
            subject: "CN=shop.example.com,O=Example Inc",
            serial: "0a:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
            not_before: "2025-04-01T00:00:00Z",
            not_after: "2026-04-01T00:00:00Z",
            san: vec!["shop.example.com"],
            fingerprint_sha256: "de:ad:be:ef:ca:fe:ba:be:12:34:56:78:9a:bc:de:f0",
        },
    ];

    let leaves: Vec<Vec<u8>> = certs.iter().map(make_leaf).collect();
    arbor_examples::queue_leaves(&mut client, leaves, "2 certificate entries").await?;

    // -- Phase 2: New certificate with proof ----------------------------------
    println!("Phase 2: Logging new certificate with ZK proof\n");

    let new_cert = CertificateEntry {
        log_entry_type: "x509_entry",
        timestamp: "2025-04-07T10:00:00Z",
        issuer: "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
        subject: "CN=api.example.com",
        serial: "0e:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
        not_before: "2025-04-07T00:00:00Z",
        not_after: "2025-07-06T00:00:00Z",
        san: vec!["api.example.com"],
        fingerprint_sha256: "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00",
    };

    let job_id = arbor_examples::submit_append(
        &mut client,
        vec![make_leaf(&new_cert)],
        "new certificate for api.example.com",
    )
    .await?;
    arbor_examples::wait_for_job(&mut client, &job_id).await?;

    // -- Phase 3: Verify a certificate is in the log --------------------------
    println!("Phase 3: Verifying certificate inclusion\n");

    let response = client
        .get_inclusion_proof(arbor_server::proto::GetInclusionProofRequest {
            leaf_index: 0,
            tree_size: 3,
        })
        .await?
        .into_inner();

    println!(
        "  Inclusion proof for leaf 0 (example.com cert): {} hashes",
        response.hashes.len()
    );
    println!();

    // -- Phase 4: Consistency proof -------------------------------------------
    println!("Phase 4: Verifying log consistency\n");

    let response = client
        .get_consistency_proof(arbor_server::proto::GetConsistencyProofRequest {
            first_tree_size: 2,
            second_tree_size: 3,
        })
        .await?
        .into_inner();

    println!(
        "  Consistency proof (size 2 -> 3): {} hashes",
        response.hashes.len()
    );
    println!();

    arbor_examples::print_tree_state(&mut client).await?;

    println!("CT monitors can verify the ZK append proof to confirm the log");
    println!("grew honestly — no certificates were removed or reordered.\n");

    Ok(())
}
