//! Software Supply Chain — binary transparency for software releases.
//!
//! Demonstrates logging software release artifacts to Arbor and proving
//! the artifact registry has not been tampered with. Users can verify
//! that the binary they downloaded was the one the maintainer published.
//!
//! # Prerequisites
//!
//! 1. Start Trillian: `cd examples && docker compose up -d`
//! 2. Start Arbor:    `cargo run -p arbor-service -- --trillian-endpoint http://localhost:8090 --create-tree`
//!
//! # Run
//!
//! ```sh
//! cargo run --example software-supply-chain
//! ```

use serde::Serialize;

#[derive(Serialize)]
struct ReleaseArtifact {
    package: &'static str,
    version: &'static str,
    platform: &'static str,
    sha256: &'static str,
    git_commit: &'static str,
    build_timestamp: &'static str,
    builder: &'static str,
    reproducible: bool,
}

fn make_leaf(artifact: &ReleaseArtifact) -> Vec<u8> {
    serde_json::to_vec(artifact).expect("serialization cannot fail")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Software Supply Chain Example ===\n");

    let mut client = arbor_examples::connect(None).await?;

    // -- Phase 1: Log initial release artifacts -------------------------------
    println!("Phase 1: Logging release artifacts\n");

    let artifacts = vec![
        ReleaseArtifact {
            package: "arbor-service-bin",
            version: "0.1.0",
            platform: "linux-amd64",
            sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            git_commit: "e42db7c",
            build_timestamp: "2025-04-07T12:00:00Z",
            builder: "github-actions",
            reproducible: true,
        },
        ReleaseArtifact {
            package: "arbor-service-bin",
            version: "0.1.0",
            platform: "darwin-arm64",
            sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            git_commit: "e42db7c",
            build_timestamp: "2025-04-07T12:05:00Z",
            builder: "github-actions",
            reproducible: true,
        },
        ReleaseArtifact {
            package: "arbor-service-bin",
            version: "0.1.0",
            platform: "windows-amd64",
            sha256: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
            git_commit: "e42db7c",
            build_timestamp: "2025-04-07T12:10:00Z",
            builder: "github-actions",
            reproducible: true,
        },
    ];

    let leaves: Vec<Vec<u8>> = artifacts.iter().map(make_leaf).collect();
    arbor_examples::queue_leaves(&mut client, leaves, "v0.1.0 for 3 platforms").await?;

    // -- Phase 2: New release with proof --------------------------------------
    println!("Phase 2: Publishing v0.2.0 with ZK proof\n");

    let new_release = ReleaseArtifact {
        package: "arbor-service-bin",
        version: "0.2.0",
        platform: "linux-amd64",
        sha256: "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        git_commit: "f1a2b3c",
        build_timestamp: "2025-04-14T08:00:00Z",
        builder: "github-actions",
        reproducible: true,
    };

    let job_id = arbor_examples::submit_append(
        &mut client,
        vec![make_leaf(&new_release)],
        "v0.2.0 linux-amd64",
    )
    .await?;
    arbor_examples::wait_for_job(&mut client, &job_id).await?;

    // -- Phase 3: Verify the artifact is in the log ---------------------------
    println!("Phase 3: Verifying artifact inclusion\n");

    let response = client
        .get_inclusion_proof(arbor_server::proto::GetInclusionProofRequest {
            leaf_index: 0,
            tree_size: 4,
        })
        .await?
        .into_inner();

    println!(
        "  Inclusion proof for leaf 0 (v0.1.0 linux-amd64): {} hashes",
        response.hashes.len()
    );
    println!();

    arbor_examples::print_tree_state(&mut client).await?;

    println!("Users can verify their downloaded binary's SHA-256 is in the log");
    println!("by checking the inclusion proof against the published tree root.\n");

    Ok(())
}
