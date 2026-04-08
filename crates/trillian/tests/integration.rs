//! Integration test that runs against a local Trillian instance.
//!
//! Prerequisites:
//!   cd docker && docker compose up -d
//!
//! Run:
//!   cargo test -p arbor-trillian --test integration -- --ignored

use arbor_core::{empty_tree_root, hash_rfc6962_leaf};
use arbor_trillian::TrillianSyncer;

/// Test the full flow: create tree, queue leaves, sync, verify roots match.
#[tokio::test]
#[ignore = "requires local Trillian (docker compose up)"]
async fn sync_and_verify_roots() {
    tracing_subscriber::fmt::init();

    let endpoint = "http://localhost:8090";

    // Create a fresh log tree.
    let mut syncer = TrillianSyncer::connect_and_create_tree(endpoint)
        .await
        .expect("failed to connect and create tree");

    println!("created tree with log_id = {}", syncer.log_id());

    // Initially empty.
    assert_eq!(syncer.local_size(), 0);
    assert_eq!(syncer.local_root(), empty_tree_root());

    // Queue 5 leaves and sync.
    let leaves: Vec<Vec<u8>> = (0..5u8).map(|i| format!("leaf-{i}").into_bytes()).collect();
    let result = syncer
        .queue_and_sync(leaves)
        .await
        .expect("queue_and_sync failed");

    println!(
        "synced: old_size={}, new_size={}, old_root={}, new_root={}",
        result.old_size,
        result.new_size,
        hex(&result.old_root),
        hex(&result.new_root),
    );

    assert_eq!(result.old_size, 0);
    assert_eq!(result.new_size, 5);
    assert_eq!(result.old_root, empty_tree_root());
    assert_ne!(result.new_root, empty_tree_root());

    // Verify our local state matches Trillian's reported root.
    let log_root = syncer.get_log_root().await.expect("get_log_root failed");
    assert_eq!(
        syncer.local_root().as_slice(),
        log_root.root_hash.as_slice()
    );
    assert_eq!(log_root.tree_size, 5);

    // Queue 3 more leaves and sync again (tests sequential batches).
    let more_leaves: Vec<Vec<u8>> = (5..8u8).map(|i| format!("leaf-{i}").into_bytes()).collect();
    let result2 = syncer
        .queue_and_sync(more_leaves)
        .await
        .expect("second queue_and_sync failed");

    assert_eq!(result2.old_size, 5);
    assert_eq!(result2.new_size, 8);
    assert_eq!(result2.old_root, result.new_root); // Chain links.

    let log_root2 = syncer.get_log_root().await.expect("get_log_root failed");
    assert_eq!(
        syncer.local_root().as_slice(),
        log_root2.root_hash.as_slice()
    );
    assert_eq!(log_root2.tree_size, 8);

    println!(
        "all roots verified! final tree_size={}, root={}",
        log_root2.tree_size,
        hex(&syncer.local_root()),
    );

    // -- Test inclusion proofs --

    // Fetch an inclusion proof for leaf 0 in the 8-leaf tree.
    let inclusion = syncer
        .get_inclusion_proof(0, 8)
        .await
        .expect("get_inclusion_proof failed");
    assert_eq!(inclusion.leaf_index, 0);
    assert_eq!(inclusion.tree_size, 8);
    let leaf0_hash = hash_rfc6962_leaf(b"leaf-0");
    assert!(
        inclusion.verify(&leaf0_hash, &syncer.local_root()),
        "inclusion proof verification failed for leaf 0"
    );
    println!(
        "inclusion proof for leaf 0 verified (proof len = {})",
        inclusion.hashes.len()
    );

    // Test inclusion proof for a middle leaf.
    let inclusion3 = syncer
        .get_inclusion_proof(3, 8)
        .await
        .expect("get_inclusion_proof for leaf 3 failed");
    let leaf3_hash = hash_rfc6962_leaf(b"leaf-3");
    assert!(
        inclusion3.verify(&leaf3_hash, &syncer.local_root()),
        "inclusion proof verification failed for leaf 3"
    );
    println!("inclusion proof for leaf 3 verified");

    // Test inclusion proof for the last leaf.
    let inclusion7 = syncer
        .get_inclusion_proof(7, 8)
        .await
        .expect("get_inclusion_proof for leaf 7 failed");
    let leaf7_hash = hash_rfc6962_leaf(b"leaf-7");
    assert!(
        inclusion7.verify(&leaf7_hash, &syncer.local_root()),
        "inclusion proof verification failed for leaf 7"
    );
    println!("inclusion proof for leaf 7 verified");

    // -- Test consistency proof --

    // Prove the tree at size 5 is a prefix of the tree at size 8.
    let consistency = syncer
        .get_consistency_proof(5, 8)
        .await
        .expect("get_consistency_proof failed");
    assert_eq!(consistency.old_size, 5);
    assert_eq!(consistency.new_size, 8);
    assert!(
        consistency.verify(&result.new_root, &result2.new_root),
        "consistency proof verification failed for 5 -> 8"
    );
    println!(
        "consistency proof 5 -> 8 verified (proof len = {})",
        consistency.hashes.len()
    );

    // Also test computing the new root from the consistency proof.
    let computed_new_root = consistency
        .new_root_from(&result.new_root)
        .expect("new_root_from failed");
    assert_eq!(computed_new_root, result2.new_root);
    println!("all proof tests passed!");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
