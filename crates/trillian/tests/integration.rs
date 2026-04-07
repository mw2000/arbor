//! Integration test that runs against a local Trillian instance.
//!
//! Prerequisites:
//!   cd docker && docker compose up -d
//!
//! Run:
//!   cargo test -p arbor-trillian --test integration -- --ignored

use arbor_core::empty_tree_root;
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
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
