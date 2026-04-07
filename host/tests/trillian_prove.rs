//! End-to-end test: Trillian log → sync → Jolt ZK proof → verify.
//!
//! Prerequisites:
//!   cd docker && docker compose up -d
//!
//! Run (must be release mode for reasonable proving time):
//!   cargo test --release -p arbor-host --test trillian_prove -- --ignored --nocapture

extern crate jolt_inlines_sha2;

use arbor_trillian::TrillianSyncer;
use guest::AppendInput;

#[tokio::test]
#[ignore = "requires local Trillian (docker compose up) and --release"]
async fn trillian_prove_and_verify() {
    tracing_subscriber::fmt::init();

    // --- 1. Sync leaves from Trillian ---
    let endpoint = "http://localhost:8090";
    let mut syncer = TrillianSyncer::connect_and_create_tree(endpoint)
        .await
        .expect("failed to connect to Trillian");

    println!("created Trillian log tree (id={})", syncer.log_id());

    let leaves: Vec<Vec<u8>> = (0..3u8)
        .map(|i| format!("trillian-leaf-{i}").into_bytes())
        .collect();

    let result = syncer
        .queue_and_sync(leaves)
        .await
        .expect("queue_and_sync failed");

    println!(
        "synced {} leaves: old_root={}, new_root={}",
        result.new_size - result.old_size,
        hex(&result.old_root),
        hex(&result.new_root),
    );

    // --- 2. Build AppendInput from SyncResult ---
    let append_input = AppendInput {
        frontier: result.old_frontier,
        tree_size: result.old_size,
        new_leaves: result.leaf_values,
    };

    // --- 3. Compile guest, preprocess, prove ---
    println!("compiling guest program...");
    let target_dir = "/tmp/arbor-guest-targets";
    let mut program = guest::compile_prove_append(target_dir);

    println!("preprocessing...");
    let shared = guest::preprocess_shared_prove_append(&mut program).unwrap();
    let prover_pp = guest::preprocess_prover_prove_append(shared.clone());
    let verifier_setup = prover_pp.generators.to_verifier_setup();
    let verifier_pp = guest::preprocess_verifier_prove_append(shared, verifier_setup, None);

    let prove = guest::build_prover_prove_append(program, prover_pp);
    let verify = guest::build_verifier_prove_append(verifier_pp);

    println!("proving...");
    let verify_input = append_input.clone();
    let (output, proof, io_device) = prove(append_input);

    println!(
        "proof generated! old_root={}, new_root={}, old_size={}, new_size={}",
        hex(&output.old_root),
        hex(&output.new_root),
        output.old_size,
        output.new_size,
    );

    assert_eq!(output.old_root, result.old_root);
    assert_eq!(output.new_root, result.new_root);
    assert_eq!(output.old_size, result.old_size);
    assert_eq!(output.new_size, result.new_size);

    // --- 4. Verify the proof ---
    println!("verifying...");
    let is_valid = verify(verify_input, output, io_device.panic, proof);
    assert!(is_valid, "ZK proof verification failed!");

    println!("ZK proof verified! Trillian log update is provably correct.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
