//! End-to-end test: Trillian log → sync → Jolt ZK proof → verify.
//!
//! Prerequisites:
//!   cd docker && docker compose up -d
//!
//! Run (must be release mode for reasonable proving time):
//!   cargo nextest run --release -p arbor-host --test trillian_prove --run-ignored ignored-only --no-capture

extern crate jolt_inlines_sha2;

use arbor_host::LogProver;

#[tokio::test]
#[ignore = "requires local Trillian (docker compose up) and --release"]
async fn trillian_prove_and_verify() {
    tracing_subscriber::fmt::init();

    // --- 1. Connect to Trillian and sync leaves ---
    let mut prover = LogProver::connect_and_create_tree("http://localhost:8090")
        .await
        .expect("failed to connect to Trillian");

    println!("created Trillian log tree (id={})", prover.log_id());

    let leaves: Vec<Vec<u8>> = (0..3u8)
        .map(|i| format!("trillian-leaf-{i}").into_bytes())
        .collect();

    let (append_input, result) = prover
        .sync_and_prepare(leaves)
        .await
        .expect("sync_and_prepare failed");

    println!(
        "synced {} leaves: old_root={}, new_root={}",
        result.new_size - result.old_size,
        hex(&result.old_root),
        hex(&result.new_root),
    );

    // --- 2. Compile guest, preprocess, prove ---
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

    // --- 3. Verify the proof ---
    println!("verifying...");
    let is_valid = verify(verify_input, output, io_device.panic, proof);
    assert!(is_valid, "ZK proof verification failed!");

    println!("ZK proof verified! Trillian log update is provably correct.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
