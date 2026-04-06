use arbor_host::MapOperator;

// Force linker to include jolt-inlines-sha2's inventory registrations.
extern crate jolt_inlines_sha2;

#[test]
fn prove_and_verify_single_update() {
    tracing_subscriber::fmt::init();

    let mut operator = MapOperator::new();
    let updates = vec![([0x42; 32], b"hello arbor".to_vec())];
    let batch_input = operator.prepare_batch(updates);

    // Compile and preprocess the guest program
    let target_dir = "/tmp/arbor-guest-targets";
    let mut program = guest::compile_derive_batch(target_dir);
    let shared_preprocessing = guest::preprocess_shared_derive_batch(&mut program).unwrap();
    let prover_preprocessing = guest::preprocess_prover_derive_batch(shared_preprocessing.clone());
    let verifier_setup = prover_preprocessing.generators.to_verifier_setup();
    let verifier_preprocessing =
        guest::preprocess_verifier_derive_batch(shared_preprocessing, verifier_setup, None);

    let prove = guest::build_prover_derive_batch(program, prover_preprocessing);
    let verify = guest::build_verifier_derive_batch(verifier_preprocessing);

    let verify_input = batch_input.clone();
    let (output, proof, io_device) = prove(batch_input);

    // Save output fields before moving
    let expected_root = operator.root();
    assert_eq!(output.new_root, expected_root);
    assert_eq!(output.num_updates, 1);

    let is_valid = verify(verify_input, output, io_device.panic, proof);
    assert!(is_valid, "proof verification failed");
}
