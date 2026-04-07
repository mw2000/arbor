// Force linker to include jolt-inlines-sha2's inventory registrations.
extern crate jolt_inlines_sha2;

use arbor_core::CompactRange;
use guest::AppendInput;

#[test]
fn prove_and_verify_append() {
    tracing_subscriber::fmt::init();

    let mut cr = CompactRange::new();
    let leaves: Vec<Vec<u8>> = vec![b"leaf0".to_vec(), b"leaf1".to_vec(), b"leaf2".to_vec()];

    let append_input = AppendInput {
        frontier: cr.frontier().to_vec(),
        tree_size: cr.size(),
        new_leaves: leaves.clone(),
    };
    for leaf in &leaves {
        cr.append(leaf);
    }

    // Compile and preprocess the guest program
    let target_dir = "/tmp/arbor-guest-targets";
    let mut program = guest::compile_prove_append(target_dir);
    let shared_preprocessing = guest::preprocess_shared_prove_append(&mut program).unwrap();
    let prover_preprocessing = guest::preprocess_prover_prove_append(shared_preprocessing.clone());
    let verifier_setup = prover_preprocessing.generators.to_verifier_setup();
    let verifier_preprocessing =
        guest::preprocess_verifier_prove_append(shared_preprocessing, verifier_setup, None);

    let prove = guest::build_prover_prove_append(program, prover_preprocessing);
    let verify = guest::build_verifier_prove_append(verifier_preprocessing);

    let verify_input = append_input.clone();
    let (output, proof, io_device) = prove(append_input);

    assert_eq!(output.new_root, cr.root());
    assert_eq!(output.old_size, 0);
    assert_eq!(output.new_size, 3);

    let is_valid = verify(verify_input, output, io_device.panic, proof);
    assert!(is_valid, "proof verification failed");
}
