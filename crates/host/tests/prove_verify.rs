// Force linker to include jolt-inlines-sha2's inventory registrations.
extern crate jolt_inlines_sha2;

use arbor_core::CompactRange;
use arbor_host::{create_append_proof, deserialize_jolt_proof, serialize_jolt_proof};
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

    let (output, proof, io_device) = prove(append_input.clone());

    assert_eq!(output.new_root, cr.root());
    assert_eq!(output.old_size, 0);
    assert_eq!(output.new_size, 3);

    // -- Test proof serialization round-trip --

    // Serialize the Jolt proof to bytes.
    let proof_bytes = serialize_jolt_proof(&proof).expect("serialize failed");
    println!("serialized Jolt proof: {} bytes", proof_bytes.len());
    assert!(!proof_bytes.is_empty());

    // -- Test AppendProof bundle --

    let append_proof = create_append_proof(append_input.clone(), output.clone(), &proof)
        .expect("create_append_proof failed");
    assert_eq!(append_proof.old_size(), 0);
    assert_eq!(append_proof.new_size(), 3);
    assert_eq!(*append_proof.new_root(), cr.root());
    assert_eq!(append_proof.proof_bytes.len(), proof_bytes.len());

    // Verify the original proof directly.
    let is_valid = verify(append_input.clone(), output.clone(), io_device.panic, proof);
    assert!(is_valid, "proof verification failed");

    // Deserialize from the AppendProof bundle and re-verify.
    let proof_roundtrip =
        deserialize_jolt_proof(&append_proof.proof_bytes).expect("deserialize failed");
    let is_valid_roundtrip = verify(
        append_proof.input,
        append_proof.output,
        false,
        proof_roundtrip,
    );
    assert!(is_valid_roundtrip, "round-trip proof verification failed");

    println!("all serialization tests passed!");
}
