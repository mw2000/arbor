//! Standalone verification for Arbor proofs.
//!
//! This crate provides a unified [`Verifier`] that can check all Arbor proof
//! types without needing a Trillian connection:
//!
//! - **Append proofs** (ZK) — Jolt zkVM proofs that a batch of leaves was
//!   correctly appended to the Merkle tree.
//! - **Inclusion proofs** — standard Merkle paths proving a leaf exists at
//!   a given index.
//! - **Consistency proofs** — proofs that an older tree is a prefix of a
//!   newer tree.
//!
//! # Example
//!
//! ```ignore
//! use arbor_verify::Verifier;
//!
//! // One-time setup (compiles guest program, expensive).
//! let verifier = Verifier::new("/tmp/arbor-guest-targets")?;
//!
//! // Verify a serialized append proof.
//! let is_valid = verifier.verify_append(&append_proof)?;
//!
//! // Verify an inclusion proof (no Jolt needed, instant).
//! let is_valid = Verifier::verify_inclusion(&inclusion_proof, &leaf_hash, &root);
//!
//! // Verify a consistency proof (no Jolt needed, instant).
//! let is_valid = Verifier::verify_consistency(&consistency_proof, &old_root, &new_root);
//! ```

// Force linker to include jolt-inlines-sha2 inventory registrations.
extern crate jolt_inlines_sha2;

pub use arbor_core::proof::{ConsistencyProof, InclusionProof};
pub use arbor_core::Hash;
pub use guest::{AppendInput, AppendOutput, AppendProof};

use jolt_sdk::{RV64IMACProof, Serializable};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("failed to deserialize Jolt proof: {0}")]
    DeserializeProof(String),

    #[error("Jolt verifier setup failed: {0}")]
    Setup(String),

    #[error("proof verification failed")]
    VerificationFailed,
}

/// Standalone proof verifier for all Arbor proof types.
///
/// Inclusion and consistency proofs are verified using pure hash operations
/// (no setup needed). Append proofs require a one-time Jolt preprocessing
/// step that compiles the guest program.
///
/// # Setup cost
///
/// `Verifier::new()` compiles the Jolt guest program and runs preprocessing.
/// This is expensive (seconds to minutes) but only needs to happen once.
/// Reuse the `Verifier` instance for multiple proof verifications.
pub struct Verifier {
    /// Boxed verify closure from Jolt. Captures the verifier preprocessing.
    verify_fn: Box<dyn Fn(AppendInput, AppendOutput, bool, RV64IMACProof) -> bool + Send>,
}

impl Verifier {
    /// Create a new verifier by compiling and preprocessing the guest program.
    ///
    /// `target_dir` is a directory for caching the compiled guest binary
    /// (e.g. `"/tmp/arbor-guest-targets"`). The same directory can be reused
    /// across runs to speed up subsequent calls.
    ///
    /// This is expensive on first call. Subsequent calls with the same
    /// `target_dir` may be faster if compilation artifacts are cached.
    pub fn new(target_dir: &str) -> Result<Self, VerifyError> {
        tracing::info!("compiling guest program...");
        let mut program = guest::compile_prove_append(target_dir);

        tracing::info!("running shared preprocessing...");
        let shared = guest::preprocess_shared_prove_append(&mut program)
            .map_err(|e| VerifyError::Setup(format!("shared preprocessing failed: {e}")))?;

        tracing::info!("running prover preprocessing (for verifier setup)...");
        let prover_pp = guest::preprocess_prover_prove_append(shared.clone());
        let verifier_setup = prover_pp.generators.to_verifier_setup();

        tracing::info!("running verifier preprocessing...");
        let verifier_pp = guest::preprocess_verifier_prove_append(shared, verifier_setup, None);

        let verify = guest::build_verifier_prove_append(verifier_pp);
        tracing::info!("verifier ready");

        Ok(Self {
            verify_fn: Box::new(verify),
        })
    }

    /// Verify a ZK append proof.
    ///
    /// Deserializes the Jolt proof from the `AppendProof` bundle and runs
    /// the Jolt verifier. Returns `Ok(true)` if the proof is valid,
    /// `Ok(false)` if it's invalid, or `Err` if deserialization fails.
    pub fn verify_append(&self, proof: &AppendProof) -> Result<bool, VerifyError> {
        let jolt_proof = RV64IMACProof::deserialize_from_bytes(&proof.proof_bytes)
            .map_err(|e| VerifyError::DeserializeProof(e.to_string()))?;

        let is_valid = (self.verify_fn)(
            proof.input.clone(),
            proof.output.clone(),
            false, // panic flag: a valid proof should never have panicked
            jolt_proof,
        );

        Ok(is_valid)
    }

    /// Verify a Merkle inclusion proof.
    ///
    /// This is a pure hash operation — no Jolt setup needed.
    /// Can be called without constructing a `Verifier`.
    ///
    /// `leaf_hash` should be the RFC 6962 leaf hash (`SHA256(0x00 || data)`).
    pub fn verify_inclusion(
        proof: &InclusionProof,
        leaf_hash: &Hash,
        expected_root: &Hash,
    ) -> bool {
        proof.verify(leaf_hash, expected_root)
    }

    /// Verify a Merkle consistency proof.
    ///
    /// This is a pure hash operation — no Jolt setup needed.
    /// Can be called without constructing a `Verifier`.
    pub fn verify_consistency(proof: &ConsistencyProof, old_root: &Hash, new_root: &Hash) -> bool {
        proof.verify(old_root, new_root)
    }
}
