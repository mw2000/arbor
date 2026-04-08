//! Arbor gRPC server — transparency log with ZK append proofs.
//!
//! Wraps the Arbor library crates (`arbor-host`, `arbor-verify`, `arbor-core`)
//! behind a tonic gRPC service. The server connects to a Trillian log backend
//! for storage and sequencing, and uses Jolt zkVM for append proofs.

// Force linker to include jolt-inlines-sha2 inventory registrations (via arbor-host).
extern crate arbor_verify;

use std::sync::Arc;

use arbor_core::proof::{ConsistencyProof, InclusionProof};
use arbor_core::HASH_BYTES;
use arbor_host::{AppendInput, AppendOutput, AppendProof, LogProver};
use arbor_store::{JobStore, ProofStore};
use arbor_verify::Verifier;
use jolt_sdk::RV64IMACProof;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

pub mod proto {
    tonic::include_proto!("arbor");
}

use proto::arbor_server::Arbor;
use proto::*;

/// Type alias for the Jolt prover closure.
type ProverFn = dyn Fn(AppendInput) -> (AppendOutput, RV64IMACProof, jolt_sdk::JoltDevice) + Send + Sync;

/// Shared server state.
pub struct ArborService {
    /// The log prover handles Trillian sync + preparing inputs.
    log_prover: Arc<Mutex<LogProver>>,
    /// The Jolt prover closure (expensive one-time setup).
    jolt_prover: Arc<ProverFn>,
    /// The verifier handles ZK proof verification (expensive one-time setup).
    verifier: Arc<Verifier>,
    /// Proof storage backend (stores ZK append proofs).
    store: Arc<dyn ProofStore>,
    /// Job storage backend (outbox for async proof generation).
    job_store: Arc<dyn JobStore>,
}

impl ArborService {
    /// Create a new `ArborService`.
    ///
    /// - `log_prover`: a connected `LogProver` (owns the Trillian connection).
    /// - `verifier`: a preprocessed `Verifier` (owns the Jolt verifier state).
    /// - `jolt_prover`: the Jolt prover closure from `guest::build_prover_prove_append`.
    /// - `store`: proof storage backend (e.g. `SqliteProofStore`).
    /// - `job_store`: job storage backend for async proof generation (e.g. `SqliteJobStore`).
    pub fn new(
        log_prover: LogProver,
        verifier: Verifier,
        jolt_prover: impl Fn(AppendInput) -> (AppendOutput, RV64IMACProof, jolt_sdk::JoltDevice) + Send + Sync + 'static,
        store: impl ProofStore + 'static,
        job_store: impl JobStore + 'static,
    ) -> Self {
        Self {
            log_prover: Arc::new(Mutex::new(log_prover)),
            jolt_prover: Arc::new(jolt_prover),
            verifier: Arc::new(verifier),
            store: Arc::new(store),
            job_store: Arc::new(job_store),
        }
    }

    /// Get a reference to the job store (for the background worker).
    pub fn job_store(&self) -> &Arc<dyn JobStore> {
        &self.job_store
    }

    /// Get a reference to the proof store (for the background worker).
    pub fn proof_store(&self) -> &Arc<dyn ProofStore> {
        &self.store
    }

    /// Get a reference to the Jolt prover (for the background worker).
    pub fn jolt_prover(&self) -> &Arc<ProverFn> {
        &self.jolt_prover
    }

    /// Get a reference to the log prover (for the background worker).
    pub fn log_prover(&self) -> &Arc<Mutex<LogProver>> {
        &self.log_prover
    }
}

/// Convert a `[u8; 32]` hash from proto bytes, returning a gRPC error on bad length.
fn hash_from_proto(bytes: &[u8], field_name: &str) -> Result<arbor_core::Hash, Status> {
    if bytes.len() != HASH_BYTES {
        return Err(Status::invalid_argument(format!(
            "{field_name}: expected {HASH_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    let mut hash = [0u8; HASH_BYTES];
    hash.copy_from_slice(bytes);
    Ok(hash)
}

/// Convert proto `repeated bytes` to `Vec<Hash>`.
fn hashes_from_proto(proto_hashes: &[Vec<u8>]) -> Result<Vec<arbor_core::Hash>, Status> {
    proto_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| hash_from_proto(h, &format!("hashes[{i}]")))
        .collect()
}

#[tonic::async_trait]
impl Arbor for ArborService {
    async fn queue_leaves(
        &self,
        request: Request<QueueLeavesRequest>,
    ) -> Result<Response<QueueLeavesResponse>, Status> {
        let req = request.into_inner();
        info!(num_leaves = req.leaves.len(), "QueueLeaves");

        let mut log_prover = self.log_prover.lock().await;
        let (_input, result) = log_prover
            .sync_and_prepare(req.leaves)
            .await
            .map_err(|e| Status::internal(format!("sync_and_prepare failed: {e}")))?;

        Ok(Response::new(QueueLeavesResponse {
            root: result.new_root.to_vec(),
            tree_size: result.new_size,
        }))
    }

    async fn prove_append(
        &self,
        request: Request<ProveAppendRequest>,
    ) -> Result<Response<ProveAppendResponse>, Status> {
        let req = request.into_inner();
        let num_leaves = req.leaves.len();
        info!(num_leaves, "ProveAppend");

        // 1. Queue leaves and sync with Trillian.
        let (input, result) = {
            let mut log_prover = self.log_prover.lock().await;
            log_prover
                .sync_and_prepare(req.leaves)
                .await
                .map_err(|e| Status::internal(format!("sync_and_prepare failed: {e}")))?
        };

        // 2. Run the Jolt prover (CPU-intensive, runs outside the lock).
        info!(num_leaves, "running Jolt prover...");
        let jolt_prover = Arc::clone(&self.jolt_prover);
        let input_clone = input.clone();
        let append_proof = tokio::task::spawn_blocking(move || {
            let (output, jolt_proof, _io_device) = jolt_prover(input_clone);
            arbor_host::create_append_proof(input, output, &jolt_proof)
        })
        .await
        .map_err(|e| Status::internal(format!("prover task panicked: {e}")))?
        .map_err(|e| Status::internal(format!("proof creation failed: {e}")))?;

        // 3. Store the proof.
        self.store
            .put(&append_proof)
            .map_err(|e| Status::internal(format!("proof storage failed: {e}")))?;

        // 4. Serialize the AppendProof bundle for the response.
        let proof_bytes = serde_json::to_vec(&append_proof)
            .map_err(|e| Status::internal(format!("proof serialization failed: {e}")))?;

        info!(
            old_size = result.old_size,
            new_size = result.new_size,
            proof_bytes = proof_bytes.len(),
            "ProveAppend complete (stored)"
        );

        Ok(Response::new(ProveAppendResponse {
            append_proof: proof_bytes,
            old_root: result.old_root.to_vec(),
            new_root: result.new_root.to_vec(),
            old_size: result.old_size,
            new_size: result.new_size,
        }))
    }

    async fn submit_append(
        &self,
        request: Request<SubmitAppendRequest>,
    ) -> Result<Response<SubmitAppendResponse>, Status> {
        let req = request.into_inner();
        let num_leaves = req.leaves.len();
        info!(num_leaves, "SubmitAppend");

        let job_id = Uuid::new_v4().to_string();

        // 1. Persist the job to the outbox.
        self.job_store
            .create_job(&job_id, &req.leaves)
            .map_err(|e| Status::internal(format!("failed to create job: {e}")))?;

        // 2. Sync with Trillian and prepare the input (fast relative to proving).
        let (input, result) = {
            let mut log_prover = self.log_prover.lock().await;
            log_prover
                .sync_and_prepare(req.leaves)
                .await
                .map_err(|e| Status::internal(format!("sync_and_prepare failed: {e}")))?
        };

        // 3. Store the prepared input so the background worker can pick it up.
        self.job_store
            .set_job_input(&job_id, &input, result.old_size, result.new_size)
            .map_err(|e| Status::internal(format!("failed to set job input: {e}")))?;

        info!(job_id = %job_id, num_leaves, old_size = result.old_size, new_size = result.new_size, "SubmitAppend accepted");

        Ok(Response::new(SubmitAppendResponse { job_id }))
    }

    async fn get_job_status(
        &self,
        request: Request<GetJobStatusRequest>,
    ) -> Result<Response<GetJobStatusResponse>, Status> {
        let req = request.into_inner();

        let summary = self
            .job_store
            .get_job(&req.job_id)
            .map_err(|e| match &e {
                arbor_store::StoreError::JobNotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(format!("job store error: {e}")),
            })?;

        // If completed, fetch the proof from the proof store.
        let append_proof = if summary.status == arbor_store::JobStatus::Completed {
            if let (Some(old_size), Some(new_size)) = (summary.old_size, summary.new_size) {
                match self.store.get(old_size, new_size) {
                    Ok(proof) => serde_json::to_vec(&proof).ok().unwrap_or_default(),
                    Err(_) => Vec::new(),
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Response::new(GetJobStatusResponse {
            job_id: summary.job_id,
            status: summary.status.as_str().to_string(),
            old_size: summary.old_size.unwrap_or(0),
            new_size: summary.new_size.unwrap_or(0),
            error: summary.error.unwrap_or_default(),
            append_proof,
        }))
    }

    async fn verify_append_proof(
        &self,
        request: Request<VerifyAppendProofRequest>,
    ) -> Result<Response<VerifyAppendProofResponse>, Status> {
        let req = request.into_inner();
        info!(
            proof_bytes = req.append_proof.len(),
            "VerifyAppendProof"
        );

        // Deserialize the AppendProof bundle.
        let append_proof: AppendProof = serde_json::from_slice(&req.append_proof)
            .map_err(|e| Status::invalid_argument(format!("invalid append_proof: {e}")))?;

        let old_root = append_proof.output.old_root.to_vec();
        let new_root = append_proof.output.new_root.to_vec();
        let old_size = append_proof.output.old_size;
        let new_size = append_proof.output.new_size;

        // Verify (CPU-intensive).
        let verifier = Arc::clone(&self.verifier);
        let valid = tokio::task::spawn_blocking(move || verifier.verify_append(&append_proof))
            .await
            .map_err(|e| Status::internal(format!("verifier task panicked: {e}")))?
            .map_err(|e| Status::internal(format!("verification failed: {e}")))?;

        info!(valid, old_size, new_size, "VerifyAppendProof complete");

        Ok(Response::new(VerifyAppendProofResponse {
            valid,
            old_root,
            new_root,
            old_size,
            new_size,
        }))
    }

    async fn get_inclusion_proof(
        &self,
        request: Request<GetInclusionProofRequest>,
    ) -> Result<Response<GetInclusionProofResponse>, Status> {
        let req = request.into_inner();
        info!(
            leaf_index = req.leaf_index,
            tree_size = req.tree_size,
            "GetInclusionProof"
        );

        let mut log_prover = self.log_prover.lock().await;
        let proof = log_prover
            .syncer_mut()
            .get_inclusion_proof(req.leaf_index, req.tree_size)
            .await
            .map_err(|e| Status::internal(format!("get_inclusion_proof failed: {e}")))?;

        Ok(Response::new(GetInclusionProofResponse {
            leaf_index: proof.leaf_index,
            tree_size: proof.tree_size,
            hashes: proof.hashes.iter().map(|h| h.to_vec()).collect(),
        }))
    }

    async fn verify_inclusion_proof(
        &self,
        request: Request<VerifyInclusionProofRequest>,
    ) -> Result<Response<VerifyInclusionProofResponse>, Status> {
        let req = request.into_inner();
        info!(
            leaf_index = req.leaf_index,
            tree_size = req.tree_size,
            "VerifyInclusionProof"
        );

        let leaf_hash = hash_from_proto(&req.leaf_hash, "leaf_hash")?;
        let expected_root = hash_from_proto(&req.expected_root, "expected_root")?;
        let hashes = hashes_from_proto(&req.hashes)?;

        let proof = InclusionProof {
            leaf_index: req.leaf_index,
            tree_size: req.tree_size,
            hashes,
        };

        let valid = Verifier::verify_inclusion(&proof, &leaf_hash, &expected_root);

        Ok(Response::new(VerifyInclusionProofResponse { valid }))
    }

    async fn get_consistency_proof(
        &self,
        request: Request<GetConsistencyProofRequest>,
    ) -> Result<Response<GetConsistencyProofResponse>, Status> {
        let req = request.into_inner();
        info!(
            first_tree_size = req.first_tree_size,
            second_tree_size = req.second_tree_size,
            "GetConsistencyProof"
        );

        let mut log_prover = self.log_prover.lock().await;
        let proof = log_prover
            .syncer_mut()
            .get_consistency_proof(req.first_tree_size, req.second_tree_size)
            .await
            .map_err(|e| Status::internal(format!("get_consistency_proof failed: {e}")))?;

        Ok(Response::new(GetConsistencyProofResponse {
            old_size: proof.old_size,
            new_size: proof.new_size,
            hashes: proof.hashes.iter().map(|h| h.to_vec()).collect(),
        }))
    }

    async fn verify_consistency_proof(
        &self,
        request: Request<VerifyConsistencyProofRequest>,
    ) -> Result<Response<VerifyConsistencyProofResponse>, Status> {
        let req = request.into_inner();
        info!(
            old_size = req.old_size,
            new_size = req.new_size,
            "VerifyConsistencyProof"
        );

        let old_root = hash_from_proto(&req.old_root, "old_root")?;
        let new_root = hash_from_proto(&req.new_root, "new_root")?;
        let hashes = hashes_from_proto(&req.hashes)?;

        let proof = ConsistencyProof {
            old_size: req.old_size,
            new_size: req.new_size,
            hashes,
        };

        let valid = Verifier::verify_consistency(&proof, &old_root, &new_root);

        Ok(Response::new(VerifyConsistencyProofResponse { valid }))
    }

    async fn get_tree_state(
        &self,
        _request: Request<GetTreeStateRequest>,
    ) -> Result<Response<GetTreeStateResponse>, Status> {
        let log_prover = self.log_prover.lock().await;
        let root = log_prover.root();
        let tree_size = log_prover.size();

        info!(tree_size, "GetTreeState");

        Ok(Response::new(GetTreeStateResponse {
            root: root.to_vec(),
            tree_size,
        }))
    }

    async fn get_stored_proof(
        &self,
        request: Request<GetStoredProofRequest>,
    ) -> Result<Response<GetStoredProofResponse>, Status> {
        let req = request.into_inner();
        info!(
            old_size = req.old_size,
            new_size = req.new_size,
            "GetStoredProof"
        );

        let proof = self
            .store
            .get(req.old_size, req.new_size)
            .map_err(|e| match &e {
                arbor_store::StoreError::NotFound { .. } => {
                    Status::not_found(e.to_string())
                }
                _ => Status::internal(format!("store error: {e}")),
            })?;

        let proof_bytes = serde_json::to_vec(&proof)
            .map_err(|e| Status::internal(format!("proof serialization failed: {e}")))?;

        Ok(Response::new(GetStoredProofResponse {
            append_proof: proof_bytes,
            old_root: proof.output.old_root.to_vec(),
            new_root: proof.output.new_root.to_vec(),
            old_size: proof.output.old_size,
            new_size: proof.output.new_size,
        }))
    }

    async fn list_stored_proofs(
        &self,
        _request: Request<ListStoredProofsRequest>,
    ) -> Result<Response<ListStoredProofsResponse>, Status> {
        info!("ListStoredProofs");

        let summaries = self
            .store
            .list()
            .map_err(|e| Status::internal(format!("store error: {e}")))?;

        let proofs = summaries
            .into_iter()
            .map(|s| StoredProofSummary {
                id: s.id,
                old_size: s.old_size,
                new_size: s.new_size,
                old_root: s.old_root.to_vec(),
                new_root: s.new_root.to_vec(),
                proof_bytes_len: s.proof_bytes_len as u64,
                created_at: s.created_at,
            })
            .collect();

        Ok(Response::new(ListStoredProofsResponse { proofs }))
    }
}
