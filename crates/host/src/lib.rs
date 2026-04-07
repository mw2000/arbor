// Force linker to include jolt-inlines-sha2 inventory registrations.
extern crate jolt_inlines_sha2;

pub use arbor_trillian::{SyncResult, SyncerError, TrillianSyncer};
pub use guest::{AppendInput, AppendOutput, AppendProof};
use jolt_sdk::{RV64IMACProof, Serializable};

/// Host-side log prover. Wraps a `TrillianSyncer` to sync leaves from
/// a Trillian log and prepare inputs for the Jolt guest prover.
pub struct LogProver {
    syncer: TrillianSyncer,
}

impl LogProver {
    /// Connect to a Trillian gRPC endpoint and use an existing log tree.
    pub async fn connect(endpoint: &str, log_id: i64) -> Result<Self, SyncerError> {
        let syncer = TrillianSyncer::connect(endpoint, log_id).await?;
        Ok(Self { syncer })
    }

    /// Connect to a Trillian gRPC endpoint and create a new log tree.
    pub async fn connect_and_create_tree(endpoint: &str) -> Result<Self, SyncerError> {
        let syncer = TrillianSyncer::connect_and_create_tree(endpoint).await?;
        Ok(Self { syncer })
    }

    pub fn log_id(&self) -> i64 {
        self.syncer.log_id()
    }

    pub fn root(&self) -> arbor_core::Hash {
        self.syncer.local_root()
    }

    pub fn size(&self) -> u64 {
        self.syncer.local_size()
    }

    /// Queue leaves to Trillian, wait for integration, sync, and return
    /// an `AppendInput` ready for the guest prover.
    ///
    /// This is the primary entry point: it handles the full
    /// Trillian sync → AppendInput construction pipeline.
    pub async fn sync_and_prepare(
        &mut self,
        leaves: Vec<Vec<u8>>,
    ) -> Result<(AppendInput, SyncResult), SyncerError> {
        let result = self.syncer.queue_and_sync(leaves).await?;
        let input = AppendInput {
            frontier: result.old_frontier.clone(),
            tree_size: result.old_size,
            new_leaves: result.leaf_values.clone(),
        };
        Ok((input, result))
    }

    /// Lower-level: construct an `AppendInput` from an existing `SyncResult`.
    pub fn prepare_from_sync(result: &SyncResult) -> AppendInput {
        AppendInput {
            frontier: result.old_frontier.clone(),
            tree_size: result.old_size,
            new_leaves: result.leaf_values.clone(),
        }
    }

    /// Access the underlying syncer for direct Trillian operations.
    pub fn syncer(&self) -> &TrillianSyncer {
        &self.syncer
    }

    /// Mutable access to the underlying syncer.
    pub fn syncer_mut(&mut self) -> &mut TrillianSyncer {
        &mut self.syncer
    }
}

/// Serialize a Jolt `RV64IMACProof` into a byte vector.
///
/// Uses ark-serialize compressed format via Jolt's `Serializable` trait.
pub fn serialize_jolt_proof(proof: &RV64IMACProof) -> Result<Vec<u8>, String> {
    proof
        .serialize_to_bytes()
        .map_err(|e| format!("failed to serialize Jolt proof: {e}"))
}

/// Deserialize a Jolt `RV64IMACProof` from bytes.
///
/// The bytes must have been produced by [`serialize_jolt_proof`] (ark-serialize compressed).
pub fn deserialize_jolt_proof(bytes: &[u8]) -> Result<RV64IMACProof, String> {
    RV64IMACProof::deserialize_from_bytes(bytes)
        .map_err(|e| format!("failed to deserialize Jolt proof: {e}"))
}

/// Create an `AppendProof` from the output of a Jolt prove call.
///
/// This is the bridge between the raw Jolt prove result and the
/// serializable `AppendProof` bundle:
///
/// ```ignore
/// let (output, jolt_proof, _io_device) = prove(input.clone());
/// let append_proof = create_append_proof(input, output, &jolt_proof)?;
/// ```
pub fn create_append_proof(
    input: AppendInput,
    output: AppendOutput,
    jolt_proof: &RV64IMACProof,
) -> Result<AppendProof, String> {
    let proof_bytes = serialize_jolt_proof(jolt_proof)?;
    Ok(AppendProof::new(input, output, proof_bytes))
}

#[cfg(test)]
mod tests {
    use arbor_core::{empty_tree_root, CompactRange};
    use guest::{prove_append, AppendInput};

    /// Helper: build an AppendInput directly from leaf data (no Trillian).
    /// Used for fast native-execution unit tests.
    fn prepare_native(
        compact_range: &mut CompactRange,
        new_leaves: Vec<Vec<u8>>,
    ) -> AppendInput {
        let input = AppendInput {
            frontier: compact_range.frontier().to_vec(),
            tree_size: compact_range.size(),
            new_leaves: new_leaves.clone(),
        };
        for leaf in &new_leaves {
            compact_range.append(leaf);
        }
        input
    }

    #[test]
    fn single_append() {
        let mut cr = CompactRange::new();
        let input = prepare_native(&mut cr, vec![b"leaf0".to_vec()]);
        let output = prove_append(input);

        assert_eq!(output.old_root, empty_tree_root());
        assert_eq!(output.new_root, cr.root());
        assert_eq!(output.old_size, 0);
        assert_eq!(output.new_size, 1);
    }

    #[test]
    fn batch_append() {
        let mut cr = CompactRange::new();
        let leaves: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i]).collect();
        let input = prepare_native(&mut cr, leaves);
        let output = prove_append(input);

        assert_eq!(output.new_root, cr.root());
        assert_eq!(output.old_size, 0);
        assert_eq!(output.new_size, 5);
    }

    #[test]
    fn sequential_batches() {
        let mut cr = CompactRange::new();

        let input1 = prepare_native(&mut cr, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let output1 = prove_append(input1);
        assert_eq!(output1.new_root, cr.root());
        assert_eq!(output1.new_size, 3);

        let input2 = prepare_native(&mut cr, vec![b"d".to_vec(), b"e".to_vec()]);
        let output2 = prove_append(input2);
        assert_eq!(output2.old_root, output1.new_root);
        assert_eq!(output2.new_root, cr.root());
        assert_eq!(output2.old_size, 3);
        assert_eq!(output2.new_size, 5);
    }

    #[test]
    fn empty_batch() {
        let mut cr = CompactRange::new();
        let root_before = cr.root();

        let input = prepare_native(&mut cr, vec![]);
        let output = prove_append(input);

        assert_eq!(output.old_root, root_before);
        assert_eq!(output.new_root, root_before);
        assert_eq!(output.new_size, 0);
    }
}
