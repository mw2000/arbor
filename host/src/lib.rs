// Force linker to include jolt-inlines-sha2 inventory registrations.
extern crate jolt_inlines_sha2;

use arbor_smt::CompactRange;
use guest::AppendInput;

/// Host-side log prover. Maintains the compact range (frontier)
/// of the append-only Merkle tree and produces inputs for the guest prover.
pub struct LogProver {
    compact_range: CompactRange,
}

impl LogProver {
    pub fn new() -> Self {
        Self {
            compact_range: CompactRange::new(),
        }
    }

    pub fn root(&self) -> arbor_smt::Hash {
        self.compact_range.root()
    }

    pub fn size(&self) -> u64 {
        self.compact_range.size()
    }

    /// Build an `AppendInput` for a batch of new leaves.
    /// Snapshots the current frontier, then applies the appends locally.
    /// The returned input can be passed to the guest program for proving.
    pub fn prepare_append(&mut self, new_leaves: Vec<Vec<u8>>) -> AppendInput {
        let input = AppendInput {
            frontier: self.compact_range.frontier().to_vec(),
            tree_size: self.compact_range.size(),
            new_leaves: new_leaves.clone(),
        };

        // Apply locally so the prover's state stays in sync.
        for leaf in &new_leaves {
            self.compact_range.append(leaf);
        }

        input
    }
}

impl Default for LogProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbor_smt::empty_tree_root;
    use guest::prove_append;

    #[test]
    fn single_append() {
        let mut prover = LogProver::new();
        let input = prover.prepare_append(vec![b"leaf0".to_vec()]);
        let output = prove_append(input);

        assert_eq!(output.old_root, empty_tree_root());
        assert_eq!(output.new_root, prover.root());
        assert_eq!(output.old_size, 0);
        assert_eq!(output.new_size, 1);
    }

    #[test]
    fn batch_append() {
        let mut prover = LogProver::new();
        let leaves: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i]).collect();
        let input = prover.prepare_append(leaves);
        let output = prove_append(input);

        assert_eq!(output.new_root, prover.root());
        assert_eq!(output.old_size, 0);
        assert_eq!(output.new_size, 5);
    }

    #[test]
    fn sequential_batches() {
        let mut prover = LogProver::new();

        // First batch: 3 leaves
        let input1 = prover.prepare_append(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let output1 = prove_append(input1);
        assert_eq!(output1.new_root, prover.root());
        assert_eq!(output1.new_size, 3);

        // Second batch: 2 more leaves
        let input2 = prover.prepare_append(vec![b"d".to_vec(), b"e".to_vec()]);
        let output2 = prove_append(input2);
        assert_eq!(output2.old_root, output1.new_root);
        assert_eq!(output2.new_root, prover.root());
        assert_eq!(output2.old_size, 3);
        assert_eq!(output2.new_size, 5);
    }

    #[test]
    fn empty_batch() {
        let mut prover = LogProver::new();
        let root_before = prover.root();

        let input = prover.prepare_append(vec![]);
        let output = prove_append(input);

        assert_eq!(output.old_root, root_before);
        assert_eq!(output.new_root, root_before);
        assert_eq!(output.new_size, 0);
    }
}
