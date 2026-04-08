#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

pub use arbor_core::{AppendInput, AppendOutput, AppendProof};
use arbor_core::CompactRange;

/// Prove that appending `new_leaves` to a Merkle tree with the given
/// compact range produces the correct new root.
///
/// This runs inside the zkVM guest. The Jolt proof attests:
/// "the tree with frontier F and size N has root R_old, and after
/// appending these leaves, the tree has root R_new and size N+K."
#[jolt::provable(
    max_input_size = 65536,
    max_output_size = 4096,
    stack_size = 65536,
    heap_size = 1048576,
    max_trace_length = 16777216
)]
fn prove_append(input: AppendInput) -> AppendOutput {
    let mut compact = CompactRange::from_parts(input.frontier, input.tree_size);
    let old_root = compact.root();
    let old_size = compact.size();

    for leaf in &input.new_leaves {
        compact.append(leaf);
    }

    AppendOutput {
        old_root,
        new_root: compact.root(),
        old_size,
        new_size: compact.size(),
    }
}

#[cfg(test)]
mod tests {
    use arbor_core::{empty_tree_root, AppendInput, CompactRange};
    use super::prove_append;

    fn prepare_native(compact_range: &mut CompactRange, new_leaves: Vec<Vec<u8>>) -> AppendInput {
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
