//! Arbor benchmarks.
//!
//! Run with: `cargo bench -p arbor-bench`
//!
//! Benchmarks:
//! - CompactRange append (raw tree building)
//! - Native prove_append (guest function without ZK)
//! - Inclusion proof verification
//! - Consistency proof verification
//! - Proof store put/get (SQLite round-trip)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use arbor_core::proof::{ConsistencyProof, InclusionProof};
use arbor_core::{hash_node, hash_rfc6962_leaf, CompactRange, Hash};
use arbor_store::SqliteProofStore;
use arbor_core::{AppendInput, AppendOutput, AppendProof};

// ---------------------------------------------------------------------------
// Proof generation helpers (mirrors the test helpers in arbor-core)
// ---------------------------------------------------------------------------

fn merkle_root_from_hashes(hashes: &[Hash]) -> Hash {
    match hashes.len() {
        0 => arbor_core::empty_tree_root(),
        1 => hashes[0],
        n => {
            let k = n.next_power_of_two() / 2;
            let left = merkle_root_from_hashes(&hashes[..k]);
            let right = merkle_root_from_hashes(&hashes[k..]);
            hash_node(&left, &right)
        }
    }
}

fn gen_inclusion_proof(leaf_hashes: &[Hash], index: usize) -> Vec<Hash> {
    let n = leaf_hashes.len();
    if n <= 1 {
        return vec![];
    }
    let k = n.next_power_of_two() / 2;
    if index < k {
        let mut proof = gen_inclusion_proof(&leaf_hashes[..k], index);
        proof.push(merkle_root_from_hashes(&leaf_hashes[k..]));
        proof
    } else {
        let mut proof = gen_inclusion_proof(&leaf_hashes[k..], index - k);
        proof.push(merkle_root_from_hashes(&leaf_hashes[..k]));
        proof
    }
}

fn gen_consistency_proof(leaf_hashes: &[Hash], old_size: usize) -> Vec<Hash> {
    let new_size = leaf_hashes.len();
    if old_size == 0 || old_size == new_size {
        return vec![];
    }

    let idx = old_size - 1;
    let incl_proof = gen_inclusion_proof(&leaf_hashes[..new_size], idx);
    let shift = old_size.trailing_zeros() as usize;

    let mut seed = leaf_hashes[idx];
    for (i, h) in incl_proof[..shift].iter().enumerate() {
        if ((idx as u64) >> i) & 1 == 0 {
            seed = hash_node(&seed, h);
        } else {
            seed = hash_node(h, &seed);
        }
    }

    let remaining = &incl_proof[shift..];
    if old_size.is_power_of_two() {
        remaining.to_vec()
    } else {
        let mut proof = vec![seed];
        proof.extend_from_slice(remaining);
        proof
    }
}

/// Build leaf data for `n` leaves.
fn make_leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

/// Build leaf hashes for `n` leaves.
fn make_leaf_hashes(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| hash_rfc6962_leaf(format!("leaf-{i}").as_bytes()))
        .collect()
}

// ---------------------------------------------------------------------------
// CompactRange benchmarks
// ---------------------------------------------------------------------------

fn bench_compact_range_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("compact_range_append");

    for &n in &[10, 100, 1_000, 10_000] {
        let leaves = make_leaves(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &leaves, |b, leaves| {
            b.iter(|| {
                let mut cr = CompactRange::new();
                for leaf in leaves {
                    cr.append(black_box(leaf));
                }
                black_box(cr.root());
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Native prove_append benchmarks (guest function, no ZK)
// ---------------------------------------------------------------------------

fn bench_native_prove_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("native_prove_append");

    for &n in &[1, 10, 50, 100] {
        let leaves = make_leaves(n);
        let cr = CompactRange::new();

        let input = AppendInput {
            frontier: cr.frontier().to_vec(),
            tree_size: cr.size(),
            new_leaves: leaves,
        };

        group.bench_with_input(BenchmarkId::from_parameter(n), &input, |b, input| {
            b.iter(|| {
                let output = guest::prove_append(black_box(input.clone()));
                black_box(output);
            });
        });
    }

    group.finish();
}

fn bench_native_prove_append_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("native_prove_append_incremental");

    // Pre-populate a tree, then benchmark appending to it.
    for &existing in &[100, 1_000, 10_000] {
        let mut cr = CompactRange::new();
        for i in 0..existing {
            cr.append(format!("pre-{i}").as_bytes());
        }

        let new_leaves: Vec<Vec<u8>> = (0..10).map(|i| format!("new-{i}").into_bytes()).collect();

        let input = AppendInput {
            frontier: cr.frontier().to_vec(),
            tree_size: cr.size(),
            new_leaves,
        };

        group.bench_with_input(
            BenchmarkId::new("10_leaves_onto", existing),
            &input,
            |b, input| {
                b.iter(|| {
                    let output = guest::prove_append(black_box(input.clone()));
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Inclusion proof verification benchmarks
// ---------------------------------------------------------------------------

fn bench_inclusion_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("inclusion_verify");

    for &n in &[8, 64, 1_024, 65_536] {
        let leaf_hashes = make_leaf_hashes(n);
        let root = merkle_root_from_hashes(&leaf_hashes);

        // Benchmark verifying proof for a leaf in the middle.
        let index = n / 2;
        let proof_hashes = gen_inclusion_proof(&leaf_hashes, index);
        let proof = InclusionProof {
            leaf_index: index as u64,
            tree_size: n as u64,
            hashes: proof_hashes,
        };

        group.bench_with_input(
            BenchmarkId::new("tree_size", n),
            &(&proof, &leaf_hashes[index], &root),
            |b, (proof, leaf_hash, root)| {
                b.iter(|| {
                    let valid = proof.verify(black_box(leaf_hash), black_box(root));
                    assert!(valid);
                    black_box(valid);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Consistency proof verification benchmarks
// ---------------------------------------------------------------------------

fn bench_consistency_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("consistency_verify");

    for &(old, new) in &[(4, 8), (32, 64), (512, 1_024), (1_000, 65_536)] {
        let leaf_hashes = make_leaf_hashes(new);
        let old_root = merkle_root_from_hashes(&leaf_hashes[..old]);
        let new_root = merkle_root_from_hashes(&leaf_hashes);

        let proof_hashes = gen_consistency_proof(&leaf_hashes, old);
        let proof = ConsistencyProof {
            old_size: old as u64,
            new_size: new as u64,
            hashes: proof_hashes,
        };

        group.bench_with_input(
            BenchmarkId::new("transition", format!("{old}_to_{new}")),
            &(&proof, &old_root, &new_root),
            |b, (proof, old_root, new_root)| {
                b.iter(|| {
                    let valid = proof.verify(black_box(old_root), black_box(new_root));
                    assert!(valid);
                    black_box(valid);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Proof store benchmarks
// ---------------------------------------------------------------------------

fn bench_proof_store(c: &mut Criterion) {
    use arbor_store::ProofStore;

    let mut group = c.benchmark_group("proof_store");

    // Build a fake proof to store.
    let proof = AppendProof::new(
        AppendInput {
            frontier: vec![[1u8; 32]],
            tree_size: 100,
            new_leaves: make_leaves(10),
        },
        AppendOutput {
            old_root: [1u8; 32],
            new_root: [2u8; 32],
            old_size: 100,
            new_size: 110,
        },
        vec![0u8; 1024], // fake ZK proof bytes
    );

    group.bench_function("put", |b| {
        let store = SqliteProofStore::in_memory().unwrap();
        b.iter(|| {
            store.put(black_box(&proof)).unwrap();
        });
    });

    group.bench_function("get", |b| {
        let store = SqliteProofStore::in_memory().unwrap();
        store.put(&proof).unwrap();
        b.iter(|| {
            let p = store.get(black_box(100), black_box(110)).unwrap();
            black_box(p);
        });
    });

    group.bench_function("list_100", |b| {
        let store = SqliteProofStore::in_memory().unwrap();
        for i in 0..100u64 {
            let p = AppendProof::new(
                AppendInput {
                    frontier: vec![[i as u8; 32]],
                    tree_size: i,
                    new_leaves: vec![vec![i as u8]],
                },
                AppendOutput {
                    old_root: [i as u8; 32],
                    new_root: [(i + 1) as u8; 32],
                    old_size: i,
                    new_size: i + 1,
                },
                vec![0u8; 256],
            );
            store.put(&p).unwrap();
        }
        b.iter(|| {
            let list = store.list().unwrap();
            black_box(list);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_compact_range_append,
    bench_native_prove_append,
    bench_native_prove_append_incremental,
    bench_inclusion_verify,
    bench_consistency_verify,
    bench_proof_store,
);
criterion_main!(benches);
