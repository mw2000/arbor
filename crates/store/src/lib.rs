//! Proof and job storage for Arbor.
//!
//! Provides a [`ProofStore`] trait for persisting ZK append proofs and a
//! [`SqliteProofStore`] implementation backed by an embedded SQLite database.
//!
//! Also provides a [`JobStore`] trait and [`SqliteJobStore`] for the outbox
//! pattern — decoupling proof requests from the long-running Jolt prover.
//!
//! Append proofs are the expensive artifacts (Jolt ZK proofs) worth persisting.
//! Inclusion and consistency proofs are cheap to fetch from Trillian on demand
//! and are not stored here.
//!
//! # Example
//!
//! ```ignore
//! use arbor_store::SqliteProofStore;
//!
//! let store = SqliteProofStore::open("proofs.db")?;
//! store.put(&append_proof)?;
//!
//! // Retrieve by tree size range.
//! let proof = store.get(0, 5)?;
//!
//! // List all stored proofs.
//! let summaries = store.list()?;
//! ```

mod job;
mod sqlite;

pub use job::{JobStatus, JobStore, JobSummary, SqliteJobStore};
pub use sqlite::SqliteProofStore;

use arbor_core::Hash;
use guest::AppendProof;

/// Errors from proof storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("proof not found for old_size={old_size}, new_size={new_size}")]
    NotFound { old_size: u64, new_size: u64 },

    #[error("job not found: {0}")]
    JobNotFound(String),
}

/// Summary of a stored proof (without the full proof blob).
#[derive(Debug, Clone)]
pub struct ProofSummary {
    /// Auto-increment row ID.
    pub id: i64,
    /// Old tree size before the append.
    pub old_size: u64,
    /// New tree size after the append.
    pub new_size: u64,
    /// Old root hash.
    pub old_root: Hash,
    /// New root hash.
    pub new_root: Hash,
    /// Size of the serialized proof in bytes.
    pub proof_bytes_len: usize,
    /// When the proof was stored (Unix timestamp seconds).
    pub created_at: i64,
}

/// Trait for proof storage backends.
///
/// Implementations must be safe to share across threads (`Send + Sync`).
pub trait ProofStore: Send + Sync {
    /// Store an append proof. Overwrites any existing proof for the same
    /// `(old_size, new_size)` pair.
    fn put(&self, proof: &AppendProof) -> Result<(), StoreError>;

    /// Retrieve an append proof by its tree size transition.
    fn get(&self, old_size: u64, new_size: u64) -> Result<AppendProof, StoreError>;

    /// Retrieve an append proof by its row ID.
    fn get_by_id(&self, id: i64) -> Result<AppendProof, StoreError>;

    /// List summaries of all stored proofs, ordered by new_size ascending.
    fn list(&self) -> Result<Vec<ProofSummary>, StoreError>;

    /// Count the number of stored proofs.
    fn count(&self) -> Result<u64, StoreError>;

    /// Delete a proof by its tree size transition. Returns true if a row was deleted.
    fn delete(&self, old_size: u64, new_size: u64) -> Result<bool, StoreError>;
}
