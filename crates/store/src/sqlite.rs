//! SQLite-backed proof storage.

use std::path::Path;

use arbor_core::AppendProof;
use rusqlite::{params, Connection, OptionalExtension};
use tracing::info;

use crate::{ProofStore, ProofSummary, StoreError};

/// SQLite-backed proof store.
///
/// Uses an embedded SQLite database (via `rusqlite` with the `bundled` feature)
/// so there are no external dependencies to install.
///
/// Thread safety: uses an internal `Mutex<Connection>` so multiple threads can
/// call store methods concurrently.
pub struct SqliteProofStore {
    conn: std::sync::Mutex<Connection>,
}

impl SqliteProofStore {
    /// Open (or create) a SQLite proof store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path.as_ref())?;
        let store = Self {
            conn: std::sync::Mutex::new(conn),
        };
        store.init_schema()?;
        info!(path = %path.as_ref().display(), "opened proof store");
        Ok(store)
    }

    /// Create an in-memory proof store (useful for tests).
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: std::sync::Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS append_proofs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                old_size    INTEGER NOT NULL,
                new_size    INTEGER NOT NULL,
                old_root    BLOB NOT NULL,
                new_root    BLOB NOT NULL,
                proof_json  BLOB NOT NULL,
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                UNIQUE(old_size, new_size)
            );

            CREATE INDEX IF NOT EXISTS idx_append_proofs_new_size
                ON append_proofs(new_size);",
        )?;
        Ok(())
    }
}

impl ProofStore for SqliteProofStore {
    fn put(&self, proof: &AppendProof) -> Result<(), StoreError> {
        let json =
            serde_json::to_vec(proof).map_err(|e| StoreError::Serialization(e.to_string()))?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO append_proofs (old_size, new_size, old_root, new_root, proof_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                proof.output.old_size as i64,
                proof.output.new_size as i64,
                proof.output.old_root.as_slice(),
                proof.output.new_root.as_slice(),
                json,
            ],
        )?;

        tracing::debug!(
            old_size = proof.output.old_size,
            new_size = proof.output.new_size,
            bytes = json.len(),
            "stored append proof"
        );

        Ok(())
    }

    fn get(&self, old_size: u64, new_size: u64) -> Result<AppendProof, StoreError> {
        let conn = self.conn.lock().unwrap();
        let json: Vec<u8> = conn
            .query_row(
                "SELECT proof_json FROM append_proofs WHERE old_size = ?1 AND new_size = ?2",
                params![old_size as i64, new_size as i64],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound { old_size, new_size })?;

        serde_json::from_slice(&json).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    fn get_by_id(&self, id: i64) -> Result<AppendProof, StoreError> {
        let conn = self.conn.lock().unwrap();
        let json: Vec<u8> = conn
            .query_row(
                "SELECT proof_json FROM append_proofs WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound {
                old_size: 0,
                new_size: 0,
            })?;

        serde_json::from_slice(&json).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    fn list(&self) -> Result<Vec<ProofSummary>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, old_size, new_size, old_root, new_root, length(proof_json), created_at
             FROM append_proofs
             ORDER BY new_size ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            let old_root_bytes: Vec<u8> = row.get(3)?;
            let new_root_bytes: Vec<u8> = row.get(4)?;

            let mut old_root = [0u8; 32];
            let mut new_root = [0u8; 32];
            if old_root_bytes.len() == 32 {
                old_root.copy_from_slice(&old_root_bytes);
            }
            if new_root_bytes.len() == 32 {
                new_root.copy_from_slice(&new_root_bytes);
            }

            Ok(ProofSummary {
                id: row.get(0)?,
                old_size: row.get::<_, i64>(1)? as u64,
                new_size: row.get::<_, i64>(2)? as u64,
                old_root,
                new_root,
                proof_bytes_len: row.get::<_, i64>(5)? as usize,
                created_at: row.get(6)?,
            })
        })?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row?);
        }
        Ok(summaries)
    }

    fn count(&self) -> Result<u64, StoreError> {
        let conn = self.conn.lock().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM append_proofs", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    fn delete(&self, old_size: u64, new_size: u64) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM append_proofs WHERE old_size = ?1 AND new_size = ?2",
            params![old_size as i64, new_size as i64],
        )?;
        Ok(deleted > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbor_core::{AppendInput, AppendOutput, AppendProof, Hash};

    fn make_proof(old_size: u64, new_size: u64) -> AppendProof {
        let old_root: Hash = [old_size as u8; 32];
        let new_root: Hash = [new_size as u8; 32];

        AppendProof::new(
            AppendInput {
                frontier: vec![old_root],
                tree_size: old_size,
                new_leaves: vec![vec![42u8]],
            },
            AppendOutput {
                old_root,
                new_root,
                old_size,
                new_size,
            },
            vec![0xDE, 0xAD, 0xBE, 0xEF], // fake proof bytes
        )
    }

    #[test]
    fn put_and_get() {
        let store = SqliteProofStore::in_memory().unwrap();
        let proof = make_proof(0, 3);

        store.put(&proof).unwrap();

        let retrieved = store.get(0, 3).unwrap();
        assert_eq!(retrieved.output.old_size, 0);
        assert_eq!(retrieved.output.new_size, 3);
        assert_eq!(retrieved.output.old_root, proof.output.old_root);
        assert_eq!(retrieved.output.new_root, proof.output.new_root);
        assert_eq!(retrieved.proof_bytes, proof.proof_bytes);
    }

    #[test]
    fn get_not_found() {
        let store = SqliteProofStore::in_memory().unwrap();
        let result = store.get(0, 99);
        assert!(matches!(result, Err(StoreError::NotFound { .. })));
    }

    #[test]
    fn put_overwrites() {
        let store = SqliteProofStore::in_memory().unwrap();

        let proof1 = make_proof(0, 3);
        store.put(&proof1).unwrap();

        // Overwrite with a different proof_bytes.
        let mut proof2 = make_proof(0, 3);
        proof2.proof_bytes = vec![0xFF; 8];
        store.put(&proof2).unwrap();

        let retrieved = store.get(0, 3).unwrap();
        assert_eq!(retrieved.proof_bytes, vec![0xFF; 8]);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn list_and_count() {
        let store = SqliteProofStore::in_memory().unwrap();

        store.put(&make_proof(0, 3)).unwrap();
        store.put(&make_proof(3, 7)).unwrap();
        store.put(&make_proof(7, 10)).unwrap();

        assert_eq!(store.count().unwrap(), 3);

        let summaries = store.list().unwrap();
        assert_eq!(summaries.len(), 3);
        // Ordered by new_size ascending.
        assert_eq!(summaries[0].new_size, 3);
        assert_eq!(summaries[1].new_size, 7);
        assert_eq!(summaries[2].new_size, 10);
        // Each summary has the correct roots.
        assert_eq!(summaries[0].old_root, [0u8; 32]);
        assert_eq!(summaries[2].new_root, [10u8; 32]);
    }

    #[test]
    fn get_by_id() {
        let store = SqliteProofStore::in_memory().unwrap();
        store.put(&make_proof(0, 3)).unwrap();
        store.put(&make_proof(3, 7)).unwrap();

        let summaries = store.list().unwrap();
        let proof = store.get_by_id(summaries[1].id).unwrap();
        assert_eq!(proof.output.old_size, 3);
        assert_eq!(proof.output.new_size, 7);
    }

    #[test]
    fn delete() {
        let store = SqliteProofStore::in_memory().unwrap();
        store.put(&make_proof(0, 3)).unwrap();
        store.put(&make_proof(3, 7)).unwrap();

        assert!(store.delete(0, 3).unwrap());
        assert!(!store.delete(0, 3).unwrap()); // already deleted
        assert_eq!(store.count().unwrap(), 1);

        // Remaining proof is still there.
        let proof = store.get(3, 7).unwrap();
        assert_eq!(proof.output.new_size, 7);
    }

    #[test]
    fn file_based_store() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("proofs.db");

        // Write.
        {
            let store = SqliteProofStore::open(&db_path).unwrap();
            store.put(&make_proof(0, 5)).unwrap();
        }

        // Re-open and read.
        {
            let store = SqliteProofStore::open(&db_path).unwrap();
            let proof = store.get(0, 5).unwrap();
            assert_eq!(proof.output.new_size, 5);
            assert_eq!(store.count().unwrap(), 1);
        }
    }
}
