//! SQLite-backed job store for the outbox pattern.

use std::path::Path;

use guest::AppendInput;
use rusqlite::{params, Connection, OptionalExtension};
use tracing::info;

use crate::StoreError;

/// Status of an outbox job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::InProgress => "in_progress",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(JobStatus::Pending),
            "in_progress" => Some(JobStatus::InProgress),
            "completed" => Some(JobStatus::Completed),
            "failed" => Some(JobStatus::Failed),
            _ => None,
        }
    }
}

/// Summary of a job (without the full input/proof blobs).
#[derive(Debug, Clone)]
pub struct JobSummary {
    pub job_id: String,
    pub status: JobStatus,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Trait for job storage backends.
///
/// Implementations must be safe to share across threads (`Send + Sync`).
pub trait JobStore: Send + Sync {
    /// Create a new pending job with the given leaves. Returns the job ID.
    fn create_job(&self, job_id: &str, leaves: &[Vec<u8>]) -> Result<(), StoreError>;

    /// Store the prepared `AppendInput` for a job (after Trillian sync).
    fn set_job_input(
        &self,
        job_id: &str,
        input: &AppendInput,
        old_size: u64,
        new_size: u64,
    ) -> Result<(), StoreError>;

    /// Atomically claim the next pending job (set status to `in_progress`).
    /// Returns `None` if no pending jobs exist.
    fn claim_next_pending(&self) -> Result<Option<String>, StoreError>;

    /// Get the leaves for a job.
    fn get_job_leaves(&self, job_id: &str) -> Result<Vec<Vec<u8>>, StoreError>;

    /// Get the prepared `AppendInput` for a job.
    fn get_job_input(&self, job_id: &str) -> Result<AppendInput, StoreError>;

    /// Mark a job as completed.
    fn mark_completed(&self, job_id: &str) -> Result<(), StoreError>;

    /// Mark a job as failed with an error message.
    fn mark_failed(&self, job_id: &str, error: &str) -> Result<(), StoreError>;

    /// Get the summary of a job by its ID.
    fn get_job(&self, job_id: &str) -> Result<JobSummary, StoreError>;
}

/// SQLite-backed job store.
pub struct SqliteJobStore {
    conn: std::sync::Mutex<Connection>,
}

impl SqliteJobStore {
    /// Open (or create) a SQLite job store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path.as_ref())?;
        let store = Self {
            conn: std::sync::Mutex::new(conn),
        };
        store.init_schema()?;
        info!(path = %path.as_ref().display(), "opened job store");
        Ok(store)
    }

    /// Create an in-memory job store (useful for tests).
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
            "CREATE TABLE IF NOT EXISTS jobs (
                job_id      TEXT PRIMARY KEY,
                status      TEXT NOT NULL DEFAULT 'pending',
                leaves_json BLOB NOT NULL,
                input_json  BLOB,
                old_size    INTEGER,
                new_size    INTEGER,
                error       TEXT,
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_status
                ON jobs(status, created_at);",
        )?;
        Ok(())
    }
}

impl JobStore for SqliteJobStore {
    fn create_job(&self, job_id: &str, leaves: &[Vec<u8>]) -> Result<(), StoreError> {
        let leaves_json =
            serde_json::to_vec(leaves).map_err(|e| StoreError::Serialization(e.to_string()))?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO jobs (job_id, leaves_json) VALUES (?1, ?2)",
            params![job_id, leaves_json],
        )?;

        tracing::debug!(job_id, "created pending job");
        Ok(())
    }

    fn set_job_input(
        &self,
        job_id: &str,
        input: &AppendInput,
        old_size: u64,
        new_size: u64,
    ) -> Result<(), StoreError> {
        let input_json =
            serde_json::to_vec(input).map_err(|e| StoreError::Serialization(e.to_string()))?;

        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE jobs SET input_json = ?1, old_size = ?2, new_size = ?3,
                            updated_at = strftime('%s', 'now')
             WHERE job_id = ?4",
            params![input_json, old_size as i64, new_size as i64, job_id],
        )?;

        if updated == 0 {
            return Err(StoreError::JobNotFound(job_id.to_string()));
        }
        Ok(())
    }

    fn claim_next_pending(&self) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let job_id: Option<String> = conn
            .query_row(
                "SELECT job_id FROM jobs WHERE status = 'pending' AND input_json IS NOT NULL
                 ORDER BY created_at ASC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(ref id) = job_id {
            conn.execute(
                "UPDATE jobs SET status = 'in_progress', updated_at = strftime('%s', 'now')
                 WHERE job_id = ?1",
                params![id],
            )?;
            tracing::debug!(job_id = %id, "claimed pending job");
        }

        Ok(job_id)
    }

    fn get_job_leaves(&self, job_id: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let json: Vec<u8> = conn
            .query_row(
                "SELECT leaves_json FROM jobs WHERE job_id = ?1",
                params![job_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::JobNotFound(job_id.to_string()))?;

        serde_json::from_slice(&json).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    fn get_job_input(&self, job_id: &str) -> Result<AppendInput, StoreError> {
        let conn = self.conn.lock().unwrap();
        let json: Vec<u8> = conn
            .query_row(
                "SELECT input_json FROM jobs WHERE job_id = ?1 AND input_json IS NOT NULL",
                params![job_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::JobNotFound(job_id.to_string()))?;

        serde_json::from_slice(&json).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    fn mark_completed(&self, job_id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE jobs SET status = 'completed', updated_at = strftime('%s', 'now')
             WHERE job_id = ?1",
            params![job_id],
        )?;

        if updated == 0 {
            return Err(StoreError::JobNotFound(job_id.to_string()));
        }
        tracing::debug!(job_id, "marked job completed");
        Ok(())
    }

    fn mark_failed(&self, job_id: &str, error: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE jobs SET status = 'failed', error = ?1, updated_at = strftime('%s', 'now')
             WHERE job_id = ?2",
            params![error, job_id],
        )?;

        if updated == 0 {
            return Err(StoreError::JobNotFound(job_id.to_string()));
        }
        tracing::debug!(job_id, error, "marked job failed");
        Ok(())
    }

    fn get_job(&self, job_id: &str) -> Result<JobSummary, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT job_id, status, old_size, new_size, error, created_at, updated_at
             FROM jobs WHERE job_id = ?1",
            params![job_id],
            |row| {
                let status_str: String = row.get(1)?;
                let old_size: Option<i64> = row.get(2)?;
                let new_size: Option<i64> = row.get(3)?;

                Ok(JobSummary {
                    job_id: row.get(0)?,
                    status: JobStatus::from_str(&status_str).unwrap_or(JobStatus::Pending),
                    old_size: old_size.map(|v| v as u64),
                    new_size: new_size.map(|v| v as u64),
                    error: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::JobNotFound(job_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_job() {
        let store = SqliteJobStore::in_memory().unwrap();
        let leaves = vec![vec![1u8, 2, 3], vec![4u8, 5, 6]];

        store.create_job("job-1", &leaves).unwrap();

        let summary = store.get_job("job-1").unwrap();
        assert_eq!(summary.status, JobStatus::Pending);
        assert!(summary.old_size.is_none());

        let retrieved_leaves = store.get_job_leaves("job-1").unwrap();
        assert_eq!(retrieved_leaves, leaves);
    }

    #[test]
    fn claim_requires_input() {
        let store = SqliteJobStore::in_memory().unwrap();
        let leaves = vec![vec![1u8]];

        store.create_job("job-1", &leaves).unwrap();

        // Can't claim yet — no input_json.
        assert!(store.claim_next_pending().unwrap().is_none());

        // Set input.
        let input = AppendInput {
            frontier: vec![[0u8; 32]],
            tree_size: 0,
            new_leaves: leaves.clone(),
        };
        store.set_job_input("job-1", &input, 0, 1).unwrap();

        // Now we can claim.
        let claimed = store.claim_next_pending().unwrap();
        assert_eq!(claimed, Some("job-1".to_string()));

        let summary = store.get_job("job-1").unwrap();
        assert_eq!(summary.status, JobStatus::InProgress);
    }

    #[test]
    fn mark_completed_and_failed() {
        let store = SqliteJobStore::in_memory().unwrap();
        store.create_job("job-ok", &[vec![1u8]]).unwrap();
        store.create_job("job-err", &[vec![2u8]]).unwrap();

        store.mark_completed("job-ok").unwrap();
        store.mark_failed("job-err", "prover crashed").unwrap();

        assert_eq!(
            store.get_job("job-ok").unwrap().status,
            JobStatus::Completed
        );

        let failed = store.get_job("job-err").unwrap();
        assert_eq!(failed.status, JobStatus::Failed);
        assert_eq!(failed.error.as_deref(), Some("prover crashed"));
    }

    #[test]
    fn get_job_not_found() {
        let store = SqliteJobStore::in_memory().unwrap();
        assert!(matches!(
            store.get_job("nonexistent"),
            Err(StoreError::JobNotFound(_))
        ));
    }

    #[test]
    fn fifo_ordering() {
        let store = SqliteJobStore::in_memory().unwrap();
        let input = AppendInput {
            frontier: vec![[0u8; 32]],
            tree_size: 0,
            new_leaves: vec![vec![1u8]],
        };

        store.create_job("job-a", &[vec![1u8]]).unwrap();
        store.create_job("job-b", &[vec![2u8]]).unwrap();

        store.set_job_input("job-a", &input, 0, 1).unwrap();
        store.set_job_input("job-b", &input, 0, 1).unwrap();

        // Should claim job-a first (FIFO).
        assert_eq!(
            store.claim_next_pending().unwrap(),
            Some("job-a".to_string())
        );
        assert_eq!(
            store.claim_next_pending().unwrap(),
            Some("job-b".to_string())
        );
        assert!(store.claim_next_pending().unwrap().is_none());
    }
}
