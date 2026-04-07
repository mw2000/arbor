use arbor_smt::CompactRange;
use tonic::transport::Channel;
use tracing::{debug, info};

use crate::log_root::LogRootV1;
use crate::proto::trillian_admin_client::TrillianAdminClient;
use crate::proto::trillian_log_client::TrillianLogClient;
use crate::proto::{
    CreateTreeRequest, GetLatestSignedLogRootRequest, GetLeavesByRangeRequest, InitLogRequest,
    LogLeaf, QueueLeafRequest, Tree, TreeState, TreeType,
};

/// Maximum number of leaves to fetch in a single gRPC call.
const FETCH_BATCH_SIZE: i64 = 1000;

#[derive(Debug, thiserror::Error)]
pub enum SyncerError {
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("log root parse error: {0}")]
    LogRootParse(#[from] crate::log_root::ParseLogRootError),

    #[error("missing signed log root in response")]
    MissingLogRoot,

    #[error("root mismatch: our {our} != trillian {trillian}", our = hex::encode(.our), trillian = hex::encode(.trillian))]
    RootMismatch { our: Vec<u8>, trillian: Vec<u8> },

    #[error("tree creation failed: missing tree in response")]
    TreeCreationFailed,
}

// Minimal hex encoding (avoids adding the `hex` crate).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Client that syncs a Trillian log into an Arbor `CompactRange`
/// and verifies our locally-computed root matches Trillian's.
pub struct TrillianSyncer {
    log_client: TrillianLogClient<Channel>,
    #[allow(dead_code)]
    admin_client: TrillianAdminClient<Channel>,
    log_id: i64,
    compact_range: CompactRange,
}

impl TrillianSyncer {
    /// Connect to a Trillian gRPC endpoint and use an existing log tree.
    pub async fn connect(endpoint: &str, log_id: i64) -> Result<Self, SyncerError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .unwrap()
            .connect()
            .await?;

        Ok(Self {
            log_client: TrillianLogClient::new(channel.clone()),
            admin_client: TrillianAdminClient::new(channel),
            log_id,
            compact_range: CompactRange::new(),
        })
    }

    /// Connect to a Trillian gRPC endpoint and create a new log tree.
    /// Returns the syncer with the newly created tree's ID.
    pub async fn connect_and_create_tree(endpoint: &str) -> Result<Self, SyncerError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .unwrap()
            .connect()
            .await?;

        let mut admin_client = TrillianAdminClient::new(channel.clone());
        let log_client = TrillianLogClient::new(channel);

        // Create a new LOG tree.
        let tree = Tree {
            tree_state: TreeState::Active.into(),
            tree_type: TreeType::Log.into(),
            max_root_duration: Some(prost_types::Duration {
                seconds: 1,
                nanos: 0,
            }),
            ..Default::default()
        };
        let resp = admin_client
            .create_tree(CreateTreeRequest {
                tree: Some(tree),
                ..Default::default()
            })
            .await?;

        let created_tree = resp.into_inner();
        let log_id = created_tree.tree_id;
        info!(log_id, "created new Trillian log tree");

        // Initialize the log (creates the initial empty signed root).
        let mut log_client_clone = log_client.clone();
        log_client_clone
            .init_log(InitLogRequest {
                log_id,
                ..Default::default()
            })
            .await?;
        info!(log_id, "initialized log tree");

        Ok(Self {
            log_client,
            admin_client,
            log_id,
            compact_range: CompactRange::new(),
        })
    }

    pub fn log_id(&self) -> i64 {
        self.log_id
    }

    pub fn compact_range(&self) -> &CompactRange {
        &self.compact_range
    }

    pub fn local_root(&self) -> arbor_smt::Hash {
        self.compact_range.root()
    }

    pub fn local_size(&self) -> u64 {
        self.compact_range.size()
    }

    /// Fetch the latest log root from Trillian and parse it.
    pub async fn get_log_root(&mut self) -> Result<LogRootV1, SyncerError> {
        let resp = self
            .log_client
            .get_latest_signed_log_root(GetLatestSignedLogRootRequest {
                log_id: self.log_id,
                ..Default::default()
            })
            .await?;

        let signed_root = resp
            .into_inner()
            .signed_log_root
            .ok_or(SyncerError::MissingLogRoot)?;

        Ok(LogRootV1::parse(&signed_root.log_root)?)
    }

    /// Queue a single leaf for inclusion in the Trillian log.
    pub async fn queue_leaf(&mut self, leaf_value: Vec<u8>) -> Result<(), SyncerError> {
        self.log_client
            .queue_leaf(QueueLeafRequest {
                log_id: self.log_id,
                leaf: Some(LogLeaf {
                    leaf_value,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// Queue multiple leaves for inclusion.
    pub async fn queue_leaves(&mut self, leaves: Vec<Vec<u8>>) -> Result<(), SyncerError> {
        for leaf_value in leaves {
            self.queue_leaf(leaf_value).await?;
        }
        Ok(())
    }

    /// Sync all new leaves from Trillian since our last known position.
    ///
    /// Fetches leaves from `self.local_size()` up to Trillian's current tree size,
    /// appends them to the local `CompactRange`, and verifies the root matches.
    ///
    /// Returns the number of new leaves synced.
    pub async fn sync(&mut self) -> Result<u64, SyncerError> {
        let log_root = self.get_log_root().await?;
        let trillian_size = log_root.tree_size;
        let local_size = self.compact_range.size();

        if trillian_size <= local_size {
            debug!(trillian_size, local_size, "already up to date");
            return Ok(0);
        }

        let new_leaves = trillian_size - local_size;
        info!(
            local_size,
            trillian_size, new_leaves, "syncing new leaves from Trillian"
        );

        // Fetch leaves in batches.
        let mut fetched = 0u64;
        while fetched < new_leaves {
            let batch_count = std::cmp::min(FETCH_BATCH_SIZE, (new_leaves - fetched) as i64);
            let start_index = (local_size + fetched) as i64;

            let resp = self
                .log_client
                .get_leaves_by_range(GetLeavesByRangeRequest {
                    log_id: self.log_id,
                    start_index,
                    count: batch_count,
                    ..Default::default()
                })
                .await?;

            let leaves = resp.into_inner().leaves;
            if leaves.is_empty() {
                // Server returned fewer leaves than expected — tree may not
                // have caught up yet. Caller should retry.
                break;
            }

            for leaf in &leaves {
                self.compact_range.append(&leaf.leaf_value);
            }
            fetched += leaves.len() as u64;

            debug!(
                fetched,
                total = new_leaves,
                "fetched batch of {} leaves",
                leaves.len()
            );
        }

        // Verify our root matches Trillian's.
        if fetched == new_leaves {
            let our_root = self.compact_range.root();
            if our_root.as_slice() != log_root.root_hash.as_slice() {
                return Err(SyncerError::RootMismatch {
                    our: our_root.to_vec(),
                    trillian: log_root.root_hash,
                });
            }
            info!(
                tree_size = trillian_size,
                root = hex::encode(&our_root),
                "root verified: local matches Trillian"
            );
        }

        Ok(fetched)
    }

    /// Convenience: queue leaves, wait for integration, sync, and return
    /// the `CompactRange` state before and after for proving.
    ///
    /// Returns `(old_frontier, old_size, leaf_values, new_root)` suitable
    /// for constructing an `AppendInput` for the guest prover.
    pub async fn queue_and_sync(
        &mut self,
        leaves: Vec<Vec<u8>>,
    ) -> Result<SyncResult, SyncerError> {
        let old_frontier = self.compact_range.frontier().to_vec();
        let old_size = self.compact_range.size();
        let old_root = self.compact_range.root();

        // Queue all leaves.
        self.queue_leaves(leaves.clone()).await?;

        // Poll until all leaves are integrated.
        let target_size = old_size + leaves.len() as u64;
        let mut synced = 0u64;
        for attempt in 0..60 {
            // Wait for the signer to integrate leaves.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            synced += self.sync().await?;
            if self.compact_range.size() >= target_size {
                break;
            }
            debug!(
                attempt,
                current_size = self.compact_range.size(),
                target_size,
                "waiting for leaf integration"
            );
        }

        if self.compact_range.size() < target_size {
            info!(
                current = self.compact_range.size(),
                target = target_size,
                synced,
                "partial sync: not all leaves integrated yet"
            );
        }

        Ok(SyncResult {
            old_frontier,
            old_size,
            old_root,
            new_root: self.compact_range.root(),
            new_size: self.compact_range.size(),
            leaf_values: leaves,
        })
    }
}

/// Result of a `queue_and_sync` operation, containing all the data needed
/// to construct an `AppendInput` for the Jolt guest prover.
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub old_frontier: Vec<arbor_smt::Hash>,
    pub old_size: u64,
    pub old_root: arbor_smt::Hash,
    pub new_root: arbor_smt::Hash,
    pub new_size: u64,
    pub leaf_values: Vec<Vec<u8>>,
}
