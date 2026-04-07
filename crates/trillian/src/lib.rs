// google.rpc types must be at crate root so generated trillian code
// can reference them via `super::google::rpc::Status`.
pub mod google {
    pub mod rpc {
        tonic::include_proto!("google.rpc");
    }
}

pub mod proto {
    tonic::include_proto!("trillian");
}

mod log_root;
mod syncer;

pub use arbor_core::proof::{ConsistencyProof, InclusionProof};
pub use log_root::{LogRootV1, ParseLogRootError};
pub use syncer::{SyncResult, SyncerError, TrillianSyncer};
