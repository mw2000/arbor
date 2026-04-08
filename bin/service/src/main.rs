//! Arbor gRPC server binary.
//!
//! Connects to a Trillian log backend and exposes the Arbor service over gRPC.
//! Includes a background worker for async proof generation (outbox pattern).
//!
//! # Usage
//!
//! ```sh
//! # Connect to an existing Trillian log tree:
//! arbor-service-bin --trillian-endpoint http://localhost:8090 --log-id 123456
//!
//! # Create a new Trillian log tree on startup:
//! arbor-service-bin --trillian-endpoint http://localhost:8090 --create-tree
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arbor_host::LogProver;
use arbor_server::proto::arbor_server::ArborServer;
use arbor_server::ArborService;
use arbor_store::{JobStore, ProofStore, SqliteJobStore, SqliteProofStore};
use arbor_verify::Verifier;
use clap::Parser;
use tonic::transport::Server;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "arbor-service-bin",
    about = "Arbor transparency log gRPC server"
)]
struct Args {
    /// gRPC listen address.
    #[arg(long, default_value = "[::1]:50051")]
    listen: String,

    /// Trillian log server gRPC endpoint.
    #[arg(long, default_value = "http://localhost:8090")]
    trillian_endpoint: String,

    /// Trillian log tree ID. Required unless --create-tree is set.
    #[arg(long)]
    log_id: Option<i64>,

    /// Create a new Trillian log tree on startup instead of using --log-id.
    #[arg(long, default_value_t = false)]
    create_tree: bool,

    /// Directory for caching the compiled Jolt guest binary.
    /// Used when --precompiled-elf is not set (local development).
    #[arg(long, default_value = "/tmp/arbor-guest-targets")]
    guest_target_dir: String,

    /// Path to a directory containing pre-compiled guest ELF files.
    ///
    /// When set, the server loads the guest program from pre-built ELF files
    /// instead of invoking the `jolt` CLI at startup. This is the recommended
    /// mode for Docker / production deployments.
    ///
    /// Expected files inside the directory:
    ///   - `guest.elf`          – the main guest ELF
    ///   - `guest-advice.elf`   – the compute-advice variant (optional)
    #[arg(long)]
    precompiled_elf: Option<PathBuf>,

    /// Path to the SQLite proof store database.
    #[arg(long, default_value = "arbor-proofs.db")]
    store_path: String,

    /// Path to the SQLite job store database.
    #[arg(long, default_value = "arbor-jobs.db")]
    job_store_path: String,

    /// Interval in seconds between background worker poll cycles.
    #[arg(long, default_value_t = 2)]
    worker_poll_interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // Validate arguments.
    if !args.create_tree && args.log_id.is_none() {
        return Err("either --log-id or --create-tree must be specified".into());
    }

    // 1. Connect to Trillian.
    info!(
        endpoint = args.trillian_endpoint,
        "connecting to Trillian..."
    );
    let prover = if args.create_tree {
        LogProver::connect_and_create_tree(&args.trillian_endpoint).await?
    } else {
        LogProver::connect(&args.trillian_endpoint, args.log_id.unwrap()).await?
    };
    info!(log_id = prover.log_id(), "connected to Trillian log");

    // 2. Set up Jolt prover + verifier (expensive one-time preprocessing).
    //
    // Two modes:
    //   a) --precompiled-elf <dir>  →  load pre-built ELF files (Docker / prod)
    //   b) default                  →  compile guest via `jolt` CLI (local dev)
    let (jolt_prover, verifier) = if let Some(ref elf_dir) = args.precompiled_elf {
        info!(?elf_dir, "loading pre-compiled guest ELF...");
        build_from_precompiled_elf(elf_dir)?
    } else {
        info!(
            target_dir = args.guest_target_dir,
            "compiling guest program via jolt CLI (this may take a while)..."
        );
        build_from_jolt_compile(&args.guest_target_dir)?
    };
    info!("Jolt prover and verifier ready");

    // 3. Open the proof store.
    info!(path = args.store_path, "opening proof store...");
    let store = SqliteProofStore::open(&args.store_path)
        .map_err(|e| format!("failed to open proof store: {e}"))?;
    info!(count = store.count().unwrap_or(0), "proof store ready");

    // 4. Open the job store.
    info!(path = args.job_store_path, "opening job store...");
    let job_store = SqliteJobStore::open(&args.job_store_path)
        .map_err(|e| format!("failed to open job store: {e}"))?;
    info!("job store ready");

    // 5. Build the gRPC service.
    let service = ArborService::new(prover, verifier, jolt_prover, store, job_store);

    // 6. Spawn the background prover worker.
    let poll_interval = Duration::from_secs(args.worker_poll_interval);
    spawn_prover_worker(&service, poll_interval);

    // 7. Start the gRPC server.
    let addr = args.listen.parse()?;
    info!(%addr, "starting Arbor gRPC server");
    Server::builder()
        .add_service(ArborServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Jolt guest program loading
// ---------------------------------------------------------------------------

/// Type alias for the boxed Jolt prover closure.
type BoxedProverFn = Box<
    dyn Fn(
            guest::AppendInput,
        ) -> (
            guest::AppendOutput,
            jolt_sdk::RV64IMACProof,
            jolt_sdk::JoltDevice,
        ) + Send
        + Sync,
>;

/// Load pre-compiled guest ELF files from `elf_dir` and build the prover +
/// verifier without needing the `jolt` CLI at runtime.
///
/// Expected files:
///   - `<elf_dir>/guest.elf`          – main guest binary
///   - `<elf_dir>/guest-advice.elf`   – compute-advice variant (optional)
fn build_from_precompiled_elf(
    elf_dir: &std::path::Path,
) -> Result<(BoxedProverFn, Verifier), Box<dyn std::error::Error>> {
    let elf_path = elf_dir.join("guest.elf");
    let advice_path = elf_dir.join("guest-advice.elf");

    let elf_bytes = std::fs::read(&elf_path)
        .map_err(|e| format!("failed to read {}: {e}", elf_path.display()))?;
    info!(path = %elf_path.display(), bytes = elf_bytes.len(), "loaded guest ELF");

    let memory_config = guest::memory_config_prove_append();

    let mut program = if advice_path.exists() {
        let advice_bytes = std::fs::read(&advice_path)
            .map_err(|e| format!("failed to read {}: {e}", advice_path.display()))?;
        info!(path = %advice_path.display(), bytes = advice_bytes.len(), "loaded compute-advice ELF");
        jolt_sdk::guest::program::Program::new_with_advice(
            &elf_bytes,
            &advice_bytes,
            &memory_config,
        )
    } else {
        info!("no compute-advice ELF found, proceeding without it");
        jolt_sdk::guest::program::Program::new(&elf_bytes, &memory_config)
    };

    let shared = guest::preprocess_shared_prove_append(&mut program)
        .map_err(|e| format!("shared preprocessing failed: {e}"))?;

    let prover_pp = guest::preprocess_prover_prove_append(shared.clone());

    let verifier_setup = prover_pp.generators.to_verifier_setup();
    let verifier_pp = guest::preprocess_verifier_prove_append(shared, verifier_setup, None);
    let verify_fn = guest::build_verifier_prove_append(verifier_pp);
    let verifier = Verifier::from_verify_fn(verify_fn);

    let jolt_prover: BoxedProverFn = Box::new(guest::build_prover_prove_append(program, prover_pp));

    Ok((jolt_prover, verifier))
}

/// Compile the guest program via the `jolt` CLI and build the prover + verifier.
/// This is the original flow used for local development.
fn build_from_jolt_compile(
    target_dir: &str,
) -> Result<(BoxedProverFn, Verifier), Box<dyn std::error::Error>> {
    let mut program = guest::compile_prove_append(target_dir);

    let shared = guest::preprocess_shared_prove_append(&mut program)
        .map_err(|e| format!("shared preprocessing failed: {e}"))?;

    let prover_pp = guest::preprocess_prover_prove_append(shared.clone());

    let verifier_setup = prover_pp.generators.to_verifier_setup();
    let verifier_pp = guest::preprocess_verifier_prove_append(shared, verifier_setup, None);
    let verify_fn = guest::build_verifier_prove_append(verifier_pp);
    let verifier = Verifier::from_verify_fn(verify_fn);

    let jolt_prover: BoxedProverFn = Box::new(guest::build_prover_prove_append(program, prover_pp));

    Ok((jolt_prover, verifier))
}

// ---------------------------------------------------------------------------
// Background prover worker
// ---------------------------------------------------------------------------

/// Spawn a background tokio task that polls the job store for pending jobs
/// and runs the Jolt prover for each one.
fn spawn_prover_worker(service: &ArborService, poll_interval: Duration) {
    let job_store = Arc::clone(service.job_store());
    let proof_store = Arc::clone(service.proof_store());
    let jolt_prover = Arc::clone(service.jolt_prover());

    info!(?poll_interval, "starting background prover worker");

    tokio::spawn(async move {
        loop {
            match job_store.claim_next_pending() {
                Ok(Some(job_id)) => {
                    info!(job_id = %job_id, "background worker claimed job");
                    process_job(&job_id, &job_store, &proof_store, &jolt_prover).await;
                }
                Ok(None) => {
                    // No pending jobs — sleep and retry.
                }
                Err(e) => {
                    error!(error = %e, "background worker failed to poll job store");
                }
            }
            tokio::time::sleep(poll_interval).await;
        }
    });
}

/// Process a single job: read the input, run the prover, store the proof.
async fn process_job(
    job_id: &str,
    job_store: &Arc<dyn JobStore>,
    proof_store: &Arc<dyn ProofStore>,
    jolt_prover: &Arc<
        dyn Fn(
                guest::AppendInput,
            ) -> (
                guest::AppendOutput,
                jolt_sdk::RV64IMACProof,
                jolt_sdk::JoltDevice,
            ) + Send
            + Sync,
    >,
) {
    // 1. Read the prepared input.
    let input = match job_store.get_job_input(job_id) {
        Ok(input) => input,
        Err(e) => {
            error!(job_id, error = %e, "failed to read job input");
            let _ = job_store.mark_failed(job_id, &format!("failed to read input: {e}"));
            return;
        }
    };

    // 2. Run the Jolt prover (CPU-intensive).
    let jolt_prover = Arc::clone(jolt_prover);
    let input_clone = input.clone();
    let job_id_owned = job_id.to_string();

    let result = tokio::task::spawn_blocking(move || {
        info!(job_id = %job_id_owned, "running Jolt prover...");
        let (output, jolt_proof, _io_device) = jolt_prover(input_clone);
        arbor_host::create_append_proof(input, output, &jolt_proof)
    })
    .await;

    let append_proof = match result {
        Ok(Ok(proof)) => proof,
        Ok(Err(e)) => {
            error!(job_id, error = %e, "proof creation failed");
            let _ = job_store.mark_failed(job_id, &format!("proof creation failed: {e}"));
            return;
        }
        Err(e) => {
            error!(job_id, error = %e, "prover task panicked");
            let _ = job_store.mark_failed(job_id, &format!("prover task panicked: {e}"));
            return;
        }
    };

    // 3. Store the proof.
    if let Err(e) = proof_store.put(&append_proof) {
        error!(job_id, error = %e, "failed to store proof");
        let _ = job_store.mark_failed(job_id, &format!("failed to store proof: {e}"));
        return;
    }

    // 4. Mark the job as completed.
    if let Err(e) = job_store.mark_completed(job_id) {
        error!(job_id, error = %e, "failed to mark job completed");
        return;
    }

    info!(
        job_id,
        old_size = append_proof.output.old_size,
        new_size = append_proof.output.new_size,
        "background worker completed job"
    );
}
