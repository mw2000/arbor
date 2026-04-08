//! Arbor gRPC server binary.
//!
//! Connects to a Trillian log backend and exposes the Arbor service over gRPC.
//!
//! # Usage
//!
//! ```sh
//! # Connect to an existing Trillian log tree:
//! arbor-server --trillian-endpoint http://localhost:8090 --log-id 123456
//!
//! # Create a new Trillian log tree on startup:
//! arbor-server --trillian-endpoint http://localhost:8090 --create-tree
//! ```

use arbor_host::LogProver;
use arbor_server::proto::arbor_server::ArborServer;
use arbor_server::ArborService;
use arbor_verify::Verifier;
use clap::Parser;
use tonic::transport::Server;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "arbor-server", about = "Arbor transparency log gRPC server")]
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
    #[arg(long, default_value = "/tmp/arbor-guest-targets")]
    guest_target_dir: String,
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
    info!(
        target_dir = args.guest_target_dir,
        "compiling guest program and running Jolt preprocessing (this may take a while)..."
    );

    let mut program = guest::compile_prove_append(&args.guest_target_dir);
    let shared = guest::preprocess_shared_prove_append(&mut program)
        .map_err(|e| format!("shared preprocessing failed: {e}"))?;

    // Prover setup.
    let prover_pp = guest::preprocess_prover_prove_append(shared.clone());

    // Verifier setup (needs prover generators).
    let verifier_setup = prover_pp.generators.to_verifier_setup();
    let verifier_pp =
        guest::preprocess_verifier_prove_append(shared, verifier_setup, None);

    let verify_fn = guest::build_verifier_prove_append(verifier_pp);
    let verifier = Verifier::from_verify_fn(verify_fn);

    // Build the prover closure.
    let jolt_prover = guest::build_prover_prove_append(program, prover_pp);
    info!("Jolt prover and verifier ready");

    // 3. Build the gRPC service.
    let service = ArborService::new(prover, verifier, jolt_prover);
    let addr = args.listen.parse()?;

    info!(%addr, "starting Arbor gRPC server");
    Server::builder()
        .add_service(ArborServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
