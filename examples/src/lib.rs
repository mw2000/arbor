//! Shared helpers for Arbor examples.

use arbor_server::proto::arbor_client::ArborClient;
use tonic::transport::Channel;

/// Default Arbor gRPC endpoint.
///
/// Override by setting the `ARBOR_ENDPOINT` environment variable, e.g.:
///   ARBOR_ENDPOINT=http://[::1]:50051 cargo run --example bank-ledger
pub const DEFAULT_ENDPOINT: &str = "http://localhost:50051";

/// Connect to the Arbor gRPC server.
///
/// Uses `endpoint` if provided, otherwise checks `ARBOR_ENDPOINT` env var,
/// otherwise falls back to [`DEFAULT_ENDPOINT`].
pub async fn connect(
    endpoint: Option<&str>,
) -> Result<ArborClient<Channel>, Box<dyn std::error::Error>> {
    let env_endpoint = std::env::var("ARBOR_ENDPOINT").ok();
    let endpoint = endpoint
        .or(env_endpoint.as_deref())
        .unwrap_or(DEFAULT_ENDPOINT);
    println!("Connecting to Arbor at {endpoint}...");
    let client = ArborClient::connect(endpoint.to_string()).await?;
    println!("Connected.\n");
    Ok(client)
}

/// Queue leaves and print the result.
pub async fn queue_leaves(
    client: &mut ArborClient<Channel>,
    leaves: Vec<Vec<u8>>,
    description: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let count = leaves.len();
    println!("  Appending {count} leaves: {description}");

    let response = client
        .queue_leaves(arbor_server::proto::QueueLeavesRequest { leaves })
        .await?
        .into_inner();

    println!(
        "  Tree state: size={}, root={}",
        response.tree_size,
        hex(&response.root)
    );
    println!();
    Ok(())
}

/// Submit leaves for async proof generation and print the job ID.
pub async fn submit_append(
    client: &mut ArborClient<Channel>,
    leaves: Vec<Vec<u8>>,
    description: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let count = leaves.len();
    println!("  Submitting {count} leaves for proof generation: {description}");

    let response = client
        .submit_append(arbor_server::proto::SubmitAppendRequest { leaves })
        .await?
        .into_inner();

    println!("  Job ID: {}", response.job_id);
    println!();
    Ok(response.job_id)
}

/// Poll a job until it completes or fails.
pub async fn wait_for_job(
    client: &mut ArborClient<Channel>,
    job_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Waiting for job {job_id}...");
    loop {
        let response = client
            .get_job_status(arbor_server::proto::GetJobStatusRequest {
                job_id: job_id.to_string(),
            })
            .await?
            .into_inner();

        match response.status.as_str() {
            "completed" => {
                println!(
                    "  Job completed: old_size={}, new_size={}, proof_bytes={}",
                    response.old_size,
                    response.new_size,
                    response.append_proof.len()
                );
                println!();
                return Ok(());
            }
            "failed" => {
                return Err(format!("Job failed: {}", response.error).into());
            }
            status => {
                print!("  status={status}...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

/// Get and print the current tree state.
pub async fn print_tree_state(
    client: &mut ArborClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .get_tree_state(arbor_server::proto::GetTreeStateRequest {})
        .await?
        .into_inner();

    println!(
        "  Tree state: size={}, root={}",
        response.tree_size,
        hex(&response.root)
    );
    println!();
    Ok(())
}

/// Format bytes as a short hex string.
pub fn hex(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    } else {
        let prefix: String = bytes[..4].iter().map(|b| format!("{b:02x}")).collect();
        let suffix: String = bytes[bytes.len() - 4..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{prefix}...{suffix}")
    }
}
