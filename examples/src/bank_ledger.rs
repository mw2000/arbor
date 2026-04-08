//! Bank Ledger — tamper-evident financial transaction log.
//!
//! Demonstrates appending financial transactions to Arbor and generating a
//! ZK proof that the ledger was extended correctly. An auditor can verify
//! the proof without access to the server or the raw transactions.
//!
//! # Prerequisites
//!
//! 1. Start Trillian: `cd examples && docker compose up -d`
//! 2. Start Arbor:    `cargo run -p arbor-service -- --trillian-endpoint http://localhost:8090 --create-tree`
//!
//! # Run
//!
//! ```sh
//! cargo run --example bank-ledger
//! ```

use serde::Serialize;

#[derive(Serialize)]
struct Transaction {
    tx_id: &'static str,
    timestamp: &'static str,
    from_account: &'static str,
    to_account: &'static str,
    amount_cents: u64,
    currency: &'static str,
    #[serde(rename = "type")]
    tx_type: &'static str,
    memo: &'static str,
}

fn make_leaf(tx: &Transaction) -> Vec<u8> {
    serde_json::to_vec(tx).expect("serialization cannot fail")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bank Ledger Example ===\n");

    let mut client = arbor_examples::connect(None).await?;

    // -- Phase 1: Queue an initial batch of transactions ----------------------
    println!("Phase 1: Appending initial transactions\n");

    let transactions = vec![
        Transaction {
            tx_id: "TXN-2025-00001",
            timestamp: "2025-04-07T09:00:00Z",
            from_account: "ACCT-1001",
            to_account: "ACCT-2044",
            amount_cents: 150_000,
            currency: "USD",
            tx_type: "wire_transfer",
            memo: "Invoice #1028 payment",
        },
        Transaction {
            tx_id: "TXN-2025-00002",
            timestamp: "2025-04-07T09:05:00Z",
            from_account: "EXTERNAL",
            to_account: "ACCT-1001",
            amount_cents: 500_000,
            currency: "USD",
            tx_type: "deposit",
            memo: "Payroll deposit",
        },
        Transaction {
            tx_id: "TXN-2025-00003",
            timestamp: "2025-04-07T09:10:00Z",
            from_account: "ACCT-3077",
            to_account: "ACCT-3077-SAVINGS",
            amount_cents: 25_000,
            currency: "USD",
            tx_type: "internal_transfer",
            memo: "Monthly savings",
        },
    ];

    let leaves: Vec<Vec<u8>> = transactions.iter().map(make_leaf).collect();
    arbor_examples::queue_leaves(&mut client, leaves, "3 bank transactions").await?;

    // -- Phase 2: Submit a new transaction with async proof generation ---------
    println!("Phase 2: Submitting transaction with ZK proof generation\n");

    let new_tx = Transaction {
        tx_id: "TXN-2025-00004",
        timestamp: "2025-04-07T10:30:00Z",
        from_account: "ACCT-2044",
        to_account: "ACCT-5500",
        amount_cents: 75_000,
        currency: "USD",
        tx_type: "wire_transfer",
        memo: "Vendor payment - Q2 supplies",
    };

    let job_id =
        arbor_examples::submit_append(&mut client, vec![make_leaf(&new_tx)], "wire transfer")
            .await?;
    arbor_examples::wait_for_job(&mut client, &job_id).await?;

    // -- Phase 3: Check final tree state --------------------------------------
    println!("Phase 3: Final ledger state\n");
    arbor_examples::print_tree_state(&mut client).await?;

    println!("An auditor can now verify the ZK proof to confirm the ledger");
    println!("grew from 3 to 4 transactions without any tampering.\n");

    Ok(())
}
