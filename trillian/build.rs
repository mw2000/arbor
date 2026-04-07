fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(
        &[
            "proto/trillian.proto",
            "proto/trillian_log_api.proto",
            "proto/trillian_admin_api.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
