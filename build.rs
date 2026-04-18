fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()
        .expect("vendored protoc binary not found");
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(false) // Rust side is client-only; server lives in Python sidecar
        .compile_protos(
            &["proto/anonymizer.proto", "proto/health.proto"],
            &["proto"],
        )?;
    Ok(())
}
