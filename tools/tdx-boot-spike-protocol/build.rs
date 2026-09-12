fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SCHEMA: &str = "proto/boot_spike.proto";
    println!("cargo:rerun-if-changed={SCHEMA}");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_with_config(prost, &[SCHEMA], &["proto"])?;
    Ok(())
}
