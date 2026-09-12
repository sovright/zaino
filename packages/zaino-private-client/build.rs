fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SCHEMA: &str = "../zainod-oram/proto/private.proto";
    println!("cargo:rerun-if-changed={SCHEMA}");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_with_config(prost, &[SCHEMA], &["../zainod-oram/proto"])?;
    Ok(())
}
