use std::io;
#[cfg(feature = "private-service")]
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const PRIVATE_PROTO: &str = "proto/private.proto";
#[cfg(feature = "private-service")]
const COMMITTED_PRIVATE_PROTO: &str = "src/private_proto.rs";
const UPDATE_PRIVATE_PROTO_ENV: &str = "ZAINO_UPDATE_PRIVATE_PROTO";

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={PRIVATE_PROTO}");
    #[cfg(feature = "private-service")]
    println!("cargo:rerun-if-changed={COMMITTED_PRIVATE_PROTO}");
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=RUSTFMT");
    println!("cargo:rerun-if-env-changed={UPDATE_PRIVATE_PROTO_ENV}");

    #[cfg(feature = "private-service")]
    run_private_proto_build()?;

    Ok(())
}

#[cfg(feature = "private-service")]
fn run_private_proto_build() -> io::Result<()> {
    if !Path::new(PRIVATE_PROTO).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "private protobuf schema is missing",
        ));
    }
    if protoc_available() {
        generate_private_proto()
    } else if update_requested() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "explicit private protobuf refresh requires protoc",
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "private-service")]
fn protoc_available() -> bool {
    let protoc = env::var_os("PROTOC").unwrap_or_else(|| "protoc".into());
    Command::new(protoc)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(feature = "private-service")]
fn generate_private_proto() -> io::Result<()> {
    let out: PathBuf = env::var_os("OUT_DIR")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?
        .into();

    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&[PRIVATE_PROTO], &["proto"])?;

    let generated = out.join("zaino.private.v1.rs");
    format_generated(&generated)?;
    if update_requested() {
        copy_generated(&generated, Path::new(COMMITTED_PRIVATE_PROTO))
    } else {
        verify_generated(&generated, Path::new(COMMITTED_PRIVATE_PROTO))
    }
}

#[cfg(feature = "private-service")]
fn update_requested() -> bool {
    matches!(env::var(UPDATE_PRIVATE_PROTO_ENV).as_deref(), Ok("1"))
}

#[cfg(feature = "private-service")]
fn format_generated(generated: &Path) -> io::Result<()> {
    let rustfmt = env::var_os("RUSTFMT").unwrap_or_else(|| "rustfmt".into());
    let status = Command::new(rustfmt)
        .args(["--edition", "2021"])
        .arg(generated)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "rustfmt failed while refreshing the private protobuf source",
        ))
    }
}

#[cfg(feature = "private-service")]
fn copy_generated(source: &Path, destination: &Path) -> io::Result<()> {
    let generated = fs::read(source)?;
    if fs::read(destination).ok().as_deref() == Some(generated.as_slice()) {
        return Ok(());
    }

    fs::write(destination, generated)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(destination)?.permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(destination, permissions)?;
    }
    Ok(())
}

#[cfg(feature = "private-service")]
fn verify_generated(generated: &Path, committed: &Path) -> io::Result<()> {
    if fs::read(generated)? == fs::read(committed)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "committed private protobuf source is stale; regenerate it explicitly",
        ))
    }
}
