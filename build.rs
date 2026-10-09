use std::{env, path::PathBuf};

const PROTOC: &str = "PROTOC";
const PROTOC_INCLUDE: &str = "PROTOC_INCLUDE";
const PROTO_ROOT: &str = "proto";
const PROTO_FILES: &[&str] = &[
    "proto/arpc.proto",
    "proto/shredstream.proto",
    "proto/shreder.proto",
    "proto/jetstream.proto",
    "proto/geyser.proto",
    "proto/solana-storage.proto",
];

// aRPC v3 shares the `arpc` proto package with `proto/arpc.proto` (the package is
// part of the gRPC method path), so it is generated into its own directory to
// keep both `arpc.rs` outputs apart.
const ARPCV3_PROTO: &str = "proto/arpcv3.proto";
const ARPCV3_OUT_DIR: &str = "arpcv3";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
    println!("cargo:rerun-if-changed=proto");
    let include_dir = ensure_protoc()?;

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let include_dir = include_dir.to_string_lossy().into_owned();
    let includes = [PROTO_ROOT, include_dir.as_str()];

    tonic_prost_build::configure()
        .file_descriptor_set_path(out_dir.join("proto_descriptors.bin"))
        .compile_protos(PROTO_FILES, &includes)?;

    let arpcv3_out_dir = out_dir.join(ARPCV3_OUT_DIR);
    std::fs::create_dir_all(&arpcv3_out_dir)?;
    tonic_prost_build::configure()
        .out_dir(arpcv3_out_dir)
        .compile_protos(&[ARPCV3_PROTO], &includes)?;

    Ok(())
}

fn ensure_protoc() -> core::result::Result<PathBuf, protoc_bin_vendored::Error> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let include_path = protoc_bin_vendored::include_path()?;

    unsafe {
        env::set_var(PROTOC, &protoc);
        env::set_var(PROTOC_INCLUDE, &include_path);
    }

    Ok(include_path)
}
