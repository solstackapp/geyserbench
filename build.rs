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
