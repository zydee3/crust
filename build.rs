use std::io::Result;

fn main() -> Result<()> {
    let proto_files = vec![
        "proto/inventory.proto",
        "proto/pstree.proto",
        "proto/core.proto",
        "proto/mm.proto",
        "proto/pagemap.proto",
        "proto/fdinfo.proto",
        "proto/fown.proto",
        "proto/fs.proto",
        "proto/creds.proto",
        "proto/seccomp.proto",
        "proto/timens.proto",
        "proto/tty.proto",
    ];

    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&proto_files, &["proto/"])?;

    Ok(())
}
