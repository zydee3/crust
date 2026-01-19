use std::io::Result;

fn main() -> Result<()> {
    // Proto files to compile - add more as needed during implementation
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

    prost_build::compile_protos(&proto_files, &["proto/"])?;

    Ok(())
}
