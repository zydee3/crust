use clap::Parser;
use crust::images::ImageDir;
use crust::restore::{find_bootstrap_gap, inject_restorer_blob};
use crust::restorer_blob::RESTORER_BLOB;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "crust")]
#[command(about = "criu restore in rust", long_about = None)]
struct Args {
    /// Path to the checkpoint image directory
    #[arg(short = 'D', long, value_name = "DIR")]
    image_dir: PathBuf,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Only parse checkpoint without attempting restore
    #[arg(long)]
    parse_only: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    log::info!("Running restore");
    log::info!("Image directory: {}", args.image_dir.display());

    // Load checkpoint
    let img_dir = ImageDir::open(&args.image_dir)?;
    let checkpoint = img_dir.load_checkpoint()?;

    log::info!("Loaded checkpoint for PID {}", checkpoint.pstree.pid);

    // Display checkpoint information
    checkpoint.display()?;

    // If parse-only mode, stop here
    if args.parse_only {
        log::info!("Parse-only mode: skipping restore");
        return Ok(());
    }

    // Find bootstrap region avoiding conflicts with target and current process
    log::info!("Finding bootstrap region...");
    const PAGE_SIZE: usize = 4096;
    const MMAP_MIN_ADDR: usize = 0x10000;  // Typical kernel mmap_min_addr

    // Round up blob size to page size
    let blob_size = RESTORER_BLOB.len();
    let bootstrap_size = (blob_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let target_addr = find_bootstrap_gap(
        &checkpoint.mm.vmas,
        std::process::id(),
        MMAP_MIN_ADDR,
        bootstrap_size,
    )?;

    log::debug!("Found bootstrap address: 0x{:x} (size: {} bytes)", target_addr, bootstrap_size);
    log::debug!("  - Checked against {} target VMAs", checkpoint.mm.vmas.len());
    log::debug!("  - Checked against current process VMAs");

    // Inject restorer blob
    log::info!("Injecting restorer blob.");
    unsafe {
        let entry_point = inject_restorer_blob(target_addr)?;
        log::debug!("Blob injected successfully at 0x{:x}", entry_point);

        // Verify blob contents
        let injected = std::slice::from_raw_parts(
            entry_point as *const u8,
            RESTORER_BLOB.len()
        );

        if injected == RESTORER_BLOB {
            log::debug!("Blob verification: PASSED ({} bytes match)", injected.len());
        } else {
            log::error!("Blob verification: FAILED (contents don't match)");
            return Err(anyhow::anyhow!("Blob verification failed"));
        }

        // Clean up - unmap blob
        log::debug!("Unmapping blob.");
        let _ = crust_syscall::syscalls::munmap(entry_point, 4096);
        log::debug!("Blob unmapped");
    }

    Ok(())
}
