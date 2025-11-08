use clap::Parser;
use crust::images::ImageDir;
use crust::restore::fork_with_pid;
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

    // Allocate exact PID for restored process
    let target_pid = checkpoint.pstree.pid as i32;
    log::info!("Target PID: {}", target_pid);
    log::info!("Forking child process with PID {}...", target_pid);

    let fork_result = fork_with_pid(target_pid)?;

    if fork_result == 0 {
        // Child process
        log::debug!("Child process created with PID: {}", std::process::id());

        // Verify PID allocation
        if std::process::id() != target_pid as u32 {
            log::error!("PID mismatch: expected {}, got {}", target_pid, std::process::id());
            std::process::exit(1);
        }

        log::debug!("PID allocation verified");
        std::process::exit(0);
    }

    // Parent process
    log::info!("Forked child with PID {}", fork_result);
    log::debug!("Waiting for child to exit...");

    let mut status = 0;
    unsafe {
        libc::waitpid(fork_result, &mut status, 0);
    }

    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        log::debug!("Child exited with code {}", exit_code);
        if exit_code != 0 {
            return Err(anyhow::anyhow!("Child process failed with exit code {}", exit_code));
        }
    } else {
        return Err(anyhow::anyhow!("Child process terminated abnormally"));
    }

    log::info!("PID control verified successfully");

    Ok(())
}
