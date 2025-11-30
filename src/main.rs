use clap::Parser;
use crust::images::ImageDir;
use crust::restore::{fork_with_pid, kill_pid_if_exists};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

// Global start time for dmesg-style logging
static START_TIME: OnceLock<Instant> = OnceLock::new();

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

    /// Kill existing process with target PID before restore
    #[arg(long)]
    kill_old_pid: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set restore start time for dmesg-style logging
    START_TIME.get_or_init(|| Instant::now());

    // Initialize logging with dmesg-style timestamps
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format(|buf, record| {
            use std::io::Write;

            // Calculate elapsed time since restore start
            let elapsed = START_TIME.get().unwrap().elapsed();
            let secs = elapsed.as_secs();
            let micros = elapsed.subsec_micros();

            // Format like dmesg: [  123.456789] LEVEL message
            writeln!(
                buf,
                "[{:5}.{:06}] {} {}",
                secs,
                micros,
                record.level(),
                record.args()
            )
        })
        .init();

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

    // Parent process: Create premap layout before fork
    // All memory mappings will be inherited by child via fork's COW
    let target_pid = checkpoint.pstree.pid as i32;
    log::info!("Target PID: {}", target_pid);

    // Check if target PID exists and kill if requested
    kill_pid_if_exists(target_pid, args.kill_old_pid)?;

    let mut premap = unsafe {
        crust::restore::PremapLayout::create_and_map(&checkpoint, std::process::id())?
    };

    log::info!("Premap layout created: {} VMAs, blob at 0x{:x}, bootstrap at 0x{:x}",
               premap.vma_count(), premap.blob_addr, premap.bootstrap_addr);

    // Verify parent has premap regions before fork
    log::info!("Checking parent's premap regions before fork...");
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let premap_count = maps.lines()
            .filter(|l| l.starts_with("01"))
            .count();
        log::info!("Parent has {} premap VMAs starting with '01'", premap_count);

        if premap_count == 0 {
            log::error!("No premap VMAs in parent before fork");
            log::error!("Parent /proc/self/maps:\n{}", maps);
        } else {
            log::info!("Parent premap VMAs verified before fork");
            // Show first few premap lines for confirmation
            for line in maps.lines().filter(|l| l.starts_with("01")).take(3) {
                log::debug!("  {}", line);
            }
        }
    }

    // Fork child process with target PID - child inherits all mappings
    log::info!("Forking child process with PID {}...", target_pid);
    let fork_result = fork_with_pid(target_pid)?;

    if fork_result == 0 {
        // Child process: all mappings already present (inherited via fork)
        let child_pid = std::process::id();
        log::info!("Child process running with PID: {}", child_pid);

        // Verify child inherited premap regions from parent
        log::info!("Checking child's inherited premap regions...");
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            let premap_count = maps.lines()
                .filter(|l| l.starts_with("01"))
                .count();
            log::info!("Child has {} premap VMAs starting with '01'", premap_count);

            if premap_count == 0 {
                log::error!("Premap VMAs were not inherited by child");
                log::error!("Child /proc/self/maps:\n{}", maps);
            } else {
                log::info!("Child premap VMAs inherited successfully");
                // Show first few premap lines for confirmation
                for line in maps.lines().filter(|l| l.starts_with("01")).take(3) {
                    log::debug!("  {}", line);
                }
            }
        }

        // Make child independent from parent's session
        // This allows the child to continue running after parent exits
        unsafe {
            let sid = libc::setsid();
            if sid < 0 {
                log::error!("setsid() failed: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            log::info!("Child created new session (SID: {})", sid);
        }

        // Verify PID allocation
        if child_pid != target_pid as u32 {
            log::error!("PID mismatch: expected {}, got {}", target_pid, child_pid);
            std::process::exit(1);
        }

        log::info!("PID allocation verified - {} VMAs inherited from parent", premap.vma_count());

        // Wait for parent to attach with ptrace and inject blob
        // Parent will use PTRACE_SEIZE + PTRACE_INTERRUPT to stop us
        log::debug!("Child ready for blob injection, entering infinite loop");

        // Use a simple spin loop with volatile read to prevent optimization
        // This ensures we stop at a clean instruction boundary when interrupted
        let counter: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        loop {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Parent will interrupt us here and change RIP to blob
        }

        // Control will transfer to restorer blob when parent sets RIP
        // This point should never be reached
    }

    // Parent process: child is running in pause() loop, ready for injection
    log::info!("Forked child with PID {}", fork_result);

    // Mark layout as transferred to child (prevents Drop cleanup)
    premap.mark_transferred();

    // Child is now running in pause() loop waiting for ptrace
    // execute_restorer_blob will use PTRACE_SEIZE + PTRACE_INTERRUPT to stop it
    log::debug!("Child running in pause loop, ready for blob injection");

    // Execute blob in child process using premap layout
    unsafe {
        crust::restore::execute_restorer_blob(fork_result, &premap, &checkpoint)?;
    }

    log::info!("Restorer blob execution complete");

    Ok(())
}
