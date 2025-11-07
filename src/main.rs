use clap::Parser;
use crust::images::ImageDir;
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
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    log::info!("crust - CRIU restore in Rust");
    log::info!("Image directory: {}", args.image_dir.display());

    // Load CRIU checkpoint
    let img_dir = ImageDir::open(&args.image_dir)?;
    let checkpoint = img_dir.load_checkpoint()?;

    log::info!("Loaded checkpoint for PID {}", checkpoint.pstree.pid);

    // Display checkpoint information
    checkpoint.display()?;

    Ok(())
}
