use std::ffi::CString;
use std::os::unix::io::RawFd;

use crate::criu::cr_restore::cr_restore_tasks;
use crate::criu::cr_service::{cr_service, cr_service_work};
use crate::criu::kerndat::{kdat_init, KernelData};
use crate::criu::options::{opts, opts_init, CriuMode, CriuOpts};

pub fn open_image_dir(dir: &str, _mode: i32) -> i32 {
    let c_dir = match CString::new(dir) {
        Ok(c) => c,
        Err(_) => {
            log::error!("Invalid directory path");
            return -1;
        }
    };

    let fd = unsafe { libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        log::error!("Can't open dir {}", dir);
        return -1;
    }

    fd
}

pub fn image_dir_mode() -> i32 {
    match opts().mode {
        CriuMode::Restore => libc::O_RDONLY,
        CriuMode::Dump | CriuMode::PreDump => libc::O_RDWR | libc::O_CREAT,
        _ => -1,
    }
}

fn check_caps() -> i32 {
    0
}

fn check_options() -> i32 {
    0
}

fn log_init(output: Option<&str>) -> i32 {
    let _ = output;
    env_logger::init();
    0
}

pub fn criu_main(args: &[String]) -> i32 {
    let ret: i32;
    let usage_error = true;

    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    if args.len() < 2 {
        print_usage(usage_error);
        return 1;
    }

    let default_opts = CriuOpts::default();
    if opts_init(default_opts).is_err() {
        log::error!("Failed to initialize options");
        return 1;
    }

    let cmd = &args[1];
    let mode = parse_mode(cmd);

    if mode == CriuMode::Unset {
        log::error!("unknown command: {}", cmd);
        print_usage(usage_error);
        return 1;
    }

    /*
     * This is to start criu service worker from libcriu calls.
     * The usage is "criu swrk <fd>" and is not for CLI/scripts.
     * The arguments semantics can change at any time with the
     * corresponding lib call change.
     */
    if mode == CriuMode::Swrk {
        if args.len() != 3 {
            eprintln!("Usage: criu swrk <fd>");
            return 1;
        }
        let fd: RawFd = match args[2].parse() {
            Ok(f) => f,
            Err(_) => {
                log::error!("Invalid fd argument");
                return 1;
            }
        };
        return cr_service_work(fd);
    }

    if check_caps() != 0 {
        return 1;
    }

    let imgs_dir = parse_images_dir(&args).unwrap_or_else(|| ".".to_string());
    let work_dir = parse_work_dir(&args).unwrap_or_else(|| imgs_dir.clone());

    if mode != CriuMode::Service {
        let dir_mode = match mode {
            CriuMode::Restore => libc::O_RDONLY,
            CriuMode::Dump | CriuMode::PreDump => libc::O_RDWR | libc::O_CREAT,
            _ => 0,
        };
        let dfd = open_image_dir(&imgs_dir, dir_mode);
        if dfd < 0 {
            log::error!("Couldn't open image dir {}", imgs_dir);
            return 1;
        }

        let c_work_dir = match CString::new(work_dir.as_str()) {
            Ok(c) => c,
            Err(_) => {
                log::error!("Invalid work directory");
                return 1;
            }
        };
        if unsafe { libc::chdir(c_work_dir.as_ptr()) } != 0 {
            log::error!("Can't change directory to {}", work_dir);
            return 1;
        }

        if log_init(None) != 0 {
            return 1;
        }

        let kdat = KernelData::default();
        if kdat_init(kdat).is_err() {
            log::error!("Could not initialize kernel features detection.");
            return 1;
        }

        if check_options() != 0 {
            return 1;
        }

        ret = match mode {
            CriuMode::Restore => cr_restore_tasks(dfd),
            CriuMode::Dump => {
                log::error!("Dump not implemented");
                1
            }
            CriuMode::PreDump => {
                log::error!("PreDump not implemented");
                1
            }
            CriuMode::Check => {
                log::error!("Check not implemented");
                1
            }
            CriuMode::LazyPages => {
                log::error!("LazyPages not implemented");
                1
            }
            CriuMode::PageServer => {
                log::error!("PageServer not implemented");
                1
            }
            CriuMode::Dedup => {
                log::error!("Dedup not implemented");
                1
            }
            CriuMode::CpuinfoDump | CriuMode::CpuinfoCheck => {
                log::error!("Cpuinfo not implemented");
                1
            }
            _ => {
                log::error!("Unknown mode");
                1
            }
        };

        unsafe { libc::close(dfd) };
        return if ret != 0 { 1 } else { 0 };
    }

    let daemon_mode = parse_daemon_mode(&args);
    cr_service(daemon_mode)
}

fn parse_mode(cmd: &str) -> CriuMode {
    match cmd {
        "dump" => CriuMode::Dump,
        "pre-dump" => CriuMode::PreDump,
        "restore" => CriuMode::Restore,
        "check" => CriuMode::Check,
        "page-server" => CriuMode::PageServer,
        "service" => CriuMode::Service,
        "dedup" => CriuMode::Dedup,
        "lazy-pages" => CriuMode::LazyPages,
        "swrk" => CriuMode::Swrk,
        "cpuinfo" => CriuMode::CpuinfoDump,
        _ => CriuMode::Unset,
    }
}

fn parse_images_dir(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "-D" || arg == "--images-dir" {
            if i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
        }
        if let Some(dir) = arg.strip_prefix("--images-dir=") {
            return Some(dir.to_string());
        }
    }
    None
}

fn parse_work_dir(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "-W" || arg == "--work-dir" {
            if i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
        }
        if let Some(dir) = arg.strip_prefix("--work-dir=") {
            return Some(dir.to_string());
        }
    }
    None
}

fn parse_daemon_mode(args: &[String]) -> bool {
    args.iter().any(|a| a == "-d" || a == "--daemon")
}

fn print_usage(error: bool) {
    eprintln!(
        r#"
Usage:
  criu dump|pre-dump -t PID [<options>]
  criu restore [<options>]
  criu check [--feature FEAT]
  criu page-server
  criu service [<options>]
  criu dedup
  criu lazy-pages -D DIR [<options>]

Commands:
  dump           checkpoint a process/tree identified by pid
  pre-dump       pre-dump task(s) minimizing their frozen time
  restore        restore a process/tree
  check          checks whether the kernel support is up-to-date
  page-server    launch page server
  service        launch service
  dedup          remove duplicates in memory dump
  cpuinfo dump   writes cpu information into image file
  cpuinfo check  validates cpu information read from image file"#
    );

    if error {
        eprintln!("\nTry -h|--help for more info");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mode_restore() {
        assert_eq!(parse_mode("restore"), CriuMode::Restore);
    }

    #[test]
    fn test_parse_mode_dump() {
        assert_eq!(parse_mode("dump"), CriuMode::Dump);
    }

    #[test]
    fn test_parse_mode_unknown() {
        assert_eq!(parse_mode("unknown"), CriuMode::Unset);
    }

    #[test]
    fn test_parse_images_dir() {
        let args = vec![
            "criu".to_string(),
            "restore".to_string(),
            "-D".to_string(),
            "/path/to/images".to_string(),
        ];
        assert_eq!(parse_images_dir(&args), Some("/path/to/images".to_string()));
    }

    #[test]
    fn test_parse_images_dir_long() {
        let args = vec![
            "criu".to_string(),
            "restore".to_string(),
            "--images-dir=/path/to/images".to_string(),
        ];
        assert_eq!(parse_images_dir(&args), Some("/path/to/images".to_string()));
    }

    #[test]
    fn test_parse_daemon_mode() {
        let args = vec![
            "criu".to_string(),
            "service".to_string(),
            "-d".to_string(),
        ];
        assert!(parse_daemon_mode(&args));

        let args2 = vec!["criu".to_string(), "service".to_string()];
        assert!(!parse_daemon_mode(&args2));
    }
}
