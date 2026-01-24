use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

use crate::criu::util::{cr_fchperm, mkdirpat};
use crate::proto::{CgControllerEntry, CgroupDirEntry, CgroupPerms, CgroupPropEntry};

pub const CG_MODE_IGNORE: u32 = 0;
pub const CG_MODE_NONE: u32 = 1 << 0;
pub const CG_MODE_PROPS: u32 = 1 << 1;
pub const CG_MODE_SOFT: u32 = 1 << 2;
pub const CG_MODE_FULL: u32 = 1 << 3;
pub const CG_MODE_STRICT: u32 = 1 << 4;
pub const CG_MODE_DEFAULT: u32 = CG_MODE_SOFT;

const PATH_MAX: usize = 4096;

struct FreezerState {
    entry: Option<CgroupPropEntry>,
    path: [u8; PATH_MAX],
    path_len: usize,
}

static FREEZER_STATE: Mutex<FreezerState> = Mutex::new(FreezerState {
    entry: None,
    path: [0; PATH_MAX],
    path_len: 0,
});

pub fn add_freezer_state_for_restore(entry: &CgroupPropEntry, path: &[u8]) {
    let path_len = path.len();
    assert!(path_len < PATH_MAX, "BUG: path_len >= sizeof(freezer_path)");

    let mut state = FREEZER_STATE.lock().unwrap();

    if state.entry.is_some() {
        let max_len = std::cmp::min(state.path_len, path_len);

        // If there are multiple freezer.state properties, that means they had
        // one common path prefix with no tasks in it. Let's find that common
        // prefix.
        for i in 0..max_len {
            if state.path[i] != path[i] {
                state.path[i] = 0;
                state.path_len = i;
                return;
            }
        }
        if path_len < state.path_len {
            state.path_len = path_len;
        }
    } else {
        state.entry = Some(entry.clone());
        // Path is not null terminated at path_len
        state.path[..path_len].copy_from_slice(path);
        state.path[path_len] = 0;
        state.path_len = path_len;
    }
}

pub fn get_freezer_state_entry() -> Option<CgroupPropEntry> {
    FREEZER_STATE.lock().unwrap().entry.clone()
}

pub fn get_freezer_path() -> Vec<u8> {
    let state = FREEZER_STATE.lock().unwrap();
    state.path[..state.path_len].to_vec()
}

const SPECIAL_PROPS: &[&str] = &[
    "cpuset.cpus",
    "cpuset.mems",
    "devices.list",
    "memory.kmem.limit_in_bytes",
    "memory.swappiness",
    "memory.oom_control",
    "memory.use_hierarchy",
    "cgroup.type",
];

pub fn add_subtree_control_prop_prefix(input: &[u8], output: &mut [u8], prefix: u8) -> usize {
    let mut off = 0;
    let mut current = 0;

    loop {
        let next = input[current..]
            .iter()
            .position(|&c| c == b' ')
            .map(|p| current + p)
            .unwrap_or(input.len());

        let len = next - current;

        output[off] = prefix;
        off += 1;
        output[off..off + len].copy_from_slice(&input[current..next]);
        off += len;
        output[off] = b' ';
        off += 1;

        if next >= input.len() {
            break;
        }
        current = next + 1;
    }

    off
}

pub fn restore_cgroup_subtree_control(cg_prop_entry: &CgroupPropEntry, fd: RawFd) -> io::Result<()> {
    let mut buf = [0u8; 1024];
    let mut line = [0u8; 1024];

    let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() - 1) };
    if ret < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            "read from cgroup.subtree_control",
        ));
    }

    let read_len = ret as usize;
    // Remove the trailing newline
    buf[read_len] = 0;

    let mut off = 0;

    // Remove all current subsys in subtree_control
    if read_len > 0 && buf[0] != 0 {
        let content_len = buf[..read_len]
            .iter()
            .position(|&c| c == b'\n' || c == 0)
            .unwrap_or(read_len);
        if content_len > 0 {
            off = add_subtree_control_prop_prefix(&buf[..content_len], &mut line, b'-');
        }
    }

    // Add subsys need to be restored in subtree_control
    let value = cg_prop_entry.value.as_bytes();
    if !value.is_empty() && value[0] != 0 {
        off += add_subtree_control_prop_prefix(value, &mut line[off..], b'+');
    }

    // Remove the trailing space
    if off > 0 {
        off -= 1;
        line[off] = 0;
    }

    if off > 0 {
        let written = unsafe { libc::write(fd, line.as_ptr() as *const libc::c_void, off) };
        if written != off as isize {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                "write to cgroup.subtree_control",
            ));
        }
    }

    Ok(())
}

pub fn restore_cgroup_prop(
    cg_prop_entry: &CgroupPropEntry,
    path: &mut [u8],
    off: usize,
    split_lines: bool,
    skip_fails: bool,
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    if manage_cgroups == CG_MODE_IGNORE {
        return Ok(());
    }

    if cg_prop_entry.value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cg_prop_entry->value was empty when should have had a value",
        ));
    }

    let is_subtree_control = cg_prop_entry.name == "cgroup.subtree_control";

    let name_with_slash = format!("/{}", cg_prop_entry.name);
    let name_bytes = name_with_slash.as_bytes();
    if off + name_bytes.len() >= PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("snprintf output was truncated for {}", cg_prop_entry.name),
        ));
    }
    path[off..off + name_bytes.len()].copy_from_slice(name_bytes);
    path[off + name_bytes.len()] = 0;

    let flag = if is_subtree_control {
        libc::O_RDWR
    } else {
        libc::O_WRONLY
    };

    let c_path = CString::new(&path[..off + name_bytes.len()])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;

    let fd = unsafe { libc::openat(cgroup_yard_fd, c_path.as_ptr(), flag) };
    if fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("bad cgroup path: {}", cg_prop_entry.name),
        ));
    }

    let result = restore_cgroup_prop_inner(
        cg_prop_entry,
        fd,
        is_subtree_control,
        split_lines,
        skip_fails,
    );

    if unsafe { libc::close(fd) } != 0 {
        // Log but don't fail
    }

    result
}

fn restore_cgroup_prop_inner(
    cg_prop_entry: &CgroupPropEntry,
    fd: RawFd,
    is_subtree_control: bool,
    split_lines: bool,
    skip_fails: bool,
) -> io::Result<()> {
    if let Some(ref perms) = cg_prop_entry.perms {
        cr_fchperm(fd, perms.uid, perms.gid, perms.mode)?;
    }

    // skip these two since restoring their values doesn't make sense
    if cg_prop_entry.name == "cgroup.procs" || cg_prop_entry.name == "tasks" {
        return Ok(());
    }

    if is_subtree_control {
        return restore_cgroup_subtree_control(cg_prop_entry, fd);
    }

    // skip restoring cgroup.type if its value is not "threaded"
    if cg_prop_entry.name == "cgroup.type" && cg_prop_entry.value != "threaded" {
        return Ok(());
    }

    if split_lines {
        let value = cg_prop_entry.value.as_bytes();
        let mut start = 0;

        loop {
            let end = value[start..]
                .iter()
                .position(|&c| c == b'\n')
                .map(|p| start + p)
                .unwrap_or(value.len());

            let line = &value[start..end];
            let written = unsafe { libc::write(fd, line.as_ptr() as *const libc::c_void, line.len()) };

            if written != line.len() as isize {
                if !skip_fails {
                    return Err(io::Error::new(
                        io::Error::last_os_error().kind(),
                        format!("Failed writing {} to cgroup", cg_prop_entry.name),
                    ));
                }
            }

            if end >= value.len() {
                break;
            }
            start = end + 1;
        }
    } else {
        let value = cg_prop_entry.value.as_bytes();
        let mut ret =
            unsafe { libc::write(fd, value.as_ptr() as *const libc::c_void, value.len()) };

        // memory.kmem.limit_in_bytes has been deprecated. Look at
        // 58056f77502f3 ("memcg, kmem: further deprecate
        // kmem.limit_in_bytes") for more details.
        if ret == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::EOPNOTSUPP)
            && cg_prop_entry.name == "memory.kmem.limit_in_bytes"
        {
            ret = value.len() as isize;
        }

        if ret != value.len() as isize {
            if !skip_fails {
                return Err(io::Error::new(
                    io::Error::last_os_error().kind(),
                    format!("Failed writing {} to cgroup", cg_prop_entry.name),
                ));
            }
        }
    }

    Ok(())
}

pub fn is_special_property(prop: &str) -> bool {
    SPECIAL_PROPS.iter().any(|&p| p == prop)
}

pub fn cgroup_contains(controllers: &[&str], name: &str, mut mask: Option<&mut u64>) -> bool {
    let n_controllers = controllers.len();

    // Check whether this is cgroup2 or not
    // For cgroup2, n_controllers == 1 and controllers[0] is empty
    if n_controllers == 1 && controllers[0].is_empty() {
        let is_match = name.is_empty();
        if let Some(m) = mask {
            if is_match {
                *m &= !1u64;
            }
        }
        return is_match;
    }

    let mut all_match = true;

    for (i, controller) in controllers.iter().enumerate() {
        let mut found = false;
        let mut loc = name;

        while let Some(pos) = loc.find(controller) {
            let after_match = pos + controller.len();
            loc = &loc[after_match..];

            // Check if this is a complete match (followed by end or comma)
            let next_char = loc.chars().next();
            match next_char {
                None | Some(',') => {
                    found = true;
                    if let Some(ref mut m) = mask {
                        **m &= !(1u64 << i);
                    }
                    break;
                }
                _ => {
                    // Not a complete match, continue searching
                }
            }
        }

        all_match &= found;
    }

    all_match && n_controllers > 0
}

pub fn filter_ifpriomap(line: &str) -> Result<String, &'static str> {
    if line.is_empty() {
        return Ok(String::new());
    }

    let mut result = Vec::new();

    for entry in line.lines() {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }

        let space_pos = trimmed.find(' ');
        let space_pos = match space_pos {
            Some(pos) => pos,
            None => return Err("Invalid value for ifpriomap"),
        };

        let priority_str = &trimmed[space_pos + 1..];
        let priority: i64 = priority_str.trim().parse().unwrap_or(0);

        if priority == 0 {
            continue;
        }

        result.push(trimmed);
    }

    Ok(result.join("\n"))
}

pub fn restore_special_property(
    pr: &mut CgroupPropEntry,
    path: &mut [u8],
    off: usize,
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    // XXX: we can drop this hack and make memory.swappiness and
    // memory.oom_control regular properties when we drop support for
    // kernels < 3.16. See 3dae7fec5.
    if pr.name == "memory.swappiness" && pr.value == "60" {
        return Ok(());
    }
    if pr.name == "memory.oom_control" && pr.value == "0" {
        return Ok(());
    }

    if pr.name == "devices.list" {
        // A bit of a fudge here. These are write only by owner
        // by default, but the container engine could have changed
        // the perms. We should come up with a better way to
        // restore all of this stuff.
        if let Some(ref mut perms) = pr.perms {
            perms.mode = 0o200;
        }
        return restore_devices_list(pr, path, off, manage_cgroups, cgroup_yard_fd);
    }

    restore_cgroup_prop(pr, path, off, false, false, manage_cgroups, cgroup_yard_fd)
}

pub fn ctrl_dir_and_opt(ctl: &CgControllerEntry) -> (String, String) {
    let mut dir_parts = Vec::new();
    let mut opt_parts = Vec::new();
    let mut none_opt = false;

    for cname in &ctl.cnames {
        let mut n = cname.as_str();

        if n.starts_with("name=") {
            n = &n[5..];
            if !none_opt {
                opt_parts.push("none".to_string());
                none_opt = true;
            }
        }

        if n.is_empty() {
            dir_parts.push("unified".to_string());
        } else {
            dir_parts.push(n.to_string());
        }
        opt_parts.push(cname.clone());
    }

    (dir_parts.join(","), opt_parts.join(","))
}

pub fn prepare_dir_perms(
    cgroup_yard_fd: RawFd,
    path: &str,
    perms: Option<&CgroupPerms>,
) -> io::Result<()> {
    let c_path = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;

    let fd = unsafe { libc::openat(cgroup_yard_fd, c_path.as_ptr(), libc::O_DIRECTORY) };
    if fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("failed to open cg dir fd ({}) for chowning", path),
        ));
    }

    let result = if let Some(p) = perms {
        cr_fchperm(fd, p.uid, p.gid, p.mode)
    } else {
        Ok(())
    };

    unsafe { libc::close(fd) };
    result
}

pub fn restore_special_props(
    path: &mut [u8],
    off: usize,
    dir_entry: &CgroupDirEntry,
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    for prop in &dir_entry.properties {
        if !is_special_property(&prop.name) {
            continue;
        }

        let mut prop_copy = prop.clone();
        restore_special_property(&mut prop_copy, path, off, manage_cgroups, cgroup_yard_fd)?;
    }

    Ok(())
}

pub fn restore_cgroup_ifpriomap(
    cg_prop_entry: &CgroupPropEntry,
    path: &mut [u8],
    off: usize,
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    let filtered_value = filter_ifpriomap(&cg_prop_entry.value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    if filtered_value.is_empty() {
        return Ok(());
    }

    let mut priomap = cg_prop_entry.clone();
    priomap.value = filtered_value;

    restore_cgroup_prop(&priomap, path, off, true, true, manage_cgroups, cgroup_yard_fd)
}

pub fn restore_devices_list(
    pr: &CgroupPropEntry,
    path: &mut [u8],
    off: usize,
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    let mut dev_deny = pr.clone();
    dev_deny.name = "devices.deny".to_string();
    dev_deny.value = "a".to_string();

    let mut dev_allow = pr.clone();
    dev_allow.name = "devices.allow".to_string();

    restore_cgroup_prop(&dev_deny, path, off, false, false, manage_cgroups, cgroup_yard_fd)?;

    /*
     * An empty string here means nothing is allowed,
     * and the kernel disallows writing an "" to devices.allow,
     * so let's just keep going.
     */
    if dev_allow.value.is_empty() {
        return Ok(());
    }

    restore_cgroup_prop(&dev_allow, path, off, true, false, manage_cgroups, cgroup_yard_fd)
}

pub fn prepare_cgroup_dir_properties(
    path: &mut [u8],
    off: usize,
    ents: &[CgroupDirEntry],
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    for e in ents {
        let mut off2 = off;

        if e.dir_name.is_empty() {
            // skip root cgroups
            prepare_cgroup_dir_properties(path, off2, &e.children, manage_cgroups, cgroup_yard_fd)?;
            continue;
        }

        let dir_component = format!("/{}", e.dir_name);
        let dir_bytes = dir_component.as_bytes();
        if off + dir_bytes.len() >= PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path too long in prepare_cgroup_dir_properties",
            ));
        }
        path[off..off + dir_bytes.len()].copy_from_slice(dir_bytes);
        off2 += dir_bytes.len();
        path[off2] = 0;

        for p in &e.properties {
            if p.name == "freezer.state" {
                add_freezer_state_for_restore(p, &path[..off2]);
                continue; // Skip restore now
            }

            // Skip restoring special cpuset props now.
            // They were restored earlier, and can cause
            // the restore to fail if some other task has
            // entered the cgroup.
            if is_special_property(&p.name) {
                continue;
            }

            // The kernel can't handle it in one write()
            // Number of network interfaces on host may differ.
            if p.name == "net_prio.ifpriomap" {
                restore_cgroup_ifpriomap(p, path, off2, manage_cgroups, cgroup_yard_fd)?;
                continue;
            }

            restore_cgroup_prop(p, path, off2, false, false, manage_cgroups, cgroup_yard_fd)?;
        }

        prepare_cgroup_dir_properties(path, off2, &e.children, manage_cgroups, cgroup_yard_fd)?;
    }

    Ok(())
}

pub fn prepare_cgroup_dirs(
    controllers: &[String],
    path: &mut [u8],
    off: usize,
    ents: &mut [CgroupDirEntry],
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    for e in ents.iter_mut() {
        let mut off2 = off;

        let dir_component = format!("/{}", e.dir_name);
        let dir_bytes = dir_component.as_bytes();
        if off + dir_bytes.len() >= PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path too long in prepare_cgroup_dirs",
            ));
        }
        path[off..off + dir_bytes.len()].copy_from_slice(dir_bytes);
        off2 += dir_bytes.len();
        path[off2] = 0;

        let path_str = std::str::from_utf8(&path[..off2])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid utf8 in path"))?;
        let c_path = CString::new(path_str)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;

        let access_ret = unsafe { libc::faccessat(cgroup_yard_fd, c_path.as_ptr(), libc::F_OK, 0) };

        if access_ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(io::Error::new(
                    err.kind(),
                    format!("Failed accessing cgroup dir {}", path_str),
                ));
            }

            if (manage_cgroups & (CG_MODE_NONE | CG_MODE_PROPS)) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Cgroup dir {} doesn't exist", path_str),
                ));
            }

            mkdirpat(cgroup_yard_fd, path_str, 0o755)?;

            if let Some(ref perms) = e.dir_perms {
                prepare_dir_perms(cgroup_yard_fd, path_str, Some(perms))?;
            }

            for _ in controllers {
                restore_special_props(path, off2, e, manage_cgroups, cgroup_yard_fd)?;
            }
        } else {
            if (manage_cgroups & CG_MODE_STRICT) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Abort restore of existing cgroups",
                ));
            }

            if (manage_cgroups & (CG_MODE_SOFT | CG_MODE_NONE)) != 0 {
                e.properties.clear();
            }

            if (manage_cgroups & CG_MODE_NONE) == 0 {
                if let Some(ref perms) = e.dir_perms {
                    prepare_dir_perms(cgroup_yard_fd, path_str, Some(perms))?;
                }
            }
        }

        prepare_cgroup_dirs(controllers, path, off2, &mut e.children, manage_cgroups, cgroup_yard_fd)?;
    }

    Ok(())
}

pub fn prepare_cgroup_properties(
    controllers: &[CgControllerEntry],
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    let mut cname_path = [0u8; PATH_MAX];

    for c in controllers {
        if c.cnames.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Each CgControllerEntry should have at least 1 cname",
            ));
        }

        let (dir_name, _opt) = ctrl_dir_and_opt(c);
        let dir_bytes = dir_name.as_bytes();
        if dir_bytes.len() >= PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "controller dir name too long",
            ));
        }
        cname_path[..dir_bytes.len()].copy_from_slice(dir_bytes);
        cname_path[dir_bytes.len()] = 0;
        let off = dir_bytes.len();

        prepare_cgroup_dir_properties(
            &mut cname_path,
            off,
            &c.dirs,
            manage_cgroups,
            cgroup_yard_fd,
        )?;
    }

    Ok(())
}

use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::namespaces::{start_unix_cred_daemon, unsc_msg_init, unsc_msg_pid_fd, UnscMsg};
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::servicefd::{ServiceFdState, SfdType};
use crate::criu::util::make_yard;
use crate::proto::{CgSetEntry, CgroupEntry};

use std::sync::atomic::{AtomicI32, Ordering};

static mut CG_YARD: Option<String> = None;

// Cgroup restore state globals
static mut RST_SETS: Option<Vec<CgSetEntry>> = None;
static mut CONTROLLERS: Option<Vec<CgControllerEntry>> = None;
static CGROUPD_PID: AtomicI32 = AtomicI32::new(0);

fn get_cgroupd_pid() -> libc::pid_t {
    CGROUPD_PID.load(Ordering::SeqCst)
}

fn set_cgroupd_pid(pid: libc::pid_t) {
    CGROUPD_PID.store(pid, Ordering::SeqCst);
}

pub fn get_rst_sets() -> &'static [CgSetEntry] {
    unsafe { RST_SETS.as_ref().map(|v| v.as_slice()).unwrap_or(&[]) }
}

pub fn get_controllers() -> &'static [CgControllerEntry] {
    unsafe { CONTROLLERS.as_ref().map(|v| v.as_slice()).unwrap_or(&[]) }
}

fn set_rst_sets(sets: Vec<CgSetEntry>) {
    unsafe { RST_SETS = Some(sets) };
}

fn set_controllers(controllers: Vec<CgControllerEntry>) {
    unsafe { CONTROLLERS = Some(controllers) };
}

/// Finds a CgSetEntry by its ID
pub fn find_rst_set_by_id(id: u32) -> Option<&'static CgSetEntry> {
    get_rst_sets().iter().find(|s| s.id == id)
}

static ROOT_CG_SET: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

pub fn set_root_cg_set(set: u32) {
    ROOT_CG_SET.store(set, std::sync::atomic::Ordering::Relaxed);
}

pub fn root_cg_set() -> u32 {
    ROOT_CG_SET.load(std::sync::atomic::Ordering::Relaxed)
}

/// Moves the current process into the specified cgroup set
fn move_in_cgroup(se: &CgSetEntry, cgroup_yard_fd: RawFd) -> i32 {
    log::info!("Move into {}", se.id);

    let controllers = get_controllers();
    let pid = unsafe { libc::getpid() };

    for ce in &se.ctls {
        let mut ctrl: Option<&CgControllerEntry> = None;

        for c in controllers {
            let cnames: Vec<&str> = c.cnames.iter().map(|s| s.as_str()).collect();
            if cgroup_contains(&cnames, &ce.name, None) {
                ctrl = Some(c);
                break;
            }
        }

        let ctrl = match ctrl {
            Some(c) => c,
            None => {
                log::error!(
                    "No cg_controller_entry found for {}/{}",
                    ce.name,
                    ce.path
                );
                return -1;
            }
        };

        let (dir_name, _opt) = ctrl_dir_and_opt(ctrl);
        let path = format!("{}/{}/cgroup.procs", dir_name, ce.path);
        log::debug!("  `-> {}", path);

        if userns_move(&path, -1, pid, cgroup_yard_fd).is_err() {
            log::error!("Can't move into {}", path);
            return -1;
        }
    }

    0
}

/// Restores a task's cgroup membership
/// Maps to: criu/cgroup.c restore_task_cgroup
pub fn restore_task_cgroup(
    manage_cgroups: u32,
    cg_set: u32,
    parent_cg_set: Option<u32>,
    cgroup_yard_fd: RawFd,
) -> i32 {
    if manage_cgroups == CG_MODE_IGNORE {
        return 0;
    }

    if cg_set == 0 {
        return 0;
    }

    let current_cgset = parent_cg_set.unwrap_or_else(root_cg_set);

    if cg_set == current_cgset {
        log::info!("Cgroups {} inherited from parent", current_cgset);
        return 0;
    }

    let se = match find_rst_set_by_id(cg_set) {
        Some(s) => s,
        None => {
            log::error!("No set {} found", cg_set);
            return -1;
        }
    };

    move_in_cgroup(se, cgroup_yard_fd)
}

pub fn set_cg_yard(path: Option<String>) {
    unsafe { CG_YARD = path };
}

pub fn get_cg_yard() -> Option<String> {
    unsafe { CG_YARD.clone() }
}

pub fn restore_freezer_state(
    manage_cgroups: u32,
    cgroup_yard_fd: RawFd,
) -> io::Result<()> {
    let (entry, path) = {
        let state = FREEZER_STATE.lock().unwrap();
        if state.entry.is_none() {
            return Ok(());
        }
        (state.entry.clone().unwrap(), state.path[..state.path_len].to_vec())
    };

    let mut path_buf = [0u8; PATH_MAX];
    let path_len = path.len();
    path_buf[..path_len].copy_from_slice(&path);

    restore_cgroup_prop(&entry, &mut path_buf, path_len, false, false, manage_cgroups, cgroup_yard_fd)
}

/// Rewrites cgroup set paths to point to a new root.
/// This handles both cgroup v1 and v2 namespace prefixes.
/// Maps to: criu/cgroup.c rewrite_cgsets
pub fn rewrite_cgsets(
    sets: &mut [CgSetEntry],
    controllers: &[String],
    dir_name: &mut String,
    newroot: &str,
) -> io::Result<()> {
    let dirlen = dir_name.len();
    let mut dirnew: Option<String> = None;

    for set in sets.iter_mut() {
        for cg in set.ctls.iter_mut() {
            // Check if this controller matches and path starts with dir_name
            let cnames_refs: Vec<&str> = controllers.iter().map(|s| s.as_str()).collect();
            if !cgroup_contains(&cnames_refs, &cg.name, None) {
                continue;
            }

            // Path has leading "/", skip it when comparing
            if cg.path.len() <= 1 || !cg.path[1..].starts_with(dir_name.as_str()) {
                continue;
            }

            if cg.cgns_prefix.is_some() && cg.cgns_prefix.unwrap() > 0 {
                let prefix = cg.cgns_prefix.unwrap() as usize;
                let old_path = cg.path.clone();
                cg.path = format!("{}{}", newroot, &old_path[prefix..]);

                if dirnew.is_none() {
                    // -1 because cgns_prefix includes leading "/"
                    dirnew = Some(format!("{}{}", newroot, &dir_name[prefix - 1..]));
                }
                cg.cgns_prefix = Some(newroot.len() as u32);
            } else {
                // No prefix - simply rename the root but keep rest of path
                let old_path = cg.path.clone();
                cg.path = format!("{}{}", newroot, &old_path[dirlen + 1..]);

                if dirnew.is_none() {
                    dirnew = Some(newroot.to_string());
                }
            }
        }
    }

    if let Some(new_dir) = dirnew {
        *dir_name = new_dir;
    }

    Ok(())
}

/// Rewrites cgroup roots based on opts.new_cgroup_roots and opts.new_global_cg_root
/// Maps to: criu/cgroup.c rewrite_cgroup_roots
pub fn rewrite_cgroup_roots(
    cge: &mut CgroupEntry,
    new_cgroup_roots: &[(String, String)], // (controller, newroot) pairs
    new_global_cg_root: Option<&str>,
) -> io::Result<()> {
    for ctrl in cge.controllers.iter_mut() {
        let n_cnames = ctrl.cnames.len();
        if n_cnames == 0 {
            continue;
        }

        let mut ctrl_mask: u64 = (1u64 << n_cnames) - 1;
        let mut newroot: Option<&str> = None;

        // Check if any new_cgroup_roots match this controller
        for (controller, root) in new_cgroup_roots {
            let old_mask = ctrl_mask;
            let cnames_refs: Vec<&str> = ctrl.cnames.iter().map(|s| s.as_str()).collect();
            cgroup_contains(&cnames_refs, controller, Some(&mut ctrl_mask));

            if old_mask != ctrl_mask {
                if let Some(existing) = newroot {
                    if existing != root {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("CG paths mismatch: {} {}", existing, root),
                        ));
                    }
                }
                newroot = Some(root);
            }

            if ctrl_mask == 0 {
                break;
            }
        }

        // Fall back to global cg root if no specific root found
        if newroot.is_none() {
            newroot = new_global_cg_root;
        }

        if let Some(root) = newroot {
            for dir in ctrl.dirs.iter_mut() {
                log::info!("rewriting {} to {}", dir.dir_name, root);
                rewrite_cgsets(
                    &mut cge.sets,
                    &ctrl.cnames,
                    &mut dir.dir_name,
                    root,
                )?;
            }
        }
    }

    Ok(())
}

/// Helper to move a process into a cgroup
fn userns_move(path: &str, _fd: RawFd, pid: libc::pid_t, cgroup_yard_fd: RawFd) -> io::Result<()> {
    let pidbuf = format!("{}", pid);

    let c_path = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;

    let fd = unsafe { libc::openat(cgroup_yard_fd, c_path.as_ptr(), libc::O_WRONLY) };
    if fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("Can't move {} into {}", pidbuf, path),
        ));
    }

    let ret = unsafe {
        libc::write(fd, pidbuf.as_ptr() as *const libc::c_void, pidbuf.len())
    };
    unsafe { libc::close(fd) };

    if ret < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("Can't move {} into {}", pidbuf, path),
        ));
    }

    Ok(())
}

/// Unblocks SIGTERM for the cgroupd daemon
fn cgroupd_unblock_sigterm() -> io::Result<()> {
    let mut unblockmask: libc::sigset_t = unsafe { std::mem::zeroed() };

    unsafe {
        libc::sigemptyset(&mut unblockmask);
        libc::sigaddset(&mut unblockmask, libc::SIGTERM);

        if libc::sigprocmask(libc::SIG_UNBLOCK, &unblockmask, std::ptr::null_mut()) != 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                "cgroupd: can't unblock SIGTERM",
            ));
        }
    }

    Ok(())
}

/// The cgroupd daemon function - moves threads into their cgroups
/// Maps to: criu/cgroup.c cgroupd
fn cgroupd(sk: RawFd) -> i32 {
    if cgroupd_unblock_sigterm().is_err() {
        return -1;
    }

    log::info!("cgroupd: Daemon started");

    loop {
        let mut um = UnscMsg::default();
        let mut call: fn(*mut libc::c_void, RawFd, libc::pid_t) -> i32 = |_, _, _| 0;
        let mut cg_set: i32 = 0;

        unsc_msg_init(
            &mut um,
            &mut call as *mut _ as *mut _,
            &mut cg_set,
            std::ptr::null_mut(),
            0,
            -1,
            None,
        );

        let ret = unsafe { libc::recvmsg(sk, &mut um.h, 0) };
        if ret <= 0 {
            log::error!("cgroupd: recv req error");
            return -1;
        }

        let mut tid: libc::pid_t = 0;
        let mut fd: RawFd = -1;
        unsc_msg_pid_fd(&um, Some(&mut tid), &mut fd);

        log::debug!("cgroupd: move process {} into cg_set {}", tid, cg_set);

        let cg_set_entry = match find_rst_set_by_id(cg_set as u32) {
            Some(e) => e,
            None => {
                log::error!("cgroupd: No set found {}", cg_set);
                return -1;
            }
        };

        let controllers = get_controllers();
        // Get service fd for CGROUP_YARD
        // This is a simplification - in full impl we'd use ServiceFdState
        let cgroup_yard_fd: RawFd = -1; // Placeholder - actual impl would get the real fd

        for ce in &cg_set_entry.ctls {
            let mut ctrl: Option<&CgControllerEntry> = None;

            for cur in controllers {
                let cnames_refs: Vec<&str> = cur.cnames.iter().map(|s| s.as_str()).collect();
                if cgroup_contains(&cnames_refs, &ce.name, None) {
                    ctrl = Some(cur);
                    break;
                }
            }

            let ctrl = match ctrl {
                Some(c) => c,
                None => {
                    log::error!("cgroupd: No cg_controller_entry found for {}/{}", ce.name, ce.path);
                    return -1;
                }
            };

            // Not a threaded controller - skip
            if ctrl.is_threaded.is_none() || !ctrl.is_threaded.unwrap() {
                continue;
            }

            let (dir, _) = ctrl_dir_and_opt(ctrl);
            let format = if !ctrl.cnames.is_empty() && !ctrl.cnames[0].is_empty() {
                format!("{}/{}/tasks", dir, ce.path)
            } else {
                format!("{}/{}/cgroup.threads", dir, ce.path)
            };

            if userns_move(&format, 0, tid, cgroup_yard_fd).is_err() {
                log::error!("cgroupd: Can't move thread {} into {}/{}", tid, ce.name, ce.path);
                return -1;
            }
        }

        // Send response with tid
        let mut response_um = UnscMsg::default();
        unsc_msg_init(
            &mut response_um,
            &mut call as *mut _ as *mut _,
            &mut cg_set,
            std::ptr::null_mut(),
            0,
            -1,
            Some(tid),
        );

        if unsafe { libc::sendmsg(sk, &response_um.h, 0) } <= 0 {
            log::error!("cgroupd: send req error");
            return -1;
        }
    }
}

/// Starts the cgroup daemon for thread restoration
/// Maps to: criu/cgroup.c prepare_cgroup_thread_sfd
pub fn prepare_cgroup_thread_sfd(sfd_state: &mut ServiceFdState) -> io::Result<()> {
    let mut pid: libc::pid_t = 0;

    let sk = start_unix_cred_daemon(&mut pid, cgroupd);
    if sk < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "failed to start cgroupd",
        ));
    }

    set_cgroupd_pid(pid);

    if sfd_state.install_service_fd(SfdType::CgroupdSk, sk) < 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "failed to install cgroupd socket",
        ));
    }

    Ok(())
}

/// Stops the cgroup daemon
/// Maps to: criu/cgroup.c stop_cgroupd
pub fn stop_cgroupd() -> io::Result<()> {
    let pid = get_cgroupd_pid();

    if pid != 0 {
        let mut blockmask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut oldmask: libc::sigset_t = unsafe { std::mem::zeroed() };

        // Block SIGCHLD to avoid triggering sigchld_handler
        unsafe {
            libc::sigemptyset(&mut blockmask);
            libc::sigaddset(&mut blockmask, libc::SIGCHLD);
            libc::sigprocmask(libc::SIG_BLOCK, &blockmask, &mut oldmask);

            libc::kill(pid, libc::SIGTERM);
            libc::waitpid(pid, std::ptr::null_mut(), 0);

            libc::sigprocmask(libc::SIG_SETMASK, &oldmask, std::ptr::null_mut());
        }

        set_cgroupd_pid(0);
    }

    Ok(())
}

/// Sets up the cgroup service fd and mounts cgroup controllers
/// Maps to: criu/cgroup.c prepare_cgroup_sfd
pub fn prepare_cgroup_sfd(
    ce: &CgroupEntry,
    sfd_state: &mut ServiceFdState,
    manage_cgroups: u32,
    cgroup_yard_opt: Option<&str>,
) -> io::Result<()> {
    if manage_cgroups == 0 {
        return Ok(());
    }

    log::info!("Preparing cgroups yard (cgroups restore mode {:#x})", manage_cgroups);

    let mut paux = [0u8; PATH_MAX];
    let off: usize;

    if let Some(yard) = cgroup_yard_opt {
        let yard_bytes = yard.as_bytes();
        paux[..yard_bytes.len()].copy_from_slice(yard_bytes);
        off = yard_bytes.len();
        set_cg_yard(Some(yard.to_string()));
    } else {
        // Create temp dir
        let template = b".criu.cgyard.XXXXXX\0";
        paux[..template.len()].copy_from_slice(template);

        let result = unsafe { libc::mkdtemp(paux.as_mut_ptr() as *mut libc::c_char) };
        if result.is_null() {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                "Can't make temp cgyard dir",
            ));
        }

        // Find length of created path
        off = paux.iter().position(|&c| c == 0).unwrap_or(0);
        let yard_str = std::str::from_utf8(&paux[..off])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf8"))?;

        set_cg_yard(Some(yard_str.to_string()));

        // Create mount namespace yard
        if make_yard(yard_str).is_err() {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                "Can't make cgroup yard",
            ));
        }
    }

    let cg_yard = get_cg_yard().unwrap();
    log::debug!("Opening {} as cg yard", cg_yard);

    let c_yard = CString::new(cg_yard.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "yard contains null"))?;

    let yard_fd = unsafe { libc::open(c_yard.as_ptr(), libc::O_DIRECTORY) };
    if yard_fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            "Can't open cgyard",
        ));
    }

    let ret = sfd_state.install_service_fd(SfdType::CgroupYard, yard_fd);
    if ret < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to install cgroup yard fd",
        ));
    }

    // Add trailing slash
    paux[off] = b'/';
    let off = off + 1;

    for ctrl in &ce.controllers {
        if ctrl.cnames.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Each cg_controller_entry must have at least 1 controller",
            ));
        }

        let (dir_name, opt) = ctrl_dir_and_opt(ctrl);
        let dir_bytes = dir_name.as_bytes();
        if off + dir_bytes.len() >= PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "controller path too long",
            ));
        }
        paux[off..off + dir_bytes.len()].copy_from_slice(dir_bytes);
        paux[off + dir_bytes.len()] = 0;
        let ctl_off = off + dir_bytes.len();

        // Check if controller already exists
        let c_path = CString::new(&paux[..ctl_off])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;

        if unsafe { libc::access(c_path.as_ptr(), libc::F_OK) } != 0 {
            let fstype = if ctrl.cnames[0].is_empty() {
                CString::new("cgroup2").unwrap()
            } else {
                CString::new("cgroup").unwrap()
            };

            log::debug!("Making controller dir {} ({})",
                std::str::from_utf8(&paux[..ctl_off]).unwrap_or("?"), opt);

            if unsafe { libc::mkdir(c_path.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::new(
                    io::Error::last_os_error().kind(),
                    format!("Can't make controller dir {}", dir_name),
                ));
            }

            let none = CString::new("none").unwrap();
            let c_opt = CString::new(opt.as_str()).unwrap();

            if unsafe {
                libc::mount(
                    none.as_ptr(),
                    c_path.as_ptr(),
                    fstype.as_ptr(),
                    0,
                    c_opt.as_ptr() as *const libc::c_void,
                )
            } < 0
            {
                return Err(io::Error::new(
                    io::Error::last_os_error().kind(),
                    format!("Can't mount controller dir {}", dir_name),
                ));
            }
        }

        // Prepare cgroup directories for this controller
        let yard_off = ctl_off - cg_yard.len() - 1;
        let mut dirs = ctrl.dirs.clone();

        if manage_cgroups != 0 {
            let controllers_vec: Vec<String> = ctrl.cnames.clone();
            let cgroup_yard_fd = sfd_state.get_service_fd(SfdType::CgroupYard);

            // Need to work with the path after the yard prefix
            let mut yard_path = paux.clone();
            prepare_cgroup_dirs(
                &controllers_vec,
                &mut yard_path,
                yard_off,
                &mut dirs,
                manage_cgroups,
                cgroup_yard_fd,
            )?;
        }
    }

    Ok(())
}

/// Main cgroup preparation function
/// Maps to: criu/cgroup.c prepare_cgroup
pub fn prepare_cgroup(sfd_state: &mut ServiceFdState, manage_cgroups: u32, cgroup_yard_opt: Option<&str>) -> io::Result<()> {
    let dfd = sfd_state.get_service_fd(SfdType::ImgFdOff);
    let mut img = open_image(dfd, CrFdType::Cgroup, "")?;

    let ce: Option<CgroupEntry> = pb_read_one_eof(&mut img).ok().flatten();
    close_image(&mut img);

    let ce = match ce {
        Some(e) => e,
        None => return Ok(()), // No cgroup data - that's OK
    };

    // Store in globals for later use
    set_rst_sets(ce.sets.clone());
    set_controllers(ce.controllers.iter().cloned().collect());

    let n_sets = ce.sets.len();

    if n_sets > 0 {
        // Prepare the cgroup yard
        prepare_cgroup_sfd(&ce, sfd_state, manage_cgroups, cgroup_yard_opt)?;

        // Start the cgroup daemon for thread restoration
        prepare_cgroup_thread_sfd(sfd_state)?;
    }

    Ok(())
}

pub fn fini_cgroup(sfd_state: &mut ServiceFdState, cgroup_yard_opt: Option<&str>) {
    let cg_yard = match get_cg_yard() {
        Some(y) => y,
        None => return,
    };

    sfd_state.close_service_fd(SfdType::CgroupYard);

    if cgroup_yard_opt.is_none() {
        let c_path = match CString::new(cg_yard.as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };

        unsafe {
            if libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) != 0 {
                log::error!("Unable to umount {}", cg_yard);
            }
            if libc::rmdir(c_path.as_ptr()) != 0 {
                log::error!("Unable to remove {}", cg_yard);
            }
        }
    }

    set_cg_yard(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_subtree_control_prop_prefix_basic() {
        let input = b"cpu memory io";
        let mut output = [0u8; 64];
        let len = add_subtree_control_prop_prefix(input, &mut output, b'+');
        assert_eq!(&output[..len], b"+cpu +memory +io ");
    }

    #[test]
    fn test_add_subtree_control_prop_prefix_single() {
        let input = b"cpu";
        let mut output = [0u8; 64];
        let len = add_subtree_control_prop_prefix(input, &mut output, b'-');
        assert_eq!(&output[..len], b"-cpu ");
    }

    #[test]
    fn test_add_subtree_control_prop_prefix_empty() {
        let input = b"";
        let mut output = [0u8; 64];
        let len = add_subtree_control_prop_prefix(input, &mut output, b'+');
        assert_eq!(len, 2);
        assert_eq!(&output[..len], b"+ ");
    }

    #[test]
    fn test_cgroup_contains_single_match() {
        let controllers = ["cpu"];
        assert!(cgroup_contains(&controllers, "cpu", None));
        assert!(cgroup_contains(&controllers, "cpu,memory", None));
        assert!(cgroup_contains(&controllers, "memory,cpu", None));
    }

    #[test]
    fn test_cgroup_contains_multiple_match() {
        let controllers = ["cpu", "memory"];
        assert!(cgroup_contains(&controllers, "cpu,memory", None));
        assert!(cgroup_contains(&controllers, "memory,cpu,io", None));
    }

    #[test]
    fn test_cgroup_contains_no_match() {
        let controllers = ["cpu"];
        assert!(!cgroup_contains(&controllers, "memory", None));
        assert!(!cgroup_contains(&controllers, "cpuacct", None)); // partial match should fail
    }

    #[test]
    fn test_cgroup_contains_partial_name() {
        // "cpu" should not match "cpuset" or "cpuacct"
        let controllers = ["cpu"];
        assert!(!cgroup_contains(&controllers, "cpuset", None));
        assert!(!cgroup_contains(&controllers, "cpuacct,memory", None));
    }

    #[test]
    fn test_cgroup_contains_mask() {
        let controllers = ["cpu", "memory", "io"];
        let mut mask = 0b111u64;
        // All three controllers must be present for it to return true
        assert!(cgroup_contains(&controllers, "cpu,memory,io", Some(&mut mask)));
        // All bits should be cleared
        assert_eq!(mask, 0b000);

        // Test partial match - should return false but still update mask for found controllers
        let mut mask2 = 0b111u64;
        assert!(!cgroup_contains(&controllers, "cpu,io", Some(&mut mask2)));
        // cpu (bit 0) and io (bit 2) found, memory (bit 1) not found
        assert_eq!(mask2, 0b010);
    }

    #[test]
    fn test_cgroup_contains_cgroup2() {
        // For cgroup2, controllers is a single empty string
        let controllers = [""];
        assert!(cgroup_contains(&controllers, "", None));
        assert!(!cgroup_contains(&controllers, "cpu", None));
    }

    #[test]
    fn test_cgroup_contains_empty_controllers() {
        let controllers: [&str; 0] = [];
        assert!(!cgroup_contains(&controllers, "cpu", None));
    }

    #[test]
    fn test_ctrl_dir_and_opt_basic() {
        let ctl = CgControllerEntry {
            cnames: vec!["cpu".to_string(), "memory".to_string()],
            dirs: vec![],
            is_threaded: None,
        };
        let (dir, opt) = ctrl_dir_and_opt(&ctl);
        assert_eq!(dir, "cpu,memory");
        assert_eq!(opt, "cpu,memory");
    }

    #[test]
    fn test_ctrl_dir_and_opt_with_name_prefix() {
        let ctl = CgControllerEntry {
            cnames: vec!["name=systemd".to_string()],
            dirs: vec![],
            is_threaded: None,
        };
        let (dir, opt) = ctrl_dir_and_opt(&ctl);
        assert_eq!(dir, "systemd");
        assert_eq!(opt, "none,name=systemd");
    }

    #[test]
    fn test_ctrl_dir_and_opt_cgroup2() {
        let ctl = CgControllerEntry {
            cnames: vec!["".to_string()],
            dirs: vec![],
            is_threaded: None,
        };
        let (dir, opt) = ctrl_dir_and_opt(&ctl);
        assert_eq!(dir, "unified");
        assert_eq!(opt, "");
    }

    #[test]
    fn test_rewrite_cgsets_simple() {
        use crate::proto::CgMemberEntry;

        let mut sets = vec![CgSetEntry {
            id: 1,
            ctls: vec![CgMemberEntry {
                name: "cpu".to_string(),
                path: "/300".to_string(),
                cgns_prefix: None,
            }],
        }];

        let controllers = vec!["cpu".to_string()];
        let mut dir_name = "300".to_string();

        let result = rewrite_cgsets(&mut sets, &controllers, &mut dir_name, "/newroot");
        assert!(result.is_ok());
        assert_eq!(dir_name, "/newroot");
        assert_eq!(sets[0].ctls[0].path, "/newroot");
    }

    #[test]
    fn test_rewrite_cgsets_with_cgns_prefix() {
        use crate::proto::CgMemberEntry;

        // Path must start with "/" + dir_name for the rewrite to trigger
        // cgns_prefix points to the namespace boundary in the path
        let mut sets = vec![CgSetEntry {
            id: 1,
            ctls: vec![CgMemberEntry {
                name: "cpu".to_string(),
                path: "/foo/bar".to_string(),
                cgns_prefix: Some(4), // length of "/foo"
            }],
        }];

        let controllers = vec!["cpu".to_string()];
        let mut dir_name = "foo/bar".to_string();

        let result = rewrite_cgsets(&mut sets, &controllers, &mut dir_name, "/newroot");
        assert!(result.is_ok());
        // After rewrite: newroot + path[prefix..] = "/newroot" + "/bar" = "/newroot/bar"
        assert_eq!(sets[0].ctls[0].path, "/newroot/bar");
        assert_eq!(sets[0].ctls[0].cgns_prefix, Some(8)); // length of "/newroot"
    }

    #[test]
    fn test_stop_cgroupd_no_daemon() {
        // Ensure stop_cgroupd handles no daemon case gracefully
        set_cgroupd_pid(0);
        let result = stop_cgroupd();
        assert!(result.is_ok());
    }
}
