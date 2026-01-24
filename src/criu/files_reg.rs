use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

use libc::{gid_t, uid_t};

use crate::criu::files::{fd_types, file_desc_add, files_collected, FileDesc, FileDescOps};
use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::mount::{service_mountpoint, try_remount_writable, MountInfoStore, PATH_MAX};
use crate::criu::namespaces::root_ns_mask;
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::rst_malloc::shmalloc;
use crate::criu::util::get_relative_path;
use crate::proto::{RegFileEntry, RemapFilePathEntry, RemapType};

struct SendSyncPtr<T>(*mut T);
unsafe impl<T> Send for SendSyncPtr<T> {}
unsafe impl<T> Sync for SendSyncPtr<T> {}

pub struct FileRemap {
    pub rpath: String,
    pub is_dir: bool,
    pub rmnt_id: i32,
    pub uid: uid_t,
    pub gid: gid_t,
}

impl FileRemap {
    pub fn new() -> Self {
        Self {
            rpath: String::new(),
            is_dir: false,
            rmnt_id: 0,
            uid: 0,
            gid: 0,
        }
    }
}

impl Default for FileRemap {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RegFileInfo {
    pub id: u32,
    pub rfe: RegFileEntry,
    pub remap: Option<Box<FileRemap>>,
    pub size_mode_checked: bool,
    pub is_dir: bool,
    pub path: Option<String>,
}

impl RegFileInfo {
    pub fn new(rfe: RegFileEntry) -> Self {
        Self {
            id: rfe.id,
            rfe,
            remap: None,
            size_mode_checked: false,
            is_dir: false,
            path: None,
        }
    }
}

pub struct RemapInfo {
    pub rpe: RemapFilePathEntry,
    pub rfi: Box<RegFileInfo>,
}

impl RemapInfo {
    pub fn new(rpe: RemapFilePathEntry, rfi: Box<RegFileInfo>) -> Self {
        Self { rpe, rfi }
    }
}

static REG_FILES: Mutex<Vec<SendSyncPtr<RegFileInfo>>> = Mutex::new(Vec::new());
static REMAPS: Mutex<Vec<RemapInfo>> = Mutex::new(Vec::new());

use crate::criu::lock::Mutex as CrMutex;
use std::sync::OnceLock;

struct SyncMutexPtr(*mut CrMutex);
unsafe impl Send for SyncMutexPtr {}
unsafe impl Sync for SyncMutexPtr {}

static REMAP_OPEN_LOCK: OnceLock<SyncMutexPtr> = OnceLock::new();

#[allow(dead_code)]
fn get_remap_lock() -> Option<&'static CrMutex> {
    REMAP_OPEN_LOCK.get().and_then(|wrapped| {
        if wrapped.0.is_null() {
            None
        } else {
            Some(unsafe { &*wrapped.0 })
        }
    })
}

fn init_remap_lock() -> i32 {
    let ptr = shmalloc(std::mem::size_of::<CrMutex>()) as *mut CrMutex;
    if ptr.is_null() {
        return -1;
    }

    unsafe {
        std::ptr::write(ptr, CrMutex::new());
        (*ptr).init();
    }

    let _ = REMAP_OPEN_LOCK.set(SyncMutexPtr(ptr));
    0
}

fn prepare_one_remap(ri: &mut RemapInfo) -> i32 {
    log::info!(
        "Configuring remap {:#x} -> {:#x}",
        ri.rfi.rfe.id,
        ri.rpe.remap_id
    );

    let remap_type = ri.rpe.remap_type.and_then(|t| RemapType::try_from(t).ok());

    match remap_type {
        Some(RemapType::Linked) => {
            // TODO: open_remap_linked
            0
        }
        Some(RemapType::Ghost) => {
            // TODO: open_remap_ghost
            0
        }
        Some(RemapType::Procfs) => {
            // handled earlier by collect_remap_dead_process
            0
        }
        _ => {
            log::error!("unknown remap type {:?}", ri.rpe.remap_type);
            -1
        }
    }
}

pub fn prepare_remaps() -> i32 {
    if init_remap_lock() != 0 {
        return -1;
    }

    let mut remaps = match REMAPS.lock() {
        Ok(r) => r,
        Err(_) => return -1,
    };

    for ri in remaps.iter_mut() {
        if prepare_one_remap(ri) != 0 {
            return -1;
        }
    }

    0
}

pub fn add_remap(remap: RemapInfo) {
    if let Ok(mut remaps) = REMAPS.lock() {
        remaps.push(remap);
    }
}

pub fn clear_remaps() {
    if let Ok(mut remaps) = REMAPS.lock() {
        remaps.clear();
    }
}

fn clean_one_remap(ri: &mut RemapInfo, store: &MountInfoStore, mntns_compat_mode: bool) -> i32 {
    let remap = match ri.rfi.remap.as_mut() {
        Some(r) => r,
        None => return 0,
    };

    if remap.rpath.is_empty() {
        return 0;
    }

    let path: String;

    if (root_ns_mask() & libc::CLONE_NEWNS as u64) == 0 {
        path = format!("/{}", remap.rpath);
    } else {
        let mnt_id = ri.rfi.rfe.mnt_id.unwrap_or(-1); /* rirfirfe %) */
        let mi_idx = match store.lookup_mnt_id(mnt_id) {
            Some(idx) => idx,
            None => {
                log::error!("The {} mount is not found for ghost", mnt_id);
                return -1;
            }
        };

        let mi = match store.get(mi_idx) {
            Some(m) => m,
            None => return -1,
        };

        let ns_mountpoint = mi.ns_mountpoint.as_deref().unwrap_or("");
        let rel_path = match get_relative_path(&remap.rpath, ns_mountpoint) {
            Some(p) => p,
            None => {
                log::error!(
                    "Can't get path {} relative to {}",
                    remap.rpath,
                    ns_mountpoint
                );
                return -1;
            }
        };

        let mp = service_mountpoint(mi, mntns_compat_mode, true).unwrap_or("");
        let sep = if rel_path.is_empty() { "" } else { "/" };
        path = format!("{}{}{}", mp, sep, rel_path);

        if path.len() >= PATH_MAX {
            log::error!("Path too long: {}", path);
            return -1;
        }

        /* We get here while in service mntns */
        if try_remount_writable(store, mi_idx, false, root_ns_mask()) != 0 {
            return -1;
        }
    }

    log::info!("Unlink remap {}", path);

    let path_cstr = match CString::new(path.as_str()) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let ret = if remap.is_dir {
        unsafe { libc::rmdir(path_cstr.as_ptr()) }
    } else {
        unsafe { libc::unlink(path_cstr.as_ptr()) }
    };

    if ret != 0 {
        log::error!(
            "Couldn't unlink remap {}: {}",
            path,
            std::io::Error::last_os_error()
        );
        return -1;
    }

    remap.rpath.clear();

    0
}

pub fn try_clean_remaps(store: &MountInfoStore, mntns_compat_mode: bool, only_ghosts: bool) -> i32 {
    let mut remaps = match REMAPS.lock() {
        Ok(r) => r,
        Err(_) => return -1,
    };

    let mut ret = 0;

    for ri in remaps.iter_mut() {
        let remap_type = ri.rpe.remap_type.and_then(|t| RemapType::try_from(t).ok());

        match remap_type {
            Some(RemapType::Ghost) => {
                ret |= clean_one_remap(ri, store, mntns_compat_mode);
            }
            Some(RemapType::Linked) if !only_ghosts => {
                ret |= clean_one_remap(ri, store, mntns_compat_mode);
            }
            _ => continue,
        }
    }

    ret
}

fn collect_one_regfile(rfe: RegFileEntry) -> i32 {
    let ptr = shmalloc(std::mem::size_of::<RegFileInfo>()) as *mut RegFileInfo;
    if ptr.is_null() {
        return -1;
    }

    let path = if rfe.name.len() == 1 && rfe.name.starts_with('/') {
        Some(".".to_string())
    } else if rfe.name.starts_with('/') {
        Some(rfe.name[1..].to_string())
    } else {
        Some(rfe.name.clone())
    };

    let id = rfe.id;

    unsafe {
        std::ptr::write(
            ptr,
            RegFileInfo {
                id,
                rfe,
                remap: None,
                size_mode_checked: false,
                is_dir: false,
                path,
            },
        );
    }

    log::info!("Collected reg file ID {:#x}", id);

    unsafe {
        let ops_ptr = shmalloc(std::mem::size_of::<FileDescOps>()) as *mut FileDescOps;
        if ops_ptr.is_null() {
            return -1;
        }
        std::ptr::write(ops_ptr, FileDescOps::new(fd_types::REG));

        let desc_ptr = shmalloc(std::mem::size_of::<FileDesc>()) as *mut FileDesc;
        if desc_ptr.is_null() {
            return -1;
        }
        FileDesc::init(desc_ptr, id, ops_ptr);
        file_desc_add(desc_ptr);
    }

    let mut reg_files = REG_FILES.lock().unwrap();
    reg_files.push(SendSyncPtr(ptr));

    0
}

fn collect_one_remap(rpe: RemapFilePathEntry) -> i32 {
    // TODO: Full remap collection requires find_file_desc_raw and remap type handling
    log::debug!(
        "Collecting remap orig_id={} remap_id={}",
        rpe.orig_id,
        rpe.remap_id
    );
    0
}

fn collect_reg_files(dfd: RawFd) -> i32 {
    let mut img = match open_image(dfd, CrFdType::RegFiles, "") {
        Ok(img) => img,
        Err(_) => return -1,
    };

    log::info!("Collecting regular files");

    loop {
        match pb_read_one_eof::<RegFileEntry>(&mut img) {
            Ok(Some(rfe)) => {
                if collect_one_regfile(rfe) < 0 {
                    close_image(&mut img);
                    return -1;
                }
            }
            Ok(None) => break,
            Err(e) => {
                log::error!("Failed to read reg file entry: {}", e);
                close_image(&mut img);
                return -1;
            }
        }
    }

    close_image(&mut img);
    log::debug!(" `- ... done");
    0
}

fn collect_remaps(dfd: RawFd) -> i32 {
    let mut img = match open_image(dfd, CrFdType::RemapFpath, "") {
        Ok(img) => img,
        Err(_) => return -1,
    };

    log::info!("Collecting remaps");

    loop {
        match pb_read_one_eof::<RemapFilePathEntry>(&mut img) {
            Ok(Some(rpe)) => {
                if collect_one_remap(rpe) < 0 {
                    close_image(&mut img);
                    return -1;
                }
            }
            Ok(None) => break,
            Err(e) => {
                log::error!("Failed to read remap entry: {}", e);
                close_image(&mut img);
                return -1;
            }
        }
    }

    close_image(&mut img);
    log::debug!(" `- ... done");
    0
}

pub fn collect_remaps_and_regfiles(dfd: RawFd) -> i32 {
    if !files_collected() && collect_reg_files(dfd) != 0 {
        return -1;
    }

    if collect_remaps(dfd) != 0 {
        return -1;
    }

    0
}

pub fn for_each_reg_file<F>(mut f: F) -> i32
where
    F: FnMut(&mut RegFileInfo) -> i32,
{
    let reg_files = REG_FILES.lock().unwrap();
    for wrapped_ptr in reg_files.iter() {
        let rfi = unsafe { &mut *wrapped_ptr.0 };
        if f(rfi) != 0 {
            return -1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::FownEntry;

    fn make_test_rfe() -> RegFileEntry {
        RegFileEntry {
            id: 1,
            flags: 0,
            pos: 0,
            fown: FownEntry {
                uid: 0,
                euid: 0,
                signum: 0,
                pid_type: 0,
                pid: 0,
            },
            name: "/test/file".to_string(),
            mnt_id: Some(1),
            size: None,
            ext: None,
            mode: None,
            build_id: vec![],
            checksum: None,
            checksum_config: None,
            checksum_parameter: None,
        }
    }

    #[test]
    fn test_file_remap_new() {
        let fr = FileRemap::new();
        assert!(fr.rpath.is_empty());
        assert!(!fr.is_dir);
        assert_eq!(fr.rmnt_id, 0);
    }

    #[test]
    fn test_reg_file_info_new() {
        let rfe = make_test_rfe();
        let rfi = RegFileInfo::new(rfe);
        assert_eq!(rfi.id, 1);
        assert!(rfi.remap.is_none());
        assert!(!rfi.size_mode_checked);
    }

    #[test]
    fn test_remap_info_new() {
        let rpe = RemapFilePathEntry {
            orig_id: 1,
            remap_id: 2,
            remap_type: Some(RemapType::Ghost as i32),
        };
        let rfe = make_test_rfe();
        let rfi = Box::new(RegFileInfo::new(rfe));
        let ri = RemapInfo::new(rpe, rfi);
        assert_eq!(ri.rpe.orig_id, 1);
        assert_eq!(ri.rpe.remap_id, 2);
    }

    #[test]
    fn test_clean_one_remap_empty_path() {
        let rpe = RemapFilePathEntry {
            orig_id: 1,
            remap_id: 2,
            remap_type: Some(RemapType::Ghost as i32),
        };
        let rfe = make_test_rfe();
        let mut rfi = Box::new(RegFileInfo::new(rfe));
        rfi.remap = Some(Box::new(FileRemap::new()));

        let mut ri = RemapInfo::new(rpe, rfi);
        let store = MountInfoStore::new();

        let ret = clean_one_remap(&mut ri, &store, false);
        assert_eq!(ret, 0);
    }
}
