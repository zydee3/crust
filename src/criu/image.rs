use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::criu::bfd::{bclose, bfdopenr, bfdopenw, bread, bwrite, Bfd};
use crate::criu::image_desc::{get_imgset_template, CrFdType};
use crate::criu::options::{opts_try, NetworkLockMethod};
use crate::criu::protobuf::{pb_read_one, pb_write_one};
use crate::proto::{InventoryEntry, Lsmtype, PagemapHead, TaskKobjIdsEntry};

pub const IMG_COMMON_MAGIC: u32 = 0x54564319;
pub const IMG_SERVICE_MAGIC: u32 = 0x55105940;
pub const RAW_IMAGE_MAGIC: u32 = 0x0;

pub const EMPTY_IMG_FD: i32 = -404;
pub const LAZY_IMG_FD: i32 = -505;

pub const O_NOBUF: i32 = libc::O_DIRECT;
pub const O_SERVICE: i32 = libc::O_DIRECTORY;
pub const O_FORCE_LOCAL: i32 = libc::O_SYNC;
pub const O_DUMP: i32 = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC;

pub const CRTOOLS_IMAGES_V1: u32 = 1;
pub const CRTOOLS_IMAGES_V1_1: u32 = 2;

pub const RUN_ID_HASH_LENGTH: usize = 37;
pub const NO_DUMP_CRIU_RUN_ID: u8 = 0x7f;

pub static mut IMG_COMMON_MAGIC_ENABLED: bool = true;

static NS_PER_ID: OnceLock<bool> = OnceLock::new();
static ROOT_IDS: OnceLock<Option<TaskKobjIdsEntry>> = OnceLock::new();
static ROOT_CG_SET: OnceLock<u32> = OnceLock::new();
static IMAGE_LSM: OnceLock<Lsmtype> = OnceLock::new();
static DUMP_CRIU_RUN_ID: OnceLock<String> = OnceLock::new();
static INVENTORY_PLUGINS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static N_INVENTORY_PLUGINS: OnceLock<i32> = OnceLock::new();

pub fn ns_per_id() -> bool {
    *NS_PER_ID.get().unwrap_or(&false)
}

pub fn root_ids() -> Option<&'static TaskKobjIdsEntry> {
    ROOT_IDS.get().and_then(|opt| opt.as_ref())
}

pub fn root_cg_set() -> u32 {
    *ROOT_CG_SET.get().unwrap_or(&0)
}

pub fn image_lsm() -> Lsmtype {
    *IMAGE_LSM.get().unwrap_or(&Lsmtype::NoLsm)
}

pub fn dump_criu_run_id() -> &'static str {
    DUMP_CRIU_RUN_ID.get().map(|s| s.as_str()).unwrap_or("")
}

fn get_inventory_plugins() -> &'static Mutex<Vec<String>> {
    INVENTORY_PLUGINS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn n_inventory_plugins() -> i32 {
    *N_INVENTORY_PLUGINS.get().unwrap_or(&0)
}

fn add_inventory_plugin(name: &str) -> i32 {
    let mut plugins = get_inventory_plugins().lock().unwrap();
    plugins.push(name.to_string());
    0
}

static PAGE_IDS: AtomicU32 = AtomicU32::new(1);

pub struct CrImg {
    pub bfd: Bfd,
    pub img_type: i32,
    pub oflags: u32,
    pub path: Option<String>,
}

impl CrImg {
    pub fn new(fd: i32) -> Self {
        CrImg {
            bfd: Bfd::new(fd),
            img_type: 0,
            oflags: 0,
            path: None,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bfd.fd == EMPTY_IMG_FD
    }

    #[inline]
    pub fn is_lazy(&self) -> bool {
        self.bfd.fd == LAZY_IMG_FD
    }

    #[inline]
    pub fn raw_fd(&self) -> RawFd {
        self.bfd.fd
    }
}

#[inline]
pub fn head_magic(oflags: u32) -> u32 {
    if (oflags as i32) & O_SERVICE != 0 {
        IMG_SERVICE_MAGIC
    } else {
        IMG_COMMON_MAGIC
    }
}

pub fn write_img_buf(img: &mut CrImg, data: &[u8]) -> io::Result<()> {
    let ret = bwrite(&mut img.bfd, data)?;

    if ret == data.len() {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("Img trimmed {}/{}", ret, data.len()),
    ))
}

pub fn read_img_buf_eof(img: &mut CrImg, buf: &mut [u8]) -> io::Result<i32> {
    let ret = bread(&mut img.bfd, buf)?;

    if ret == buf.len() {
        return Ok(1);
    }
    if ret == 0 {
        return Ok(0);
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("Img trimmed {}/{}", ret, buf.len()),
    ))
}

pub fn read_img_buf(img: &mut CrImg, buf: &mut [u8]) -> io::Result<()> {
    let ret = read_img_buf_eof(img, buf)?;

    if ret == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF"));
    }

    Ok(())
}

pub fn write_img_u32(img: &mut CrImg, val: u32) -> io::Result<()> {
    write_img_buf(img, &val.to_ne_bytes())
}

pub fn read_img_u32(img: &mut CrImg) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    read_img_buf(img, &mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

pub fn img_write_magic(img: &mut CrImg, oflags: u32, type_magic: u32) -> io::Result<()> {
    let common_magic_enabled = unsafe { IMG_COMMON_MAGIC_ENABLED };

    if common_magic_enabled && img.img_type != CR_FD_INVENTORY {
        let cmagic = head_magic(oflags);
        write_img_u32(img, cmagic)?;
    }

    write_img_u32(img, type_magic)
}

pub fn img_check_magic(
    img: &mut CrImg,
    oflags: u32,
    expected_magic: u32,
    path: &str,
) -> io::Result<()> {
    let mut magic = read_img_u32(img)?;

    let common_magic_enabled = unsafe { IMG_COMMON_MAGIC_ENABLED };

    if common_magic_enabled && img.img_type != CR_FD_INVENTORY {
        if magic != head_magic(oflags) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Head magic doesn't match for {}", path),
            ));
        }

        magic = read_img_u32(img)?;
    }

    if magic != expected_magic {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Magic doesn't match for {}", path),
        ));
    }

    Ok(())
}

pub const CR_FD_INVENTORY: i32 = 0;
pub const CR_FD_PAGES: i32 = 66;
pub const CR_FD_PERM: libc::mode_t = 0o600;

pub fn do_open_image(
    img: &mut CrImg,
    dfd: RawFd,
    img_type: i32,
    oflags: u32,
    path: &str,
    type_magic: u32,
) -> io::Result<()> {
    let flags = (oflags as i32) & !(O_NOBUF | O_SERVICE | O_FORCE_LOCAL);

    let c_path = CString::new(path).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "path contains null byte")
    })?;

    let ret = unsafe { libc::openat(dfd, c_path.as_ptr(), flags, CR_FD_PERM as libc::c_int) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if (flags & libc::O_CREAT) == 0 && err.raw_os_error() == Some(libc::ENOENT) {
            img.bfd.fd = EMPTY_IMG_FD;
            return Ok(());
        }
        return Err(io::Error::new(
            err.kind(),
            format!("Unable to open {}: {}", path, err),
        ));
    }

    img.bfd.fd = ret;
    img.img_type = img_type;
    img.oflags = oflags;

    if (oflags as i32) & O_NOBUF != 0 {
        img.bfd.setraw();
    } else {
        if flags == libc::O_RDONLY {
            bfdopenr(&mut img.bfd)?;
        } else {
            bfdopenw(&mut img.bfd)?;
        }
    }

    if type_magic == RAW_IMAGE_MAGIC {
        return Ok(());
    }

    if flags == libc::O_RDONLY {
        img_check_magic(img, oflags, type_magic, path)?;
    } else {
        img_write_magic(img, oflags, type_magic)?;
    }

    Ok(())
}

pub fn close_image(img: &mut CrImg) {
    if img.is_lazy() {
        img.path = None;
    } else if !img.is_empty() {
        bclose(&mut img.bfd);
    }
}

pub fn open_image_lazy(img: &mut CrImg, dfd: RawFd, type_magic: u32) -> io::Result<()> {
    let path = img.path.take().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "no path for lazy image")
    })?;

    do_open_image(img, dfd, img.img_type, img.oflags, &path, type_magic)
}

pub fn open_image_at(
    dfd: RawFd,
    fd_type: CrFdType,
    flags: u32,
    path: &str,
) -> io::Result<CrImg> {
    let tmpl = get_imgset_template(fd_type);
    let oflags = flags | tmpl.oflags as u32;

    let mut img = CrImg::new(EMPTY_IMG_FD);
    img.img_type = fd_type as i32;
    img.oflags = oflags;

    let lazy = dfd == -1 && (flags as i32 & libc::O_CREAT) != 0;

    if lazy {
        img.bfd.fd = LAZY_IMG_FD;
        img.path = Some(path.to_string());
        return Ok(img);
    }

    do_open_image(&mut img, dfd, fd_type as i32, oflags, path, tmpl.magic)?;

    Ok(img)
}

pub fn open_image(dfd: RawFd, fd_type: CrFdType, path: &str) -> io::Result<CrImg> {
    open_image_at(dfd, fd_type, libc::O_RDONLY as u32, path)
}

pub fn open_image_create(dfd: RawFd, fd_type: CrFdType, path: &str) -> io::Result<CrImg> {
    let flags = (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY) as u32;
    open_image_at(dfd, fd_type, flags, path)
}

pub fn img_raw_size(img: &CrImg) -> io::Result<libc::off_t> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };

    let ret = unsafe { libc::fstat(img.bfd.fd, &mut stat) };
    if ret != 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            "Failed to get image stats",
        ));
    }

    Ok(stat.st_size)
}

pub const CR_PARENT_LINK: &str = "parent";

pub fn open_parent(dfd: RawFd) -> io::Result<Option<RawFd>> {
    let c_path = std::ffi::CStr::from_bytes_with_nul(b"parent\0").unwrap();

    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatat(dfd, c_path.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };

    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(err);
    }

    let pfd = unsafe { libc::openat(dfd, c_path.as_ptr(), libc::O_RDONLY) };
    if pfd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            "Can't open parent path",
        ));
    }

    Ok(Some(pfd))
}

pub fn up_page_ids_base() {
    // When page server and criu dump work on the same dir, the shmem pagemaps
    // and regular pagemaps may have IDs conflicts. Fix this by making page
    // server produce page images with higher IDs.
    let current = PAGE_IDS.load(Ordering::SeqCst);
    assert!(current == 1, "up_page_ids_base called after page_ids used");
    PAGE_IDS.store(current + 0x10000, Ordering::SeqCst);
}

pub fn open_pages_image_at(
    dfd: RawFd,
    flags: u32,
    pmi: &mut CrImg,
    pmi_dfd: RawFd,
    pmi_magic: u32,
) -> io::Result<(CrImg, u32)> {
    let id: u32;

    if flags == libc::O_RDONLY as u32 || flags == (libc::O_RDONLY | libc::O_RDWR) as u32 {
        let h: PagemapHead = pb_read_one(pmi)?;
        id = h.pages_id;
    } else {
        id = PAGE_IDS.fetch_add(1, Ordering::SeqCst);
        let h = PagemapHead { pages_id: id };
        pb_write_one(pmi, &h, pmi_dfd, pmi_magic)?;
    }

    let path = format!("pages-{}.img", id);
    let img = open_image_at(dfd, CrFdType::Pages, flags, &path)?;

    Ok((img, id))
}

use crate::criu::servicefd::{ServiceFdState, SfdType};

pub fn close_image_dir(sfd_state: &mut ServiceFdState) {
    // if opts.stream { img_streamer_finish(); } - streaming mode not implemented
    sfd_state.close_service_fd(SfdType::ImgFdOff);
}

/// Validates and reads the image inventory.
/// Maps to: check_img_inventory (criu/image.c:38-156)
pub fn check_img_inventory(dfd: RawFd, restore: bool) -> i32 {
    let mut img = match open_image(dfd, CrFdType::Inventory, "") {
        Ok(img) => img,
        Err(e) => {
            log::error!("Failed to open inventory image: {}", e);
            return -1;
        }
    };

    let he: InventoryEntry = match pb_read_one(&mut img) {
        Ok(entry) => entry,
        Err(e) => {
            log::error!("Failed to read inventory entry: {}", e);
            close_image(&mut img);
            return -1;
        }
    };

    if he.fdinfo_per_id.is_none() || he.fdinfo_per_id == Some(false) {
        log::error!("Too old image, no longer supported");
        close_image(&mut img);
        return -1;
    }

    let _ = NS_PER_ID.set(he.ns_per_id.unwrap_or(false));

    if let Some(ids) = he.root_ids {
        let _ = ROOT_IDS.set(Some(ids));
    } else {
        let _ = ROOT_IDS.set(None);
    }

    if let Some(cg_set) = he.root_cg_set {
        if cg_set == 0 {
            log::error!("Corrupted root cgset");
            close_image(&mut img);
            return -1;
        }
        let _ = ROOT_CG_SET.set(cg_set);
    }

    if let Some(lsm_type) = he.lsmtype {
        let lsm = Lsmtype::try_from(lsm_type).unwrap_or(Lsmtype::NoLsm);
        let _ = IMAGE_LSM.set(lsm);
    } else {
        let _ = IMAGE_LSM.set(Lsmtype::NoLsm);
    }

    match he.img_version {
        CRTOOLS_IMAGES_V1 => {
            unsafe { IMG_COMMON_MAGIC_ENABLED = false };
        }
        CRTOOLS_IMAGES_V1_1 => {
            // newer images with extra magic in the head - already true by default
        }
        ver => {
            log::error!("Not supported images version {}", ver);
            close_image(&mut img);
            return -1;
        }
    }

    if restore {
        let options = match opts_try() {
            Some(o) => o,
            None => {
                log::error!("Options not initialized");
                close_image(&mut img);
                return -1;
            }
        };

        if he.tcp_close == Some(true) && options.tcp_close == 0 {
            log::error!("Need to set the --tcp-close options.");
            close_image(&mut img);
            return -1;
        }

        if he.allow_uprobes == Some(true) && options.allow_uprobes == 0 {
            log::error!("Dumped with --allow-uprobes. Need to set it on restore as well.");
            close_image(&mut img);
            return -1;
        }

        // Handle network lock method
        if he.network_lock_method.is_none() {
            log::info!("Network lock method not found in inventory image");
            log::info!("Falling back to iptables network lock method");
            // Note: opts is immutable, so we can't modify it here
            // The caller should handle this case
        }

        // Handle plugins
        if he.plugins_entry.is_none() {
            // backwards compatibility: all plugins should be enabled during restore
            let _ = N_INVENTORY_PLUGINS.set(-1);
        } else if let Some(pe) = he.plugins_entry {
            for plugin in pe.plugins {
                if add_inventory_plugin(&plugin) != 0 {
                    close_image(&mut img);
                    return -1;
                }
            }
            let plugins = get_inventory_plugins().lock().unwrap();
            let _ = N_INVENTORY_PLUGINS.set(plugins.len() as i32);
        }

        // Handle dump_criu_run_id
        if let Some(run_id) = he.dump_criu_run_id {
            log::info!("Dump CRIU run id = {}", run_id);
            let _ = DUMP_CRIU_RUN_ID.set(run_id);
        } else {
            // If restoring from an old image, mark that no dump_criu_run_id exists
            let marker = String::from_utf8(vec![NO_DUMP_CRIU_RUN_ID]).unwrap_or_default();
            let _ = DUMP_CRIU_RUN_ID.set(marker);
        }
    }

    close_image(&mut img);
    0
}

/// Returns the network lock method from the inventory.
/// This is used by the caller after check_img_inventory to determine the method.
pub fn inventory_network_lock_method(dfd: RawFd) -> Option<NetworkLockMethod> {
    let mut img = match open_image(dfd, CrFdType::Inventory, "") {
        Ok(img) => img,
        Err(_) => return None,
    };

    let he: InventoryEntry = match pb_read_one(&mut img) {
        Ok(entry) => entry,
        Err(_) => {
            close_image(&mut img);
            return None;
        }
    };

    close_image(&mut img);

    he.network_lock_method.map(|m| match m {
        0 => NetworkLockMethod::Iptables,
        1 => NetworkLockMethod::Nftables,
        2 => NetworkLockMethod::Skip,
        _ => NetworkLockMethod::Iptables,
    })
}
