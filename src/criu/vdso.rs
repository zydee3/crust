use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use libc::pid_t;

use crate::criu::bfd::{bclose, bfdopenr, breadline, Bfd};
use crate::criu::kerndat::{kdat, VdsoSymtable};

pub const VDSO_BAD_ADDR: usize = usize::MAX;
pub const VVAR_BAD_ADDR: usize = usize::MAX;
pub const VDSO_BAD_SIZE: usize = usize::MAX;
pub const VVAR_BAD_SIZE: usize = usize::MAX;
pub const PROC_SELF: pid_t = 0;

#[derive(Debug, Clone)]
pub struct VdsoMaps {
    pub vdso_start: usize,
    pub vvar_start: usize,
    pub sym: VdsoSymtable,
    pub compatible: bool,
}

impl Default for VdsoMaps {
    fn default() -> Self {
        Self {
            vdso_start: VDSO_BAD_ADDR,
            vvar_start: VVAR_BAD_ADDR,
            sym: VdsoSymtable {
                vdso_size: VDSO_BAD_SIZE,
                vvar_size: VVAR_BAD_SIZE,
                vvar_vclock_size: 0,
                vdso_before_vvar: false,
            },
            compatible: false,
        }
    }
}

static VDSO_MAPS: OnceLock<std::sync::RwLock<VdsoMaps>> = OnceLock::new();

fn get_vdso_maps() -> &'static std::sync::RwLock<VdsoMaps> {
    VDSO_MAPS.get_or_init(|| std::sync::RwLock::new(VdsoMaps::default()))
}

fn is_kdat_vdso_sym_valid() -> bool {
    let maps = get_vdso_maps().read().unwrap();
    let kdat = kdat();

    if maps.sym.vdso_size != kdat.vdso_sym.vdso_size {
        return false;
    }
    if maps.sym.vvar_size != kdat.vdso_sym.vvar_size {
        return false;
    }

    true
}

pub fn vdso_parse_maps(pid: pid_t, s: &mut VdsoMaps) -> io::Result<()> {
    *s = VdsoMaps::default();

    let path = if pid == PROC_SELF {
        "/proc/self/maps".to_string()
    } else {
        format!("/proc/{}/maps", pid)
    };

    let path_cstr = CString::new(path).unwrap();
    let fd: RawFd = unsafe { libc::open(path_cstr.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut f = Bfd::new(fd);
    if let Err(e) = bfdopenr(&mut f) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let result = parse_maps_inner(&mut f, s);
    bclose(&mut f);
    result
}

fn parse_maps_inner(f: &mut Bfd, s: &mut VdsoMaps) -> io::Result<()> {
    loop {
        let line = match breadline(f)? {
            Some(l) => l,
            None => break,
        };

        let line_str = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let has_vdso = line_str.contains("[vdso]");
        let has_vvar = line_str.contains("[vvar]");
        let has_vvar_vclock = line_str.contains("[vvar_vclock]");

        if !has_vdso && !has_vvar && !has_vvar_vclock {
            continue;
        }

        let (start, end) = parse_address_range(line_str)?;

        if has_vdso {
            if s.vdso_start != VDSO_BAD_ADDR {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Got second vDSO entry",
                ));
            }
            s.vdso_start = start;
            s.sym.vdso_size = end - start;
        } else if has_vvar {
            if s.vvar_start != VVAR_BAD_ADDR {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Got second VVAR entry",
                ));
            }
            s.vvar_start = start;
            s.sym.vvar_size = end - start;
        } else {
            if s.vvar_start == VDSO_BAD_ADDR || s.vvar_start + s.sym.vvar_size != start {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VVAR and VVAR_VCLOCK entries are not subsequent",
                ));
            }
            s.sym.vvar_vclock_size = end - start;
            s.sym.vvar_size += s.sym.vvar_vclock_size;
        }
    }

    if s.vdso_start != VDSO_BAD_ADDR && s.vvar_start != VVAR_BAD_ADDR {
        s.sym.vdso_before_vvar = s.vdso_start < s.vvar_start;
    }

    Ok(())
}

fn parse_address_range(line: &str) -> io::Result<(usize, usize)> {
    let range_end = line.find(' ').unwrap_or(line.len());
    let range_str = &line[..range_end];

    let dash_pos = range_str.find('-').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Can't find vDSO/VVAR bounds")
    })?;

    let start =
        usize::from_str_radix(&range_str[..dash_pos], 16).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Can't parse start address")
        })?;

    let end = usize::from_str_radix(&range_str[dash_pos + 1..], 16).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "Can't parse end address")
    })?;

    Ok((start, end))
}

pub fn vdso_init_restore() -> io::Result<()> {
    let kdat = kdat();

    if kdat.vdso_sym.vdso_size == VDSO_BAD_SIZE {
        log::debug!("Kdat has empty vdso symtable - probably CONFIG_VDSO is not set");
        return Ok(());
    }

    // Already filled vdso_maps during kdat test
    {
        let maps = get_vdso_maps().read().unwrap();
        if maps.vdso_start != VDSO_BAD_ADDR {
            return Ok(());
        }
    }

    // Parsing self-maps here only to find vvar/vdso vmas in
    // criu's address space, for further remapping to restorer's
    // parking zone. Don't need to do this if map-vdso API
    // is present.
    if !kdat.can_map_vdso {
        let mut parsed_maps = VdsoMaps::default();
        vdso_parse_maps(PROC_SELF, &mut parsed_maps)?;

        {
            let mut maps = get_vdso_maps().write().unwrap();
            *maps = parsed_maps;
        }

        if !is_kdat_vdso_sym_valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Kdat sizes of vdso/vvar differ to maps file",
            ));
        }
    }

    {
        let mut maps = get_vdso_maps().write().unwrap();
        maps.sym = kdat.vdso_sym.clone();
    }

    Ok(())
}

pub fn vdso_is_present() -> bool {
    let maps = get_vdso_maps().read().unwrap();
    maps.vdso_start != VDSO_BAD_ADDR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdso_maps_default() {
        let maps = VdsoMaps::default();
        assert_eq!(maps.vdso_start, VDSO_BAD_ADDR);
        assert_eq!(maps.vvar_start, VVAR_BAD_ADDR);
        assert_eq!(maps.sym.vdso_size, VDSO_BAD_SIZE);
        assert_eq!(maps.sym.vvar_size, VVAR_BAD_SIZE);
        assert!(!maps.compatible);
    }

    #[test]
    fn test_parse_address_range() {
        let line = "7ffd2d5f0000-7ffd2d5f2000 r-xp 00000000 00:00 0                          [vdso]";
        let (start, end) = parse_address_range(line).unwrap();
        assert_eq!(start, 0x7ffd2d5f0000);
        assert_eq!(end, 0x7ffd2d5f2000);
    }

    #[test]
    fn test_parse_address_range_vvar() {
        let line = "7ffd2d5ec000-7ffd2d5f0000 r--p 00000000 00:00 0                          [vvar]";
        let (start, end) = parse_address_range(line).unwrap();
        assert_eq!(start, 0x7ffd2d5ec000);
        assert_eq!(end, 0x7ffd2d5f0000);
    }

    #[test]
    fn test_vdso_parse_maps_self() {
        let mut maps = VdsoMaps::default();
        let result = vdso_parse_maps(PROC_SELF, &mut maps);
        assert!(result.is_ok());
        // On a normal Linux system, vDSO should be present
        // but we don't assert this as it could vary
    }
}
