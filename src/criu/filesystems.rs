use crate::proto::Fstype;

pub struct FsType {
    pub name: &'static str,
    pub code: i32,
}

impl FsType {
    const fn new(name: &'static str, code: i32) -> Self {
        Self { name, code }
    }
}

static FSTYPES: &[FsType] = &[
    FsType::new("unsupported", Fstype::Unsupported as i32),
    FsType::new("auto_cr", Fstype::Auto as i32),
    FsType::new("proc", Fstype::Proc as i32),
    FsType::new("sysfs", Fstype::Sysfs as i32),
    FsType::new("devtmpfs", Fstype::Devtmpfs as i32),
    FsType::new("binfmt_misc", Fstype::BinfmtMisc as i32),
    FsType::new("tmpfs", Fstype::Tmpfs as i32),
    FsType::new("devpts", Fstype::Devpts as i32),
    FsType::new("simfs", Fstype::Simfs as i32),
    // btrfs has code UNSUPPORTED in CRIU
    FsType::new("btrfs", Fstype::Unsupported as i32),
    FsType::new("pstore", Fstype::Pstore as i32),
    FsType::new("mqueue", Fstype::Mqueue as i32),
    FsType::new("securityfs", Fstype::Securityfs as i32),
    FsType::new("fusectl", Fstype::Fusectl as i32),
    FsType::new("debugfs", Fstype::Debugfs as i32),
    FsType::new("tracefs", Fstype::Tracefs as i32),
    FsType::new("cgroup", Fstype::Cgroup as i32),
    FsType::new("cgroup2", Fstype::Cgroup2 as i32),
    FsType::new("aufs", Fstype::Aufs as i32),
    FsType::new("fuse", Fstype::Fuse as i32),
    FsType::new("overlay", Fstype::Overlayfs as i32),
    FsType::new("autofs", Fstype::Autofs as i32),
];

pub fn decode_fstype(fst: i32) -> &'static FsType {
    if fst == Fstype::Unsupported as i32 {
        return &FSTYPES[0];
    }

    for fstype in FSTYPES.iter().skip(1) {
        if fstype.code == fst {
            return fstype;
        }
    }

    // Not found - return unsupported
    &FSTYPES[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_fstype_proc() {
        let fs = decode_fstype(Fstype::Proc as i32);
        assert_eq!(fs.name, "proc");
        assert_eq!(fs.code, Fstype::Proc as i32);
    }

    #[test]
    fn test_decode_fstype_tmpfs() {
        let fs = decode_fstype(Fstype::Tmpfs as i32);
        assert_eq!(fs.name, "tmpfs");
    }

    #[test]
    fn test_decode_fstype_unsupported() {
        let fs = decode_fstype(Fstype::Unsupported as i32);
        assert_eq!(fs.name, "unsupported");
    }

    #[test]
    fn test_decode_fstype_unknown() {
        // Unknown code should return unsupported
        let fs = decode_fstype(9999);
        assert_eq!(fs.name, "unsupported");
    }
}
