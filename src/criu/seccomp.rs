use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::protobuf::pb_read_one_eof;
use crate::proto::SeccompEntry;

static SECCOMP_IMG_ENTRY: OnceLock<Option<SeccompEntry>> = OnceLock::new();

pub fn get_seccomp_img_entry() -> Option<&'static SeccompEntry> {
    SECCOMP_IMG_ENTRY.get().and_then(|opt| opt.as_ref())
}

pub fn seccomp_read_image(dfd: RawFd) -> i32 {
    let mut img = match open_image(dfd, CrFdType::Seccomp, "") {
        Ok(img) => img,
        Err(_) => return -1,
    };

    let ret = pb_read_one_eof::<SeccompEntry>(&mut img);
    close_image(&mut img);

    match ret {
        Ok(Some(entry)) => {
            let _ = SECCOMP_IMG_ENTRY.set(Some(entry));
        }
        Ok(None) => {
            // there were no filters
            let _ = SECCOMP_IMG_ENTRY.set(None);
        }
        Err(_) => {
            return -1;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_entry_init() {
        // Initially no entry should be set
        assert!(get_seccomp_img_entry().is_none());
    }
}
