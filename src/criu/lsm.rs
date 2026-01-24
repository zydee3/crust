use super::kerndat::kdat;
use super::options::opts;

pub const LSMTYPE_NO_LSM: i32 = 0;
pub const LSMTYPE_SELINUX: i32 = 1;
pub const LSMTYPE_APPARMOR: i32 = 2;

pub fn lsm_check_opts() -> Result<Option<String>, i32> {
    let options = opts();

    if !options.lsm_supplied {
        return Ok(None);
    }

    let profile = match &options.lsm_profile {
        Some(p) => p,
        None => {
            log::error!("lsm_supplied but no lsm_profile");
            return Err(-1);
        }
    };

    let colon_pos = match profile.find(':') {
        Some(pos) => pos,
        None => {
            log::error!("invalid argument {} for --lsm-profile", profile);
            return Err(-1);
        }
    };

    let lsm_name = &profile[..colon_pos];
    let lsm_profile = &profile[colon_pos + 1..];

    if lsm_name == "apparmor" {
        if kdat().lsm != LSMTYPE_APPARMOR {
            log::error!("apparmor LSM specified but apparmor not supported by kernel");
            return Err(-1);
        }
        Ok(Some(lsm_profile.to_string()))
    } else if lsm_name == "selinux" {
        if kdat().lsm != LSMTYPE_SELINUX {
            log::error!("selinux LSM specified but selinux not supported by kernel");
            return Err(-1);
        }
        Ok(Some(lsm_profile.to_string()))
    } else if lsm_name == "none" {
        Ok(None)
    } else {
        log::error!("unknown lsm {}", lsm_name);
        Err(-1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsmtype_constants() {
        assert_eq!(LSMTYPE_NO_LSM, 0);
        assert_eq!(LSMTYPE_SELINUX, 1);
        assert_eq!(LSMTYPE_APPARMOR, 2);
    }
}
