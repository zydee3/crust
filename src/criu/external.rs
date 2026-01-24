use std::ptr;

pub struct External {
    pub id: String,
    pub data: Option<*mut libc::c_void>,
}

impl External {
    pub fn new(id: String) -> Self {
        Self { id, data: None }
    }

    pub fn with_data(id: String, data: *mut libc::c_void) -> Self {
        Self {
            id,
            data: Some(data),
        }
    }
}

pub enum ExternalLookupResult<'a> {
    Found(&'a str),
    FoundNoValue,
    NotFound,
}

pub fn external_lookup_by_key<'a>(externals: &'a [External], key: &str) -> ExternalLookupResult<'a> {
    let key_len = key.len();

    for ext in externals {
        if !ext.id.starts_with(key) {
            continue;
        }

        let id_bytes = ext.id.as_bytes();
        if id_bytes.len() > key_len {
            if id_bytes[key_len] == b':' {
                return ExternalLookupResult::Found(&ext.id[key_len + 1..]);
            }
        } else if id_bytes.len() == key_len {
            return ExternalLookupResult::FoundNoValue;
        }
    }

    ExternalLookupResult::NotFound
}

pub fn external_lookup_by_key_raw<'a>(
    externals: &'a [External],
    key: &str,
) -> *const u8 {
    match external_lookup_by_key(externals, key) {
        ExternalLookupResult::Found(value) => value.as_ptr(),
        ExternalLookupResult::FoundNoValue => ptr::null(),
        ExternalLookupResult::NotFound => {
            (-(libc::ENOENT as isize)) as usize as *const u8
        }
    }
}

pub fn is_err_ptr(ptr: *const u8) -> bool {
    (ptr as usize) >= (usize::MAX - 4095)
}

pub fn ptr_err(ptr: *const u8) -> i32 {
    -(ptr as isize) as i32
}

pub fn external_for_each_type<F>(externals: &[External], type_prefix: &str, mut cb: F) -> i32
where
    F: FnMut(&External) -> i32,
{
    let ln = type_prefix.len();

    for ext in externals {
        if !ext.id.starts_with(type_prefix) {
            continue;
        }

        let id_bytes = ext.id.as_bytes();
        if id_bytes.len() <= ln || id_bytes[ln] != b'[' {
            continue;
        }

        let ret = cb(ext);
        if ret != 0 {
            return ret;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_lookup_found_with_value() {
        let externals = vec![
            External::new("mnt[100]:/host/path".to_string()),
            External::new("dev[/dev/sda]:disk1".to_string()),
        ];

        match external_lookup_by_key(&externals, "mnt[100]") {
            ExternalLookupResult::Found(value) => assert_eq!(value, "/host/path"),
            _ => panic!("Expected Found with value"),
        }
    }

    #[test]
    fn test_external_lookup_found_no_value() {
        let externals = vec![External::new("mnt[100]".to_string())];

        match external_lookup_by_key(&externals, "mnt[100]") {
            ExternalLookupResult::FoundNoValue => {}
            _ => panic!("Expected FoundNoValue"),
        }
    }

    #[test]
    fn test_external_lookup_not_found() {
        let externals = vec![External::new("mnt[100]:/path".to_string())];

        match external_lookup_by_key(&externals, "mnt[200]") {
            ExternalLookupResult::NotFound => {}
            _ => panic!("Expected NotFound"),
        }
    }

    #[test]
    fn test_external_lookup_prefix_not_match() {
        let externals = vec![External::new("mnt[100]extra:/path".to_string())];

        match external_lookup_by_key(&externals, "mnt[100]") {
            ExternalLookupResult::NotFound => {}
            _ => panic!("Expected NotFound for prefix mismatch"),
        }
    }

    #[test]
    fn test_external_for_each_type_matches() {
        let externals = vec![
            External::new("veth[eth0]:br0".to_string()),
            External::new("mnt[100]:/path".to_string()),
            External::new("veth[eth1]:br1".to_string()),
        ];

        let mut matched = Vec::new();
        let ret = external_for_each_type(&externals, "veth", |ext| {
            matched.push(ext.id.clone());
            0
        });

        assert_eq!(ret, 0);
        assert_eq!(matched, vec!["veth[eth0]:br0", "veth[eth1]:br1"]);
    }

    #[test]
    fn test_external_for_each_type_callback_abort() {
        let externals = vec![
            External::new("veth[eth0]:br0".to_string()),
            External::new("veth[eth1]:br1".to_string()),
        ];

        let mut count = 0;
        let ret = external_for_each_type(&externals, "veth", |_ext| {
            count += 1;
            -1 // Return non-zero to abort
        });

        assert_eq!(ret, -1);
        assert_eq!(count, 1); // Only called once before abort
    }

    #[test]
    fn test_external_for_each_type_no_matches() {
        let externals = vec![
            External::new("mnt[100]:/path".to_string()),
            External::new("dev[sda]:disk".to_string()),
        ];

        let mut count = 0;
        let ret = external_for_each_type(&externals, "veth", |_ext| {
            count += 1;
            0
        });

        assert_eq!(ret, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_external_for_each_type_no_bracket() {
        // "vethfoo" doesn't have '[' after "veth", so shouldn't match
        let externals = vec![External::new("vethfoo:bar".to_string())];

        let mut count = 0;
        let ret = external_for_each_type(&externals, "veth", |_ext| {
            count += 1;
            0
        });

        assert_eq!(ret, 0);
        assert_eq!(count, 0);
    }
}
