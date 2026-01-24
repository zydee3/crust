pub fn cpu_init() -> i32 {
    0
}

pub fn cpu_validate_cpuinfo() -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_init_stub() {
        assert_eq!(cpu_init(), 0);
    }

    #[test]
    fn test_cpu_validate_cpuinfo_stub() {
        assert_eq!(cpu_validate_cpuinfo(), 0);
    }
}
