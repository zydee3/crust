#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptAction {
    PreDump = 0,
    PostDump,
    PreRestore,
    SetupNs,
    PostSetupNs,
    PostRestore,
    NetworkLock,
    NetworkUnlock,
    CleanUp,
    PreResume,
    PostResume,
    Max,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHook {
    PostForking = 0,
    ResumeDevicesLate,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrPluginStage {
    Dump = 0,
    Restore,
}

pub fn run_scripts(_act: ScriptAction) -> i32 {
    0
}

pub fn run_plugins(_hook: PluginHook, _pid: Option<libc::pid_t>) -> i32 {
    -libc::ENOTSUP
}

pub fn cr_plugin_init(_stage: CrPluginStage) -> i32 {
    0
}

pub fn cr_plugin_fini(_stage: CrPluginStage, _ret: i32) {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_scripts_stub() {
        assert_eq!(run_scripts(ScriptAction::PreRestore), 0);
        assert_eq!(run_scripts(ScriptAction::PostRestore), 0);
    }

    #[test]
    fn test_run_plugins_stub() {
        assert_eq!(run_plugins(PluginHook::PostForking, None), -libc::ENOTSUP);
    }

    #[test]
    fn test_cr_plugin_init_stub() {
        assert_eq!(cr_plugin_init(CrPluginStage::Restore), 0);
        assert_eq!(cr_plugin_init(CrPluginStage::Dump), 0);
    }
}
