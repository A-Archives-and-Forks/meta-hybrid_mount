use std::{
    ffi::{CStr, CString},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result};
use log::{debug, warn};
use serde::Serialize;

const HYMO_MAGIC1: i32 = 0x48594D4F;
const HYMO_MAGIC2: i32 = 0x524F4F54;
const HYMO_PROTOCOL_VERSION: i32 = 7;

const HYMO_CMD_ADD_RULE: i32 = 0x48001;
const HYMO_CMD_DEL_RULE: i32 = 0x48002;
const HYMO_CMD_HIDE_RULE: i32 = 0x48003;
const HYMO_CMD_CLEAR_ALL: i32 = 0x48005;
const HYMO_CMD_GET_VERSION: i32 = 0x48006;
const HYMO_CMD_LIST_RULES: i32 = 0x48007;
const HYMO_CMD_SET_DEBUG: i32 = 0x48008;
const HYMO_CMD_REORDER_MNT_ID: i32 = 0x48009;
const HYMO_CMD_SET_STEALTH: i32 = 0x48010;
const HYMO_CMD_HIDE_OVERLAY_XATTRS: i32 = 0x48011;
const HYMO_CMD_ADD_MERGE_RULE: i32 = 0x48012;
const HYMO_CMD_SET_AVC_LOG_SPOOFING: i32 = 0x48013;

static IS_AVAILABLE: AtomicBool = AtomicBool::new(false);

#[repr(C)]
struct HymoSyscallArg {
    src: *const std::ffi::c_char,
    target: *const std::ffi::c_char,
    type_: std::ffi::c_int,
}

#[repr(C)]
struct HymoSyscallListArg {
    buf: *mut std::ffi::c_char,
    size: usize,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HymoFsStatus {
    Available,
    NotPresent,
    KernelTooOld,
    ModuleTooOld,
}

#[derive(Serialize, Default, Debug)]
pub struct HymoRuleRedirect {
    pub src: String,
    pub target: String,
    pub type_: i32,
}

#[derive(Serialize, Default, Debug)]
pub struct HymoRuleMerge {
    pub src: String,
    pub target: String,
}

#[derive(Serialize, Default, Debug)]
pub struct HymoRules {
    pub redirects: Vec<HymoRuleRedirect>,
    pub hides: Vec<String>,
    pub injects: Vec<String>,
    pub merges: Vec<HymoRuleMerge>,
    pub xattr_sbs: Vec<String>,
}

#[derive(Serialize, Default, Debug)]
pub struct HymoKernelStatus {
    pub available: bool,
    pub protocol_version: i32,
    pub config_version: i32,
    pub rules: HymoRules,
    pub stealth_active: bool,
    pub debug_active: bool,
}

pub struct HymoFs;

impl HymoFs {
    unsafe fn syscall(cmd: i32, arg: *const std::ffi::c_void) -> i32 {
        libc::syscall(
            libc::SYS_reboot,
            HYMO_MAGIC1 as std::ffi::c_int,
            HYMO_MAGIC2 as std::ffi::c_int,
            cmd as std::ffi::c_int,
            arg,
        ) as i32
    }

    pub fn check_status() -> HymoFsStatus {
        let version = unsafe { Self::syscall(HYMO_CMD_GET_VERSION, std::ptr::null()) };

        if version < 0 {
            IS_AVAILABLE.store(false, Ordering::Relaxed);
            return HymoFsStatus::NotPresent;
        }

        if version < HYMO_PROTOCOL_VERSION {
            warn!(
                "HymoFS: Kernel protocol version {} is too old (expected {})",
                version, HYMO_PROTOCOL_VERSION
            );
            return HymoFsStatus::KernelTooOld;
        }

        IS_AVAILABLE.store(true, Ordering::Relaxed);
        HymoFsStatus::Available
    }

    pub fn is_available() -> bool {
        if IS_AVAILABLE.load(Ordering::Relaxed) {
            return true;
        }
        Self::check_status() == HymoFsStatus::Available
    }

    pub fn get_version() -> Option<i32> {
        let version = unsafe { Self::syscall(HYMO_CMD_GET_VERSION, std::ptr::null()) };
        if version >= 0 { Some(version) } else { None }
    }

    pub fn clear() -> Result<()> {
        debug!("HymoFS: Clearing all rules");
        let ret = unsafe { Self::syscall(HYMO_CMD_CLEAR_ALL, std::ptr::null()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("HymoFS clear failed with code {}", ret))
        }
    }

    pub fn add_rule(src: &str, target: &str, type_val: i32) -> Result<()> {
        debug!(
            "HymoFS: ADD_RULE src='{}' target='{}' type={}",
            src, target, type_val
        );
        let c_src = CString::new(src)?;
        let c_target = CString::new(target)?;

        let arg = HymoSyscallArg {
            src: c_src.as_ptr(),
            target: c_target.as_ptr(),
            type_: type_val as std::ffi::c_int,
        };

        let ret = unsafe {
            Self::syscall(
                HYMO_CMD_ADD_RULE,
                &arg as *const _ as *const std::ffi::c_void,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("HymoFS add_rule failed"))
        }
    }

    pub fn add_merge_rule(src: &str, target: &str) -> Result<()> {
        debug!(
            "HymoFS: ADD_MERGE_RULE system='{}' module='{}'",
            src, target
        );
        let c_src = CString::new(src)?;
        let c_target = CString::new(target)?;

        let arg = HymoSyscallArg {
            src: c_src.as_ptr(),
            target: c_target.as_ptr(),
            type_: 0,
        };

        let ret = unsafe {
            Self::syscall(
                HYMO_CMD_ADD_MERGE_RULE,
                &arg as *const _ as *const std::ffi::c_void,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("HymoFS add_merge_rule failed"))
        }
    }

    #[allow(dead_code)]
    pub fn delete_rule(src: &str) -> Result<()> {
        debug!("HymoFS: DEL_RULE src='{}'", src);
        let c_src = CString::new(src)?;
        let arg = HymoSyscallArg {
            src: c_src.as_ptr(),
            target: std::ptr::null(),
            type_: 0,
        };
        let ret = unsafe {
            Self::syscall(
                HYMO_CMD_DEL_RULE,
                &arg as *const _ as *const std::ffi::c_void,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("HymoFS delete_rule failed"))
        }
    }

    pub fn hide_path(path: &str) -> Result<()> {
        debug!("HymoFS: HIDE_RULE path='{}'", path);
        let c_path = CString::new(path)?;
        let arg = HymoSyscallArg {
            src: c_path.as_ptr(),
            target: std::ptr::null(),
            type_: 0,
        };
        let ret = unsafe {
            Self::syscall(
                HYMO_CMD_HIDE_RULE,
                &arg as *const _ as *const std::ffi::c_void,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("HymoFS hide_path failed"))
        }
    }

    #[allow(dead_code)]
    pub fn list_active_rules() -> Result<String> {
        let capacity = 128 * 1024;
        let mut buffer = vec![0u8; capacity];
        let mut arg = HymoSyscallListArg {
            buf: buffer.as_mut_ptr() as *mut std::ffi::c_char,
            size: capacity,
        };

        let ret = unsafe {
            Self::syscall(
                HYMO_CMD_LIST_RULES,
                &mut arg as *mut _ as *mut std::ffi::c_void,
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!("HymoFS list_rules failed"));
        }

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const std::ffi::c_char) };
        Ok(c_str.to_string_lossy().into_owned())
    }

    pub fn get_kernel_status() -> Result<HymoKernelStatus> {
        if !Self::is_available() {
            return Ok(HymoKernelStatus {
                available: false,
                ..Default::default()
            });
        }

        let mut status = HymoKernelStatus {
            available: true,
            stealth_active: false,
            debug_active: false,
            ..Default::default()
        };

        if let Some(v) = Self::get_version() {
            status.protocol_version = v;
        }

        let raw_info = match Self::list_active_rules() {
            Ok(info) => info,
            Err(e) => {
                warn!("HymoFS list rules failed: {}", e);
                return Ok(status);
            }
        };

        for line in raw_info.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "HymoFS" => {
                    if parts.len() >= 4 && parts[1] == "Atomiconfig" && parts[2] == "Version:" {
                        status.config_version = parts[3].parse().unwrap_or(0);
                    }
                }
                "add" => {
                    if parts.len() >= 4 {
                        status.rules.redirects.push(HymoRuleRedirect {
                            src: parts[1].to_string(),
                            target: parts[2].to_string(),
                            type_: parts[3].parse().unwrap_or(0),
                        });
                    }
                }
                "hide" => {
                    if parts.len() >= 2 {
                        status.rules.hides.push(parts[1].to_string());
                    }
                }
                "inject" => {
                    if parts.len() >= 2 {
                        status.rules.injects.push(parts[1].to_string());
                    }
                }
                "merge" => {
                    if parts.len() >= 3 {
                        status.rules.merges.push(HymoRuleMerge {
                            src: parts[1].to_string(),
                            target: parts[2].to_string(),
                        });
                    }
                }
                "hide_xattr_sb" => {
                    if parts.len() >= 2 {
                        status.rules.xattr_sbs.push(parts[1].to_string());
                    }
                }
                _ => {}
            }
        }

        Ok(status)
    }

    pub fn inject_directory(target_base: &Path, module_dir: &Path) -> Result<()> {
        if !module_dir.exists() {
            return Ok(());
        }

        if module_dir.is_dir() {
            debug!(
                "HymoFS: MERGE_RULE dir: {} -> {}",
                module_dir.display(),
                target_base.display()
            );
            if let Err(e) = Self::add_merge_rule(
                &target_base.to_string_lossy(),
                &module_dir.to_string_lossy(),
            ) {
                warn!(
                    "Failed to add merge rule for {}: {}",
                    target_base.display(),
                    e
                );
            }
            return Ok(());
        }

        debug!(
            "HymoFS: ADD_RULE file: {} -> {}",
            module_dir.display(),
            target_base.display()
        );
        if let Err(e) = Self::add_rule(
            &target_base.to_string_lossy(),
            &module_dir.to_string_lossy(),
            0,
        ) {
            warn!("Failed to add rule for {}: {}", target_base.display(), e);
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn delete_directory_rules(_target_base: &Path, _module_dir: &Path) -> Result<()> {
        Ok(())
    }

    pub fn set_debug(enable: bool) -> Result<()> {
        let val: i32 = if enable { 1 } else { 0 };
        unsafe {
            Self::syscall(
                HYMO_CMD_SET_DEBUG,
                &val as *const _ as *const std::ffi::c_void,
            )
        };
        Ok(())
    }

    pub fn set_stealth(enable: bool) -> Result<()> {
        let val: i32 = if enable { 1 } else { 0 };
        unsafe {
            Self::syscall(
                HYMO_CMD_SET_STEALTH,
                &val as *const _ as *const std::ffi::c_void,
            )
        };
        Ok(())
    }

    pub fn set_avc_log_spoofing(enable: bool) -> Result<()> {
        let val: i32 = if enable { 1 } else { 0 };
        let arg = HymoSyscallArg {
            src: std::ptr::null(),
            target: std::ptr::null(),
            type_: val as std::ffi::c_int,
        };

        unsafe {
            Self::syscall(
                HYMO_CMD_SET_AVC_LOG_SPOOFING,
                &arg as *const _ as *const std::ffi::c_void,
            )
        };
        Ok(())
    }

    pub fn hide_overlay_xattrs(path: &str) -> Result<()> {
        debug!("HymoFS: HIDE_XATTRS path='{}'", path);
        let c_path = CString::new(path)?;

        let arg = HymoSyscallArg {
            src: c_path.as_ptr(),
            target: std::ptr::null(),
            type_: 0,
        };

        unsafe {
            Self::syscall(
                HYMO_CMD_HIDE_OVERLAY_XATTRS,
                &arg as *const _ as *const std::ffi::c_void,
            )
        };
        Ok(())
    }

    pub fn reorder_mnt_id() -> Result<()> {
        unsafe { Self::syscall(HYMO_CMD_REORDER_MNT_ID, std::ptr::null()) };
        Ok(())
    }
}
