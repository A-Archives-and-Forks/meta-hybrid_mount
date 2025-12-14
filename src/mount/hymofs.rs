use std::ffi::CString;
use std::fs::File;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::fd::AsRawFd;
use std::path::Path;
use anyhow::{Context, Result};
use walkdir::WalkDir;
use crate::defs::HYMO_PROTOCOL_VERSION;

const DEV_PATH: &str = "/dev/hymo_ctl";
const HYMO_IOC_MAGIC: u8 = 0xE0;

const _IOC_NRBITS: u32 = 8;
const _IOC_TYPEBITS: u32 = 8;
const _IOC_SIZEBITS: u32 = 14;
const _IOC_DIRBITS: u32 = 2;

const _IOC_NRSHIFT: u32 = 0;
const _IOC_TYPESHIFT: u32 = _IOC_NRSHIFT + _IOC_NRBITS;
const _IOC_SIZESHIFT: u32 = _IOC_TYPESHIFT + _IOC_TYPEBITS;
const _IOC_DIRSHIFT: u32 = _IOC_SIZESHIFT + _IOC_SIZEBITS;

const _IOC_NONE: u32 = 0;
const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2;
const _IOC_READ_WRITE: u32 = 3;

macro_rules! _IOC {
    ($dir:expr, $type:expr, $nr:expr, $size:expr) => {
        (($dir) << _IOC_DIRSHIFT) |
        (($type) << _IOC_TYPESHIFT) |
        (($nr) << _IOC_NRSHIFT) |
        (($size) << _IOC_SIZESHIFT)
    };
}

macro_rules! _IO {
    ($type:expr, $nr:expr) => {
        _IOC!(_IOC_NONE, $type, $nr, 0)
    };
}

macro_rules! _IOR {
    ($type:expr, $nr:expr, $size:ty) => {
        _IOC!(_IOC_READ, $type, $nr, std::mem::size_of::<$size>() as u32)
    };
}

macro_rules! _IOW {
    ($type:expr, $nr:expr, $size:ty) => {
        _IOC!(_IOC_WRITE, $type, $nr, std::mem::size_of::<$size>() as u32)
    };
}

macro_rules! _IOWR {
    ($type:expr, $nr:expr, $size:ty) => {
        _IOC!(_IOC_READ_WRITE, $type, $nr, std::mem::size_of::<$size>() as u32)
    };
}

#[repr(C)]
struct HymoIoctlArg {
    src: *const libc::c_char,
    target: *const libc::c_char,
    r#type: libc::c_int,
}

#[allow(dead_code)]
#[repr(C)]
struct HymoIoctlListArg {
    buf: *mut libc::c_char,
    size: usize,
}

fn ioc_add_rule() -> libc::c_int { _IOW!(HYMO_IOC_MAGIC as u32, 1, HymoIoctlArg) as libc::c_int }
#[allow(dead_code)]
fn ioc_del_rule() -> libc::c_int { _IOW!(HYMO_IOC_MAGIC as u32, 2, HymoIoctlArg) as libc::c_int }
fn ioc_hide_rule() -> libc::c_int { _IOW!(HYMO_IOC_MAGIC as u32, 3, HymoIoctlArg) as libc::c_int }
#[allow(dead_code)]
fn ioc_inject_rule() -> libc::c_int { _IOW!(HYMO_IOC_MAGIC as u32, 4, HymoIoctlArg) as libc::c_int }
fn ioc_clear_all() -> libc::c_int { _IO!(HYMO_IOC_MAGIC as u32, 5) as libc::c_int }
fn ioc_get_version() -> libc::c_int { _IOR!(HYMO_IOC_MAGIC as u32, 6, libc::c_int) as libc::c_int }
#[allow(dead_code)]
fn ioc_list_rules() -> libc::c_int { _IOWR!(HYMO_IOC_MAGIC as u32, 7, HymoIoctlListArg) as libc::c_int }
fn ioc_set_debug() -> libc::c_int { _IOW!(HYMO_IOC_MAGIC as u32, 8, libc::c_int) as libc::c_int }

#[derive(Debug, PartialEq)]
pub enum HymoFsStatus {
    Available,
    NotPresent,
    ProtocolMismatch,
    KernelTooOld,
    ModuleTooOld,
}

pub struct HymoFs;

impl HymoFs {
    pub fn is_available() -> bool {
        Path::new(DEV_PATH).exists()
    }

    pub fn check_status() -> HymoFsStatus {
        if !Self::is_available() {
            return HymoFsStatus::NotPresent;
        }

        match Self::get_version() {
            Some(v) => {
                if v == HYMO_PROTOCOL_VERSION {
                    HymoFsStatus::Available
                } else if v < HYMO_PROTOCOL_VERSION {
                    HymoFsStatus::KernelTooOld
                } else {
                    HymoFsStatus::ModuleTooOld
                }
            },
            None => HymoFsStatus::ProtocolMismatch
        }
    }

    pub fn get_version() -> Option<i32> {
        let file = File::open(DEV_PATH).ok()?;
        let mut version: libc::c_int = 0;
        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), ioc_get_version() as _, &mut version)
        };
        if ret == 0 {
            Some(version as i32)
        } else {
            None
        }
    }

    pub fn set_debug(enable: bool) -> Result<()> {
        let file = File::open(DEV_PATH)?;
        let val: libc::c_int = if enable { 1 } else { 0 };
        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), ioc_set_debug() as _, &val)
        };
        if ret != 0 {
            anyhow::bail!("Failed to set debug mode, ioctl ret: {}", ret);
        }
        Ok(())
    }

    pub fn clear() -> Result<()> {
        let file = File::open(DEV_PATH).context("Failed to open HymoFS control device")?;
        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), ioc_clear_all() as _)
        };
        if ret != 0 {
            anyhow::bail!("Failed to clear rules, ioctl ret: {}", ret);
        }
        Ok(())
    }

    pub fn add_rule(src: &str, target: &str, type_: i32) -> Result<()> {
        let file = File::open(DEV_PATH)?;
        let c_src = CString::new(src)?;
        let c_target = CString::new(target)?;

        let arg = HymoIoctlArg {
            src: c_src.as_ptr(),
            target: c_target.as_ptr(),
            r#type: type_ as libc::c_int,
        };

        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), ioc_add_rule() as _, &arg)
        };
        if ret != 0 {
            anyhow::bail!("Failed to add rule, ioctl ret: {}", ret);
        }
        Ok(())
    }

    pub fn delete_rule(src: &str) -> Result<()> {
        let file = File::open(DEV_PATH)?;
        let c_src = CString::new(src)?;
        
        let arg = HymoIoctlArg {
            src: c_src.as_ptr(),
            target: std::ptr::null(),
            r#type: 0,
        };

        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), ioc_del_rule() as _, &arg)
        };
        if ret != 0 {
            anyhow::bail!("Failed to delete rule, ioctl ret: {}", ret);
        }
        Ok(())
    }

    pub fn hide_path(target: &str) -> Result<()> {
        let file = File::open(DEV_PATH)?;
        let c_target = CString::new(target)?;

        let arg = HymoIoctlArg {
            src: c_target.as_ptr(),
            target: std::ptr::null(),
            r#type: 0,
        };

        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), ioc_hide_rule() as _, &arg)
        };
        if ret != 0 {
            anyhow::bail!("Failed to hide path, ioctl ret: {}", ret);
        }
        Ok(())
    }

    pub fn get_active_rules() -> Result<String> {
        let file = File::open(DEV_PATH)?;
        let mut buf = vec![0u8; 128 * 1024]; 
        
        let mut arg = HymoIoctlListArg {
            buf: buf.as_mut_ptr() as *mut libc::c_char,
            size: buf.len(),
        };

        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), ioc_list_rules() as _, &mut arg)
        };

        if ret < 0 {
             anyhow::bail!("Failed to list rules, ioctl ret: {}", ret);
        }
        
        let len = ret as usize;
        if len > buf.len() {
             anyhow::bail!("Buffer too small for rules list");
        }
        
        buf.truncate(len);
        let s = String::from_utf8(buf).context("Invalid UTF-8 in rules list")?;
        Ok(s)
    }

    pub fn inject_directory(target_base: &Path, module_dir: &Path) -> Result<()> {
        if !module_dir.exists() || !module_dir.is_dir() {
            return Ok(());
        }

        for entry in WalkDir::new(module_dir).min_depth(1) {
            let entry = entry?;
            let current_path = entry.path();
            
            let rel_path = current_path.strip_prefix(module_dir)?;
            
            let target_path = target_base.join(rel_path);
            let target_str = target_path.to_string_lossy();
            let src_str = current_path.to_string_lossy();

            let metadata = entry.metadata()?;
            let file_type = metadata.file_type();

            if file_type.is_file() || file_type.is_symlink() {
                if let Err(e) = Self::add_rule(&target_str, &src_str, 0) {
                    log::warn!("Failed to add rule for {}: {}", target_str, e);
                }
            } else if file_type.is_char_device() {
                if metadata.rdev() == 0 {
                    if let Err(e) = Self::hide_path(&target_str) {
                        log::warn!("Failed to hide path {}: {}", target_str, e);
                    }
                }
            }
        }
        Ok(())
    }
}
