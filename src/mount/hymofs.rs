use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use anyhow::{Context, Result};
use log::{debug, warn};
use walkdir::WalkDir;
use serde::Serialize;
use nix::{ioctl_write_ptr, ioctl_read, ioctl_none, ioctl_readwrite, ioctl_write_int};

const DEV_PATH: &str = "/dev/hymo_ctl";
const HYMO_IOC_MAGIC: u8 = 0xE0;

#[repr(C)]
struct HymoIoctlArg {
    src: *const libc::c_char,
    target: *const libc::c_char,
    r#type: libc::c_int,
}

#[repr(C)]
struct HymoIoctlListArg {
    buf: *mut libc::c_char,
    size: usize,
}

ioctl_write_ptr!(ioc_add_rule, HYMO_IOC_MAGIC, 1, HymoIoctlArg);
ioctl_write_ptr!(ioc_del_rule, HYMO_IOC_MAGIC, 2, HymoIoctlArg);
ioctl_write_ptr!(ioc_hide_rule, HYMO_IOC_MAGIC, 3, HymoIoctlArg);
ioctl_none!(ioc_clear_all, HYMO_IOC_MAGIC, 5);
ioctl_readwrite!(ioc_list_rules, HYMO_IOC_MAGIC, 7, HymoIoctlListArg);
ioctl_write_ptr!(ioc_set_debug, HYMO_IOC_MAGIC, 8, libc::c_int);

pub struct HymoFs;

impl HymoFs {
    fn open_dev() -> Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEV_PATH)
            .with_context(|| format!("Failed to open {}", DEV_PATH))
    }

    pub fn is_available() -> bool {
        Path::new(DEV_PATH).exists()
    }

    pub fn set_debug(enable: bool) -> Result<()> {
        let file = Self::open_dev()?;
        let val: libc::c_int = if enable { 1 } else { 0 };
        
        unsafe { ioc_set_debug(file.as_raw_fd(), &val) }
            .context("Failed to set debug mode")?;
        Ok(())
    }

    pub fn clear() -> Result<()> {
        let file = Self::open_dev().context("Failed to open HymoFS control device")?;
        
        unsafe { ioc_clear_all(file.as_raw_fd()) }
            .context("Failed to clear rules")?;
        Ok(())
    }

    pub fn add_rule(src: &str, target: &str, type_val: i32) -> Result<()> {
        let file = Self::open_dev()?;
        let c_src = CString::new(src)?;
        let c_target = CString::new(target)?;

        let arg = HymoIoctlArg {
            src: c_src.as_ptr(),
            target: c_target.as_ptr(),
            r#type: type_val as libc::c_int,
        };

        unsafe { ioc_add_rule(file.as_raw_fd(), &arg) }
            .context("Failed to add rule")?;
        Ok(())
    }

    pub fn delete_rule(src: &str) -> Result<()> {
        let file = Self::open_dev()?;
        let c_src = CString::new(src)?;
        
        let arg = HymoIoctlArg {
            src: c_src.as_ptr(),
            target: std::ptr::null(),
            r#type: 0,
        };

        unsafe { ioc_del_rule(file.as_raw_fd(), &arg) }
            .context("Failed to delete rule")?;
        Ok(())
    }

    pub fn hide_path(target: &str) -> Result<()> {
        let file = Self::open_dev()?;
        let c_target = CString::new(target)?;

        let arg = HymoIoctlArg {
            src: c_target.as_ptr(),
            target: std::ptr::null(),
            r#type: 0,
        };

        unsafe { ioc_hide_rule(file.as_raw_fd(), &arg) }
            .context("Failed to hide path")?;
        Ok(())
    }

    pub fn get_active_rules() -> Result<String> {
        let file = Self::open_dev()?;
        let mut buf = vec![0u8; 128 * 1024]; 
        
        let mut arg = HymoIoctlListArg {
            buf: buf.as_mut_ptr() as *mut libc::c_char,
            size: buf.len(),
        };

        let ret = unsafe { ioc_list_rules(file.as_raw_fd(), &mut arg) }
            .context("Failed to list rules")?;

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
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("HymoFS walk error: {}", e);
                    continue;
                }
            };

            let current_path = entry.path().to_path_buf();
            let relative_path = match current_path.strip_prefix(module_dir) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let target_path = target_base.join(relative_path);
            let file_type = entry.file_type();

            if file_type.is_file() || file_type.is_symlink() {
                let target_str = target_path.to_string_lossy();
                let src_str = current_path.to_string_lossy();
                if let Err(e) = Self::add_rule(&target_str, &src_str, 0) {
                    warn!("Failed to add rule for {}: {}", target_str, e);
                }
            } else if file_type.is_char_device() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.rdev() == 0 {
                        let target_str = target_path.to_string_lossy();
                        if let Err(e) = Self::hide_path(&target_str) {
                            warn!("Failed to hide path {}: {}", target_str, e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    #[allow(dead_code)]
    pub fn delete_directory_rules(target_base: &Path, module_dir: &Path) -> Result<()> {
        if !module_dir.exists() || !module_dir.is_dir() {
            return Ok(());
        }

        for entry in WalkDir::new(module_dir).min_depth(1) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("HymoFS walk error: {}", e);
                    continue;
                }
            };

            let current_path = entry.path().to_path_buf();
            let relative_path = match current_path.strip_prefix(module_dir) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let target_path = target_base.join(relative_path);
            let target_str = target_path.to_string_lossy();
            let file_type = entry.file_type();

            if file_type.is_file() || file_type.is_symlink() {
                if let Err(e) = Self::delete_rule(&target_str) {
                    warn!("Failed to delete rule for {}: {}", target_str, e);
                }
            } else if file_type.is_char_device() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.rdev() == 0 {
                        if let Err(e) = Self::delete_rule(&target_str) {
                            warn!("Failed to delete hidden rule for {}: {}", target_str, e);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
