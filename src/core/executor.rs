use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use anyhow::Result;
use rayon::prelude::*;
use crate::{
    conf::config, 
    mount::{magic, overlay, hymofs::HymoFs}, 
    utils,
    core::planner::{MountPlan, OverlayOperation}
};

pub struct ExecutionResult {
    pub overlay_module_ids: Vec<String>,
    pub hymo_module_ids: Vec<String>,
    pub magic_module_ids: Vec<String>,
}

fn extract_id(path: &Path) -> Option<String> {
    path.parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().to_string())
}

fn extract_module_root(partition_path: &Path) -> Option<PathBuf> {
    partition_path.parent().map(|p| p.to_path_buf())
}

struct PendingOverlayItem {
    source: PathBuf,
    partition: String,
}

struct OverlayResult {
    magic_roots: Vec<PathBuf>,
    fallback_ids: Vec<String>,
    success_records: Vec<(PathBuf, String)>,
}

pub fn execute(plan: &MountPlan, config: &config::Config) -> Result<ExecutionResult> {
    let mut magic_queue = plan.magic_module_paths.clone();
    let mut global_success_map: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    
    let mut final_overlay_ids = HashSet::new();
    let mut final_hymo_ids = HashSet::new();
    
    plan.overlay_module_ids.iter().for_each(|id| { final_overlay_ids.insert(id.clone()); });
    plan.hymo_module_ids.iter().for_each(|id| { final_hymo_ids.insert(id.clone()); });

    let mut pending_hymo_fallbacks: Vec<PendingOverlayItem> = Vec::new();

    if !plan.hymo_ops.is_empty() {
        if HymoFs::is_available() {
            log::info!(">> Phase 1: HymoFS Injection...");
            if let Err(e) = HymoFs::clear() {
                log::warn!("Failed to reset HymoFS rules: {}", e);
            }

            for op in &plan.hymo_ops {
                let part_name = op.target.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                
                log::debug!("Injecting {} -> {}", op.source.display(), op.target.display());
                
                match HymoFs::inject_directory(&op.target, &op.source) {
                    Ok(_) => {
                        if let Some(root) = extract_module_root(&op.source) {
                            global_success_map.entry(root).or_default().insert(part_name);
                        }
                    },
                    Err(e) => {
                        log::error!("HymoFS failed for {}: {}. Queueing for Overlay.", op.module_id, e);
                        pending_hymo_fallbacks.push(PendingOverlayItem {
                            source: op.source.clone(),
                            partition: part_name,
                        });
                        final_hymo_ids.remove(&op.module_id);
                    }
                }
            }
        } else {
            log::warn!("!! HymoFS requested but kernel support is missing. Falling back to Overlay/Magic.");
            for op in &plan.hymo_ops {
                let part_name = op.target.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                pending_hymo_fallbacks.push(PendingOverlayItem {
                    source: op.source.clone(),
                    partition: part_name,
                });
                final_hymo_ids.remove(&op.module_id);
            }
        }
    }

    let mut merged_overlay_ops = plan.overlay_ops.clone();
    
    if !pending_hymo_fallbacks.is_empty() {
        log::info!(">> Phase 2: Merging {} Hymo failures into Overlay plan...", pending_hymo_fallbacks.len());
        
        for item in pending_hymo_fallbacks {
            if let Some(op) = merged_overlay_ops.iter_mut().find(|o| o.partition_name == item.partition) {
                op.lowerdirs.insert(0, item.source.clone());
            } else {
                let target_path = Path::new("/").join(&item.partition);
                if target_path.exists() {
                     merged_overlay_ops.push(OverlayOperation {
                        partition_name: item.partition,
                        target: target_path.to_string_lossy().to_string(),
                        lowerdirs: vec![item.source.clone()],
                    });
                } else {
                    log::warn!("Cannot fallback Hymo module for non-existent partition: {}", item.partition);
                    if let Some(root) = extract_module_root(&item.source) {
                        magic_queue.push(root);
                    }
                }
            }
            if let Some(id) = extract_id(&item.source) {
                final_overlay_ids.insert(id);
            }
        }
    }

    log::info!(">> Phase 3: OverlayFS Execution...");
    let overlay_results: Vec<OverlayResult> = merged_overlay_ops.par_iter()
        .map(|op| {
            let lowerdir_strings: Vec<String> = op.lowerdirs.iter()
                .map(|p: &PathBuf| p.display().to_string())
                .collect();
                
            log::info!("Mounting {} [OVERLAY] ({} layers)", op.target, lowerdir_strings.len());
            
            if let Err(e) = overlay::mount_overlay(&op.target, &lowerdir_strings, None, None, config.disable_umount) {
                log::warn!("OverlayFS failed for {}: {}. Triggering fallback.", op.target, e);
                
                let mut local_magic = Vec::new();
                let mut local_fallback_ids = Vec::new();

                for layer_path in &op.lowerdirs {
                    if let Some(root) = extract_module_root(layer_path) {
                        local_magic.push(root.clone());
                        if let Some(id) = extract_id(layer_path) {
                            local_fallback_ids.push(id);
                        }
                    }
                }
                return OverlayResult {
                    magic_roots: local_magic,
                    fallback_ids: local_fallback_ids,
                    success_records: Vec::new(),
                };
            }
            
            let mut successes = Vec::new();
            for layer_path in &op.lowerdirs {
                 if let Some(root) = extract_module_root(layer_path) {
                     successes.push((root, op.partition_name.clone()));
                 }
            }

            OverlayResult {
                magic_roots: Vec::new(),
                fallback_ids: Vec::new(),
                success_records: successes,
            }
        })
        .collect();

    for res in overlay_results {
        magic_queue.extend(res.magic_roots);
        
        for id in res.fallback_ids {
            final_overlay_ids.remove(&id); 
        }
        
        for (root, partition) in res.success_records {
            global_success_map.entry(root)
                .or_default()
                .insert(partition);
        }
    }

    magic_queue.sort();
    magic_queue.dedup();

    let mut final_magic_ids = Vec::new();

    if !magic_queue.is_empty() {
        let tempdir = if let Some(t) = &config.tempdir { 
            t.clone() 
        } else { 
            utils::select_temp_dir()? 
        };
        
        for path in &magic_queue {
            if let Some(name) = path.file_name() {
                final_magic_ids.push(name.to_string_lossy().to_string());
            }
        }
        
        log::info!(">> Phase 4: Magic Mount (Complementary Fallback) for {} modules...", magic_queue.len());
        
        utils::ensure_temp_dir(&tempdir)?;
        
        if let Err(e) = magic::mount_partitions(
            &tempdir, 
            &magic_queue, 
            &config.mountsource, 
            &config.partitions, 
            global_success_map, 
            config.disable_umount
        ) {
            log::error!("Magic Mount critical failure: {:#}", e);
            final_magic_ids.clear();
        }
        
        utils::cleanup_temp_dir(&tempdir);
    }

    let mut result_overlay = final_overlay_ids.into_iter().collect::<Vec<_>>();
    let mut result_hymo = final_hymo_ids.into_iter().collect::<Vec<_>>();
    let mut result_magic = final_magic_ids;

    result_overlay.sort();
    result_hymo.sort();
    result_magic.sort();
    result_magic.dedup();

    Ok(ExecutionResult {
        overlay_module_ids: result_overlay,
        hymo_module_ids: result_hymo,
        magic_module_ids: result_magic,
    })
}
