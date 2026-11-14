use std::collections::BTreeMap;
use std::fs::{self};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::Config;
use crate::model::*;

pub(crate) fn build_manifest(
    config: &Config,
    old_functions: usize,
    new_functions: usize,
    exact: usize,
    entries: Vec<ChangedFunction>,
    js_decompile: JsDecompileStats,
) -> Manifest {
    let mut inputs = BTreeMap::new();
    inputs.insert(
        "old".to_string(),
        config
            .old_label
            .clone()
            .unwrap_or_else(|| config.old_path.display().to_string()),
    );
    inputs.insert(
        "new".to_string(),
        config
            .new_label
            .clone()
            .unwrap_or_else(|| config.new_path.display().to_string()),
    );

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "old_sqlite".to_string(),
        "artifacts/hermes/old.sqlite".to_string(),
    );
    artifacts.insert(
        "new_sqlite".to_string(),
        "artifacts/hermes/new.sqlite".to_string(),
    );
    artifacts.insert("diff".to_string(), "artifacts/hermes/diff.json".to_string());

    let stats = ManifestStats {
        old_functions,
        new_functions,
        exact,
        partial: entries.iter().filter(|e| e.kind == "partial").count(),
        new: entries.iter().filter(|e| e.kind == "new").count(),
        deleted: entries.iter().filter(|e| e.kind == "deleted").count(),
        js_decompile,
    };

    Manifest {
        generated_at: now_string(),
        mode: "hermes".to_string(),
        inputs,
        artifacts,
        stats,
        functions: entries,
    }
}

pub(crate) fn now_string() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("unix:{}", d.as_secs()))
        .unwrap_or_else(|_| "unix:0".to_string())
}

pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
