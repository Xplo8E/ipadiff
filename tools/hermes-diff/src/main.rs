//! hermes-diff: CLI entry point and run orchestration.
mod diff;
mod js;
mod manifest;
mod model;
mod records;
mod report;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use diff::{diff_functions, filter_weak_hermes_partials};
use js::prepare_js_decompilers;
use manifest::{build_manifest, write_json};
use records::{export_sqlite, load_bundle};
use report::{render_entries, write_readme};

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) old_path: PathBuf,
    pub(crate) new_path: PathBuf,
    pub(crate) old_label: Option<String>,
    pub(crate) new_label: Option<String>,
    pub(crate) out_dir: PathBuf,
    pub(crate) max_functions: Option<usize>,
    pub(crate) js_decompile: bool,
}

pub(crate) fn main() -> Result<()> {
    let config = parse_args()?;
    run(config)
}

pub(crate) fn parse_args() -> Result<Config> {
    let mut old_path = None;
    let mut new_path = None;
    let mut old_label = None;
    let mut new_label = None;
    let mut out_dir = None;
    let mut max_functions = None;
    let mut js_decompile = true;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--old" => old_path = args.next().map(PathBuf::from),
            "--new" => new_path = args.next().map(PathBuf::from),
            "--old-label" => old_label = args.next(),
            "--new-label" => new_label = args.next(),
            "--out-dir" => out_dir = args.next().map(PathBuf::from),
            "--max-functions" => {
                max_functions = Some(
                    args.next()
                        .context("missing value for --max-functions")?
                        .parse()
                        .context("invalid --max-functions")?,
                );
            }
            "--html" => {}
            "--no-js-decompile" => js_decompile = false,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let config = Config {
        old_path: old_path.context("missing --old")?,
        new_path: new_path.context("missing --new")?,
        old_label,
        new_label,
        out_dir: out_dir.context("missing --out-dir")?,
        max_functions,
        js_decompile,
    };

    ensure_exists(&config.old_path, "old Hermes bundle")?;
    ensure_exists(&config.new_path, "new Hermes bundle")?;
    Ok(config)
}

pub(crate) fn print_usage() {
    eprintln!(
        "Usage: hermes-diff --old <old.hbc|main.jsbundle> --new <new.hbc|main.jsbundle> --out-dir <dir> [--old-label TEXT] [--new-label TEXT] [--max-functions N] [--no-js-decompile]"
    );
}

pub(crate) fn ensure_exists(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        bail!("{label} not found: {}", path.display());
    }
    Ok(())
}

pub(crate) fn run(config: Config) -> Result<()> {
    fs::create_dir_all(&config.out_dir)?;
    let artifacts_dir = config.out_dir.join("artifacts");
    let hermes_dir = artifacts_dir.join("hermes");
    let functions_dir = config.out_dir.join("functions");
    if functions_dir.exists() {
        fs::remove_dir_all(&functions_dir)
            .with_context(|| format!("failed to clear {}", functions_dir.display()))?;
    }
    fs::create_dir_all(&functions_dir)?;
    fs::create_dir_all(&hermes_dir)?;

    println!("[stage] hermes_export:old");
    let old = load_bundle(&config.old_path)?;
    export_sqlite(&old, &hermes_dir.join("old.sqlite"))?;
    println!("[stage] hermes_export:new");
    let new = load_bundle(&config.new_path)?;
    export_sqlite(&new, &hermes_dir.join("new.sqlite"))?;

    println!("[stage] hermes_diff");
    let (mut entries, exact_count) = diff_functions(&old, &new);
    if let Some(limit) = config.max_functions {
        entries.truncate(limit);
    }

    let raw_entries = entries.clone();
    write_json(
        &artifacts_dir.join("changed-functions.raw.json"),
        &raw_entries,
    )?;
    let (mut entries, filtered_entries) = filter_weak_hermes_partials(entries, &old, &new);
    write_json(
        &artifacts_dir.join("changed-functions.filtered.json"),
        &filtered_entries,
    )?;

    let mut js_decompilers = prepare_js_decompilers(&config);
    render_entries(
        &mut entries,
        &old,
        &new,
        &config.out_dir,
        &mut js_decompilers,
    )?;
    write_json(&artifacts_dir.join("changed-functions.json"), &entries)?;
    write_json(&hermes_dir.join("diff.json"), &entries)?;

    let manifest = build_manifest(
        &config,
        old.len(),
        new.len(),
        exact_count,
        entries,
        js_decompilers.stats,
    );
    write_json(&config.out_dir.join("manifest.json"), &manifest)?;
    write_readme(&config.out_dir, &manifest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::{diff::*, js::*, manifest::*, model::*, records::*, report::*};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn func(id: u32, name: Option<&str>, text: &str) -> FunctionRecord {
        let instructions = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .enumerate()
            .map(|(index, line)| InstructionRecord {
                index,
                offset: index as u32,
                opcode: line
                    .split_whitespace()
                    .next()
                    .unwrap_or("Unknown")
                    .to_string(),
                formatted_text: line.to_string(),
                normalized_text: normalize_instruction_text(line),
            })
            .collect::<Vec<_>>();
        let normalized_material = instructions
            .iter()
            .map(|instr| instr.normalized_text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let instruction_hash = hash_text(&normalized_material);
        FunctionRecord {
            id,
            name: name.map(str::to_string),
            display_name: name.unwrap_or("unnamed").to_string(),
            offset: id * 10,
            param_count: 0,
            register_count: 0,
            symbol_count: 0,
            bytecode_size: text.len() as u32,
            header_type: "Small".to_string(),
            instruction_count: text.lines().count(),
            opcode_hash: hash_text("op"),
            instruction_hash: instruction_hash.clone(),
            string_refs_hash: hash_text(""),
            function_refs_hash: hash_text(""),
            text: text.to_string(),
            instructions,
        }
    }

    fn filtered_partial_count(old_text: &str, new_text: &str) -> usize {
        let old = vec![func(1, Some("a"), old_text)];
        let new = vec![func(1, Some("a"), new_text)];
        let (entries, _) = diff_functions(&old, &new);
        let (_, filtered) = filter_weak_hermes_partials(entries, &old, &new);
        filtered.len()
    }

    #[test]
    fn unchanged_same_id_is_suppressed() {
        let old = vec![func(1, Some("a"), "LoadConstZero\nRet\n")];
        let new = vec![func(1, Some("a"), "LoadConstZero\nRet\n")];
        let (entries, exact) = diff_functions(&old, &new);
        assert_eq!(exact, 1);
        assert!(entries.is_empty());
    }

    #[test]
    fn changed_same_id_is_partial() {
        let old = vec![func(1, Some("a"), "LoadConstZero\nRet\n")];
        let new = vec![func(1, Some("a"), "LoadConstUInt8 1\nRet\n")];
        let (entries, exact) = diff_functions(&old, &new);
        assert_eq!(exact, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "partial");
    }

    #[test]
    fn one_sided_functions_are_reported() {
        let old = vec![func(1, Some("old"), "Ret\n")];
        let new = vec![func(2, Some("new"), "Ret\n")];
        let (entries, exact) = diff_functions(&old, &new);
        assert_eq!(exact, 0);
        assert_eq!(entries.iter().filter(|e| e.kind == "deleted").count(), 1);
        assert_eq!(entries.iter().filter(|e| e.kind == "new").count(), 1);
    }

    #[test]
    fn same_id_name_mismatch_is_not_partial() {
        let old = vec![func(1, Some("old_name"), "LoadConstZero\nRet\n")];
        let new = vec![func(1, Some("new_name"), "LoadConstTrue\nRet\n")];
        let (entries, exact) = diff_functions(&old, &new);
        assert_eq!(exact, 0);
        assert_eq!(entries.iter().filter(|e| e.kind == "deleted").count(), 1);
        assert_eq!(entries.iter().filter(|e| e.kind == "new").count(), 1);
    }

    #[test]
    fn same_id_duplicate_name_mismatch_uses_ordinal_matching() {
        let old = vec![
            func(10, Some("Button"), "old_a\nRet\n"),
            func(11, Some("Button"), "old_b\nRet\n"),
        ];
        let new = vec![
            func(10, Some("Button"), "old_b\nRet\n"),
            func(12, Some("Button"), "new_b\nRet\n"),
        ];
        let (entries, exact) = diff_functions(&old, &new);
        assert_eq!(exact, 0);
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .any(|entry| entry.old_id == Some(10) && entry.new_id == Some(10))
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.old_id == Some(11) && entry.new_id == Some(12))
        );
    }

    #[test]
    fn normalization_ignores_shifted_table_indices() {
        assert_eq!(
            normalize_instruction_text(r#"GetById  r8,  r6,  1,  "animating""#),
            normalize_instruction_text(r#"GetById  r8,  r6,  99,  "animating""#),
        );
        assert_eq!(
            normalize_instruction_text("NewObjectWithBuffer  r2,  6,  6,  910,  11542"),
            normalize_instruction_text("NewObjectWithBufferLong  r2,  6,  6,  913,  11564"),
        );
        assert_eq!(
            normalize_instruction_text("NewArrayWithBuffer  r2,  2,  2,  88"),
            normalize_instruction_text("NewArrayWithBufferLong  r2,  2,  2,  67855"),
        );
        assert_eq!(
            normalize_instruction_text("CreateClosure  r4,  r7,  Function<$FUNC_36956>"),
            normalize_instruction_text("CreateClosure  r4,  r7,  Function<$FUNC_36969>"),
        );
    }

    #[test]
    fn js_decompile_stats_count_only_real_attempts() {
        let mut stats = JsDecompileStats::disabled();
        stats.enabled = true;

        record_js_result(&mut stats, &JsDecompileResult::Ok("x\n".to_string()));
        record_js_result(&mut stats, &JsDecompileResult::Error("bad".to_string()));
        record_js_result(&mut stats, &JsDecompileResult::Panic("boom".to_string()));
        record_js_result(
            &mut stats,
            &JsDecompileResult::Skipped("no context".to_string()),
        );

        assert_eq!(stats.attempted, 3);
        assert_eq!(stats.success, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.panicked, 1);
    }

    #[test]
    fn duplicate_stable_names_match_by_ordinal() {
        let old = vec![
            func(10, Some("ComponentName"), "LoadConstZero\nRet\n"),
            func(20, Some("ComponentName"), "LoadConstTrue\nRet\n"),
        ];
        let new = vec![
            func(11, Some("ComponentName"), "LoadConstZero\nRet\n"),
            func(21, Some("ComponentName"), "LoadConstFalse\nRet\n"),
        ];
        let (entries, exact) = diff_functions(&old, &new);
        assert_eq!(exact, 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "partial");
        assert_eq!(entries[0].old_id, Some(20));
        assert_eq!(entries[0].new_id, Some(21));
    }

    #[test]
    fn weak_filter_removes_env_slot_only_partial() {
        assert_eq!(
            filtered_partial_count(
                "GetEnvironment r0, 1\nLoadFromEnvironment r3, r0, 9\nRet r3\n",
                "GetEnvironment r0, 1\nLoadFromEnvironment r3, r0, 10\nRet r3\n",
            ),
            1
        );
    }

    #[test]
    fn weak_filter_removes_branch_target_only_partial() {
        assert_eq!(
            filtered_partial_count(
                "LoadConstZero r0\nJmpTrue 34, r0\nRet r0\n",
                "LoadConstZero r0\nJmpTrue 30, r0\nRet r0\n",
            ),
            1
        );
    }

    #[test]
    fn weak_filter_removes_branch_and_buffer_churn() {
        assert_eq!(
            filtered_partial_count(
                "NewObjectWithBufferLong r3, 3, 3, 15000, 72366\nJNotLess 34, r6, r14\nRet r3\n",
                "NewObjectWithBuffer r3, 3, 3, 20667, 18272\nJNotLess 30, r6, r14\nRet r3\n",
            ),
            1
        );
    }

    #[test]
    fn weak_filter_keeps_property_name_change() {
        assert_eq!(
            filtered_partial_count(
                "GetById r1, r0, 1, \"find\"\nCall2 r0, r1, r0, r2\nRet r0\n",
                "GetById r1, r0, 1, \"sort\"\nCall2 r0, r1, r0, r2\nRet r0\n",
            ),
            0
        );
    }

    #[test]
    fn weak_filter_keeps_large_real_body_change() {
        assert_eq!(
            filtered_partial_count(
                "GetById r1, r0, 1, \"useIntl\"\nCall1 r1, r1, r0\nCreateClosure r2, r3, Function<closeMenu>\nRet r2\n",
                "GetById r1, r0, 1, \"useServices\"\nCall1 r1, r1, r0\nCreateClosure r2, r3, Function<openMenu>\nCall2 r4, r2, r0, r1\nRet r4\n",
            ),
            0
        );
    }
}
