use std::collections::{BTreeMap, HashMap};
use std::fs::{self};
use std::path::Path;

use anyhow::Result;

use crate::js::{decompile_js_function, js_result_error, js_result_status, record_js_result};
use crate::model::*;

pub(crate) fn render_entries(
    entries: &mut [ChangedFunction],
    old: &[FunctionRecord],
    new: &[FunctionRecord],
    out_dir: &Path,
    js_decompilers: &mut JsDecompilerSet,
) -> Result<()> {
    let old_by_id: HashMap<u32, &FunctionRecord> = old.iter().map(|f| (f.id, f)).collect();
    let new_by_id: HashMap<u32, &FunctionRecord> = new.iter().map(|f| (f.id, f)).collect();
    let functions_dir = out_dir.join("functions");

    for entry in entries {
        let function_dir = functions_dir.join(&entry.slug);
        fs::create_dir_all(&function_dir)?;
        let mut files = BTreeMap::new();

        if let Some(old_id) = entry.old_id {
            let path = function_dir.join("old.hbc.txt");
            fs::write(&path, &old_by_id[&old_id].text)?;
            files.insert("old.hbc.txt".to_string(), relative(out_dir, &path));
        }
        if let Some(new_id) = entry.new_id {
            let path = function_dir.join("new.hbc.txt");
            fs::write(&path, &new_by_id[&new_id].text)?;
            files.insert("new.hbc.txt".to_string(), relative(out_dir, &path));
        }
        if entry.kind == "partial" {
            let old_text = &old_by_id[&entry.old_id.unwrap()].text;
            let new_text = &new_by_id[&entry.new_id.unwrap()].text;
            let patch = unified_diff(
                old_text,
                new_text,
                &format!("{}/old.hbc.txt", entry.slug),
                &format!("{}/new.hbc.txt", entry.slug),
            );
            let patch_path = function_dir.join("diff.patch");
            fs::write(&patch_path, &patch)?;
            files.insert("diff.patch".to_string(), relative(out_dir, &patch_path));

            let diff_md = format!("# Diff\n\n```diff\n{}```\n", patch);
            let diff_path = function_dir.join("diff.md");
            fs::write(&diff_path, diff_md)?;
            files.insert("diff.md".to_string(), relative(out_dir, &diff_path));
        } else {
            let summary_path = function_dir.join("summary.md");
            fs::write(&summary_path, one_sided_summary(entry))?;
            files.insert("summary.md".to_string(), relative(out_dir, &summary_path));
        }

        if js_decompilers.stats.enabled {
            render_js_artifacts(entry, &function_dir, out_dir, js_decompilers, &mut files)?;
        }

        let meta_path = function_dir.join("meta.json");
        entry.files = files;
        fs::write(&meta_path, serde_json::to_vec_pretty(&entry)?)?;
        entry
            .files
            .insert("meta.json".to_string(), relative(out_dir, &meta_path));
        fs::write(&meta_path, serde_json::to_vec_pretty(&entry)?)?;
    }
    Ok(())
}

pub(crate) fn render_js_artifacts(
    entry: &mut ChangedFunction,
    function_dir: &Path,
    out_dir: &Path,
    js_decompilers: &mut JsDecompilerSet,
    files: &mut BTreeMap<String, String>,
) -> Result<()> {
    let mut info = ChangedFunctionJsDecompile::default();
    let mut old_js = None;
    let mut new_js = None;

    if let Some(old_id) = entry.old_id {
        let result = decompile_js_function(js_decompilers.old.as_ref(), old_id);
        record_js_result(&mut js_decompilers.stats, &result);
        info.old_status = Some(js_result_status(&result));
        info.old_error = js_result_error(&result);
        match result {
            JsDecompileResult::Ok(code) => {
                let path = function_dir.join("old.js");
                fs::write(&path, &code)?;
                files.insert("old.js".to_string(), relative(out_dir, &path));
                old_js = Some(code);
            }
            JsDecompileResult::Error(message) | JsDecompileResult::Panic(message) => {
                let path = function_dir.join("old.js.error.txt");
                fs::write(&path, message)?;
                files.insert("old.js.error.txt".to_string(), relative(out_dir, &path));
            }
            JsDecompileResult::Skipped(_) => {}
        }
    }

    if let Some(new_id) = entry.new_id {
        let result = decompile_js_function(js_decompilers.new.as_ref(), new_id);
        record_js_result(&mut js_decompilers.stats, &result);
        info.new_status = Some(js_result_status(&result));
        info.new_error = js_result_error(&result);
        match result {
            JsDecompileResult::Ok(code) => {
                let path = function_dir.join("new.js");
                fs::write(&path, &code)?;
                files.insert("new.js".to_string(), relative(out_dir, &path));
                new_js = Some(code);
            }
            JsDecompileResult::Error(message) | JsDecompileResult::Panic(message) => {
                let path = function_dir.join("new.js.error.txt");
                fs::write(&path, message)?;
                files.insert("new.js.error.txt".to_string(), relative(out_dir, &path));
            }
            JsDecompileResult::Skipped(_) => {}
        }
    }

    if entry.kind == "partial"
        && let (Some(old_text), Some(new_text)) = (old_js.as_deref(), new_js.as_deref())
    {
        let patch = unified_diff(
            old_text,
            new_text,
            &format!("{}/old.js", entry.slug),
            &format!("{}/new.js", entry.slug),
        );
        let patch_path = function_dir.join("js.diff.patch");
        fs::write(&patch_path, &patch)?;
        files.insert("js.diff.patch".to_string(), relative(out_dir, &patch_path));

        let diff_md = format!("# JS Diff\n\n```diff\n{}```\n", patch);
        let diff_path = function_dir.join("js.diff.md");
        fs::write(&diff_path, diff_md)?;
        files.insert("js.diff.md".to_string(), relative(out_dir, &diff_path));
    }

    entry.js_decompile = Some(info);
    Ok(())
}

pub(crate) fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

pub(crate) fn one_sided_summary(entry: &ChangedFunction) -> String {
    let mut lines = vec![
        format!("kind: {}", entry.kind),
        format!("slug: {}", entry.slug),
        format!("description: {}", entry.description),
    ];
    if let Some(id) = entry.old_id {
        lines.push(format!("old_id: {id}"));
    }
    if let Some(id) = entry.new_id {
        lines.push(format!("new_id: {id}"));
    }
    lines.push(String::new());
    lines.join("\n")
}

pub(crate) fn unified_diff(old: &str, new: &str, old_label: &str, new_label: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = format!("--- {old_label}\n+++ {new_label}\n@@\n");

    if old_lines.len().saturating_mul(new_lines.len()) > 1_000_000 {
        for line in &old_lines {
            out.push_str(&format!("-{line}\n"));
        }
        for line in &new_lines {
            out.push_str(&format!("+{line}\n"));
        }
        return out;
    }

    let edits = lcs_diff(&old_lines, &new_lines);
    for edit in edits {
        match edit {
            DiffEdit::Equal(line) => out.push_str(&format!(" {line}\n")),
            DiffEdit::Delete(line) => out.push_str(&format!("-{line}\n")),
            DiffEdit::Insert(line) => out.push_str(&format!("+{line}\n")),
        }
    }
    out
}

pub(crate) enum DiffEdit<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

pub(crate) fn lcs_diff<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<DiffEdit<'a>> {
    let mut table = vec![vec![0usize; new.len() + 1]; old.len() + 1];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            table[i][j] = if old[i] == new[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }

    let mut edits = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            edits.push(DiffEdit::Equal(old[i]));
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            edits.push(DiffEdit::Delete(old[i]));
            i += 1;
        } else {
            edits.push(DiffEdit::Insert(new[j]));
            j += 1;
        }
    }
    while i < old.len() {
        edits.push(DiffEdit::Delete(old[i]));
        i += 1;
    }
    while j < new.len() {
        edits.push(DiffEdit::Insert(new[j]));
        j += 1;
    }
    edits
}

pub(crate) fn write_readme(out_dir: &Path, manifest: &Manifest) -> Result<()> {
    let mut lines = vec![
        "# Hermes Bytecode Diff Report".to_string(),
        String::new(),
        format!("- mode: `{}`", manifest.mode),
        format!("- old_input: `{}`", manifest.inputs["old"]),
        format!("- new_input: `{}`", manifest.inputs["new"]),
        format!("- generated_at: `{}`", manifest.generated_at),
        String::new(),
        "## Run Stats".to_string(),
        String::new(),
        format!("- old_functions: {}", manifest.stats.old_functions),
        format!("- new_functions: {}", manifest.stats.new_functions),
        format!("- exact_unchanged: {}", manifest.stats.exact),
        format!("- partial: {}", manifest.stats.partial),
        format!("- new: {}", manifest.stats.new),
        format!("- deleted: {}", manifest.stats.deleted),
        {
            let mut js_line = format!(
                "- js_decompile: enabled={}, ok={}, refused={}, panicked={}",
                manifest.stats.js_decompile.enabled,
                manifest.stats.js_decompile.success,
                manifest.stats.js_decompile.failed,
                manifest.stats.js_decompile.panicked,
            );
            if manifest.stats.js_decompile.failed > 0 {
                js_line.push_str(
                    "\n\n> Note: `refused` counts functions the decompiler could not lower \
                     to IR (async generators and unsupported constructs). The bytecode dump \
                     (`*.hbc.txt`) is still written for them; no JS is emitted rather than \
                     wrong JS.",
                );
            }
            js_line
        },
        String::new(),
        "## Functions".to_string(),
        String::new(),
        "| kind | slug | ratio | link |".to_string(),
        "| --- | --- | --- | --- |".to_string(),
    ];

    for entry in &manifest.functions {
        let ratio = entry
            .ratio
            .map(|value| format!("{value:.3}"))
            .unwrap_or_default();
        lines.push(format!(
            "| {} | `{}` | {} | [open](functions/{}) |",
            entry.kind, entry.slug, ratio, entry.slug
        ));
    }
    fs::write(out_dir.join("README.md"), lines.join("\n") + "\n")?;
    Ok(())
}
