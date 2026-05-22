use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::BufReader;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use hermes_rs::hermes::function_header::FunctionHeader;
use hermes_rs::hermes_file::HermesFile;
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct Config {
    old_path: PathBuf,
    new_path: PathBuf,
    old_label: Option<String>,
    new_label: Option<String>,
    out_dir: PathBuf,
    max_functions: Option<usize>,
    js_decompile: bool,
}

#[derive(Debug, Clone, Serialize)]
struct InstructionRecord {
    index: usize,
    offset: u32,
    opcode: String,
    formatted_text: String,
    normalized_text: String,
}

#[derive(Debug, Clone, Serialize)]
struct FunctionRecord {
    id: u32,
    name: Option<String>,
    display_name: String,
    offset: u32,
    param_count: u32,
    register_count: u32,
    symbol_count: u32,
    bytecode_size: u32,
    header_type: String,
    instruction_count: usize,
    opcode_hash: String,
    instruction_hash: String,
    string_refs_hash: String,
    function_refs_hash: String,
    text: String,
    instructions: Vec<InstructionRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct ChangedFunction {
    kind: String,
    slug: String,
    old_id: Option<u32>,
    new_id: Option<u32>,
    old_name: Option<String>,
    new_name: Option<String>,
    ratio: Option<f64>,
    description: String,
    old_hash: Option<String>,
    new_hash: Option<String>,
    files: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<ChangedFunctionFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    js_decompile: Option<ChangedFunctionJsDecompile>,
}

#[derive(Debug, Clone, Serialize)]
struct ChangedFunctionFilter {
    reason: String,
    similarity_ratio: f64,
    changed_instruction_count: usize,
    weak_instruction_count: usize,
    meaningful_instruction_count: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ChangedFunctionJsDecompile {
    #[serde(skip_serializing_if = "Option::is_none")]
    old_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Manifest {
    generated_at: String,
    mode: String,
    inputs: BTreeMap<String, String>,
    artifacts: BTreeMap<String, String>,
    stats: ManifestStats,
    functions: Vec<ChangedFunction>,
}

#[derive(Debug, Serialize)]
struct ManifestStats {
    old_functions: usize,
    new_functions: usize,
    exact: usize,
    partial: usize,
    new: usize,
    deleted: usize,
    js_decompile: JsDecompileStats,
}

#[derive(Debug, Clone, Serialize)]
struct JsDecompileStats {
    enabled: bool,
    old_context_status: String,
    new_context_status: String,
    attempted: usize,
    success: usize,
    failed: usize,
    panicked: usize,
}

impl JsDecompileStats {
    fn disabled() -> Self {
        Self {
            enabled: false,
            old_context_status: "skipped".to_string(),
            new_context_status: "skipped".to_string(),
            attempted: 0,
            success: 0,
            failed: 0,
            panicked: 0,
        }
    }
}

struct JsDecompiler {
    file: hbc::BytecodeFile,
    context: hbc::PipelineContext,
}

struct JsDecompilerSet {
    old: Option<JsDecompiler>,
    new: Option<JsDecompiler>,
    stats: JsDecompileStats,
}

enum JsDecompileResult {
    Ok(String),
    Error(String),
    Panic(String),
    Skipped(String),
}

enum JsDecompilerBuildFailure {
    Error,
    Panic,
}

fn main() -> Result<()> {
    let config = parse_args()?;
    run(config)
}

fn parse_args() -> Result<Config> {
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

fn print_usage() {
    eprintln!(
        "Usage: hermes-diff --old <old.hbc|main.jsbundle> --new <new.hbc|main.jsbundle> --out-dir <dir> [--old-label TEXT] [--new-label TEXT] [--max-functions N] [--no-js-decompile]"
    );
}

fn ensure_exists(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        bail!("{label} not found: {}", path.display());
    }
    Ok(())
}

fn run(config: Config) -> Result<()> {
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

fn load_bundle(path: &Path) -> Result<Vec<FunctionRecord>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hermes_file = HermesFile::deserialize(&mut reader);
    let mut records = Vec::with_capacity(hermes_file.function_headers.len());

    for func_idx in 0..hermes_file.function_headers.len() {
        let fh = hermes_file.function_headers[func_idx].clone();
        let func_name = hermes_file.get_string_from_storage_by_index(fh.func_name() as usize);
        let name = if func_name.is_empty() {
            None
        } else {
            Some(func_name)
        };
        let display_name = name.clone().unwrap_or_else(|| format!("$FUNC_{func_idx}"));
        let header_type = match fh {
            FunctionHeader::Small(_) => "Small",
            FunctionHeader::Large(_) => "Large",
        }
        .to_string();

        let raw_instructions = hermes_file.get_func_bytecode(func_idx as u32);
        let mut instructions = Vec::with_capacity(raw_instructions.len());
        let mut offset = 0u32;
        for (index, instr) in raw_instructions.iter().enumerate() {
            let formatted_text = instr.display(&hermes_file);
            let normalized_text = normalize_instruction_text(&formatted_text);
            instructions.push(InstructionRecord {
                index,
                offset,
                opcode: opcode_name(instr),
                formatted_text,
                normalized_text,
            });
            offset = offset.saturating_add(instr.size() as u32);
        }

        let opcode_material = instructions
            .iter()
            .map(|instr| instr.opcode.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let instruction_material = instructions
            .iter()
            .map(|instr| instr.normalized_text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let string_refs = extract_quoted_refs(&instruction_material).join("\n");
        let function_refs = extract_function_refs(&instruction_material).join("\n");
        let text = render_function_text(
            func_idx as u32,
            &display_name,
            fh.param_count(),
            fh.frame_size(),
            fh.env_size(),
            &header_type,
            fh.byte_size(),
            fh.offset(),
            &instructions,
        );

        records.push(FunctionRecord {
            id: func_idx as u32,
            name,
            display_name,
            offset: fh.offset(),
            param_count: fh.param_count(),
            register_count: fh.frame_size(),
            symbol_count: fh.env_size(),
            bytecode_size: fh.byte_size(),
            header_type,
            instruction_count: instructions.len(),
            opcode_hash: hash_text(&opcode_material),
            instruction_hash: hash_text(&instruction_material),
            string_refs_hash: hash_text(&string_refs),
            function_refs_hash: hash_text(&function_refs),
            text,
            instructions,
        });
    }

    Ok(records)
}

fn render_function_text(
    id: u32,
    name: &str,
    param_count: u32,
    register_count: u32,
    symbol_count: u32,
    header_type: &str,
    bytecode_size: u32,
    offset: u32,
    instructions: &[InstructionRecord],
) -> String {
    let mut lines = vec![
        "------------------------------------------------".to_string(),
        format!(
            "Function<{name}>({param_count} params, {register_count} registers, {symbol_count} symbols): # Type: {header_type}FunctionHeader - funcID: {id} ({bytecode_size} bytes @ {offset})"
        ),
        String::new(),
    ];
    for instr in instructions {
        lines.push(format!("{}\t{}", instr.index, instr.formatted_text));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn opcode_name(instr: &hermes_rs::HermesInstruction) -> String {
    let debug = format!("{instr:?}");
    if let Some(start) = debug.find('(') {
        let rest = &debug[start + 1..];
        if let Some(end) = rest.find('(') {
            return rest[..end].to_string();
        }
    }
    "Unknown".to_string()
}

fn normalize_instruction_text(text: &str) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalize_shiftable_table_indices(&compact)
}

fn normalize_shiftable_table_indices(text: &str) -> String {
    let mut normalized = text.to_string();

    for opcode in [
        "GetById",
        "GetByIdShort",
        "PutById",
        "PutByIdShort",
        "PutNewOwnById",
        "PutNewOwnByIdShort",
        "TryGetById",
    ] {
        if normalized.starts_with(opcode) && normalized.contains('"') {
            normalized = replace_number_before_first_quote(&normalized, "STRID");
            break;
        }
    }

    for opcode in ["NewObjectWithBuffer", "NewObjectWithBufferLong"] {
        if normalized.starts_with(opcode) {
            normalized = replace_trailing_numbers(&normalized, 2, "BUFID");
            normalized = normalized.replacen("NewObjectWithBufferLong", "NewObjectWithBuffer", 1);
            break;
        }
    }

    for opcode in ["NewArrayWithBuffer", "NewArrayWithBufferLong"] {
        if normalized.starts_with(opcode) {
            normalized = replace_trailing_numbers(&normalized, 1, "BUFID");
            normalized = normalized.replacen("NewArrayWithBufferLong", "NewArrayWithBuffer", 1);
            break;
        }
    }

    normalized = normalize_anonymous_function_refs(&normalized);

    normalized
}

fn replace_number_before_first_quote(text: &str, replacement: &str) -> String {
    let Some(quote_idx) = text.find('"') else {
        return text.to_string();
    };
    let prefix = &text[..quote_idx];
    let suffix = &text[quote_idx..];
    let Some((start, end)) = last_number_span(prefix) else {
        return text.to_string();
    };
    format!(
        "{}{}{}{}",
        &prefix[..start],
        replacement,
        &prefix[end..],
        suffix
    )
}

fn replace_trailing_numbers(text: &str, count: usize, replacement: &str) -> String {
    let mut out = text.to_string();
    for _ in 0..count {
        let Some((start, end)) = last_number_span(&out) else {
            break;
        };
        out.replace_range(start..end, replacement);
    }
    out
}

fn last_number_span(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut end = bytes.len();
    while end > 0 && !bytes[end - 1].is_ascii_digit() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut start = end;
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    Some((start, end))
}

fn normalize_anonymous_function_refs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let marker = "Function<$FUNC_";
    let mut rest = text;
    while let Some(idx) = rest.find(marker) {
        out.push_str(&rest[..idx]);
        let after_marker = &rest[idx + marker.len()..];
        let digit_len = after_marker
            .as_bytes()
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digit_len > 0 && after_marker[digit_len..].starts_with('>') {
            out.push_str("Function<$FUNC>");
            rest = &after_marker[digit_len + 1..];
        } else {
            out.push_str(marker);
            rest = after_marker;
        }
    }
    out.push_str(rest);
    out
}

fn extract_quoted_refs(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quote {
            escaped = true;
            continue;
        }
        if ch == '"' {
            if in_quote {
                refs.push(current.clone());
                current.clear();
            }
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            current.push(ch);
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

fn extract_function_refs(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let marker = "Function<";
    let mut rest = text;
    while let Some(start) = rest.find(marker) {
        let after = &rest[start + marker.len()..];
        if let Some(end) = after.find('>') {
            refs.push(after[..end].to_string());
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

fn hash_text(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn export_sqlite(functions: &[FunctionRecord], path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE functions (
            id INTEGER PRIMARY KEY,
            name TEXT,
            offset INTEGER,
            param_count INTEGER,
            register_count INTEGER,
            symbol_count INTEGER,
            bytecode_size INTEGER,
            header_type TEXT,
            instruction_count INTEGER,
            opcode_hash TEXT,
            instruction_hash TEXT,
            string_refs_hash TEXT,
            function_refs_hash TEXT
        );
        CREATE TABLE instructions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            func_id INTEGER NOT NULL,
            instr_index INTEGER,
            offset INTEGER,
            opcode_name TEXT,
            formatted_text TEXT,
            normalized_text TEXT
        );
        CREATE INDEX idx_instructions_func ON instructions(func_id);
        CREATE INDEX idx_functions_instruction_hash ON functions(instruction_hash);
        "#,
    )?;
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('function_count', ?)",
        [functions.len().to_string()],
    )?;

    let tx = conn.unchecked_transaction()?;
    {
        let mut func_stmt = tx.prepare(
            r#"
            INSERT INTO functions (
                id, name, offset, param_count, register_count, symbol_count,
                bytecode_size, header_type, instruction_count, opcode_hash,
                instruction_hash, string_refs_hash, function_refs_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )?;
        let mut instr_stmt = tx.prepare(
            r#"
            INSERT INTO instructions (
                func_id, instr_index, offset, opcode_name, formatted_text, normalized_text
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )?;
        for func in functions {
            func_stmt.execute(rusqlite::params![
                func.id,
                func.name,
                func.offset,
                func.param_count,
                func.register_count,
                func.symbol_count,
                func.bytecode_size,
                func.header_type,
                func.instruction_count,
                func.opcode_hash,
                func.instruction_hash,
                func.string_refs_hash,
                func.function_refs_hash,
            ])?;
            for instr in &func.instructions {
                instr_stmt.execute(rusqlite::params![
                    func.id,
                    instr.index,
                    instr.offset,
                    instr.opcode,
                    instr.formatted_text,
                    instr.normalized_text,
                ])?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

fn diff_functions(old: &[FunctionRecord], new: &[FunctionRecord]) -> (Vec<ChangedFunction>, usize) {
    let old_by_id: HashMap<u32, &FunctionRecord> = old.iter().map(|f| (f.id, f)).collect();
    let new_by_id: HashMap<u32, &FunctionRecord> = new.iter().map(|f| (f.id, f)).collect();
    let mut matched_old = HashSet::new();
    let mut matched_new = HashSet::new();
    let mut entries = Vec::new();
    let mut exact_count = 0usize;
    let old_name_counts = name_counts(old);
    let new_name_counts = name_counts(new);

    for old_func in old {
        if let Some(new_func) = new_by_id.get(&old_func.id) {
            if !same_id_match_allowed(old_func, new_func, &old_name_counts, &new_name_counts) {
                continue;
            }
            matched_old.insert(old_func.id);
            matched_new.insert(new_func.id);
            if old_func.instruction_hash == new_func.instruction_hash {
                exact_count += 1;
            } else {
                entries.push(make_partial(old_func, new_func, "same function id"));
            }
        }
    }

    let old_hashes = unique_index(
        old.iter()
            .filter(|f| !matched_old.contains(&f.id) && is_strong_cross_id_match_candidate(f)),
        |f| f.instruction_hash.as_str(),
    );
    let new_hashes = unique_index(
        new.iter()
            .filter(|f| !matched_new.contains(&f.id) && is_strong_cross_id_match_candidate(f)),
        |f| f.instruction_hash.as_str(),
    );
    for (hash, old_id) in old_hashes {
        if let Some(new_id) = new_hashes.get(hash.as_str()) {
            matched_old.insert(old_id);
            matched_new.insert(*new_id);
            exact_count += 1;
        }
    }

    let old_names = unique_index(
        old.iter()
            .filter(|f| !matched_old.contains(&f.id) && f.name.is_some()),
        |f| f.name.as_deref().unwrap_or_default(),
    );
    let new_names = unique_index(
        new.iter()
            .filter(|f| !matched_new.contains(&f.id) && f.name.is_some()),
        |f| f.name.as_deref().unwrap_or_default(),
    );
    for (name, old_id) in old_names {
        if let Some(new_id) = new_names.get(name.as_str()) {
            let old_func = old_by_id[&old_id];
            let new_func = new_by_id[new_id];
            matched_old.insert(old_id);
            matched_new.insert(*new_id);
            if old_func.instruction_hash == new_func.instruction_hash {
                exact_count += 1;
            } else {
                entries.push(make_partial(
                    old_func,
                    new_func,
                    "same unique function name",
                ));
            }
        }
    }

    let duplicate_name_matches =
        duplicate_name_ordinal_matches(old, new, &matched_old, &matched_new);
    for (old_id, new_id) in duplicate_name_matches {
        let old_func = old_by_id[&old_id];
        let new_func = new_by_id[&new_id];
        matched_old.insert(old_id);
        matched_new.insert(new_id);
        if old_func.instruction_hash == new_func.instruction_hash {
            exact_count += 1;
        } else {
            entries.push(make_partial(
                old_func,
                new_func,
                "same duplicate function name and ordinal",
            ));
        }
    }

    for old_func in old {
        if !matched_old.contains(&old_func.id) {
            entries.push(make_one_sided("deleted", old_func));
        }
    }
    for new_func in new {
        if !matched_new.contains(&new_func.id) {
            entries.push(make_one_sided("new", new_func));
        }
    }

    entries.sort_by(|left, right| {
        kind_order(&left.kind)
            .cmp(&kind_order(&right.kind))
            .then_with(|| left.slug.cmp(&right.slug))
    });
    (entries, exact_count)
}

fn filter_weak_hermes_partials(
    entries: Vec<ChangedFunction>,
    old: &[FunctionRecord],
    new: &[FunctionRecord],
) -> (Vec<ChangedFunction>, Vec<ChangedFunction>) {
    let old_by_id: HashMap<u32, &FunctionRecord> = old.iter().map(|f| (f.id, f)).collect();
    let new_by_id: HashMap<u32, &FunctionRecord> = new.iter().map(|f| (f.id, f)).collect();
    let mut kept = Vec::new();
    let mut filtered = Vec::new();

    for mut entry in entries {
        let filter = classify_weak_hermes_partial(&entry, &old_by_id, &new_by_id);
        if let Some(filter) = filter {
            entry.filter = Some(filter);
            filtered.push(entry);
        } else {
            kept.push(entry);
        }
    }

    (kept, filtered)
}

fn classify_weak_hermes_partial(
    entry: &ChangedFunction,
    old_by_id: &HashMap<u32, &FunctionRecord>,
    new_by_id: &HashMap<u32, &FunctionRecord>,
) -> Option<ChangedFunctionFilter> {
    if entry.kind != "partial" {
        return None;
    }
    let old_func = old_by_id.get(&entry.old_id?)?;
    let new_func = new_by_id.get(&entry.new_id?)?;
    let metrics = partial_instruction_metrics(old_func, new_func);
    if metrics.changed_instruction_count == 0 {
        return None;
    }

    if metrics.meaningful_instruction_count == 0 {
        return Some(metrics.into_filter("weak_layout_env"));
    }

    let weak_dominates = metrics.weak_instruction_count >= metrics.meaningful_instruction_count * 4;
    let high_similarity = metrics.similarity_ratio >= 0.90;
    if high_similarity && weak_dominates && metrics.meaningful_instruction_count <= 2 {
        return Some(metrics.into_filter("weak_layout_env"));
    }

    None
}

#[derive(Debug)]
struct PartialInstructionMetrics {
    similarity_ratio: f64,
    changed_instruction_count: usize,
    weak_instruction_count: usize,
    meaningful_instruction_count: usize,
}

impl PartialInstructionMetrics {
    fn into_filter(self, reason: &str) -> ChangedFunctionFilter {
        ChangedFunctionFilter {
            reason: reason.to_string(),
            similarity_ratio: self.similarity_ratio,
            changed_instruction_count: self.changed_instruction_count,
            weak_instruction_count: self.weak_instruction_count,
            meaningful_instruction_count: self.meaningful_instruction_count,
        }
    }
}

fn partial_instruction_metrics(
    old_func: &FunctionRecord,
    new_func: &FunctionRecord,
) -> PartialInstructionMetrics {
    let max_len = old_func.instructions.len().max(new_func.instructions.len());
    let mut changed_instruction_count = 0usize;
    let mut weak_instruction_count = 0usize;
    let mut meaningful_instruction_count = 0usize;

    for idx in 0..max_len {
        match (
            old_func.instructions.get(idx),
            new_func.instructions.get(idx),
        ) {
            (Some(old_instr), Some(new_instr)) => {
                if old_instr.normalized_text == new_instr.normalized_text {
                    continue;
                }
                changed_instruction_count += 1;
                if weak_normalized_instruction_text(&old_instr.normalized_text)
                    == weak_normalized_instruction_text(&new_instr.normalized_text)
                {
                    weak_instruction_count += 1;
                } else {
                    meaningful_instruction_count += 1;
                }
            }
            _ => {
                changed_instruction_count += 1;
                meaningful_instruction_count += 1;
            }
        }
    }

    PartialInstructionMetrics {
        similarity_ratio: similarity_ratio(&old_func.text, &new_func.text),
        changed_instruction_count,
        weak_instruction_count,
        meaningful_instruction_count,
    }
}

fn weak_normalized_instruction_text(text: &str) -> String {
    let mut normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(opcode) = normalized.split_whitespace().next().map(str::to_string) {
        if opcode.starts_with('J') {
            normalized = replace_operand(&normalized, 0, "TARGET");
        }
        match opcode.as_str() {
            "GetEnvironment" => normalized = replace_operand(&normalized, 1, "ENV"),
            "LoadFromEnvironment" => normalized = replace_operand(&normalized, 2, "ENV_SLOT"),
            "StoreToEnvironment" => normalized = replace_operand(&normalized, 1, "ENV_SLOT"),
            _ => {}
        }
    }
    normalized
}

fn replace_operand(text: &str, operand_index: usize, replacement: &str) -> String {
    let Some((opcode, operands_text)) = text.split_once(' ') else {
        return text.to_string();
    };
    let mut operands = operands_text
        .split(',')
        .map(|operand| operand.trim().to_string())
        .collect::<Vec<_>>();
    if operand_index >= operands.len() {
        return text.to_string();
    }
    operands[operand_index] = replacement.to_string();
    format!("{opcode} {}", operands.join(", "))
}

fn duplicate_name_ordinal_matches(
    old: &[FunctionRecord],
    new: &[FunctionRecord],
    matched_old: &HashSet<u32>,
    matched_new: &HashSet<u32>,
) -> Vec<(u32, u32)> {
    let mut old_groups: BTreeMap<&str, Vec<&FunctionRecord>> = BTreeMap::new();
    let mut new_groups: BTreeMap<&str, Vec<&FunctionRecord>> = BTreeMap::new();

    for func in old {
        if matched_old.contains(&func.id) {
            continue;
        }
        if let Some(name) = func
            .name
            .as_deref()
            .filter(|name| is_stable_duplicate_name(name))
        {
            old_groups.entry(name).or_default().push(func);
        }
    }
    for func in new {
        if matched_new.contains(&func.id) {
            continue;
        }
        if let Some(name) = func
            .name
            .as_deref()
            .filter(|name| is_stable_duplicate_name(name))
        {
            new_groups.entry(name).or_default().push(func);
        }
    }

    let mut matches = Vec::new();
    for (name, old_items) in old_groups {
        let Some(new_items) = new_groups.get(name) else {
            continue;
        };
        if old_items.len() != new_items.len() || old_items.len() < 2 || old_items.len() > 10 {
            continue;
        }
        for (old_func, new_func) in old_items.iter().zip(new_items.iter()) {
            matches.push((old_func.id, new_func.id));
        }
    }
    matches
}

fn is_stable_duplicate_name(name: &str) -> bool {
    if name.len() < 4 {
        return false;
    }
    if name.starts_with('?') || name.starts_with('_') || name.contains("anon") {
        return false;
    }
    !matches!(
        name,
        "get"
            | "set"
            | "value"
            | "children"
            | "onPress"
            | "onClose"
            | "selector"
            | "rename"
            | "updater"
            | "menu"
            | "pane"
            | "renderItem"
            | "renderLeft"
            | "renderRight"
            | "renderLabel"
    )
}

fn name_counts(functions: &[FunctionRecord]) -> HashMap<&str, usize> {
    let mut counts = HashMap::new();
    for func in functions {
        if let Some(name) = func.name.as_deref() {
            *counts.entry(name).or_default() += 1;
        }
    }
    counts
}

fn same_id_match_allowed(
    old: &FunctionRecord,
    new: &FunctionRecord,
    old_name_counts: &HashMap<&str, usize>,
    new_name_counts: &HashMap<&str, usize>,
) -> bool {
    if old.instruction_hash == new.instruction_hash {
        return true;
    }
    match (&old.name, &new.name) {
        (Some(old_name), Some(new_name)) => {
            old_name == new_name
                && old_name_counts.get(old_name.as_str()) == Some(&1)
                && new_name_counts.get(new_name.as_str()) == Some(&1)
        }
        _ => false,
    }
}

fn unique_index<'a, I, F>(items: I, key_fn: F) -> BTreeMap<String, u32>
where
    I: Iterator<Item = &'a FunctionRecord>,
    F: Fn(&'a FunctionRecord) -> &'a str,
{
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut ids: HashMap<String, u32> = HashMap::new();
    for item in items {
        let key = key_fn(item);
        if key.is_empty() {
            continue;
        }
        *counts.entry(key.to_string()).or_default() += 1;
        ids.entry(key.to_string()).or_insert(item.id);
    }
    counts
        .into_iter()
        .filter_map(|(key, count)| (count == 1).then(|| (key.clone(), ids[&key])))
        .collect()
}

fn is_strong_cross_id_match_candidate(func: &FunctionRecord) -> bool {
    func.instruction_count >= 3
        && func.bytecode_size >= 8
        && (func.string_refs_hash != hash_text("")
            || func.function_refs_hash != hash_text("")
            || func.name.is_some())
}

fn kind_order(kind: &str) -> u8 {
    match kind {
        "partial" => 0,
        "new" => 1,
        "deleted" => 2,
        _ => 3,
    }
}

fn make_partial(old: &FunctionRecord, new: &FunctionRecord, reason: &str) -> ChangedFunction {
    let name = new.name.as_deref().or(old.name.as_deref());
    ChangedFunction {
        kind: "partial".to_string(),
        slug: format!(
            "partial__{}__old_{}__new_{}",
            sanitize_name(name),
            old.id,
            new.id
        ),
        old_id: Some(old.id),
        new_id: Some(new.id),
        old_name: old.name.clone(),
        new_name: new.name.clone(),
        ratio: Some(similarity_ratio(&old.text, &new.text)),
        description: reason.to_string(),
        old_hash: Some(old.instruction_hash.clone()),
        new_hash: Some(new.instruction_hash.clone()),
        files: BTreeMap::new(),
        filter: None,
        js_decompile: None,
    }
}

fn make_one_sided(kind: &str, func: &FunctionRecord) -> ChangedFunction {
    let suffix = if kind == "new" { "new" } else { "old" };
    ChangedFunction {
        kind: kind.to_string(),
        slug: format!(
            "{kind}__{}__{suffix}_{}",
            sanitize_name(func.name.as_deref()),
            func.id
        ),
        old_id: (kind == "deleted").then_some(func.id),
        new_id: (kind == "new").then_some(func.id),
        old_name: (kind == "deleted").then(|| func.name.clone()).flatten(),
        new_name: (kind == "new").then(|| func.name.clone()).flatten(),
        ratio: None,
        description: format!("function exists only in {suffix} Hermes bundle"),
        old_hash: (kind == "deleted").then(|| func.instruction_hash.clone()),
        new_hash: (kind == "new").then(|| func.instruction_hash.clone()),
        files: BTreeMap::new(),
        filter: None,
        js_decompile: None,
    }
}

fn sanitize_name(value: Option<&str>) -> String {
    let raw = value.unwrap_or("unnamed");
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.chars().take(80).collect()
    }
}

fn similarity_ratio(old: &str, new: &str) -> f64 {
    let mut old_counts: HashMap<&str, usize> = HashMap::new();
    let mut new_counts: HashMap<&str, usize> = HashMap::new();
    for line in old.lines() {
        *old_counts.entry(line).or_default() += 1;
    }
    for line in new.lines() {
        *new_counts.entry(line).or_default() += 1;
    }
    let old_total: usize = old_counts.values().sum();
    let new_total: usize = new_counts.values().sum();
    if old_total + new_total == 0 {
        return 1.0;
    }
    let common: usize = old_counts
        .iter()
        .map(|(line, count)| count.min(new_counts.get(line).unwrap_or(&0)))
        .sum();
    (2.0 * common as f64) / (old_total + new_total) as f64
}

fn prepare_js_decompilers(config: &Config) -> JsDecompilerSet {
    if !config.js_decompile {
        return JsDecompilerSet {
            old: None,
            new: None,
            stats: JsDecompileStats::disabled(),
        };
    }

    println!("[stage] hermes_js_decompile:context");
    let old_result = build_js_decompiler(&config.old_path);
    let new_result = build_js_decompiler(&config.new_path);

    let mut stats = JsDecompileStats {
        enabled: true,
        old_context_status: js_context_status(&old_result),
        new_context_status: js_context_status(&new_result),
        attempted: 0,
        success: 0,
        failed: 0,
        panicked: 0,
    };

    let old = match old_result {
        Ok(decompiler) => Some(decompiler),
        Err(error) => {
            if matches!(error, JsDecompilerBuildFailure::Panic) {
                stats.panicked += 1;
            } else {
                stats.failed += 1;
            }
            None
        }
    };
    let new = match new_result {
        Ok(decompiler) => Some(decompiler),
        Err(error) => {
            if matches!(error, JsDecompilerBuildFailure::Panic) {
                stats.panicked += 1;
            } else {
                stats.failed += 1;
            }
            None
        }
    };

    JsDecompilerSet { old, new, stats }
}

fn js_context_status(
    result: &std::result::Result<JsDecompiler, JsDecompilerBuildFailure>,
) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(JsDecompilerBuildFailure::Error) => "error".to_string(),
        Err(JsDecompilerBuildFailure::Panic) => "panic".to_string(),
    }
}

fn build_js_decompiler(path: &Path) -> std::result::Result<JsDecompiler, JsDecompilerBuildFailure> {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<JsDecompiler> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read Hermes bundle {}", path.display()))?;
        let file = hbc::BytecodeFile::parse_auto(&bytes)
            .with_context(|| format!("failed to parse Hermes bundle {}", path.display()))?;
        let (format, _) = hbc::BytecodeFormat::for_version_or_latest(file.header.version)
            .with_context(|| {
                format!(
                    "unsupported Hermes bytecode version {}",
                    file.header.version
                )
            })?;
        let options = hbc::DecompileOptionsV2::optimized();
        let context = hbc::PipelineContext::build_with_options(&file, &format, &options)
            .with_context(|| {
                format!(
                    "failed to build JS decompiler context for {}",
                    path.display()
                )
            })?;
        Ok(JsDecompiler { file, context })
    }));

    match result {
        Ok(Ok(decompiler)) => Ok(decompiler),
        Ok(Err(error)) => {
            eprintln!("[hermes-js-decompile] {}", format!("{error:#}"));
            Err(JsDecompilerBuildFailure::Error)
        }
        Err(payload) => {
            eprintln!("[hermes-js-decompile] {}", panic_payload_to_string(payload));
            Err(JsDecompilerBuildFailure::Panic)
        }
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "panic while decompiling Hermes bytecode".to_string()
    }
}

fn decompile_js_function(decompiler: Option<&JsDecompiler>, function_id: u32) -> JsDecompileResult {
    let Some(decompiler) = decompiler else {
        return JsDecompileResult::Skipped("JS decompiler context unavailable".to_string());
    };

    let result = catch_unwind(AssertUnwindSafe(|| {
        decompiler
            .context
            .generate_function_code(&decompiler.file, function_id)
    }));
    match result {
        Ok(code) => {
            if code.trim_start().starts_with("// Error:") {
                JsDecompileResult::Error(code.trim().to_string())
            } else {
                JsDecompileResult::Ok(ensure_trailing_newline(code))
            }
        }
        Err(payload) => JsDecompileResult::Panic(panic_payload_to_string(payload)),
    }
}

fn ensure_trailing_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

fn record_js_result(stats: &mut JsDecompileStats, result: &JsDecompileResult) {
    match result {
        JsDecompileResult::Ok(_) => {
            stats.attempted += 1;
            stats.success += 1;
        }
        JsDecompileResult::Error(_) => {
            stats.attempted += 1;
            stats.failed += 1;
        }
        JsDecompileResult::Panic(_) => {
            stats.attempted += 1;
            stats.panicked += 1;
        }
        JsDecompileResult::Skipped(_) => {}
    }
}

fn js_result_status(result: &JsDecompileResult) -> String {
    match result {
        JsDecompileResult::Ok(_) => "ok",
        JsDecompileResult::Error(_) => "error",
        JsDecompileResult::Panic(_) => "panic",
        JsDecompileResult::Skipped(_) => "skipped",
    }
    .to_string()
}

fn js_result_error(result: &JsDecompileResult) -> Option<String> {
    match result {
        JsDecompileResult::Error(message)
        | JsDecompileResult::Panic(message)
        | JsDecompileResult::Skipped(message) => Some(message.clone()),
        JsDecompileResult::Ok(_) => None,
    }
}

fn render_entries(
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

fn render_js_artifacts(
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

    if entry.kind == "partial" {
        if let (Some(old_text), Some(new_text)) = (old_js.as_deref(), new_js.as_deref()) {
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
    }

    entry.js_decompile = Some(info);
    Ok(())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn one_sided_summary(entry: &ChangedFunction) -> String {
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

fn unified_diff(old: &str, new: &str, old_label: &str, new_label: &str) -> String {
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

enum DiffEdit<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

fn lcs_diff<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<DiffEdit<'a>> {
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

fn build_manifest(
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

fn now_string() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("unix:{}", d.as_secs()))
        .unwrap_or_else(|_| "unix:0".to_string())
}

fn write_readme(out_dir: &Path, manifest: &Manifest) -> Result<()> {
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
        format!(
            "- js_decompile: enabled={}, success={}, failed={}, panicked={}",
            manifest.stats.js_decompile.enabled,
            manifest.stats.js_decompile.success,
            manifest.stats.js_decompile.failed,
            manifest.stats.js_decompile.panicked,
        ),
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

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
