use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

use anyhow::{Context, Result};
use hermes_rs::hermes::function_header::FunctionHeader;
use hermes_rs::hermes_file::HermesFile;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::model::*;

pub(crate) fn load_bundle(path: &Path) -> Result<Vec<FunctionRecord>> {
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

pub(crate) fn render_function_text(
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

pub(crate) fn opcode_name(instr: &hermes_rs::HermesInstruction) -> String {
    let debug = format!("{instr:?}");
    if let Some(start) = debug.find('(') {
        let rest = &debug[start + 1..];
        if let Some(end) = rest.find('(') {
            return rest[..end].to_string();
        }
    }
    "Unknown".to_string()
}

pub(crate) fn normalize_instruction_text(text: &str) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalize_shiftable_table_indices(&compact)
}

pub(crate) fn normalize_shiftable_table_indices(text: &str) -> String {
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

pub(crate) fn replace_number_before_first_quote(text: &str, replacement: &str) -> String {
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

pub(crate) fn replace_trailing_numbers(text: &str, count: usize, replacement: &str) -> String {
    let mut out = text.to_string();
    for _ in 0..count {
        let Some((start, end)) = last_number_span(&out) else {
            break;
        };
        out.replace_range(start..end, replacement);
    }
    out
}

pub(crate) fn last_number_span(text: &str) -> Option<(usize, usize)> {
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

pub(crate) fn normalize_anonymous_function_refs(text: &str) -> String {
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

pub(crate) fn extract_quoted_refs(text: &str) -> Vec<String> {
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

pub(crate) fn extract_function_refs(text: &str) -> Vec<String> {
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

pub(crate) fn hash_text(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn export_sqlite(functions: &[FunctionRecord], path: &Path) -> Result<()> {
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
