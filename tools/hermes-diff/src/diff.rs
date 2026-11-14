use std::collections::{BTreeMap, HashMap, HashSet};

use crate::model::*;
use crate::records::hash_text;

pub(crate) fn diff_functions(
    old: &[FunctionRecord],
    new: &[FunctionRecord],
) -> (Vec<ChangedFunction>, usize) {
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

pub(crate) fn filter_weak_hermes_partials(
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

pub(crate) fn classify_weak_hermes_partial(
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

pub(crate) struct PartialInstructionMetrics {
    pub(crate) similarity_ratio: f64,
    pub(crate) changed_instruction_count: usize,
    pub(crate) weak_instruction_count: usize,
    pub(crate) meaningful_instruction_count: usize,
}

impl PartialInstructionMetrics {
    pub(crate) fn into_filter(self, reason: &str) -> ChangedFunctionFilter {
        ChangedFunctionFilter {
            reason: reason.to_string(),
            similarity_ratio: self.similarity_ratio,
            changed_instruction_count: self.changed_instruction_count,
            weak_instruction_count: self.weak_instruction_count,
            meaningful_instruction_count: self.meaningful_instruction_count,
        }
    }
}

pub(crate) fn partial_instruction_metrics(
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

pub(crate) fn weak_normalized_instruction_text(text: &str) -> String {
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

pub(crate) fn replace_operand(text: &str, operand_index: usize, replacement: &str) -> String {
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

pub(crate) fn duplicate_name_ordinal_matches(
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

pub(crate) fn is_stable_duplicate_name(name: &str) -> bool {
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

pub(crate) fn name_counts(functions: &[FunctionRecord]) -> HashMap<&str, usize> {
    let mut counts = HashMap::new();
    for func in functions {
        if let Some(name) = func.name.as_deref() {
            *counts.entry(name).or_default() += 1;
        }
    }
    counts
}

pub(crate) fn same_id_match_allowed(
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

pub(crate) fn unique_index<'a, I, F>(items: I, key_fn: F) -> BTreeMap<String, u32>
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

pub(crate) fn is_strong_cross_id_match_candidate(func: &FunctionRecord) -> bool {
    func.instruction_count >= 3
        && func.bytecode_size >= 8
        && (func.string_refs_hash != hash_text("")
            || func.function_refs_hash != hash_text("")
            || func.name.is_some())
}

pub(crate) fn kind_order(kind: &str) -> u8 {
    match kind {
        "partial" => 0,
        "new" => 1,
        "deleted" => 2,
        _ => 3,
    }
}

pub(crate) fn make_partial(
    old: &FunctionRecord,
    new: &FunctionRecord,
    reason: &str,
) -> ChangedFunction {
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

pub(crate) fn make_one_sided(kind: &str, func: &FunctionRecord) -> ChangedFunction {
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

pub(crate) fn sanitize_name(value: Option<&str>) -> String {
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

pub(crate) fn similarity_ratio(old: &str, new: &str) -> f64 {
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
