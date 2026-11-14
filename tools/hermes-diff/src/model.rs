use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstructionRecord {
    pub(crate) index: usize,
    pub(crate) offset: u32,
    pub(crate) opcode: String,
    pub(crate) formatted_text: String,
    pub(crate) normalized_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FunctionRecord {
    pub(crate) id: u32,
    pub(crate) name: Option<String>,
    pub(crate) display_name: String,
    pub(crate) offset: u32,
    pub(crate) param_count: u32,
    pub(crate) register_count: u32,
    pub(crate) symbol_count: u32,
    pub(crate) bytecode_size: u32,
    pub(crate) header_type: String,
    pub(crate) instruction_count: usize,
    pub(crate) opcode_hash: String,
    pub(crate) instruction_hash: String,
    pub(crate) string_refs_hash: String,
    pub(crate) function_refs_hash: String,
    pub(crate) text: String,
    pub(crate) instructions: Vec<InstructionRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChangedFunction {
    pub(crate) kind: String,
    pub(crate) slug: String,
    pub(crate) old_id: Option<u32>,
    pub(crate) new_id: Option<u32>,
    pub(crate) old_name: Option<String>,
    pub(crate) new_name: Option<String>,
    pub(crate) ratio: Option<f64>,
    pub(crate) description: String,
    pub(crate) old_hash: Option<String>,
    pub(crate) new_hash: Option<String>,
    pub(crate) files: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) filter: Option<ChangedFunctionFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) js_decompile: Option<ChangedFunctionJsDecompile>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChangedFunctionFilter {
    pub(crate) reason: String,
    pub(crate) similarity_ratio: f64,
    pub(crate) changed_instruction_count: usize,
    pub(crate) weak_instruction_count: usize,
    pub(crate) meaningful_instruction_count: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ChangedFunctionJsDecompile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) old_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) new_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) old_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) new_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Manifest {
    pub(crate) generated_at: String,
    pub(crate) mode: String,
    pub(crate) inputs: BTreeMap<String, String>,
    pub(crate) artifacts: BTreeMap<String, String>,
    pub(crate) stats: ManifestStats,
    pub(crate) functions: Vec<ChangedFunction>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ManifestStats {
    pub(crate) old_functions: usize,
    pub(crate) new_functions: usize,
    pub(crate) exact: usize,
    pub(crate) partial: usize,
    pub(crate) new: usize,
    pub(crate) deleted: usize,
    pub(crate) js_decompile: JsDecompileStats,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct JsDecompileStats {
    pub(crate) enabled: bool,
    pub(crate) old_context_status: String,
    pub(crate) new_context_status: String,
    pub(crate) attempted: usize,
    pub(crate) success: usize,
    pub(crate) failed: usize,
    pub(crate) panicked: usize,
}

impl JsDecompileStats {
    pub(crate) fn disabled() -> Self {
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

pub(crate) struct JsDecompiler {
    pub(crate) file: hbc::BytecodeFile,
    pub(crate) context: hbc::PipelineContext,
}

pub(crate) struct JsDecompilerSet {
    pub(crate) old: Option<JsDecompiler>,
    pub(crate) new: Option<JsDecompiler>,
    pub(crate) stats: JsDecompileStats,
}

pub(crate) enum JsDecompileResult {
    Ok(String),
    Error(String),
    Panic(String),
    Skipped(String),
}

pub(crate) enum JsDecompilerBuildFailure {
    Error,
    Panic,
}
