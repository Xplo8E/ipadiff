use std::fs::{self};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use anyhow::{Context, Result};

use crate::Config;
use crate::model::*;

pub(crate) fn prepare_js_decompilers(config: &Config) -> JsDecompilerSet {
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

pub(crate) fn js_context_status(
    result: &std::result::Result<JsDecompiler, JsDecompilerBuildFailure>,
) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(JsDecompilerBuildFailure::Error) => "error".to_string(),
        Err(JsDecompilerBuildFailure::Panic) => "panic".to_string(),
    }
}

pub(crate) fn build_js_decompiler(
    path: &Path,
) -> std::result::Result<JsDecompiler, JsDecompilerBuildFailure> {
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
            eprintln!("[hermes-js-decompile] {error:#}");
            Err(JsDecompilerBuildFailure::Error)
        }
        Err(payload) => {
            eprintln!("[hermes-js-decompile] {}", panic_payload_to_string(payload));
            Err(JsDecompilerBuildFailure::Panic)
        }
    }
}

pub(crate) fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "panic while decompiling Hermes bytecode".to_string()
    }
}

pub(crate) fn decompile_js_function(
    decompiler: Option<&JsDecompiler>,
    function_id: u32,
) -> JsDecompileResult {
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

pub(crate) fn ensure_trailing_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

pub(crate) fn record_js_result(stats: &mut JsDecompileStats, result: &JsDecompileResult) {
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

pub(crate) fn js_result_status(result: &JsDecompileResult) -> String {
    match result {
        JsDecompileResult::Ok(_) => "ok",
        JsDecompileResult::Error(_) => "error",
        JsDecompileResult::Panic(_) => "panic",
        JsDecompileResult::Skipped(_) => "skipped",
    }
    .to_string()
}

pub(crate) fn js_result_error(result: &JsDecompileResult) -> Option<String> {
    match result {
        JsDecompileResult::Error(message)
        | JsDecompileResult::Panic(message)
        | JsDecompileResult::Skipped(message) => Some(message.clone()),
        JsDecompileResult::Ok(_) => None,
    }
}
