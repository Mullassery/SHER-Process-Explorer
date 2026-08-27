//! Stack-sampling profiling (`Tier::Profile`) via the real `perf` tool,
//! following the same "shell out to the real thing" MVP-sized choice
//! `systemd.rs`/`kernel_log.rs` already make, rather than reinventing a
//! native `perf_event_open` sampler + stack unwinder + symbolizer from
//! scratch. Requires `perf` installed and enough privilege
//! (`CAP_PERFMON`/`perf_event_paranoid`) — both surface as a normal
//! `TelemetryError::Io`, since that's exactly what they are: this specific
//! command failing, not a code bug.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use sher_pe_model::{HotFunction, Pid};

use crate::{Result, TelemetryError};

/// Records a short `perf` sample of `pid` for `duration`, then reports the
/// hottest symbols by an overhead percentage. Uses a temp file for the
/// `perf.data` output (rather than piping) because `perf report` needs to
/// seek the file, not just stream it.
pub fn sample_hot_functions(pid: Pid, duration: Duration) -> Result<Vec<HotFunction>> {
    let data_path =
        std::env::temp_dir().join(format!("sher-pe-perf-{pid}-{}.data", std::process::id()));

    let record = Command::new("perf")
        .args([
            "record",
            "--quiet",
            "-p",
            &pid.to_string(),
            "--call-graph",
            "fp",
            "-o",
        ])
        .arg(&data_path)
        .arg("--")
        .arg("sleep")
        .arg(duration.as_secs().max(1).to_string())
        .output()
        .map_err(|source| TelemetryError::Io {
            path: "perf record".to_string(),
            source,
        })?;

    if !record.status.success() {
        let _ = std::fs::remove_file(&data_path);
        return Err(TelemetryError::Io {
            path: "perf record".to_string(),
            source: std::io::Error::other(format!(
                "perf record exited with {}: {}",
                record.status,
                String::from_utf8_lossy(&record.stderr)
            )),
        });
    }

    let report = Command::new("perf")
        .args(["report", "--stdio", "-n", "--sort=overhead,symbol", "-i"])
        .arg(&data_path)
        .output()
        .map_err(|source| TelemetryError::Io {
            path: "perf report".to_string(),
            source,
        });
    let _ = std::fs::remove_file(&data_path);
    let report = report?;

    if !report.status.success() {
        return Err(TelemetryError::Io {
            path: "perf report".to_string(),
            source: std::io::Error::other(format!(
                "perf report exited with {}: {}",
                report.status,
                String::from_utf8_lossy(&report.stderr)
            )),
        });
    }

    parse_perf_report(
        &String::from_utf8_lossy(&report.stdout),
        Path::new("perf report"),
    )
}

/// Parses `perf report --stdio -n --sort=overhead,symbol` output. Format
/// (comment lines start with `#`, blank lines separate sections):
/// ```text
/// # Overhead  Samples  Symbol
/// #   ........  .......  ..............
/// #
///     42.31%       11  [.] malloc
///     18.20%        5  [k] do_syscall_64
/// ```
/// The `[.]`/`[k]` marker (user/kernel space) prefixes the symbol; the
/// module perf attributes it to is not in this particular column layout,
/// so `module` falls back to the marker's meaning ("user"/"kernel") —
/// `--sort=overhead,symbol,dso` would add a real module column at the
/// cost of a wider table this parser would need to handle; deferred until
/// a real need for per-module breakdown shows up.
fn parse_perf_report(stdout: &str, path: &Path) -> Result<Vec<HotFunction>> {
    let mut hot_functions = Vec::new();
    // Counts lines that look like they should have been a data row (not a
    // `#` comment, not blank) but didn't parse — as opposed to simply
    // having zero data rows at all, which is a legitimate "no samples"
    // result, not a parse failure.
    let mut unparsed_data_lines = 0u32;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parsed = (|| -> Option<HotFunction> {
            let (overhead_str, rest) = line.split_once('%')?;
            let overhead_percent = overhead_str.trim().parse::<f64>().ok()?;
            // `rest` is now e.g. `       11  [.] malloc` — skip the sample
            // count, then take the marker + symbol as-is.
            let rest = rest.trim_start();
            let marker_start = rest.find('[')?;
            let symbol_part = rest[marker_start..].trim();
            let module = if symbol_part.starts_with("[k]") {
                "kernel"
            } else {
                "user"
            }
            .to_string();
            // Just the token right after the `[.]`/`[k]` marker — when
            // `perf` can't resolve a symbol name (e.g. a stripped/static
            // binary) it prints the raw address followed by further
            // placeholder columns (`  -      -`) that must not be
            // swept into the symbol string.
            let symbol = symbol_part.split_whitespace().nth(1).unwrap_or("");
            if symbol.is_empty() {
                return None;
            }
            Some(HotFunction {
                symbol: symbol.to_string(),
                module,
                overhead_percent,
            })
        })();

        match parsed {
            Some(hot_function) => hot_functions.push(hot_function),
            None => unparsed_data_lines += 1,
        }
    }

    if hot_functions.is_empty() && unparsed_data_lines > 0 {
        return Err(crate::linux::procfs::common::parse_err(
            path,
            "no recognizable overhead/symbol rows in perf report output",
        ));
    }
    Ok(hot_functions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_perf_report_extracts_overhead_and_symbol() {
        let stdout = "\
# Overhead  Samples  Symbol
#   ........  .......  ..............
#
    42.31%       11  [.] malloc
    18.20%        5  [k] do_syscall_64
    10.00%        3  [.] memcpy
";
        let hot = parse_perf_report(stdout, Path::new("test")).unwrap();
        assert_eq!(hot.len(), 3);
        assert_eq!(hot[0].symbol, "malloc");
        assert_eq!(hot[0].module, "user");
        assert!((hot[0].overhead_percent - 42.31).abs() < 0.001);
        assert_eq!(hot[1].symbol, "do_syscall_64");
        assert_eq!(hot[1].module, "kernel");
    }

    #[test]
    fn parse_perf_report_drops_placeholder_columns_after_unresolved_symbol() {
        // Real output from a stripped/static binary in a minimal
        // container: `perf` can't resolve a name, so it prints the raw
        // address followed by extra `-` placeholder columns that must
        // not end up inside the symbol string.
        let stdout = "\
# Overhead  Samples  Command  Shared Object  Symbol
#   ........  .......  .......  .............  ..............
#
   100.00%       20  sh        libc.so.6  [.] 0x0000aaaadaa446b0  -      -
    50.00%       10  sh        libc.so.6  [.] __libc_start_main   -      -
";
        let hot = parse_perf_report(stdout, Path::new("test")).unwrap();
        assert_eq!(hot.len(), 2);
        assert_eq!(hot[0].symbol, "0x0000aaaadaa446b0");
        assert_eq!(hot[1].symbol, "__libc_start_main");
    }

    #[test]
    fn parse_perf_report_empty_output_is_empty_not_error() {
        let hot = parse_perf_report("", Path::new("test")).unwrap();
        assert!(hot.is_empty());
    }

    #[test]
    fn parse_perf_report_only_comments_is_empty_not_error() {
        let stdout = "# Overhead  Samples  Symbol\n#   ........  .......  ..............\n";
        let hot = parse_perf_report(stdout, Path::new("test")).unwrap();
        assert!(hot.is_empty());
    }
}
