mod entropy;
mod ioc;
mod pe;
mod schema;
mod strings;
mod yara_scan;

use clap::{Parser, Subcommand};
use rayon::prelude::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

#[derive(Parser)]
#[command(
    name = "offsetscan",
    about = "Standalone native corpus-scale static-triage engine — schema-compatible with OffsetInspect.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Emit newline-delimited JSON (one compact object per line) instead of a pretty array.
    /// Results stream as each file finishes, so peak memory stays flat over large corpora.
    #[arg(long, global = true)]
    ndjson: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse PE headers/sections/imports/imphash/overlay for one or more files.
    Pe {
        /// File or directory (use --recurse for directories) or glob pattern.
        path: String,
        #[arg(long)]
        recurse: bool,
        /// Map this file offset (decimal or 0x-hex) to its containing PE section.
        #[arg(long, value_parser = parse_offset)]
        offset: Option<u64>,
    },
    /// Per-window Shannon entropy for one or more files.
    Entropy {
        path: String,
        #[arg(long, default_value_t = 256)]
        window: usize,
        #[arg(long, default_value_t = 7.0)]
        high_threshold: f64,
        #[arg(long)]
        recurse: bool,
    },
    /// Extract ASCII/UTF-16LE printable strings for one or more files.
    Strings {
        path: String,
        #[arg(long, default_value_t = 4)]
        min_length: usize,
        #[arg(long)]
        recurse: bool,
    },
    /// Consolidated IOC panel (hashes, entropy, PE info, string count).
    Ioc {
        path: String,
        #[arg(long)]
        recurse: bool,
    },
}

/// Parse a byte offset given as decimal or `0x`-prefixed hexadecimal.
fn parse_offset(s: &str) -> Result<u64, String> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).map_err(|e| e.to_string()),
        None => s.parse::<u64>().map_err(|e| e.to_string()),
    }
}

fn expand_paths(path: &str, recurse: bool) -> Vec<PathBuf> {
    let p = Path::new(path);
    if p.is_file() {
        return vec![p.to_path_buf()];
    }
    if p.is_dir() {
        let mut out = Vec::new();
        if recurse {
            for entry in walkdir::WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    out.push(entry.into_path());
                }
            }
        } else if let Ok(read) = fs::read_dir(p) {
            for entry in read.filter_map(|e| e.ok()) {
                if entry.path().is_file() {
                    out.push(entry.path());
                }
            }
        }
        return out;
    }
    // Treat as glob pattern.
    glob::glob(path)
        .map(|paths| paths.filter_map(|p| p.ok()).collect())
        .unwrap_or_default()
}

fn main() {
    let cli = Cli::parse();
    let ndjson = cli.ndjson;

    match cli.command {
        Commands::Pe {
            path,
            recurse,
            offset,
        } => {
            let files = expand_paths(&path, recurse);
            run(files, ndjson, move |f| {
                let data = fs::read(f).ok()?;
                let mut info = pe::parse_pe(&data, &f.to_string_lossy()).ok()?;
                if let Some(off) = offset {
                    info.mapped_offset = Some(off);
                    info.mapped_section = pe::offset_to_section(&data, off).ok().flatten();
                }
                Some(info)
            });
        }
        Commands::Entropy {
            path,
            window,
            high_threshold,
            recurse,
        } => {
            let files = expand_paths(&path, recurse);
            run(files, ndjson, move |f| {
                let data = fs::read(f).ok()?;
                Some(entropy::build_entropy_result(
                    &data,
                    &f.to_string_lossy(),
                    window,
                    high_threshold,
                ))
            });
        }
        Commands::Strings {
            path,
            min_length,
            recurse,
        } => {
            let files = expand_paths(&path, recurse);
            run(files, ndjson, move |f| {
                let data = fs::read(f).ok()?;
                let mut hits = strings::extract_ascii_strings(&data, min_length);
                hits.extend(strings::extract_utf16le_strings(&data, min_length));
                Some((f.to_string_lossy().to_string(), hits))
            });
        }
        Commands::Ioc { path, recurse } => {
            let files = expand_paths(&path, recurse);
            run(files, ndjson, move |f| {
                let data = fs::read(f).ok()?;
                Some(ioc::build_ioc_panel(&data, &f.to_string_lossy()))
            });
        }
    }
}

/// Process files in parallel and emit results. In `--ndjson` mode each result is written as
/// one compact line as it completes, so peak memory stays flat regardless of corpus size.
/// Otherwise every result is collected and printed as a single pretty JSON array
/// (input-order-preserving, a drop-in for OffsetInspect's array output).
fn run<T, F>(files: Vec<PathBuf>, ndjson: bool, process: F)
where
    T: serde::Serialize + Send,
    F: Fn(&Path) -> Option<T> + Sync,
{
    if ndjson {
        files.par_iter().for_each(|f| {
            if let Some(result) = process(f) {
                emit_ndjson_line(&result);
            }
        });
    } else {
        let results: Vec<T> = files.par_iter().filter_map(|f| process(f)).collect();
        print_json(&results);
    }
}

fn emit_ndjson_line<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(s) => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            let _ = writeln!(lock, "{s}");
        }
        Err(e) => eprintln!("failed to serialize output: {e}"),
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("failed to serialize output: {e}"),
    }
}
