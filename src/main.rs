mod entropy;
mod ioc;
mod pe;
mod schema;
mod strings;
mod yara_scan;

use clap::{Parser, Subcommand};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "offsetscan",
    about = "Standalone native corpus-scale static-triage engine — schema-compatible with OffsetInspect.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse PE headers/sections/imports/imphash/overlay for one or more files.
    Pe {
        /// File or directory (use --recurse for directories) or glob pattern.
        path: String,
        #[arg(long)]
        recurse: bool,
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

    match cli.command {
        Commands::Pe { path, recurse } => {
            let files = expand_paths(&path, recurse);
            let results: Vec<_> = files
                .par_iter()
                .filter_map(|f| {
                    let data = fs::read(f).ok()?;
                    let path_str = f.to_string_lossy().to_string();
                    pe::parse_pe(&data, &path_str).ok()
                })
                .collect();
            print_json(&results);
        }
        Commands::Entropy {
            path,
            window,
            high_threshold,
            recurse,
        } => {
            let files = expand_paths(&path, recurse);
            let results: Vec<_> = files
                .par_iter()
                .filter_map(|f| {
                    let data = fs::read(f).ok()?;
                    Some(entropy::build_entropy_result(
                        &data,
                        &f.to_string_lossy(),
                        window,
                        high_threshold,
                    ))
                })
                .collect();
            print_json(&results);
        }
        Commands::Strings {
            path,
            min_length,
            recurse,
        } => {
            let files = expand_paths(&path, recurse);
            let results: Vec<_> = files
                .par_iter()
                .filter_map(|f| {
                    let data = fs::read(f).ok()?;
                    let mut hits = strings::extract_ascii_strings(&data, min_length);
                    hits.extend(strings::extract_utf16le_strings(&data, min_length));
                    Some((f.to_string_lossy().to_string(), hits))
                })
                .collect();
            print_json(&results);
        }
        Commands::Ioc { path, recurse } => {
            let files = expand_paths(&path, recurse);
            let results: Vec<_> = files
                .par_iter()
                .filter_map(|f| {
                    let data = fs::read(f).ok()?;
                    let path_str = f.to_string_lossy().to_string();
                    Some(ioc::build_ioc_panel(&data, &path_str))
                })
                .collect();
            print_json(&results);
        }
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("failed to serialize output: {e}"),
    }
}
