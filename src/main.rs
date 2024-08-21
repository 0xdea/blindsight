//
// blindsight - Dump LSASS memory bypassing countermeasures
// Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//
// > "There's no such things as survival of the fittest.
// > Survival of the most adequate, maybe.
// > It doesn't matter whether a solution's optimal.
// > All that matters is whether it beats the alternative."
// >
// > -- Peter Watts, Blindsight (2006)
//
// Red teaming tool to dump LSASS memory, bypassing common countermeasures.
// It uses Transactional NTFS (TxF API) to transparently scramble the memory
// dump, to avoid triggering AV/EDR/XDR.
//

use std::env;
use std::path::Path;
use std::process;

const PROG: &str = "bindsight.exe";

fn main() {
    println!("blindsight - Dump LSASS memory bypassing countermeasures");
    println!("Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>");
    println!();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    let prog = Path::new(&args[0])
        .file_name()
        .unwrap()
        .to_str()
        .unwrap_or(PROG);

    let action = match args.len() {
        1 => "dump",
        2 => &args[1].clone(),
        _ => {
            usage(prog);
            process::exit(1);
        }
    };
    if action.starts_with('-') {
        usage(prog);
        process::exit(1);
    }

    // Let's do it
    match blindsight::run(action) {
        Ok(()) => (),
        Err(err) => {
            eprintln!("[!] Error: {err}");
            process::exit(1);
        }
    }
}

/// Print usage information
fn usage(prog: &str) {
    println!("Usage:");
    println!(".\\{prog} [dump | file_to_unscramble.log]");
    println!("\nExamples:");
    println!(".\\{prog}");
    println!(".\\{prog} 29ABE9Hy.log");
}
