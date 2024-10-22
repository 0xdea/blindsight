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
        _ => "-",
    };
    if action.starts_with('-') {
        usage(prog);
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

/// Print usage information and exit
fn usage(prog: &str) {
    println!("Usage:");
    println!(".\\{prog} [dump | file_to_unscramble.log]");
    println!("\nExamples:");
    println!(".\\{prog}");
    println!(".\\{prog} 29ABE9Hy.log");

    process::exit(1);
}
