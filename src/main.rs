//!
//! blindsight - Dump LSASS memory bypassing countermeasures
//! Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "There's no such things as survival of the fittest.  
//! > Survival of the most adequate, maybe.  
//! > It doesn't matter whether a solution's optimal.  
//! > All that matters is whether it beats the alternative."  
//! >  
//! > -- Peter Watts, Blindsight (2006)  
//!
//! Simple tool to dump LSASS memory, bypassing common countermeasures.
//! TODO: features.
//!
//! # See also
//! https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary  
//! https://attack.mitre.org/techniques/T1003/001/  
//! https://github.com/fortra/nanodump  
//! https://github.com/w1u0u1/minidump/tree/main/minidump  
//! https://github.com/anthemtotheego/CredBandit  
//! https://github.com/joaoviictorti/RustRedOps  
//! https://github.com/Kudaes/Dumpy  
//!
//! # Cross-compiling
//! ```sh
//! [macOS example]
//! $ brew install mingw-w64
//! $ rustup target add x86_64-pc-windows-gnu
//! $ cargo build --release --target x86_64-pc-windows-gnu
//! ```
//!
//! # Usage
//! ```sh
//! TODO
//! ```
//!
//! # Examples
//! TODO:
//! ```sh
//! TODO
//! ```
//!
//! //! TODO:
//! ```sh
//! TODO
//! ```
//!
//! # Tested on
//! * TODO
//!

use std::env;
use std::path::Path;
use std::process;

use blindsight::*;

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
        .unwrap_or("blindsight.exe");
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
    match run(action) {
        Ok(()) => (),
        Err(err) => {
            eprintln!("[!] Error: {}", err);
            process::exit(1);
        }
    }
}
