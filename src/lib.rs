use std::error::Error;

mod minidump;
mod crypto;

/// Implement the main logic of the program
pub fn run(action: &str) -> Result<(), Box<dyn Error>> {
    match action {
        "dump" => minidump::dump()?,
        _ => crypto::decrypt(action)?,
    }
    
    Ok(())
}

/// Print usage information
pub fn usage(prog: &str) {
    println!("Usage:");
    println!(".\\{prog} [dump | file_to_decrypt.log]");
    println!("\nExamples:");
    println!(".\\{prog}");
    println!(".\\{prog} 29ABE9Hy.log");
}
