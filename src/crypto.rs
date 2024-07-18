use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};

const KEY: &[u8] = b"DEADBEEF";

pub fn encrypt() -> Result<(), Box<dyn Error>> {
    todo!();
}

pub fn decrypt(path: &str) -> Result<(), Box<dyn Error>> {
    let len = fs::metadata(path)?.len();
    let mut file = File::open(path)?;

    let mut buf = Vec::<u8>::new();
    file.read_to_end(&mut buf)?;

    xor(buf.as_mut_slice(), KEY);

    let mut out_file = File::create_new("lsass.dmp")?;
    let _count = out_file.write(&buf)?;
    println!("[+] Successfully created output file");

    Ok(())
}

pub fn xor(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(byte, key_byte)| *byte ^= key_byte);
}
