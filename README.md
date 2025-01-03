# blindsight

[![](https://img.shields.io/github/stars/0xdea/blindsight.svg?style=flat&color=yellow)](https://github.com/0xdea/blindsight)
[![](https://img.shields.io/github/forks/0xdea/blindsight.svg?style=flat&color=green)](https://github.com/0xdea/blindsight)
[![](https://img.shields.io/github/watchers/0xdea/blindsight.svg?style=flat&color=red)](https://github.com/0xdea/blindsight)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)

> "There's no such things as survival of the fittest.  
> Survival of the most adequate, maybe.  
> It doesn't matter whether a solution's optimal.  
> All that matters is whether it beats the alternative."
>
> -- Peter Watts, Blindsight (2006)

Red teaming tool to dump LSASS memory, bypassing basic countermeasures.
It uses Transactional NTFS (TxF API) to transparently scramble the memory
dump, to avoid triggering AV/EDR/XDR.

Blog post:

* <https://security.humanativaspa.it/an-offensive-rust-encore>

See also:

* <https://attack.mitre.org/techniques/T1003/001/>
* <https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary>
* <https://www.ired.team/offensive-security/credential-access-and-credential-dumping>
* <https://github.com/fortra/nanodump>
* <https://github.com/w1u0u1/minidump>
* <https://github.com/anthemtotheego/CredBandit>
* <https://github.com/joaoviictorti/RustRedOps>
* <https://github.com/Kudaes/Dumpy>

## Cross-compiling (macOS example)

```sh
$ brew install mingw-w64
$ rustup target add x86_64-pc-windows-gnu
$ cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

Inside an Administrator's PowerShell window:

```sh
C:\> .\blindsight.exe [dump | file_to_unscramble.log]
```

## Examples

Dump LSASS memory:

```sh
C:\> .\blindsight.exe
```

Unscramble memory dump:

```sh
C:\> .\blindsight.exe 29ABE9Hy.log
```

## Tested on

* Microsoft Windows 10 (x64)
* Microsoft Windows 11 (x64)
* Microsoft Windows 11 (ARM64)
* Microsoft Windows Server 2016 (x64)
* Microsoft Windows Server 2019 (x64)
* Microsoft Windows Server 2022 (x64)

*Note: Do not test on production servers, as accessing LSASS might cause system instability!*

## TODO

* Optimize memory usage (simply corrupt "magic bytes" instead of XORing?)
* Use litcrypt2 or similar to encrypt strings locally
* Allow to manually specify LSASS pid to avoid noisy process scans
* Avoid directly opening LSASS handle (e.g., via PssCaptureSnapshot)
* Use https://github.com/Kudaes/DInvoke_rs or similar for API hooks evasion
* https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html
* Implement fileless exfiltration channels (e.g., TFTP, FTP, HTTP...)
* Consider dumping to memory using minidump callbacks instead of TxF API
* https://adepts.of0x.cc/hookson-hootoff/
* Consider better command line handling if minimal is not enough
