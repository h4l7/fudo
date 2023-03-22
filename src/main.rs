// Author: Nicholas Haltmeyer <halt@dtllc.io>
// Created: 2022-06-03 <%Y-%M-%D>
// Copyright (c) 2022 Liberas Inc - All Rights Reserved

#![crate_name = "fudo"]
//! # fudo
//! Command line utility to encrypt binary distributions, launch encrypted binaries without ever storing plaintext on disk, decrypt files, and scrub files from disk.

use aead::{stream, NewAead};
use anyhow::anyhow;
use chacha20poly1305::XChaCha20Poly1305;
use clap::Parser;
use dialoguer::{Confirm, Password};
use filetime::FileTime;
use indicatif::{ProgressBar, ProgressStyle};
use libc::c_char;

use rand::{rngs::OsRng, Rng, RngCore};
use std::{
    env,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::{io::FromRawFd, prelude::AsRawFd},
    path::PathBuf,
};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(clap::Parser, Debug)]
#[clap(author, version, about=SPLASH_BIJA)]
struct Args {
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(clap::Subcommand, Debug)]
enum Mode {
    #[clap(about = "Encrypt the provided file using XChaCha20-Poly1305")]
    Encrypt {
        #[clap(help = "Input file")]
        bin: String,
        #[clap(short = 'o', help = "Output file")]
        enc: String,
    },
    #[clap(about = "Decrypt the provided file using XChaCha20-Poly1305")]
    Decrypt {
        #[clap(help("Input file"))]
        enc: String,
        #[clap(short = 'o', help = "Output file")]
        bin: String,
    },
    #[clap(about = "Scrub the provided file from the file system")]
    Scrub {
        #[clap(help = "Input file")]
        bin: String,
        #[clap(long, default_value = "2", help = "passes")]
        passes: usize,
    },
    #[clap(about = "Launch the provided encrypted static binary in memory")]
    Launch {
        #[clap(help = "Input file")]
        enc: String,
        #[clap(long, help = "Arguments to forward, as a space delimited list")]
        forward_args: Option<String>,
        #[clap(
            long,
            help = "Environment variables to forward, as a space delimited KEY=VALUE list"
        )]
        forward_env: Option<String>,
    },
}

/// Length of `chacha20poly1305::Key`
const KEY_LEN: usize = 32;
/// MTU of each XChaCha20Poly1305 message
const MSG_LEN: usize = 4096 - TAG_LEN;
/// `A::NonceSize: Sub<U5>` means our 24-byte nonce (with STREAM overhead) becomes 19-byte (sans STREAM overhead)
const NONCE_LEN: usize = 19;
/// Size of salt used in argon2_id PB-KDF
const SALT_LEN: usize = 32;
/// Block size of each scrub pass
const SCRUB_LEN: usize = 512;
/// Length of `chacha20poly1305::Tag`
const TAG_LEN: usize = 16;

const BAR_TEMPLATE: &str = "{elapsed_precise:>8} | {binary_bytes_per_sec:<12} [{bar:40.red}] {bytes:>10} / {total_bytes:<10} {msg}";
const BAR_CHARS: &str = "=> ";

const DIALOG_PASSWD: &str = "password";
const DIALOG_PASSWD_CONF: &str = "password (confirm)";
const DIALOG_PASSWD_ERROR: &str = "passwords entered do not match.";

const SPLASH_BIJA: &str = "
                .-+%@#+-.                         
            .-*%@@@@@@@@@@#+-                     
            -+#@@@@@@@@@@#+-.-+#*-.               
 -:             :=#@@#=:.-+%@@@@@@@@#+-           
  .-=-.           .:=+#@@@@@@@@@@@@%*=:--.        
     .=**+---=+*%@@@@@@@@@@@@@@@#=.               
        .=#@@@@@@@@@@@@@@@@@#+:    .-=++-.        
            -*%@@@@@@%#*##%*=::=*%@@@@@@@@@#+=:   
          :=++++=--=+*%@@@@@@@@@@@@@@@@@@@#*+-:.  
   =-:..=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*=.         
   :*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-             
       .:-=*#@@@@@@@@@@@@@@@@@@@@@*               
          :=*%@@@@@@@@@@@#@@@@@@@@+               
     .-+%@@@@@@@@@@@@@@%+--=*%@@@@@*.             
 .=*@@@@@@@@@@@@@#%%@@@@@@@@@#**+*%@@#=.          
*@@@@@@@@@@@#+--*@@@@@@@@@@@@@@@@%+:.:-++=-:      
:*%@@@@@@*:  =%@@@@@@@@@@@%*#@@@@@@@%-      ....  
   .:=*%@= +@@@@@@@@@@@@+. =@@@@@@@@@@.           
         :@@@@@@@@@@@@+   =@@@@@@@@@@=            
          :=*%@@@@@@%.   :@@@@@@@@@%.             
               .:-=*+    -@@@@@@@@%               
                           :=*%@@@#               
                                :-+#*-.           
                                     .:-::.       
                                           ..     
";

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.mode {
        Mode::Encrypt { bin, enc } => {
            let bin_path: PathBuf = bin.try_into()?;
            let bin_file = File::open(&bin_path)?;
            let bin_metadata = bin_file.metadata()?;

            assert!(bin_metadata.is_file());

            let bin_len = bin_metadata.len();
            let mut bin_read = BufReader::new(bin_file);
            let mut enc_write = BufWriter::new(File::create(enc)?);

            let bar = ProgressBar::new(bin_len);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template(BAR_TEMPLATE)
                    .progress_chars(BAR_CHARS),
            );

            encrypt_file(&mut bin_read, &mut enc_write, bar)?;
        }
        Mode::Decrypt { enc, bin } => {
            let enc_path: PathBuf = enc.try_into()?;
            let enc_file = File::open(&enc_path)?;
            let enc_metadata = enc_file.metadata()?;

            assert!(enc_metadata.is_file());

            let enc_len = enc_metadata.len();
            let mut enc_read = BufReader::new(enc_file);
            let mut bin_write = BufWriter::new(File::create(bin)?);

            let bar = ProgressBar::new(enc_len);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template(BAR_TEMPLATE)
                    .progress_chars(BAR_CHARS),
            );

            decrypt_file(&mut enc_read, &mut bin_write, bar)?;
        }
        Mode::Scrub { bin, passes } => {
            scrub(&bin, passes)?;
        }
        Mode::Launch {
            enc,
            forward_args,
            forward_env,
        } => {
            let enc_path: PathBuf = enc.try_into()?;
            let enc_file = File::open(&enc_path)?;
            let enc_metadata = enc_file.metadata()?;

            assert!(enc_metadata.is_file());

            let enc_len = enc_metadata.len();
            let mut enc_read = BufReader::new(enc_file);

            let bar = ProgressBar::new(enc_len);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template(BAR_TEMPLATE)
                    .progress_chars(BAR_CHARS),
            );

            let mfd_cstring = CString::new(Uuid::new_v4().to_string())?;

            unsafe {
                let bin_mfd = libc::memfd_create(mfd_cstring.into_raw(), libc::MFD_CLOEXEC);
                let mut bin_file = File::from_raw_fd(bin_mfd);
                decrypt_file(&mut enc_read, &mut bin_file, bar)?;

                let bin_mfd = bin_file.as_raw_fd();
                launch(&bin_mfd, forward_args, forward_env)?;
            }
        }
    }

    Ok(())
}

// Used dexios secure_erase as reference
// https://github.com/brxken128/dexios/commit/30a95c477b670cfa8b8300501e9038d19675025d
// TODO Need to compare with GNU shred and scrub(1)
fn scrub(bin_fd: &str, passes: usize) -> anyhow::Result<()> {
    let bin_file = File::open(bin_fd)?;
    let metadata = bin_file.metadata()?;

    assert!(metadata.is_file());
    assert!(!metadata.permissions().readonly());

    let bin_len = metadata.len();
    let bin_blocks = bin_len / SCRUB_LEN as u64;
    let bin_residue = bin_len - (bin_blocks * SCRUB_LEN as u64);

    if !Confirm::new()
        .with_prompt(format!("Are you sure you want to scrub {bin_fd}?"))
        .default(false)
        .interact()?
    {
        return Ok(());
    }

    let bar = ProgressBar::new_spinner();

    // Modifying the file in-place.
    {
        let mut buffer = [0u8; SCRUB_LEN];
        let mut bin_file = OpenOptions::new().write(true).open(bin_fd)?;

        for i in 0..passes {
            bar.set_message(format!("{}/{passes:}", i + 1));
            bar.tick();

            let inner_bar = ProgressBar::new(bin_len);
            inner_bar.set_style(
                ProgressStyle::default_bar()
                    .template(BAR_TEMPLATE)
                    .progress_chars(BAR_CHARS),
            );

            bin_file.seek(SeekFrom::Start(0))?;

            for _ in 0..bin_blocks {
                OsRng.fill_bytes(&mut buffer);
                bin_file.write_all(&buffer)?;
                inner_bar.inc(SCRUB_LEN as u64);
            }

            OsRng.fill_bytes(&mut buffer[..bin_residue as usize]);
            bin_file.write_all(&buffer[..bin_residue as usize])?;
            inner_bar.inc(bin_residue);

            // Hit the plunger.
            bin_file.flush()?;

            inner_bar.finish_and_clear();
        }
    }

    // Overwrite with zeroes, then truncate
    {
        bar.set_message("Zeroing...".to_owned());
        bar.tick();

        let inner_bar = ProgressBar::new(bin_len);
        inner_bar.set_style(
            ProgressStyle::default_bar()
                .template(BAR_TEMPLATE)
                .progress_chars(BAR_CHARS),
        );
        let buffer = [0u8; SCRUB_LEN];
        let mut bin_file = OpenOptions::new().write(true).open(bin_fd)?;
        bin_file.seek(SeekFrom::Start(0))?;

        for _ in 0..bin_blocks {
            bin_file.write_all(&buffer)?;
            inner_bar.inc(SCRUB_LEN as u64);
        }

        bin_file.write_all(&buffer[..bin_residue as usize])?;
        inner_bar.inc(bin_residue);

        // Hit the plunger.
        bin_file.flush()?;

        // Truncate
        bin_file.set_len(0)?;
        bin_file.flush()?;

        inner_bar.finish_and_clear();
        // NOTE maybe(?) rename file for `passes`
    }

    filetime::set_file_times(bin_fd, FileTime::zero(), FileTime::zero())?;
    std::fs::remove_file(bin_fd)?;
    bar.finish_and_clear();

    Ok(())
}

/// Dispatch decrypted binary from its fildes through `fexecve(3)`.
unsafe fn launch(
    mfd: &impl AsRawFd,
    forward_args: Option<String>,
    forward_env: Option<String>,
) -> anyhow::Result<()> {
    // argv: *const *const c_char
    let forward_args_string: String;

    if let Some(forward_args_string_tmp) = forward_args {
        forward_args_string = forward_args_string_tmp;
    } else {
        forward_args_string = "".to_owned();
    }

    let args: Vec<CString> = shlex::split(&forward_args_string)
        .unwrap()
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).unwrap())
        .collect();
    let mut args_raw: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
    args_raw.push(std::ptr::null());
    let argv: *const *const c_char = args_raw.as_ptr();

    // envp: *const *const c_char
    let envs: Vec<CString>;

    if let Some(forward_env_string) = forward_env {
        envs = shlex::split(&forward_env_string)
            .unwrap()
            .iter()
            .map(|env| CString::new(env.as_bytes()).unwrap())
            .collect();
    } else {
        let vars = env::vars();
        envs = vars
            .map(|(k, v)| CString::new(format!("{k}={v}").as_bytes()).unwrap())
            .collect();
    }

    let mut envs_raw: Vec<*const c_char> = envs.iter().map(|env| env.as_ptr()).collect();
    envs_raw.push(std::ptr::null());
    let envp: *const *const c_char = envs_raw.as_ptr();

    match libc::fexecve(mfd.as_raw_fd(), argv, envp) {
        libc::EXIT_SUCCESS => {
            Ok(())
        },
        libc::EINVAL => {
            Err(anyhow!("EINVAL fd is not a valid file descriptor, or argv is NULL, or envp is NULL."))
        },
        libc::ENOENT => {
            Err(anyhow!("ENOENT The close-on-exec flag is set on fd, and fd refers to a script. See man fexecve for more."))
        },
        libc::ENOSYS => {
            Err(anyhow!("ENOSYS The kernel does not provide the execveat(2) system call, and the /proc filesystem could not be accessed."))
        }
        _ => {
            unreachable!();
        }
    }
}

fn encrypt_file(
    bin_file: &mut impl Read,
    enc_file: &mut impl Write,
    bar: ProgressBar,
) -> anyhow::Result<()> {
    let mut password = Password::new()
        .with_prompt(DIALOG_PASSWD)
        .with_confirmation(DIALOG_PASSWD_CONF, DIALOG_PASSWD_ERROR)
        .interact()?;

    let mut salt: [u8; SALT_LEN] = OsRng.gen();
    let mut nonce: [u8; NONCE_LEN] = OsRng.gen();

    let mut key = derive_key(&password, &salt);
    password.zeroize();

    let aead = XChaCha20Poly1305::new(&key);
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, &nonce.into());

    enc_file.write_all(&salt)?;
    enc_file.write_all(&nonce)?;

    let mut buffer = vec![0; MSG_LEN + TAG_LEN];
    let mut filled: usize = 0;

    loop {
        let read_count = bin_file.read(&mut buffer[filled..MSG_LEN])?;
        filled += read_count;

        if filled == MSG_LEN {
            buffer.truncate(MSG_LEN);
            stream_encryptor.encrypt_next_in_place(&[], &mut buffer)?;
            enc_file.write_all(&buffer)?;
            bar.inc(filled as u64);
            filled = 0;
        } else if read_count == 0 {
            buffer.truncate(filled);
            stream_encryptor.encrypt_last_in_place(&[], &mut buffer)?;
            enc_file.write_all(&buffer)?;
            bar.inc(filled as u64);

            break;
        }
    }

    key.zeroize();
    nonce.zeroize();
    salt.zeroize();
    bar.finish_and_clear();

    Ok(())
}

fn decrypt_file(
    enc_file: &mut impl Read,
    bin_file: &mut impl Write,
    bar: ProgressBar,
) -> anyhow::Result<()> {
    let mut password = Password::new()
        .with_prompt(DIALOG_PASSWD)
        .with_confirmation(DIALOG_PASSWD_CONF, DIALOG_PASSWD_ERROR)
        .interact()?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];

    enc_file.read_exact(&mut salt)?;

    enc_file.read_exact(&mut nonce)?;

    let mut key = derive_key(&password, &salt);
    password.zeroize();

    let aead = XChaCha20Poly1305::new(&key);
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, &nonce.into());

    let mut buffer = vec![0u8; MSG_LEN + TAG_LEN];
    let mut filled = 0;

    loop {
        let read_count = enc_file.read(&mut buffer[filled..])?;
        filled += read_count;

        if filled == MSG_LEN + TAG_LEN {
            stream_decryptor.decrypt_next_in_place(&[], &mut buffer)?;
            bin_file.write_all(&buffer)?;
            buffer.zeroize();
            buffer.resize(MSG_LEN + TAG_LEN, 0);
            bar.inc(filled as u64);
            filled = 0;
        } else if read_count == 0 {
            buffer.truncate(filled);
            stream_decryptor.decrypt_last_in_place(&[], &mut buffer)?;
            bin_file.write_all(&buffer)?;
            bar.inc(filled as u64);

            break;
        }
    }

    key.zeroize();
    nonce.zeroize();
    salt.zeroize();
    bar.finish_and_clear();

    Ok(())
}

fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> chacha20poly1305::Key {
    let config = &argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: KEY_LEN as u32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };

    let key: [u8; KEY_LEN] = argon2::hash_raw(password.as_bytes(), salt, config)
        .expect("our hardcoded config is valid")
        .try_into()
        .expect("we configured it to be KEY_LEN");
    key.into()
}
