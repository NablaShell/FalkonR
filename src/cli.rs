use std::io::{self, Write};

use anyhow::{Context, Result, bail};
use clap::Parser;
use zeroize::Zeroizing;

use crate::crypto::SecureBytes;

#[derive(Parser, Debug)]
#[command(
    name = "FalkonR",
    about = "FalkonR — encrypted directory archiver
Version: 0.1.0",
    disable_help_flag = true
)]
pub struct Args {
    #[arg(long, short = 'l', value_name = "DIR")]
    pub lock: Option<String>,

    #[arg(long, short = 'u', value_name = "FILE")]
    pub unlock: Option<String>,

    #[arg(long, short = 'o', value_name = "PATH", default_value = "vault.bak")]
    pub output: String,

    #[arg(long, short = 'v')]
    pub verbose: bool,

    #[arg(long, short = 'h', action = clap::ArgAction::Help)]
    pub help: Option<bool>,
}

impl Args {
    pub fn parse() -> Result<Self> {
        let a = <Self as Parser>::parse();
        if a.lock.is_some() && a.unlock.is_some() {
            bail!("Specify --lock or --unlock, not both.");
        }
        Ok(a)
    }
}

/// Reads a password from the terminal without echo.
pub fn prompt_password(prompt: &str) -> Result<SecureBytes> {
    let pw = rpassword::prompt_password(prompt).context("read password")?;
    Ok(SecureBytes::from(pw.into_bytes()))
}

fn read_confirmed(prompt1: &str, prompt2: &str) -> Result<SecureBytes> {
    let p1 = prompt_password(prompt1)?;
    let p2 = prompt_password(prompt2)?;
    if p1.as_slice() != p2.as_slice() {
        bail!("passwords do not match");
    }
    Ok(p1)
}

/// Interactive password flow for `--lock`:
///
/// 1. Ask for the main password twice.
/// 2. Ask: "Do you want use duress password? y/N: "
/// 3. If yes, ask for the duress password twice (must differ from main).
///
/// Returns `(main_password, Option<duress_password>)`.
pub fn prompt_lock_passwords() -> Result<(SecureBytes, Option<SecureBytes>)> {
    let main = read_confirmed("Password: ", "Confirm:  ")?;

    let use_duress = confirm("Do you want use duress password?")?;
    if !use_duress {
        return Ok((main, None));
    }

    let duress = read_confirmed("Duress password: ", "Confirm duress: ")?;
    if duress.as_slice() == main.as_slice() {
        bail!("duress password must differ from the main password");
    }

    Ok((main, Some(duress)))
}

/// YES/no confirmation. Default is "no" — Enter means "no".
pub fn confirm(prompt: &str) -> Result<bool> {
    let mut stdout = io::stdout();
    write!(stdout, "{prompt} [y/N]: ")?;
    stdout.flush()?;

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(ans == "y" || ans == "yes")
}

/// Never used — kept for parity with Go version.
#[allow(dead_code)]
pub fn _unused_zeroize() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::new())
}
