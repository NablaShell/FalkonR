mod cli;
mod compress;
mod crypto;
mod progress;
mod vault;
mod wipe;

use std::process::ExitCode;

use cli::Args;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(1);
        }
    };

    let result = if let Some(dir) = args.lock.as_ref() {
        lock(dir, &args).await
    } else if let Some(file) = args.unlock.as_ref() {
        unlock(file, &args).await
    } else {
        eprintln!("Use --lock <dir> or --unlock <file>");
        return ExitCode::from(1);
    };

    match result {
        Ok(()) => {
            println!("Done.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn lock(dir: &str, args: &Args) -> anyhow::Result<()> {
    let meta = tokio::fs::metadata(dir).await?;
    if !meta.is_dir() {
        anyhow::bail!("--lock target is not a directory: {dir}");
    }

    // ---- Password flow with duress ----
    let (password, duress) = cli::prompt_lock_passwords()?;

    let chunk_size = detect_chunk_size();
    eprintln!("Chunk size: {} MB", chunk_size / (1024 * 1024));

    vault::pack(dir, &args.output, &password, duress.as_ref(), chunk_size).await?;
    eprintln!("Wiping source...");
    if let Err(e) = wipe::dir(dir).await {
        eprintln!("Warning: wipe failed: {e}");
    }
    Ok(())
}

async fn unlock(file: &str, _args: &Args) -> anyhow::Result<()> {
    tokio::fs::metadata(file).await?;

    let password = cli::prompt_password("Password: ")?;

    match vault::unpack(file, ".", &password).await {
        Ok(()) => Ok(()),
        Err(e) if e.to_string() == vault::DURESS_ERR => {
            if cli::confirm("Duress password detected. Destroy vault?")? {
                wipe::file(file).await?;
                println!("Vault destroyed.");
            } else {
                println!("Cancelled.");
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}
/// Reads /proc/meminfo on Linux; falls back to 256 MiB elsewhere.
fn detect_chunk_size() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(data) = std::fs::read_to_string("/proc/meminfo") {
            for line in data.lines() {
                if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    if let Some(kb) = rest.split_whitespace().next() {
                        if let Ok(kb) = kb.parse::<u64>() {
                            let chunk = (kb * 1024 / 4) as usize;
                            return chunk.clamp(16 * 1024 * 1024, 1024 * 1024 * 1024);
                        }
                    }
                }
            }
        }
    }
    256 * 1024 * 1024
}
