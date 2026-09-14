use std::io::{Seek, SeekFrom, Write};

use anyhow::{Context, Result, bail};
use rand::RngCore;
use walkdir::WalkDir;

pub async fn file(path: &str) -> Result<()> {
    if path.contains("..") {
        bail!("path must not contain '..'");
    }

    let md = tokio::fs::metadata(path).await?;
    let size = md.len();

    // Use a std File for seek + random writes.
    let path = path.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| format!("open {path}"))?;

        let mut pattern = vec![0u8; 4096];
        for pass in 0..3 {
            f.seek(SeekFrom::Start(0))?;
            let mut rem = size;
            while rem > 0 {
                if pass == 2 {
                    pattern.fill(0);
                } else {
                    rand::thread_rng().fill_bytes(&mut pattern);
                }
                let n = (pattern.len() as u64).min(rem) as usize;
                f.write_all(&pattern[..n])?;
                rem -= n as u64;
            }
            f.sync_all()?;
        }
        drop(f);
        std::fs::remove_file(&path)?;
        Ok(())
    })
    .await
    .context("wipe task panicked")??;

    Ok(())
}

pub async fn dir(path: &str) -> Result<()> {
    let path_owned = path.to_string();
    let files: Vec<String> = tokio::task::spawn_blocking(move || {
        WalkDir::new(&path_owned)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    })
    .await
    .context("walk task panicked")?;

    for f in files {
        file(&f).await?;
    }
    tokio::fs::remove_dir_all(path).await?;
    Ok(())
}
