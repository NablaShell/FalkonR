use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use sha2::{Digest, Sha512};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use walkdir::WalkDir;

use crate::compress;
use crate::crypto::{self, ChunkedWriter, SecureBytes};
use crate::progress::ProgressWriter;
use crate::vault::format::*;

#[derive(Clone)]
struct FileEntry {
    path: PathBuf,
    size: u64,
}

fn scan(root: &Path) -> Result<(Vec<FileEntry>, String)> {
    let dir_name = root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_string());

    let mut entries: Vec<FileEntry> = WalkDir::new(root)
        .into_iter()
        .par_bridge()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            let rel = e.path().strip_prefix(root).ok()?.to_path_buf();
            Some(FileEntry {
                path: rel,
                size: md.len(),
            })
        })
        .collect();

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((entries, dir_name))
}

pub async fn pack(
    dir: &str,
    output: &str,
    password: &SecureBytes,
    duress: Option<&SecureBytes>,
    chunk_size: usize,
) -> Result<()> {
    let root = Path::new(dir).to_path_buf();
    let (entries, dir_name) = tokio::task::spawn_blocking({
        let r = root.clone();
        move || scan(&r)
    })
    .await
    .context("scan task panicked")??;

    if dir_name.len() > MAX_DIR_NAME_LEN as usize {
        bail!("directory name too long");
    }

    let mut total_payload: u64 = 2 + 4 + dir_name.len() as u64 + 64 + 4;
    for e in &entries {
        total_payload += 4 + e.path.as_os_str().len() as u64 + 8 + e.size;
    }

    // ---- real slot (in-memory) ----
    let salt_real = crypto::generate_salt()?;
    let real_slot = tokio::task::spawn_blocking({
        let root = root.clone();
        let entries = entries.clone();
        let dir_name = dir_name.clone();
        let password = password.as_slice().to_vec();
        move || {
            encrypt_slot(
                &password,
                &salt_real,
                chunk_size,
                total_payload,
                "Packing",
                |w, _h| write_archive_body(w, &root, &entries, &dir_name),
            )
        }
    })
    .await
    .context("real slot task panicked")??;

    // ---- duress slot (in-memory) ----
    let duress_slot = if let Some(dpw) = duress {
        let salt_duress = crypto::generate_salt()?;
        let pw = dpw.as_slice().to_vec();
        let slot = tokio::task::spawn_blocking(move || {
            encrypt_slot(
                &pw,
                &salt_duress,
                chunk_size,
                DURESS_MARKER.len() as u64,
                "Packing duress",
                |w, _h| {
                    w.write_all(DURESS_MARKER)?;
                    Ok(())
                },
            )
        })
        .await
        .context("duress slot task panicked")??;
        Some((salt_duress, slot))
    } else {
        None
    };

    // ---- write file ----
    let mut out = File::create(output)
        .await
        .with_context(|| format!("create output {output}"))?;

    // Header
    let mut hdr = Vec::with_capacity(HEADER_SIZE);
    hdr.extend_from_slice(&MAGIC_VAULT.to_be_bytes());
    hdr.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    hdr.push(if duress_slot.is_some() { 2 } else { 1 });
    hdr.push(0u8);
    out.write_all(&hdr).await?;

    // Slot 0
    write_slot(&mut out, &salt_real, &real_slot).await?;

    // Slot 1
    if let Some((salt_duress, slot)) = duress_slot {
        write_slot(&mut out, &salt_duress, &slot).await?;
    }

    out.flush().await?;
    out.sync_all().await?;
    Ok(())
}

async fn write_slot<W>(out: &mut W, salt: &[u8; crypto::SALT_SIZE], slot: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    out.write_all(salt).await?;
    out.write_all(&(slot.len() as u64).to_be_bytes()).await?;
    out.write_all(slot).await?;
    Ok(())
}

/// Encrypts `body` into an in-memory buffer.
fn encrypt_slot<F>(
    password: &[u8],
    salt: &[u8; crypto::SALT_SIZE],
    chunk_size: usize,
    total: u64,
    label: &str,
    body: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(&mut dyn Write, &mut Sha512) -> Result<()>,
{
    let key = crypto::derive_key(password, salt)?;

    let mut out = Vec::with_capacity(1 << 20);
    {
        let mut chunked = ChunkedWriter::new(&mut out, &key, chunk_size)?;
        let mut comp = compress::compress(&mut chunked)?;
        let mut bar = ProgressWriter::new(&mut comp, total, label);

        body(&mut bar, &mut Sha512::new())?;

        bar.finish();
        drop(bar);
        comp.finish()?;
        chunked.finish()?;
    }
    Ok(out)
}

fn write_archive_body<W: Write + ?Sized>(
    w: &mut W,
    root: &Path,
    entries: &[FileEntry],
    dir_name: &str,
) -> Result<()> {
    use std::io::Read;

    let mut hdr = Vec::with_capacity(2 + 4 + dir_name.len() + 64 + 4);
    hdr.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    hdr.extend_from_slice(&(dir_name.len() as u32).to_be_bytes());
    hdr.extend_from_slice(dir_name.as_bytes());
    hdr.extend_from_slice(&[0u8; 64]);
    hdr.extend_from_slice(&MAGIC_VAULT.to_be_bytes());
    w.write_all(&hdr)?;

    for e in entries {
        let path_str = e.path.to_string_lossy().replace('\\', "/");
        let path_bytes = path_str.as_bytes();

        w.write_all(&(path_bytes.len() as u32).to_be_bytes())?;
        w.write_all(path_bytes)?;
        w.write_all(&e.size.to_be_bytes())?;

        let mut f = std::fs::File::open(root.join(&e.path))?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n])?;
        }
    }
    Ok(())
}
