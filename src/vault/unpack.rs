use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use tokio::fs;

use crate::compress;
use crate::crypto::{self, ChunkedReader, SecureBytes};
use crate::vault::format::*;

pub const DURESS_ERR: &str = "DURESS";

enum SlotKind {
    Real,
    Duress,
}

/// Returns:
///   Ok(Some(Real))    — key подходит, это реальный слот
///   Ok(Some(Duress))  — key подходит, это duress-слот
///   Ok(None)          — key не подходит
fn classify_slot(slot_bytes: &[u8], key: &[u8; crypto::KEY_SIZE]) -> Result<Option<SlotKind>> {
    let cursor = Cursor::new(slot_bytes);
    let chunked = ChunkedReader::new(cursor, key)?;
    let mut dec = compress::decompress(chunked)?;

    let mut buf = vec![0u8; DURESS_MARKER.len()];
    match dec.read_exact(&mut buf) {
        Ok(()) if buf == DURESS_MARKER => Ok(Some(SlotKind::Duress)),
        Ok(()) => Ok(Some(SlotKind::Real)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(Some(SlotKind::Real)),
        Err(_) => Ok(None),
    }
}

pub async fn unpack(vault_path: &str, target_dir: &str, password: &SecureBytes) -> Result<()> {
    if vault_path.contains("..") {
        bail!("vault path must not contain '..'");
    }

    let data = fs::read(vault_path)
        .await
        .with_context(|| format!("read vault {vault_path}"))?;

    if data.len() < HEADER_SIZE {
        bail!("vault too short");
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let version = u16::from_be_bytes([data[4], data[5]]);
    let slot_count = data[6];

    if magic != MAGIC_VAULT {
        bail!("bad magic");
    }
    if version != FORMAT_VERSION {
        bail!("unsupported version {version}");
    }
    if slot_count == 0 || slot_count > MAX_SLOTS {
        bail!("bad slot count {slot_count}");
    }

    let mut off = HEADER_SIZE;

    for idx in 0..slot_count {
        if off + crypto::SALT_SIZE + 8 > data.len() {
            bail!("truncated slot header at slot {idx}");
        }

        let mut salt = [0u8; crypto::SALT_SIZE];
        salt.copy_from_slice(&data[off..off + crypto::SALT_SIZE]);
        off += crypto::SALT_SIZE;

        let slot_len = u64::from_be_bytes(data[off..off + 8].try_into().unwrap()) as usize;
        off += 8;

        if off + slot_len > data.len() {
            bail!("truncated slot body at slot {idx}");
        }
        let slot_bytes = &data[off..off + slot_len];
        off += slot_len;

        let key = crypto::derive_key(password.as_slice(), &salt)?;

        match classify_slot(slot_bytes, &key)? {
            Some(SlotKind::Duress) => {
                return Err(anyhow::anyhow!(DURESS_ERR));
            }
            Some(SlotKind::Real) => {
                let cursor = Cursor::new(slot_bytes);
                let chunked = ChunkedReader::new(cursor, &key)?;
                let dec = compress::decompress(chunked)?;
                return restore_stream(dec, target_dir);
            }
            None => continue,
        }
    }

    bail!("wrong password");
}

// restore_stream, sanitize_component, sanitize_relative — без изменений
fn restore_stream<R: Read>(mut r: R, target_dir: &str) -> Result<()> {
    std::fs::create_dir_all(target_dir)?;
    let target = PathBuf::from(target_dir);

    // Version (2B)
    let mut b2 = [0u8; 2];
    r.read_exact(&mut b2)?;
    let ver = u16::from_be_bytes(b2);
    if ver != FORMAT_VERSION {
        bail!("unsupported inner version {ver}");
    }

    // Dir name length (4B)
    let mut b4 = [0u8; 4];
    r.read_exact(&mut b4)?;
    let name_len = u32::from_be_bytes(b4);
    if name_len > MAX_DIR_NAME_LEN {
        bail!("dirname too long: {name_len}");
    }

    let mut dir_bytes = vec![0u8; name_len as usize];
    r.read_exact(&mut dir_bytes)?;
    let dir_name = String::from_utf8(dir_bytes)?;
    let clean_dir = sanitize_component(&dir_name)?;

    // Skip hash (64) + magic (4)
    let mut skip = [0u8; 68];
    r.read_exact(&mut skip)?;
    let magic = u32::from_be_bytes([skip[64], skip[65], skip[66], skip[67]]);
    if magic != MAGIC_VAULT {
        bail!("bad inner magic");
    }

    let root = target.join(&clean_dir);
    std::fs::create_dir_all(&root)?;

    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let path_len = u32::from_be_bytes(len_buf);
        if path_len == 0 || path_len > MAX_PATH_LEN {
            bail!("bad path length: {path_len}");
        }

        let mut path_bytes = vec![0u8; path_len as usize];
        r.read_exact(&mut path_bytes)?;
        let file_path = String::from_utf8(path_bytes)?;
        let clean = sanitize_relative(&file_path)?;

        let mut size_buf = [0u8; 8];
        r.read_exact(&mut size_buf)?;
        let file_size = u64::from_be_bytes(size_buf);
        if file_size > MAX_FILE_SIZE {
            bail!("file too large: {file_size}");
        }

        let out_path = root.join(&clean);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut out = std::fs::File::create(&out_path)?;
        let mut remaining = file_size;
        let mut buf = [0u8; 64 * 1024];
        while remaining > 0 {
            let n = (buf.len() as u64).min(remaining) as usize;
            r.read_exact(&mut buf[..n])?;
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
    }

    println!("\nRestored: {}", root.display());
    Ok(())
}

fn sanitize_component(s: &str) -> Result<String> {
    let p = std::path::Path::new(s);
    if p.is_absolute() || s.contains('/') || s.contains('\\') || s == ".." || s == "." {
        bail!("invalid root dirname: {s}");
    }
    Ok(s.to_string())
}

fn sanitize_relative(s: &str) -> Result<PathBuf> {
    let p = std::path::Path::new(s);
    if p.is_absolute() {
        bail!("absolute path: {s}");
    }
    for c in p.components() {
        use std::path::Component::*;
        match c {
            Normal(_) => {}
            _ => bail!("path traversal blocked: {s}"),
        }
    }
    Ok(p.to_path_buf())
}
