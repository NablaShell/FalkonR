use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

pub const SALT_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

const ARGON_MEMORY: u32 = 64 * 1024;
const ARGON_ITERATIONS: u32 = 3;
const ARGON_PARALLELISM: u32 = 2;

pub fn generate_salt() -> Result<[u8; SALT_SIZE]> {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng()
        .try_fill_bytes(&mut salt)
        .context("salt")?;
    Ok(salt)
}

pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    if salt.len() != SALT_SIZE {
        bail!("salt must be {SALT_SIZE} bytes, got {}", salt.len());
    }

    let params = Params::new(
        ARGON_MEMORY,
        ARGON_ITERATIONS,
        ARGON_PARALLELISM,
        Some(KEY_SIZE),
    )
    .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_SIZE];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(key)
}
