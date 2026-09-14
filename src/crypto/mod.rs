pub mod argon;
pub mod chunks;

pub use argon::{KEY_SIZE, SALT_SIZE, derive_key, generate_salt};
pub use chunks::{ChunkedReader, ChunkedWriter};

use zeroize::Zeroize;

pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
