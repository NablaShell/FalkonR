use std::io::{self, Read, Write};

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

const CHUNK_LEN_SIZE: usize = 4;
const NONCE_SIZE: usize = 12;
pub const MIN_CHUNK: usize = 16 * 1024 * 1024;

/// Encrypts plaintext in chunks: `[u32 len][12B nonce][ciphertext+tag]`.
pub struct ChunkedWriter<W: Write> {
    inner: W,
    cipher: ChaCha20Poly1305,
    chunk_size: usize,
    buf: Vec<u8>,
    total: u64,
}

impl<W: Write> ChunkedWriter<W> {
    pub fn new(inner: W, key: &[u8; 32], chunk_size: usize) -> Result<Self> {
        let chunk_size = chunk_size.max(MIN_CHUNK);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Ok(Self {
            inner,
            cipher,
            chunk_size,
            buf: Vec::with_capacity(chunk_size),
            total: 0,
        })
    }

    pub fn total_written(&self) -> u64 {
        self.total
    }

    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }

        let n = self.chunk_size.min(self.buf.len());
        let plain = &self.buf[..n];
        if plain.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk exceeds uint32",
            ));
        }

        self.inner.write_all(&(plain.len() as u32).to_be_bytes())?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.inner.write_all(&nonce_bytes)?;

        let ct = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plain,
                    aad: &[],
                },
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encrypt: {e}")))?;

        self.inner.write_all(&ct)?;
        self.total += n as u64;

        // Drain the consumed prefix.
        self.buf.drain(..n);
        Ok(())
    }
}

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.chunk_size {
            self.flush_chunk()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> ChunkedWriter<W> {
    pub fn finish(mut self) -> io::Result<W> {
        while !self.buf.is_empty() {
            self.flush_chunk()?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}

/// Reads and decrypts chunks produced by [`ChunkedWriter`].
pub struct ChunkedReader<R: Read> {
    inner: R,
    cipher: ChaCha20Poly1305,
    buf: Vec<u8>,
    off: usize,
}

impl<R: Read> ChunkedReader<R> {
    pub fn new(inner: R, key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Ok(Self {
            inner,
            cipher,
            buf: Vec::new(),
            off: 0,
        })
    }

    fn read_chunk(&mut self) -> io::Result<()> {
        let mut len_buf = [0u8; CHUNK_LEN_SIZE];
        self.inner.read_exact(&mut len_buf)?;
        let plain_len = u32::from_be_bytes(len_buf) as usize;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        self.inner.read_exact(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag_size = 16; // Poly1305
        let mut ct = vec![0u8; plain_len + tag_size];
        self.inner.read_exact(&mut ct)?;

        let plain = self
            .cipher
            .decrypt(nonce, Payload { msg: &ct, aad: &[] })
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decrypt: {e}")))?;

        self.buf = plain;
        self.off = 0;
        Ok(())
    }
}

impl<R: Read> Read for ChunkedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.off >= self.buf.len() {
            match self.read_chunk() {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
        }
        let n = (self.buf.len() - self.off).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.off..self.off + n]);
        self.off += n;
        Ok(n)
    }
}

/// Convenience: split a `Vec<u8>` into chunks for parallel encryption.
/// Currently unused directly, but demonstrates the chunking contract.
#[allow(dead_code)]
pub fn split_chunks(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    data.chunks(chunk_size.max(MIN_CHUNK)).collect()
}
