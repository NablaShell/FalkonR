use std::io::{self, Read, Write};

use anyhow::Result;

pub const DEFAULT_LEVEL: i32 = 3;

pub fn compress<W: Write>(w: W) -> Result<zstd::stream::write::Encoder<'static, W>> {
    let enc = zstd::stream::write::Encoder::new(w, DEFAULT_LEVEL)?;
    Ok(enc)
}

pub fn decompress<R: Read>(r: R) -> Result<zstd::stream::read::Decoder<'static, io::BufReader<R>>> {
    let dec = zstd::stream::read::Decoder::new(r)?;
    Ok(dec)
}
