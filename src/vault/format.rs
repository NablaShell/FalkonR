pub const MAGIC_VAULT: u32 = 0x0BADC0DE;
pub const FORMAT_VERSION: u16 = 2;
pub const MAX_PATH_LEN: u32 = 4096;
pub const MAX_DIR_NAME_LEN: u32 = 255;
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024;

pub const MAX_SLOTS: u8 = 2;

pub const HEADER_SIZE: usize = 4 + 2 + 1 + 1; // magic + version + slot_count + pad

/// Payload written to a duress slot instead of the real archive.
pub const DURESS_MARKER: &[u8] = b"\x00\x00DURESS\x00\x00";
