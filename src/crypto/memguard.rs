use anyhow::Result;

/// Zeroes a slice. Uses `zeroize` under the hood.
pub fn burn(buf: &mut [u8]) {
    use zeroize::Zeroize;
    buf.zeroize();
}

#[cfg(unix)]
pub fn lock_memory(buf: &[u8]) -> Result<()> {
    unsafe {
        let ret = libc::mlock(buf.as_ptr() as *const _, buf.len());
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn lock_memory(_buf: &[u8]) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn unlock_memory(buf: &[u8]) -> Result<()> {
    unsafe {
        let ret = libc::munlock(buf.as_ptr() as *const _, buf.len());
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn unlock_memory(_buf: &[u8]) -> Result<()> {
    Ok(())
}
