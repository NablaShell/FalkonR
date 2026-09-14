use std::io::{Read, Write};
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};

pub struct ProgressReader<R: Read> {
    inner: R,
    bar: ProgressBar,
    total: u64,
    current: u64,
    start: Instant,
}

impl<R: Read> ProgressReader<R> {
    pub fn new(inner: R, total: u64, prefix: &str) -> Self {
        let bar = if console::Term::stderr().is_term() {
            let b = ProgressBar::new(total);
            b.set_style(
                ProgressStyle::with_template(
                    "{prefix:>12} [{bar:40}] {percent:>3}% {bytes}/{total_bytes} ({bytes_per_sec})",
                )
                .unwrap()
                .progress_chars("█░"),
            );
            b.set_prefix(prefix.to_string());
            b
        } else {
            ProgressBar::hidden()
        };

        Self {
            inner,
            bar,
            total,
            current: 0,
            start: Instant::now(),
        }
    }

    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.current += n as u64;
        self.bar.set_position(self.current);
        let _ = self.total;
        let _ = self.start;
        Ok(n)
    }
}

pub struct ProgressWriter<W: Write> {
    inner: W,
    bar: ProgressBar,
}

impl<W: Write> ProgressWriter<W> {
    pub fn new(inner: W, total: u64, prefix: &str) -> Self {
        let bar = if console::Term::stderr().is_term() {
            let b = ProgressBar::new(total);
            b.set_style(
                ProgressStyle::with_template(
                    "{prefix:>12} [{bar:40}] {percent:>3}% {bytes}/{total_bytes} ({bytes_per_sec})",
                )
                .unwrap()
                .progress_chars("█░"),
            );
            b.set_prefix(prefix.to_string());
            b
        } else {
            ProgressBar::hidden()
        };

        Self { inner, bar }
    }

    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }
}

impl<W: Write> Write for ProgressWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bar.inc(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
