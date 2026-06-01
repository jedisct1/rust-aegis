use std::fs::File;
use std::io;
use std::path::Path;

/// Backing storage for a RAF file.
///
/// Implement this trait to store an encrypted file somewhere other than the
/// local filesystem (in memory, over the network, and so on). [`FileIo`] is the
/// built-in implementation backed by [`std::fs::File`].
pub trait RafIo {
    /// Reads exactly `buf.len()` bytes starting at `offset`.
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    /// Writes all of `buf` starting at `offset`.
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()>;
    /// Returns the current size of the backing storage in bytes.
    fn get_size(&mut self) -> io::Result<u64>;
    /// Resizes the backing storage to `size` bytes.
    fn set_size(&mut self, size: u64) -> io::Result<()>;
    /// Flushes any buffered writes to durable storage.
    ///
    /// The default implementation is a no-op.
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A [`RafIo`] implementation backed by a [`std::fs::File`].
pub struct FileIo(File);

impl FileIo {
    /// Wraps an already-open file. The file must be opened for both reading and writing.
    pub fn new(file: File) -> Self {
        FileIo(file)
    }

    /// Opens `path` for reading and writing, creating it if it does not exist.
    ///
    /// An existing file is left intact; the caller decides whether to truncate
    /// via [`RafBuilder::truncate`](super::RafBuilder::truncate).
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        Ok(FileIo(file))
    }

    /// Opens an existing file at `path` for reading and writing.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::options().read(true).write(true).open(path)?;
        Ok(FileIo(file))
    }
}

#[cfg(unix)]
impl RafIo for FileIo {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.0.read_exact_at(buf, offset)
    }

    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.0.write_all_at(buf, offset)
    }

    fn get_size(&mut self) -> io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }

    fn set_size(&mut self, size: u64) -> io::Result<()> {
        self.0.set_len(size)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}

#[cfg(not(unix))]
impl RafIo for FileIo {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.read_exact(buf)
    }

    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.write_all(buf)
    }

    fn get_size(&mut self) -> io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }

    fn set_size(&mut self, size: u64) -> io::Result<()> {
        self.0.set_len(size)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}
