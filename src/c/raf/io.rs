use std::fs::File;
use std::io;
use std::path::Path;

pub trait RafIo {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()>;
    fn get_size(&mut self) -> io::Result<u64>;
    fn set_size(&mut self, size: u64) -> io::Result<()>;
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct FileIo(File);

impl FileIo {
    pub fn new(file: File) -> Self {
        FileIo(file)
    }

    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        Ok(FileIo(file))
    }

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
