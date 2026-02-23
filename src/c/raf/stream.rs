use std::io::{self, Read, Seek, SeekFrom, Write};

use super::algorithm::Algorithm;
use super::context::Raf;

pub struct RafCursor<'a, A: Algorithm> {
    raf: &'a mut Raf<A>,
    pos: u64,
}

impl<A: Algorithm> Raf<A> {
    pub fn cursor(&mut self) -> RafCursor<'_, A> {
        RafCursor { raf: self, pos: 0 }
    }
}

impl<A: Algorithm> Read for RafCursor<'_, A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self
            .raf
            .read(buf, self.pos)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<A: Algorithm> Write for RafCursor<'_, A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self
            .raf
            .write(buf, self.pos)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.raf
            .sync()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

impl<A: Algorithm> Seek for RafCursor<'_, A> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(p) => {
                let size = self.raf.size();
                if p >= 0 {
                    size.checked_add(p as u64)
                } else {
                    size.checked_sub(p.unsigned_abs())
                }
            }
            SeekFrom::Current(p) => {
                if p >= 0 {
                    self.pos.checked_add(p as u64)
                } else {
                    self.pos.checked_sub(p.unsigned_abs())
                }
            }
        };
        match new_pos {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(io::Error::new(io::ErrorKind::InvalidInput, "seek overflow")),
        }
    }
}
