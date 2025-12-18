use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_BUFFER_SIZE: usize = 1 << 20;

pub struct SerialBuffer {
    buffer: VecDeque<u8>,
    out: Box<dyn Write + Send>,
    write_out: Arc<AtomicBool>,
}

impl SerialBuffer {
    pub fn new(out: Box<dyn Write + Send>, write_out: Arc<AtomicBool>) -> Self {
        Self {
            buffer: VecDeque::new(),
            out,
            write_out,
        }
    }

    fn fill_buffer(&mut self, buf: &[u8]) {
        if buf.len() >= MAX_BUFFER_SIZE {
            let offset = buf.len() - MAX_BUFFER_SIZE;
            self.buffer = VecDeque::from(buf[offset..].to_vec());
            return;
        }

        let num_allowed_bytes = MAX_BUFFER_SIZE - buf.len();
        if self.buffer.len() > num_allowed_bytes {
            let num_bytes_to_remove = self.buffer.len() - num_allowed_bytes;
            self.buffer.drain(..num_bytes_to_remove);
        }
        self.buffer.extend(buf);
    }
}

impl Write for SerialBuffer {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        if !self.write_out.load(Ordering::Acquire) {
            self.fill_buffer(buf);
            return Ok(buf.len());
        }

        self.flush()?;

        if !self.buffer.is_empty() {
            self.fill_buffer(buf);
            return Ok(buf.len());
        }

        let mut offset = 0;
        loop {
            match self.out.write(&buf[offset..]) {
                Ok(written_bytes) => {
                    if written_bytes < buf.len() - offset {
                        offset += written_bytes;
                        continue
                    };
                }
                Err(e) => {
                    if !matches!(e.kind(), std::io::ErrorKind::WouldBlock) {
                        return Err(e);
                    }
                    self.fill_buffer(&buf[offset..]);
                }
            }

            break;
        }

        self.out.flush()?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        if !self.write_out.load(Ordering::Acquire) {
            return Ok(());
        }

        while let Some(byte) = self.buffer.pop_front() {
            if self.out.write_all(&[byte]).is_err() {
                self.buffer.push_front(byte);
                break;
            }
        }

        self.out.flush()
    }
}
