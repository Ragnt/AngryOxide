use std::io::{Error, ErrorKind, Read};

use crate::PcapError;

/// Internal structure that bufferize its input and allow to parse element from its buffer.
#[derive(Debug)]
pub(crate) struct ReadBuffer<R: Read> {
    /// Reader from which we read the data from
    reader: R,
    /// Internal buffer
    buffer: Vec<u8>,
    /// Current start position of the buffer
    pos: usize,
    /// Current end position of the buffer
    len: usize,
}

impl<R: Read> ReadBuffer<R> {
    /// Creates a new ReadBuffer with capacity of 8_000_000
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, 8_000_000)
    }

    /// Creates a new ReadBuffer with the given capacity
    pub fn with_capacity(reader: R, capacity: usize) -> Self {
        Self { reader, buffer: vec![0_u8; capacity], pos: 0, len: 0 }
    }

    /// Parse data from the internal buffer
    ///
    /// Safety
    ///
    /// The parser must NOT keep a reference to the buffer in input.
    pub fn parse_with<'a, 'b: 'a, 'c: 'a, F, O>(&'c mut self, mut parser: F) -> Result<O, PcapError>
    where
        F: FnMut(&'a [u8]) -> Result<(&'a [u8], O), PcapError>,
        F: 'b,
        O: 'a,
    {
        loop {
            let buf = &self.buffer[self.pos..self.len];

            // Sound because 'b and 'c must outlive 'a so the buffer cannot be modified while someone has a ref on it
            let buf: &'a [u8] = unsafe { std::mem::transmute(buf) };

            match parser(buf) {
                Ok((rem, value)) => {
                    self.advance_with_slice(rem);
                    return Ok(value);
                },

                Err(PcapError::IncompleteBuffer) => {
                    // The parsed data len should never be more than the buffer capacity
                    if buf.len() == self.buffer.len() {
                        return Err(PcapError::IoError(Error::from(ErrorKind::UnexpectedEof)));
                    }

                    let nb_read = self.fill_buf().map_err(PcapError::IoError)?;
                    if nb_read == 0 {
                        return Err(PcapError::IoError(Error::from(ErrorKind::UnexpectedEof)));
                    }
                },

                Err(e) => return Err(e),
            }
        }
    }

    /// Fill the inner buffer.
    /// Copy the remaining data inside buffer at its start and the fill the end part with data from the reader.
    fn fill_buf(&mut self) -> Result<usize, std::io::Error> {
        // Copy the remaining data to the start of the buffer
        let rem_len = unsafe {
            let buf_ptr_mut = self.buffer.as_mut_ptr();
            let rem_ptr_mut = buf_ptr_mut.add(self.pos);
            std::ptr::copy(rem_ptr_mut, buf_ptr_mut, self.len - self.pos);
            self.len - self.pos
        };

        let nb_read = self.reader.read(&mut self.buffer[rem_len..])?;

        self.len = rem_len + nb_read;
        self.pos = 0;

        Ok(nb_read)
    }

    /// Advance the internal buffer position.
    fn advance(&mut self, nb_bytes: usize) {
        assert!(self.pos + nb_bytes <= self.len);
        self.pos += nb_bytes;
    }

    /// Advance the internal buffer position.
    fn advance_with_slice(&mut self, rem: &[u8]) {
        // Compute the length between the buffer and the slice
        let diff_len = (rem.as_ptr() as usize)
            .checked_sub(self.buffer().as_ptr() as usize)
            .expect("Rem is not a sub slice of self.buffer");

        self.advance(diff_len)
    }

    /// Return the valid data of the internal buffer
    pub fn buffer(&self) -> &[u8] {
        &self.buffer[self.pos..self.len]
    }

    /// Return true there are some data that can be read
    pub fn has_data_left(&mut self) -> Result<bool, std::io::Error> {
        // The buffer can be empty and the reader can still have data
        if self.buffer().is_empty() {
            let nb_read = self.fill_buf()?;
            if nb_read == 0 {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Return the inner reader
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Return a reference over the inner reader
    pub fn get_ref(&self) -> &R {
        &self.reader
    }
}

#[cfg(test)]
mod test {
    /*
    // Shouldn't compile
    #[test]
    fn parse_with_safety() {
        let a = &[0_u8; 10];
        let b = &mut &a[..];

        let input = vec![1_u8; 100];
        let input_read = &mut &input[..];
        let mut reader = super::ReadBuffer::new(input_read);

        unsafe {
            reader.parse_with(|buf| {
                *b = buf;
                Ok((buf, ()))
            });
        }

        unsafe {
            reader.has_data_left();
        }

        println!("{:?}", b);
    }
    */
}
