//! Unknown Block.

use std::borrow::Cow;
use std::io::{Result as IoResult, Write};

use byteorder_slice::ByteOrder;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use crate::PcapError;

/// Unknown block
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownBlock<'a> {
    /// Block type
    pub type_: u32,
    /// Block length
    pub length: u32,
    /// Block value
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownBlock<'a> {
    /// Creates a new [`UnknownBlock`]
    pub fn new(type_: u32, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock { type_, length, value: Cow::Borrowed(value) }
    }
}

impl<'a> PcapNgBlock<'a> for UnknownBlock<'a> {
    fn from_slice<B: ByteOrder>(_slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError>
    where
        Self: Sized,
    {
        unimplemented!("UnkknownBlock::<as PcapNgBlock>::From_slice shouldn't be called")
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_all(&self.value)?;
        Ok(self.value.len())
    }

    fn into_block(self) -> Block<'a> {
        Block::Unknown(self)
    }
}
