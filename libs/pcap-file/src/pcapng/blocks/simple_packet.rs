//! Simple Packet Block (SPB).

use std::borrow::Cow;
use std::io::{Result as IoResult, Write};

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use crate::errors::PcapError;

/// The Simple Packet Block (SPB) is a lightweight container for storing the packets coming from the network.
///
/// Its presence is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SimplePacketBlock<'a> {
    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,
}

impl<'a> PcapNgBlock<'a> for SimplePacketBlock<'a> {
    fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 4 {
            return Err(PcapError::InvalidField("SimplePacketBlock: block length < 4"));
        }
        let original_len = slice.read_u32::<B>().unwrap();

        let packet = SimplePacketBlock { original_len, data: Cow::Borrowed(slice) };

        Ok((&[], packet))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;

        let pad_len = (4 - (self.data.len() % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(4 + self.data.len() + pad_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::SimplePacket(self)
    }
}
