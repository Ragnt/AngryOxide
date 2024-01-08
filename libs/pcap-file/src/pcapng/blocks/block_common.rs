//! Common block types.

use std::borrow::Cow;
use std::io::{Result as IoResult, Write};

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};
use derive_into_owned::IntoOwned;

use super::enhanced_packet::EnhancedPacketBlock;
use super::interface_description::InterfaceDescriptionBlock;
use super::interface_statistics::InterfaceStatisticsBlock;
use super::name_resolution::NameResolutionBlock;
use super::packet::PacketBlock;
use super::section_header::SectionHeaderBlock;
use super::simple_packet::SimplePacketBlock;
use super::systemd_journal_export::SystemdJournalExportBlock;
use super::unknown::UnknownBlock;
use crate::errors::PcapError;
use crate::PcapResult;


/// Section header block type
pub const SECTION_HEADER_BLOCK: u32 = 0x0A0D0D0A;
/// Interface description block type
pub const INTERFACE_DESCRIPTION_BLOCK: u32 = 0x00000001;
/// Packet block type
pub const PACKET_BLOCK: u32 = 0x00000002;
/// Simple packet block type
pub const SIMPLE_PACKET_BLOCK: u32 = 0x00000003;
/// Name resolution block type
pub const NAME_RESOLUTION_BLOCK: u32 = 0x00000004;
/// Interface statistic block type
pub const INTERFACE_STATISTIC_BLOCK: u32 = 0x00000005;
/// Enhanced packet block type
pub const ENHANCED_PACKET_BLOCK: u32 = 0x00000006;
/// Systemd journal export block type
pub const SYSTEMD_JOURNAL_EXPORT_BLOCK: u32 = 0x00000009;

//   0               1               2               3
//   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                          Block Type                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Block Total Length                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  /                          Block Body                           /
//  /          /* variable length, aligned to 32 bits */            /
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Block Total Length                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// PcapNg Block
#[derive(Clone, Debug)]
pub struct RawBlock<'a> {
    /// Type field
    pub type_: u32,
    /// Initial length field
    pub initial_len: u32,
    /// Body of the block
    pub body: Cow<'a, [u8]>,
    /// Trailer length field
    pub trailer_len: u32,
}

impl<'a> RawBlock<'a> {
    /// Parses a borrowed [`RawBlock`] from a slice.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 12 {
            return Err(PcapError::IncompleteBuffer);
        }

        let type_ = slice.read_u32::<B>().unwrap();

        // Special case for the section header because we don't know the endianness yet
        if type_ == SECTION_HEADER_BLOCK {
            let initial_len = slice.read_u32::<BigEndian>().unwrap();

            // Check the first field of the Section header to find the endianness
            let mut tmp_slice = slice;
            let magic = tmp_slice.read_u32::<BigEndian>().unwrap();
            let res = match magic {
                0x1A2B3C4D => inner_parse::<BigEndian>(slice, type_, initial_len),
                0x4D3C2B1A => inner_parse::<LittleEndian>(slice, type_, initial_len.swap_bytes()),
                _ => Err(PcapError::InvalidField("SectionHeaderBlock: invalid magic number")),
            };

            return res;
        }
        else {
            let initial_len = slice.read_u32::<B>().map_err(|_| PcapError::IncompleteBuffer)?;
            return inner_parse::<B>(slice, type_, initial_len);
        };

        // Section Header parsing
        fn inner_parse<B: ByteOrder>(slice: &[u8], type_: u32, initial_len: u32) -> Result<(&[u8], RawBlock<'_>), PcapError> {
            if (initial_len % 4) != 0 {
                return Err(PcapError::InvalidField("Block: (initial_len % 4) != 0"));
            }

            if initial_len < 12 {
                return Err(PcapError::InvalidField("Block: initial_len < 12"));
            }

            // Check if there is enough data for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(PcapError::IncompleteBuffer);
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize..];

            let trailer_len = rem.read_u32::<B>().unwrap();

            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block: initial_length != trailer_length"));
            }

            let block = RawBlock { type_, initial_len, body: Cow::Borrowed(body), trailer_len };

            Ok((rem, block))
        }
    }

    /// Writes a [`RawBlock`] to a writer.
    ///
    /// Uses the endianness of the header.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u32::<B>(self.type_)?;
        writer.write_u32::<B>(self.initial_len)?;
        writer.write_all(&self.body[..])?;
        writer.write_u32::<B>(self.trailer_len)?;

        Ok(self.body.len() + 6)
    }

    /// Tries to convert a [`RawBlock`] into a [`Block`]
    pub fn try_into_block<B: ByteOrder>(self) -> PcapResult<Block<'a>> {
        Block::try_from_raw_block::<B>(self)
    }
}

/// PcapNg parsed blocks
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Block<'a> {
    /// Section Header block
    SectionHeader(SectionHeaderBlock<'a>),
    /// Interface Description block
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    /// Packet block
    Packet(PacketBlock<'a>),
    /// Simple packet block
    SimplePacket(SimplePacketBlock<'a>),
    /// Name Resolution block
    NameResolution(NameResolutionBlock<'a>),
    /// Interface statistics block
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    /// Enhanced packet block
    EnhancedPacket(EnhancedPacketBlock<'a>),
    /// Systemd Journal Export block
    SystemdJournalExport(SystemdJournalExportBlock<'a>),
    /// Unknown block
    Unknown(UnknownBlock<'a>),
}

impl<'a> Block<'a> {
    /// Parses a [`Block`] from a slice
    pub fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        let (rem, raw_block) = RawBlock::from_slice::<B>(slice)?;
        let block = Self::try_from_raw_block::<B>(raw_block)?;

        Ok((rem, block))
    }

    /// Writes a [`Block`] to a writer.
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        return match self {
            Self::SectionHeader(b) => inner_write_to::<B, _, W>(b, SECTION_HEADER_BLOCK, writer),
            Self::InterfaceDescription(b) => inner_write_to::<B, _, W>(b, INTERFACE_DESCRIPTION_BLOCK, writer),
            Self::Packet(b) => inner_write_to::<B, _, W>(b, PACKET_BLOCK, writer),
            Self::SimplePacket(b) => inner_write_to::<B, _, W>(b, SIMPLE_PACKET_BLOCK, writer),
            Self::NameResolution(b) => inner_write_to::<B, _, W>(b, NAME_RESOLUTION_BLOCK, writer),
            Self::InterfaceStatistics(b) => inner_write_to::<B, _, W>(b, INTERFACE_STATISTIC_BLOCK, writer),
            Self::EnhancedPacket(b) => inner_write_to::<B, _, W>(b, ENHANCED_PACKET_BLOCK, writer),
            Self::SystemdJournalExport(b) => inner_write_to::<B, _, W>(b, SYSTEMD_JOURNAL_EXPORT_BLOCK, writer),
            Self::Unknown(b) => inner_write_to::<B, _, W>(b, b.type_, writer),
        };

        fn inner_write_to<'a, B: ByteOrder, BL: PcapNgBlock<'a>, W: Write>(block: &BL, block_code: u32, writer: &mut W) -> IoResult<usize> {
            // Fake write to compute the data length
            let data_len = block.write_to::<B, _>(&mut std::io::sink()).unwrap();
            let pad_len = (4 - (data_len % 4)) % 4;

            let block_len = data_len + pad_len + 12;

            writer.write_u32::<B>(block_code)?;
            writer.write_u32::<B>(block_len as u32)?;
            block.write_to::<B, _>(writer)?;
            writer.write_all(&[0_u8; 3][..pad_len])?;
            writer.write_u32::<B>(block_len as u32)?;

            Ok(block_len)
        }
    }

    /// Tries to create a [`Block`] from a [`RawBlock`].
    ///
    /// The RawBlock must be Borrowed.
    pub fn try_from_raw_block<B: ByteOrder>(raw_block: RawBlock<'a>) -> Result<Block<'a>, PcapError> {
        let body = match raw_block.body {
            Cow::Borrowed(b) => b,
            _ => panic!("The raw block is not borrowed"),
        };

        match raw_block.type_ {
            SECTION_HEADER_BLOCK => {
                let (_, block) = SectionHeaderBlock::from_slice::<BigEndian>(body)?;
                Ok(Block::SectionHeader(block))
            },
            INTERFACE_DESCRIPTION_BLOCK => {
                let (_, block) = InterfaceDescriptionBlock::from_slice::<B>(body)?;
                Ok(Block::InterfaceDescription(block))
            },
            PACKET_BLOCK => {
                let (_, block) = PacketBlock::from_slice::<B>(body)?;
                Ok(Block::Packet(block))
            },
            SIMPLE_PACKET_BLOCK => {
                let (_, block) = SimplePacketBlock::from_slice::<B>(body)?;
                Ok(Block::SimplePacket(block))
            },
            NAME_RESOLUTION_BLOCK => {
                let (_, block) = NameResolutionBlock::from_slice::<B>(body)?;
                Ok(Block::NameResolution(block))
            },
            INTERFACE_STATISTIC_BLOCK => {
                let (_, block) = InterfaceStatisticsBlock::from_slice::<B>(body)?;
                Ok(Block::InterfaceStatistics(block))
            },
            ENHANCED_PACKET_BLOCK => {
                let (_, block) = EnhancedPacketBlock::from_slice::<B>(body)?;
                Ok(Block::EnhancedPacket(block))
            },
            SYSTEMD_JOURNAL_EXPORT_BLOCK => {
                let (_, block) = SystemdJournalExportBlock::from_slice::<B>(body)?;
                Ok(Block::SystemdJournalExport(block))
            },
            type_ => Ok(Block::Unknown(UnknownBlock::new(type_, raw_block.initial_len, body))),
        }
    }

    /// Tries to downcasts the current block into an [`EnhancedPacketBlock`]
    pub fn into_enhanced_packet(self) -> Option<EnhancedPacketBlock<'a>> {
        match self {
            Block::EnhancedPacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block into an [`InterfaceDescriptionBlock`]
    pub fn into_interface_description(self) -> Option<InterfaceDescriptionBlock<'a>> {
        match self {
            Block::InterfaceDescription(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block into an [`InterfaceStatisticsBlock`]
    pub fn into_interface_statistics(self) -> Option<InterfaceStatisticsBlock<'a>> {
        match self {
            Block::InterfaceStatistics(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`NameResolutionBlock`], if possible
    pub fn into_name_resolution(self) -> Option<NameResolutionBlock<'a>> {
        match self {
            Block::NameResolution(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`PacketBlock`], if possible
    pub fn into_packet(self) -> Option<PacketBlock<'a>> {
        match self {
            Block::Packet(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`SectionHeaderBlock`], if possible
    pub fn into_section_header(self) -> Option<SectionHeaderBlock<'a>> {
        match self {
            Block::SectionHeader(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`SimplePacketBlock`], if possible
    pub fn into_simple_packet(self) -> Option<SimplePacketBlock<'a>> {
        match self {
            Block::SimplePacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`SystemdJournalExportBlock`], if possible
    pub fn into_systemd_journal_export(self) -> Option<SystemdJournalExportBlock<'a>> {
        match self {
            Block::SystemdJournalExport(a) => Some(a),
            _ => None,
        }
    }
}


/// Common interface for the PcapNg blocks
pub trait PcapNgBlock<'a> {
    /// Parse a new block from a slice
    fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&[u8], Self), PcapError>
    where
        Self: std::marker::Sized;

    /// Write the content of a block into a writer
    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize>;

    /// Convert a block into the [`Block`] enumeration
    fn into_block(self) -> Block<'a>;
}
