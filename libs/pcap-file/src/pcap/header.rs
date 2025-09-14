use std::io::Write;

use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use byteorder_slice::{BigEndian, ByteOrder, LittleEndian};

use crate::errors::*;
use crate::{DataLink, Endianness, TsResolution};

/// Pcap Global Header
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PcapHeader {
    /// Major version number
    pub version_major: u16,

    /// Minor version number
    pub version_minor: u16,

    /// GMT to local timezone correction, should always be 0
    pub ts_correction: i32,

    /// Timestamp accuracy, should always be 0
    pub ts_accuracy: u32,

    /// Max length of captured packet, typically 65535
    pub snaplen: u32,

    /// DataLink type (first layer in the packet)
    pub datalink: DataLink,

    /// Timestamp resolution of the pcap (microsecond or nanosecond)
    pub ts_resolution: TsResolution,

    /// Endianness of the pcap (excluding the packet data)
    pub endianness: Endianness,
}

impl PcapHeader {
    /// Creates a new [`PcapHeader`] from a slice of bytes.
    ///
    /// Returns an error if the reader doesn't contain a valid pcap
    /// or if there is a reading error.
    ///
    /// [`PcapError::IncompleteBuffer`] indicates that there is not enough data in the buffer.
    pub fn from_slice(mut slice: &[u8]) -> PcapResult<(&[u8], PcapHeader)> {
        // Check that slice.len() > PcapHeader length
        if slice.len() < 24 {
            return Err(PcapError::IncompleteBuffer);
        }

        let magic_number = slice.read_u32::<BigEndian>().unwrap();

        match magic_number {
            0xA1B2C3D4 => return init_pcap_header::<BigEndian>(slice, TsResolution::MicroSecond, Endianness::Big),
            0xA1B23C4D => return init_pcap_header::<BigEndian>(slice, TsResolution::NanoSecond, Endianness::Big),
            0xD4C3B2A1 => return init_pcap_header::<LittleEndian>(slice, TsResolution::MicroSecond, Endianness::Little),
            0x4D3CB2A1 => return init_pcap_header::<LittleEndian>(slice, TsResolution::NanoSecond, Endianness::Little),
            _ => return Err(PcapError::InvalidField("PcapHeader: wrong magic number")),
        };

        // Inner function used for the initialisation of the PcapHeader.
        // Must check the srcclength before calling it.
        fn init_pcap_header<B: ByteOrder>(
            mut src: &[u8],
            ts_resolution: TsResolution,
            endianness: Endianness,
        ) -> PcapResult<(&[u8], PcapHeader)> {
            let header = PcapHeader {
                version_major: src.read_u16::<B>().unwrap(),
                version_minor: src.read_u16::<B>().unwrap(),
                ts_correction: src.read_i32::<B>().unwrap(),
                ts_accuracy: src.read_u32::<B>().unwrap(),
                snaplen: src.read_u32::<B>().unwrap(),
                datalink: DataLink::from(src.read_u32::<B>().unwrap()),
                ts_resolution,
                endianness,
            };

            Ok((src, header))
        }
    }

    /// Writes a [`PcapHeader`] to a writer.
    ///
    /// Uses the endianness of the header.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> PcapResult<usize> {
        return match self.endianness {
            Endianness::Big => write_header::<_, BigEndian>(self, writer),
            Endianness::Little => write_header::<_, LittleEndian>(self, writer),
        };

        fn write_header<W: Write, B: ByteOrder>(header: &PcapHeader, writer: &mut W) -> PcapResult<usize> {
            let magic_number = match header.ts_resolution {
                TsResolution::MicroSecond => 0xA1B2C3D4,
                TsResolution::NanoSecond => 0xA1B23C4D,
            };

            writer.write_u32::<B>(magic_number).map_err(PcapError::IoError)?;
            writer.write_u16::<B>(header.version_major).map_err(PcapError::IoError)?;
            writer.write_u16::<B>(header.version_minor).map_err(PcapError::IoError)?;
            writer.write_i32::<B>(header.ts_correction).map_err(PcapError::IoError)?;
            writer.write_u32::<B>(header.ts_accuracy).map_err(PcapError::IoError)?;
            writer.write_u32::<B>(header.snaplen).map_err(PcapError::IoError)?;
            writer.write_u32::<B>(header.datalink.into()).map_err(PcapError::IoError)?;

            Ok(24)
        }
    }
}

/// Creates a new [`PcapHeader`] with these parameters:
///
/// ```rust,ignore
/// PcapHeader {
///     version_major: 2,
///     version_minor: 4,
///     ts_correction: 0,
///     ts_accuracy: 0,
///     snaplen: 65535,
///     datalink: DataLink::ETHERNET,
///     ts_resolution: TsResolution::MicroSecond,
///     endianness: Endianness::Big
/// };
/// ```
impl Default for PcapHeader {
    fn default() -> Self {
        PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::MicroSecond,
            endianness: Endianness::Big,
        }
    }
}
