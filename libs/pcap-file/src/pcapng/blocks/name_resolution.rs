//! Name Resolution Block (NRB).

use std::borrow::Cow;
use std::io::{Result as IoResult, Write};

use byteorder_slice::ByteOrder;
use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::result::ReadSlice;
use derive_into_owned::IntoOwned;

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CustomBinaryOption, CustomUtf8Option, PcapNgOption, UnknownOption, WriteOptTo};
use crate::errors::PcapError;

/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct NameResolutionBlock<'a> {
    /// Records
    pub records: Vec<Record<'a>>,
    /// Options
    pub options: Vec<NameResolutionOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for NameResolutionBlock<'a> {
    fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        let mut records = Vec::new();

        loop {
            let (slice_tmp, record) = Record::from_slice::<B>(slice)?;
            slice = slice_tmp;

            match record {
                Record::End => break,
                _ => records.push(record),
            }
        }

        let (rem, options) = NameResolutionOption::opts_from_slice::<B>(slice)?;

        let block = NameResolutionBlock { records, options };

        Ok((rem, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        let mut len = 0;

        for record in &self.records {
            len += record.write_to::<B, _>(writer)?;
        }
        len += Record::End.write_to::<B, _>(writer)?;

        len += NameResolutionOption::write_opts_to::<B, _>(&self.options, writer)?;

        Ok(len)
    }

    fn into_block(self) -> Block<'a> {
        Block::NameResolution(self)
    }
}

/// Resolution block record types
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Record<'a> {
    /// End of the records
    End,
    /// Ipv4 records
    Ipv4(Ipv4Record<'a>),
    /// Ipv6 records
    Ipv6(Ipv6Record<'a>),
    /// Unknown records
    Unknown(UnknownRecord<'a>),
}

impl<'a> Record<'a> {
    /// Parse a [`Record`] from a slice
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        let type_ = slice.read_u16::<B>().map_err(|_| PcapError::IncompleteBuffer)?;
        let length = slice.read_u16::<B>().map_err(|_| PcapError::IncompleteBuffer)?;
        let pad_len = (4 - length % 4) % 4;

        if slice.len() < length as usize {
            return Err(PcapError::InvalidField("NameResolutionBlock: Record length > slice.len()"));
        }
        let value = &slice[..length as usize];

        let record = match type_ {
            0 => {
                if length != 0 {
                    return Err(PcapError::InvalidField("NameResolutionBlock: nrb_record_end length != 0"));
                }
                Record::End
            },

            1 => {
                let record = Ipv4Record::from_slice(value)?;
                Record::Ipv4(record)
            },

            2 => {
                let record = Ipv6Record::from_slice(value)?;
                Record::Ipv6(record)
            },

            _ => {
                let record = UnknownRecord::new(type_, length, value);
                Record::Unknown(record)
            },
        };

        let len = length as usize + pad_len as usize;

        Ok((&slice[len..], record))
    }

    /// Write a [`Record`] to a writer
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            Record::End => {
                writer.write_u16::<B>(0)?;
                writer.write_u16::<B>(0)?;

                Ok(4)
            },

            Record::Ipv4(a) => {
                let len = a.write_to::<B, _>(&mut std::io::sink()).unwrap();
                let pad_len = (4 - len % 4) % 4;

                writer.write_u16::<B>(1)?;
                writer.write_u16::<B>(len as u16)?;
                a.write_to::<B, _>(writer)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len + pad_len)
            },

            Record::Ipv6(a) => {
                let len = a.write_to::<B, _>(&mut std::io::sink()).unwrap();
                let pad_len = (4 - len % 4) % 4;

                writer.write_u16::<B>(2)?;
                writer.write_u16::<B>(len as u16)?;
                a.write_to::<B, _>(writer)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len + pad_len)
            },

            Record::Unknown(a) => {
                let len = a.value.len();
                let pad_len = (4 - len % 4) % 4;

                writer.write_u16::<B>(a.type_)?;
                writer.write_u16::<B>(a.length)?;
                writer.write_all(&a.value)?;
                writer.write_all(&[0_u8; 3][..pad_len])?;

                Ok(4 + len + pad_len)
            },
        }
    }
}

/// Ipv4 records
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv4Record<'a> {
    /// IPv4 Addr
    pub ip_addr: Cow<'a, [u8]>,
    /// Fqdn
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv4Record<'a> {
    /// Parse a [`Ipv4Record`] from a slice
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, PcapError> {
        if slice.len() < 6 {
            return Err(PcapError::InvalidField("NameResolutionBlock: Ipv4Record len < 6"));
        }

        let ip_addr = &slice[..4];
        slice = &slice[4..];

        let mut names = vec![];
        for name in slice.split(|&b| b == 0) {
            if name.is_empty() {
                break;
            }
            names.push(Cow::Borrowed(std::str::from_utf8(name)?));
        }

        if names.is_empty() {
            return Err(PcapError::InvalidField("NameResolutionBlock: Ipv4Record without any name"));
        }

        let record = Ipv4Record { ip_addr: Cow::Borrowed(ip_addr), names };

        Ok(record)
    }

    /// Write a [`Ipv4Record`] to a writter
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        let mut len = 4;

        writer.write_all(&self.ip_addr)?;
        for name in &self.names {
            writer.write_all(name.as_bytes())?;
            writer.write_u8(0)?;

            len += name.len();
            len += 1;
        }

        Ok(len)
    }
}

/// Ipv6 records
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct Ipv6Record<'a> {
    /// Ipv6 addr
    pub ip_addr: Cow<'a, [u8]>,
    /// Fqdn
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> Ipv6Record<'a> {
    /// Parse a [`Ipv6Record`] from a slice
    pub fn from_slice(mut slice: &'a [u8]) -> Result<Self, PcapError> {
        if slice.len() < 18 {
            return Err(PcapError::InvalidField("NameResolutionBlock: Ipv6Record len < 18"));
        }

        let ip_addr = &slice[..16];
        slice = &slice[16..];

        let mut names = vec![];
        for name in slice.split(|&b| b == 0) {
            if name.is_empty() {
                break;
            }

            names.push(Cow::Borrowed(std::str::from_utf8(name)?));
        }

        if names.is_empty() {
            return Err(PcapError::InvalidField("NameResolutionBlock: Ipv6Record without any name"));
        }

        let record = Ipv6Record { ip_addr: Cow::Borrowed(ip_addr), names };

        Ok(record)
    }

    /// Write a [`Ipv6Record`] to a writter
    pub fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        let mut len = 16;

        writer.write_all(&self.ip_addr)?;
        for name in &self.names {
            writer.write_all(name.as_bytes())?;
            writer.write_u8(0)?;

            len += name.len();
            len += 1;
        }

        Ok(len)
    }
}

/// Unknown records
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownRecord<'a> {
    /// Records type
    pub type_: u16,
    /// Record length
    pub length: u16,
    /// Record body
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownRecord<'a> {
    /// Creates a new [`UnknownRecord`]
    fn new(type_: u16, length: u16, value: &'a [u8]) -> Self {
        UnknownRecord { type_, length, value: Cow::Borrowed(value) }
    }
}

/// The Name Resolution Block (NRB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum NameResolutionOption<'a> {
    /// The opt_comment option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment(Cow<'a, str>),

    /// The ns_dnsname option is a UTF-8 string containing the name of the machine (DNS server) used to perform the name resolution.
    NsDnsName(Cow<'a, str>),

    /// The ns_dnsIP4addr option specifies the IPv4 address of the DNS server.
    NsDnsIpv4Addr(Cow<'a, [u8]>),

    /// The ns_dnsIP6addr option specifies the IPv6 address of the DNS server.
    NsDnsIpv6Addr(Cow<'a, [u8]>),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

impl<'a> PcapNgOption<'a> for NameResolutionOption<'a> {
    fn from_slice<B: ByteOrder>(code: u16, length: u16, slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => NameResolutionOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => NameResolutionOption::NsDnsName(Cow::Borrowed(std::str::from_utf8(slice)?)),
            3 => {
                if slice.len() != 4 {
                    return Err(PcapError::InvalidField("NameResolutionOption: NsDnsIpv4Addr length != 4"));
                }
                NameResolutionOption::NsDnsIpv4Addr(Cow::Borrowed(slice))
            },
            4 => {
                if slice.len() != 16 {
                    return Err(PcapError::InvalidField("NameResolutionOption: NsDnsIpv6Addr length != 16"));
                }
                NameResolutionOption::NsDnsIpv6Addr(Cow::Borrowed(slice))
            },

            2988 | 19372 => NameResolutionOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
            2989 | 19373 => NameResolutionOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

            _ => NameResolutionOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            NameResolutionOption::Comment(a) => a.write_opt_to::<B, W>(1, writer),
            NameResolutionOption::NsDnsName(a) => a.write_opt_to::<B, W>(2, writer),
            NameResolutionOption::NsDnsIpv4Addr(a) => a.write_opt_to::<B, W>(3, writer),
            NameResolutionOption::NsDnsIpv6Addr(a) => a.write_opt_to::<B, W>(4, writer),
            NameResolutionOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer),
            NameResolutionOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer),
            NameResolutionOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer),
        }
    }
}
