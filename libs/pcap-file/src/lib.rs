#![allow(clippy::unreadable_literal)]

//! Provides parsers, readers and writers for Pcap and PcapNg files.
//!
//! For Pcap files see the [`pcap`] module, especially [`PcapParser`](pcap::PcapParser),
//! [`PcapReader<R>`](pcap::PcapReader) and [`PcapWriter<W>`](pcap::PcapWriter).
//!
//! For PcapNg files see the [`pcapng`] module, especially [`PcapNgParser`](pcapng::PcapNgParser),
//! [`PcapNgReader<R>`](pcapng::PcapNgReader) and [`PcapNgWriter<W>`](pcapng::PcapNgWriter)

pub use common::*;
pub use errors::*;

pub(crate) mod common;
pub(crate) mod errors;
pub(crate) mod read_buffer;

pub mod pcap;
pub mod pcapng;
