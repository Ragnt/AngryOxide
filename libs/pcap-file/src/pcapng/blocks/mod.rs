//! Contains the PcapNg blocks.

pub(crate) mod block_common;
pub mod enhanced_packet;
pub mod interface_description;
pub mod interface_statistics;
pub mod name_resolution;
pub mod opt_common;
pub mod packet;
pub mod section_header;
pub mod simple_packet;
pub mod systemd_journal_export;
pub mod unknown;

pub use block_common::*;
